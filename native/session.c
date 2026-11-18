// SPDX-License-Identifier: LGPL-2.1-or-later
#include "session.h"
#include "host-proof.h"
#include <openssl/kdf.h>
#include <string.h>

enum { MAX_PLAINTEXT = 16384, RECORD_OVERHEAD = 5 + 8 + 16 };
enum { ALERT = 21, HANDSHAKE = 22, APPLICATION = 23 };

struct record_keys {
  guint8 key[32], salt[4];
  guint64 sequence;
};

struct x1fold_session {
  struct record_keys tx, rx;
  int fd;
  gboolean active, notification_pending;
};

static gboolean
failure (GError **error, const char *message)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, message);
  return FALSE;
}

static gboolean
prf (const guint8 *secret, int secret_len, const char *label, const guint8 *seed,
     int seed_len, guint8 *output, size_t output_len)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_TLS1_PRF, NULL);
  size_t len = output_len;
  gboolean ok = ctx && EVP_PKEY_derive_init (ctx) == 1 &&
    EVP_PKEY_CTX_set_tls1_prf_md (ctx, EVP_sha384 ()) == 1 &&
    EVP_PKEY_CTX_set1_tls1_prf_secret (ctx, secret, secret_len) == 1 &&
    EVP_PKEY_CTX_add1_tls1_prf_seed (ctx, (const guint8 *) label, strlen (label)) == 1 &&
    EVP_PKEY_CTX_add1_tls1_prf_seed (ctx, seed, seed_len) == 1 &&
    EVP_PKEY_derive (ctx, output, &len) == 1 && len == output_len;
  EVP_PKEY_CTX_free (ctx);
  return ok;
}

static gboolean
session_keys (X1FoldSession *s, EVP_PKEY *peer, EVP_PKEY *ephemeral,
              const struct x1fold_server_flight *hello, guint8 master[48])
{
  guint8 shared[32], seed[64], keys[72];
  size_t shared_size = sizeof shared;
  memcpy (seed, hello->client_random, 32);
  memcpy (seed + 32, hello->server_random, 32);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey (NULL, ephemeral, NULL);
  gboolean ok = ctx && EVP_PKEY_derive_init (ctx) == 1 &&
    EVP_PKEY_derive_set_peer (ctx, peer) == 1 &&
    EVP_PKEY_derive (ctx, shared, &shared_size) == 1 && shared_size == sizeof shared &&
    prf (shared, sizeof shared, "master secret", seed, sizeof seed, master, 48) &&
    prf (master, 48, "key expansion", seed, sizeof seed, keys, sizeof keys);
  if (ok)
    {
      memcpy (s->tx.key, keys, 32);
      memcpy (s->rx.key, keys + 32, 32);
      memcpy (s->tx.salt, keys + 64, 4);
      memcpy (s->rx.salt, keys + 68, 4);
    }
  OPENSSL_cleanse (shared, sizeof shared);
  OPENSSL_cleanse (keys, sizeof keys);
  EVP_PKEY_CTX_free (ctx);
  return ok;
}

static void
header (guint8 out[5], guint8 type, gsize payload_size)
{
  out[0] = type;
  out[1] = 3;
  out[2] = 3;
  out[3] = payload_size >> 8;
  out[4] = payload_size & 0xff;
}

/* Each direction has its own sequence space. The explicit nonce is carried
 * on the wire. Use the send sequence for unique nonces under the send key. */
static gboolean
crypt_record (struct record_keys *keys, gboolean encrypt, guint8 type, guint8 explicit_iv[8],
              const guint8 *input, guint8 *output, int len, guint8 tag[16])
{
  if (keys->sequence == G_MAXUINT64)
    return FALSE;
  guint64 seq = GUINT64_TO_BE (keys->sequence);
  guint8 nonce[12], aad[13];
  if (encrypt)
    memcpy (explicit_iv, &seq, 8);
  memcpy (nonce, keys->salt, 4);
  memcpy (nonce + 4, explicit_iv, 8);
  memcpy (aad, &seq, 8);
  header (aad + 8, type, len);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int used = 0, tail = 0;
  gboolean ok = ctx && EVP_CipherInit_ex (ctx, EVP_aes_256_gcm (), NULL, keys->key,
                                          nonce, encrypt) == 1 &&
    EVP_CipherUpdate (ctx, NULL, &used, aad, sizeof aad) == 1 &&
    EVP_CipherUpdate (ctx, output, &used, input, len) == 1 && used == len &&
    (encrypt || EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1) &&
    EVP_CipherFinal_ex (ctx, output + used, &tail) == 1 && tail == 0 &&
    (!encrypt || EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1);
  EVP_CIPHER_CTX_free (ctx);
  if (ok)
    keys->sequence++;
  return ok;
}

static gboolean
seal (X1FoldSession *s, guint8 type, const guint8 *plain, gsize size, guint8 *wire)
{
  header (wire, type, size + 24);
  return crypt_record (&s->tx, TRUE, type, wire + 5, plain, wire + 13, size,
                       wire + 13 + size);
}

static gboolean
unseal (X1FoldSession *s, guint8 type, guint8 *wire, gsize size, guint8 *plain)
{
  if (size < RECORD_OVERHEAD || size > MAX_PLAINTEXT + RECORD_OVERHEAD ||
      wire[0] != type || wire[1] != 3 || wire[2] != 3 ||
      (gsize) ((wire[3] << 8) | wire[4]) != size - 5)
    return FALSE;
  return crypt_record (&s->rx, FALSE, type, wire + 5, wire + 13, plain, size - RECORD_OVERHEAD,
                       wire + size - 16);
}

static gboolean
finish_handshake (X1FoldSession *s, const struct x1fold_server_flight *hello, GBytes *proof,
                  const guint8 master[48], gint64 deadline, GCancellable *cancel, GError **error)
{
  static const guint8 change_cipher[] = {20,3,3,0,1,1};
  guint8 digest[32], client[16] = {20,0,0,12}, server[16] = {20,0,0,12};
  g_autoptr(GChecksum) hash = g_checksum_new (G_CHECKSUM_SHA256);
  gsize size, digest_size = sizeof digest;
  const guint8 *data = g_bytes_get_data (hello->transcript, &size);
  g_checksum_update (hash, data, size);
  data = g_bytes_get_data (proof, &size);
  g_checksum_update (hash, data, size);
  g_checksum_get_digest (hash, digest, &digest_size);
  /* Both Tudor Finished values cover the transcript through CertificateVerify. */
  if (!prf (master, 48, "client finished", digest, sizeof digest, client + 4, 12) ||
      !prf (master, 48, "server finished", digest, sizeof digest, server + 4, 12))
    return failure (error, "Deriving Tudor Finished values failed");
  const gsize request_size = 9 + size + sizeof change_cipher + RECORD_OVERHEAD + sizeof client;
  g_autofree guint8 *request = g_malloc0 (request_size);
  request[0] = 0x44;
  header (request + 4, HANDSHAKE, size);
  memcpy (request + 9, data, size);
  memcpy (request + 9 + size, change_cipher, sizeof change_cipher);
  if (!seal (s, HANDSHAKE, client, sizeof client, request + 9 + size + sizeof change_cipher))
    return failure (error, "Encrypting client Finished failed");

  guint8 wire[sizeof change_cipher + RECORD_OVERHEAD + sizeof server], plain[sizeof server];
  gsize received;
  if (!x1fold_exchange (s->fd, request, request_size, wire, sizeof wire, &received,
                        deadline, cancel, error))
    return FALSE;
  if (received != sizeof wire || memcmp (wire, change_cipher, sizeof change_cipher) ||
      !unseal (s, HANDSHAKE, wire + sizeof change_cipher, received - sizeof change_cipher, plain) ||
      CRYPTO_memcmp (plain, server, sizeof server))
    return failure (error, "Reader Finished authentication failed");
  return TRUE;
}

X1FoldSession *
x1fold_session_open (int fd, const struct x1fold_version *version, GBytes *sensor_cert,
                     GBytes *host_cert, EVP_PKEY *host_identity, gint64 deadline,
                     GCancellable *cancel, GError **error)
{
  g_return_val_if_fail (version && sensor_cert && host_cert && host_identity, NULL);
  gsize size;
  const guint8 *cert = g_bytes_get_data (host_cert, &size);
  if (!x1fold_check_host_identity (cert, size, host_identity, error))
    return NULL;
  cert = g_bytes_get_data (sensor_cert, &size);
  EVP_PKEY *peer = x1fold_sensor_public_key (version, cert, size, error);
  if (!peer)
    return NULL;
  X1FoldSession *s = g_new0 (X1FoldSession, 1);
  s->fd = fd;
  gboolean active;
  struct x1fold_server_flight hello = {0};
  EVP_PKEY *ephemeral = NULL;
  g_autoptr(GBytes) proof = NULL;
  guint8 master[48];
  if (!x1fold_session_status (fd, &active, error))
    goto out;
  if (active)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_BUSY, "Reader already has an active session");
      goto out;
    }
  cert = g_bytes_get_data (host_cert, &size);
  if (!x1fold_request_server_flight (fd, deadline, cancel, &hello, error) ||
      !x1fold_build_host_proof (&hello, cert, size, host_identity, &proof, &ephemeral, error))
    goto out;
  if (!session_keys (s, peer, ephemeral, &hello, master))
    {
      failure (error, "Tudor key agreement failed");
      goto out;
    }
  s->active = finish_handshake (s, &hello, proof, master, deadline, cancel, error);
out:
  OPENSSL_cleanse (master, sizeof master);
  EVP_PKEY_free (ephemeral);
  EVP_PKEY_free (peer);
  g_clear_pointer (&hello.transcript, g_bytes_unref);
  if (!s->active)
    g_clear_pointer (&s, x1fold_session_free);
  return s;
}

static gboolean
record_exchange (X1FoldSession *s, guint8 type, const guint8 *command, gsize size, guint8 *reply,
                 gsize capacity, gsize *received, gint64 deadline, GCancellable *cancel, GError **error)
{
  *received = 0;
  if (!s->active)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED, "Tudor session is closed");
      return FALSE;
    }
  if (!command || !size || size > MAX_PLAINTEXT || capacity > MAX_PLAINTEXT || (!reply && capacity))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid Tudor record size");
      return FALSE;
    }
  if (g_cancellable_set_error_if_cancelled (cancel, error))
    return FALSE;
  if (g_get_monotonic_time () >= deadline)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "Tudor command deadline expired");
      return FALSE;
    }
  s->active = FALSE;
  g_autofree guint8 *request = g_malloc (RECORD_OVERHEAD + size);
  g_autofree guint8 *wire = g_malloc (RECORD_OVERHEAD + capacity);
  if (!seal (s, type, command, size, request))
    return failure (error, "Encrypting Tudor record failed");
  gsize got;
  if (!x1fold_exchange_notified (s->fd, request, RECORD_OVERHEAD + size, wire,
                                 RECORD_OVERHEAD + capacity, &got, deadline, cancel,
                                 &s->notification_pending, error))
    return FALSE;
  guint8 *plain = OPENSSL_malloc (MAX (capacity, 1));
  if (!plain || !unseal (s, type, wire, got, plain))
    {
      OPENSSL_clear_free (plain, MAX (capacity, 1));
      return failure (error, "Reader record authentication failed");
    }
  *received = got - RECORD_OVERHEAD;
  if (*received)
    memcpy (reply, plain, *received);
  OPENSSL_clear_free (plain, MAX (capacity, 1));
  s->active = TRUE;
  return TRUE;
}

gboolean
x1fold_session_command (X1FoldSession *s, const guint8 *command, gsize size, guint8 *reply,
                        gsize capacity, gsize *received, gint64 deadline,
                        GCancellable *cancel, GError **error)
{
  return record_exchange (s, APPLICATION, command, size, reply, capacity, received, deadline,
                          cancel, error);
}

gboolean
x1fold_session_listen (X1FoldSession *s, gboolean listen, GError **error)
{
  if (listen && !s->active)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED, "Tudor session is closed");
      return FALSE;
    }
  s->notification_pending = FALSE;
  return x1fold_event_listen (s->fd, listen, error);
}

gboolean
x1fold_session_wait_notification (X1FoldSession *s, gint64 deadline, GCancellable *cancel,
                                  GError **error)
{
  if (g_cancellable_set_error_if_cancelled (cancel, error))
    return FALSE;
  if (s->notification_pending)
    {
      s->notification_pending = FALSE;
      return TRUE;
    }
  return x1fold_read_notification (s->fd, deadline, cancel, error);
}

gboolean
x1fold_session_close (X1FoldSession *s, gint64 deadline, GCancellable *cancel, GError **error)
{
  const guint8 close_notify[] = {1,0};
  guint8 reply[2];
  gsize received;
  gboolean ok = record_exchange (s, ALERT, close_notify, 2, reply, 2, &received, deadline,
                                 cancel, error);
  s->active = FALSE;
  return ok && ((received == 2 && !memcmp (reply, close_notify, 2)) ||
                failure (error, "Reader did not acknowledge close_notify"));
}

void
x1fold_session_free (X1FoldSession *s)
{
  if (s)
    {
      OPENSSL_cleanse (s, sizeof *s);
      g_free (s);
    }
}
