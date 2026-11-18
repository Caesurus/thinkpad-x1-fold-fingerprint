// SPDX-License-Identifier: LGPL-2.1-or-later
/* Offline request generation and one explicit registration. The owner supplies
 * the host key on fd 4 and a separately configured local issuing provider.
 * A registration additionally needs an exclusively claimed reader on fd 3. */
#include "credentials.h"
#include "pairing.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static EVP_PKEY *
open_signer (const char *uri)
{
  OSSL_STORE_CTX *store = OSSL_STORE_open (uri, UI_null (), NULL, NULL, NULL);
  if (!store)
    return NULL;
  EVP_PKEY *key = NULL;
  if (OSSL_STORE_expect (store, OSSL_STORE_INFO_PKEY) == 1)
    while (!OSSL_STORE_eof (store))
      {
        OSSL_STORE_INFO *info = OSSL_STORE_load (store);
        if (!info)
          {
            if (!OSSL_STORE_eof (store))
              g_clear_pointer (&key, EVP_PKEY_free);
            break;
          }
        if (OSSL_STORE_INFO_get_type (info) == OSSL_STORE_INFO_PKEY)
          {
            if (key)
              {
                OSSL_STORE_INFO_free (info);
                g_clear_pointer (&key, EVP_PKEY_free);
                break;
              }
            key = OSSL_STORE_INFO_get1_PKEY (info);
          }
        OSSL_STORE_INFO_free (info);
      }
  if (OSSL_STORE_close (store) != 1)
    g_clear_pointer (&key, EVP_PKEY_free);
  return key;
}

static gboolean
store_at (int fd, const guint8 *data, gsize size, off_t at)
{
  while (size)
    {
      ssize_t n = pwrite (fd, data, size, at);
      if (n < 0 && errno == EINTR)
        continue;
      if (n == 0)
        errno = EIO;
      if (n <= 0)
        return FALSE;
      data += n;
      size -= n;
      at += n;
    }
  return TRUE;
}

static gboolean
parse_serial (const char *s, guint8 out[6])
{
  if (strlen (s) != 12)
    return FALSE;
  for (guint i = 0; i < 6; i++)
    {
      int hi = g_ascii_xdigit_value (s[2 * i]);
      int lo = g_ascii_xdigit_value (s[2 * i + 1]);
      if (hi < 0 || lo < 0)
        return FALSE;
      out[i] = (hi << 4) | lo;
    }
  static const guint8 blank[6], erased[6] = {255,255,255,255,255,255};
  return memcmp (out, blank, 6) && memcmp (out, erased, 6);
}

static void
free_key_bio (gpointer data)
{
  BIO_free (data);
}

/* Serialize only the owner key whose public coordinates were just checked. */
static GBytes *
encode_owner (EVP_PKEY *owner, GError **error)
{
  BIO *bio = BIO_new (BIO_s_secmem ());
  char *pem = NULL;
  long len = 0;
  if (bio && PEM_write_bio_PrivateKey (bio, owner, NULL, NULL, 0, NULL, NULL) == 1)
    len = BIO_get_mem_data (bio, &pem);
  if (len > 0)
    return g_bytes_new_with_free_func (pem, len, free_key_bio, bio);
  BIO_free (bio);
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot encode validated host key");
  return NULL;
}

/* Only ciphertext goes to stdout. systemd-creds reads the inputs over pipes. */
static GBytes *
encrypt_credential (const char *name, GBytes *value, gboolean user_scope, GError **error)
{
  g_autofree char *option = g_strdup_printf ("--name=%s", name);
  const char *args[9] = {"/usr/bin/systemd-creds", "--with-key=host", "--pretty", option};
  guint i = 4;
  if (user_scope)
    args[i++] = "--user";
  args[i++] = "encrypt";
  args[i++] = "-";
  args[i++] = "-";
  g_autoptr(GSubprocess) proc = g_subprocess_newv (args,
      G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE, error);
  if (!proc)
    return NULL;
  g_autoptr(GBytes) output = NULL;
  if (!g_subprocess_communicate (proc, value, NULL, &output, NULL, error) ||
      !g_subprocess_wait_check (proc, NULL, error))
    return NULL;
  return g_steal_pointer (&output);
}

static int
service_config (const char *flags, const char *path, gboolean user_scope)
{
  g_autoptr(GError) error = NULL;
  guint64 security;
  if (!g_ascii_string_to_unsigned (flags, 16, 0, G_MAXUINT16, &security, &error))
    {
      fprintf (stderr, "Expected firmware security flags in hexadecimal.\n");
      return 2;
    }
  struct x1fold_version version = {
    .major = 10, .minor = 1, .product = 0x41, .security = (guint16) security
  };
  guint8 reply[802];
  int result_fd = open (path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  struct stat st;
  gboolean complete = result_fd >= 0 && !fstat (result_fd, &st) && S_ISREG (st.st_mode) &&
                      st.st_size == sizeof reply && pread (result_fd, reply, sizeof reply, 0) == sizeof reply;
  if (result_fd >= 0)
    close (result_fd);
  if (!complete)
    {
      fputs ("Expected a complete 802-byte registration response.\n", stderr);
      return 1;
    }
  EVP_PKEY *owner = x1fold_load_host_key_fd (4, &error);
  g_autoptr(GBytes) host = NULL, sensor = NULL;
  gboolean valid = owner && x1fold_check_pair_response (&version, owner, reply, sizeof reply,
                                                        &host, &sensor, &error);
  g_autoptr(GBytes) pem = valid ? encode_owner (owner, &error) : NULL;
  EVP_PKEY_free (owner);
  if (pem)
    {
      const char *names[] = {"x1fold-native.host.cert", "x1fold-native.sensor.cert", "x1fold-native.host-key.pem"};
      GBytes *records[] = {host, sensor, pem};
      g_autoptr(GString) config = g_string_new ("[Service]\nLoadCredentialEncrypted=\n");
      for (guint i = 0; i < G_N_ELEMENTS (records); i++)
        {
          g_autoptr(GBytes) encrypted = encrypt_credential (names[i], records[i], user_scope, &error);
          if (!encrypted)
            break;
          gsize len;
          const char *data = g_bytes_get_data (encrypted, &len);
          g_string_append_len (config, data, len);
          g_string_append_c (config, '\n');
        }
      if (!error)
        return fwrite (config->str, 1, config->len, stdout) == config->len && fflush (stdout) == 0 ? 0 : 1;
    }
  fprintf (stderr, "%s\n", error->message);
  return 1;
}

static int
run (gboolean registration, const guint8 serial[6], const char *issuer_uri, const char *output)
{
  g_autoptr(GError) error = NULL;
  EVP_PKEY *host = x1fold_load_host_key_fd (4, &error);
  if (!host)
    {
      fprintf (stderr, "%s\n", error->message);
      return 1;
    }
  EVP_PKEY *issuer = open_signer (issuer_uri);
  if (!issuer)
    {
      fputs ("Cannot open a single local issuer signing key.\n", stderr);
      EVP_PKEY_free (host);
      return 1;
    }
  g_autoptr(GBytes) request = x1fold_create_host_request (host, issuer, &error);
  g_autoptr(GBytes) returned = NULL, sensor = NULL;
  int rc = 1, dir = -1, out = -1;
  g_autofree char *parent = g_path_get_dirname (output);
  g_autofree char *name = g_path_get_basename (output);
  if (!request)
    goto done;
  if (registration)
    {
      int flags = fcntl (3, F_GETFL);
      if (flags < 0 || fcntl (3, F_SETFL, flags | O_NONBLOCK) < 0)
        {
          perror ("reader fd 3");
          goto done;
        }
    }
  dir = open (parent, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (dir < 0 || (out = openat (dir, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)) < 0)
    {
      perror ("create new output");
      goto done;
    }
  if (!registration)
    {
      if (store_at (out, g_bytes_get_data (request, NULL), g_bytes_get_size (request), 0) &&
          fsync (out) == 0 && fsync (dir) == 0)
        rc = 0;
      else
        perror ("save signed request");
      goto done;
    }
  /* Make room and persist a pending marker before the only device write.
   * Publish a zero status only after both certificate records are durable. */
  guint8 pending[802] = {0xff, 0xff};
  if (!store_at (out, pending, sizeof pending, 0) || fsync (out) || fsync (dir))
    {
      perror ("reserve pairing result");
      goto done;
    }
  X1FoldPairOutcome outcome = x1fold_register_host (3, serial, request, host, issuer, &returned, &sensor,
      g_get_monotonic_time () + 15 * G_TIME_SPAN_SECOND, NULL, &error);
  if (outcome != X1FOLD_PAIR_ACCEPTED)
    {
      const char *states[] = {"Registration not sent", "Registration outcome unknown", "Reader refused registration"};
      fprintf (stderr, "%s\n", states[outcome]);
      goto done;
    }
  const guint8 success[] = {0, 0};
  if (!store_at (out, g_bytes_get_data (returned, NULL), 400, 2) ||
      !store_at (out, g_bytes_get_data (sensor, NULL), 400, 402) || fsync (out) ||
      !store_at (out, success, sizeof success, 0) || fsync (out))
    {
      perror ("reader accepted registration but saving its response failed");
      goto done;
    }
  puts ("Reader accepted registration. Saved both certificates.");
  rc = 0;
done:
  if (error)
    fprintf (stderr, "%s\n", error->message);
  if (out >= 0 && close (out))
    rc = 1;
  if (dir >= 0)
    close (dir);
  EVP_PKEY_free (host);
  EVP_PKEY_free (issuer);
  return rc;
}

int
main (int argc, char **argv)
{
  guint8 serial[6] = {0};
  if ((argc == 4 || (argc == 5 && !strcmp (argv[4], "--user"))) && !strcmp (argv[1], "service-config"))
    return service_config (argv[2], argv[3], argc == 5);
  if (argc == 4 && !strcmp (argv[1], "request"))
    return run (FALSE, serial, argv[2], argv[3]);
  if (argc == 5 && !strcmp (argv[1], "register") && parse_serial (argv[2], serial) && geteuid () != 0)
    return run (TRUE, serial, argv[3], argv[4]);
  fputs ("Usage: native-register request ISSUER-URI NEW-REQUEST\n"
         "       native-register register READER-SERIAL ISSUER-URI NEW-RESPONSE\n"
         "       native-register service-config SECURITY-HEX SAVED-RESPONSE [--user]\n"
         "Supply the host signing key on fd 4. Registration requires an unprivileged process and reader fd 3.\n",
         stderr);
  return 2;
}
