// SPDX-License-Identifier: LGPL-2.1-or-later
/* Validate normal registration with an ephemeral test issuer and local
 * owner. The optional public fixture exercises the real sensor trust anchor. */
#include "pairing.h"
#include <openssl/pem.h>
#include <string.h>
#include <unistd.h>

enum response { ALLOW, REFUSE, SHORT, WRONG_KEY };
static enum response behavior;
static guint reads, writes, formats, fail_format, short_format;
static gboolean busy, storage_error;
static guint storage_checks;
static guint8 provisioning = 3;
static guint8 security_low = 0x0b;
static guint8 record[400], sensor[400], serial[6] = {1,2,3,4,5,6};

gboolean
__wrap_x1fold_check_fd (int fd, dev_t dev, GError **error)
{
  return fd == STDIN_FILENO;
}

gboolean
__wrap_x1fold_session_status (int fd, gboolean *active, GError **error)
{
  *active = busy;
  return TRUE;
}

gboolean
__wrap_x1fold_check_host_storage_until (int fd, gboolean *present, gint64 deadline,
                                       GCancellable *cancel, GError **error)
{
  g_assert_cmpuint (reads, ==, 1);
  g_assert_cmpuint (writes, ==, 0);
  storage_checks++;
  if (storage_error)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid HOST directory");
      return FALSE;
    }
  *present = FALSE;
  return TRUE;
}

gboolean
__wrap_x1fold_exchange (int fd, const guint8 *cmd, gsize len, guint8 *reply, gsize capacity,
                        gsize *size, gint64 deadline, GCancellable *cancel, GError **error)
{
  memset (reply, 0, capacity);
  if (len == 1)
    {
      g_assert_cmpuint (cmd[0], ==, 1);
      g_assert_cmpuint (capacity, >=, 38);
      reply[10] = 10;
      reply[11] = 1;
      reply[13] = 0x41;
      memcpy (reply + 18, serial, 6);
      reply[24] = security_low;
      reply[25] = 0xa1;
      reply[37] = provisioning;
      *size = 38;
      reads++;
      return TRUE;
    }
  if (len == 2 && cmd[0] == 0x3f)
    {
      g_assert_cmpuint (cmd[1], ==, formats + 1);
      g_assert_cmpuint (capacity, >=, 2);
      formats++;
      reply[0] = fail_format == formats ? 0x4f : 0;
      *size = short_format == formats ? 1 : 2;
      return TRUE;
    }
  writes++;
  g_assert_cmpuint (cmd[0], ==, 0x93);
  g_assert_cmpmem (cmd + 1, len - 1, record, sizeof record);
  g_assert_cmpuint (capacity, >=, 802);
  if (behavior == REFUSE)
    {
      reply[0] = 3;
      reply[1] = 4;
      *size = 2;
      return TRUE;
    }
  memcpy (reply + 2, record, 141);
  reply[143] = 2;
  reply[144] = 32;
  if (behavior == WRONG_KEY)
    reply[6] ^= 1;
  memcpy (reply + 402, sensor, 400);
  *size = behavior == SHORT ? 801 : 802;
  return TRUE;
}

static void
attempt (EVP_PKEY *host, EVP_PKEY *issuer, const guint8 target[6], guint reads_expected,
         guint writes_expected, X1FoldPairOutcome expected)
{
  g_autoptr(GBytes) request = g_bytes_new_static (record, sizeof record);
  g_autoptr(GBytes) host_cert = NULL, sensor_cert = NULL;
  g_autoptr(GError) error = NULL;
  reads = writes = storage_checks = 0;
  g_assert_cmpint (x1fold_register_host (0, target, request, host, issuer, &host_cert, &sensor_cert,
                                         g_get_monotonic_time () + G_TIME_SPAN_SECOND, NULL, &error), ==, expected);
  g_assert_cmpuint (reads, ==, reads_expected);
  g_assert_cmpuint (writes, ==, writes_expected);
  g_assert_cmpuint (storage_checks, ==, writes_expected || storage_error);
  if (expected == X1FOLD_PAIR_ACCEPTED)
    {
      g_assert_no_error (error);
      g_assert_cmpuint (g_bytes_get_size (host_cert), ==, 400);
      g_assert_cmpmem (g_bytes_get_data (sensor_cert, NULL), g_bytes_get_size (sensor_cert), sensor, 400);
    }
  else
    {
      g_assert_nonnull (error);
      g_assert_null (host_cert);
      g_assert_null (sensor_cert);
    }
}

static void
format_attempt (const guint8 target[6], guint expected_reads, guint expected_storage,
                guint expected_formats, gboolean success)
{
  g_autoptr(GError) error = NULL;
  reads = writes = formats = storage_checks = 0;
  gboolean result = x1fold_format_pairing_storage (0, target,
      g_get_monotonic_time () + G_TIME_SPAN_SECOND, NULL, &error);
  g_assert_cmpint (result, ==, success);
  g_assert_cmpuint (reads, ==, expected_reads);
  g_assert_cmpuint (storage_checks, ==, expected_storage);
  g_assert_cmpuint (formats, ==, expected_formats);
  g_assert_cmpuint (writes, ==, 0);
  if (success)
    g_assert_no_error (error);
  else
    g_assert_nonnull (error);
}

int
main (int argc, char **argv)
{
  EVP_PKEY *host = EVP_PKEY_Q_keygen (NULL, NULL, "EC", "prime256v1");
  EVP_PKEY *issuer = EVP_PKEY_Q_keygen (NULL, NULL, "EC", "prime256v1");
  g_assert_nonnull (host);
  g_assert_nonnull (issuer);
  g_autoptr(GBytes) generated = x1fold_create_host_request (host, issuer, NULL);
  g_assert_nonnull (generated);
  g_assert_cmpuint (g_bytes_get_size (generated), ==, sizeof record);
  g_autoptr(GError) preflight_error = NULL;
  g_assert_true (x1fold_validate_host_request (generated, host, issuer, &preflight_error));
  g_assert_no_error (preflight_error);
  guint8 altered[400];
  memcpy (altered, g_bytes_get_data (generated, NULL), sizeof altered);
  altered[4] ^= 1;
  g_autoptr(GBytes) invalid = g_bytes_new (altered, sizeof altered);
  g_assert_false (x1fold_validate_host_request (invalid, host, issuer, &preflight_error));
  g_assert_nonnull (preflight_error);
  g_clear_error (&preflight_error);
  memcpy (record, g_bytes_get_data (generated, NULL), sizeof record);
  guint8 other[6] = {2};
  format_attempt (serial, 1, 1, 2, TRUE);
  format_attempt (NULL, 0, 0, 0, FALSE);
  busy = TRUE;
  format_attempt (serial, 0, 0, 0, FALSE);
  busy = FALSE;
  format_attempt (other, 1, 0, 0, FALSE);
  provisioning = 1;
  format_attempt (serial, 1, 0, 0, FALSE);
  provisioning = 3;
  storage_error = TRUE;
  format_attempt (serial, 1, 1, 0, FALSE);
  storage_error = FALSE;
  fail_format = 1;
  format_attempt (serial, 1, 1, 1, FALSE);
  fail_format = 2;
  format_attempt (serial, 1, 1, 2, FALSE);
  fail_format = 0;
  short_format = 1;
  format_attempt (serial, 1, 1, 1, FALSE);
  short_format = 0;
  attempt (issuer, issuer, serial, 0, 0, X1FOLD_PAIR_NOT_SENT);
  attempt (host, host, serial, 0, 0, X1FOLD_PAIR_NOT_SENT);
  guint8 *der = NULL;
  int der_len = i2d_PUBKEY (host, &der);
  g_assert_cmpint (der_len, >, 0);
  const guint8 *encoded = der;
  EVP_PKEY *public_only = d2i_PUBKEY (NULL, &encoded, der_len);
  g_assert_nonnull (public_only);
  g_assert_null (x1fold_create_host_request (host, public_only, NULL));
  EVP_PKEY *wrong_curve = EVP_PKEY_Q_keygen (NULL, NULL, "EC", "secp384r1");
  g_assert_nonnull (wrong_curve);
  g_assert_null (x1fold_create_host_request (wrong_curve, issuer, NULL));
  g_assert_null (x1fold_create_host_request (host, wrong_curve, NULL));
  EVP_PKEY_free (wrong_curve);
  attempt (public_only, issuer, serial, 0, 0, X1FOLD_PAIR_NOT_SENT);
  EVP_PKEY_free (public_only);
  OPENSSL_free (der);
  record[145] ^= 1;
  attempt (host, issuer, serial, 0, 0, X1FOLD_PAIR_NOT_SENT);
  record[145] ^= 1;
  busy = TRUE;
  attempt (host, issuer, serial, 0, 0, X1FOLD_PAIR_NOT_SENT);
  busy = FALSE;
  attempt (host, issuer, other, 1, 0, X1FOLD_PAIR_NOT_SENT);
  provisioning = 1;
  attempt (host, issuer, serial, 1, 0, X1FOLD_PAIR_NOT_SENT);
  provisioning = 3;
  security_low = 0x0a;
  attempt (host, issuer, serial, 1, 0, X1FOLD_PAIR_NOT_SENT);
  security_low = 0x0b;
  storage_error = TRUE;
  attempt (host, issuer, serial, 1, 0, X1FOLD_PAIR_NOT_SENT);
  storage_error = FALSE;
  behavior = REFUSE;
  attempt (host, issuer, serial, 1, 1, X1FOLD_PAIR_REFUSED);
  behavior = SHORT;
  attempt (host, issuer, serial, 1, 1, X1FOLD_PAIR_UNCONFIRMED);
  behavior = WRONG_KEY;
  attempt (host, issuer, serial, 1, 1, X1FOLD_PAIR_UNCONFIRMED);
  behavior = ALLOW;
  attempt (host, issuer, serial, 1, 1, X1FOLD_PAIR_UNCONFIRMED);
  if (argc == 4)
    {
      g_autofree gchar *response = NULL;
      gsize size;
      g_assert_true (g_file_get_contents (argv[1], &response, &size, NULL));
      g_assert_cmpuint (size, ==, 802);
      memcpy (sensor, response + 402, 400);
      attempt (host, issuer, serial, 1, 1, X1FOLD_PAIR_ACCEPTED);
      BIO *bio = BIO_new_file (argv[2], "r");
      g_assert_nonnull (bio);
      EVP_PKEY *recorded_host = PEM_read_bio_PUBKEY (bio, NULL, NULL, NULL);
      BIO_free (bio);
      g_assert_nonnull (recorded_host);
      struct x1fold_version v = {.product = 0x41, .major = 10, .minor = 1, .security = 0xa10b};
      g_autoptr(GBytes) returned = NULL, device = NULL;
      g_assert_true (x1fold_check_pair_response (&v, recorded_host, (guint8 *) response, size,
                                                 &returned, &device, NULL));
      g_autofree gchar *captured_request = NULL;
      g_assert_true (g_file_get_contents (argv[3], &captured_request, &size, NULL));
      g_assert_cmpuint (size, ==, 401);
      g_assert_cmpuint ((guint8) captured_request[0], ==, 0x93);
      g_assert_cmpmem (captured_request + 5, 136, response + 6, 136);
      g_autoptr(GBytes) reconstructed = x1fold_create_host_request (recorded_host, issuer, NULL);
      g_assert_nonnull (reconstructed);
      g_assert_cmpmem (g_bytes_get_data (reconstructed, NULL), 142, captured_request + 1, 142);
      guint8 *raw = (guint8 *) captured_request + 1;
      guint siglen = raw[142] | ((guint) raw[143] << 8);
      g_assert_cmpuint (siglen, <=, 72);
      EVP_MD_CTX *verify = EVP_MD_CTX_new ();
      g_assert_cmpint (EVP_DigestVerifyInit (verify, NULL, EVP_sha256 (), NULL, recorded_host), ==, 1);
      g_assert_cmpint (EVP_DigestVerify (verify, raw + 144, siglen, raw, 142), ==, 0);
      EVP_MD_CTX_free (verify);
      EVP_PKEY_free (recorded_host);
    }
  EVP_PKEY_free (issuer);
  EVP_PKEY_free (host);
  return 0;
}
