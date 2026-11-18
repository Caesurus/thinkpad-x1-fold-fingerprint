// SPDX-License-Identifier: LGPL-2.1-or-later
/* This binary links two test-only wrappers for a synthetic peer on a packet
 * socket. All handshake and record exchanges use the production transport. */
#include "session.h"
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <string.h>
#include <unistd.h>

static EVP_PKEY *test_peer;
static gboolean reader_busy;

EVP_PKEY *
__wrap_x1fold_sensor_public_key (const struct x1fold_version *version, const guint8 *cert,
                                 gsize size, GError **error)
{
  g_assert_cmpmem (cert, size, "test reader", 11);
  g_assert_cmpint (EVP_PKEY_up_ref (test_peer), ==, 1);
  return test_peer;
}

gboolean
__wrap_x1fold_session_status (int fd, gboolean *active, GError **error)
{
  *active = reader_busy;
  return TRUE;
}

int
main (int argc, char **argv)
{
  g_assert_cmpint (argc, ==, 3);
  int fd = atoi (argv[1]);
  const char *mode = argv[2];
  struct x1fold_version version = { .major = 10, .minor = 1, .product = 0x41, .security = 0xa10b };
  guint8 reader_der[128];
  ssize_t length = read (fd, reader_der, sizeof reader_der);
  g_assert_cmpint (length, >, 0);
  const guint8 *der = reader_der;
  test_peer = d2i_PUBKEY (NULL, &der, length);
  g_assert_nonnull (test_peer);

  EVP_PKEY *host = EVP_PKEY_Q_keygen (NULL, NULL, "EC", "prime256v1");
  g_assert_nonnull (host);
  guint8 *host_der = NULL;
  int der_len = i2d_PUBKEY (host, &host_der);
  g_assert_cmpint (der_len, >, 0);
  g_assert_cmpint (write (fd, host_der, der_len), ==, der_len);
  OPENSSL_free (host_der);
  guint8 cert[400] = {0x3f,0x5f,23,0};
  cert[141] = 2;
  cert[142] = 32;
  reader_busy = !strcmp (mode, "open-busy");
  BIGNUM *coord = NULL;
  g_assert_cmpint (EVP_PKEY_get_bn_param (host, OSSL_PKEY_PARAM_EC_PUB_X, &coord), ==, 1);
  g_assert_cmpint (BN_bn2lebinpad (coord, cert + 4, 68), ==, 68);
  g_assert_cmpint (EVP_PKEY_get_bn_param (host, OSSL_PKEY_PARAM_EC_PUB_Y, &coord), ==, 1);
  g_assert_cmpint (BN_bn2lebinpad (coord, cert + 72, 68), ==, 68);
  BN_free (coord);
  if (!strcmp (mode, "open-wrong-host"))
    cert[72] ^= 1;
  g_autoptr(GBytes) host_cert = g_bytes_new_static (cert, sizeof cert);
  g_autoptr(GBytes) sensor_cert = g_bytes_new_static ("test reader", 11);
  gint64 deadline = g_get_monotonic_time () + 4 * G_TIME_SPAN_SECOND;
  g_autoptr(GError) error = NULL;
  X1FoldSession *session = x1fold_session_open (fd, &version, sensor_cert, host_cert, host,
                                              deadline, NULL, &error);
  EVP_PKEY_free (test_peer);
  EVP_PKEY_free (host);
  if (g_str_has_prefix (mode, "open-"))
    {
      g_assert_null (session);
      if (reader_busy)
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_BUSY);
      else
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
      return 0;
    }
  if (g_str_has_prefix (mode, "handshake-"))
    {
      g_assert_null (session);
      g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
      return 0;
    }
  g_assert_no_error (error);
  g_assert_nonnull (session);
  const guint8 version_command = 1;
  for (int i = 0; i < 2; i++)
    {
      guint8 reply[38];
      memset (reply, 0xcd, sizeof reply);
      gsize size = 999;
      gboolean ok = x1fold_session_command (session, &version_command, 1, reply, sizeof reply,
                                            &size, deadline, NULL, &error);
      if (i == 1 && g_str_has_prefix (mode, "record-"))
        {
          g_assert_false (ok);
          g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
          g_assert_cmpuint (size, ==, 0);
          for (guint j = 0; j < sizeof reply; j++)
            g_assert_cmphex (reply[j], ==, 0xcd);
          g_clear_error (&error);
          g_assert_false (x1fold_session_command (session, &version_command, 1, reply,
                          sizeof reply, &size, deadline, NULL, &error));
          g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED);
          x1fold_session_free (session);
          return 0;
        }
      g_assert_no_error (error);
      g_assert_true (ok);
      g_assert_cmpuint (size, ==, sizeof reply);
      for (guint j = 0; j < sizeof reply; j++)
        g_assert_cmpuint (reply[j], ==, i + j);
    }
  gboolean closed = x1fold_session_close (session, deadline, NULL, &error);
  if (!strcmp (mode, "close-invalid"))
    {
      g_assert_false (closed);
      g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
    }
  else
    {
      g_assert_no_error (error);
      g_assert_true (closed);
    }
  x1fold_session_free (session);
  return 0;
}
