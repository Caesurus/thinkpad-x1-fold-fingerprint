// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sensor-certificate.h"

static void
reject (const struct x1fold_version *version, guint8 *cert, gsize length, GIOErrorEnum code)
{
  g_autoptr(GError) error = NULL;
  g_assert_null (x1fold_sensor_public_key (version, cert, length, &error));
  g_assert_error (error, G_IO_ERROR, (int) code);
}

int
main (int argc, char **argv)
{
  struct x1fold_version version = { .product = 0x41, .major = 10, .minor = 1, .security = 0xa10b };
  guint8 malformed[400] = {0x3f, 0x5f, 23};
  reject (&version, malformed, 399, G_IO_ERROR_INVALID_DATA);
  reject (&version, malformed, 400, G_IO_ERROR_INVALID_DATA);
  malformed[142] = 70;
  reject (&version, malformed, 400, G_IO_ERROR_INVALID_DATA);
  if (argc == 2)
    {
      g_autofree gchar *contents = NULL;
      gsize length = 0;
      g_assert_true (g_file_get_contents (argv[1], &contents, &length, NULL));
      guint8 *cert = (guint8 *) contents;
      EVP_PKEY *sensor = x1fold_sensor_public_key (&version, cert, length, NULL);
      g_assert_nonnull (sensor);
      g_assert_cmpint (EVP_PKEY_get_bits (sensor), ==, 256);
      EVP_PKEY_free (sensor);
      version.security ^= (1 << 13);
      reject (&version, cert, length, G_IO_ERROR_INVALID_DATA);
      version.security ^= (1 << 13);
      cert[4] ^= 1;
      reject (&version, cert, length, G_IO_ERROR_INVALID_DATA);
      cert[4] ^= 1;
      cert[145] ^= 1;
      reject (&version, cert, length, G_IO_ERROR_INVALID_DATA);
    }
  version.minor = 2;
  reject (&version, malformed, 400, G_IO_ERROR_NOT_SUPPORTED);
  return 0;
}
