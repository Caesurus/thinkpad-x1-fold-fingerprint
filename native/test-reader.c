// SPDX-License-Identifier: LGPL-2.1-or-later
/* For packet-socket tests only. The test peer signs with a fresh P-256 key. */
#include "sensor-certificate.h"
#include <openssl/x509.h>
#include <sys/stat.h>
#include <unistd.h>

/* The diagnostic's test descriptor is always a socket, including on root-run CI. */
uid_t
__wrap_geteuid (void)
{
  return 65534;
}

gboolean
__wrap_x1fold_check_fd (int fd, dev_t expected, GError **error)
{
  struct stat st;
  return fstat (fd, &st) == 0 && S_ISSOCK (st.st_mode);
}

gboolean
__wrap_x1fold_session_status (int fd, gboolean *active, GError **error)
{
  *active = FALSE;
  return TRUE;
}

EVP_PKEY *
__wrap_x1fold_sensor_public_key (const struct x1fold_version *version, const guint8 *cert,
                                 gsize size, GError **error)
{
  g_assert_cmpuint (size, ==, 400);
  g_assert_cmpmem (cert, 4, "TEST", 4);
  const guint8 *der = cert + 4;
  return d2i_PUBKEY (NULL, &der, size - 4);
}
