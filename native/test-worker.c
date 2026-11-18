// SPDX-License-Identifier: LGPL-2.1-or-later
/* Exercise the process after the broker handoff. Only this test binary links
 * the simulated HID device and test certificate verifier. */
#include "worker.h"
#include "sensor-certificate.h"
#include <linux/hidraw.h>
#include <openssl/x509.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static gboolean signal_wait;
gboolean __real_x1fold_read_notification (int fd, gint64 deadline, GCancellable *cancel, GError **error);

gboolean
__wrap_x1fold_read_notification (int fd, gint64 deadline, GCancellable *cancel, GError **error)
{
  if (signal_wait)
    g_assert_cmpint (write (fd, "W", 1), ==, 1);
  return __real_x1fold_read_notification (fd, deadline, cancel, error);
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

int
__wrap_ioctl (int fd, unsigned long op, ...)
{
  g_assert_cmpuint (op, ==, HIDIOCSFEATURE (20));
  va_list args;
  va_start (args, op);
  const void *report = va_arg (args, void *);
  va_end (args);
  return write (fd, report, 20);
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

int
main (int argc, char **argv)
{
  g_assert_cmpint (argc, ==, 4);
  signal_wait = g_str_equal (argv[3], "verify-client-cancel");
  int channel = atoi (argv[1]), hid = atoi (argv[2]);
  struct fold_bio_frame request;
  g_assert_cmpint (recv (channel, &request, sizeof request, MSG_TRUNC), ==, sizeof request);
  return x1fold_serve_request (request, channel, hid);
}
