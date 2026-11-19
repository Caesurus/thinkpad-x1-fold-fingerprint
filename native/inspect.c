// SPDX-License-Identifier: LGPL-2.1-or-later
/* Caller holds the exclusive reader claim. systemd supplies fd 3.
 * In --paired mode fds 4, 5 and 6 supply the owner's existing pairing. */
#include "capture.h"
#include "host-storage.h"
#include <errno.h>
#include <fcntl.h>
#include "credentials.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void
prompt_touch (gpointer unused)
{
  puts ("Touch the Fold fingerprint reader now.");
  fflush (stdout);
}

static gboolean
inspect_pairing (int fd, const struct x1fold_version *expected, gboolean capture, GError **error)
{
  X1FoldSession *session = x1fold_open_paired_fds (fd, expected, 4, 5, 6,
      g_get_monotonic_time () + 8 * G_TIME_SPAN_SECOND, NULL, error);
  if (!session)
    return FALSE;

  struct x1fold_version confirmed;
  gboolean ok = x1fold_session_read_version (session, &confirmed,
      g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND, NULL, error);
  if (ok)
    {
      if (confirmed.product != expected->product || confirmed.build != expected->build ||
          confirmed.major != expected->major || confirmed.minor != expected->minor ||
          memcmp (expected->serial, confirmed.serial, sizeof expected->serial))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "Authenticated firmware identity did not match discovery");
          ok = FALSE;
        }
      if (ok && capture)
        ok = x1fold_capture_frame (session, X1FOLD_CAPTURE_VERIFY,
                                   g_get_monotonic_time () + 30 * G_TIME_SPAN_SECOND, NULL,
                                   prompt_touch, NULL, error);
      if (!x1fold_session_close (session, g_get_monotonic_time () + 3 * G_TIME_SPAN_SECOND,
                                 NULL, ok ? error : NULL))
        ok = FALSE;
    }
  x1fold_session_free (session);
  gboolean active;
  if (!ok || !x1fold_session_status (fd, &active, error))
    return FALSE;
  if (active)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_BUSY, "Reader still reports an active session");
      return FALSE;
    }
  return TRUE;
}

int
main (int argc, char **argv)
{
  gboolean capture = argc == 3 && !strcmp (argv[2], "--capture");
  gboolean paired = (argc == 2 || capture) && !strcmp (argv[1], "--paired");
  gboolean storage = argc == 2 && !strcmp (argv[1], "--host-storage");
  if (argc != 1 && !paired && !storage)
    {
      fputs ("Usage: native-inspect [--host-storage | --paired [--capture]]\n", stderr);
      return 1;
    }
  const int fd = 3;
  struct stat st;
  struct x1fold_version info;
  g_autoptr(GError) error = NULL;
  gboolean active;
  if (geteuid () == 0 || fstat (fd, &st))
    {
      fputs ("An unprivileged process and an inherited hidraw fd are required\n", stderr);
      return 1;
    }
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      perror ("set nonblocking HID I/O");
      return 1;
    }
  if (!x1fold_check_fd (fd, st.st_rdev, &error) || !x1fold_session_status (fd, &active, &error))
    goto failure;
  if (active)
    {
      puts ("Reader already has an active session");
      return 2;
    }
  if (!x1fold_read_version (fd, &info, FALSE, NULL, &error) ||
      (paired && !inspect_pairing (fd, &info, capture, &error)))
    goto failure;
  if (storage)
    {
      if (info.product != 0x41 || info.major != 10 || info.minor != 1)
        {
          fputs ("Unsupported Fold storage profile\n", stderr);
          return 1;
        }
      gboolean has_pairing;
      if (!x1fold_check_host_storage (fd, &has_pairing, &error))
        goto failure;
      puts (has_pairing ? "HOST contains a checksum-verified pairing record." :
                          "HOST contains no pairing record.");
    }
  if (capture)
    puts ("Reader reported finger down and frame ready. Capture finished and session closed.");
  printf ("%sfirmware %u.%u build %u, product 0x%02x, interface 0x%02x, "
          "provisioning %u, security flags 0x%04x, pairing mode %s\n",
          paired ? "Verified paired session, closed, " : "Reader ",
          info.major, info.minor, info.build, info.product, info.firmware_interface,
          info.provisioning, info.security,
          info.security & X1FOLD_SECURITY_ADVANCED_PAIRING ? "advanced" : "basic");
  return 0;
failure:
  fprintf (stderr, "%s\n", error->message);
  return 1;
}
