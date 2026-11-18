/* Read public metadata from a systemd-passed hidraw fd. The caller holds the
 * fprintd device claim. Do not send plaintext commands in an active session. */
#include "../libfprint/transport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int
main (void)
{
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
  if (!x1fold_read_version (fd, &info, FALSE, NULL, &error))
    goto failure;
  printf ("Firmware %u.%u build %u, product 0x%02x, interface 0x%02x, "
          "provisioning %u, security flags 0x%04x\n",
          info.major, info.minor, info.build, info.product, info.firmware_interface,
          info.provisioning, info.security);
  return 0;
failure:
  fprintf (stderr, "%s\n", error->message);
  return 1;
}
