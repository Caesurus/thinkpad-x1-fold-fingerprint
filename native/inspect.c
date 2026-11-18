// SPDX-License-Identifier: LGPL-2.1-or-later
/* Caller holds the exclusive reader claim. systemd supplies fd 3.
 * In --paired mode fds 4, 5 and 6 supply the owner's existing pairing. */
#include "session.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static GBytes *
certificate_fd (int fd, GError **error)
{
  guint8 record[400];
  struct stat st;
  if (fstat (fd, &st) || !S_ISREG (st.st_mode) || st.st_size != sizeof record ||
      pread (fd, record, sizeof record, 0) != sizeof record)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Expected a 400-byte pairing certificate on fd %d", fd);
      return NULL;
    }
  return g_bytes_new (record, sizeof record);
}

static int
no_password_prompt (char *buf, int size, int writing, void *user)
{
  return -1;
}

static gboolean
authenticated_version (int fd, const struct x1fold_version *expected, GError **error)
{
  g_autoptr(GBytes) sensor = certificate_fd (4, error);
  if (!sensor)
    return FALSE;
  g_autoptr(GBytes) host = certificate_fd (5, error);
  if (!host)
    return FALSE;
  struct stat st;
  if (fstat (6, &st) || !S_ISREG (st.st_mode) || st.st_size <= 0 || st.st_size > 16384)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Expected the paired host PEM key on fd 6");
      return FALSE;
    }
  BIO *bio = BIO_new_fd (6, BIO_NOCLOSE);
  EVP_PKEY *identity = bio ? PEM_read_bio_PrivateKey (bio, NULL, no_password_prompt, NULL) : NULL;
  BIO_free (bio);
  if (!identity)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Cannot load paired host identity");
      return FALSE;
    }
  X1FoldSession *session = x1fold_session_open (fd, expected, sensor, host, identity,
      g_get_monotonic_time () + 8 * G_TIME_SPAN_SECOND, NULL, error);
  EVP_PKEY_free (identity);
  if (!session)
    return FALSE;

  guint8 command = 1, reply[38];
  gsize size;
  struct x1fold_version confirmed;
  gboolean ok = x1fold_session_command (session, &command, 1, reply, sizeof reply, &size,
      g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND, NULL, error);
  if (ok)
    {
      if (!x1fold_parse_version (reply, size, &confirmed) ||
          confirmed.product != expected->product || confirmed.build != expected->build ||
          confirmed.major != expected->major || confirmed.minor != expected->minor ||
          memcmp (expected->serial, confirmed.serial, sizeof expected->serial))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "Authenticated firmware identity did not match discovery");
          ok = FALSE;
        }
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
  gboolean paired = argc == 2 && !strcmp (argv[1], "--paired");
  if (argc != 1 && !paired)
    {
      fputs ("Usage: native-inspect [--paired]\n", stderr);
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
      (paired && !authenticated_version (fd, &info, &error)))
    goto failure;
  printf ("%sfirmware %u.%u build %u, product 0x%02x, interface 0x%02x, "
          "provisioning %u, security flags 0x%04x\n",
          paired ? "Verified paired session, closed, " : "Reader ",
          info.major, info.minor, info.build, info.product, info.firmware_interface,
          info.provisioning, info.security);
  return 0;
failure:
  fprintf (stderr, "%s\n", error->message);
  return 1;
}
