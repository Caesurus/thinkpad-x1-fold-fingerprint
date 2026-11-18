// SPDX-License-Identifier: LGPL-2.1-or-later
#include "transport.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static const guint8 descriptor[] = {
  0x06, 0x00, 0xff, 0x09, 0x01, 0xa1, 0x01, 0x85, 0x0e, 0x09, 0x02, 0x15,
  0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x13, 0x91, 0x02, 0x85, 0x0f,
  0x09, 0x06, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x3f, 0x81,
  0x02, 0x85, 0x10, 0x09, 0x05, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
  0x95, 0x13, 0x81, 0x02, 0x85, 0x11, 0x09, 0x07, 0x15, 0x00, 0x26, 0xff,
  0x00, 0x75, 0x08, 0x95, 0x13, 0xb1, 0x02, 0xc0
};

gboolean
x1fold_is_descriptor (const guint8 *data, gsize size)
{
  return size == sizeof descriptor && memcmp (descriptor, data, size) == 0;
}

static gboolean
sys_error (const char *operation, GError **error)
{
  int saved = errno;
  g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved), "%s: %s", operation, g_strerror (saved));
  return FALSE;
}

static gboolean
check_fd (int fd, dev_t expected, GError **error)
{
  struct stat st;
  struct hidraw_devinfo info;
  int size;
  struct hidraw_report_descriptor desc = { 0 };
  if (fstat (fd, &st) < 0)
    return sys_error ("fstat", error);
  if (!S_ISCHR (st.st_mode) || st.st_rdev != expected)
    goto mismatch;
  if (ioctl (fd, HIDIOCGRAWINFO, &info) < 0 || ioctl (fd, HIDIOCGRDESCSIZE, &size) < 0)
    return sys_error ("HID identity", error);
  if (info.bustype != BUS_USB || info.vendor != 0x17ef || info.product != 0x6142 || size != sizeof descriptor)
    goto mismatch;
  desc.size = size;
  if (ioctl (fd, HIDIOCGRDESC, &desc) < 0)
    return sys_error ("HID report descriptor", error);
  if (x1fold_is_descriptor (desc.value, desc.size))
    return TRUE;
mismatch:
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Opened node does not match the fingerprint HID");
  return FALSE;
}

gboolean
x1fold_read_serial (int fd, guint8 serial[6], GCancellable *cancellable, GError **error)
{
  /* Tudor GET_VERSION, single fragment, index 0xff, first and last flags. */
  const guint8 request[20] = { 0x0e, 's','y','n','a','p','t','i','c', 3,0,0,0, 0xff,0xc0, 1 };
  const guint8 header[] = { 0x0f, 's','y','n','a','p','t','i','c', 42,0,0,0, 38,0,0,0, 0,0 };
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  gboolean sent = FALSE, recovered = FALSE;
  while (TRUE)
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        return FALSE;
      gint64 remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "GET_VERSION timed out");
          return FALSE;
        }
      struct pollfd pfd = { .fd = fd, .events = sent ? POLLIN : POLLOUT };
      int rc = poll (&pfd, 1, MIN (100, (remaining + 999) / 1000));
      if (rc < 0 && errno != EINTR)
        return sys_error ("poll", error);
      if (rc <= 0)
        continue;
      if (!(pfd.revents & pfd.events))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED, "Fingerprint HID disconnected");
          return FALSE;
        }
      if (!sent)
        {
          ssize_t n = write (fd, request, sizeof request);
          if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
          if (n < 0)
            return sys_error ("write GET_VERSION", error);
          if (n != sizeof request)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Short HID write");
              return FALSE;
            }
          sent = TRUE;
          continue;
        }

      guint8 report[65];
      ssize_t n = read (fd, report, sizeof report);
      if (n < 0 && (errno == EINTR || errno == EAGAIN))
        continue;
      if (n < 0)
        return sys_error ("read GET_VERSION", error);
      if (n == 20 && report[0] == 0x10)
        continue;
      /* After an interrupted worker, GET_VERSION can produce a TLS alert and
       * close its abandoned session. Confirm the hardware flag before retrying. */
      if (!recovered && n == 64 && memcmp (report, header, 9) == 0)
        {
          guint32 size, chunk;
          memcpy (&size, report + 13, 4);
          memcpy (&chunk, report + 9, 4);
          size = GUINT32_FROM_LE (size);
          chunk = GUINT32_FROM_LE (chunk);
          gboolean alert = size >= 5 && size <= 47 && report[17] == 21 &&
                           report[18] == 3 && ((((guint) report[20] << 8) | report[21]) == size - 5);
          gboolean abandoned = size == 2 && report[17] == 0x15 && report[18] == 3;
          if (chunk == size + 4 && (alert || abandoned))
            {
              guint8 feature[20] = {0x11};
              if (ioctl (fd, HIDIOCGFEATURE (sizeof feature), feature) == sizeof feature &&
                  memcmp (feature + 1, "synaptic", 8) == 0 && feature[9] >= 1 && feature[9] <= 7 &&
                  !feature[10] && !feature[11] && !feature[12] && !feature[13])
                {
                  recovered = TRUE;
                  sent = FALSE;
                  continue;
                }
            }
        }
      if (n != 64 || memcmp (report, header, sizeof header) != 0)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Tudor GET_VERSION response");
          return FALSE;
        }
      /* Status, build date, build number, eight version/product bytes, then serial. */
      memcpy (serial, report + 35, 6);
      guint32 build;
      memcpy (&build, report + 23, sizeof build);
      g_debug ("X1 Fold Tudor firmware %u.%u build %u product 0x%02x",
               report[27], report[28], GUINT32_FROM_LE (build), report[30]);
      return TRUE;
    }
}

int
x1fold_open_sensor (const gchar *path, dev_t expected, guint8 serial[6], GCancellable *cancellable, GError **error)
{
  int fd = open (path, O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    {
      sys_error ("open fingerprint HID", error);
      return -1;
    }
  if (!check_fd (fd, expected, error) || !x1fold_read_serial (fd, serial, cancellable, error))
    {
      close (fd);
      return -1;
    }
  return fd;
}
