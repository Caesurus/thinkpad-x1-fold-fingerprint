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

gboolean
x1fold_check_fd (int fd, dev_t expected, GError **error)
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

static gboolean
invalid_reply (GError **error)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Tudor reply envelope");
  return FALSE;
}

static guint32
read_le32 (const guint8 *bytes)
{
  guint32 value;
  memcpy (&value, bytes, sizeof value);
  return GUINT32_FROM_LE (value);
}

static ssize_t
transfer_report (int fd, guint8 *report, gsize size, gboolean writing, gint64 deadline,
                 GCancellable *cancellable, GError **error)
{
  struct pollfd pfd = { .fd = fd, .events = writing ? POLLOUT : POLLIN };
  while (TRUE)
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        return -1;
      gint64 remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "Fingerprint HID timed out");
          return -1;
        }
      int rc = poll (&pfd, 1, (MIN (remaining, 100000) + 999) / 1000);
      if (rc < 0 && errno != EINTR)
        {
          sys_error ("poll fingerprint HID", error);
          return -1;
        }
      if (rc <= 0)
        continue;
      if (!(pfd.revents & pfd.events))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED, "Fingerprint HID disconnected");
          return -1;
        }
      ssize_t n = writing ? write (fd, report, size) : read (fd, report, size);
      if (n < 0 && (errno == EINTR || errno == EAGAIN))
        continue;
      if (n < 0)
        sys_error (writing ? "write fingerprint HID" : "read fingerprint HID", error);
      return n;
    }
}

gboolean
x1fold_exchange (int fd, const guint8 *command, gsize command_len,
                 guint8 *reply, gsize capacity, gsize *reply_len, gint64 deadline,
                 GCancellable *cancellable, GError **error)
{
  *reply_len = 0;
  if (!command || !command_len || command_len > 248u * 16384u || (!reply && capacity))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid Tudor exchange");
      return FALSE;
    }
  for (gsize offset = 0; offset < command_len; offset += 248)
    {
      guint8 envelope[14 + 248] = "synaptic";
      gsize chunk = MIN (248, command_len - offset);
      guint32 fragment_size = GUINT32_TO_LE (chunk + 2);
      guint16 sequence = offset + chunk == command_len ? 0x80ff : offset / 248;
      sequence = GUINT16_TO_LE (sequence | (offset == 0 ? 0x4000 : 0));
      memcpy (envelope + 8, &fragment_size, 4);
      memcpy (envelope + 12, &sequence, 2);
      memcpy (envelope + 14, command + offset, chunk);
      for (gsize pos = 0; pos < 14 + chunk; pos += 19)
        {
          guint8 report[20] = {0x0e};
          memcpy (report + 1, envelope + pos, MIN (19, 14 + chunk - pos));
          ssize_t n = transfer_report (fd, report, sizeof report, TRUE, deadline, cancellable, error);
          if (n < 0)
            return FALSE;
          if (n != sizeof report)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Short fingerprint HID write");
              return FALSE;
            }
        }
    }

  gsize total = 0, used = 0, fragment_left = 0;
  while (TRUE)
    {
      guint8 report[65];
      ssize_t n = transfer_report (fd, report, sizeof report, FALSE, deadline, cancellable, error);
      if (n < 0)
        return FALSE;
      if (n == 20 && report[0] == 0x10)
        continue;
      if (n != 64 || report[0] != 0x0f)
        return invalid_reply (error);
      gsize pos = 1;
      if (!fragment_left)
        {
          if (memcmp (report + 1, "synaptic", 8))
            return invalid_reply (error);
          guint32 fragment = read_le32 (report + 9);
          guint prefix = used == 0 ? 4 : 0;
          pos = 13 + prefix;
          if (prefix)
            total = read_le32 (report + 13);
          if (total > capacity || fragment != MIN (249u - prefix, total - used) + prefix)
            return invalid_reply (error);
          fragment_left = fragment - prefix;
        }
      gsize take = MIN (64 - pos, fragment_left);
      if (take)
        memcpy (reply + used, report + pos, take);
      used += take;
      fragment_left -= take;
      if (used == total)
        {
          *reply_len = total;
          return TRUE;
        }
    }
}

gboolean
x1fold_session_status (int fd, gboolean *active, GError **error)
{
  guint8 feature[20] = {0x11};
  int n = ioctl (fd, HIDIOCGFEATURE (sizeof feature), feature);
  if (n < 0)
    return sys_error ("read session status", error);
  if (n != sizeof feature || feature[0] != 0x11 || memcmp (feature + 1, "synaptic", 8) ||
      read_le32 (feature + 9) < 1 || read_le32 (feature + 9) > 7)
    return invalid_reply (error);
  *active = feature[13] != 0;
  return TRUE;
}

gboolean
x1fold_parse_version (const guint8 *reply, gsize size, struct x1fold_version *info)
{
  if (size != 38 || reply[0] != 0 || reply[1] != 0)
    return FALSE;
  *info = (struct x1fold_version) {
    .build = read_le32 (reply + 6), .major = reply[10], .minor = reply[11],
    .product = reply[13], .security = (guint16) (reply[24] | (reply[25] << 8)),
    .firmware_interface = reply[30], .provisioning = reply[37] & 0x0f
  };
  memcpy (info->serial, reply + 18, sizeof info->serial);
  return TRUE;
}

gboolean
x1fold_read_version (int fd, struct x1fold_version *info, gboolean recover,
                     GCancellable *cancellable, GError **error)
{
  const guint8 version = 1;
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  for (guint attempt = 0; attempt < 2; attempt++)
    {
      guint8 reply[47];
      gsize size;
      if (!x1fold_exchange (fd, &version, 1, reply, sizeof reply, &size, deadline, cancellable, error))
        {
          g_prefix_error (error, "Invalid Tudor GET_VERSION exchange: ");
          return FALSE;
        }
      if (x1fold_parse_version (reply, size, info))
        {
          g_debug ("X1 Fold Tudor firmware %u.%u build %u product 0x%02x",
                   reply[10], reply[11], read_le32 (reply + 6), reply[13]);
          return TRUE;
        }
      /* A previous worker may have exited with an active session. Retry only
       * after a recognized alert and an independent inactive status read. */
      gboolean alert = size >= 5 && reply[0] == 21 && reply[1] == 3 &&
                       ((((guint) reply[3] << 8) | reply[4]) == size - 5);
      gboolean abandoned = size == 2 && reply[0] == 0x15 && reply[1] == 3;
      gboolean active;
      if (recover && attempt == 0 && (alert || abandoned))
        {
          if (!x1fold_session_status (fd, &active, error))
            return FALSE;
          if (!active)
            continue;
        }
      break;
    }
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Tudor GET_VERSION response");
  return FALSE;
}

gboolean
x1fold_read_serial (int fd, guint8 serial[6], GCancellable *cancellable, GError **error)
{
  struct x1fold_version info;
  if (!x1fold_read_version (fd, &info, TRUE, cancellable, error))
    return FALSE;
  memcpy (serial, info.serial, sizeof info.serial);
  return TRUE;
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
  if (!x1fold_check_fd (fd, expected, error) || !x1fold_read_serial (fd, serial, cancellable, error))
    {
      close (fd);
      return -1;
    }
  return fd;
}
