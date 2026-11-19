// SPDX-License-Identifier: LGPL-2.1-or-later
#include "host-storage.h"
#include <string.h>

enum { INFO = 0x3e, READ_PARTITION = 0x40, HOST = 2, FOLD_HOST_SIZE = 4096 };

static guint16
le16 (const guint8 *p)
{
  return p[0] | ((guint16) p[1] << 8);
}

static guint32
le32 (const guint8 *p)
{
  guint32 value;
  memcpy (&value, p, sizeof value);
  return GUINT32_FROM_LE (value);
}

static gboolean
invalid (GError **error, const char *message)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, message);
  return FALSE;
}

static gboolean
inspect_tags (const guint8 *data, gsize size, gboolean *has_pairing, GError **error)
{
  gboolean version = FALSE, pairing = FALSE;
  g_autoptr(GChecksum) sum = g_checksum_new (G_CHECKSUM_SHA256);
  while (size)
    {
      if (size < 2)
        return invalid (error, "Truncated HOST tag");
      guint tag = le16 (data);
      if (tag == 0xffff)
        break;
      if (size < 36 || le16 (data + 2) > size - 36)
        return invalid (error, "Truncated HOST record");
      guint len = le16 (data + 2);
      const guint8 *body = data + 36;
      guint8 digest[32];
      gsize digest_len = sizeof digest;
      g_checksum_reset (sum);
      g_checksum_update (sum, body, len);
      g_checksum_get_digest (sum, digest, &digest_len);
      if (memcmp (data + 4, digest, sizeof digest))
        return invalid (error, "HOST record checksum mismatch");
      if (tag == 1)
        {
          if (version || len != 4 || le32 (body) != 1)
            return invalid (error, "Unsupported HOST version record");
          version = TRUE;
        }
      if (tag == 2)
        {
          if (pairing || !len)
            return invalid (error, "Invalid HOST pairing record");
          pairing = TRUE;
        }
      data += 36 + len;
      size -= 36 + len;
    }
  if (pairing && !version)
    return invalid (error, "HOST pairing record missing its version");
  *has_pairing = pairing;
  return TRUE;
}

gboolean
x1fold_check_host_storage (int fd, gboolean *has_pairing, GError **error)
{
  *has_pairing = FALSE;
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  const guint8 info = INFO;
  guint8 directory[16 + 16 * 12];
  gsize n;
  if (!x1fold_exchange (fd, &info, 1, directory, sizeof directory, &n, deadline, NULL, error))
    return FALSE;
  if (n < 16 || le16 (directory) || n - 16 != le16 (directory + 14) * 12u)
    return invalid (error, "Invalid partition directory");
  gboolean found = FALSE;
  for (gsize i = 16; i < n; i += 12)
    if (directory[i] == HOST)
      {
        if (found || le32 (directory + i + 8) != FOLD_HOST_SIZE)
          return invalid (error, "Unsupported Fold HOST partition layout");
        found = TRUE;
      }
  if (!found)
    return invalid (error, "Fold HOST partition missing");

  const guint8 cmd[13] = {READ_PARTITION, HOST, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0x10};
  guint8 reply[8 + FOLD_HOST_SIZE];
  gboolean ok = x1fold_exchange (fd, cmd, sizeof cmd, reply, sizeof reply, &n, deadline, NULL, error);
  if (ok && (n != sizeof reply || le16 (reply) || le32 (reply + 2) != FOLD_HOST_SIZE))
    ok = invalid (error, "Invalid Fold HOST read reply");
  if (ok)
    ok = inspect_tags (reply + 8, FOLD_HOST_SIZE, has_pairing, error);
  explicit_bzero (reply, sizeof reply);
  return ok;
}
