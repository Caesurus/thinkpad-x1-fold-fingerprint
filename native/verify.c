// SPDX-License-Identifier: LGPL-2.1-or-later
#include "verify.h"
#include <string.h>

enum { MATCH = 0x99, METRICS = 0x9d, LIST = 0x9f, DATA = 0xa1, TEMPLATE = 2, PAYLOAD = 3 };
enum { RECORD_LIMIT = 16384, GUID_SUBJECT = 2 };

struct metadata {
  const guint8 *tuid, *subject, *finger;
};

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
usable_id (const guint8 *id, gsize size)
{
  guint8 any = 0, all = 0xff;
  for (gsize i = 0; i < size; i++)
    {
      any |= id[i];
      all &= id[i];
    }
  return any != 0 && all != 0xff;
}

/* Parse public enrollment metadata. Keep pointers in the authenticated reply
 * only for its lifetime. Reject duplicate identity fields and partial tags. */
static gboolean
decode_metadata (const guint8 *p, gsize len, struct metadata *out, GError **error)
{
  *out = (struct metadata){0};
  while (len >= 6)
    {
      guint tag = le16 (p);
      guint32 n = le32 (p + 2);
      p += 6;
      len -= 6;
      if (n > len)
        goto malformed;
      switch (tag)
        {
        case 0:
          if (out->tuid || n != 16 || !usable_id (p, n))
            goto malformed;
          out->tuid = p;
          break;
        case 1:
          if (out->subject || n != 76)
            goto malformed;
          out->subject = p;
          break;
        case 2:
          if (out->finger || n != 1)
            goto malformed;
          out->finger = p;
          break;
        default:
          break;
        }
      len -= n;
      p += n;
    }
  if (!len && out->tuid && out->subject && out->finger)
    return TRUE;
malformed:
  return invalid (error, "Malformed enrollment metadata");
}

static gboolean
belongs_to (const struct metadata *meta, const struct fold_bio_identity *print)
{
  return le32 (meta->subject) == GUID_SUBJECT && !memcmp (meta->subject + 4, print->guid, 16) &&
         *meta->finger == print->finger;
}

static gboolean
ok_status (guint command, const guint8 *reply, gsize len, GError **error)
{
  if (len < 2)
    return invalid (error, "Missing biometric command status");
  if (le16 (reply) == 0)
    return TRUE;
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Reader command 0x%02x returned 0x%04x",
               command, le16 (reply));
  return FALSE;
}

/* Read only object IDs and enrollment metadata. Template data does not enter
 * the worker. All supported list and payload replies fit one protected record. */
static GBytes *
read_object (X1FoldSession *s, guint8 operation, guint8 kind, const guint8 id[16],
             gint64 deadline, GCancellable *cancel, GError **error)
{
  guint8 cmd[21] = {operation, kind};
  guint8 reply[RECORD_LIMIT];
  gsize length;
  memcpy (cmd + 5, id, 16);
  if (!x1fold_session_command (s, cmd, sizeof cmd, reply, sizeof reply, &length,
                               deadline, cancel, error) || !ok_status (operation, reply, length, error))
    return NULL;
  if (operation == LIST && length >= 4 && length - 4 == 16u * le16 (reply + 2))
    return g_bytes_new (reply + 4, length - 4);
  if (operation == DATA && length >= 8 && length - 8 == le32 (reply + 4))
    return g_bytes_new (reply + 8, length - 8);
  invalid (error, "Invalid enrollment object length");
  return NULL;
}

static gboolean
resolve_print (X1FoldSession *s, const struct fold_bio_identity *print, guint8 tuid[16],
               gint64 deadline, GCancellable *cancel, GError **error)
{
  guint8 all[16];
  memset (all, 0xff, sizeof all);
  g_autoptr(GBytes) list = read_object (s, LIST, TEMPLATE, all, deadline, cancel, error);
  if (!list)
    return FALSE;
  gsize len;
  const guint8 *ids = g_bytes_get_data (list, &len);
  gboolean found = FALSE;
  for (gsize i = 0; i < len; i += 16)
    {
      if (!usable_id (ids + i, 16))
        return invalid (error, "Unexpected template ID in reader directory");
      g_autoptr(GBytes) children = read_object (s, LIST, PAYLOAD, ids + i, deadline, cancel, error);
      if (!children)
        return FALSE;
      gsize child_len;
      const guint8 *payloads = g_bytes_get_data (children, &child_len);
      for (gsize j = 0; j < child_len; j += 16)
        {
          if (!usable_id (payloads + j, 16))
            return invalid (error, "Unexpected payload ID in reader directory");
          g_autoptr(GBytes) payload = read_object (s, DATA, PAYLOAD, payloads + j, deadline, cancel, error);
          if (!payload)
            return FALSE;
          gsize payload_len;
          const guint8 *data = g_bytes_get_data (payload, &payload_len);
          struct metadata meta;
          if (!decode_metadata (data, payload_len, &meta, error))
            return FALSE;
          if (memcmp (meta.tuid, ids + i, 16))
            return invalid (error, "Enrollment payload refers to another template");
          if (belongs_to (&meta, print))
            {
              if (found)
                return invalid (error, "Ambiguous enrollment on reader");
              memcpy (tuid, meta.tuid, 16);
              found = TRUE;
            }
        }
    }
  if (!found)
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "Requested enrollment missing on reader");
  return found;
}

static gboolean
check_frame_quality (X1FoldSession *s, gint64 deadline, GCancellable *cancel,
                     gboolean *acceptable, GError **error)
{
  const guint8 cmd[] = {METRICS, 0, 0, 1, 0};
  guint8 reply[18];
  gsize size;
  if (!x1fold_session_command (s, cmd, sizeof cmd, reply, sizeof reply, &size,
                               deadline, cancel, error) || !ok_status (METRICS, reply, size, error))
    return FALSE;
  if (size != sizeof reply || le32 (reply + 2) != 0x10000 || le32 (reply + 6) != 8)
    return invalid (error, "Unsupported reader image quality report");
  guint32 quality = le32 (reply + 10);
  if (quality > 100)
    return invalid (error, "Invalid reader image quality");
  *acceptable = quality >= 50;
  return TRUE;
}

static gboolean
match_frame (X1FoldSession *s, const struct fold_bio_identity *print, const guint8 tuid[16],
             gint64 deadline, GCancellable *cancel, gboolean *matched, GError **error)
{
  guint8 cmd[29] = {MATCH, 1,0,0,0, 16};
  memcpy (cmd + 13, tuid, 16);
  guint8 reply[1602];
  gsize size;
  if (!x1fold_session_command (s, cmd, sizeof cmd, reply, sizeof reply, &size,
                               deadline, cancel, error))
    return FALSE;
  if (size == 2 && (le16 (reply) == 0x509 || le16 (reply) == 0x683))
    return TRUE;
  if (!ok_status (MATCH, reply, size, error))
    return FALSE;
  if (size < 66 || le32 (reply + 18) != 36 || le32 (reply + 22) != 0 ||
      le32 (reply + 26) != size - 66)
    return invalid (error, "Unsupported reader match result");
  if (!le32 (reply + 30))
    return TRUE;
  struct metadata meta;
  if (!decode_metadata (reply + 66, size - 66, &meta, error))
    return FALSE;
  if (memcmp (meta.tuid, reply + 2, 16))
    return invalid (error, "Conflicting template IDs in reader match result");
  *matched = !memcmp (tuid, meta.tuid, 16) && belongs_to (&meta, print);
  return TRUE;
}

gboolean
x1fold_verify_print (X1FoldSession *s, const struct fold_bio_identity *print,
                     gint64 deadline, GCancellable *cancel, void (*ready) (gpointer),
                     gpointer user_data, gboolean *matched, GError **error)
{
  *matched = FALSE;
  if (!print || !usable_id (print->guid, 16) || !usable_id (print->serial, 6) ||
      print->reserved || print->finger < 1 || print->finger > 10)
    return invalid (error, "Invalid saved enrollment identity");
  struct x1fold_version version;
  if (!x1fold_session_read_version (s, &version, deadline, cancel, error))
    return FALSE;
  if (memcmp (version.serial, print->serial, 6))
    return invalid (error, "Saved enrollment belongs to a different reader");
  guint8 tuid[16];
  gboolean acceptable;
  if (!resolve_print (s, print, tuid, deadline, cancel, error) ||
      !x1fold_capture_frame (s, X1FOLD_CAPTURE_VERIFY, deadline, cancel, ready, user_data, error) ||
      !check_frame_quality (s, deadline, cancel, &acceptable, error))
    return FALSE;
  return !acceptable || match_frame (s, print, tuid, deadline, cancel, matched, error);
}
