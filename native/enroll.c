// SPDX-License-Identifier: LGPL-2.1-or-later
#include "enroll.h"
#include "records.h"
#include <string.h>

enum { ENROLL = 0x96, MATCH = 0x99, START = 1, ADD = 2, COMMIT = 3, FINISH = 4 };

static guint16
u16 (const guint8 *p)
{
  return p[0] | ((guint16) p[1] << 8);
}

static guint32
u32 (const guint8 *p)
{
  guint32 n;
  memcpy (&n, p, sizeof n);
  return GUINT32_FROM_LE (n);
}

static gboolean
bad (GError **error, const char *reason)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, reason);
  return FALSE;
}

static gboolean
enroll_command (X1FoldSession *s, const guint8 *cmd, gsize len, guint8 *reply, gsize expected,
                gint64 deadline, GCancellable *cancel, GError **error)
{
  gsize received;
  if (!x1fold_session_command (s, cmd, len, reply, expected, &received, deadline, cancel, error))
    return FALSE;
  if (received >= 2 && u16 (reply))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Enrollment step %u returned 0x%04x",
                   cmd[1], u16 (reply));
      return FALSE;
    }
  return received == expected || bad (error, "Unexpected enrollment response length");
}

/* Check this captured frame against the existing directory before adding it
 * to the temporary template. Only a definite matcher rejection permits ADD. */
static gboolean
check_duplicate (X1FoldSession *s, GBytes *existing, gint64 deadline, GCancellable *cancel, GError **error)
{
  gsize len;
  const guint8 *ids = g_bytes_get_data (existing, &len);
  if (!len)
    return TRUE;
  guint32 le_length = GUINT32_TO_LE ((guint32) len);
  g_autofree guint8 *cmd = g_malloc0 (13 + len);
  cmd[0] = MATCH;
  cmd[1] = 1;
  memcpy (cmd + 5, &le_length, 4);
  memcpy (cmd + 13, ids, len);
  guint8 reply[1602];
  gsize received;
  if (!x1fold_session_command (s, cmd, 13 + len, reply, sizeof reply, &received, deadline, cancel, error))
    return FALSE;
  if (received == 2 && u16 (reply) == 0x509)
    return TRUE;
  struct x1fold_match_result result;
  if (!x1fold_parse_match_result (reply, received, &result, error))
    return FALSE;
  if (result.score)
    for (gsize i = 0; i < len; i += 16)
      if (!memcmp (ids + i, result.template_id, 16))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_EXISTS, "Reader matched an existing fingerprint");
          return FALSE;
        }
  return bad (error, "Reader did not rule out a duplicate fingerprint");
}

static gboolean
collect_samples (X1FoldSession *s, GBytes *existing, guint8 tuid[16], gint64 deadline,
                 GCancellable *cancel, X1FoldSampleReport report, gpointer data, GError **error)
{
  const guint8 add[] = {ENROLL, ADD, 0, 0, 0};
  guint previous = 0;
  while (previous < 100)
    {
      guint8 reply[82];
      if (!x1fold_capture_frame (s, X1FOLD_CAPTURE_ENROLL, deadline, cancel, NULL, NULL, error) ||
          !check_duplicate (s, existing, deadline, cancel, error) ||
          !enroll_command (s, add, sizeof add, reply, sizeof reply, deadline, cancel, error))
        return FALSE;
      const guint8 *stats = reply + 22;
      guint progress = u16 (stats + 2);
      gboolean rejected = u32 (stats + 28) != 0;
      if (u32 (reply + 18) != 60 || progress > 100 || progress < previous ||
          (rejected && progress != previous) || (progress == 100 && u32 (stats + 48)))
        return bad (error, "Inconsistent enrollment sample statistics");
      gboolean retry = rejected || progress == previous;
      if (report && !report (progress, retry, data))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Enrollment client disconnected");
          return FALSE;
        }
      previous = progress;
      if (progress == 100)
        memcpy (tuid, reply + 2, 16);
    }
  return TRUE;
}

static gboolean
commit_print (X1FoldSession *s, GBytes *existing, const struct fold_bio_identity *print,
              const guint8 tuid[16], gint64 deadline, GCancellable *cancel, GError **error)
{
  guint8 zero[16] = {0}, wildcard[16];
  memset (wildcard, 0xff, sizeof wildcard);
  if (!memcmp (tuid, zero, 16) || !memcmp (tuid, wildcard, 16))
    return bad (error, "Reader supplied an invalid new template ID");
  gsize len;
  const guint8 *ids = g_bytes_get_data (existing, &len);
  for (gsize i = 0; i < len; i += 16)
    if (!memcmp (ids + i, tuid, 16))
      return bad (error, "New template ID is already in use");

  /* Commit header followed by 3 (16-bit tag, 32-bit length, value) fields.
   * The WinBio GUID identity is a 4-byte selector and a 72-byte union. */
  guint8 cmd[124] = {ENROLL, COMMIT};
  cmd[9] = sizeof cmd - 13;
  guint8 *template_field = cmd + 13, *subject = template_field + 6 + 16, *finger = subject + 6 + 76;
  template_field[2] = 16;
  memcpy (template_field + 6, tuid, 16);
  subject[0] = 1;
  subject[2] = 76;
  subject[6] = 2;
  memcpy (subject + 10, print->guid, 16);
  finger[0] = 2;
  finger[2] = 1;
  finger[6] = print->finger;
  guint8 reply[2];
  return enroll_command (s, cmd, sizeof cmd, reply, sizeof reply, deadline, cancel, error);
}

gboolean
x1fold_enroll_print (X1FoldSession *s, const struct fold_bio_identity *print, gint64 deadline,
                     GCancellable *cancel, X1FoldSampleReport report, gpointer data, GError **error)
{
  guint8 tuid[16], recorded[16];
  gboolean found;
  g_autoptr(GBytes) before = x1fold_enrollment_directory (s, print, recorded, &found, deadline, cancel, error);
  if (!before)
    return FALSE;
  if (found)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_EXISTS, "Enrollment identity already exists");
      return FALSE;
    }
  const guint8 start[13] = {ENROLL, START}, finish[5] = {ENROLL, FINISH};
  guint8 started[6], finished[2];
  gsize n;
  if (!x1fold_session_command (s, start, sizeof start, started, sizeof started, &n, deadline, cancel, error))
    return FALSE;
  if (n >= 2 && u16 (started))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Reader refused enrollment start: 0x%04x", u16 (started));
      return FALSE;
    }
  /* A truncated success reply can leave a temporary enrollment active. */
  gboolean ok = ((n == sizeof started && u32 (started + 2) == 0) || bad (error, "Unexpected enrollment start reply")) &&
                collect_samples (s, before, tuid, deadline, cancel, report, data, error) &&
                commit_print (s, before, print, tuid, deadline, cancel, error);
  if (!enroll_command (s, finish, sizeof finish, finished, sizeof finished,
                       g_get_monotonic_time () + 3 * G_TIME_SPAN_SECOND, NULL, ok ? error : NULL) || !ok)
    return FALSE;
  g_autoptr(GBytes) after = x1fold_enrollment_directory (s, print, recorded, &found, deadline, cancel, error);
  if (!after)
    return FALSE;
  return (found && !memcmp (tuid, recorded, 16) && x1fold_directory_delta (after, before, tuid)) ||
         bad (error, "Committed fingerprint could not be confirmed in the reader directory");
}
