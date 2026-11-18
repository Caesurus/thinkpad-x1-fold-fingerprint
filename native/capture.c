// SPDX-License-Identifier: LGPL-2.1-or-later
#include "capture.h"
#include <string.h>

enum { FINGER_DOWN = 1u << 1, FRAME_READY = 1u << 24, PAGE_SIZE = 32 };
enum { FRAME_ACQUIRE = 0x80, FRAME_FINISH = 0x81, EVENT_CONFIG = 0x86, EVENT_READ = 0x87 };

struct event_queue {
  guint16 seq;
  gboolean legacy;
};

static guint16
le16 (const guint8 *p)
{
  return p[0] | ((guint16) p[1] << 8);
}

static gboolean
bad_reply (guint8 command, GError **error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
               "Invalid reader reply to capture command 0x%02x", command);
  return FALSE;
}

static gboolean
check_status (guint8 command, const guint8 *reply, gsize size, GError **error)
{
  if (size < 2)
    return bad_reply (command, error);
  if (le16 (reply) == 0)
    return TRUE;
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Capture command 0x%02x returned 0x%04x",
               command, le16 (reply));
  return FALSE;
}

static gboolean
configure_events (X1FoldSession *s, guint32 mask, struct event_queue *q, gint64 deadline,
                  GCancellable *cancel, GError **error)
{
  guint8 request[37] = { EVENT_CONFIG }, reply[66];
  guint32 bits = GUINT32_TO_LE (mask);
  memcpy (request + 1, &bits, 4);
  memcpy (request + 17, &bits, 4);
  request[33] = mask ? 0 : 4;
  gsize size;
  if (!x1fold_session_command (s, request, sizeof request, reply, sizeof reply, &size,
                               deadline, cancel, error) ||
      !check_status (EVENT_CONFIG, reply, size, error))
    return FALSE;
  if (size != sizeof reply)
    return bad_reply (EVENT_CONFIG, error);
  q->seq = le16 (reply + 64);
  return TRUE;
}

static gboolean
acquire (X1FoldSession *s, X1FoldCapturePurpose purpose, gint64 deadline,
         GCancellable *cancel, GError **error)
{
  guint8 request[] = {FRAME_ACQUIRE, 0x0c,0,0,0, 1,0,0,0, 1,0,0,8, 1,1,1,0};
  if (purpose == X1FOLD_CAPTURE_VERIFY)
    {
      request[1] = 0x14;
      request[2] = 0x10;
    }
  guint8 reply[2];
  for (guint attempt = 1; ; attempt++)
    {
      gsize size;
      if (!x1fold_session_command (s, request, sizeof request, reply, sizeof reply, &size,
                                   deadline, cancel, error))
        return FALSE;
      if (size != 2 || le16 (reply) != 0x06ea || attempt == 3)
        return check_status (FRAME_ACQUIRE, reply, size, error);
      gint64 remain = deadline - g_get_monotonic_time ();
      if (remain > 0)
        g_usleep (MIN (remain, 100 * G_TIME_SPAN_MILLISECOND));
    }
}

static gboolean
wait_frame (X1FoldSession *s, struct event_queue *q, gint64 deadline,
            GCancellable *cancel, GError **error)
{
  guint32 seen = 0;
  while (TRUE)
    {
      guint8 request[] = {EVENT_READ, q->seq & 0xff, q->seq >> 8, PAGE_SIZE,0, 1,0,0,0};
      guint8 reply[6 + 12 * PAGE_SIZE];
      gsize size;
      if (!x1fold_session_command (s, request, q->legacy ? 5 : sizeof request,
                                   reply, sizeof reply, &size, deadline, cancel, error))
        return FALSE;
      if (!q->legacy && size == 2 && le16 (reply) >= 0x405 && le16 (reply) <= 0x407)
        {
          q->legacy = TRUE;
          continue;
        }
      if (!check_status (EVENT_READ, reply, size, error))
        return FALSE;
      if (size < 6)
        return bad_reply (EVENT_READ, error);
      guint count = le16 (reply + 2), pending = le16 (reply + 4);
      if (count > PAGE_SIZE || size != 6 + 12 * count || (q->legacy && pending < count))
        return bad_reply (EVENT_READ, error);
      if (q->legacy)
        pending -= count;
      if (!count && pending)
        return bad_reply (EVENT_READ, error);
      for (guint i = 0; i < count; i++)
        {
          guint type = reply[6 + 12 * i];
          if (type == 1 || type == 24)
            seen |= 1u << type;
        }
      q->seq += count;
      if (seen == (FINGER_DOWN | FRAME_READY))
        return TRUE;
      if (!pending && !x1fold_session_wait_notification (s, deadline, cancel, error))
        return FALSE;
    }
}

static gboolean
finish (X1FoldSession *s, gint64 deadline, GError **error)
{
  const guint8 cmd = FRAME_FINISH;
  guint8 reply[2];
  gsize size;
  return x1fold_session_command (s, &cmd, 1, reply, sizeof reply, &size, deadline, NULL, error) &&
         check_status (cmd, reply, size, error);
}

gboolean
x1fold_capture_frame (X1FoldSession *s, X1FoldCapturePurpose purpose, gint64 deadline,
                      GCancellable *cancel, void (*ready) (gpointer), gpointer user_data,
                      GError **error)
{
  if (purpose != X1FOLD_CAPTURE_VERIFY && purpose != X1FOLD_CAPTURE_ENROLL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Unknown capture purpose");
      return FALSE;
    }
  struct event_queue queue = {0};
  if (!configure_events (s, FRAME_READY, &queue, deadline, cancel, error))
    return FALSE;
  gboolean acquired = acquire (s, purpose, deadline, cancel, error);
  gboolean listener_requested = FALSE, captured = FALSE;
  if (acquired && configure_events (s, FRAME_READY | FINGER_DOWN, &queue, deadline, cancel, error))
    {
      listener_requested = TRUE;
      if (x1fold_session_listen (s, TRUE, error))
        {
          if (ready)
            ready (user_data);
          captured = wait_frame (s, &queue, deadline, cancel, error);
        }
    }

  /* A deadline or cancellation while waiting for a HID notification leaves
   * the secure channel usable. Give teardown its own bounded I/O window. */
  gint64 cleanup = g_get_monotonic_time () + 3 * G_TIME_SPAN_SECOND;
  if (listener_requested && !x1fold_session_listen (s, FALSE, captured ? error : NULL))
    captured = FALSE;
  if (!configure_events (s, 0, &queue, cleanup, NULL, captured ? error : NULL))
    captured = FALSE;
  if (acquired && !finish (s, cleanup, captured ? error : NULL))
    captured = FALSE;
  return captured;
}
