// SPDX-License-Identifier: LGPL-2.1-or-later
/* One unprivileged socket-activated fprintd transaction. */
#include "credentials.h"
#include "verify.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

struct monitor {
  int socket;
  GCancellable *cancel;
};

static gpointer
watch_client (gpointer arg)
{
  struct monitor *m = arg;
  struct pollfd fd = {.fd = m->socket, .events = POLLIN};
  while (poll (&fd, 1, -1) < 0 && errno == EINTR)
    ;
  g_cancellable_cancel (m->cancel);
  return NULL;
}

static enum fold_bio_event
verify (int hid, const struct fold_bio_identity *print, GCancellable *cancel, GError **error)
{
  const char *path = g_getenv ("CREDENTIALS_DIRECTORY");
  const char *names[] = {"sensor.cert", "host.cert", "host-key.pem"};
  int dir = path ? open (path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
  if (dir < 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "Pairing credential directory unavailable");
      return FOLD_ERROR;
    }
  int fds[] = {-1, -1, -1};
  enum fold_bio_event result = FOLD_ERROR;
  for (guint i = 0; i < G_N_ELEMENTS (fds); i++)
    {
      fds[i] = openat (dir, names[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
      if (fds[i] < 0)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "Missing pairing credential %s", names[i]);
          goto done;
        }
    }
  struct stat st;
  int flags = fcntl (hid, F_GETFL);
  if (flags < 0 || fcntl (hid, F_SETFL, flags | O_NONBLOCK) < 0 || fstat (hid, &st))
    goto done;
  struct x1fold_version version;
  gboolean active;
  if (!x1fold_check_fd (hid, st.st_rdev, error) || !x1fold_session_status (hid, &active, error))
    goto done;
  if (active)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_BUSY, "Reader already has an active session");
      goto done;
    }
  if (!x1fold_read_version (hid, &version, FALSE, cancel, error))
    goto done;
  if (memcmp (print->serial, version.serial, sizeof version.serial))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Enrollment reader mismatch");
      goto done;
    }
  X1FoldSession *session = x1fold_open_paired_fds (hid, &version, fds[0], fds[1], fds[2],
      g_get_monotonic_time () + 8 * G_TIME_SPAN_SECOND, cancel, error);
  if (!session)
    goto done;
  gboolean matched;
  gboolean ok = x1fold_verify_print (session, print, g_get_monotonic_time () + 30 * G_TIME_SPAN_SECOND,
                                     cancel, NULL, NULL, &matched, error);
  gboolean closed = x1fold_session_close (session, g_get_monotonic_time () + 3 * G_TIME_SPAN_SECOND,
                                          NULL, ok ? error : NULL);
  x1fold_session_free (session);
  if (ok && closed)
    result = matched ? FOLD_MATCH : FOLD_NO_MATCH;
done:
  for (guint i = 0; i < G_N_ELEMENTS (fds); i++)
    if (fds[i] >= 0)
      close (fds[i]);
  close (dir);
  return g_cancellable_is_cancelled (cancel) ? FOLD_CANCELLED : result;
}

int
main (void)
{
  struct fold_bio_frame frame;
  int channel, hid;
  if (!geteuid () || fold_bio_accept (STDIN_FILENO, &frame, &channel, &hid))
    return 1;
  g_autoptr(GError) error = NULL;
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  struct monitor monitor = {channel, cancel};
  GThread *watcher = g_thread_new ("fprintd-disconnect", watch_client, &monitor);
  frame.event = frame.op == FOLD_VERIFY ? verify (hid, &frame.print, cancel, &error) : FOLD_ERROR;
  close (hid);
  gboolean sent = send (channel, &frame, sizeof frame, MSG_NOSIGNAL) == sizeof frame;
  shutdown (channel, SHUT_RDWR);
  g_thread_join (watcher);
  close (channel);
  if (error)
    fprintf (stderr, "Fold verify: %s\n", error->message);
  return !sent || frame.event == FOLD_ERROR;
}
