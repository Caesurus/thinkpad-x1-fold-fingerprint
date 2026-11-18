// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <gio/gio.h>
#include <sys/types.h>

struct x1fold_version {
  guint32 build;
  guint16 security;
  guint8 major, minor, product, serial[6], firmware_interface, provisioning;
};

gboolean x1fold_check_fd (int fd, dev_t expected, GError **error);
gboolean x1fold_session_status (int fd, gboolean *active, GError **error);
gboolean x1fold_parse_version (const guint8 *reply, gsize size, struct x1fold_version *version);
gboolean x1fold_read_version (int fd, struct x1fold_version *version, gboolean recover,
                              GCancellable *cancellable, GError **error);
gboolean x1fold_is_descriptor (const guint8 *descriptor, gsize size);
/* One outstanding command on an identified nonblocking reader. On failure
 * discard the partial reply. Deadline is an absolute GLib monotonic time. */
gboolean x1fold_exchange (int fd, const guint8 *command, gsize command_len,
                          guint8 *reply, gsize capacity, gsize *reply_len,
                          gint64 deadline, GCancellable *cancellable, GError **error);
gboolean x1fold_read_serial (int fd, guint8 serial[6], GCancellable *cancellable, GError **error);
int x1fold_open_sensor (const gchar *path, dev_t expected, guint8 serial[6], GCancellable *cancellable, GError **error);
