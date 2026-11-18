// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <gio/gio.h>
#include <sys/types.h>

gboolean x1fold_is_descriptor (const guint8 *descriptor, gsize size);
gboolean x1fold_read_serial (int fd, guint8 serial[6], GCancellable *cancellable, GError **error);
int x1fold_open_sensor (const gchar *path, dev_t expected, guint8 serial[6], GCancellable *cancellable, GError **error);
