// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "../libfprint/transport.h"

/* Requires an exclusive claim on an identified, idle reader. */
gboolean x1fold_check_host_storage (int fd, gboolean *has_pairing, GError **error);
gboolean x1fold_check_host_storage_until (int fd, gboolean *has_pairing, gint64 deadline,
                                          GCancellable *cancel, GError **error);
