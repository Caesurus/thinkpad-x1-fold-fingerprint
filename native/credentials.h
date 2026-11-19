// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "session.h"

EVP_PKEY *x1fold_load_host_key_fd (int fd, GError **error);
X1FoldSession *x1fold_open_paired_fds (int reader_fd, const struct x1fold_version *version,
                                      int sensor_fd, int host_fd, int key_fd, gint64 deadline,
                                      GCancellable *cancel, GError **error);
