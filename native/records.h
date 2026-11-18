// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "verify.h"

/* Internal operations shared by authenticated enrollment and deletion. */
GBytes *x1fold_enrollment_directory (X1FoldSession *s, const struct fold_bio_identity *print,
                                     guint8 tuid[16], gboolean *found, gint64 deadline,
                                     GCancellable *cancel, GError **error);
gboolean x1fold_directory_delta (GBytes *larger, GBytes *smaller, const guint8 target[16]);
