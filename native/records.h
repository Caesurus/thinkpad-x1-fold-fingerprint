// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "verify.h"

struct x1fold_match_result {
  const guint8 *template_id;
  const guint8 *identity;
  gsize identity_len;
  guint32 score;
};

/* Both statuses mean the captured frame matched no requested template. */
gboolean x1fold_match_is_no_match (const guint8 *reply, gsize size);

/* The returned views borrow storage from the successful match reply. */
gboolean x1fold_parse_match_result (const guint8 *reply, gsize size,
                                    struct x1fold_match_result *result, GError **error);

/* Internal operations shared by authenticated enrollment and deletion. */
GBytes *x1fold_enrollment_directory (X1FoldSession *s, const struct fold_bio_identity *print,
                                     guint8 tuid[16], gboolean *found, gint64 deadline,
                                     GCancellable *cancel, GError **error);
gboolean x1fold_directory_delta (GBytes *larger, GBytes *smaller, const guint8 target[16]);
