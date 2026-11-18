// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "session.h"

typedef enum {
  X1FOLD_CAPTURE_VERIFY,
  X1FOLD_CAPTURE_ENROLL
} X1FoldCapturePurpose;

/* Wait for a new finger-down and frame-ready event for one acquisition. The
 * result is a frame on the reader for a subsequent biometric operation.
 * The ready callback runs synchronously once the reader has been armed. */
gboolean x1fold_capture_frame (X1FoldSession *session, X1FoldCapturePurpose purpose,
                               gint64 deadline, GCancellable *cancel,
                               void (*ready) (gpointer), gpointer user_data, GError **error);
