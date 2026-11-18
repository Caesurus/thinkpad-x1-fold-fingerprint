// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "capture.h"
#include "../libfprint/biometric-ipc.h"

/* Verify requires an existing fprintd print on this authenticated reader.
 * TRUE means the operation completed. matched is set only for a fresh,
 * successful match to the requested template, WinBio subject and finger. */
gboolean x1fold_verify_print (X1FoldSession *session, const struct fold_bio_identity *print,
                              gint64 deadline, GCancellable *cancel, void (*ready) (gpointer),
                              gpointer user_data, gboolean *matched, GError **error);
