// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "capture.h"
#include "../libfprint/biometric-ipc.h"

/* FOLD_RETRY means capture completed but its quality precluded comparison. */
enum fold_bio_event x1fold_verify_result (X1FoldSession *session, const struct fold_bio_identity *print,
                                          gint64 deadline, GCancellable *cancel, void (*ready) (gpointer),
                                          gpointer user_data, GError **error);

/* Verify requires an existing fprintd print on this authenticated reader.
 * TRUE means the operation completed. matched is set only for a fresh,
 * successful match to the requested template, WinBio subject and finger. */
gboolean x1fold_verify_print (X1FoldSession *session, const struct fold_bio_identity *print,
                              gint64 deadline, GCancellable *cancel, void (*ready) (gpointer),
                              gpointer user_data, gboolean *matched, GError **error);

/* Delete one uniquely bound template or confirm the print is already absent.
 * An acknowledged write is checked against the directory of surviving IDs. */
gboolean x1fold_delete_print (X1FoldSession *session, const struct fold_bio_identity *print,
                              gint64 deadline, GCancellable *cancel, GError **error);
