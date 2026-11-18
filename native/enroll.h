// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "verify.h"

/* Reports each sample after the reader has evaluated it. Returning FALSE
 * cancels enrollment before commit. A retry does not advance enrollment. */
typedef gboolean (*X1FoldSampleReport) (guint percent, gboolean retry, gpointer data);
gboolean x1fold_enroll_print (X1FoldSession *session, const struct fold_bio_identity *print,
                              gint64 deadline, GCancellable *cancel, X1FoldSampleReport report,
                              gpointer data, GError **error);
