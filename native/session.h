// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "sensor-certificate.h"

typedef struct x1fold_session X1FoldSession;

/* Use an exclusively claimed, identified, nonblocking reader and an existing
 * pairing for that reader. Keep fd open and serialize operations until close.
 * The returned object has verified the server Finished for this exchange. */
X1FoldSession *x1fold_session_open (int fd, const struct x1fold_version *version,
                                    GBytes *sensor_cert, GBytes *host_cert,
                                    EVP_PKEY *host_identity, gint64 deadline,
                                    GCancellable *cancel, GError **error);

/* Single-record exchanges. Reply is published only after tag verification.
 * An I/O or authentication failure invalidates the session. */
gboolean x1fold_session_command (X1FoldSession *session, const guint8 *command,
                                 gsize size, guint8 *reply, gsize capacity,
                                 gsize *received, gint64 deadline,
                                 GCancellable *cancel, GError **error);
gboolean x1fold_session_close (X1FoldSession *session, gint64 deadline,
                               GCancellable *cancel, GError **error);
void x1fold_session_free (X1FoldSession *session);
