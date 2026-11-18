// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "sensor-certificate.h"

typedef enum {
  X1FOLD_PAIR_NOT_SENT, X1FOLD_PAIR_UNCONFIRMED, X1FOLD_PAIR_REFUSED, X1FOLD_PAIR_ACCEPTED
} X1FoldPairOutcome;

/* Explicit administrative registration on an exclusively claimed, nonblocking
 * reader. The caller has already persisted the owner's signing key and obtained
 * the 400-byte host request from the issuer accepted by this reader. Supply
 * that issuer's trusted public key independently of the request. The caller
 * must have authorized registration on this particular reader. Provisioning
 * state 3 also occurs on owned readers. Never retry
 * an unconfirmed exchange automatically. Persist both returned certificates
 * before opening a session. This function does not format, reset or reconnect. */
X1FoldPairOutcome x1fold_register_host (int fd, const guint8 selected_serial[6],
                                       GBytes *issued_request, EVP_PKEY *host_key, EVP_PKEY *host_issuer,
                                       GBytes **host_cert, GBytes **sensor_cert, gint64 deadline,
                                       GCancellable *cancel, GError **error);

/* Validate the public records from an already received pairing response.
 * The returned credentials are candidates until an authenticated reconnect. */
gboolean x1fold_check_pair_response (const struct x1fold_version *version, EVP_PKEY *host_key,
                                     const guint8 *reply, gsize size, GBytes **host_cert,
                                     GBytes **sensor_cert, GError **error);
