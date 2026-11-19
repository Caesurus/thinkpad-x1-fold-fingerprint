// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "sensor-certificate.h"

typedef enum {
  X1FOLD_PAIR_NOT_SENT, X1FOLD_PAIR_UNCONFIRMED, X1FOLD_PAIR_REFUSED, X1FOLD_PAIR_ACCEPTED
} X1FoldPairOutcome;

/* Construct the public record locally. Supply the owner's host public key and
 * a signing-provider handle already authorized to issue requests for this
 * reader. No export of either private key is needed. */
GBytes *x1fold_create_host_request (EVP_PKEY *host_public, EVP_PKEY *issuer_signer, GError **error);

/* Erase SSFS and HOST in that order before a new pairing. The caller must
 * persist its new host key first; either format can leave the old pairing
 * unusable. No retry is performed after an uncertain exchange. */
gboolean x1fold_format_pairing_storage (int fd, const guint8 selected_serial[6],
                                        gint64 deadline, GCancellable *cancel, GError **error);

/* Explicit administrative registration on an exclusively claimed, nonblocking
 * reader. Persist the owner's signing key and prepare the 400-byte host
 * request with the issuer accepted by this reader. Supply
 * that issuer's trusted public key independently of the request. The caller
 * must have authorized registration on this particular reader. Provisioning
 * state 3 also occurs on owned readers. Never retry
 * an unconfirmed exchange automatically. Read and validate HOST before PAIR. Persist both returned certificates
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
