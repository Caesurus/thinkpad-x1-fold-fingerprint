// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "../libfprint/transport.h"

/* The unauthenticated transcript is needed for CertificateVerify and Finished.
 * GBytes contains handshake messages starting with ClientHello, without HID,
 * command or TLS record headers. */
struct x1fold_server_flight {
  guint8 client_random[32], server_random[32];
  GBytes *transcript;
};

/* Start a full handshake on an exclusively claimed, idle, paired device.
 * On success the caller owns the transcript and must unref it. The caller must
 * complete or tear down the handshake before starting another operation. */
gboolean x1fold_request_server_flight (int fd, gint64 deadline,
                                       GCancellable *cancel,
                                       struct x1fold_server_flight *result,
                                       GError **error);
