// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "handshake.h"
#include <openssl/evp.h>

gboolean x1fold_check_host_identity (const guint8 *certificate, gsize cert_len,
                                     EVP_PKEY *host_identity, GError **error);

/* Pass the issued host certificate and its owning key from an existing
 * pairing. The returned handshake messages contain only public data.
 * The caller owns the GBytes and the fresh ECDH private key. */
gboolean x1fold_build_host_proof (const struct x1fold_server_flight *flight,
                                  const guint8 *certificate, gsize cert_len,
                                  EVP_PKEY *host_identity, GBytes **messages,
                                  EVP_PKEY **exchange_key, GError **error);
