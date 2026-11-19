// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "../libfprint/transport.h"
#include <openssl/evp.h>

/* On success the caller owns a validated sensor public key and must release
 * it with EVP_PKEY_free. A certificate alone does not authenticate a session. */
EVP_PKEY *x1fold_sensor_public_key (const struct x1fold_version *version,
                                   const guint8 *record, gsize length, GError **error);
