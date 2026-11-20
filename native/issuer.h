// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <gio/gio.h>
#include <openssl/evp.h>

/* Derive a P-256 issuer from the supplied 32-byte profile context. */
EVP_PKEY *x1fold_derive_issuer (const guint8 context[32], GError **error);

/* Reproduce the issuer selected by Lenovo's Fold v153 driver. */
EVP_PKEY *x1fold_fold_issuer (GError **error);
