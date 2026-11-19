// SPDX-License-Identifier: LGPL-2.1-or-later
#include "issuer.h"
#include <openssl/core_names.h>
#include <stdio.h>

int
main (void)
{
  guint8 context[32], public_point[65];
  if (fread (context, 1, sizeof context, stdin) != sizeof context || fgetc (stdin) != EOF)
    return 2;
  g_autoptr(GError) error = NULL;
  EVP_PKEY *issuer = x1fold_derive_issuer (context, &error);
  OPENSSL_cleanse (context, sizeof context);
  g_assert_no_error (error);
  g_assert_nonnull (issuer);
  size_t size = sizeof public_point;
  g_assert_cmpint (EVP_PKEY_get_octet_string_param (issuer, OSSL_PKEY_PARAM_PUB_KEY,
                                                  public_point, sizeof public_point, &size), ==, 1);
  g_assert_cmpuint (size, ==, sizeof public_point);
  EVP_PKEY_free (issuer);
  return fwrite (public_point, 1, sizeof public_point, stdout) == sizeof public_point ? 0 : 1;
}
