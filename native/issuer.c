// SPDX-License-Identifier: LGPL-2.1-or-later
#include "issuer.h"
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <string.h>

EVP_PKEY *
x1fold_derive_issuer (const guint8 context[32], GError **error)
{
  if (!context)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing issuer context");
      return NULL;
    }
  guint8 seed[18], scalar[32] = {0}, public_point[65];
  memcpy (seed, context + 16, 16);
  seed[16] = seed[17] = 0xaa;
  static const guint8 label[] = "HS_KEY_PAIR_GEN";
  size_t size = sizeof scalar;
  EVP_PKEY_CTX *derive = EVP_PKEY_CTX_new_id (EVP_PKEY_TLS1_PRF, NULL);
  gboolean derived = derive && EVP_PKEY_derive_init (derive) == 1 &&
    EVP_PKEY_CTX_set_tls1_prf_md (derive, EVP_sha256 ()) == 1 &&
    EVP_PKEY_CTX_set1_tls1_prf_secret (derive, context, 16) == 1 &&
    EVP_PKEY_CTX_add1_tls1_prf_seed (derive, label, sizeof label - 1) == 1 &&
    EVP_PKEY_CTX_add1_tls1_prf_seed (derive, seed, sizeof seed) == 1 &&
    EVP_PKEY_derive (derive, scalar, &size) == 1 && size == sizeof scalar;
  EVP_PKEY_CTX_free (derive);
  OPENSSL_cleanse (seed, sizeof seed);

  BIGNUM *private = derived ? BN_secure_new () : NULL;
  if (private)
    {
      if (BN_lebin2bn (scalar, sizeof scalar, private))
        BN_set_flags (private, BN_FLG_CONSTTIME);
      else
        g_clear_pointer (&private, BN_clear_free);
    }
  OPENSSL_cleanse (scalar, sizeof scalar);
  EC_GROUP *group = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  EC_POINT *point = group ? EC_POINT_new (group) : NULL;
  EVP_PKEY *key = NULL;
  OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new ();
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *import = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (private && !BN_is_zero (private) && group && point &&
      BN_cmp (private, EC_GROUP_get0_order (group)) < 0 &&
      EC_POINT_mul (group, point, private, NULL, NULL, NULL) == 1 &&
      EC_POINT_point2oct (group, point, POINT_CONVERSION_UNCOMPRESSED,
                         public_point, sizeof public_point, NULL) == sizeof public_point &&
      builder && OSSL_PARAM_BLD_push_utf8_string (builder, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) == 1 &&
      OSSL_PARAM_BLD_push_BN (builder, OSSL_PKEY_PARAM_PRIV_KEY, private) == 1 &&
      OSSL_PARAM_BLD_push_octet_string (builder, OSSL_PKEY_PARAM_PUB_KEY, public_point, sizeof public_point) == 1)
    {
      params = OSSL_PARAM_BLD_to_param (builder);
      if (params && import && EVP_PKEY_fromdata_init (import) == 1 &&
          EVP_PKEY_fromdata (import, &key, EVP_PKEY_KEYPAIR, params) == 1)
        {
          EVP_PKEY_CTX *check = EVP_PKEY_CTX_new_from_pkey (NULL, key, NULL);
          if (!check || EVP_PKEY_pairwise_check (check) != 1)
            g_clear_pointer (&key, EVP_PKEY_free);
          EVP_PKEY_CTX_free (check);
        }
    }
  EVP_PKEY_CTX_free (import);
  OSSL_PARAM_free (params);
  OSSL_PARAM_BLD_free (builder);
  EC_POINT_free (point);
  EC_GROUP_free (group);
  BN_clear_free (private);
  if (!key)
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Issuer derivation failed");
  return key;
}
