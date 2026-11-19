// SPDX-License-Identifier: LGPL-2.1-or-later
#include "host-proof.h"
#include <openssl/core_names.h>
#include <string.h>

static gboolean
verify (EVP_PKEY *key, const guint8 *prefix, gsize prefix_len,
        const guint8 *messages, gsize len)
{
  g_assert_cmpuint (len, >=, 485);
  g_assert_cmpuint (messages[481], ==, 15);
  g_assert_cmpuint (messages[484], ==, len - 485);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  g_assert_nonnull (ctx);
  g_assert_cmpint (EVP_DigestVerifyInit (ctx, NULL, EVP_sha256 (), NULL, key), ==, 1);
  g_assert_cmpint (EVP_DigestVerifyUpdate (ctx, prefix, prefix_len), ==, 1);
  g_assert_cmpint (EVP_DigestVerifyUpdate (ctx, messages, 481), ==, 1);
  gboolean valid = EVP_DigestVerifyFinal (ctx, messages + 485, len - 485) == 1;
  EVP_MD_CTX_free (ctx);
  return valid;
}

int
main (void)
{
  EVP_PKEY *identity = EVP_PKEY_Q_keygen (NULL, NULL, "EC", "prime256v1");
  g_assert_nonnull (identity);
  /* Synthetic shape fixture, valid only in this device-free test. */
  guint8 cert[400] = {0x3f,0x5f,23,0};
  cert[141] = 2;
  cert[142] = 32;
  BIGNUM *coord = NULL;
  g_assert_cmpint (EVP_PKEY_get_bn_param (identity, OSSL_PKEY_PARAM_EC_PUB_X, &coord), ==, 1);
  g_assert_cmpint (BN_bn2lebinpad (coord, cert + 4, 68), ==, 68);
  g_assert_cmpint (EVP_PKEY_get_bn_param (identity, OSSL_PKEY_PARAM_EC_PUB_Y, &coord), ==, 1);
  g_assert_cmpint (BN_bn2lebinpad (coord, cert + 72, 68), ==, 68);
  BN_free (coord);

  guint8 prefix[] = {1,0,0,3,3,3,0};
  g_autoptr(GBytes) transcript = g_bytes_new (prefix, sizeof prefix);
  struct x1fold_server_flight flight = { .transcript = transcript };
  guint8 previous_point[65] = {0};
  for (guint i = 0; i < 2; i++)
    {
      g_autoptr(GBytes) messages = NULL;
      EVP_PKEY *ephemeral = NULL;
      g_assert_true (x1fold_build_host_proof (&flight, cert, sizeof cert, identity,
                                               &messages, &ephemeral, NULL));
      gsize length;
      const guint8 *data = g_bytes_get_data (messages, &length);
      guint8 point[65];
      size_t point_len;
      g_assert_cmpint (EVP_PKEY_get_octet_string_param (ephemeral, OSSL_PKEY_PARAM_PUB_KEY,
                                                       point, sizeof point, &point_len), ==, 1);
      const guint8 header[] = {11,0,1,152,0,1,144,0,1,144,0,0};
      g_assert_cmpmem (data, sizeof header, header, sizeof header);
      g_assert_cmpmem (data + 12, 400, cert, 400);
      g_assert_cmpmem (data + 416, 65, point, point_len);
      g_assert_true (memcmp (point, previous_point, 65) != 0);
      memcpy (previous_point, point, 65);
      g_assert_true (verify (identity, prefix, sizeof prefix, data, length));
      prefix[6] ^= 1;
      g_assert_false (verify (identity, prefix, sizeof prefix, data, length));
      prefix[6] ^= 1;
      g_autofree guint8 *tampered = g_memdup2 (data, length);
      tampered[418] ^= 1;
      g_assert_false (verify (identity, prefix, sizeof prefix, tampered, length));
      EVP_PKEY_free (ephemeral);
    }
  cert[72] ^= 1;
  GBytes *messages;
  EVP_PKEY *exchange;
  g_assert_false (x1fold_build_host_proof (&flight, cert, sizeof cert, identity,
                                            &messages, &exchange, NULL));
  g_assert_null (messages);
  g_assert_null (exchange);
  EVP_PKEY_free (identity);
  return 0;
}
