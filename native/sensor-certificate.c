// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sensor-certificate.h"
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* N3LGF05W HID v153, public verification points, SEC1 uncompressed form.
 * GET_VERSION security bit 13 selects the second public key on firmware 10.1. */
static const guint8 issuer_points[2][65] = {
  {
    0x04, 0x33, 0xd6, 0x20, 0x8c, 0xa5, 0xf5, 0xda, 0x82, 0x4b, 0x46, 0xea,
    0x1c, 0xa2, 0x5e, 0x67, 0x32, 0x7e, 0xfc, 0x0c, 0x4c, 0xe9, 0x37, 0xd9,
    0xd8, 0x44, 0x12, 0x0d, 0x6c, 0xc0, 0x8b, 0xfe, 0x5d, 0xb9, 0x55, 0xe1,
    0x81, 0xfc, 0x4b, 0xf6, 0xc6, 0x2b, 0x91, 0xaf, 0xcd, 0xf3, 0xb6, 0x1e,
    0xc7, 0x18, 0xdc, 0xe7, 0x08, 0x47, 0x42, 0xc4, 0x1f, 0x57, 0xc1, 0xf0,
    0x77, 0x7c, 0x34, 0xa0, 0xfd,
  },
  {
    0x04, 0xcb, 0x65, 0x62, 0x93, 0xb9, 0x70, 0x18, 0x06, 0xae, 0x3b, 0x1a,
    0x52, 0x08, 0xe4, 0x69, 0xf4, 0x65, 0xa6, 0xa5, 0x19, 0x5b, 0xd8, 0xb7,
    0xe3, 0x9f, 0x23, 0x65, 0x06, 0x11, 0xdc, 0xdf, 0xdc, 0xa7, 0x00, 0x42,
    0x4e, 0xe0, 0x97, 0xb3, 0xc1, 0x59, 0xbe, 0x79, 0x10, 0x89, 0x50, 0x2f,
    0x40, 0xba, 0x57, 0x1e, 0xca, 0x91, 0xb1, 0x06, 0xb4, 0x88, 0x1f, 0x19,
    0x63, 0x7e, 0x44, 0xbf, 0xdc,
  },
};

static EVP_PKEY *
public_point (const guint8 point[65])
{
  char group[] = "prime256v1";
  guint8 encoded[65];
  memcpy (encoded, point, sizeof encoded);
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
    OSSL_PARAM_construct_octet_string (OSSL_PKEY_PARAM_PUB_KEY, encoded, sizeof encoded),
    OSSL_PARAM_construct_end ()
  };
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  EVP_PKEY *key = NULL;
  if (ctx && EVP_PKEY_fromdata_init (ctx) == 1 &&
      EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_PUBLIC_KEY, params) == 1)
    {
      EVP_PKEY_CTX *check = EVP_PKEY_CTX_new_from_pkey (NULL, key, NULL);
      if (!check || EVP_PKEY_public_check (check) != 1)
        g_clear_pointer (&key, EVP_PKEY_free);
      EVP_PKEY_CTX_free (check);
    }
  EVP_PKEY_CTX_free (ctx);
  return key;
}

EVP_PKEY *
x1fold_sensor_public_key (const struct x1fold_version *version, const guint8 *record,
                          gsize length, GError **error)
{
  if (version->product != 0x41 || version->major != 10 || version->minor != 1 ||
      !(version->security & X1FOLD_SECURITY_ADVANCED_PAIRING))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                           "Unknown sensor certificate verification profile");
      return NULL;
    }
  /* Both coordinates occupy 68 little-endian bytes, including high zeroes.
   * The signed part ends just before the two-byte signature length. */
  static const guint8 zeroes[36] = {0};
  if (!record || length != 400 || memcmp (record, "\x3f\x5f\x17\x00", 4) ||
      record[141] != 0 || memcmp (record + 36, zeroes, 36) ||
      memcmp (record + 104, zeroes, 36))
    goto invalid;

  guint siglen = record[142] | (record[143] << 8);
  if (siglen < 8 || siglen > 72)
    goto invalid;
  EVP_PKEY *issuer = public_point (issuer_points[(version->security >> 13) & 1]);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  gboolean valid = issuer && ctx &&
                   EVP_DigestVerifyInit (ctx, NULL, EVP_sha256 (), NULL, issuer) == 1 &&
                   EVP_DigestVerify (ctx, record + 144, siglen, record, 142) == 1;
  EVP_MD_CTX_free (ctx);
  EVP_PKEY_free (issuer);
  if (!valid)
    goto invalid;

  guint8 point[65] = {4};
  for (guint i = 0; i < 32; i++)
    {
      point[1 + i] = record[35 - i];
      point[33 + i] = record[103 - i];
    }
  EVP_PKEY *sensor = public_point (point);
  if (sensor)
    return sensor;
invalid:
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                       "Invalid sensor certificate or issuer signature");
  return NULL;
}
