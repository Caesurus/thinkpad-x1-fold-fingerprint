// SPDX-License-Identifier: LGPL-2.1-or-later
#include "host-proof.h"
#include <openssl/core_names.h>
#include <string.h>

static gboolean
coordinate_matches (EVP_PKEY *key, const char *name, const guint8 *coordinate)
{
  BIGNUM *value = NULL;
  guint8 encoded[68];
  gboolean matches = EVP_PKEY_get_bn_param (key, name, &value) == 1 &&
                     BN_bn2lebinpad (value, encoded, sizeof encoded) == sizeof encoded &&
                     memcmp (encoded, coordinate, sizeof encoded) == 0;
  BN_free (value);
  return matches;
}

gboolean
x1fold_check_host_identity (const guint8 *cert, gsize cert_len, EVP_PKEY *host_identity,
                            GError **error)
{
  if (!cert || cert_len != 400 ||
      memcmp (cert, "\x3f\x5f\x17\x00", 4) || cert[141] != 2 ||
      cert[142] != 32 || cert[143] != 0 || !host_identity ||
      !EVP_PKEY_is_a (host_identity, "EC") ||
      !coordinate_matches (host_identity, OSSL_PKEY_PARAM_EC_PUB_X, cert + 4) ||
      !coordinate_matches (host_identity, OSSL_PKEY_PARAM_EC_PUB_Y, cert + 72))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "Expected a returned host certificate and its matching signing key");
      return FALSE;
    }
  return TRUE;
}

gboolean
x1fold_build_host_proof (const struct x1fold_server_flight *flight,
                         const guint8 *cert, gsize cert_len, EVP_PKEY *host_identity,
                         GBytes **messages, EVP_PKEY **exchange_key, GError **error)
{
  *messages = NULL;
  *exchange_key = NULL;
  g_return_val_if_fail (flight && flight->transcript, FALSE);
  if (!x1fold_check_host_identity (cert, cert_len, host_identity, error))
    return FALSE;
  /* The Tudor Certificate message repeats the 400-byte length and has two
   * reserved bytes before the certificate. Initialize those bytes explicitly. */
  const guint8 cert_header[] = {11,0,1,0x98, 0,1,0x90, 0,1,0x90, 0,0};
  const guint8 exchange_header[] = {16,0,0,65};
  g_autoptr(GByteArray) out = g_byte_array_sized_new (560);
  g_byte_array_append (out, cert_header, sizeof cert_header);
  g_byte_array_append (out, cert, cert_len);
  g_byte_array_append (out, exchange_header, sizeof exchange_header);

  EVP_PKEY *ephemeral = EVP_PKEY_Q_keygen (NULL, NULL, "EC", "prime256v1");
  EVP_MD_CTX *sign = NULL;
  guint8 point[65];
  size_t point_len = 0;
  if (!ephemeral || EVP_PKEY_parameters_eq (ephemeral, host_identity) != 1 ||
      EVP_PKEY_get_octet_string_param (ephemeral, OSSL_PKEY_PARAM_PUB_KEY, point,
                                       sizeof point, &point_len) != 1 ||
      point_len != sizeof point || point[0] != 4)
    goto failed;
  g_byte_array_append (out, point, sizeof point);
  gsize len;
  const guint8 *prefix = g_bytes_get_data (flight->transcript, &len);
  guint8 signature[72];
  size_t sig_len = sizeof signature;
  sign = EVP_MD_CTX_new ();
  if (!sign || EVP_DigestSignInit (sign, NULL, EVP_sha256 (), NULL, host_identity) != 1 ||
      EVP_DigestSignUpdate (sign, prefix, len) != 1 ||
      EVP_DigestSignUpdate (sign, out->data, out->len) != 1 ||
      EVP_DigestSignFinal (sign, signature, &sig_len) != 1 || sig_len > sizeof signature)
    goto failed;
  const guint8 verify_header[] = {15,0,0,(guint8) sig_len};
  g_byte_array_append (out, verify_header, sizeof verify_header);
  g_byte_array_append (out, signature, sig_len);
  EVP_MD_CTX_free (sign);
  *exchange_key = ephemeral;
  *messages = g_byte_array_free_to_bytes (g_steal_pointer (&out));
  return TRUE;

failed:
  EVP_MD_CTX_free (sign);
  EVP_PKEY_free (ephemeral);
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Preparing host handshake proof failed");
  return FALSE;
}
