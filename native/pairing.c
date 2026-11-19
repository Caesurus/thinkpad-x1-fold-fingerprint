// SPDX-License-Identifier: LGPL-2.1-or-later
#include "pairing.h"
#include "host-storage.h"
#include "host-proof.h"
#include <openssl/core_names.h>
#include <string.h>
#include <sys/stat.h>

GBytes *
x1fold_create_host_request (EVP_PKEY *host, EVP_PKEY *signer, GError **error)
{
  guint8 cert[400] = {0x3f, 0x5f, 0x17, 0};
  BIGNUM *x = NULL, *y = NULL;
  gboolean encoded = host && EVP_PKEY_is_a (host, "EC") &&
    EVP_PKEY_get_bn_param (host, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1 &&
    EVP_PKEY_get_bn_param (host, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1 &&
    BN_bn2lebinpad (x, cert + 4, 68) == 68 && BN_bn2lebinpad (y, cert + 72, 68) == 68;
  BN_free (x);
  BN_free (y);
  if (!encoded || !x1fold_host_public_matches (cert, sizeof cert, host))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Expected a P-256 host public key");
      return NULL;
    }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  size_t len = 72;
  gboolean signed_ok = ctx && signer && EVP_PKEY_parameters_eq (host, signer) == 1 &&
    EVP_DigestSignInit (ctx, NULL, EVP_sha256 (), NULL, signer) == 1 &&
    EVP_DigestSign (ctx, cert + 144, &len, cert, 142) == 1 && len >= 8 && len <= 72;
  EVP_MD_CTX_free (ctx);
  if (!signed_ok)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "The configured pairing issuer could not sign");
      return NULL;
    }
  cert[142] = (guint8) len;
  return g_bytes_new (cert, sizeof cert);
}

static gboolean
validate_request (GBytes *request, EVP_PKEY *host, EVP_PKEY *issuer, GError **error)
{
  gsize len;
  const guint8 *r = g_bytes_get_data (request, &len);
  if (!x1fold_host_public_matches (r, len, host) || r[140] || r[141] ||
      !issuer || EVP_PKEY_parameters_eq (host, issuer) != 1)
    goto invalid;
  guint signature_len = r[142] | ((guint) r[143] << 8);
  static const guint8 zeros[256] = {0};
  if (signature_len < 8 || signature_len > 72 ||
      memcmp (r + 144 + signature_len, zeros, sizeof zeros - signature_len))
    goto invalid;
  EVP_MD_CTX *verify = EVP_MD_CTX_new ();
  gboolean signed_request = verify &&
    EVP_DigestVerifyInit (verify, NULL, EVP_sha256 (), NULL, issuer) == 1 &&
    EVP_DigestVerify (verify, r + 144, signature_len, r, 142) == 1;
  EVP_MD_CTX_free (verify);
  if (!signed_request)
    goto invalid;
  /* An owner who only has the public record could not open the ensuing
   * session. Confirm usability of the private key before sending PAIR. */
  static const guint8 proof[] = "X1 Fold host key availability";
  EVP_MD_CTX *sign = EVP_MD_CTX_new ();
  guint8 signature[80];
  size_t n = sizeof signature;
  gboolean can_sign = sign && EVP_DigestSignInit (sign, NULL, EVP_sha256 (), NULL, host) == 1 &&
                      EVP_DigestSign (sign, signature, &n, proof, sizeof proof - 1) == 1;
  EVP_MD_CTX_free (sign);
  if (can_sign)
    return TRUE;
invalid:
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                       "Expected an issuer-approved host request and its usable signing key");
  return FALSE;
}

gboolean
x1fold_check_pair_response (const struct x1fold_version *version, EVP_PKEY *host_key,
                            const guint8 *reply, gsize size, GBytes **host_cert,
                            GBytes **sensor_cert, GError **error)
{
  *host_cert = NULL;
  *sensor_cert = NULL;
  if (!reply || size != 802 || reply[0] || reply[1])
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid pairing reply");
      return FALSE;
    }
  if (!x1fold_check_host_identity (reply + 2, 400, host_key, error))
    return FALSE;
  EVP_PKEY *sensor = x1fold_sensor_public_key (version, reply + 402, 400, error);
  if (!sensor)
    return FALSE;
  EVP_PKEY_free (sensor);
  *host_cert = g_bytes_new (reply + 2, 400);
  *sensor_cert = g_bytes_new (reply + 402, 400);
  return TRUE;
}

static gboolean
check_pair_target (int fd, const guint8 serial[6], struct x1fold_version *version,
                   gint64 deadline, GCancellable *cancel, GError **error)
{
  struct stat st;
  if (fstat (fd, &st) < 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing reader descriptor");
      return FALSE;
    }
  gboolean active;
  if (!x1fold_check_fd (fd, st.st_rdev, error) || !x1fold_session_status (fd, &active, error))
    return FALSE;
  if (active)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_BUSY, "Reader already has an active session");
      return FALSE;
    }
  if (g_cancellable_set_error_if_cancelled (cancel, error))
    return FALSE;
  const guint8 get_version = 1;
  guint8 raw_version[38];
  gsize size;
  if (!x1fold_exchange (fd, &get_version, 1, raw_version, sizeof raw_version, &size, deadline, cancel, error))
    return FALSE;
  if (!x1fold_parse_version (raw_version, size, version) || memcmp (serial, version->serial, 6) ||
      version->product != 0x41 || version->major != 10 || version->minor != 1 ||
      version->provisioning != 3 || !(version->security & X1FOLD_SECURITY_ADVANCED_PAIRING))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Unexpected pairing target or profile");
      return FALSE;
    }
  return TRUE;
}

gboolean
x1fold_format_pairing_storage (int fd, const guint8 serial[6], gint64 deadline,
                               GCancellable *cancel, GError **error)
{
  struct x1fold_version version;
  if (!serial)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing pairing target");
      return FALSE;
    }
  if (!check_pair_target (fd, serial, &version, deadline, cancel, error))
    return FALSE;
  for (guint8 partition = 1; partition <= 2; partition++)
    {
      const guint8 cmd[2] = {0x3f, partition};
      guint8 reply[2];
      gsize size;
      if (g_cancellable_set_error_if_cancelled (cancel, error))
        return FALSE;
      if (!x1fold_exchange (fd, cmd, sizeof cmd, reply, sizeof reply, &size, deadline, cancel, error))
        {
          g_prefix_error (error, "Formatting partition %u: ", partition);
          return FALSE;
        }
      if (size != 2 || reply[0] || reply[1])
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Formatting partition %u failed (status 0x%04x, reply length %zu)",
                       partition, size == 2 ? reply[0] | (reply[1] << 8) : 0xffff, size);
          return FALSE;
        }
    }
  return TRUE;
}

X1FoldPairOutcome
x1fold_register_host (int fd, const guint8 serial[6], GBytes *request, EVP_PKEY *host,
                      EVP_PKEY *issuer, GBytes **host_cert, GBytes **sensor_cert,
                      gint64 deadline, GCancellable *cancel, GError **error)
{
  *host_cert = NULL;
  *sensor_cert = NULL;
  if (!request || !serial)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing pairing request or target");
      return X1FOLD_PAIR_NOT_SENT;
    }
  if (!validate_request (request, host, issuer, error))
    return X1FOLD_PAIR_NOT_SENT;
  struct x1fold_version version;
  if (!check_pair_target (fd, serial, &version, deadline, cancel, error))
    return X1FOLD_PAIR_NOT_SENT;
  gsize size;
  gboolean has_pairing;
  if (!x1fold_check_host_storage_until (fd, &has_pairing, deadline, cancel, error))
    {
      g_prefix_error (error, "Reading HOST before registration: ");
      return X1FOLD_PAIR_NOT_SENT;
    }
  guint8 cmd[401] = {0x93}, reply[802];
  memcpy (cmd + 1, g_bytes_get_data (request, NULL), 400);
  if (g_cancellable_set_error_if_cancelled (cancel, error))
    return X1FOLD_PAIR_NOT_SENT;
  if (g_get_monotonic_time () >= deadline)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "Deadline expired before registration");
      return X1FOLD_PAIR_NOT_SENT;
    }
  if (!x1fold_exchange (fd, cmd, sizeof cmd, reply, sizeof reply, &size, deadline, cancel, error))
    return X1FOLD_PAIR_UNCONFIRMED;
  if (size == 2 && (reply[0] || reply[1]))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Reader declined host registration (0x%04x); HOST pairing record %s",
                   reply[0] | (reply[1] << 8), has_pairing ? "present" : "absent");
      return X1FOLD_PAIR_REFUSED;
    }
  return x1fold_check_pair_response (&version, host, reply, size, host_cert, sensor_cert, error)
         ? X1FOLD_PAIR_ACCEPTED : X1FOLD_PAIR_UNCONFIRMED;
}
