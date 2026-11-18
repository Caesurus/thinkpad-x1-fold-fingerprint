// SPDX-License-Identifier: LGPL-2.1-or-later
#include "credentials.h"
#include <openssl/pem.h>
#include <sys/stat.h>
#include <unistd.h>

static GBytes *
certificate_fd (int fd, GError **error)
{
  guint8 record[400];
  struct stat st;
  if (fstat (fd, &st) || !S_ISREG (st.st_mode) || st.st_size != sizeof record ||
      pread (fd, record, sizeof record, 0) != sizeof record)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Expected a 400-byte pairing certificate on fd %d", fd);
      return NULL;
    }
  return g_bytes_new (record, sizeof record);
}

static int
no_password_prompt (char *buf, int size, int writing, void *user)
{
  return -1;
}

X1FoldSession *
x1fold_open_paired_fds (int fd, const struct x1fold_version *expected, int sensor_fd, int host_fd,
                       int key_fd, gint64 deadline, GCancellable *cancel, GError **error)
{
  g_autoptr(GBytes) sensor = certificate_fd (sensor_fd, error);
  if (!sensor)
    return NULL;
  g_autoptr(GBytes) host = certificate_fd (host_fd, error);
  if (!host)
    return NULL;
  struct stat st;
  if (fstat (key_fd, &st) || !S_ISREG (st.st_mode) || st.st_size <= 0 || st.st_size > 16384)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Expected a protected file with the paired host PEM key");
      return NULL;
    }
  BIO *bio = BIO_new_fd (key_fd, BIO_NOCLOSE);
  EVP_PKEY *identity = bio ? PEM_read_bio_PrivateKey (bio, NULL, no_password_prompt, NULL) : NULL;
  BIO_free (bio);
  if (!identity)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Cannot load paired host identity");
      return NULL;
    }
  X1FoldSession *session = x1fold_session_open (fd, expected, sensor, host, identity,
      deadline, cancel, error);
  EVP_PKEY_free (identity);
  return session;
}
