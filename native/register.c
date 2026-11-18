// SPDX-License-Identifier: LGPL-2.1-or-later
/* Offline request generation and one explicit registration. The owner supplies
 * the host key on fd 4 and a separately configured local issuing provider.
 * A registration additionally needs an exclusively claimed reader on fd 3. */
#include "credentials.h"
#include "pairing.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static EVP_PKEY *
open_signer (const char *uri)
{
  OSSL_STORE_CTX *store = OSSL_STORE_open (uri, UI_null (), NULL, NULL, NULL);
  if (!store)
    return NULL;
  EVP_PKEY *key = NULL;
  if (OSSL_STORE_expect (store, OSSL_STORE_INFO_PKEY) == 1)
    while (!OSSL_STORE_eof (store))
      {
        OSSL_STORE_INFO *info = OSSL_STORE_load (store);
        if (!info)
          {
            if (!OSSL_STORE_eof (store))
              g_clear_pointer (&key, EVP_PKEY_free);
            break;
          }
        if (OSSL_STORE_INFO_get_type (info) == OSSL_STORE_INFO_PKEY)
          {
            if (key)
              {
                OSSL_STORE_INFO_free (info);
                g_clear_pointer (&key, EVP_PKEY_free);
                break;
              }
            key = OSSL_STORE_INFO_get1_PKEY (info);
          }
        OSSL_STORE_INFO_free (info);
      }
  if (OSSL_STORE_close (store) != 1)
    g_clear_pointer (&key, EVP_PKEY_free);
  return key;
}

static gboolean
store_at (int fd, const guint8 *data, gsize size, off_t at)
{
  while (size)
    {
      ssize_t n = pwrite (fd, data, size, at);
      if (n < 0 && errno == EINTR)
        continue;
      if (n == 0)
        errno = EIO;
      if (n <= 0)
        return FALSE;
      data += n;
      size -= n;
      at += n;
    }
  return TRUE;
}

static gboolean
parse_serial (const char *s, guint8 out[6])
{
  if (strlen (s) != 12)
    return FALSE;
  for (guint i = 0; i < 6; i++)
    {
      int hi = g_ascii_xdigit_value (s[2 * i]);
      int lo = g_ascii_xdigit_value (s[2 * i + 1]);
      if (hi < 0 || lo < 0)
        return FALSE;
      out[i] = (hi << 4) | lo;
    }
  static const guint8 blank[6], erased[6] = {255,255,255,255,255,255};
  return memcmp (out, blank, 6) && memcmp (out, erased, 6);
}

static int
run (gboolean registration, const guint8 serial[6], const char *issuer_uri, const char *output)
{
  g_autoptr(GError) error = NULL;
  EVP_PKEY *host = x1fold_load_host_key_fd (4, &error);
  if (!host)
    {
      fprintf (stderr, "%s\n", error->message);
      return 1;
    }
  EVP_PKEY *issuer = open_signer (issuer_uri);
  if (!issuer)
    {
      fputs ("Cannot open a single local issuer signing key.\n", stderr);
      EVP_PKEY_free (host);
      return 1;
    }
  g_autoptr(GBytes) request = x1fold_create_host_request (host, issuer, &error);
  g_autoptr(GBytes) returned = NULL, sensor = NULL;
  int rc = 1, dir = -1, out = -1;
  g_autofree char *parent = g_path_get_dirname (output);
  g_autofree char *name = g_path_get_basename (output);
  if (!request)
    goto done;
  if (registration)
    {
      int flags = fcntl (3, F_GETFL);
      if (flags < 0 || fcntl (3, F_SETFL, flags | O_NONBLOCK) < 0)
        {
          perror ("reader fd 3");
          goto done;
        }
    }
  dir = open (parent, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (dir < 0 || (out = openat (dir, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)) < 0)
    {
      perror ("create new output");
      goto done;
    }
  if (!registration)
    {
      if (store_at (out, g_bytes_get_data (request, NULL), g_bytes_get_size (request), 0) &&
          fsync (out) == 0 && fsync (dir) == 0)
        rc = 0;
      else
        perror ("save signed request");
      goto done;
    }
  /* Make room and persist a pending marker before the only device write.
   * Publish a zero status only after both certificate records are durable. */
  guint8 pending[802] = {0xff, 0xff};
  if (!store_at (out, pending, sizeof pending, 0) || fsync (out) || fsync (dir))
    {
      perror ("reserve pairing result");
      goto done;
    }
  X1FoldPairOutcome outcome = x1fold_register_host (3, serial, request, host, issuer, &returned, &sensor,
      g_get_monotonic_time () + 15 * G_TIME_SPAN_SECOND, NULL, &error);
  if (outcome != X1FOLD_PAIR_ACCEPTED)
    {
      const char *states[] = {"Registration not sent", "Registration outcome unknown", "Reader refused registration"};
      fprintf (stderr, "%s\n", states[outcome]);
      goto done;
    }
  const guint8 success[] = {0, 0};
  if (!store_at (out, g_bytes_get_data (returned, NULL), 400, 2) ||
      !store_at (out, g_bytes_get_data (sensor, NULL), 400, 402) || fsync (out) ||
      !store_at (out, success, sizeof success, 0) || fsync (out))
    {
      perror ("reader accepted registration but saving its response failed");
      goto done;
    }
  puts ("Reader accepted registration. Saved both certificates.");
  rc = 0;
done:
  if (error)
    fprintf (stderr, "%s\n", error->message);
  if (out >= 0 && close (out))
    rc = 1;
  if (dir >= 0)
    close (dir);
  EVP_PKEY_free (host);
  EVP_PKEY_free (issuer);
  return rc;
}

int
main (int argc, char **argv)
{
  guint8 serial[6] = {0};
  if (argc == 4 && !strcmp (argv[1], "request"))
    return run (FALSE, serial, argv[2], argv[3]);
  if (argc == 5 && !strcmp (argv[1], "register") && parse_serial (argv[2], serial) && geteuid () != 0)
    return run (TRUE, serial, argv[3], argv[4]);
  fputs ("Usage: native-register request ISSUER-URI NEW-REQUEST\n"
         "       native-register register READER-SERIAL ISSUER-URI NEW-RESPONSE\n"
         "Supply the host signing key on fd 4. Registration requires an unprivileged process and reader fd 3.\n",
         stderr);
  return 2;
}
