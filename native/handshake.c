// SPDX-License-Identifier: LGPL-2.1-or-later
#include "handshake.h"
#include <openssl/rand.h>
#include <string.h>

static guint16
read_be16 (const guint8 *bytes)
{
  return ((guint16) bytes[0] << 8) | bytes[1];
}

static gboolean
invalid_flight (GError **error)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                       "Invalid or unsupported Tudor server handshake");
  return FALSE;
}

/* In the observed full handshake the reader sends ServerHello followed by
 * CertificateRequest and ServerHelloDone. TLS records can split messages. */
static gboolean
accept_server_messages (const guint8 *messages, gsize size, guint8 random[32],
                        GError **error)
{
  const guint8 request_and_done[] = {13, 0, 0, 4, 1, 64, 0, 0, 14, 0, 0, 0};
  if (size < 4 + 38 + sizeof request_and_done || messages[0] != 2 || messages[1] != 0)
    return invalid_flight (error);
  guint hello_len = read_be16 (messages + 2);
  const guint8 *hello = messages + 4;
  if (4 + hello_len + sizeof request_and_done != size ||
      hello[0] != 3 || hello[1] != 0x83)
    return invalid_flight (error);
  guint id_size = hello[34];
  if (id_size > 32 || hello_len != 38 + id_size)
    return invalid_flight (error);
  const guint8 *selection = hello + 35 + id_size;
  if (read_be16 (selection) != 0xc02e || selection[2] != 0 ||
      memcmp (hello + hello_len, request_and_done, sizeof request_and_done))
    return invalid_flight (error);

  memcpy (random, hello + 2, 32);
  return TRUE;
}

gboolean
x1fold_request_server_flight (int fd, gint64 deadline, GCancellable *cancel,
                              struct x1fold_server_flight *result, GError **error)
{
  /* The Tudor client sends an empty compression vector and unwrapped hello
   * extensions. The seven zero ID bytes request a new session. Offer only
   * the ECDH_ECDSA / AES-256-GCM suite selected in both recordings. */
  guint8 request[74] = {0x44, 0, 0, 0, 22, 3, 3, 0, 65, 1, 0, 0, 61, 3, 3};
  const guint8 tail[] = {7, 0, 0, 0, 0, 0, 0, 0,
                         0, 2, 0xc0, 0x2e, 0,
                         0, 10, 0, 4, 0, 2, 0, 23,
                         0, 11, 0, 2, 1, 0};
  G_STATIC_ASSERT (47 + sizeof tail == sizeof request);
  if (RAND_bytes (request + 15, 32) != 1)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Generating client random failed");
      return FALSE;
    }
  memcpy (request + 47, tail, sizeof tail);

  guint8 reply[1024];
  gsize size;
  if (!x1fold_exchange (fd, request, sizeof request, reply, sizeof reply, &size,
                        deadline, cancel, error))
    return FALSE;

  g_autoptr(GByteArray) transcript = g_byte_array_sized_new (sizeof request + size);
  const guint client_len = sizeof request - 9;
  g_byte_array_append (transcript, request + 9, client_len);
  for (gsize pos = 0; pos < size;)
    {
      if (size - pos < 5 || reply[pos] != 22 ||
          reply[pos + 1] != 3 || reply[pos + 2] != 3)
        return invalid_flight (error);
      guint len = read_be16 (reply + pos + 3);
      pos += 5;
      if (!len || len > size - pos)
        return invalid_flight (error);
      g_byte_array_append (transcript, reply + pos, len);
      pos += len;
    }
  struct x1fold_server_flight flight;
  if (!accept_server_messages (transcript->data + client_len, transcript->len - client_len,
                               flight.server_random, error))
    return FALSE;
  memcpy (flight.client_random, request + 15, sizeof flight.client_random);
  flight.transcript = g_byte_array_free_to_bytes (g_steal_pointer (&transcript));
  *result = flight;
  return TRUE;
}
