// SPDX-License-Identifier: LGPL-2.1-or-later
#include "handshake.h"
#include <glib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void
exercise (const guint8 *wire, gsize size, const guint8 *messages, gsize msglen)
{
  guint8 envelope[150] = "synaptic";
  if (size > sizeof envelope - 16)
    g_error ("Oversize test fixture");
  envelope[8] = size + 4;
  envelope[12] = size;
  memcpy (envelope + 16, wire, size);
  int fds[2];
  g_assert_cmpint (socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, fds), ==, 0);
  for (guint pos = 0; pos < size + 16; pos += 63)
    {
      guint8 report[64] = {0x0f};
      memcpy (report + 1, envelope + pos, MIN (63, size + 16 - pos));
      g_assert_cmpint (write (fds[1], report, sizeof report), ==, sizeof report);
    }
  g_autoptr(GError) error = NULL;
  struct x1fold_server_flight flight = {0};
  gboolean ok = x1fold_request_server_flight (fds[0], g_get_monotonic_time () + G_TIME_SPAN_SECOND,
                                              NULL, &flight, &error);
  if (messages)
    {
      g_assert_no_error (error);
      g_assert_true (ok);
      guint8 request[95];
      for (guint pos = 0; pos < sizeof request; pos += 19)
        {
          guint8 report[20];
          g_assert_cmpint (read (fds[1], report, sizeof report), ==, sizeof report);
          g_assert_cmphex (report[0], ==, 0x0e);
          memcpy (request + pos, report + 1, 19);
        }
      const guint8 prefix[] = {0x44,0,0,0,22,3,3,0,65,1,0,0,61,3,3};
      g_assert_cmpmem (request + 14, sizeof prefix, prefix, sizeof prefix);
      const guint8 expected_params[] = {7,0,0,0,0,0,0,0,0,2,0xc0,0x2e,0,0,10,0,4,0,2,0,23,0,11,0,2,1,0};
      g_assert_cmpmem (request + 14 + 47, sizeof expected_params, expected_params, sizeof expected_params);
      g_assert_cmpmem (flight.client_random, 32, request + 14 + 15, 32);
      g_assert_cmpmem (flight.server_random, 32, messages + 6, 32);
      gsize length;
      const guint8 *bytes = g_bytes_get_data (flight.transcript, &length);
      g_assert_cmpuint (length, ==, 65 + msglen);
      g_assert_cmpmem (bytes, 65, request + 14 + 9, 65);
      g_assert_cmpmem (bytes + 65, msglen, messages, msglen);
      g_bytes_unref (flight.transcript);
    }
  else
    {
      g_assert_false (ok);
      g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
      g_assert_null (flight.transcript);
    }
  close (fds[0]);
  close (fds[1]);
}

int
main (int argc, char **argv)
{
  guint8 reply[66] = {22,3,3,0,61,2,0,0,45,3,0x83};
  for (guint i = 0; i < 32; i++)
    reply[11 + i] = i;
  const guint8 tail[] = {7,1,2,3,4,5,6,7,0xc0,0x2e,0,13,0,0,4,1,64,0,0,14,0,0,0};
  memcpy (reply + 43, tail, sizeof tail);
  exercise (reply, sizeof reply, reply + 5, 61);
  for (guint split = 1; split < 61; split++)
    {
      guint8 divided[71] = {22,3,3,0};
      divided[4] = split;
      memcpy (divided + 5, reply + 5, split);
      memcpy (divided + 5 + split, reply, 5);
      divided[9 + split] = 61 - split;
      memcpy (divided + 10 + split, reply + 5 + split, 61 - split);
      exercise (divided, sizeof divided, reply + 5, 61);
    }
  const guint positions[] = {0, 2, 4, 5, 8, 10, 43, 52, 53, 54, 60, 62};
  for (guint i = 0; i < G_N_ELEMENTS (positions); i++)
    {
      guint pos = positions[i];
      reply[pos] ^= 1;
      exercise (reply, sizeof reply, NULL, 0);
      reply[pos] ^= 1;
    }
  for (int i = 1; i < argc; i++)
    {
      g_autofree gchar *file = NULL;
      gsize len;
      g_assert_true (g_file_get_contents (argv[i], &file, &len, NULL));
      g_assert_cmpuint (len, ==, 66);
      exercise ((const guint8 *) file, len, (const guint8 *) file + 5, len - 5);
    }
  return 0;
}
