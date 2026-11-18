/* Exercise the production C transport on packet sockets, without a device. */
#include "../transport.h"
#include <glib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void
send_reply (int fd, const guint8 *data, guint32 length)
{
  guint32 pos = 0;
  do
    {
      guint8 envelope[261] = "synaptic";
      guint prefix = pos == 0 ? 4 : 0;
      guint chunk = MIN (length - pos, 249 - prefix);
      guint32 wire = GUINT32_TO_LE (chunk + prefix);
      memcpy (envelope + 8, &wire, 4);
      wire = GUINT32_TO_LE (length);
      if (prefix)
        memcpy (envelope + 12, &wire, 4);
      memcpy (envelope + 12 + prefix, data + pos, chunk);
      for (guint offset = 0; offset < 12 + prefix + chunk; offset += 63)
        {
          guint8 event[20] = {0x10}, report[64] = {0x0f};
          guint n = MIN (63, 12 + prefix + chunk - offset);
          memcpy (report + 1, envelope + offset, n);
          g_assert_cmpint (write (fd, event, sizeof event), ==, sizeof event);
          g_assert_cmpint (write (fd, report, sizeof report), ==, sizeof report);
        }
      pos += chunk;
    }
  while (pos < length);
}

int
main (void)
{
  int pair[2];
  g_assert_cmpint (socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, pair), ==, 0);
  guint8 input[497], output[497];
  for (guint i = 0; i < sizeof input; i++)
    input[i] = i;
  const guint boundaries[] = {1, 5, 6, 47, 48, 245, 246, 248, 249, 494, 495, 497};
  for (guint i = 0; i < G_N_ELEMENTS (boundaries); i++)
    {
      guint size = boundaries[i];
      send_reply (pair[1], input, size);
      g_autoptr(GError) error = NULL;
      gsize received = 0;
      g_assert_true (x1fold_exchange (pair[0], input, size, output, sizeof output, &received,
                                      g_get_monotonic_time () + G_TIME_SPAN_SECOND, NULL, &error));
      g_assert_no_error (error);
      g_assert_cmpmem (input, size, output, received);
      for (guint pos = 0; pos < size; pos += 248)
        {
          guint amount = MIN (248, size - pos);
          guint sequence = pos + amount == size ? 0x80ff : pos / 248;
          if (!pos)
            sequence |= 0x4000;
          for (guint k = 0; k < amount + 14; k += 19)
            {
              guint8 report[20], expected[20] = {0x0e};
              g_assert_cmpint (read (pair[1], report, sizeof report), ==, sizeof report);
              if (k == 0)
                {
                  memcpy (expected + 1, "synaptic", 8);
                  expected[9] = amount + 2;
                  expected[13] = sequence & 0xff;
                  expected[14] = sequence >> 8;
                  memcpy (expected + 15, input + pos, MIN (amount, 5));
                }
              else
                memcpy (expected + 1, input + pos + k - 14, MIN (19, amount + 14 - k));
              g_assert_cmpmem (report, sizeof report, expected, sizeof expected);
            }
        }
    }
  g_autoptr(GError) error = NULL;
  gsize received = 99;
  send_reply (pair[1], input, 48);
  g_assert_false (x1fold_exchange (pair[0], input, 1, output, 47, &received,
                                  g_get_monotonic_time () + G_TIME_SPAN_SECOND, NULL, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
  g_assert_cmpuint (received, ==, 0);
  g_clear_error (&error);
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  g_cancellable_cancel (cancel);
  g_assert_false (x1fold_exchange (pair[0], input, 1, output, sizeof output, &received,
                                   g_get_monotonic_time () + G_TIME_SPAN_SECOND, cancel, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_clear_error (&error);
  g_assert_false (x1fold_exchange (pair[0], input, 1, output, sizeof output, &received,
                                   g_get_monotonic_time () - 1, NULL, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT);
  close (pair[0]);
  close (pair[1]);
  return 0;
}
