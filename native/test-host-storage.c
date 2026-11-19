// SPDX-License-Identifier: LGPL-2.1-or-later
#include "host-storage.h"
#include <string.h>


enum scenario { PRESENT, EMPTY, DAMAGED, OVERSIZED, REPEATED, BAD_VERSION, WRONG_PARTITION, SHORT };
static enum scenario scenario;
static guint reads;

static guint
entry (guint8 *p, guint8 tag, const guint8 *value, guint8 len)
{
  p[0] = tag;
  p[1] = p[3] = 0;
  p[2] = len;
  g_autoptr(GChecksum) sum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (sum, value, len);
  gsize size = 32;
  g_checksum_get_digest (sum, p + 4, &size);
  memcpy (p + 36, value, len);
  return 36 + len;
}

gboolean
__wrap_x1fold_exchange (int fd, const guint8 *cmd, gsize len, guint8 *reply, gsize cap,
                        gsize *received, gint64 deadline, GCancellable *cancel, GError **error)
{
  if (reads++ == 0)
    {
      g_assert_cmpmem (cmd, len, "\x3e", 1);
      g_assert_cmpuint (cap, >=, 28);
      memset (reply, 0, 28);
      reply[14] = 1;
      reply[16] = scenario == WRONG_PARTITION ? 1 : 2;
      reply[25] = 16; /* 4096 bytes */
      *received = 28;
      return TRUE;
    }
  const guint8 expected[13] = {0x40, 2, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0x10};
  g_assert_cmpmem (cmd, len, expected, sizeof expected);
  g_assert_cmpuint (cap, >=, 4104);
  memset (reply, 0, 8);
  reply[3] = 16;
  guint8 *body = reply + 8;
  memset (body, 0xff, 4096);
  guint8 version[] = {scenario == BAD_VERSION ? 2 : 1, 0, 0, 0};
  guint n = entry (body, 1, version, sizeof version);
  const guint8 dummy[] = {1, 2, 3};
  if (scenario != EMPTY)
    n += entry (body + n, 2, dummy, sizeof dummy);
  if (scenario == DAMAGED) body[n-1] ^= 1;
  if (scenario == REPEATED) entry (body + n, 2, dummy, sizeof dummy);
  if (scenario == OVERSIZED) body[43] = 0xff;
  *received = scenario == SHORT ? 4103 : 4104;
  return TRUE;
}

int
main (void)
{
  for (scenario = PRESENT; scenario <= SHORT; scenario++)
    {
      gboolean present = TRUE;
      g_autoptr(GError) error = NULL;
      reads = 0;
      gboolean ok = x1fold_check_host_storage (3, &present, &error);
      g_assert_cmpint (ok, ==, scenario == PRESENT || scenario == EMPTY);
      g_assert_cmpint (present, ==, scenario == PRESENT);
      g_assert_cmpint (error == NULL, ==, ok);
      g_assert_cmpuint (reads, ==, scenario == WRONG_PARTITION ? 1 : 2);
    }
  return 0;
}
