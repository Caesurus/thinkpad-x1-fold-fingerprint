// SPDX-License-Identifier: LGPL-2.1-or-later
#include "host-storage.h"
#include <string.h>
#include <stdio.h>


enum scenario {
  PRESENT, EMPTY, DAMAGED, OVERSIZED, REPEATED, BAD_VERSION, WRONG_PARTITION,
  SHORT, MISSING_VERSION, ZERO_PAIRING, DUPLICATE_HOST, WRONG_HOST_SIZE, WRONG_COUNT
};
static enum scenario scenario;
static guint reads;
static guint8 *fixture_image;

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
      gsize size = scenario == DUPLICATE_HOST ? 40 : 28;
      g_assert_cmpuint (cap, >=, size);
      memset (reply, 0, size);
      reply[14] = scenario == DUPLICATE_HOST || scenario == WRONG_COUNT ? 2 : 1;
      reply[16] = scenario == WRONG_PARTITION ? 1 : 2;
      reply[25] = scenario == WRONG_HOST_SIZE ? 8 : 16;
      if (scenario == DUPLICATE_HOST)
        memcpy (reply + 28, reply + 16, 12);
      *received = size;
      return TRUE;
    }
  const guint8 expected[13] = {0x40, 2, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0x10};
  g_assert_cmpmem (cmd, len, expected, sizeof expected);
  g_assert_cmpuint (cap, >=, 4104);
  memset (reply, 0, 8);
  reply[3] = 16;
  guint8 *body = reply + 8;
  if (fixture_image)
    {
      memcpy (body, fixture_image, 4096);
      *received = 4104;
      return TRUE;
    }
  memset (body, 0xff, 4096);
  guint8 version[] = {scenario == BAD_VERSION ? 2 : 1, 0, 0, 0};
  guint n = scenario == MISSING_VERSION ? 0 : entry (body, 1, version, sizeof version);
  const guint8 dummy[] = {1, 2, 3};
  if (scenario != EMPTY)
    n += entry (body + n, 2, dummy, scenario == ZERO_PAIRING ? 0 : sizeof dummy);
  if (scenario == DAMAGED) body[n-1] ^= 1;
  if (scenario == REPEATED) entry (body + n, 2, dummy, sizeof dummy);
  if (scenario == OVERSIZED) body[43] = 0xff;
  *received = scenario == SHORT ? 4103 : 4104;
  return TRUE;
}

static const struct storage_case {
  const char *name;
  enum scenario scenario;
  guint exchanges;
} cases[] = {
  {"/host-storage/present", PRESENT, 2},
  {"/host-storage/empty", EMPTY, 2},
  {"/host-storage/damaged", DAMAGED, 2},
  {"/host-storage/oversized", OVERSIZED, 2},
  {"/host-storage/repeated", REPEATED, 2},
  {"/host-storage/bad-version", BAD_VERSION, 2},
  {"/host-storage/wrong-partition", WRONG_PARTITION, 1},
  {"/host-storage/short-read", SHORT, 2},
  {"/host-storage/missing-version", MISSING_VERSION, 2},
  {"/host-storage/empty-pairing", ZERO_PAIRING, 2},
  {"/host-storage/duplicate-host", DUPLICATE_HOST, 1},
  {"/host-storage/wrong-host-size", WRONG_HOST_SIZE, 1},
  {"/host-storage/wrong-directory-count", WRONG_COUNT, 1},
};

static void
test_storage (gconstpointer data)
{
  const struct storage_case *test = data;
  scenario = test->scenario;
  reads = 0;
  gboolean present = TRUE;
  g_autoptr(GError) error = NULL;
  gboolean ok = x1fold_check_host_storage (3, &present, &error);
  g_assert_cmpint (ok, ==, scenario == PRESENT || scenario == EMPTY);
  g_assert_cmpint (present, ==, scenario == PRESENT);
  if (ok)
    g_assert_no_error (error);
  else
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
  g_assert_cmpuint (reads, ==, test->exchanges);
}

int
main (int argc, char **argv)
{
  if (argc == 2 && !strcmp (argv[1], "--image"))
    {
      guint8 image[4096];
      if (fread (image, 1, sizeof image, stdin) != sizeof image || getchar () != EOF)
        return 2;
      fixture_image = image;
      gboolean present;
      g_autoptr(GError) error = NULL;
      gboolean ok = x1fold_check_host_storage (3, &present, &error);
      puts (ok ? (present ? "present" : "absent") : "invalid");
      return 0;
    }
  g_test_init (&argc, &argv, NULL);
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    g_test_add_data_func (cases[i].name, &cases[i], test_storage);
  return g_test_run ();
}
