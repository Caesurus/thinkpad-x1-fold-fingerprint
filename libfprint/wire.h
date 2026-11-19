// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <glib.h>
#include <string.h>

/* HID report fields may start at unaligned offsets. */
static inline guint16
read_le16 (const guint8 *bytes)
{
  guint16 value;
  memcpy (&value, bytes, sizeof value);
  return GUINT16_FROM_LE (value);
}

static inline guint32
read_le32 (const guint8 *bytes)
{
  guint32 value;
  memcpy (&value, bytes, sizeof value);
  return GUINT32_FROM_LE (value);
}
