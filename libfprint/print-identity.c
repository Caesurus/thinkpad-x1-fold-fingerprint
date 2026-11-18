// SPDX-License-Identifier: LGPL-2.1-or-later
#include "print-identity.h"
#include <string.h>

#define PRINT_VERSION 1
/* Byte 0 is the version, 1..16 are the WinBio GUID bytes, 17..22 are
 * the Tudor serial, and 23 is the exact WinBio subfactor. */
#define PRINT_SIZE 24

static gboolean
usable_bytes(const guint8 *data, gsize size)
{
  guint8 combined = 0, intersection = 0xff;
  for (gsize i = 0; i < size; ++i) {
    combined |= data[i];
    intersection &= data[i];
  }
  return combined != 0 && intersection != 0xff;
}

gchar *
x1fold_sensor_id(const guint8 serial[6])
{
  if (!usable_bytes(serial, 6))
    return NULL;
  return g_strdup_printf("tudor-%02x%02x%02x%02x%02x%02x",
                         serial[0], serial[1], serial[2], serial[3], serial[4], serial[5]);
}

static const guint8 winbio_fingers[] = {
  [FP_FINGER_LEFT_THUMB] = 6, [FP_FINGER_LEFT_INDEX] = 7, [FP_FINGER_LEFT_MIDDLE] = 8,
  [FP_FINGER_LEFT_RING] = 9, [FP_FINGER_LEFT_LITTLE] = 10,
  [FP_FINGER_RIGHT_THUMB] = 1, [FP_FINGER_RIGHT_INDEX] = 2, [FP_FINGER_RIGHT_MIDDLE] = 3,
  [FP_FINGER_RIGHT_RING] = 4, [FP_FINGER_RIGHT_LITTLE] = 5,
};

guint8
x1fold_winbio_finger(FpFinger finger)
{
  return finger >= FP_FINGER_FIRST && finger <= FP_FINGER_LAST ? winbio_fingers[finger] : 0;
}

static gboolean
invalid(GError **error)
{
  g_set_error_literal(error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                      "Print identity is invalid for this reader and finger");
  return FALSE;
}

static gboolean
belongs_to(FpDevice *device, FpPrint *print, const struct fold_bio_identity *identity)
{
  FpFinger finger = fp_print_get_finger(print);
  g_autofree gchar *id = x1fold_sensor_id(identity->serial);
  return id && !identity->reserved && usable_bytes(identity->guid, sizeof identity->guid) &&
         finger >= FP_FINGER_FIRST && finger <= FP_FINGER_LAST && winbio_fingers[finger] == identity->finger &&
         g_str_equal(fp_device_get_driver(device), "x1fold_hid") &&
         g_str_equal(fp_device_get_device_id(device), id) && fp_print_compatible(print, device);
}

gboolean
x1fold_save_print_identity(FpDevice *device, FpPrint *print, const struct fold_bio_identity *identity,
                           GError **error)
{
  FpiPrintType type;
  g_object_get(print, "fpi-type", &type, NULL);
  if (type != FPI_PRINT_UNDEFINED || !belongs_to(device, print, identity))
    return invalid(error);
  guint8 bytes[PRINT_SIZE] = {PRINT_VERSION};
  memcpy(bytes + 1, identity->guid, sizeof identity->guid);
  memcpy(bytes + 17, identity->serial, sizeof identity->serial);
  bytes[23] = identity->finger;
  fpi_print_set_type(print, FPI_PRINT_RAW);
  g_object_set(print, "fpi-data", g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes, sizeof bytes, 1), NULL);
  return TRUE;
}

gboolean
x1fold_load_print_identity(FpDevice *device, FpPrint *print, struct fold_bio_identity *identity,
                           GError **error)
{
  FpiPrintType type;
  g_autoptr(GVariant) payload = NULL;
  *identity = (struct fold_bio_identity){0};
  g_object_get(print, "fpi-type", &type, "fpi-data", &payload, NULL);
  if (type != FPI_PRINT_RAW || !payload || !g_variant_is_of_type(payload, G_VARIANT_TYPE_BYTESTRING))
    return invalid(error);
  gsize size;
  const guint8 *data = g_variant_get_fixed_array(payload, &size, 1);
  if (size != PRINT_SIZE || data[0] != PRINT_VERSION)
    return invalid(error);
  struct fold_bio_identity decoded = {.finger = data[23]};
  memcpy(decoded.guid, data + 1, sizeof decoded.guid);
  memcpy(decoded.serial, data + 17, sizeof decoded.serial);
  if (!belongs_to(device, print, &decoded))
    return invalid(error);
  *identity = decoded;
  return TRUE;
}
