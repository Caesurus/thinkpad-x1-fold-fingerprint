// SPDX-License-Identifier: LGPL-2.1-or-later
/* Test serialized metadata on a simulated FpDevice, without enrolling. */
#include "../print-identity.h"
#include <fprint.h>
#include <string.h>

static void
reject(FpDevice *device, FpPrint *print)
{
  struct fold_bio_identity output;
  const struct fold_bio_identity empty = {0};
  g_autoptr(GError) error = NULL;
  memset(&output, 0xff, sizeof output);
  g_assert_false(x1fold_load_print_identity(device, print, &output, &error));
  g_assert_error(error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_assert_cmpmem(&output, sizeof output, &empty, sizeof empty);
}

int
main(void)
{
  g_assert_nonnull(g_getenv("UMOCKDEV_DIR"));
  g_autoptr(FpContext) context = fp_context_new();
  GPtrArray *devices = fp_context_get_devices(context);
  g_assert_cmpuint(devices->len, ==, 1);
  FpDevice *device = g_ptr_array_index(devices, 0);
  const struct fold_bio_identity canonical = {
    .guid = {3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18}, .serial = {1,2,3,4,5,6}
  };
  /* Explicitly exercise both mappings for all fingers. */
  const FpFinger fingers[] = { FP_FINGER_RIGHT_THUMB, FP_FINGER_RIGHT_INDEX, FP_FINGER_RIGHT_MIDDLE,
                               FP_FINGER_RIGHT_RING, FP_FINGER_RIGHT_LITTLE, FP_FINGER_LEFT_THUMB,
                               FP_FINGER_LEFT_INDEX, FP_FINGER_LEFT_MIDDLE, FP_FINGER_LEFT_RING, FP_FINGER_LEFT_LITTLE };
  for (gsize i = 0; i < G_N_ELEMENTS(fingers); ++i) {
    struct fold_bio_identity identity = canonical, decoded;
    identity.finger = i + 1;
    g_autoptr(FpPrint) print = fp_print_new(device);
    fp_print_set_finger(print, fingers[i]);
    g_autoptr(GError) error = NULL;
    if (g_str_equal(fp_device_get_device_id(device), X1FOLD_UNIDENTIFIED)) {
      g_assert_false(x1fold_save_print_identity(device, print, &identity, &error));
      g_assert_error(error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
      return 0;
    }
    g_assert_cmpstr(fp_device_get_device_id(device), ==, "tudor-010203040506");
    g_assert_true(x1fold_save_print_identity(device, print, &identity, &error));
    g_autofree guchar *serialized = NULL;
    gsize size;
    g_assert_true(fp_print_serialize(print, &serialized, &size, &error));
    g_autoptr(FpPrint) restored = fp_print_deserialize(serialized, size, &error);
    g_assert_no_error(error);
    g_assert_true(fp_print_compatible(restored, device));
    g_assert_true(x1fold_load_print_identity(device, restored, &decoded, &error));
    g_assert_cmpmem(&identity, sizeof identity, &decoded, sizeof decoded);

    fp_print_set_finger(restored, FP_FINGER_UNKNOWN);
    reject(device, restored);
    fp_print_set_finger(restored, fingers[(i + 1) % G_N_ELEMENTS(fingers)]);
    reject(device, restored);
    fp_print_set_finger(restored, fingers[i]);
    g_autoptr(GVariant) value = NULL;
    g_object_get(print, "fpi-data", &value, NULL);
    gsize len;
    const guint8 *data = g_variant_get_fixed_array(value, &len, 1);
    g_assert_cmpuint(len, ==, 24);
    guint8 bytes[24];
    const unsigned mutations[] = {0, 17, 23};
    for (gsize j = 0; j < G_N_ELEMENTS(mutations); ++j) {
      memcpy(bytes, data, len);
      bytes[mutations[j]] ^= 0xff;
      g_object_set(restored, "fpi-data", g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes, len, 1), NULL);
      reject(device, restored);
    }
    memcpy(bytes, data, len);
    memset(bytes + 1, 0, 16);
    g_object_set(restored, "fpi-data", g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes, len, 1), NULL);
    reject(device, restored);
    g_object_set(restored, "fpi-data", g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, len - 1, 1), NULL);
    reject(device, restored);
    g_object_set(restored, "fpi-data", g_variant_new_string("unknown format"), NULL);
    reject(device, restored);
    g_autoptr(FpPrint) foreign = g_object_new(FP_TYPE_PRINT, "driver", "x1fold_hid", "device-id", "tudor-090909090909",
                                               "fpi-type", FPI_PRINT_RAW, "fpi-data", value, NULL);
    fp_print_set_finger(foreign, fingers[i]);
    reject(device, foreign);
  }
  return 0;
}
