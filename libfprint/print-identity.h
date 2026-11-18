// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <fpi-device.h>
#include "biometric-ipc.h"

#define X1FOLD_UNIDENTIFIED "diagnostic-unidentified"
guint8 x1fold_winbio_finger(FpFinger finger);
gchar *x1fold_sensor_id(const guint8 serial[6]);
gboolean x1fold_save_print_identity(FpDevice *device, FpPrint *print,
                                    const struct fold_bio_identity *identity, GError **error);
gboolean x1fold_load_print_identity(FpDevice *device, FpPrint *print,
                                    struct fold_bio_identity *identity, GError **error);
