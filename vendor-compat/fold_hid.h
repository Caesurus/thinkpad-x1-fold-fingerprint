#ifndef X1FOLD_HID_H
#define X1FOLD_HID_H

#include <stddef.h>
#include <sys/types.h>
#include "winapi/api.h"

/* Metadata-only attachment is useful for offline enumeration. */
bool fold_hid_attach(HANDLE handle, USHORT vid, USHORT pid, unsigned interface_number,
                     USHORT bcd_device, const BYTE *descriptor, size_t length);
/* Bind a hidraw O_RDWR | O_NONBLOCK file before publishing its Windows handle.
 * Each Windows open has its own Linux open file description. The host supplies
 * the verified USB interface number and bcdDevice. This call keeps its own fd
 * and checks the bus, IDs, and report descriptor directly on that fd. */
bool fold_hid_attach_fd(HANDLE handle, int hidraw_fd, unsigned interface_number, USHORT bcd_device);
bool fold_hid_attach_probe_fd(HANDLE handle, int hidraw_fd, unsigned interface_number, USHORT bcd_device);
/* Call from the Windows file destructor. */
void fold_hid_detach(HANDLE handle);

struct fold_hid_attributes {
    ULONG size;
    USHORT vendor_id, product_id, version;
};

struct fold_hid_caps {
    USHORT usage, usage_page;
    USHORT input_length, output_length, feature_length, reserved[17];
    USHORT link_nodes;
    USHORT input_buttons, input_values, input_indices;
    USHORT output_buttons, output_values, output_indices;
    USHORT feature_buttons, feature_values, feature_indices;
};

struct fold_hid_value_caps {
    USHORT usage_page;
    BYTE report_id, is_alias;
    USHORT bit_field, link_collection, link_usage, link_usage_page;
    BYTE is_range, is_string_range, is_designator_range, is_absolute, has_null, reserved;
    USHORT bit_size, report_count, reserved2[5];
    ULONG units_exponent, units;
    LONG logical_min, logical_max, physical_min, physical_max;
    /* This collection has single usages. This is the NotRange union layout. */
    USHORT usage, reserved3, string_index, reserved4;
    USHORT designator_index, reserved5, data_index, reserved6;
};

#endif
