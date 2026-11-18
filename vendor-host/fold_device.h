#ifndef X1FOLD_DEVICE_H
#define X1FOLD_DEVICE_H
#include <stdbool.h>
#include <stdint.h>
struct fold_device;
struct tudor_device;
struct fold_store;

struct fold_adapter_versions {
    uint16_t sensor, engine, storage;
    bool enrollment_methods, verification_methods;
};

struct fold_open_result {
    const char *stage;
    uint32_t code, sensor_status;
};

bool fold_platform_table_available(void);

/* Offline: call after tudor_init. Queries the real DLL storage export. */
bool fold_device_interfaces(struct fold_adapter_versions *versions);
/* Isolated worker only. The trusted host must already have bound the CM path
 * and the physical file with the intended I/O policy. Installs the authenticated
 * registry before PnP. Never opens paths, creates a database or resets USB. */
struct fold_device *fold_device_open(struct fold_store *store, struct fold_open_result *result);
/* Returns the activated device only after a successful vendor QueryStatus. */
struct tudor_device *fold_device_ready(struct fold_device *session);
int fold_device_record_count(struct tudor_device *, const uint8_t guid[16], uint8_t finger);
bool fold_device_delete_print(struct tudor_device *, const uint8_t guid[16], uint8_t finger);
bool fold_device_close(struct fold_device *session);

#endif
