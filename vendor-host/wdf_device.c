/* UMDF device metadata used by the Lenovo HID driver. */
#include "winapi/wdf/internal.h"
#include "fold_cm.h"
#include <stdatomic.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* The WDF dispatcher reports preparation and D0 callbacks while flushing its
 * queue. The private helper serves one device per process. */
static _Atomic uint32_t attachment_error;
void fold_attachment_failed(NTSTATUS status) { atomic_store(&attachment_error, status); }
void fold_attachment_reset(void) { atomic_store(&attachment_error, 0); }
uint32_t fold_attachment_status(void) { return atomic_load(&attachment_error); }

/* Only the offline version test supplies a synthetic SMBIOS table. */
#ifdef X1FOLD_OFFLINE_METADATA
#include "metadata_fixture.h"
#endif
#ifndef X1FOLD_OFFLINE_METADATA
static pthread_once_t platform_once = PTHREAD_ONCE_INIT;
static unsigned char *platform_table;
static UINT platform_size;

static void load_platform_table(void)
{
    const char *path = secure_getenv("FOLD_PLATFORM_DIRECTORY");
    if (!path) path = secure_getenv("CREDENTIALS_DIRECTORY");
    if (!path || path[0] != '/') return;
    int dir = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return;
    int fd = openat(dir, "rsmb", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    close(dir);
    if (fd < 0) return;
    FILE *fp = fdopen(fd, "rb");
    if (!fp) {
        close(fd);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 8 || st.st_size > 8 + 1024 * 1024) {
        fclose(fp);
        return;
    }
    size_t size = (size_t)st.st_size;
    unsigned char *table = malloc(size);
    bool complete = table && fread(table, 1, size, fp) == size;
    fclose(fp);
    uint32_t records_size;
    if (complete) {
        memcpy(&records_size, table + 4, sizeof records_size);
        if (records_size == size - 8) {
            platform_table = table;
            platform_size = (UINT)size;
            return;
        }
    }
    free(table);
}
#endif

static UINT raw_smbios(void *buffer, DWORD size)
{
#ifdef X1FOLD_OFFLINE_METADATA
    return fold_metadata_smbios(buffer, size);
#else
    pthread_once(&platform_once, load_platform_table);
    if (!platform_table) {
        winerr_set_code(5); /* ERROR_ACCESS_DENIED */
        return 0;
    }
    if (buffer && size >= platform_size) memcpy(buffer, platform_table, platform_size);
    return platform_size;
#endif
}

bool fold_platform_table_available(void) { return raw_smbios(NULL, 0) != 0; }

static UINT __winfnc GetSystemFirmwareTable(DWORD provider, DWORD id, void *buffer, DWORD size)
{
    /* The Fold DLL supplies the FACP table ID to the raw SMBIOS provider
       for both its size query and its read. It still parses RawSMBIOSData. */
    if (provider == 0x52534d42 && (id == 0 || id == 0x50434146))
        return raw_smbios(buffer, size);
    switch (provider) {
    case 0x52534d42: winerr_set_code(1168); break; /* ERROR_NOT_FOUND */
    case 0x41435049: /* ACPI */
    case 0x4649524d: winerr_set_code(5); break;    /* ERROR_ACCESS_DENIED */
    default:         winerr_set_code(1);           /* ERROR_INVALID_FUNCTION */
    }
    return 0;
}
WINAPI(GetSystemFirmwareTable)

struct pnp_capabilities {
    ULONG size;
    ULONG lock_supported, eject_supported, removable, dock_device, unique_id;
    ULONG silent_install, surprise_removal_ok, hardware_disabled, no_display_in_ui;
    ULONG address, ui_number;
};

_Static_assert(sizeof(struct pnp_capabilities) == 48, "UMDF device capabilities layout");

static WDF_OBJECT_CONTEXT_TYPE_INFO capabilities_type = {
    .Size = sizeof(WDF_OBJECT_CONTEXT_TYPE_INFO),
    .ContextName = "FoldPnpCapabilities",
    .ContextSize = sizeof(struct pnp_capabilities),
};

extern void *__winfnc WdfObjectGetTypedContextWorker(
    WDF_DRIVER_GLOBALS *, WDFOBJECT, WDF_OBJECT_CONTEXT_TYPE_INFO *);
extern NTSTATUS __winfnc WdfObjectAllocateContext(
    WDF_DRIVER_GLOBALS *, WDFOBJECT, WDF_OBJECT_ATTRIBUTES *, void **);

static void __winfnc WdfDeviceSetPnpCapabilities(
        WDF_DRIVER_GLOBALS *globals, WDFOBJECT device, const struct pnp_capabilities *caps) {
    if (!device || !caps || caps->size != sizeof(*caps)) {
        log_error("Unexpected UMDF device capabilities");
        abort();
    }
    void *context = WdfObjectGetTypedContextWorker(globals, device, &capabilities_type);
    if (!context) {
        WDF_OBJECT_ATTRIBUTES attrs = {
            .Size = sizeof(attrs),
            .ContextTypeInfo = &capabilities_type,
        };
        if (WdfObjectAllocateContext(globals, device, &attrs, &context) != STATUS_SUCCESS)
            abort();
    }
    memcpy(context, caps, sizeof(*caps));
}
WDFFUNC(WdfDeviceSetPnpCapabilities, 33)

struct interface_property {
    ULONG size;
    const GUID *interface_class;
    const UNICODE_STRING *reference;
    const void *key;
    ULONG locale, flags;
};

/* The private host has no Windows app-broker interface. Lenovo treats
   publishing and reading back its Windows app capabilities as optional. */
static NTSTATUS __winfnc WdfDeviceAssignInterfaceProperty(
        WDF_DRIVER_GLOBALS *globals, WDFOBJECT device, const struct interface_property *prop,
        ULONG type, ULONG size, const void *data) {
    return 0xc00000bb; /* STATUS_NOT_SUPPORTED */
}
WDFFUNC(WdfDeviceAssignInterfaceProperty, 50)

static NTSTATUS __winfnc WdfDeviceAllocAndQueryInterfaceProperty(
        WDF_DRIVER_GLOBALS *globals, WDFOBJECT device, const struct interface_property *prop,
        ULONG pool, WDF_OBJECT_ATTRIBUTES *attrs, WDFOBJECT *memory, ULONG *type) {
    if (!memory || !type) return 0xc000000d; /* STATUS_INVALID_PARAMETER */
    *memory = NULL;
    *type = 0;
    return 0xc00000bb;
}
WDFFUNC(WdfDeviceAllocAndQueryInterfaceProperty, 51)

struct device_property_key {
    GUID id;
    ULONG pid;
};

struct device_property {
    ULONG size;
    const struct device_property_key *key;
    ULONG locale, flags;
};

extern NTSTATUS __winfnc WdfMemoryCreatePreallocated(WDF_DRIVER_GLOBALS *,
    WDF_OBJECT_ATTRIBUTES *, void *, size_t, WDFOBJECT *);

static NTSTATUS __winfnc WdfDeviceAllocAndQueryPropertyEx(
        WDF_DRIVER_GLOBALS *globals, WDFOBJECT device, const struct device_property *prop,
        ULONG pool, WDF_OBJECT_ATTRIBUTES *attrs, WDFOBJECT *memory, ULONG *type) {
    const GUID instance_id = DEFINE_GUID(78c34fc8,104a,4aca,9ea4,524d52996e57);
    if (!memory || !type) return 0xc000000d;
    *memory = NULL;
    *type = 0;
    if (!device || !prop || prop->size != sizeof(*prop) || !prop->key || prop->flags)
        return 0xc000000d;
    if (prop->key->pid != 256 || memcmp(&prop->key->id, &instance_id, sizeof(GUID)))
        return 0xc0000225; /* STATUS_NOT_FOUND */
    const char *id = fold_cm_biometric_id();
    if (!id) return 0xc000000e; /* STATUS_NO_SUCH_DEVICE */
    size_t chars = strlen(id) + 1;
    WCHAR *value = calloc(chars, sizeof(*value));
    if (!value) return 0xc000009a; /* STATUS_INSUFFICIENT_RESOURCES */
    for (size_t i = 0; i < chars; ++i)
        value[i] = (unsigned char)id[i];
    NTSTATUS status = WdfMemoryCreatePreallocated(globals, attrs, value, chars * sizeof(*value), memory);
    if (status != STATUS_SUCCESS) {
        free(value);
        return 0xc000009a;
    }
    ((struct wdf_memory *)*memory)->owns_data = true;
    *type = 0x12; /* DEVPROP_TYPE_STRING */
    return STATUS_SUCCESS;
}
WDFFUNC(WdfDeviceAllocAndQueryPropertyEx, 55)

static void *__winfnc WdfMemoryGetBuffer(
        WDF_DRIVER_GLOBALS *globals, struct wdf_memory *memory, size_t *size) {
    if (size) *size = memory->data_size;
    return memory->data;
}
WDFFUNC(WdfMemoryGetBuffer, 119)
