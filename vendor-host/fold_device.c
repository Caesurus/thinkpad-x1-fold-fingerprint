/* Built in place of the pinned libtudor src/tudor/device.c. Keep the same WBF
 * IOCTL/async bridge and all upstream match routines; use an HID-specific open
 * and the vendor's own storage adapter. */
#include "fold_wbf.inc"
#include "fold_device.h"
#include "fold_registry.h"
#include "fold_cm.h"
#include "../vendor-compat/fold_file.h"
#include <stddef.h>

typedef HRESULT __winfnc lifecycle(WINBIO_PIPELINE *);
extern void fold_attachment_reset(void);
extern uint32_t fold_attachment_status(void);
struct fold_device {
    struct tudor_device device;
    WINBIO_PIPELINE pipeline;
    lifecycle *cleanup[10];
    unsigned completed;
    bool ready;
};

#define HAS_ENTRY(table, member) \
    ((table)->Size >= offsetof(__typeof__(*(table)), member) + sizeof((table)->member) && (table)->member)

bool fold_device_interfaces(struct fold_adapter_versions *versions)
{
    if (!versions || !tudor_adapter_dll || !tudor_sensor_adapter || !tudor_engine_adapter) return false;
    winmodule_set_cur(&tudor_adapter_dll->module);
    api_WbioQueryStorageInterface query = find_dll_export(&tudor_adapter_dll->image, "WbioQueryStorageInterface");
    WINBIO_STORAGE_INTERFACE *storage = NULL;
    if (!query || query(&storage) || !storage || storage->Type != 3 ||
        !HAS_ENTRY(storage, Attach) || !HAS_ENTRY(storage, Detach) ||
        !HAS_ENTRY(storage, OpenDatabase) || !HAS_ENTRY(storage, CloseDatabase)) return false;
    if (tudor_sensor_adapter->Type != 1 || tudor_engine_adapter->Type != 2 ||
        !HAS_ENTRY(tudor_sensor_adapter, Attach) || !HAS_ENTRY(tudor_sensor_adapter, Detach) ||
        !HAS_ENTRY(tudor_sensor_adapter, QueryStatus) ||
        !HAS_ENTRY(tudor_engine_adapter, Attach) || !HAS_ENTRY(tudor_engine_adapter, Detach)) return false;
    tudor_storage_adapter = storage;
    WINBIO_SENSOR_INTERFACE *sensor = tudor_sensor_adapter;
    WINBIO_ENGINE_INTERFACE *engine = tudor_engine_adapter;
    bool captures = HAS_ENTRY(sensor, StartCapture) && HAS_ENTRY(sensor, FinishCapture) &&
                    HAS_ENTRY(sensor, PushDataToEngine);
    *versions = (struct fold_adapter_versions){
        tudor_sensor_adapter->Version.MajorVersion, tudor_engine_adapter->Version.MajorVersion,
        storage->Version.MajorVersion,
        captures && HAS_ENTRY(sensor, ClearContext) && HAS_ENTRY(storage, ClearContext) &&
            HAS_ENTRY(engine, ClearContext) && HAS_ENTRY(engine, CreateEnrollment) &&
            HAS_ENTRY(engine, SetEnrollmentParameters) && HAS_ENTRY(engine, UpdateEnrollment) &&
            HAS_ENTRY(engine, CheckForDuplicate) && HAS_ENTRY(engine, CommitEnrollment) &&
            HAS_ENTRY(engine, DiscardEnrollment),
        captures && HAS_ENTRY(engine, VerifyFeatureSet)
    };
    return true;
}

static HRESULT __winfnc open_database(WINBIO_PIPELINE *pipeline)
{
    GUID db = DEFINE_GUID(d6612bd6,ecc0,40bf,80ff,7e480722ad8c);
    /* Both strings are empty in the Lenovo INF. The driver checks them for NULL. */
    return pipeline->StorageInterface->OpenDatabase(pipeline, &db, u"", u"");
}

struct step { const char *name; lifecycle *start, *stop; };
#define REQUIRED(table, a, b) {#table "." #a, (table)->a, (table)->b}
#define OPTIONAL(table, a, b) {#table "." #a, HAS_ENTRY(table,a) ? (table)->a : NULL, \
                                          HAS_ENTRY(table,b) ? (table)->b : NULL}

struct fold_device *fold_device_open(struct fold_store *store, struct fold_open_result *result)
{
    if (!result) return NULL;
    *result = (struct fold_open_result){.stage = "BiometricHidBinding", .code = E_INVALIDARG};
    struct fold_adapter_versions versions;
    if (!fold_cm_hid_path() || !fold_file_bound_for_biometrics()) return NULL;
    result->stage = "SystemFirmwareTable";
    if (!fold_platform_table_available()) { result->code = 0x80070005; return NULL; }
    result->stage = "AuthenticatedRegistry";
    if (!fold_registry_install(store)) return NULL;
    result->stage = "WinBioInterfaces";
    if (!fold_device_interfaces(&versions)) return NULL;
    if (!versions.enrollment_methods || !versions.verification_methods) { result->code = E_NOTIMPL; return NULL; }
    struct fold_device *session = calloc(1, sizeof(*session));
    if (!session) { result->code = 0x8007000e; return NULL; }
    struct tudor_device *device = &session->device;
    int error = pthread_mutex_init(&device->records_lock, NULL);
    if (error) { result->code = error; free(session); return NULL; }
    winmodule_set_cur(&tudor_driver_dll->module);
    device->reg_key = winreg_open_key(device, "HKEY_LOCAL_MACHINE\\Tudor\\Device");
    result->stage = "WdfAddDevice";
    fold_attachment_reset();
    result->code = winwdf_add_device(tudor_wdf_driver, device->reg_key, NULL, &device->wdf_device);
    if (!result->code && !device->wdf_device) result->code = 0xc000009d;
    if (result->code && device->wdf_device) goto partial_attachment;
    if (result->code) goto fail;
    result->stage = "WdfPrepareHardware";
    winwdf_event_queue_flush();
    result->code = fold_attachment_status();
    if (result->code) goto partial_attachment;
    result->stage = "WdfOpenDevice";
    result->code = winwdf_open_device(device->wdf_device, &device->wdf_file);
    if (!result->code && !device->wdf_file) result->code = 0xc000009d;
    if (result->code) goto fail;
    winmodule_set_cur(&tudor_adapter_dll->module);
    device->winbio_file = winio_create_file(device, true, NULL, NULL, (winio_devctrl_fnc *)tudor_devctrl,
                                            (winio_cancel_fnc *)tudor_cancel, (winio_cleanup_fnc *)tudor_cleanup, NULL);
    device->pipeline = &session->pipeline;
    WINBIO_SENSOR_INTERFACE *sensor = tudor_sensor_adapter;
    WINBIO_ENGINE_INTERFACE *engine = tudor_engine_adapter;
    WINBIO_STORAGE_INTERFACE *storage = tudor_storage_adapter;
    *device->pipeline = (WINBIO_PIPELINE){
        .SensorHandle = device->winbio_file, .EngineHandle = INVALID_HANDLE_VALUE,
        .StorageHandle = INVALID_HANDLE_VALUE, .SensorInterface = sensor,
        .EngineInterface = engine, .StorageInterface = storage
    };
    const struct step steps[] = {
        REQUIRED(sensor, Attach, Detach), REQUIRED(engine, Attach, Detach),
        REQUIRED(storage, Attach, Detach), {"storage.OpenDatabase", open_database, storage->CloseDatabase},
        OPTIONAL(storage, PipelineInit, PipelineCleanup), OPTIONAL(engine, PipelineInit, PipelineCleanup),
        OPTIONAL(sensor, PipelineInit, PipelineCleanup), OPTIONAL(storage, Activate, Deactivate),
        OPTIONAL(engine, Activate, Deactivate), OPTIONAL(sensor, Activate, Deactivate)
    };
    _Static_assert(sizeof(steps)/sizeof(steps[0]) == sizeof(session->cleanup)/sizeof(session->cleanup[0]), "cleanup slots");
    for (size_t i = 0; i < sizeof(steps)/sizeof(steps[0]); ++i) {
        const struct step *step = &steps[i];
        if (!step->start && !step->stop) continue; /* The negotiated ABI predates this lifecycle pair. */
        result->stage = step->name;
        if (!step->start || !step->stop) { result->code = E_NOTIMPL; goto fail; }
        result->code = step->start(device->pipeline);
        if (result->code) goto fail;
        session->cleanup[session->completed++] = step->stop;
    }
    result->stage = "sensor.QueryStatus";
    ULONG sensor_status = WINBIO_SENSOR_FAILURE;
    for (unsigned attempt = 0; attempt < 20; ++attempt) {
        result->code = sensor->QueryStatus(device->pipeline, &sensor_status);
        if (result->code || sensor_status != WINBIO_SENSOR_BUSY) break;
        usleep(250000);
    }
    result->sensor_status = sensor_status;
    if (result->code || sensor_status != WINBIO_SENSOR_READY) goto fail;
    result->stage = "ready";
    session->ready = true;
    return session;
partial_attachment:
    /* This one-transaction worker owns the guest, source fd and locks. The
     * upstream removal code calls all shutdown callbacks, even for stages the
     * DLL never initialized. Let the kernel release these process resources. */
    fprintf(stderr, "%s returned 0x%08x; terminating incomplete WDF attachment\n", result->stage, result->code);
    _exit(72);
fail:
    fold_device_close(session);
    return NULL;
}

struct tudor_device *fold_device_ready(struct fold_device *session)
{
    return session && session->ready ? &session->device : NULL;
}

bool fold_device_close(struct fold_device *session)
{
    if (!session) return false;
    bool ok = true;
    struct tudor_device *device = &session->device;
    session->ready = false;
    winmodule_set_cur(&tudor_adapter_dll->module);
    while (session->completed)
        if (session->cleanup[--session->completed](device->pipeline)) ok = false;
    if (device->winbio_file) winhandle_destroy(device->winbio_file);
    winmodule_set_cur(&tudor_driver_dll->module);
    if (device->wdf_file) winwdf_close_file(device->wdf_file);
    if (device->wdf_device) {
        winwdf_remove_device(device->wdf_device);
        winwdf_event_queue_flush();
    }
    if (device->reg_key) winhandle_destroy(device->reg_key);
    pthread_mutex_destroy(&device->records_lock);
    free(session);
    return ok;
}

static WINBIO_IDENTITY print_subject(const uint8_t guid[16])
{
    WINBIO_IDENTITY subject = {.Type = WINBIO_ID_TYPE_GUID};
    memcpy(&subject.TemplateGuid, guid, sizeof(subject.TemplateGuid));
    return subject;
}

int fold_device_record_count(struct tudor_device *device, const uint8_t guid[16], uint8_t finger)
{
    WINBIO_STORAGE_INTERFACE *storage = device->pipeline->StorageInterface;
    if (!HAS_ENTRY(storage, QueryBySubject) || !HAS_ENTRY(storage, GetRecordCount)) return -1;
    WINBIO_IDENTITY subject = print_subject(guid);
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hr = storage->QueryBySubject(device->pipeline, &subject, finger);
    if (hr == WINBIO_E_DATABASE_NO_RESULTS || hr == WINBIO_E_DATABASE_NO_SUCH_RECORD) return 0;
    SIZE_T count = 0;
    if (hr || storage->GetRecordCount(device->pipeline, &count) || count > INT32_MAX) return -1;
    return (int)count;
}

bool fold_device_delete_print(struct tudor_device *device, const uint8_t guid[16], uint8_t finger)
{
    WINBIO_STORAGE_INTERFACE *storage = device->pipeline->StorageInterface;
    if (!HAS_ENTRY(storage, DeleteRecord) || !finger || finger > 10) return false;
    WINBIO_IDENTITY subject = print_subject(guid);
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hr = storage->DeleteRecord(device->pipeline, &subject, finger);
    return (!hr || hr == WINBIO_E_DATABASE_NO_SUCH_RECORD || hr == WINBIO_E_DATABASE_NO_RESULTS) &&
           fold_device_record_count(device, guid, finger) == 0;
}
