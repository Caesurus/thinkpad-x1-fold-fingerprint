#include "fold_hid.h"
#include <fcntl.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <unistd.h>

_Static_assert(sizeof(struct fold_hid_attributes) == 12, "HIDD_ATTRIBUTES ABI");
_Static_assert(sizeof(struct fold_hid_caps) == 64, "HIDP_CAPS ABI");
_Static_assert(sizeof(struct fold_hid_value_caps) == 72, "HIDP_VALUE_CAPS ABI");
_Static_assert(offsetof(struct fold_hid_value_caps, report_count) == 20, "ReportCount ABI");
_Static_assert(offsetof(struct fold_hid_value_caps, usage) == 56, "NotRange ABI");

static const BYTE report_descriptor[] = {
    0x06,0x00,0xff,0x09,0x01,0xa1,0x01,
    0x85,0x0e,0x09,0x02,0x15,0x00,0x26,0xff,0x00,0x75,0x08,0x95,0x13,0x91,0x02,
    0x85,0x0f,0x09,0x06,0x15,0x00,0x26,0xff,0x00,0x75,0x08,0x95,0x3f,0x81,0x02,
    0x85,0x10,0x09,0x05,0x15,0x00,0x26,0xff,0x00,0x75,0x08,0x95,0x13,0x81,0x02,
    0x85,0x11,0x09,0x07,0x15,0x00,0x26,0xff,0x00,0x75,0x08,0x95,0x13,0xb1,0x02,
    0xc0
};

enum {
    hid_success = 0x00110000, hid_invalid_data = 0xc0110001,
    hid_invalid_type = 0xc0110002, hid_short_buffer = 0xc0110007,
    error_invalid_handle = 6, error_out_of_memory = 8, error_invalid_parameter = 87
};

struct hid_file {
    HANDLE handle;
    USHORT bcd_device;
    int fd;
    struct hid_file *next;
};
/* Preparsed data survives the originating file handle until the caller frees it. */
struct parsed_hid {
    struct parsed_hid *next;
};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct hid_file *files;
static struct parsed_hid *parsed_list;

static struct hid_file **file_slot(HANDLE handle)
{
    struct hid_file **slot = &files;
    while (*slot && (*slot)->handle != handle) slot = &(*slot)->next;
    return slot;
}

static bool attach_file(HANDLE handle, USHORT vid, USHORT pid, unsigned interface_number,
                        USHORT bcd_device, const BYTE *descriptor, size_t length, int owned_fd)
{
    if (!handle || handle == INVALID_HANDLE_VALUE || vid != 0x17ef || pid != 0x6142 ||
        interface_number != 4 || length != sizeof(report_descriptor) || !descriptor ||
        memcmp(descriptor, report_descriptor, length) != 0) return false;

    struct hid_file *file = malloc(sizeof(*file));
    if (!file) return false;
    pthread_mutex_lock(&lock);
    if (*file_slot(handle)) {
        pthread_mutex_unlock(&lock);
        free(file);
        return false;
    }
    *file = (struct hid_file){handle, bcd_device, owned_fd, files};
    files = file;
    pthread_mutex_unlock(&lock);
    return true;
}

bool fold_hid_attach(HANDLE handle, USHORT vid, USHORT pid, unsigned interface_number,
                     USHORT bcd_device, const BYTE *descriptor, size_t length)
{
    return attach_file(handle, vid, pid, interface_number, bcd_device, descriptor, length, -1);
}

static bool attach_fd(HANDLE handle, int hidraw_fd, unsigned interface_number, USHORT bcd_device,
                      bool metadata_only)
{
    int fd = fcntl(hidraw_fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) return false;

    int flags = fcntl(fd, F_GETFL);
    struct hidraw_devinfo info;
    struct hidraw_report_descriptor descriptor = {.size = sizeof(report_descriptor)};
    int length = 0;
    bool bound = flags >= 0 && (flags & (O_NONBLOCK | O_ACCMODE)) == (O_NONBLOCK | O_RDWR) &&
                 interface_number == 4 && ioctl(fd, HIDIOCGRAWINFO, &info) == 0 && info.bustype == BUS_USB &&
                 ioctl(fd, HIDIOCGRDESCSIZE, &length) == 0 && length == (int) sizeof(report_descriptor) &&
                 ioctl(fd, HIDIOCGRDESC, &descriptor) == 0 &&
                 attach_file(handle, (USHORT)info.vendor, (USHORT)info.product, interface_number,
                             bcd_device, descriptor.value, descriptor.size, metadata_only ? -1 : fd);
    if (!bound || metadata_only) close(fd);
    return bound;
}

bool fold_hid_attach_fd(HANDLE h, int fd, unsigned iface, USHORT rev)
{ return attach_fd(h, fd, iface, rev, false); }

bool fold_hid_attach_probe_fd(HANDLE h, int fd, unsigned iface, USHORT rev)
{ return attach_fd(h, fd, iface, rev, true); }

void fold_hid_detach(HANDLE handle)
{
    pthread_mutex_lock(&lock);
    struct hid_file **slot = file_slot(handle);
    struct hid_file *file = *slot;
    if (file) *slot = file->next;
    pthread_mutex_unlock(&lock);
    if (file && file->fd >= 0) close(file->fd);
    free(file);
}

static BOOLEAN hid_error(int code)
{
    winerr_set_code(code);
    return FALSE;
}

void __winfnc HidD_GetHidGuid(GUID *guid)
{
    if (guid) *guid = DEFINE_GUID(4d1e55b2, f16f, 11cf, 88cb, 001111000030);
}
WINAPI(HidD_GetHidGuid)

BOOLEAN __winfnc HidD_GetAttributes(HANDLE handle, struct fold_hid_attributes *out)
{
    if (!out) return hid_error(error_invalid_parameter);
    pthread_mutex_lock(&lock);
    struct hid_file *file = *file_slot(handle);
    if (file) *out = (struct fold_hid_attributes){sizeof(*out), 0x17ef, 0x6142, file->bcd_device};
    bool found = file != NULL;
    pthread_mutex_unlock(&lock);
    return found ? TRUE : hid_error(error_invalid_handle);
}
WINAPI(HidD_GetAttributes)

BOOLEAN __winfnc HidD_GetPreparsedData(HANDLE handle, struct parsed_hid **out)
{
    if (!out) return hid_error(error_invalid_parameter);
    *out = NULL;
    pthread_mutex_lock(&lock);
    if (!*file_slot(handle)) {
        pthread_mutex_unlock(&lock);
        return hid_error(error_invalid_handle);
    }
    struct parsed_hid *data = malloc(sizeof(*data));
    if (data) {
        data->next = parsed_list;
        parsed_list = data;
        *out = data;
    }
    pthread_mutex_unlock(&lock);
    return data ? TRUE : hid_error(error_out_of_memory);
}
WINAPI(HidD_GetPreparsedData)

static struct parsed_hid **parsed_slot(const struct parsed_hid *data)
{
    struct parsed_hid **slot = &parsed_list;
    while (*slot && *slot != data) slot = &(*slot)->next;
    return slot;
}

BOOLEAN __winfnc HidD_FreePreparsedData(struct parsed_hid *data)
{
    pthread_mutex_lock(&lock);
    struct parsed_hid **slot = parsed_slot(data);
    if (!*slot) {
        pthread_mutex_unlock(&lock);
        return hid_error(error_invalid_parameter);
    }
    *slot = data->next;
    pthread_mutex_unlock(&lock);
    free(data);
    return TRUE;
}
WINAPI(HidD_FreePreparsedData)

static bool valid_data(const struct parsed_hid *data)
{
    pthread_mutex_lock(&lock);
    bool valid = *parsed_slot(data) != NULL;
    pthread_mutex_unlock(&lock);
    return valid;
}

NTSTATUS __winfnc HidP_GetCaps(const struct parsed_hid *data, struct fold_hid_caps *out)
{
    if (!out || !valid_data(data)) return hid_invalid_data;
    *out = (struct fold_hid_caps){
        .usage = 1, .usage_page = 0xff00, .link_nodes = 1,
        .input_length = 64, .output_length = 20, .feature_length = 20,
        .input_values = 2, .input_indices = 2, .output_values = 1,
        .output_indices = 1, .feature_values = 1, .feature_indices = 1
    };
    return hid_success;
}
WINAPI(HidP_GetCaps)

NTSTATUS __winfnc HidP_GetValueCaps(unsigned type, struct fold_hid_value_caps *out,
                                    USHORT *count, const struct parsed_hid *data)
{
    static const struct { BYTE id, usage, count; } reports[][2] = {
        {{0x0f, 6, 63}, {0x10, 5, 19}}, {{0x0e, 2, 19}}, {{0x11, 7, 19}}
    };
    if (!valid_data(data)) return hid_invalid_data;
    if (type >= 3) return hid_invalid_type;
    if (!count) return hid_short_buffer;
    USHORT available = out ? *count : 0;
    *count = type == 0 ? 2 : 1;
    for (USHORT i = 0; i < *count && i < available; ++i) {
        out[i] = (struct fold_hid_value_caps){
            .usage_page = 0xff00, .report_id = reports[type][i].id, .bit_field = 2,
            .link_usage = 1, .link_usage_page = 0xff00, .is_absolute = 1,
            .bit_size = 8, .report_count = reports[type][i].count, .logical_max = 255,
            .usage = reports[type][i].usage, .data_index = i
        };
    }
    return available < *count ? hid_short_buffer : hid_success;
}
WINAPI(HidP_GetValueCaps)

/* Pin the open file description while an operation runs concurrently with close. */
static int duplicate_io_fd(HANDLE handle)
{
    pthread_mutex_lock(&lock);
    struct hid_file *file = *file_slot(handle);
    int fd = -1;
    if (file && file->fd >= 0) fd = fcntl(file->fd, F_DUPFD_CLOEXEC, 0);
    else errno = file ? EACCES : EBADF;
    int error = errno;
    pthread_mutex_unlock(&lock);
    errno = error;
    return fd;
}

static BOOLEAN hid_io_error(int error)
{
    switch (error) {
    case EBADF: return hid_error(error_invalid_handle);
    case EACCES: case EPERM: return hid_error(5);      /* ERROR_ACCESS_DENIED */
    case ENODEV: case ENXIO: return hid_error(1167);   /* ERROR_DEVICE_NOT_CONNECTED */
    case ETIMEDOUT: return hid_error(121);             /* ERROR_SEM_TIMEOUT */
    case ECANCELED: case EINTR: return hid_error(995); /* ERROR_OPERATION_ABORTED */
    case EMFILE: case ENFILE: return hid_error(4);     /* ERROR_TOO_MANY_OPEN_FILES */
    case EINVAL: return hid_error(error_invalid_parameter);
    default: return hid_error(1117);                   /* ERROR_IO_DEVICE */
    }
}

static BOOLEAN feature_report(HANDLE handle, void *buffer, ULONG length, bool get)
{
    enum { feature_id = 0x11, feature_size = 20 };
    if (!buffer || length != feature_size || ((BYTE *)buffer)[0] != feature_id)
        return hid_error(error_invalid_parameter);
    int fd = duplicate_io_fd(handle);
    if (fd < 0) return hid_io_error(errno);

    BYTE report[feature_size] = {feature_id};
    if (!get) memcpy(report + 1, (BYTE *)buffer + 1, sizeof(report) - 1);
    /* A feature write can change device state. Never retry a partial transfer. */
    int transferred = ioctl(fd, get ? HIDIOCGFEATURE(feature_size) : HIDIOCSFEATURE(feature_size), report);
    int error = errno;
    close(fd);
    if (transferred < 0) return hid_io_error(error);
    if (transferred != feature_size || report[0] != feature_id)
        return hid_error(13); /* ERROR_INVALID_DATA */
    if (get) memcpy(buffer, report, sizeof(report));
    return TRUE;
}

BOOLEAN __winfnc HidD_GetFeature(HANDLE handle, void *buffer, ULONG length)
{
    return feature_report(handle, buffer, length, true);
}
WINAPI(HidD_GetFeature)

BOOLEAN __winfnc HidD_SetFeature(HANDLE handle, void *buffer, ULONG length)
{
    return feature_report(handle, buffer, length, false);
}
WINAPI(HidD_SetFeature)

BOOLEAN __winfnc HidD_FlushQueue(HANDLE handle)
{
    int fd = duplicate_io_fd(handle);
    if (fd < 0) return hid_io_error(errno);
    BYTE report[64];
    int error = 0;
    /* hidraw keeps a bounded FIFO per open. Draining at most one ring discards
     * everything queued on entry, even if additional traffic keeps arriving. */
    for (unsigned drained = 0; drained < HIDRAW_BUFFER_SIZE;) {
        ssize_t size = read(fd, report, sizeof(report));
        if (size > 0) {
            ++drained;
        } else if (size < 0 && errno == EINTR) {
            continue;
        } else {
            if (size == 0) error = ENODEV;
            else if (errno != EAGAIN) error = errno;
            break;
        }
    }
    close(fd);
    return error ? hid_io_error(error) : TRUE;
}
WINAPI(HidD_FlushQueue)
