#include "fold_file.h"
#include "fold_hid.h"
#include "../vendor-host/fold_cm.h"
#ifdef X1FOLD_OFFLINE_METADATA
#include "../vendor-host/metadata_fixture.h"
#endif
#include "winapi/internal.h"
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <strings.h>
#include <sys/eventfd.h>
#include <unistd.h>

/* A delegated open file description owns one physical input FIFO. Give it to
 * one Windows file at a time. Reads and writes can proceed independently. */
enum { queue_limit = 16, read_size = 64, write_size = 20 };
enum { disconnected = 1167, bad_report = 13, io_failure = 1117, aborted = 995 };
struct request {
    OVERLAPPED *overlapped;
    uint64_t order;
    void *input;
    BYTE output[write_size];
    bool writing, busy, cancelled;
};
struct hid_io {
    HANDLE handle;
    int fd, wake;
    bool running, closing, signaled, probe, awaiting_version;
    pthread_t worker;
    uint64_t next_order;
    struct request requests[queue_limit];
};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static struct hid_io *active;
static int source_fd = -1;
static USHORT revision;
static bool probe_binding, version_submitted, saw_open, saw_version;
static const BYTE get_version[write_size] = {0x0e,'s','y','n','a','p','t','i','c',3,0,0,0,0xff,0xc0,1};

/* These original entry points remain responsible for the upstream WBF files. */
extern BOOL __winfnc ReadFile(HANDLE, void *, DWORD, DWORD *, OVERLAPPED *);
extern BOOL __winfnc WriteFile(HANDLE, const void *, DWORD, DWORD *, OVERLAPPED *);
extern BOOL __winfnc CancelIoEx(HANDLE, OVERLAPPED *);
extern BOOL __winfnc GetOverlappedResult(HANDLE, OVERLAPPED *, DWORD *, BOOL);
extern DWORD __winfnc WaitForSingleObject(HANDLE, DWORD);
extern BOOL __winfnc CloseHandle(HANDLE);

static BOOL failed(DWORD code)
{
    winerr_set_code(code);
    return FALSE;
}

static bool bind_file(int fd, uint16_t usb_revision, bool probe)
{
    pthread_mutex_lock(&lock);
    bool bound = source_fd < 0 && !active && fold_cm_hid_path();
    if (bound) {
        source_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        bound = source_fd >= 0;
        revision = usb_revision;
        probe_binding = probe;
        version_submitted = false;
        saw_open = false;
        saw_version = false;
    }
    pthread_mutex_unlock(&lock);
    return bound;
}

bool fold_file_bind(int fd, uint16_t usb_revision) { return bind_file(fd, usb_revision, false); }
bool fold_file_bind_probe(int fd, uint16_t usb_revision) { return bind_file(fd, usb_revision, true); }

bool fold_file_bound_for_biometrics(void)
{
    pthread_mutex_lock(&lock);
    bool available = source_fd >= 0 && !probe_binding;
    pthread_mutex_unlock(&lock);
    return available;
}

bool fold_file_saw_open(void)
{
    pthread_mutex_lock(&lock);
    bool seen = saw_open;
    pthread_mutex_unlock(&lock);
    return seen;
}

bool fold_file_saw_version(void)
{
    pthread_mutex_lock(&lock);
    bool seen = saw_version;
    pthread_mutex_unlock(&lock);
    return seen;
}

bool fold_file_wait_version(unsigned timeout_ms)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
    deadline.tv_sec += deadline.tv_nsec / 1000000000L;
    deadline.tv_nsec %= 1000000000L;
    pthread_mutex_lock(&lock);
    while (source_fd >= 0 && probe_binding && !saw_version)
        if (pthread_cond_clockwait(&changed, &lock, CLOCK_MONOTONIC, &deadline)) break;
    bool confirmed = saw_version;
    pthread_mutex_unlock(&lock);
    return confirmed;
}

void fold_file_unbind(void)
{
    pthread_mutex_lock(&lock);
    if (source_fd >= 0) close(source_fd);
    source_fd = -1;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
}

static void wake_worker(struct hid_io *file)
{
    eventfd_t one = 1;
    while (eventfd_write(file->wake, one) < 0 && errno == EINTR) {}
}

static void finish(struct request *request, DWORD error, DWORD count)
{
    OVERLAPPED *overlapped = request->overlapped;
    /* Internal follows the NT I/O completion ABI; translate to Win32 on query. */
    NTSTATUS status = STATUS_SUCCESS;
    if (error == aborted) status = STATUS_CANCELLED;
    else if (error == disconnected) status = 0xc000009d; /* STATUS_DEVICE_NOT_CONNECTED */
    else if (error == bad_report) status = 0xc000003e; /* STATUS_DATA_ERROR */
    else if (error) status = 0xc0000185; /* STATUS_IO_DEVICE_ERROR */
    overlapped->InternalHigh = count;
    overlapped->Internal = status;
    request->overlapped = NULL;
    active->signaled = true;
    if (overlapped->hEvent) win_set_event(overlapped->hEvent);
    pthread_cond_broadcast(&changed);
}

static struct request *oldest(struct hid_io *file, bool writing)
{
    struct request *first = NULL;
    for (size_t i = 0; i < queue_limit; i++) {
        struct request *r = &file->requests[i];
        if (r->overlapped && writing == r->writing && (!first || r->order < first->order)) first = r;
    }
    return first;
}

/* Enter and return with the state lock held. Run the kernel call without the
 * lock, so CancelIoEx can mark a request even during a USB transfer. */
static void transfer(struct hid_io *file, struct request *r)
{
    if (!r) return;
    BYTE input[read_size + 1] = {0};
    r->busy = true;
    pthread_mutex_unlock(&lock);
#ifdef X1FOLD_SERVICE_WORKER
    /* Normal discovery and TLS records used by the paired OEM driver. A
     * login transaction must never start plaintext ownership or firmware work. */
    if (r->writing && !memcmp(r->output + 1, "synaptic", 8) && (r->output[14] & 0x40)) {
        switch (r->output[15]) {
        case 0x01: case 0xb4: case 0x57: case 0x19: case 0x3e: case 0x40:
        case 0x8e: case 0xaf: case 0x9e: case 0x44:
            break;
        case 0x15: case 0x17:
            if (r->output[16] == 3 && r->output[17] >= 1 && r->output[17] <= 3) break;
            _exit(71);
        default:
            _exit(71);
        }
    }
#endif
    ssize_t size = r->writing ? write(file->fd, r->output, write_size) : read(file->fd, input, sizeof(input));
    int saved = errno;
    pthread_mutex_lock(&lock);
    r->busy = false;
    if (r->cancelled) {
        finish(r, aborted, 0);
    } else if (size < 0 && (saved == EAGAIN || (!r->writing && saved == EINTR))) {
        return;
    } else if (!size || (size < 0 && (saved == ENODEV || saved == ENXIO))) {
        finish(r, disconnected, 0);
    } else if (size < 0) {
        finish(r, io_failure, 0);
    } else if (r->writing) {
        if (file->probe && size == write_size) file->awaiting_version = true;
        finish(r, size == write_size ? 0 : io_failure, size == write_size ? write_size : 0);
    } else if (file->probe) {
        static const BYTE version_reply[] = {0x0f,'s','y','n','a','p','t','i','c',42,0,0,0,38,0,0,0,0,0};
        if (size == 20 && input[0] == 0x10) return; /* Interleaved HID event. */
        file->awaiting_version = false;
#ifdef X1FOLD_OFFLINE_METADATA
        if (size == read_size && !memcmp(input, fold_fixture_bad_command, read_size)) {
            memcpy(r->input, input, read_size);
            finish(r, 0, read_size);
            return;
        }
#endif
        if (size == read_size && !memcmp(input, version_reply, sizeof(version_reply))) {
            memcpy(r->input, input, read_size);
            saw_version = true;
            finish(r, 0, read_size);
        } else finish(r, bad_report, 0);
    } else if ((size == read_size && input[0] == 0x0f) || (size == 20 && input[0] == 0x10)) {
        /* Windows returns the collection's full input report length, including
         * zero padding for the shorter event. The Lenovo DLL checks that length. */
        memcpy(r->input, input, read_size);
        finish(r, 0, read_size);
    } else {
        finish(r, bad_report, 0);
    }
}

static void *run_worker(void *arg)
{
    struct hid_io *file = arg;
    pthread_mutex_lock(&lock);
    while (!file->closing) {
        bool read_enabled = !file->probe || file->awaiting_version;
        short events = (read_enabled && oldest(file, false) ? POLLIN : 0) | (oldest(file, true) ? POLLOUT : 0);
        struct pollfd fds[] = {{file->wake, POLLIN, 0}, {events ? file->fd : -1, events, 0}};
        pthread_mutex_unlock(&lock);
        int rc = poll(fds, 2, -1);
        int saved = errno;
        pthread_mutex_lock(&lock);
        if (file->closing) break;
        if (rc < 0 && saved == EINTR) continue;
        if (fds[0].revents & POLLIN) {
            eventfd_t value;
            while (eventfd_read(file->wake, &value) < 0 && errno == EINTR) {}
        }
        if (rc < 0 || fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            for (size_t i = 0; i < queue_limit; i++)
                if (file->requests[i].overlapped) finish(&file->requests[i], disconnected, 0);
            continue;
        }
        if (fds[1].revents & POLLOUT) transfer(file, oldest(file, true));
        if (!file->closing && fds[1].revents & POLLIN) transfer(file, oldest(file, false));
    }
    pthread_mutex_unlock(&lock);
    return NULL;
}

static bool cancel_requests(struct hid_io *file, OVERLAPPED *specific)
{
    bool found = false;
    for (size_t i = 0; i < queue_limit; i++) {
        struct request *r = &file->requests[i];
        if (!r->overlapped || (specific && r->overlapped != specific)) continue;
        found = true;
        if (r->busy) r->cancelled = true;
        else finish(r, aborted, 0);
    }
    wake_worker(file);
    return found;
}

static void close_file(void *ctx)
{
    struct hid_io *file = ctx;
    pthread_mutex_lock(&lock);
    file->closing = true;
    cancel_requests(file, NULL);
    pthread_mutex_unlock(&lock);
    if (file->running) pthread_join(file->worker, NULL);
    fold_hid_detach(file->handle);
    pthread_mutex_lock(&lock);
    if (active == file) active = NULL;
    pthread_mutex_unlock(&lock);
    close(file->fd);
    close(file->wake);
    free(file);
}

static HANDLE open_file(bool match, DWORD access, DWORD share, DWORD disposition, DWORD flags, HANDLE template)
{
    if (!match) { failed(2); return INVALID_HANDLE_VALUE; }
    if (access != 0xc0000000u || (share & ~3u) || disposition != 3 ||
        flags != FILE_FLAG_OVERLAPPED || template) { failed(87); return INVALID_HANDLE_VALUE; }
    pthread_mutex_lock(&lock);
    saw_open = true;
    if (source_fd < 0 || active) {
        DWORD error = active ? 32 : disconnected;
        pthread_mutex_unlock(&lock);
        failed(error);
        return INVALID_HANDLE_VALUE;
    }
    struct hid_io *file = calloc(1, sizeof(*file));
    if (!file) { pthread_mutex_unlock(&lock); failed(8); return INVALID_HANDLE_VALUE; }
    file->fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    file->wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (file->fd < 0 || file->wake < 0) {
        if (file->fd >= 0) close(file->fd);
        if (file->wake >= 0) close(file->wake);
        free(file);
        pthread_mutex_unlock(&lock);
        failed(4);
        return INVALID_HANDLE_VALUE;
    }
    file->handle = winio_create_file(file, true, NULL, NULL, NULL, NULL, NULL, close_file);
    file->signaled = true;
    file->probe = probe_binding;
    active = file;
    bool attached = file->probe ? fold_hid_attach_probe_fd(file->handle, file->fd, 4, revision) :
                                  fold_hid_attach_fd(file->handle, file->fd, 4, revision);
    if (attached &&
        pthread_create(&file->worker, NULL, run_worker, file) == 0) {
        file->running = true;
        HANDLE handle = file->handle;
        pthread_mutex_unlock(&lock);
        return handle;
    }
    pthread_mutex_unlock(&lock);
    winhandle_destroy(file->handle);
    failed(disconnected);
    return INVALID_HANDLE_VALUE;
}

HANDLE __winfnc CreateFileA(const char *name, DWORD access, DWORD share, void *security,
                            DWORD disposition, DWORD flags, HANDLE template)
{
    (void)security;
    const char *path = fold_cm_hid_path();
    return open_file(path && name && !strcasecmp(path, name), access, share, disposition, flags, template);
}
WINAPI(CreateFileA)

HANDLE __winfnc CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *security,
                            DWORD disposition, DWORD flags, HANDLE template)
{
    (void)security;
    const char *path = fold_cm_hid_path();
    bool match = name && path;
    while (match && *path) {
        match = *name <= 127 && tolower((unsigned char)*name) == tolower((unsigned char)*path);
        ++name;
        ++path;
    }
    return open_file(match && !*name, access, share, disposition, flags, template);
}
WINAPI(CreateFileW)

/* Called under lock after the HID output report length has been checked. */
static const BYTE *probe_command(const void *buf)
{
#ifdef X1FOLD_OFFLINE_METADATA
    if (!memcmp(buf, fold_fixture_version2, write_size)) return fold_fixture_version2;
#endif
    if (version_submitted || memcmp(buf, get_version, write_size)) return NULL;
    version_submitted = true;
    return get_version;
}

static BOOL submit(HANDLE handle, void *buf, DWORD size, DWORD *bytes, OVERLAPPED *ov, bool writing)
{
    pthread_mutex_lock(&lock);
    if (!active || handle != active->handle) {
        pthread_mutex_unlock(&lock);
        return writing ? WriteFile(handle, buf, size, bytes, ov) : ReadFile(handle, buf, size, bytes, ov);
    }
    if (bytes) *bytes = 0;
    if (active->closing || !ov || !buf || (writing ? (size != write_size || ((BYTE *)buf)[0] != 0x0e) : size < read_size)) {
        pthread_mutex_unlock(&lock);
        return failed(87);
    }
    struct request *slot = NULL;
    for (size_t i = 0; i < queue_limit; i++) {
        struct request *r = &active->requests[i];
        if (r->overlapped == ov) { pthread_mutex_unlock(&lock); return failed(87); }
        if (!r->overlapped && !slot) slot = r;
    }
    if (!slot) { pthread_mutex_unlock(&lock); return failed(1816); } /* ERROR_NOT_ENOUGH_QUOTA */
    const void *output = buf;
    if (writing && active->probe) {
        output = probe_command(buf);
        if (!output) {
            pthread_mutex_unlock(&lock);
            return failed(5);
        }
    }
    *slot = (struct request){.overlapped = ov, .order = ++active->next_order, .writing = writing};
    if (writing) memcpy(slot->output, output, write_size);
    else slot->input = buf;
    ov->Internal = STATUS_PENDING;
    ov->InternalHigh = 0;
    active->signaled = false;
    if (ov->hEvent) win_reset_event(ov->hEvent);
    wake_worker(active);
    pthread_mutex_unlock(&lock);
    return failed(ERROR_IO_PENDING);
}

static BOOL __winfnc read_file(HANDLE h, void *buf, DWORD size, DWORD *bytes, OVERLAPPED *ov)
{ return submit(h, buf, size, bytes, ov, false); }

static BOOL __winfnc write_file(HANDLE h, const void *buf, DWORD size, DWORD *bytes, OVERLAPPED *ov)
{ return submit(h, (void *)buf, size, bytes, ov, true); }

static BOOL __winfnc cancel_io(HANDLE handle, OVERLAPPED *ov)
{
    pthread_mutex_lock(&lock);
    if (!active || active->handle != handle) { pthread_mutex_unlock(&lock); return CancelIoEx(handle, ov); }
    bool found = cancel_requests(active, ov);
    pthread_mutex_unlock(&lock);
    return found ? TRUE : failed(1168);
}

static BOOL __winfnc get_result(HANDLE handle, OVERLAPPED *ov, DWORD *count, BOOL wait)
{
    pthread_mutex_lock(&lock);
    if (!active || active->handle != handle) {
        pthread_mutex_unlock(&lock);
        return GetOverlappedResult(handle, ov, count, wait);
    }
    if (!ov || !count) { pthread_mutex_unlock(&lock); return failed(87); }
    while (wait && ov->Internal == STATUS_PENDING) pthread_cond_wait(&changed, &lock);
    NTSTATUS status = ov->Internal;
    *count = ov->InternalHigh;
    pthread_mutex_unlock(&lock);
    if (status == STATUS_PENDING) return failed(ERROR_IO_INCOMPLETE);
    if (status == STATUS_CANCELLED) return failed(aborted);
    if (status == 0xc000009d) return failed(disconnected);
    if (status == 0xc000003e) return failed(bad_report);
    return status == STATUS_SUCCESS ? TRUE : failed(io_failure);
}

static DWORD __winfnc wait_file(HANDLE handle, DWORD timeout)
{
    pthread_mutex_lock(&lock);
    if (!active || active->handle != handle) {
        pthread_mutex_unlock(&lock);
        return WaitForSingleObject(handle, timeout);
    }
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout / 1000;
    deadline.tv_nsec += (timeout % 1000) * 1000000L;
    deadline.tv_sec += deadline.tv_nsec / 1000000000L;
    deadline.tv_nsec %= 1000000000L;
    DWORD result = 0;
    while (active && active->handle == handle && !active->signaled) {
        int error = timeout == INFINITE ? pthread_cond_wait(&changed, &lock) :
                    pthread_cond_clockwait(&changed, &lock, CLOCK_MONOTONIC, &deadline);
        if (error == ETIMEDOUT && active && !active->signaled) {
            result = WAIT_TIMEOUT;
            break;
        }
    }
    pthread_mutex_unlock(&lock);
    return result;
}

static BOOL __winfnc close_handle(HANDLE handle)
{
    if (!handle || handle == INVALID_HANDLE_VALUE) return failed(6);
    return CloseHandle(handle);
}

/* Apply -Wl,--wrap=resolve_windows_api. DeviceIoControl and the WinBio file
 * callbacks stay in libtudor. Only this module's physical handle is dispatched. */
extern void *__real_resolve_windows_api(const char *);
extern void *fold_module_api(const char *) __attribute__((weak));
void *__wrap_resolve_windows_api(const char *name)
{
    void *module_api = fold_module_api ? fold_module_api(name) : NULL;
    if (module_api) return module_api;
    if (!strcmp(name, "ReadFile")) return read_file;
    if (!strcmp(name, "WriteFile")) return write_file;
    if (!strcmp(name, "CancelIoEx")) return cancel_io;
    if (!strcmp(name, "GetOverlappedResult")) return get_result;
    if (!strcmp(name, "WaitForSingleObject")) return wait_file;
    if (!strcmp(name, "CloseHandle")) return close_handle;
    return __real_resolve_windows_api(name);
}
