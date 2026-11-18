/* The two vendor DLLs stay mapped until guest shutdown. The Windows CRT
   holds a module reference while a worker thread runs. */
#include "tudor/internal.h"
#include <limits.h>
#include <strings.h>
#include <unistd.h>

extern BOOL __winfnc GetModuleHandleExW(DWORD, const WCHAR *, HANDLE *);
extern HANDLE __winfnc GetModuleHandleA(const char *);
extern BOOL __winfnc FreeLibrary(HANDLE);
extern void __winfnc ExitThread(DWORD);

static unsigned references[NUM_WINDRV_DLLS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct winmodule process_module;
static char executable[PATH_MAX + 1];
static const char *environment[] = {NULL};
static pthread_once_t process_once = PTHREAD_ONCE_INIT;

static void register_process(void)
{
    ssize_t size = readlink("/proc/self/exe", executable, sizeof executable);
    if (size <= 0 || (size_t)size >= sizeof executable) return;
    executable[size] = '\0';
    process_module.name = executable;
    process_module.cmdline = executable;
    process_module.environ = environment;
    winmodule_register(&process_module);
}

static HANDLE process_handle(void)
{
    pthread_once(&process_once, register_process);
    if (!process_module.handle) winerr_set_code(126);
    return process_module.handle;
}

static HANDLE __winfnc module_a(const char *name)
{
    if (!name) return process_handle();
    for (unsigned i = 0; i < NUM_WINDRV_DLLS; ++i) {
        struct winmodule *module = &tudor_windrv_dlls[i].module;
        if (module->handle && !strcasecmp(name, module->name)) return module->handle;
    }
    HANDLE handle = GetModuleHandleA(name);
    if (!handle) winerr_set_code(126);
    return handle;
}

static HANDLE __winfnc module_w(const WCHAR *name)
{
    if (!name) return process_handle();
    char *text = winstr_to_str(name);
    if (!text) { winerr_set_code(8); return NULL; }
    HANDLE handle = module_a(text);
    free(text);
    return handle;
}

/* NULL requests the executable, even when called from a vendor DLL.
   The wide API measures its buffer in WCHARs. A truncated name still
   terminates and returns the caller's original capacity. */
static const char *module_name(HANDLE handle)
{
    if (!handle) handle = process_handle();
    if (!handle || handle == INVALID_HANDLE_VALUE) { winerr_set_code(6); return NULL; }
    const struct winmodule *module = handle->data;
    return module->name;
}

static DWORD copy_name(void *out, DWORD capacity, const void *source, size_t length, size_t unit)
{
    if (!out || !capacity) { winerr_set_code(capacity ? 87 : 122); return 0; }
    size_t copied = length < capacity ? length : (size_t)capacity - 1;
    memcpy(out, source, copied * unit);
    memset((char *)out + copied * unit, 0, unit);
    if (length >= capacity) { winerr_set_code(122); return capacity; }
    return (DWORD)copied;
}

static DWORD __winfnc filename_a(HANDLE handle, char *out, DWORD capacity)
{
    const char *name = module_name(handle);
    return name ? copy_name(out, capacity, name, strlen(name), sizeof(*out)) : 0;
}

static DWORD __winfnc filename_w(HANDLE handle, WCHAR *out, DWORD capacity)
{
    const char *name = module_name(handle);
    if (!name) return 0;
    WCHAR *wide = winstr_from_str(name);
    if (!wide) { winerr_set_code(8); return 0; }
    DWORD len = copy_name(out, capacity, wide, winstr_len(wide), sizeof(*out));
    free(wide);
    return len;
}

static BOOL invalid(DWORD code)
{
    winerr_set_code(code);
    return FALSE;
}

static BOOL __winfnc module_handle(DWORD flags, const WCHAR *name, HANDLE *out)
{
    enum { PIN = 1, UNCHANGED = 2, FROM_ADDRESS = 4 };
    if (!out) return invalid(87);
    *out = NULL;
    if ((flags & ~7u) || ((flags & PIN) && (flags & UNCHANGED))) return invalid(87);
    if (!name) {
        if (flags & FROM_ADDRESS) return invalid(126);
        *out = process_handle();
        return *out != NULL;
    }
    char *text = flags & FROM_ADDRESS ? NULL : winstr_to_str(name);
    for (unsigned i = 0; i < NUM_WINDRV_DLLS; ++i) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];
        uintptr_t address = (uintptr_t)name, base = (uintptr_t)dll->image.base_addr;
        if (!base || !dll->module.handle) continue;
        bool found = (flags & FROM_ADDRESS) ?
            (address >= base && address - base < (size_t)dll->image.image_size) :
            (text && !strcasecmp(text, dll->module.name));
        if (found) {
            free(text);
            pthread_mutex_lock(&lock);
            if (!(flags & UNCHANGED)) references[i]++;
            *out = dll->module.handle;
            pthread_mutex_unlock(&lock);
            return TRUE;
        }
    }
    free(text);
    if (flags & FROM_ADDRESS) return invalid(126);
    return GetModuleHandleExW(flags, name, out);
}

static BOOL __winfnc release(HANDLE handle)
{
    if (!handle || handle == INVALID_HANDLE_VALUE) return invalid(6);
    if (handle == process_handle()) return TRUE; /* process lifetime */
    for (unsigned i = 0; i < NUM_WINDRV_DLLS; ++i) {
        if (handle != tudor_windrv_dlls[i].module.handle) continue;
        pthread_mutex_lock(&lock);
        bool held = references[i] != 0;
        if (held) references[i]--;
        pthread_mutex_unlock(&lock);
        return held ? TRUE : invalid(6);
    }
    return FreeLibrary(handle);
}

static void __winfnc release_and_exit(HANDLE handle, DWORD result)
{
    release(handle);
    ExitThread(result);
}

void *fold_module_api(const char *name)
{
    if (!strcmp(name, "GetModuleHandleA")) return module_a;
    if (!strcmp(name, "GetModuleHandleW")) return module_w;
    if (!strcmp(name, "GetModuleFileNameA")) return filename_a;
    if (!strcmp(name, "GetModuleFileNameW")) return filename_w;
    if (!strcmp(name, "GetModuleHandleExW")) return module_handle;
    if (!strcmp(name, "FreeLibrary")) return release;
    if (!strcmp(name, "FreeLibraryAndExitThread")) return release_and_exit;
    return NULL;
}
