/* The private worker has no Windows window station or Terminal Services
 * session. Windows failures here leave notification handling to the vendor. */
#include "winapi/internal.h"
#include "fold_message.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Win64 WTSINFOEXW with WTSINFOEX_LEVEL1_W in its aligned union. */
struct console_info { DWORD level, padding, session; BYTE other[220]; };
_Static_assert(sizeof(struct console_info) == 232, "Win64 WTSINFOEXW size");

static bool read_console(struct console_info *info)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    const char *path = secure_getenv("FOLD_WTS_SOCKET");
    if (!path) path = "/run/fold-console.sock";
    if (strlen(path) >= sizeof(address.sun_path)) return false;
    memcpy(address.sun_path, path, strlen(path) + 1);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    struct timeval timeout = {.tv_sec = 8};
    bool ok = !setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
              !connect(fd, (const struct sockaddr *)&address, sizeof(address)) &&
              recv(fd, info, sizeof(*info), MSG_TRUNC) == sizeof(*info) && info->level == 1;
    close(fd);
    return ok;
}

static DWORD __winfnc WTSGetActiveConsoleSessionId(void)
{
    struct console_info info;
    return read_console(&info) ? info.session : UINT32_MAX;
}
WINAPI(WTSGetActiveConsoleSessionId)

static BOOL __winfnc WTSQuerySessionInformationW(HANDLE server, DWORD id, DWORD type,
                                                 WCHAR **out, DWORD *size)
{
    if (!out || !size) { winerr_set_code(87); return FALSE; }
    *out = NULL;
    *size = 0;
    if (server || type != 25) { winerr_set_code(50); return FALSE; }
    struct console_info info;
    if (!read_console(&info) || (id != info.session && id != UINT32_MAX)) {
        winerr_set_code(7022); /* ERROR_CTX_WINSTATION_NOT_FOUND */
        return FALSE;
    }
    *out = malloc(sizeof(info));
    if (!*out) { winerr_set_code(8); return FALSE; }
    memcpy(*out, &info, sizeof(info));
    *size = sizeof(info);
    return TRUE;
}
WINAPI(WTSQuerySessionInformationW)

static void __winfnc WTSFreeMemory(void *data) { free(data); }
WINAPI(WTSFreeMemory)

static USHORT __winfnc RegisterClassExW(const void *window_class)
{
    if (!fold_message_init()) return 0;
    winerr_set_code(window_class ? 5 : 87); /* ERROR_ACCESS_DENIED / INVALID_PARAMETER */
    return 0;
}
WINAPI(RegisterClassExW)

static HANDLE __winfnc CreateWindowExW(DWORD extended, const WCHAR *class_name, const WCHAR *name,
                                       DWORD style, int x, int y, int w, int h, HANDLE parent,
                                       HANDLE menu, HANDLE instance, void *data)
{
    (void)extended; (void)class_name; (void)name; (void)style; (void)x; (void)y;
    (void)w; (void)h; (void)parent; (void)menu; (void)instance; (void)data;
    if (!fold_message_init()) return NULL;
    winerr_set_code(5); /* No window station was delegated. */
    return NULL;
}
WINAPI(CreateWindowExW)

static BOOL __winfnc DestroyWindow(HANDLE window)
{
    /* CreateWindowExW cannot return a window in the headless station. */
    (void)window;
    winerr_set_code(1400); /* ERROR_INVALID_WINDOW_HANDLE */
    return FALSE;
}
WINAPI(DestroyWindow)

static BOOL __winfnc WTSRegisterSessionNotification(HANDLE window, DWORD flags)
{
    (void)window;
    (void)flags;
    winerr_set_code(1400);
    return FALSE;
}
WINAPI(WTSRegisterSessionNotification)

static BOOL __winfnc WTSUnRegisterSessionNotification(HANDLE window)
{
    (void)window;
    winerr_set_code(1400);
    return FALSE;
}
WINAPI(WTSUnRegisterSessionNotification)

static BOOL __winfnc UnregisterClassW(const WCHAR *name, HANDLE instance)
{
    (void)name; (void)instance;
    if (!fold_message_init()) return FALSE;
    winerr_set_code(1411); /* ERROR_CLASS_DOES_NOT_EXIST */
    return FALSE;
}
WINAPI(UnregisterClassW)
