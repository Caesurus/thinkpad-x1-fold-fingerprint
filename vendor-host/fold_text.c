/* WideCharToMultiByte for the US-Western/UTF-8 Windows host. */
#include "winapi/api.h"
#include <errno.h>
#include <iconv.h>
#include <limits.h>

static int conversion_error(DWORD code) {
    winerr_set_code(code);
    return 0;
}

static int __winfnc lstrlenW(const WCHAR *wide) {
    return wide ? winstr_len(wide) : 0;
}
WINAPI(lstrlenW)

static WCHAR *__winfnc lstrcpyW(WCHAR *target, const WCHAR *source) {
    if (!target || !source) return NULL;
    memcpy(target, source, ((size_t)winstr_len(source) + 1) * sizeof(*source));
    return target;
}
WINAPI(lstrcpyW)

static int __winfnc WideCharToMultiByte(UINT page, DWORD flags, const WCHAR *wide,
        int count, char *out, int capacity, const char *replacement, BOOL *used_default) {
    const bool utf8 = page == 65001;
    if (!wide || count == 0 || count < -1 || capacity < 0 || (capacity && !out) ||
            (page != 0 && page != 1252 && !utf8) || (utf8 && (replacement || used_default)))
        return conversion_error(87); /* ERROR_INVALID_PARAMETER */
    if ((utf8 && (flags & ~0x80u)) ||
        (!utf8 && flags != 0 && flags != 0x200 && flags != 0x400))
        return conversion_error(1004); /* ERROR_INVALID_FLAGS */
    if (used_default) *used_default = FALSE;

    size_t chars = count == -1 ? (size_t)winstr_len(wide) + 1 : (size_t)count;
    char *input = (char *)wide;
    size_t left = chars * sizeof(*wide);
    iconv_t cv = iconv_open(utf8 ? "UTF-8" : "WINDOWS-1252", "UTF-16LE");
    if (cv == (iconv_t)-1) return conversion_error(87);
    size_t total = 0;
    DWORD error = 0;
    while (left) {
        char scratch[256];
        char *cursor = capacity ? out + total : scratch;
        size_t available = capacity ? (size_t)capacity - total : sizeof scratch;
        size_t before = available;
        size_t result = iconv(cv, &input, &left, &cursor, &available);
        total += before - available;
        if (result != (size_t)-1) continue;
        if (errno == E2BIG && !capacity) continue;
        if (errno == E2BIG) { error = 122; break; } /* ERROR_INSUFFICIENT_BUFFER */
        if ((errno != EILSEQ && errno != EINVAL) || (utf8 && flags == 0x80)) {
            error = 1113; /* ERROR_NO_UNICODE_TRANSLATION */
            break;
        }
        const char *fallback = utf8 ? "\xef\xbf\xbd" : (replacement ? replacement : "?");
        size_t length = utf8 ? 3 : 1;
        if (capacity && available < length) { error = 122; break; }
        if (capacity) memcpy(out + total, fallback, length);
        if (used_default) *used_default = TRUE;
        total += length;
        const WCHAR *failed = (const WCHAR *)input;
        size_t skip = sizeof(*wide);
        if (left >= 2 * skip && failed[0] >= 0xd800 && failed[0] <= 0xdbff &&
                failed[1] >= 0xdc00 && failed[1] <= 0xdfff)
            skip *= 2;
        input += skip;
        left -= skip;
    }
    iconv_close(cv);
    if (error || total > INT_MAX) return conversion_error(error ? error : 122);
    return (int)total;
}
WINAPI(WideCharToMultiByte)
