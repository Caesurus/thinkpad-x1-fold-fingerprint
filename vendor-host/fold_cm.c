/* Windows Configuration Manager view of the single USB reader delegated to
   this host. The parent chain models Lenovo's fingerprint filter's child. */
#include "fold_cm.h"
#include "winapi/api.h"
#include <ctype.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <openssl/sha.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

enum { OK, INVALID_POINTER = 3, INVALID_FLAG = 4, NO_DEVNODE = 13,
       BUFFER_SMALL = 26, BAD_DEVICE_ID = 30 };
enum { BIOMETRIC = 1, HID, USB_INTERFACE, USB_DEVICE };
static const char hid_class[] = "{4d1e55b2-f16f-11cf-88cb-001111000030}";
static const char *const hwid[] = {NULL,
    "{53D29EF7-377C-4D14-864B-EB3A85769359}\\SYNAPTICSFINGERPRINTSENSOR_VID&06CB_PID&00DD",
    "HID\\VID_17EF&PID_6142&MI_04", "USB\\VID_17EF&PID_6142&MI_04", "USB\\VID_17EF&PID_6142"};
static char ids[5][256], path[256];
static bool bound;

static void register_location(const char *location)
{
    for (unsigned i = BIOMETRIC; i <= USB_DEVICE; i++)
        snprintf(ids[i], sizeof ids[i], "%s\\%s", hwid[i], location);
    snprintf(path, sizeof path, "\\\\?\\HID#VID_17EF&PID_6142&MI_04#%s#%s", location, hid_class);
    bound = true;
}

#ifdef X1FOLD_OFFLINE_PNP
/* Only the device-free integration test links this entry point. */
void fold_cm_offline_fixture(void) { register_location("OFFLINE_TEST"); }
#endif

bool fold_cm_bind(int fd)
{
    struct hidraw_devinfo info;
    struct hidraw_report_descriptor descriptor = {0};
    struct stat st;
    int size;
    char iface_path[128], location[96] = {0};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    static const unsigned char known[] = {
        0xe5,0xa3,0xb7,0x72,0xdf,0xa4,0x4a,0x13,0x1f,0x7c,0xfc,0xee,0x62,0x76,0x48,0x83,
        0x35,0x37,0xbd,0xae,0xe5,0x98,0xf0,0x36,0x3d,0x31,0xc9,0x14,0xc2,0xa2,0xfa,0x16
    };
    if (bound || fstat(fd, &st) || !S_ISCHR(st.st_mode) ||
        ioctl(fd, HIDIOCGRAWINFO, &info) < 0 || info.bustype != BUS_USB ||
        info.vendor != 0x17ef || info.product != 0x6142 ||
        ioctl(fd, HIDIOCGRDESCSIZE, &size) < 0 || size != 68) return false;
    descriptor.size = size;
    if (ioctl(fd, HIDIOCGRDESC, &descriptor) < 0 ||
        !SHA256(descriptor.value, size, digest) || memcmp(digest, known, sizeof known)) return false;
    snprintf(iface_path, sizeof iface_path, "/sys/dev/char/%u:%u/device/../bInterfaceNumber",
             major(st.st_rdev), minor(st.st_rdev));
    FILE *file = fopen(iface_path, "r");
    if (!file) return false;
    unsigned iface;
    bool valid = fscanf(file, "%x", &iface) == 1 && iface == 4;
    fclose(file);
    if (!valid || ioctl(fd, HIDIOCGRAWPHYS(sizeof location - 1), location) <= 0 || !location[0])
        return false;
    for (char *c = location; *c; ++c)
        if (!isalnum((unsigned char)*c)) *c = '_';
    register_location(location);
    return true;
}

const char *fold_cm_hid_path(void) { return bound ? path : NULL; }
const char *fold_cm_biometric_id(void) { return bound ? ids[BIOMETRIC] : NULL; }

static bool same_wide(const WCHAR *wide, const char *ascii)
{
    if (!wide || !ascii) return false;
    for (; *ascii; ++ascii, ++wide)
        if (*wide > 127 || tolower((unsigned char)*wide) != tolower((unsigned char)*ascii)) return false;
    return *wide == 0;
}

static bool has_hid(const GUID *class_id)
{
    GUID hid = DEFINE_GUID(4d1e55b2,f16f,11cf,88cb,001111000030);
    return bound && class_id && memcmp(class_id, &hid, sizeof hid) == 0;
}

static ULONG list(const GUID *class_id, const void *filter, void *dst, ULONG capacity,
                  ULONG *size, ULONG flags, bool wide)
{
    if (!class_id || (!size && !dst)) return INVALID_POINTER;
    if (flags > 1) return INVALID_FLAG;
    bool match = has_hid(class_id) && (!filter || (wide ? same_wide(filter, ids[HID]) :
                                                   strcasecmp(filter, ids[HID]) == 0));
    size_t len = match ? strlen(path) + 1 : 0;
    if (size) { *size = (ULONG)len + 1; return OK; }
    if (capacity < len + 1) return BUFFER_SMALL;
    for (size_t i = 0; i <= len; i++) {
        char c = i < len ? path[i] : 0;
        if (wide) ((WCHAR *)dst)[i] = (unsigned char)c;
        else ((char *)dst)[i] = c;
    }
    return OK;
}

ULONG __winfnc CM_Get_Device_Interface_List_SizeA(ULONG *sz, const GUID *g, const char *id, ULONG f)
{ return list(g, id, NULL, 0, sz, f, false); }
WINAPI(CM_Get_Device_Interface_List_SizeA)
ULONG __winfnc CM_Get_Device_Interface_List_SizeW(ULONG *sz, const GUID *g, const WCHAR *id, ULONG f)
{ return list(g, id, NULL, 0, sz, f, true); }
WINAPI(CM_Get_Device_Interface_List_SizeW)
ULONG __winfnc CM_Get_Device_Interface_ListA(const GUID *g, const char *id, char *buf, ULONG n, ULONG f)
{ return list(g, id, buf, n, NULL, f, false); }
WINAPI(CM_Get_Device_Interface_ListA)
ULONG __winfnc CM_Get_Device_Interface_ListW(const GUID *g, const WCHAR *id, WCHAR *buf, ULONG n, ULONG f)
{ return list(g, id, buf, n, NULL, f, true); }
WINAPI(CM_Get_Device_Interface_ListW)

ULONG __winfnc CM_Locate_DevNodeW(ULONG *out, const WCHAR *id, ULONG flags)
{
    if (!out) return INVALID_POINTER;
    if (flags) return INVALID_FLAG;
    if (!id) return NO_DEVNODE;
    for (unsigned i = BIOMETRIC; bound && i <= USB_DEVICE; i++)
        if (same_wide(id, ids[i])) { *out = i; return OK; }
    return NO_DEVNODE;
}
WINAPI(CM_Locate_DevNodeW)

ULONG __winfnc CM_Get_Parent(ULONG *out, ULONG node, ULONG flags)
{
    if (!out) return INVALID_POINTER;
    if (flags) return INVALID_FLAG;
    if (!bound || node < BIOMETRIC || node >= USB_DEVICE) return NO_DEVNODE;
    *out = node + 1;
    return OK;
}
WINAPI(CM_Get_Parent)

ULONG __winfnc CM_Get_Device_ID_Size(ULONG *out, ULONG node, ULONG flags)
{
    if (!out) return INVALID_POINTER;
    if (flags) return INVALID_FLAG;
    if (!bound || node < BIOMETRIC || node > USB_DEVICE) return NO_DEVNODE;
    /* Lenovo 6.0.8.1153 passes this size straight back as the output
       capacity. Reserve the terminator in our private guest namespace. */
    *out = (ULONG)strlen(ids[node]) + 1;
    return OK;
}
WINAPI(CM_Get_Device_ID_Size)

ULONG __winfnc CM_Get_Device_IDW(ULONG node, WCHAR *buf, ULONG cap, ULONG flags)
{
    if (!buf) return INVALID_POINTER;
    if (flags) return INVALID_FLAG;
    if (!bound || node < BIOMETRIC || node > USB_DEVICE) return NO_DEVNODE;
    ULONG n = (ULONG)strlen(ids[node]);
    for (ULONG i = 0; i <= n && i < cap; i++) buf[i] = (unsigned char)ids[node][i];
    return cap <= n ? BUFFER_SMALL : OK;
}
WINAPI(CM_Get_Device_IDW)
