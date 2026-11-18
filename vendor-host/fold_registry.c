#include "fold_registry.h"
#include "../vendor-protection/protection.h"
#include "tudor/internal.h"
#include <strings.h>
#include <unistd.h>

/* The host implements registry values, but has no WinBio account enumeration.
 * Report that to the driver during hardware preparation. */
static LONG __winfnc RegQueryInfoKeyW(HANDLE key, WCHAR *class_name, DWORD *class_len,
        DWORD *reserved, DWORD *subkeys, DWORD *longest_subkey, DWORD *longest_class,
        DWORD *values, DWORD *longest_value, DWORD *largest_data, DWORD *security_size,
        void *last_write)
{
    return 120; /* ERROR_CALL_NOT_IMPLEMENTED */
}
WINAPI(RegQueryInfoKeyW)

static bool registry_value(void *context, void *object, const char *key,
                           const char *value, bool write, void *buf,
                           size_t *size, enum winreg_val_type *type)
{
    if (!key || !value || !size || !type) return false;
    enum fold_store_scope scope;
    if (!strcasecmp(key, "HKEY_LOCAL_MACHINE\\Tudor\\Device") && !strcasecmp(value, "SecureInfo"))
        scope = FOLD_DEVICE_PROPERTY;
    else if (!strcasecmp(key, "HKEY_CURRENT_USER\\Software\\Synaptics\\PairingData"))
        scope = FOLD_USER_PAIRING;
    else
        return tudor_reg_handler(NULL, object, key, value, write, buf, size, type);

    struct fold_store *store = context;
    if (write)
        return *type == WINREG_BINARY && fold_store_write_at(store, scope, value, buf, *size);
    unsigned char *data = NULL;
    size_t len = 0;
    enum fold_read status = fold_store_read_at(store, scope, value, &data, &len);
    if (status == FOLD_READ_MISSING) {
        winerr_set_code(2); /* ERROR_FILE_NOT_FOUND */
        return false;
    }
    /* The guest interprets a missing value as permission to provision. Stop
       this isolated worker if an existing pairing cannot be authenticated. */
    if (status != FOLD_READ_OK) _exit(74);
    bool fits = !buf || *size >= len;
    if (buf && fits) memcpy(buf, data, len);
    *size = len;
    *type = WINREG_BINARY;
    fold_protection_free(data, len);
    if (!fits) winerr_set_code(234); /* ERROR_MORE_DATA */
    return fits;
}

bool fold_registry_install(struct fold_store *store)
{
    /* Exercise authenticated sealing and unsealing before allowing any pairing
       operation. A host started without a persistent credential fails here. */
    static const char purpose[] = "x1fold/registry/startup";
    const unsigned char check = 1;
    unsigned char *sealed = NULL, *opened = NULL;
    size_t sealed_len = 0, opened_len = 0;
    if (!store || store->lock < 0 ||
        fold_protection_seal_record(purpose, &check, 1, &sealed, &sealed_len))
        return false;
    bool ok = fold_protection_unseal_record(purpose, sealed, sealed_len, &opened, &opened_len) == 0
              && opened_len == 1 && opened[0] == check;
    fold_protection_free(sealed, sealed_len);
    fold_protection_free(opened, opened_len);
    if (ok) winreg_set_handler(registry_value, store);
    return ok;
}
