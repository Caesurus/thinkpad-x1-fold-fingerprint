/* The Fold adapter opens its local "SYNA" RSA_FULL container to hash with
 * CALG_SHA1. The pinned CryptoAPI host provides the actual EVP digest. */
#include "winapi/crypt/crypt.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static struct crypt_provider hash_provider;

static BOOL failure(DWORD error)
{
    winerr_set_code(error);
    return FALSE;
}

BOOL __winfnc CryptAcquireContextW(struct crypt_provider **result, const WCHAR *container,
                                   const WCHAR *provider, DWORD type, DWORD flags)
{
    enum { create_keyset = 8, delete_keyset = 16 };
    static const WCHAR name[] = u"SYNA";
    if (!result) return failure(87);
    *result = NULL;
    if (!container || provider || type != PROV_RSA_FULL) return failure(0x80090014u);
    for (size_t i = 0; i < sizeof(name)/sizeof(name[0]); i++)
        if (container[i] != name[i]) return failure(0x80090016u);
    if (flags && flags != create_keyset && flags != delete_keyset) return failure(0x80090009u);
    const char *state = secure_getenv("FOLD_PROVIDER_STATE");
    int dir = open(state ? state : "/state", O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
    struct stat st;
    if (dir < 0) return failure(5);
    if (fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 077)) {
        close(dir);
        return failure(5);
    }
    /* No RSA key material is requested by this adapter. Keep the existence
     * of its hash-only container durable across worker processes. */
    const char *marker = ".syna-hash-container";
    int options = O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    options |= flags == create_keyset ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY;
    int fd = openat(dir, marker, options, 0600);
    DWORD error = 0;
    if (fd < 0)
        error = errno == ENOENT ? 0x80090016u : errno == EEXIST ? 0x8009000fu : 5;
    else if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
             (st.st_mode & 0777) != 0600 || st.st_nlink != 1 || st.st_size)
        error = 5;
    else if (flags == delete_keyset && unlinkat(dir, marker, 0))
        error = 5;
    else if (flags && fsync(dir))
        error = 5;
    if (fd >= 0) close(fd);
    close(dir);
    if (error) return failure(error);
    if (flags != delete_keyset) *result = &hash_provider;
    return TRUE;
}
WINAPI(CryptAcquireContextW)
