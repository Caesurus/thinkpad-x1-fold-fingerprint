#include "fold_store.h"
#include "../vendor-protection/protection.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

/* One host handles pairing updates to this private directory at a time. */
bool fold_store_open(struct fold_store *s, int directory, const unsigned char serial[6])
{
    struct stat st;
    static const unsigned char empty_serial[6], erased_serial[6] = {255,255,255,255,255,255};
    if (!s) return false;
    *s = (struct fold_store){.directory = -1, .lock = -1};
    if (!serial || !memcmp(serial, empty_serial, 6) || !memcmp(serial, erased_serial, 6) ||
        fstat(directory, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) return false;
    s->directory = fcntl(directory, F_DUPFD_CLOEXEC, 3);
    if (s->directory == -1) return false;
    s->lock = openat(s->directory, ".lock", O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0600);
    if (s->lock < 0 || fstat(s->lock, &st) || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || st.st_uid != geteuid() || (st.st_mode & 0777) != 0600 ||
        flock(s->lock, LOCK_EX|LOCK_NB)) {
        fold_store_close(s);
        return false;
    }
    memcpy(s->serial, serial, 6);
    return true;
}

void fold_store_close(struct fold_store *s)
{
    if (s->lock >= 0) close(s->lock);
    if (s->directory >= 0) close(s->directory);
    *s = (struct fold_store){.directory = -1, .lock = -1};
}

static bool record_name(const struct fold_store *s, enum fold_store_scope scope, const char *value,
                        char name[65], char purpose[96])
{
    unsigned char material[6 + 1 + 256], digest[32];
    if (!value || s->lock < 0) return false;
    size_t n = strnlen(value, 256);
    if (!n || n == 256) return false;
    size_t prefix = sizeof s->serial;
    memcpy(material, s->serial, prefix);
    /* A zero byte is outside the old registry value alphabet. Existing
       user records retain their file names and authenticated purposes. */
    if (scope == FOLD_DEVICE_PROPERTY) material[prefix++] = 0;
    else if (scope != FOLD_USER_PAIRING) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = value[i];
        if (c < 32 || c > 126) return false;
        material[prefix + i] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
    }
    if (EVP_Digest(material, prefix + n, digest, NULL, EVP_sha256(), NULL) != 1) return false;
    for (unsigned i = 0; i < sizeof digest; ++i) snprintf(name + 2*i, 3, "%02x", digest[i]);
    snprintf(purpose, 96, "x1fold/registry/pairing/%s", name);
    return true;
}

static bool transfer_all(int fd, unsigned char *buf, size_t len, bool writing)
{
    while (len) {
        ssize_t n = writing ? write(fd, buf, len) : read(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

bool fold_store_write(struct fold_store *s, const char *value, const void *data, size_t size)
{
    return fold_store_write_at(s, FOLD_USER_PAIRING, value, data, size);
}

bool fold_store_write_at(struct fold_store *s, enum fold_store_scope scope, const char *value,
                         const void *data, size_t size)
{
    char name[65], purpose[96], temp[40];
    unsigned long long nonce;
    unsigned char *sealed = NULL;
    size_t sealed_size = 0;
    if (!record_name(s, scope, value, name, purpose) || (!data && size) ||
        getrandom(&nonce, sizeof nonce, 0) != sizeof nonce ||
        fold_protection_seal_record(purpose, data, size, &sealed, &sealed_size)) return false;
    snprintf(temp, sizeof temp, ".new-%016llx", nonce);
    int fd = openat(s->directory, temp, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0600);
    bool ok = false;
    if (fd >= 0) {
        ok = transfer_all(fd, sealed, sealed_size, true) && fsync(fd) == 0;
        if (close(fd)) ok = false;
        if (ok) ok = renameat(s->directory, temp, s->directory, name) == 0;
        if (ok) ok = fsync(s->directory) == 0;
        else unlinkat(s->directory, temp, 0);
    }
    fold_protection_free(sealed, sealed_size);
    return ok;
}

enum fold_read fold_store_read(struct fold_store *s, const char *value, unsigned char **data, size_t *size)
{
    return fold_store_read_at(s, FOLD_USER_PAIRING, value, data, size);
}

enum fold_read fold_store_read_at(struct fold_store *s, enum fold_store_scope scope, const char *value,
                                  unsigned char **data, size_t *size)
{
    char name[65], purpose[96];
    struct stat st;
    if (!data || !size) return FOLD_READ_ERROR;
    *data = NULL;
    *size = 0;
    if (!record_name(s, scope, value, name, purpose)) return FOLD_READ_ERROR;
    int fd = openat(s->directory, name, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? FOLD_READ_MISSING : FOLD_READ_ERROR;
    bool ok = false;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
        st.st_uid == geteuid() && (st.st_mode & 0777) == 0600 &&
        st.st_size > 0 && st.st_size <= (1 << 20) + 4096) {
        unsigned char *sealed = malloc(st.st_size);
        if (sealed) {
            ok = transfer_all(fd, sealed, st.st_size, false) &&
                 fold_protection_unseal_record(purpose, sealed, st.st_size, data, size) == 0;
            free(sealed);
        }
    }
    close(fd);
    return ok ? FOLD_READ_OK : FOLD_READ_ERROR;
}
