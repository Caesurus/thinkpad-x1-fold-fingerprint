// SPDX-License-Identifier: LGPL-2.1-or-later
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <errno.h>
#include <fcntl.h>
#include <endian.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "winapi/api.h"
#include "winapi/crypt/wincrypt.h"
#include "protection.h"

enum { KEY = 32, NONCE = 12, TAG = 16, MAX_DATA = 1024 * 1024, MAX_ENTROPY = 65536,
       MAX_DESCR = 4096, MEMORY_SLOTS = 128 };
static const unsigned char record_header[8] = {'X','1','F','R','E','C',1,0};
static const unsigned char header[] = {'X','1','F','D','P','A',1,0};
enum { PREFIX = sizeof header + NONCE, OVERHEAD = PREFIX + TAG };

static struct secrets {
    unsigned char memory[KEY], service[KEY];
    bool has_service;
} *keys;
static pid_t owner;
static pthread_mutex_t memory_lock = PTHREAD_MUTEX_INITIALIZER;
static struct slot {
    bool used;
    size_t size;
    unsigned char hash[SHA256_DIGEST_LENGTH], nonce[NONCE], tag[TAG];
} slots[MEMORY_SLOTS];

/* On ACL-capable filesystems systemd grants a named service UID access.
 * stat() then exposes the ACL mask as group mode bits. Only accept that
 * mask if the kernel ACL grants exclusive access to root and this UID. */
static bool private_credential(int fd, const struct stat *st) {
    uid_t uid = geteuid();
    if ((st->st_uid != uid && st->st_uid != 0) || (st->st_mode & 0007)) return false;
    if (!(st->st_mode & 0070)) return true;

    struct {
        struct posix_acl_xattr_header header;
        struct posix_acl_xattr_entry entries[8];
    } acl;
    ssize_t n = fgetxattr(fd, "system.posix_acl_access", &acl, sizeof acl);
    size_t h = sizeof acl.header, e = sizeof acl.entries[0];
    if (n < (ssize_t)h || ((size_t)n-h) % e || le32toh(acl.header.a_version) != POSIX_ACL_XATTR_VERSION)
        return false;
    bool named = false;
    for (size_t i = 0; i < ((size_t)n-h)/e; i++) {
        unsigned tag = le16toh(acl.entries[i].e_tag), perm = le16toh(acl.entries[i].e_perm);
        switch (tag) {
        case ACL_USER_OBJ:
        case ACL_MASK:
            break;
        case ACL_USER:
            if (le32toh(acl.entries[i].e_id) != uid || (perm & ACL_WRITE)) return false;
            named = true;
            break;
        case ACL_GROUP_OBJ:
        case ACL_OTHER:
            if (perm) return false;
            break;
        default:
            return false;
        }
    }
    return named;
}

int fold_protection_start(int fd) {
    if (keys || fd < -1) return -1;
    struct secrets *s = mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) return -1;
    if (madvise(s, sizeof(*s), MADV_DONTDUMP) || madvise(s, sizeof(*s), MADV_WIPEONFORK) ||
        mlock(s, sizeof(*s)) || RAND_priv_bytes(s->memory, KEY) != 1)
        goto fail;
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || !private_credential(fd, &st) ||
            (st.st_mode & 0222) || (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY ||
            st.st_size != KEY || pread(fd, s->service, KEY, 0) != KEY)
            goto fail;
        s->has_service = true;
    }
    if (mprotect(s, sizeof(*s), PROT_READ)) goto fail;
    owner = getpid();
    keys = s;
    return 0;
fail:
    OPENSSL_cleanse(s, sizeof(*s));
    munmap(s, sizeof(*s));
    return -1;
}

int fold_protection_start_systemd(void) {
    const char *path = secure_getenv("CREDENTIALS_DIRECTORY");
    if (!path || path[0] != '/') return -1;
    int dir = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return -1;
    struct stat st;
    int fd = -1;
    if (!fstat(dir, &st) && private_credential(dir, &st))
        fd = openat(dir, "x1fold-dpapi", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0) return -1;
    int status = fold_protection_start(fd);
    close(fd);
    return status;
}

static bool available(void) {
    return keys && owner == getpid();
}

static BOOL failed(void) {
    winerr_set_code(13);  /* ERROR_INVALID_DATA */
    return FALSE;
}

static bool derive(const char *context, const DATA_BLOB *entropy, unsigned char key[KEY]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t len = KEY;
    unsigned char salt[SHA256_DIGEST_LENGTH];
    bool ok = ctx && EVP_PKEY_derive_init(ctx) > 0 &&
              EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, keys->service, KEY) > 0 &&
              (!entropy || (SHA256(entropy->pbData, entropy->cbData, salt) &&
                            EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof salt) > 0)) &&
              EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)context, strlen(context)) > 0 &&
              EVP_PKEY_derive(ctx, key, &len) > 0 && len == KEY;
    OPENSSL_cleanse(salt, sizeof salt);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* Decryption output is always private scratch until the tag verifies. */
static bool aead(bool encrypt, const unsigned char key[KEY], const unsigned char nonce[NONCE],
                 const unsigned char domain[8], const char *purpose, const void *in, size_t size,
                 unsigned char *out, unsigned char tag[TAG]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n, tail;
    bool ok = ctx && EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce, encrypt) == 1 &&
              EVP_CipherUpdate(ctx, NULL, &n, domain, 8) == 1 &&
              (!purpose || EVP_CipherUpdate(ctx, NULL, &n, (const unsigned char *)purpose, strlen(purpose)) == 1) &&
              EVP_CipherUpdate(ctx, out, &n, in, (int)size) == 1 && n == (int)size &&
              (encrypt || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG, tag) == 1) &&
              EVP_CipherFinal_ex(ctx, out + n, &tail) == 1 && tail == 0 &&
              (!encrypt || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG, tag) == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void fold_protection_free(void *ptr, size_t size) {
    if (ptr) {
        OPENSSL_cleanse(ptr, size);
        free(ptr);
    }
}

static int record(bool encrypt, const char *purpose, const void *input, size_t size,
                  unsigned char **out, size_t *out_size) {
    if (!out || !out_size) return -1;
    *out = NULL;
    *out_size = 0;
    if (!available() || !keys->has_service || !purpose || !*purpose ||
        strnlen(purpose, 129) > 128 || (size && !input)) return -1;
    const unsigned char *in = input;
    if (encrypt ? size > MAX_DATA : (size < OVERHEAD || size > MAX_DATA + OVERHEAD ||
                                      memcmp(in, record_header, sizeof record_header))) return -1;
    size_t len = encrypt ? size + OVERHEAD : size - OVERHEAD;
    unsigned char *result = malloc(len ? len : 1);
    unsigned char key[KEY], tag[TAG];
    bool ok = false;
    if (!result || !derive("X1Fold/registry/v1", NULL, key)) goto done;
    if (encrypt) {
        memcpy(result, record_header, sizeof record_header);
        if (RAND_bytes(result + sizeof record_header, NONCE) != 1) goto done;
        ok = aead(true, key, result + sizeof record_header, record_header, purpose,
                  in, size, result + PREFIX, result + PREFIX + size);
    } else {
        memcpy(tag, in + PREFIX + len, TAG);
        ok = aead(false, key, in + sizeof record_header, record_header, purpose,
                  in + PREFIX, len, result, tag);
    }
done:
    OPENSSL_cleanse(key, sizeof key);
    if (!ok) {
        fold_protection_free(result, len);
        return -1;
    }
    *out = result;
    *out_size = len;
    return 0;
}

int fold_protection_seal_record(const char *purpose, const void *input, size_t size,
                                unsigned char **out, size_t *out_size) {
    return record(true, purpose, input, size, out, out_size);
}

int fold_protection_unseal_record(const char *purpose, const void *input, size_t size,
                                  unsigned char **out, size_t *out_size) {
    return record(false, purpose, input, size, out, out_size);
}

static bool valid_data(const DATA_BLOB *in, const DATA_BLOB *entropy, void *reserved,
                       void *prompt, DWORD flags, size_t limit) {
    return available() && keys->has_service && in && in->cbData <= limit &&
           (!in->cbData || in->pbData) && !reserved && !prompt && !(flags & ~1u) &&
           (!entropy || (entropy->cbData <= MAX_ENTROPY && (!entropy->cbData || entropy->pbData)));
}

__winfnc BOOL CryptProtectData(DATA_BLOB *in, const char16_t *descr, DATA_BLOB *entropy,
                              void *reserved, void *prompt, DWORD flags, DATA_BLOB *out) {
    if (!out || out == in || out == entropy) return failed();
    *out = (DATA_BLOB){0};
    if (!valid_data(in, entropy, reserved, prompt, flags, MAX_DATA)) return failed();
    size_t chars = 0;
    if (descr) {
        while (chars <= MAX_DESCR && descr[chars]) chars++;
        if (chars > MAX_DESCR) return failed();
    }
    /* Four little-endian bytes for the UTF-16 code-unit count. The relink ABI is x86-64. */
    uint32_t count = (uint32_t)chars;
    size_t desc_size = chars * sizeof(*descr), len = sizeof count + desc_size + in->cbData;
    unsigned char key[KEY], *plain = malloc(len), *box = malloc(OVERHEAD + len);
    bool ok = false;
    if (!plain || !box) goto done;
    memcpy(plain, &count, sizeof count);
    if (desc_size) memcpy(plain + sizeof count, descr, desc_size);
    if (in->cbData) memcpy(plain + sizeof count + desc_size, in->pbData, in->cbData);
    memcpy(box, header, sizeof header);
    if (!derive("X1Fold/DPAPI/service/v1", entropy, key) || RAND_bytes(box + sizeof header, NONCE) != 1 ||
        !aead(true, key, box + sizeof header, header, NULL, plain, len, box + PREFIX, box + PREFIX + len))
        goto done;
    out->pbData = box;
    out->cbData = OVERHEAD + len;
    ok = true;
done:
    if (!ok) free(box);
    fold_protection_free(plain, len);
    OPENSSL_cleanse(key, sizeof key);
    return ok ? TRUE : failed();
}
WINAPI(CryptProtectData)

__winfnc BOOL CryptUnprotectData(DATA_BLOB *in, char16_t **descr, DATA_BLOB *entropy,
                                void *reserved, void *prompt, DWORD flags, DATA_BLOB *out) {
    if (!out || out == in || out == entropy) return failed();
    *out = (DATA_BLOB){0};
    if (descr) *descr = NULL;
    if (!valid_data(in, entropy, reserved, prompt, flags, MAX_DATA + OVERHEAD + 4 + MAX_DESCR * 2) ||
        in->cbData < OVERHEAD + 4 || memcmp(in->pbData, header, sizeof header))
        return failed();
    size_t len = in->cbData - OVERHEAD;
    unsigned char key[KEY], *plain = malloc(len), *data = NULL;
    char16_t *description = NULL;
    bool ok = false;
    if (!plain || !derive("X1Fold/DPAPI/service/v1", entropy, key) ||
        !aead(false, key, in->pbData + sizeof header, header, NULL, in->pbData + PREFIX, len,
              plain, in->pbData + PREFIX + len))
        goto done;
    uint32_t chars;
    memcpy(&chars, plain, sizeof chars);
    if (chars > MAX_DESCR || (size_t)chars * 2 > len - 4) goto done;
    size_t desc_size = chars * 2, data_size = len - 4 - desc_size;
    if (data_size > MAX_DATA) goto done;
    if (descr) {
        description = calloc(chars + 1, sizeof(*description));
        if (!description) goto done;
        memcpy(description, plain + 4, desc_size);
    }
    data = malloc(data_size ? data_size : 1);
    if (!data) goto done;
    memcpy(data, plain + 4 + desc_size, data_size);
    if (descr) *descr = description;
    out->pbData = data;
    out->cbData = data_size;
    ok = true;
done:
    if (!ok) free(description);
    fold_protection_free(plain, len);
    OPENSSL_cleanse(key, sizeof key);
    return ok ? TRUE : failed();
}
WINAPI(CryptUnprotectData)

static BOOL memory_block(bool encrypt, void *data, DWORD size, DWORD flags) {
    if (!available() || !data || size == 0 || size % 16 || size > MAX_DATA || flags != 0)
        return failed();
    unsigned char *scratch = malloc(size);
    if (!scratch) return failed();
    bool ok = false;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!encrypt && !SHA256(data, size, hash)) goto finish;
    pthread_mutex_lock(&memory_lock);
    for (size_t i = 0; i < MEMORY_SLOTS; i++) {
        struct slot *entry = &slots[i];
        if (encrypt) {
            if (entry->used) continue;
            if (RAND_bytes(entry->nonce, NONCE) != 1 ||
                !aead(true, keys->memory, entry->nonce, header, NULL, data, size, scratch, entry->tag) ||
                !SHA256(scratch, size, entry->hash))
                break;
            entry->size = size;
            entry->used = true;
        } else {
            if (!entry->used || entry->size != size ||
                CRYPTO_memcmp(hash, entry->hash, sizeof hash)) continue;
            if (!aead(false, keys->memory, entry->nonce, header, NULL, data, size, scratch, entry->tag)) break;
            OPENSSL_cleanse(entry, sizeof(*entry));
        }
        memcpy(data, scratch, size);
        ok = true;
        break;
    }
    pthread_mutex_unlock(&memory_lock);
finish:
    fold_protection_free(scratch, size);
    return ok ? TRUE : failed();
}

__winfnc BOOL CryptProtectMemory(void *data, DWORD size, DWORD flags) {
    return memory_block(true, data, size, flags);
}
WINAPI(CryptProtectMemory)

__winfnc BOOL CryptUnprotectMemory(void *data, DWORD size, DWORD flags) {
    return memory_block(false, data, size, flags);
}
WINAPI(CryptUnprotectMemory)
