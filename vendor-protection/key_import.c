#include "winapi/crypt/crypt.h"
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

enum {
    error_invalid_parameter = 87,
    error_no_memory = 8,
    bad_data = 0x80090005u,
    bad_version = 0x80090007u,
    bad_algorithm = 0x80090008u,
    bad_flags = 0x80090009u,
    bad_type = 0x8009000au,
    hmac_import = 0x100, /* CRYPT_IPSEC_HMAC_KEY */
};

struct aes_session {
    const EVP_CIPHER *cipher;
    BYTE material[32], iv[16], feedback[16];
    pthread_mutex_t lock;
};

static BOOL import_error(DWORD code) {
    winerr_set_code(code);
    return FALSE;
}

__winfnc BOOL CryptImportKey(struct crypt_provider *provider, const BLOBHEADER *data,
        DWORD length, struct crypt_key *wrapping_key, DWORD flags, struct crypt_key **out) {
    if (!out) return import_error(error_invalid_parameter);
    *out = NULL;
    if (!data || provider != &crypt_prov_rsa_aes || wrapping_key)
        return import_error(error_invalid_parameter);
    if (length < sizeof(BLOBHEADER)) return import_error(bad_data);
    if (data->bType != type_PLAINTEXTKEYBLOB) return import_error(bad_type);
    if (data->bVersion != 2) return import_error(bad_version);
    if (data->reserved) return import_error(bad_data);
    if (length < sizeof(PLAINTEXTKEYBLOB)) return import_error(bad_data);

    const PLAINTEXTKEYBLOB *blob = (const PLAINTEXTKEYBLOB *)data;
    size_t size = length - sizeof(*blob);
    if (!size || size > INT_MAX || blob->dwKeySize != size) return import_error(bad_data);
    const EVP_CIPHER *cipher = NULL;
    switch (data->aiKeyAlg) {
    case CALG_RC2:
        if (flags != hmac_import) return import_error(bad_flags);
        break;
    case CALG_AES_128: cipher = EVP_aes_128_cbc(); break;
    case CALG_AES_192: cipher = EVP_aes_192_cbc(); break;
    case CALG_AES_256: cipher = EVP_aes_256_cbc(); break;
    default: return import_error(bad_algorithm);
    }
    if (cipher && (flags & ~1u)) return import_error(bad_flags);
    if (cipher && size != (size_t)EVP_CIPHER_get_key_length(cipher)) return import_error(bad_data);
    struct crypt_key *key = calloc(1, sizeof(*key));
    if (!key) return import_error(error_no_memory);
    if (cipher) {
        struct aes_session *aes = calloc(1, sizeof(*aes));
        if (!aes || pthread_mutex_init(&aes->lock, NULL)) {
            free(aes);
            free(key);
            return import_error(error_no_memory);
        }
        aes->cipher = cipher;
        memcpy(aes->material, blob->rgbKeyData, size);
        key->key_data = aes;
    } else {
        key->plain_data = malloc(size);
        if (!key->plain_data) {
            free(key);
            return import_error(error_no_memory);
        }
        memcpy(key->plain_data, blob->rgbKeyData, size);
        key->plain_size = size;
    }
    key->prov = provider;
    *out = key;
    return TRUE;
}
WINAPI(CryptImportKey)

__winfnc BOOL CryptDestroyKey(struct crypt_key *key) {
    if (!key || key->prov != &crypt_prov_rsa_aes) return import_error(error_invalid_parameter);
    if (key->key_data) {
        struct aes_session *aes = key->key_data;
        pthread_mutex_destroy(&aes->lock);
        OPENSSL_cleanse(aes, sizeof(*aes));
        free(aes);
    }
    if (key->plain_data) OPENSSL_cleanse(key->plain_data, key->plain_size);
    free(key->plain_data);
    free(key);
    return TRUE;
}
WINAPI(CryptDestroyKey)

/* The Microsoft Enhanced RSA and AES provider defaults to CBC with a zero IV.
 * The Fold driver sets KP_MODE and KP_IV explicitly and supplies whole blocks. */
__winfnc BOOL CryptSetKeyParam(struct crypt_key *key, DWORD param, const BYTE *value, DWORD flags)
{
    if (!key || !key->key_data || !value) return import_error(error_invalid_parameter);
    if (flags) return import_error(bad_flags);
    struct aes_session *aes = key->key_data;
    if (param == 4) { /* KP_MODE */
        DWORD mode;
        memcpy(&mode, value, sizeof mode);
        return mode == 1 ? TRUE : import_error(bad_data);
    }
    if (param != 1) return import_error(bad_type); /* KP_IV */
    pthread_mutex_lock(&aes->lock);
    memcpy(aes->iv, value, 16);
    memcpy(aes->feedback, value, 16);
    pthread_mutex_unlock(&aes->lock);
    return TRUE;
}
WINAPI(CryptSetKeyParam)

static BOOL cipher_data(struct crypt_key *key, void *hash, BOOL final, DWORD flags,
                        BYTE *data, DWORD *len, DWORD capacity, bool encrypt)
{
    if (!key || !key->key_data || !len || hash) return import_error(error_invalid_parameter);
    if (flags) return import_error(bad_flags);
    DWORD input = *len;
    if (input > INT_MAX - 16 || ((!encrypt || !final) && input % 16) ||
        (!encrypt && (!data || (final && !input)))) return import_error(bad_data);
    DWORD needed = encrypt && final ? input + 16 - input % 16 : input;
    if (!data || capacity < needed) {
        *len = needed;
        return !data ? TRUE : import_error(234); /* ERROR_MORE_DATA */
    }
    struct aes_session *aes = key->key_data;
    BYTE *out = OPENSSL_malloc((size_t)input + 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!out || !ctx) {
        OPENSSL_free(out);
        EVP_CIPHER_CTX_free(ctx);
        return import_error(error_no_memory);
    }
    int written = 0, tail = 0;
    pthread_mutex_lock(&aes->lock);
    bool ok = EVP_CipherInit_ex(ctx, aes->cipher, NULL, aes->material, aes->feedback, encrypt) == 1 &&
              EVP_CIPHER_CTX_set_padding(ctx, !!final) == 1 &&
              EVP_CipherUpdate(ctx, out, &written, data, (int)input) == 1 &&
              EVP_CipherFinal_ex(ctx, out + written, &tail) == 1;
    if (ok) {
        if (final) memcpy(aes->feedback, aes->iv, 16);
        else if (input) memcpy(aes->feedback, (encrypt ? out : data) + input - 16, 16);
        *len = (DWORD)(written + tail);
        memcpy(data, out, *len);
    }
    pthread_mutex_unlock(&aes->lock);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_clear_free(out, (size_t)input + 16);
    return ok ? TRUE : import_error(bad_data);
}

__winfnc BOOL CryptEncrypt(struct crypt_key *key, void *hash, BOOL final, DWORD flags,
                          BYTE *data, DWORD *len, DWORD capacity)
{
    return cipher_data(key, hash, final, flags, data, len, capacity, true);
}
WINAPI(CryptEncrypt)

__winfnc BOOL CryptDecrypt(struct crypt_key *key, void *hash, BOOL final, DWORD flags,
                          BYTE *data, DWORD *len)
{
    return cipher_data(key, hash, final, flags, data, len, len ? *len : 0, false);
}
WINAPI(CryptDecrypt)
