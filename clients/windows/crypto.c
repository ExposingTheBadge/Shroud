/*
 * GHOSTLINK Windows Crypto — FIPS 140-2 via CNG
 */
#include "client.h"

static BCRYPT_ALG_HANDLE hAesGcm = NULL;
static BCRYPT_ALG_HANDLE hSha256 = NULL;

BOOL crypto_init(void) {
    SECURITY_STATUS s;
    s = BCryptOpenAlgorithmProvider(&hAesGcm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;
    BCryptSetProperty(hAesGcm, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    s = BCryptOpenAlgorithmProvider(&hSha256, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    return BCRYPT_SUCCESS(s);
}

void crypto_random_bytes(BYTE *buf, DWORD len) {
    BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

/* ── ECDH P-384 Key Generation ────────────────────────────────────── */
KeyPair crypto_generate_keypair(void) {
    KeyPair kp = {0};
    SECURITY_STATUS s;
    NCRYPT_PROV_HANDLE hProv = NULL;

    s = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(s)) return kp;

    /* Create a temporary P-384 ECDH key */
    s = NCryptCreatePersistedKey(hProv, &kp.handle, NCRYPT_ECDH_P384_ALGORITHM, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(s)) {
        NCryptFreeObject(hProv);
        return kp;
    }

    /* Finalize (generate) the key */
    s = NCryptFinalizeKey(kp.handle, 0);
    if (!BCRYPT_SUCCESS(s)) {
        NCryptDeleteKey(kp.handle, 0);
        NCryptFreeObject(hProv);
        kp.handle = NULL;
        return kp;
    }

    /* Export public key */
    kp.pub.len = PUBLIC_KEY_MAX;
    s = NCryptExportKey(kp.handle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL,
                        kp.pub.data, PUBLIC_KEY_MAX, &kp.pub.len, 0);

    NCryptFreeObject(hProv);
    return kp;
}

void crypto_free_keypair(KeyPair *kp) {
    if (kp->handle) NCryptDeleteKey(kp->handle, 0);
    ZeroMemory(kp, sizeof(KeyPair));
}

/* ── ECDH Shared Secret → AES-256 Key via SHA-256 KDF ──────────────── */
BOOL crypto_derive_shared_secret(NCRYPT_KEY_HANDLE my_priv, PublicKey *peer_pub,
                                  BYTE shared_key[AES_KEY_LEN]) {
    NCRYPT_SECRET_HANDLE hSecret = NULL;
    BYTE rawSecret[48]; /* P-384 shared secret */
    DWORD secretLen = sizeof(rawSecret);

    /* Import peer's public key for ECDH */
    NCRYPT_KEY_HANDLE hPeerKey = NULL;
    SECURITY_STATUS s = NCryptImportKey(NULL, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL,
                          &hPeerKey, peer_pub->data, peer_pub->len, 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    /* ECDH agreement */
    s = NCryptSecretAgreement(my_priv, hPeerKey, &hSecret, 0);
    NCryptDeleteKey(hPeerKey, 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    /* Derive secret */
    s = NCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, (PUCHAR)BCRYPT_SHA256_ALGORITHM,
                        rawSecret, secretLen, &secretLen, 0);
    NCryptFreeBuffer(hSecret);

    /* Hash raw secret to get AES-256 key */
    if (!BCRYPT_SUCCESS(s)) return FALSE;
    return crypto_sha256(rawSecret, secretLen, shared_key);
}

/* ── AES-256-GCM Encrypt ──────────────────────────────────────────── */
BOOL crypto_aes_gcm_encrypt(const BYTE key[AES_KEY_LEN], const BYTE *plain,
                              DWORD plain_len, BYTE *nonce, BYTE *cipher, BYTE *tag) {
    BCRYPT_KEY_HANDLE hKey = NULL;
    SECURITY_STATUS s;

    crypto_random_bytes(nonce, AES_GCM_IV_LEN);

    /* Build key blob: BCRYPT_KEY_DATA_BLOB_HEADER + key bytes */
    BYTE keyImport[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_LEN];
    BCRYPT_KEY_DATA_BLOB_HEADER *hdr = (BCRYPT_KEY_DATA_BLOB_HEADER*)keyImport;
    hdr->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    hdr->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    hdr->cbKeyData = AES_KEY_LEN;
    memcpy(keyImport + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key, AES_KEY_LEN);

    s = BCryptImportKey(hAesGcm, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0,
                        keyImport, sizeof(keyImport), 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = AES_GCM_IV_LEN;
    authInfo.pbTag = tag;
    authInfo.cbTag = AES_GCM_TAG_LEN;

    DWORD resultLen = 0;
    s = BCryptEncrypt(hKey, (PUCHAR)plain, plain_len, &authInfo, NULL, 0,
                      cipher, plain_len, &resultLen, 0);
    BCryptDestroyKey(hKey);
    return BCRYPT_SUCCESS(s);
}

/* ── AES-256-GCM Decrypt ──────────────────────────────────────────── */
BOOL crypto_aes_gcm_decrypt(const BYTE key[AES_KEY_LEN], const BYTE *nonce,
                              const BYTE *cipher, DWORD cipher_len,
                              const BYTE *tag, BYTE *plain) {
    BCRYPT_KEY_HANDLE hKey = NULL;
    SECURITY_STATUS s;

    BYTE keyImport[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_LEN];
    BCRYPT_KEY_DATA_BLOB_HEADER *hdr = (BCRYPT_KEY_DATA_BLOB_HEADER*)keyImport;
    hdr->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    hdr->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    hdr->cbKeyData = AES_KEY_LEN;
    memcpy(keyImport + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key, AES_KEY_LEN);

    s = BCryptImportKey(hAesGcm, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0,
                        keyImport, sizeof(keyImport), 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = AES_GCM_IV_LEN;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = AES_GCM_TAG_LEN;

    DWORD resultLen = 0;
    s = BCryptDecrypt(hKey, (PUCHAR)cipher, cipher_len, &authInfo, NULL, 0,
                      plain, cipher_len, &resultLen, 0);
    BCryptDestroyKey(hKey);
    return BCRYPT_SUCCESS(s);
}

/* ── SHA-256 ──────────────────────────────────────────────────────── */
BOOL crypto_sha256(const BYTE *data, DWORD len, BYTE hash[SHA256_LEN]) {
    BCRYPT_HASH_HANDLE hHash = NULL;
    SECURITY_STATUS s;
    s = BCryptCreateHash(hSha256, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;
    BCryptHashData(hHash, (PUCHAR)data, len, 0);
    BCryptFinishHash(hHash, hash, SHA256_LEN, 0);
    BCryptDestroyHash(hHash);
    return TRUE;
}

/* ── Hex ──────────────────────────────────────────────────────────── */
char* crypto_hex_encode(const BYTE *data, DWORD len) {
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;
    for (DWORD i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", data[i]);
    hex[len * 2] = 0;
    return hex;
}

BOOL crypto_hex_decode(const char *hex, BYTE *data, DWORD *len) {
    DWORD hl = (DWORD)strlen(hex);
    if (hl % 2) return FALSE;
    *len = hl / 2;
    for (DWORD i = 0; i < *len; i++)
        sscanf(hex + i * 2, "%2hhx", &data[i]);
    return TRUE;
}

/* ── File Encryption / Decryption ──────────────────────────────────── */
BOOL crypto_encrypt_file_data(const BYTE *key, const BYTE *input, DWORD input_len,
                               BYTE **output, DWORD *output_len) {
    /* Format: [nonce:12][ciphertext][tag:16] — nonce prepended to output */
    BYTE nonce[12], tag[16];
    crypto_random_bytes(nonce, 12);

    /* Ciphertext is same length as plaintext */
    BYTE *ct = malloc(input_len);
    if (!ct) return FALSE;

    if (!crypto_aes_gcm_encrypt(key, input, input_len, nonce, ct, tag)) {
        free(ct); return FALSE;
    }

    *output_len = 12 + input_len + 16;
    *output = malloc(*output_len);
    if (!*output) { free(ct); return FALSE; }

    memcpy(*output, nonce, 12);
    memcpy(*output + 12, ct, input_len);
    memcpy(*output + 12 + input_len, tag, 16);

    free(ct);
    return TRUE;
}

BOOL crypto_decrypt_file_data(const BYTE *key, const BYTE *input, DWORD input_len,
                               BYTE **output, DWORD *output_len) {
    /* Input format: [nonce:12][ciphertext][tag:16] */
    if (input_len < 28) return FALSE;  /* 12 nonce + 16 tag minimum */

    BYTE nonce[12];
    memcpy(nonce, input, 12);

    DWORD ct_len = input_len - 12 - 16;
    *output_len = ct_len;
    *output = malloc(ct_len);
    if (!*output) return FALSE;

    return crypto_aes_gcm_decrypt(key, nonce, input + 12, ct_len, input + 12 + ct_len, *output);
}
