/*
 * GHOSTLINK Windows Crypto — FIPS 140-2 via CNG
 */
#include "client.h"
#include "ratchet.h"

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

/* ── ECDH P-384 Key Generation ──────────────────────────────────────
 * Tries to generate inside the TPM via the Microsoft Platform Crypto
 * Provider so the private scalar never leaves silicon. If the TPM isn't
 * present or refuses the algorithm we fall back to the software provider.
 *
 * crypto_keypair_origin() reports which one we ended up using so the UI
 * can display TPM-backed vs software-backed status. */
static int g_last_kp_origin = 0;  /* 0 = software, 1 = TPM */

int crypto_keypair_origin(void) { return g_last_kp_origin; }

KeyPair crypto_generate_keypair(void) {
    KeyPair kp = {0};
    SECURITY_STATUS s;
    NCRYPT_PROV_HANDLE hProv = NULL;

    /* 1. Try TPM-backed Platform Crypto Provider. */
    s = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (BCRYPT_SUCCESS(s)) {
        s = NCryptCreatePersistedKey(hProv, &kp.handle, NCRYPT_ECDH_P384_ALGORITHM, NULL, 0, 0);
        if (BCRYPT_SUCCESS(s)) {
            /* Ask the TPM to mark the key non-exportable. */
            DWORD nonExport = NCRYPT_ALLOW_DECRYPT_FLAG;
            NCryptSetProperty(kp.handle, NCRYPT_EXPORT_POLICY_PROPERTY,
                              (PUCHAR)&nonExport, sizeof(nonExport), 0);
            s = NCryptFinalizeKey(kp.handle, 0);
            if (BCRYPT_SUCCESS(s)) {
                kp.pub.len = PUBLIC_KEY_MAX;
                if (BCRYPT_SUCCESS(NCryptExportKey(kp.handle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL,
                                                   kp.pub.data, PUBLIC_KEY_MAX, &kp.pub.len, 0))) {
                    NCryptFreeObject(hProv);
                    g_last_kp_origin = 1;
                    return kp;
                }
            }
            NCryptDeleteKey(kp.handle, 0);
            kp.handle = NULL;
        }
        NCryptFreeObject(hProv);
        hProv = NULL;
    }

    /* 2. Software fallback — Microsoft Software Key Storage Provider. */
    s = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(s)) return kp;
    s = NCryptCreatePersistedKey(hProv, &kp.handle, NCRYPT_ECDH_P384_ALGORITHM, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(s)) { NCryptFreeObject(hProv); return kp; }
    s = NCryptFinalizeKey(kp.handle, 0);
    if (!BCRYPT_SUCCESS(s)) {
        NCryptDeleteKey(kp.handle, 0); NCryptFreeObject(hProv);
        kp.handle = NULL; return kp;
    }
    kp.pub.len = PUBLIC_KEY_MAX;
    NCryptExportKey(kp.handle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL,
                    kp.pub.data, PUBLIC_KEY_MAX, &kp.pub.len, 0);
    NCryptFreeObject(hProv);
    g_last_kp_origin = 0;
    return kp;
}

void crypto_free_keypair(KeyPair *kp) {
    if (kp->handle) NCryptDeleteKey(kp->handle, 0);
    ZeroMemory(kp, sizeof(KeyPair));
}

/* ── ECDH Shared Secret → AES-256 Key via SHA-256 KDF ──────────────── */
BOOL crypto_derive_shared_secret(NCRYPT_KEY_HANDLE my_priv, PublicKey *peer_pub,
                                  BYTE shared_key[AES_KEY_LEN]) {
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hPeerKey = NULL;
    NCRYPT_SECRET_HANDLE hSecret = NULL;
    BYTE derived[64];
    DWORD derivedLen = sizeof(derived);

    SECURITY_STATUS s = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    s = NCryptImportKey(hProv, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL,
                        &hPeerKey, peer_pub->data, peer_pub->len, 0);
    NCryptFreeObject(hProv);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    s = NCryptSecretAgreement(my_priv, hPeerKey, &hSecret, 0);
    NCryptDeleteKey(hPeerKey, 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    /* SHA-256 KDF over raw ECDH secret. pParameterList must be a real
       BCryptBufferDesc — passing the algorithm string directly is what
       caused NTE_INVALID_PARAMETER. */
    BCryptBuffer kdfBuf;
    kdfBuf.cbBuffer = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
    kdfBuf.BufferType = KDF_HASH_ALGORITHM;
    kdfBuf.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;

    BCryptBufferDesc kdfDesc;
    kdfDesc.ulVersion = BCRYPTBUFFER_VERSION;
    kdfDesc.cBuffers = 1;
    kdfDesc.pBuffers = &kdfBuf;

    s = NCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &kdfDesc,
                        derived, derivedLen, &derivedLen, 0);
    NCryptFreeObject(hSecret);
    if (!BCRYPT_SUCCESS(s) || derivedLen < AES_KEY_LEN) return FALSE;

    /* derived now holds SHA-256(raw_ECDH) — matches server's first hash step. */
    memcpy(shared_key, derived, AES_KEY_LEN);
    return TRUE;
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

/* ── Auth Key Derivation ──────────────────────────────────────────── */
BOOL crypto_auth_derive_key(NCRYPT_KEY_HANDLE my_priv, const BYTE *peer_blob, DWORD blob_len, BYTE key_out[32]) {
    if (blob_len == 0 || blob_len > PUBLIC_KEY_MAX) return FALSE;
    PublicKey pk;
    memcpy(pk.data, peer_blob, blob_len);
    pk.len = blob_len;
    BYTE shared[AES_KEY_LEN];
    if (!crypto_derive_shared_secret(my_priv, &pk, shared)) return FALSE;
    BYTE buf[AES_KEY_LEN + 17];
    memcpy(buf, shared, AES_KEY_LEN);
    memcpy(buf + AES_KEY_LEN, "GHOSTLINK-AUTH-v1", 17);
    return crypto_sha256(buf, sizeof(buf), key_out);
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

/* ── Safety number (per-contact pair fingerprint) ──────────────────
 * Same wire formula as Signal-style numeric fingerprints:
 *   1. Sort the two 32-byte pubkeys lexicographically.
 *   2. Prepend a 1-byte protocol-version tag (= 1).
 *   3. SHA-512 the result, take the first 30 bytes.
 *   4. Emit 6 groups of 5 decimal digits, each from a 5-byte big-endian
 *      slice mod 100000.
 */
char* safety_number_compute(const BYTE my_pub[32], const BYTE their_pub[32]) {
    /* Sort */
    const BYTE *a = my_pub;
    const BYTE *b = their_pub;
    if (memcmp(my_pub, their_pub, 32) > 0) { a = their_pub; b = my_pub; }

    /* SHA-512 with version tag */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, NULL, 0)))
        return NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &h, NULL, 0, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return NULL;
    }
    BYTE ver = 1;
    BCryptHashData(h, &ver, 1, 0);
    BCryptHashData(h, (PUCHAR)a, 32, 0);
    BCryptHashData(h, (PUCHAR)b, 32, 0);
    BYTE digest[64];
    BOOL ok = BCRYPT_SUCCESS(BCryptFinishHash(h, digest, 64, 0));
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!ok) return NULL;

    /* 6 groups of 5 digits = 35 chars (5 digits + 5 spaces + NUL) */
    char *out = (char*)malloc(35);
    if (!out) return NULL;
    char *p = out;
    for (int g = 0; g < 6; g++) {
        unsigned long long v = 0;
        for (int i = 0; i < 5; i++) v = (v << 8) | digest[g * 5 + i];
        unsigned int n = (unsigned int)(v % 100000ULL);
        if (g > 0) *p++ = ' ';
        sprintf(p, "%05u", n);
        p += 5;
    }
    *p = 0;
    return out;
}


/* ── PQ Hybrid Client KEX (ECDH-P384 + ML-KEM-1024) ──────────────────
 * Mirrors crypto/pq_hybrid.py:client_encapsulate. Server blob layout:
 *   4B 'PKG2' | 4B ec_len(96) | 96B ec_xy | 4B kem_len(1568) | 1568B kem_pk
 * Client blob layout:
 *   4B 'PKC2' | 96B ec_xy | 1568B kem_ct  (1668 total)
 */
#define MAGIC_SERVER_PUB 0x32474B50UL  /* 'PKG2' LE */
#define MAGIC_CLIENT_PUB 0x32434B50UL  /* 'PKC2' LE */
#define PQ_EC_LEN        96
#define PQ_KEM_PK_LEN    1568
#define PQ_KEM_CT_LEN    1568
#define PQ_CLIENT_BLOB   (4 + PQ_EC_LEN + PQ_KEM_CT_LEN)

BOOL crypto_pq_hybrid_client(const BYTE *server_blob, DWORD server_blob_len,
                             BYTE *client_blob_out, DWORD *client_blob_len_io,
                             BYTE session_key_out[32]) {
    if (server_blob_len < 4 + 4 + PQ_EC_LEN + 4 + PQ_KEM_PK_LEN) return FALSE;
    if (!kyber_available()) return FALSE;
    if (*client_blob_len_io < PQ_CLIENT_BLOB) { *client_blob_len_io = PQ_CLIENT_BLOB; return FALSE; }

    DWORD magic = *(const DWORD*)server_blob;
    if (magic != MAGIC_SERVER_PUB) return FALSE;
    DWORD ec_len = *(const DWORD*)(server_blob + 4);
    if (ec_len != PQ_EC_LEN) return FALSE;
    const BYTE *server_ec_xy = server_blob + 8;
    DWORD kem_len = *(const DWORD*)(server_blob + 8 + PQ_EC_LEN);
    if (kem_len != PQ_KEM_PK_LEN) return FALSE;
    const BYTE *server_kem_pk = server_blob + 8 + PQ_EC_LEN + 4;

    /* 1. Generate our ECDH P-384 ephemeral and export uncompressed X||Y. */
    KeyPair kp = crypto_generate_keypair();
    if (!kp.handle) return FALSE;
    /* kp.pub.data = BCRYPT_ECCKEY_BLOB (8B) + X (48) + Y (48) */
    if (kp.pub.len < 8 + PQ_EC_LEN) { crypto_free_keypair(&kp); return FALSE; }
    BYTE client_ec_xy[PQ_EC_LEN];
    memcpy(client_ec_xy, kp.pub.data + 8, PQ_EC_LEN);

    /* 2. Build server's ECC public-key blob and import. */
    BYTE peer_blob[8 + PQ_EC_LEN];
    BCRYPT_ECCKEY_BLOB *ph = (BCRYPT_ECCKEY_BLOB*)peer_blob;
    ph->dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    ph->cbKey = 48;
    memcpy(peer_blob + 8, server_ec_xy, PQ_EC_LEN);

    NCRYPT_PROV_HANDLE prov = NULL;
    if (!BCRYPT_SUCCESS(NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0))) {
        crypto_free_keypair(&kp); return FALSE;
    }
    NCRYPT_KEY_HANDLE peer_key = 0;
    SECURITY_STATUS s = NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &peer_key,
                                        peer_blob, sizeof(peer_blob), 0);
    NCryptFreeObject(prov);
    if (!BCRYPT_SUCCESS(s)) { crypto_free_keypair(&kp); return FALSE; }

    /* 3. Compute raw ECDH shared (48 bytes). */
    NCRYPT_SECRET_HANDLE secret = 0;
    s = NCryptSecretAgreement(kp.handle, peer_key, &secret, 0);
    NCryptDeleteKey(peer_key, 0);
    if (!BCRYPT_SUCCESS(s)) { crypto_free_keypair(&kp); return FALSE; }
    BYTE ec_shared[PQ_EC_LEN] = {0};
    DWORD ec_shared_len = 0;
    s = NCryptDeriveKey(secret, L"TRUNCATE", NULL, ec_shared, sizeof(ec_shared), &ec_shared_len, 0);
    NCryptFreeObject(secret);
    crypto_free_keypair(&kp);
    if (!BCRYPT_SUCCESS(s) || ec_shared_len < 48) return FALSE;

    /* 4. Kyber encapsulate against server's KEM pubkey. */
    BYTE kem_ct[PQ_KEM_CT_LEN]; BYTE kem_shared[32];
    if (!kyber_encaps(kem_ct, kem_shared, server_kem_pk)) return FALSE;

    /* 5. HKDF-SHA512 over (ec_shared || kem_shared) with 64 zero-byte salt
          and info = "GHOSTLINK-PQ-HYBRID-v1". 32-byte output. */
    BYTE ikm[48 + 32];
    memcpy(ikm, ec_shared, 48);
    memcpy(ikm + 48, kem_shared, 32);
    BYTE salt[64] = {0};
    const BYTE info[] = "GHOSTLINK-PQ-HYBRID-v1";
    if (!ratchet_hkdf_sha512(salt, 64, ikm, sizeof(ikm), info, sizeof(info) - 1,
                             session_key_out, 32))
        return FALSE;

    /* 6. Pack client blob. */
    BYTE *p = client_blob_out;
    *(DWORD*)p = MAGIC_CLIENT_PUB; p += 4;
    memcpy(p, client_ec_xy, PQ_EC_LEN); p += PQ_EC_LEN;
    memcpy(p, kem_ct, PQ_KEM_CT_LEN);
    *client_blob_len_io = PQ_CLIENT_BLOB;
    return TRUE;
}
