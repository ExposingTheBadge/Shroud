/*
 * SHROUD Windows Client — FIPS 140-2 Native C
 * Compile: build.bat (vcvars64 + cl /O2 /MT *.c /Fe:SHROUD.exe)
 */

#ifndef SHROUD_CLIENT_H
#define SHROUD_CLIENT_H

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NTDDI_VERSION 0x0A000000  /* Windows 10 — needed for BCRYPT_ECDH_ALGORITHM, X25519, HKDF */
#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <winhttp.h>
#include <winsock2.h>
#include <dpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "comdlg32.lib")

/* ── Configuration ────────────────────────────────────────────────── */
/*
 * Bootstrap relay endpoint. The XOR-encoded SERVER_HOST_ENC scheme that
 * lived here through v2.4.x had two bugs: the wsprintf in network_init
 * ignored the decoded value (so the binary always pointed at a stale
 * literal IP regardless of what the encode bytes said), and the encoder
 * disagreed with the decoder on key indexing (decoder read past the
 * end of "SHROUD"). Both bugs masked each other for years but broke
 * the moment the legacy hardcoded IP went away.
 *
 * Real obfuscation against strings(1) does nothing useful here — the
 * binary makes plaintext HTTPS calls to the address either way. The
 * operator-manifest endpoint published by the bootstrap relay is the
 * proper relay-discovery mechanism going forward; clients hit this
 * address only long enough to fetch + verify the signed manifest, then
 * route through whatever relay (clearnet or .onion) the manifest
 * points them at.
 */
#define SERVER_HOST       L"44.202.225.57"
#define SERVER_PORT       58443
#define SERVER_USE_TLS    1

#define AES_KEY_LEN       32
#define AES_GCM_IV_LEN    12
#define AES_GCM_TAG_LEN   16
#define SHA256_LEN        32
#define PUBLIC_KEY_MAX    512
#define DEVICE_ID_LEN     32
#define MAX_USERNAME      64
#define MAX_PASSWORD      128
#define MAX_DEVICE_NAME   64
#define MAX_MESSAGE_BODY  4096
#define MSG_CACHE_FILE    "D:\\SHROUD\\msgcache.enc"

/* ── Types ─────────────────────────────────────────────────────────── */
typedef struct {
    BYTE data[PUBLIC_KEY_MAX];
    DWORD len;
} PublicKey;

typedef struct {
    NCRYPT_KEY_HANDLE handle;
    PublicKey pub;
} KeyPair;

typedef struct {
    char id[DEVICE_ID_LEN * 2 + 1];
    char username[MAX_USERNAME + 1];
    char device_name[MAX_DEVICE_NAME + 1];
    char platform[16];
    KeyPair identity_key;
    BYTE session_key[AES_KEY_LEN];
    BOOL session_valid;
} DeviceConfig;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} HttpResponse;

/* ── Crypto API ───────────────────────────────────────────────────── */
BOOL   crypto_init(void);
KeyPair crypto_generate_keypair(void);
void   crypto_free_keypair(KeyPair *kp);
BOOL   crypto_derive_shared_secret(NCRYPT_KEY_HANDLE my_priv, PublicKey *peer_pub, BYTE shared_key[AES_KEY_LEN]);
BOOL   crypto_aes_gcm_encrypt(const BYTE key[AES_KEY_LEN], const BYTE *plain, DWORD plain_len, BYTE *nonce, BYTE *cipher, BYTE *tag);
BOOL   crypto_aes_gcm_decrypt(const BYTE key[AES_KEY_LEN], const BYTE *nonce, const BYTE *cipher, DWORD cipher_len, const BYTE *tag, BYTE *plain);
BOOL   crypto_sha256(const BYTE *data, DWORD len, BYTE hash[SHA256_LEN]);
void   crypto_random_bytes(BYTE *buf, DWORD len);
char*  crypto_hex_encode(const BYTE *data, DWORD len);
BOOL   crypto_hex_decode(const char *hex, BYTE *data, DWORD *len);
BOOL   crypto_auth_derive_key(NCRYPT_KEY_HANDLE my_priv, const BYTE *peer_blob, DWORD blob_len, BYTE key_out[32]);

/* Returns 1 if the most-recently-generated keypair lives inside the TPM,
 * 0 if software fallback. Updated by crypto_generate_keypair(). */
int    crypto_keypair_origin(void);

/* Post-quantum hybrid client KEX.
 *   server_blob:        the server_public_key_blob bytes from /api/v1/key-exchange-v2
 *                       (4B magic 'PKG2' + 4B ec_len(96) + 96B ec_xy + 4B kem_len(1568) + 1568B kem_pk)
 *   client_blob_out:    receives 4B 'PKC2' + 96B ec_xy + 1568B kem_ct = 1668 bytes
 *   client_blob_len:    in: capacity, out: written
 *   session_key_out:    32-byte HKDF-SHA512(ECDH_shared || KEM_shared, "SHROUD-PQ-HYBRID-v1") */
BOOL   crypto_pq_hybrid_client(const BYTE *server_blob, DWORD server_blob_len,
                               BYTE *client_blob_out, DWORD *client_blob_len_io,
                               BYTE session_key_out[32]);

/* ── Network API ──────────────────────────────────────────────────── */
BOOL   network_init(void);
void   network_cleanup(void);
/* Route subsequent requests through a SOCKS5 (or HTTP CONNECT) proxy.
 * Pass "socks=127.0.0.1:9050" to tunnel through a local Tor daemon, or
 * NULL/"" to disable. Returns FALSE if the session couldn't be rebuilt
 * (in which case the previous session is preserved). */
BOOL   network_set_proxy(const char *proxy);
HttpResponse* network_post(const char *path, const char *json_body);
HttpResponse* network_post_h(const char *path, const char *json_body, const char *extra_header);
HttpResponse* network_post_bytes(const char *path, const BYTE *data, DWORD data_len,
                                 const char *content_type);
HttpResponse* network_get(const char *path);
HttpResponse* network_upload_file(const char *path, const BYTE *data, DWORD data_len,
                                   const char *sender_id, const char *recipient_id,
                                   const char *metadata_json);
HttpResponse* network_download_file(const char *path, const char *device_id,
                                     BYTE **out_data, DWORD *out_len);
HttpResponse* network_delete(const char *path, const char *device_id);
void   network_free_response(HttpResponse *r);

/* File transfer helpers */
BOOL   crypto_encrypt_file_data(const BYTE *key, const BYTE *input, DWORD input_len,
                                 BYTE **output, DWORD *output_len);
BOOL   crypto_decrypt_file_data(const BYTE *key, const BYTE *input, DWORD input_len,
                                 BYTE **output, DWORD *output_len);

/* ── Storage API ──────────────────────────────────────────────────── */
BOOL   storage_save_keypair(const char *device_id, KeyPair *kp);
BOOL   storage_load_keypair(const char *device_id, KeyPair *kp);
BOOL   storage_save_config(DeviceConfig *cfg);
BOOL   storage_load_config(DeviceConfig *cfg);
BOOL   storage_exists(void);
void   storage_delete_all(void);
void   app_instance_id(char *out, int outSize);

/* Generic DPAPI-wrapped at-rest storage. The plaintext blob is encrypted
 * with the current user's master key (CryptProtectData) so a stolen disk
 * image is useless without the user's Windows credentials.
 *
 * `path` is an absolute filesystem path. `tag` is an optional descriptive
 * label baked into the DPAPI entropy. Returns TRUE on success.
 *
 * On load: caller must `free()` *plain_out. */
BOOL   storage_save_blob(const wchar_t *path, const wchar_t *tag,
                         const BYTE *plain, DWORD plain_len);
BOOL   storage_load_blob(const wchar_t *path, BYTE **plain_out, DWORD *plain_len_out);

/* ── JSON helpers ─────────────────────────────────────────────────── */
char*  json_get_string(const char *json, const char *key);

/* ── Post-Quantum Kyber-1024 API ──────────────────────────────────── */
#define KYBER_1024_PK_LEN  1568
#define KYBER_1024_SK_LEN  3168
#define KYBER_1024_CT_LEN  1568
#define KYBER_1024_SS_LEN  32

BOOL   kyber_init(void);
void   kyber_cleanup(void);
BOOL   kyber_available(void);
BOOL   kyber_keygen(BYTE *pk_out, BYTE *sk_out);
BOOL   kyber_encaps(BYTE *ct_out, BYTE *ss_out, const BYTE *pk);
BOOL   kyber_decaps(BYTE *ss_out, const BYTE *ct, const BYTE *sk);
DWORD  kyber_pk_size(void);
DWORD  kyber_sk_size(void);
DWORD  kyber_ct_size(void);
DWORD  kyber_ss_size(void);

/* ── OQS Signature Verifier (server identity attestation) ─────────── */
BOOL oqs_sig_available(void);
BOOL oqs_sig_verify(const char *algorithm,
                    const BYTE *message, DWORD message_len,
                    const BYTE *signature, DWORD signature_len,
                    const BYTE *public_key);
BOOL shroud_verify_server_sig(const BYTE *pk_blob, DWORD pk_blob_len,
                                  const BYTE *sig_blob, DWORD sig_blob_len,
                                  const BYTE *message, DWORD message_len);

/* Pure-C Ed25519 verify (no DLL dependency). 16-limb radix-2^16 field
 * arithmetic, SHA-512 from BCrypt. Self-test runs lazily on first call;
 * if it fails (which it never has on RFC 8032 vectors 1 and 2),
 * ed25519_available() returns FALSE forever and the higher-level
 * triple-hybrid checker falls back to ML-DSA + SPHINCS+ only. */
BOOL ed25519_available(void);
BOOL ed25519_verify(const BYTE *msg, DWORD msg_len,
                    const BYTE sig[64], const BYTE pub[32]);

/* Safety number: stable per-pair fingerprint of two X25519 identity
 * pubkeys. SHA-512 over sorted([a,b]); take 30 bytes, emit six
 * 5-digit groups (30 visible digits). Same string is computed on both
 * sides — users compare out-of-band to defeat MITM. Returns the
 * formatted string ("12345 67890 12345 67890 12345 67890"). Caller
 * frees the result.  Returns NULL on failure. */
char* safety_number_compute(const BYTE my_pub[32], const BYTE their_pub[32]);

/* ── TPM 2.0 API ──────────────────────────────────────────────────── */
BOOL   tpm_detect(void);
BOOL   tpm_is_available(void);
BOOL   tpm_is_20(void);
DWORD  tpm_spec_version(void);
const char* tpm_manufacturer(void);
BOOL   tpm_seal_key(const BYTE *keyData, DWORD keyLen, const char *label);
BOOL   tpm_unseal_key(BYTE **keyData, DWORD *keyLen, const char *label);
void   tpm_status_string(char *buf, int bufSize);

/* ── Security Status Display ──────────────────────────────────────── */
void   UpdateSecurityStatus(void);

#endif /* SHROUD_CLIENT_H */
