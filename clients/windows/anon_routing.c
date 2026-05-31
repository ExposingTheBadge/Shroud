/*
 * SHROUD anonymous routing — Windows client implementation.
 *
 * See anon_routing.h for the API. The wire format matches
 * crypto/anon_routing.py exactly so this client and the Python
 * server-side reference impl interoperate byte-for-byte.
 *
 * Crypto comes from the existing client primitives:
 *   - X25519 keygen + DH: ratchet_x25519_keygen / ratchet_x25519_dh (ratchet.c)
 *   - AES-256-GCM: crypto_aes_gcm_encrypt / crypto_aes_gcm_decrypt (crypto.c)
 *   - SHA-256 + HMAC-SHA256: BCrypt
 *   - RNG: crypto_random_bytes (crypto.c)
 *
 * HKDF-SHA256 is implemented locally (RFC 5869) because the project's
 * existing HKDF helper uses SHA-512 and the Python ref uses SHA-256.
 */
#include "anon_routing.h"

#include <bcrypt.h>
#include <ntstatus.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

/* ── Local HMAC-SHA256 + HKDF (RFC 5869) ─────────────────────────── */

#define SHA256_DIGEST_LEN 32

static BOOL hmac_sha256(const BYTE *key, DWORD key_len,
                        const BYTE *data, DWORD data_len,
                        BYTE out[SHA256_DIGEST_LEN]) {
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st;
    BOOL ok = FALSE;

    st = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM,
                                     NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) return FALSE;
    st = BCryptCreateHash(h_alg, &h, NULL, 0, (PUCHAR)key, key_len, 0);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;
    st = BCryptHashData(h, (PUCHAR)data, data_len, 0);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;
    st = BCryptFinishHash(h, out, SHA256_DIGEST_LEN, 0);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;
    ok = TRUE;
cleanup:
    if (h)     BCryptDestroyHash(h);
    if (h_alg) BCryptCloseAlgorithmProvider(h_alg, 0);
    return ok;
}

static BOOL hkdf_extract(const BYTE *salt, DWORD salt_len,
                         const BYTE *ikm, DWORD ikm_len,
                         BYTE prk_out[SHA256_DIGEST_LEN]) {
    BYTE zeros[SHA256_DIGEST_LEN] = {0};
    if (salt_len == 0) {
        salt = zeros;
        salt_len = SHA256_DIGEST_LEN;
    }
    return hmac_sha256(salt, salt_len, ikm, ikm_len, prk_out);
}

static BOOL hkdf_expand(const BYTE prk[SHA256_DIGEST_LEN],
                        const BYTE *info, DWORD info_len,
                        BYTE *okm_out, DWORD okm_len) {
    BYTE t[SHA256_DIGEST_LEN];
    DWORD t_len = 0;
    DWORD written = 0;
    BYTE counter = 1;
    BYTE buf[SHA256_DIGEST_LEN + 256 + 1]; /* T(n-1) || info || counter */

    if (okm_len > 255 * SHA256_DIGEST_LEN) return FALSE;

    while (written < okm_len) {
        DWORD in_len = 0;
        if (t_len) {
            memcpy(buf, t, SHA256_DIGEST_LEN);
            in_len = SHA256_DIGEST_LEN;
        }
        if (info_len) {
            memcpy(buf + in_len, info, info_len);
            in_len += info_len;
        }
        buf[in_len++] = counter++;
        if (!hmac_sha256(prk, SHA256_DIGEST_LEN, buf, in_len, t)) return FALSE;
        t_len = SHA256_DIGEST_LEN;
        DWORD copy = (okm_len - written < SHA256_DIGEST_LEN)
                     ? (okm_len - written) : SHA256_DIGEST_LEN;
        memcpy(okm_out + written, t, copy);
        written += copy;
    }
    return TRUE;
}

/* ── Routing tag (Rule 2) ────────────────────────────────────────── */

static void be_u64(uint64_t v, BYTE out[8]) {
    out[0] = (BYTE)(v >> 56);
    out[1] = (BYTE)(v >> 48);
    out[2] = (BYTE)(v >> 40);
    out[3] = (BYTE)(v >> 32);
    out[4] = (BYTE)(v >> 24);
    out[5] = (BYTE)(v >> 16);
    out[6] = (BYTE)(v >> 8);
    out[7] = (BYTE)v;
}

static int memcmp_const(const BYTE *a, const BYTE *b, DWORD n) {
    DWORD i;
    for (i = 0; i < n; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

uint64_t anon_pair_id(const BYTE my_id[32], const BYTE their_id[32]) {
    const BYTE *lo;
    const BYTE *hi;
    BYTE in[32 + 2 + 32]; /* lo || "||" || hi */
    BYTE digest[SHA256_DIGEST_LEN];

    if (memcmp_const(my_id, their_id, 32) <= 0) {
        lo = my_id; hi = their_id;
    } else {
        lo = their_id; hi = my_id;
    }
    memcpy(in, lo, 32);
    in[32] = '|'; in[33] = '|';
    memcpy(in + 34, hi, 32);

    /* SHA-256 via BCrypt (one-shot). */
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st;
    BOOL ok = FALSE;
    st = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (BCRYPT_SUCCESS(st)) {
        st = BCryptCreateHash(h_alg, &h, NULL, 0, NULL, 0, 0);
        if (BCRYPT_SUCCESS(st)) {
            st = BCryptHashData(h, in, sizeof(in), 0);
            if (BCRYPT_SUCCESS(st)) {
                st = BCryptFinishHash(h, digest, sizeof(digest), 0);
                if (BCRYPT_SUCCESS(st)) ok = TRUE;
            }
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(h_alg, 0);
    }
    if (!ok) return 0;

    /* First 8 bytes, big-endian -> uint64_t */
    uint64_t pid = 0;
    int i;
    for (i = 0; i < 8; i++) pid = (pid << 8) | digest[i];
    return pid;
}

uint64_t anon_epoch_for(uint64_t unix_ts) {
    return unix_ts / SHROUD_EPOCH_SECONDS;
}

BOOL anon_routing_tag(const BYTE shared_root[32],
                      uint64_t pair,
                      uint64_t epoch,
                      BYTE tag_out[SHROUD_ROUTING_TAG_LEN]) {
    static const BYTE SALT[] = "shroud-tag-v1";
    BYTE prk[SHA256_DIGEST_LEN];
    BYTE info[16];

    if (!hkdf_extract(SALT, sizeof(SALT) - 1, shared_root, 32, prk)) return FALSE;
    be_u64(pair, info);
    be_u64(epoch, info + 8);
    return hkdf_expand(prk, info, sizeof(info), tag_out, SHROUD_ROUTING_TAG_LEN);
}

DWORD anon_routing_tags_window(const BYTE shared_root[32],
                               uint64_t pair,
                               uint64_t anchor_epoch,
                               DWORD window,
                               BYTE tags_out[][SHROUD_ROUTING_TAG_LEN],
                               DWORD tags_cap) {
    DWORD written = 0;
    int64_t lo = (int64_t)anchor_epoch - (int64_t)window;
    int64_t hi = (int64_t)anchor_epoch + (int64_t)window;
    int64_t e;
    for (e = lo; e <= hi && written < tags_cap; e++) {
        if (!anon_routing_tag(shared_root, pair, (uint64_t)e, tags_out[written])) break;
        written++;
    }
    return written;
}

/* ── Sealed envelope (Rule 1) ────────────────────────────────────── */

/* PRK := HKDF-Extract("shroud-seal-v1", ecdh_shared || eph_pub || recipient_pub)
 * KEY := HKDF-Expand(PRK, "key", 32)
 * AES-256-GCM AAD := eph_pub || recipient_pub
 */
static BOOL derive_seal_key(const BYTE ecdh_shared[32],
                            const BYTE eph_pub[32],
                            const BYTE recipient_pub[32],
                            BYTE key_out[32]) {
    static const BYTE SALT[] = "shroud-seal-v1";
    BYTE ikm[32 + 32 + 32];
    BYTE prk[SHA256_DIGEST_LEN];
    memcpy(ikm,        ecdh_shared,   32);
    memcpy(ikm + 32,   eph_pub,       32);
    memcpy(ikm + 64,   recipient_pub, 32);
    if (!hkdf_extract(SALT, sizeof(SALT) - 1, ikm, sizeof(ikm), prk)) return FALSE;
    return hkdf_expand(prk, (const BYTE *)"key", 3, key_out, 32);
}

BOOL anon_seal(const BYTE *payload, DWORD payload_len,
               const BYTE recipient_pub[32],
               BYTE *sealed_out, DWORD *sealed_len_out) {
    BYTE eph_priv[32], eph_pub[32];
    BYTE shared[32];
    BYTE key[32];

    if (!ratchet_x25519_keygen(eph_priv, eph_pub)) return FALSE;
    if (!ratchet_x25519_dh(eph_priv, recipient_pub, shared)) {
        SecureZeroMemory(eph_priv, 32); return FALSE;
    }
    if (!derive_seal_key(shared, eph_pub, recipient_pub, key)) {
        SecureZeroMemory(eph_priv, 32); SecureZeroMemory(shared, 32); return FALSE;
    }
    SecureZeroMemory(eph_priv, 32);
    SecureZeroMemory(shared, 32);

    /* Lay out the wire bytes. */
    DWORD off = 0;
    sealed_out[off++] = SHROUD_SEAL_VERSION;
    memcpy(sealed_out + off, eph_pub, SHROUD_SEAL_EPHEMERAL_LEN);
    off += SHROUD_SEAL_EPHEMERAL_LEN;

    /* The existing crypto_aes_gcm_encrypt overwrites its nonce parameter
     * with a fresh random nonce. We point it directly at the wire-bytes
     * nonce slot so the bytes on the wire match the bytes used for
     * encryption. AAD is intentionally NOT used: eph_pub and
     * recipient_pub are bound into the KDF input (see derive_seal_key),
     * which provides the same tamper-detection without needing an
     * AAD-capable AES-GCM helper. The Python and Kotlin ports also
     * skip AAD for wire-format parity. */
    BYTE *nonce_out = sealed_out + off;
    off += SHROUD_SEAL_NONCE_LEN;
    BYTE *ct  = sealed_out + off;
    BYTE *tag = sealed_out + off + payload_len;
    if (!crypto_aes_gcm_encrypt(key, payload, payload_len, nonce_out, ct, tag)) {
        SecureZeroMemory(key, 32); return FALSE;
    }
    SecureZeroMemory(key, 32);

    if (sealed_len_out) {
        *sealed_len_out = SHROUD_SEAL_FIXED_OVERHEAD + payload_len;
    }
    return TRUE;
}

BOOL anon_unseal(const BYTE *sealed, DWORD sealed_len,
                 const BYTE my_priv[32], const BYTE my_pub[32],
                 BYTE *payload_out, DWORD *payload_len_out) {
    if (sealed_len < SHROUD_SEAL_FIXED_OVERHEAD) return FALSE;
    if (sealed[0] != SHROUD_SEAL_VERSION) return FALSE;

    const BYTE *eph_pub = sealed + 1;
    const BYTE *nonce   = sealed + 1 + SHROUD_SEAL_EPHEMERAL_LEN;
    DWORD ct_len = sealed_len - SHROUD_SEAL_FIXED_OVERHEAD;
    const BYTE *ct  = nonce + SHROUD_SEAL_NONCE_LEN;
    const BYTE *tag = ct + ct_len;

    BYTE shared[32];
    if (!ratchet_x25519_dh(my_priv, eph_pub, shared)) return FALSE;

    BYTE key[32];
    if (!derive_seal_key(shared, eph_pub, my_pub, key)) {
        SecureZeroMemory(shared, 32); return FALSE;
    }
    SecureZeroMemory(shared, 32);

    BOOL ok = crypto_aes_gcm_decrypt(key, nonce, ct, ct_len, tag, payload_out);
    SecureZeroMemory(key, 32);
    if (!ok) return FALSE;

    if (payload_len_out) *payload_len_out = ct_len;
    return TRUE;
}
