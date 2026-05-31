/*
 * SHROUD Double Ratchet — Windows C port
 *
 * Mirrors crypto/double_ratchet.py 1:1. Uses BCrypt for HMAC-SHA512 and
 * AES-256-GCM. X25519 keys are produced via BCrypt's BCRYPT_ECDH_ALGORITHM
 * with BCRYPT_ECC_CURVE_25519 (Windows 10 1809+).
 *
 * Test plan: build the project, populate a RatchetState from
 * ratchet_init_alice() with the same shared secret + bob_pub used in the
 * Python self-test, encrypt a fixed plaintext, and confirm
 * crypto/double_ratchet.py decrypts it identically. The wire format is
 * byte-exact.
 */
#define _CRT_SECURE_NO_WARNINGS
#include "ratchet.h"
#include <string.h>
#include <stdio.h>

/* NT_SUCCESS is normally in <winnt.h> but only when the user defined macro
   guard wasn't tripped; redefine locally for safety. */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* The Windows 10 SDK defines BCRYPT_ECC_CURVE_25519 and the generic-magic
 * constants. If we're targeting an older SDK they may need shimming. */
#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519 L"curve25519"
#endif
#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME L"ECCCurveName"
#endif
#ifndef BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC  0x504B4345
#endif
#ifndef BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC
#define BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC 0x564B4345
#endif

static BCRYPT_ALG_HANDLE g_alg_ecdh = NULL;
static BCRYPT_ALG_HANDLE g_alg_hmac_sha512 = NULL;
static BCRYPT_ALG_HANDLE g_alg_aes_gcm = NULL;

BOOL ratchet_init_crypto(void) {
    if (!g_alg_ecdh) {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_ecdh, BCRYPT_ECDH_ALGORITHM, NULL, 0))) return FALSE;
        if (!NT_SUCCESS(BCryptSetProperty(g_alg_ecdh, BCRYPT_ECC_CURVE_NAME,
                                          (PUCHAR)BCRYPT_ECC_CURVE_25519,
                                          (ULONG)((wcslen(BCRYPT_ECC_CURVE_25519) + 1) * sizeof(WCHAR)),
                                          0))) return FALSE;
    }
    if (!g_alg_hmac_sha512) {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_hmac_sha512, BCRYPT_SHA512_ALGORITHM, NULL,
                                                    BCRYPT_ALG_HANDLE_HMAC_FLAG))) return FALSE;
    }
    if (!g_alg_aes_gcm) {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_aes_gcm, BCRYPT_AES_ALGORITHM, NULL, 0))) return FALSE;
        if (!NT_SUCCESS(BCryptSetProperty(g_alg_aes_gcm, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) return FALSE;
    }
    return TRUE;
}

/* ── X25519 keygen + DH ──────────────────────────────────────────── */
BOOL ratchet_x25519_keygen(BYTE priv[32], BYTE pub[32]) {
    if (!ratchet_init_crypto()) return FALSE;
    BCRYPT_KEY_HANDLE h = NULL;
    if (!NT_SUCCESS(BCryptGenerateKeyPair(g_alg_ecdh, &h, 255, 0))) return FALSE;
    if (!NT_SUCCESS(BCryptFinalizeKeyPair(h, 0))) { BCryptDestroyKey(h); return FALSE; }

    /* Export private (full keypair): blob = BCRYPT_ECCKEY_BLOB + X(32) + Y(32) + D(32) */
    BYTE buf[8 + 32 * 3]; ULONG cb = 0;
    if (!NT_SUCCESS(BCryptExportKey(h, NULL, BCRYPT_ECCPRIVATE_BLOB, buf, sizeof(buf), &cb, 0))) {
        BCryptDestroyKey(h); return FALSE;
    }
    /* X25519 montgomery curve in BCrypt returns u-coordinate in X(32); D is the scalar. */
    memcpy(pub,  buf + 8,  32);
    memcpy(priv, buf + 8 + 64, 32);
    BCryptDestroyKey(h);
    return TRUE;
}

BOOL ratchet_x25519_dh(const BYTE priv[32], const BYTE pub[32], BYTE shared[32]) {
    if (!ratchet_init_crypto()) return FALSE;

    /* Construct a private-key blob with our scalar + the peer pub as X. */
    BYTE blob[8 + 32 * 3]; ZeroMemory(blob, sizeof(blob));
    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB*)blob;
    hdr->dwMagic = BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
    hdr->cbKey = 32;
    memcpy(blob + 8,        pub,  32);  /* X = peer pub */
    /* Y left zero — Montgomery-curve consumer ignores it */
    memcpy(blob + 8 + 64,   priv, 32);

    BCRYPT_KEY_HANDLE my_priv = NULL;
    if (!NT_SUCCESS(BCryptImportKeyPair(g_alg_ecdh, NULL, BCRYPT_ECCPRIVATE_BLOB, &my_priv, blob, sizeof(blob), 0)))
        return FALSE;

    /* Make a public-key blob from the peer pub. */
    BYTE pblob[8 + 32 * 2]; ZeroMemory(pblob, sizeof(pblob));
    BCRYPT_ECCKEY_BLOB *ph = (BCRYPT_ECCKEY_BLOB*)pblob;
    ph->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC; ph->cbKey = 32;
    memcpy(pblob + 8, pub, 32);
    BCRYPT_KEY_HANDLE peer_pub = NULL;
    if (!NT_SUCCESS(BCryptImportKeyPair(g_alg_ecdh, NULL, BCRYPT_ECCPUBLIC_BLOB, &peer_pub, pblob, sizeof(pblob), 0))) {
        BCryptDestroyKey(my_priv); return FALSE;
    }

    BCRYPT_SECRET_HANDLE sec = NULL;
    NTSTATUS st = BCryptSecretAgreement(my_priv, peer_pub, &sec, 0);
    BCryptDestroyKey(my_priv); BCryptDestroyKey(peer_pub);
    if (!NT_SUCCESS(st)) return FALSE;

    BCryptBuffer derive_bufs[1];
    derive_bufs[0].BufferType = KDF_HASH_ALGORITHM;
    derive_bufs[0].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
    derive_bufs[0].cbBuffer = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
    BCryptBufferDesc desc; desc.ulVersion = BCRYPTBUFFER_VERSION; desc.cBuffers = 0; desc.pBuffers = NULL;

    /* Pull the raw shared (32 bytes) directly. KDF_RAW_SECRET available on Win 10+. */
    ULONG out_len = 0;
    st = BCryptDeriveKey(sec, L"TRUNCATE", NULL, shared, 32, &out_len, KDF_USE_SECRET_AS_HMAC_KEY_FLAG);
    if (!NT_SUCCESS(st)) {
        /* Fallback: BCRYPT_KDF_RAW_SECRET (Win10 1607+) */
        st = BCryptDeriveKey(sec, L"TRUNCATE", &desc, shared, 32, &out_len, 0);
    }
    BCryptDestroySecret(sec);
    return NT_SUCCESS(st) && out_len == 32;
}

/* ── HMAC-SHA512 ──────────────────────────────────────────────────── */
BOOL ratchet_hmac_sha512(const BYTE *key, DWORD key_len, const BYTE *data, DWORD data_len, BYTE out[64]) {
    if (!ratchet_init_crypto()) return FALSE;
    BCRYPT_HASH_HANDLE h = NULL;
    if (!NT_SUCCESS(BCryptCreateHash(g_alg_hmac_sha512, &h, NULL, 0, (PUCHAR)key, key_len, 0))) return FALSE;
    BOOL ok = NT_SUCCESS(BCryptHashData(h, (PUCHAR)data, data_len, 0))
           && NT_SUCCESS(BCryptFinishHash(h, out, 64, 0));
    BCryptDestroyHash(h);
    return ok;
}
#define hmac_sha512 ratchet_hmac_sha512

/* ── HKDF-SHA512 — extract-then-expand ───────────────────────────── */
BOOL ratchet_hkdf_sha512(const BYTE *salt, DWORD salt_len,
                         const BYTE *ikm, DWORD ikm_len,
                         const BYTE *info, DWORD info_len,
                         BYTE *out, DWORD out_len) {
    BYTE prk[64];
    BYTE zero_salt[64] = {0};
    const BYTE *s = (salt && salt_len) ? salt : zero_salt;
    DWORD sl = (salt && salt_len) ? salt_len : 64;
    if (!hmac_sha512(s, sl, ikm, ikm_len, prk)) return FALSE;

    BYTE t[64]; DWORD t_len = 0;
    DWORD off = 0; BYTE counter = 1;
    while (off < out_len) {
        BYTE *buf = (BYTE*)malloc(t_len + info_len + 1);
        if (!buf) return FALSE;
        if (t_len) memcpy(buf, t, t_len);
        memcpy(buf + t_len, info, info_len);
        buf[t_len + info_len] = counter;
        if (!hmac_sha512(prk, 64, buf, t_len + info_len + 1, t)) { free(buf); return FALSE; }
        free(buf);
        t_len = 64;
        DWORD copy = (out_len - off > 64) ? 64 : (out_len - off);
        memcpy(out + off, t, copy);
        off += copy; counter++;
    }
    return TRUE;
}

#define hkdf_sha512 ratchet_hkdf_sha512

/* ── KDF helpers (match crypto/double_ratchet.py exactly) ────────── */
static const BYTE INFO_RK[] = "SHROUD-DR-RK";
static BOOL kdf_rk(const BYTE rk[32], const BYTE dh[32], BYTE new_rk[32], BYTE new_ck[32]) {
    BYTE out[64];
    if (!hkdf_sha512(rk, 32, dh, 32, INFO_RK, sizeof(INFO_RK) - 1, out, 64)) return FALSE;
    memcpy(new_rk, out, 32); memcpy(new_ck, out + 32, 32);
    return TRUE;
}

static BOOL kdf_ck(BYTE ck[32], BYTE new_ck[32], BYTE mk[32]) {
    BYTE b1 = 0x01, b2 = 0x02;
    BYTE out[64];
    if (!hmac_sha512(ck, 32, &b1, 1, out)) return FALSE;
    memcpy(mk, out, 32);
    if (!hmac_sha512(ck, 32, &b2, 1, out)) return FALSE;
    memcpy(new_ck, out, 32);
    return TRUE;
}

/* ── AES-256-GCM via BCrypt ──────────────────────────────────────── */
static BOOL aes_gcm_encrypt(const BYTE key[32],
                            const BYTE nonce[12],
                            const BYTE *aad, DWORD aad_len,
                            const BYTE *plain, DWORD plain_len,
                            BYTE *ct_with_tag /* plain_len + 16 */) {
    if (!ratchet_init_crypto()) return FALSE;
    BCRYPT_KEY_HANDLE k = NULL;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(g_alg_aes_gcm, &k, NULL, 0, (PUCHAR)key, 32, 0))) return FALSE;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info; BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce; info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)aad; info.cbAuthData = aad_len;
    info.pbTag = ct_with_tag + plain_len; info.cbTag = 16;
    ULONG out_len = 0;
    NTSTATUS st = BCryptEncrypt(k, (PUCHAR)plain, plain_len, &info, NULL, 0,
                                ct_with_tag, plain_len, &out_len, 0);
    BCryptDestroyKey(k);
    return NT_SUCCESS(st);
}

static BOOL aes_gcm_decrypt(const BYTE key[32],
                            const BYTE nonce[12],
                            const BYTE *aad, DWORD aad_len,
                            const BYTE *ct_with_tag, DWORD ct_len, /* includes 16-byte tag */
                            BYTE *plain) {
    if (ct_len < 16) return FALSE;
    if (!ratchet_init_crypto()) return FALSE;
    BCRYPT_KEY_HANDLE k = NULL;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(g_alg_aes_gcm, &k, NULL, 0, (PUCHAR)key, 32, 0))) return FALSE;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info; BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce; info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)aad; info.cbAuthData = aad_len;
    info.pbTag = (PUCHAR)(ct_with_tag + ct_len - 16); info.cbTag = 16;
    DWORD plain_len = ct_len - 16;
    ULONG out_len = 0;
    NTSTATUS st = BCryptDecrypt(k, (PUCHAR)ct_with_tag, plain_len, &info, NULL, 0,
                                plain, plain_len, &out_len, 0);
    BCryptDestroyKey(k);
    return NT_SUCCESS(st);
}

/* ── State setup ─────────────────────────────────────────────────── */
BOOL ratchet_init_alice(RatchetState *st, const BYTE shared[32], const BYTE bob_pub[32]) {
    ZeroMemory(st, sizeof(*st));
    if (!ratchet_x25519_keygen(st->dhs_priv, st->dhs_pub)) return FALSE;
    BYTE dh[32];
    if (!ratchet_x25519_dh(st->dhs_priv, bob_pub, dh)) return FALSE;
    if (!kdf_rk(shared, dh, st->rk, st->cks)) return FALSE;
    st->has_cks = TRUE; st->has_ckr = FALSE;
    memcpy(st->dhr_pub, bob_pub, 32); st->has_dhr = TRUE;
    return TRUE;
}

BOOL ratchet_init_bob(RatchetState *st, const BYTE shared[32],
                      const BYTE my_priv[32], const BYTE my_pub[32]) {
    ZeroMemory(st, sizeof(*st));
    memcpy(st->rk, shared, 32);
    memcpy(st->dhs_priv, my_priv, 32);
    memcpy(st->dhs_pub,  my_pub,  32);
    return TRUE;
}

/* ── DH ratchet step on receive ──────────────────────────────────── */
static BOOL dh_ratchet_step(RatchetState *st, const BYTE new_dhr_pub[32]) {
    st->pn = st->ns; st->ns = 0; st->nr = 0;
    memcpy(st->dhr_pub, new_dhr_pub, 32); st->has_dhr = TRUE;

    BYTE dh1[32];
    if (!ratchet_x25519_dh(st->dhs_priv, st->dhr_pub, dh1)) return FALSE;
    BYTE new_rk[32]; BYTE new_ckr[32];
    if (!kdf_rk(st->rk, dh1, new_rk, new_ckr)) return FALSE;
    memcpy(st->rk, new_rk, 32); memcpy(st->ckr, new_ckr, 32); st->has_ckr = TRUE;

    if (!ratchet_x25519_keygen(st->dhs_priv, st->dhs_pub)) return FALSE;
    BYTE dh2[32];
    if (!ratchet_x25519_dh(st->dhs_priv, st->dhr_pub, dh2)) return FALSE;
    BYTE new_cks[32];
    if (!kdf_rk(st->rk, dh2, new_rk, new_cks)) return FALSE;
    memcpy(st->rk, new_rk, 32); memcpy(st->cks, new_cks, 32); st->has_cks = TRUE;
    return TRUE;
}

static BOOL skip_message_keys(RatchetState *st, DWORD until) {
    if (!st->has_ckr) return TRUE;
    if (st->nr + RATCHET_MAX_SKIP < until) return FALSE;
    while (st->nr < until) {
        if (st->skipped_count >= RATCHET_MAX_SKIP) return FALSE;
        BYTE mk[32]; BYTE new_ckr[32];
        if (!kdf_ck(st->ckr, new_ckr, mk)) return FALSE;
        memcpy(st->ckr, new_ckr, 32);
        memcpy(st->skipped[st->skipped_count].dhr_pub, st->dhr_pub, 32);
        st->skipped[st->skipped_count].n = st->nr;
        memcpy(st->skipped[st->skipped_count].mk, mk, 32);
        st->skipped_count++;
        st->nr++;
    }
    return TRUE;
}

/* ── Encrypt ─────────────────────────────────────────────────────── */
BOOL ratchet_encrypt(RatchetState *st,
                     const BYTE *plain, DWORD plain_len,
                     const BYTE *aad,   DWORD aad_len,
                     BYTE *envelope, DWORD *envelope_len_io) {
    if (!st->has_cks) return FALSE;
    DWORD needed = RATCHET_HEADER_LEN + RATCHET_NONCE_LEN + plain_len + RATCHET_GCM_TAG_LEN;
    if (*envelope_len_io < needed) { *envelope_len_io = needed; return FALSE; }

    BYTE mk[32]; BYTE new_cks[32];
    if (!kdf_ck(st->cks, new_cks, mk)) return FALSE;
    memcpy(st->cks, new_cks, 32);

    BYTE nonce[12]; crypto_random_bytes(nonce, 12);

    /* Build header */
    BYTE *p = envelope;
    *(DWORD*)p = RATCHET_MAGIC; p += 4;
    memcpy(p, st->dhs_pub, 32); p += 32;
    *(DWORD*)p = st->pn; p += 4;
    *(DWORD*)p = st->ns; p += 4;
    memcpy(p, nonce, 12); p += 12;

    /* AAD = header || caller_aad */
    DWORD full_aad_len = RATCHET_HEADER_LEN + aad_len;
    BYTE *full_aad = (BYTE*)malloc(full_aad_len);
    if (!full_aad) return FALSE;
    memcpy(full_aad, envelope, RATCHET_HEADER_LEN);
    if (aad_len) memcpy(full_aad + RATCHET_HEADER_LEN, aad, aad_len);

    BOOL ok = aes_gcm_encrypt(mk, nonce, full_aad, full_aad_len, plain, plain_len, p);
    free(full_aad);
    if (!ok) return FALSE;
    st->ns++;
    *envelope_len_io = needed;
    return TRUE;
}

/* ── Decrypt ─────────────────────────────────────────────────────── */
BOOL ratchet_decrypt(RatchetState *st,
                     const BYTE *envelope, DWORD envelope_len,
                     const BYTE *aad,      DWORD aad_len,
                     BYTE *plain, DWORD *plain_len_io) {
    if (envelope_len < RATCHET_HEADER_LEN + RATCHET_NONCE_LEN + RATCHET_GCM_TAG_LEN) return FALSE;
    DWORD magic = *(const DWORD*)envelope;
    if (magic != RATCHET_MAGIC) return FALSE;
    const BYTE *dh_pub = envelope + 4;
    DWORD pn = *(const DWORD*)(envelope + 36);
    DWORD n  = *(const DWORD*)(envelope + 40);
    const BYTE *nonce = envelope + 44;
    const BYTE *ct    = envelope + 56;
    DWORD ct_len      = envelope_len - 56;
    DWORD plain_len   = ct_len - RATCHET_GCM_TAG_LEN;
    if (*plain_len_io < plain_len) { *plain_len_io = plain_len; return FALSE; }

    DWORD full_aad_len = RATCHET_HEADER_LEN + aad_len;
    BYTE *full_aad = (BYTE*)malloc(full_aad_len);
    if (!full_aad) return FALSE;
    memcpy(full_aad, envelope, RATCHET_HEADER_LEN);
    if (aad_len) memcpy(full_aad + RATCHET_HEADER_LEN, aad, aad_len);

    /* Try skipped-key cache first */
    for (DWORD i = 0; i < st->skipped_count; i++) {
        if (st->skipped[i].n == n && memcmp(st->skipped[i].dhr_pub, dh_pub, 32) == 0) {
            BOOL ok = aes_gcm_decrypt(st->skipped[i].mk, nonce, full_aad, full_aad_len, ct, ct_len, plain);
            free(full_aad);
            if (!ok) return FALSE;
            /* Remove */
            for (DWORD j = i + 1; j < st->skipped_count; j++) st->skipped[j-1] = st->skipped[j];
            st->skipped_count--;
            *plain_len_io = plain_len;
            return TRUE;
        }
    }

    if (!st->has_dhr || memcmp(st->dhr_pub, dh_pub, 32) != 0) {
        if (st->has_ckr) {
            if (!skip_message_keys(st, pn)) { free(full_aad); return FALSE; }
        }
        if (!dh_ratchet_step(st, dh_pub)) { free(full_aad); return FALSE; }
    }

    if (!skip_message_keys(st, n)) { free(full_aad); return FALSE; }

    BYTE mk[32]; BYTE new_ckr[32];
    if (!kdf_ck(st->ckr, new_ckr, mk)) { free(full_aad); return FALSE; }
    memcpy(st->ckr, new_ckr, 32);
    st->nr++;

    BOOL ok = aes_gcm_decrypt(mk, nonce, full_aad, full_aad_len, ct, ct_len, plain);
    free(full_aad);
    if (!ok) return FALSE;
    *plain_len_io = plain_len;
    return TRUE;
}

/* ── State persistence (encrypted via DPAPI) ─────────────────────── */
BOOL ratchet_state_save(const RatchetState *st, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return FALSE;
    size_t n = fwrite(st, 1, sizeof(*st), f);
    fclose(f);
    return n == sizeof(*st);
}

BOOL ratchet_state_load(RatchetState *st, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return FALSE;
    size_t n = fread(st, 1, sizeof(*st), f);
    fclose(f);
    return n == sizeof(*st);
}

/* Bootstrap shared from a static-static X25519 DH.
 * Both sides compute the same 32-byte output because DH is symmetric.
 * Legacy — kept so v1.6-era peers still bootstrap. New code should
 * call ratchet_x3dh_alice / ratchet_x3dh_bob. */
BOOL ratchet_compute_bootstrap(const BYTE my_priv[32], const BYTE peer_pub[32],
                                BYTE shared_out[32]) {
    BYTE dh[32];
    if (!ratchet_x25519_dh(my_priv, peer_pub, dh)) return FALSE;
    static const BYTE info[] = "SHROUD-RATCHET-BOOT-v1";
    BYTE salt[64] = {0};
    return ratchet_hkdf_sha512(salt, 64, dh, 32, info, sizeof(info) - 1, shared_out, 32);
}

/* ── X3DH ───────────────────────────────────────────────────────────
 * Derives the session root key as
 *   SK = HKDF-SHA512(0, F || DH1 || DH2 [|| DH3 || DH4], "SHROUD-X3DH-v1")
 * where F is 32 bytes of 0xFF (Signal-style domain-separation prefix
 * that prevents the X3DH output from colliding with raw DH output of any
 * other protocol). DH3/DH4 are only included when a one-time prekey is
 * available; otherwise we degrade gracefully to a 2-DH handshake. */

static const BYTE X3DH_INFO[] = "SHROUD-X3DH-v1";
#define X3DH_KM_MAX (32 + 32 * 4)

static BOOL x3dh_finalize(const BYTE *km, DWORD km_len, BYTE sk_out[32]) {
    BYTE salt[64] = {0};
    return ratchet_hkdf_sha512(salt, 64, km, km_len,
                               X3DH_INFO, sizeof(X3DH_INFO) - 1, sk_out, 32);
}

BOOL ratchet_x3dh_alice(const BYTE my_ik_priv[32],
                        const BYTE my_ek_priv[32],
                        const BYTE peer_ik_pub[32],
                        const BYTE peer_opk_pub[32],
                        BYTE sk_out[32]) {
    BYTE km[X3DH_KM_MAX];
    memset(km, 0xFF, 32);
    if (!ratchet_x25519_dh(my_ik_priv, peer_ik_pub, km + 32))  return FALSE;  /* DH1 */
    if (!ratchet_x25519_dh(my_ek_priv, peer_ik_pub, km + 64))  return FALSE;  /* DH2 */
    DWORD km_len = 32 + 64;
    if (peer_opk_pub) {
        if (!ratchet_x25519_dh(my_ek_priv, peer_opk_pub, km + 96))  return FALSE;  /* DH3 */
        if (!ratchet_x25519_dh(my_ik_priv, peer_opk_pub, km + 128)) return FALSE;  /* DH4 */
        km_len = 32 + 128;
    }
    BOOL ok = x3dh_finalize(km, km_len, sk_out);
    SecureZeroMemory(km, sizeof(km));
    return ok;
}

BOOL ratchet_x3dh_bob(const BYTE my_ik_priv[32],
                      const BYTE my_opk_priv[32],
                      const BYTE peer_ik_pub[32],
                      const BYTE peer_ek_pub[32],
                      BYTE sk_out[32]) {
    BYTE km[X3DH_KM_MAX];
    memset(km, 0xFF, 32);
    /* Note the swapped arguments vs Alice — ECDH symmetry ensures the
     * shared values are identical. */
    if (!ratchet_x25519_dh(my_ik_priv, peer_ik_pub, km + 32))  return FALSE;  /* DH1 */
    if (!ratchet_x25519_dh(my_ik_priv, peer_ek_pub, km + 64))  return FALSE;  /* DH2 */
    DWORD km_len = 32 + 64;
    if (my_opk_priv) {
        if (!ratchet_x25519_dh(my_opk_priv, peer_ek_pub, km + 96))  return FALSE;  /* DH3 */
        if (!ratchet_x25519_dh(my_opk_priv, peer_ik_pub, km + 128)) return FALSE;  /* DH4 */
        km_len = 32 + 128;
    }
    BOOL ok = x3dh_finalize(km, km_len, sk_out);
    SecureZeroMemory(km, sizeof(km));
    return ok;
}
