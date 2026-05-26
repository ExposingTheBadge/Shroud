/*
 * GHOSTLINK Windows OQS Signature Verifier
 * ========================================
 * Dynamically loads liboqs (oqs.dll) and exposes signature verification for
 * ML-DSA-87 + SPHINCS+-SHA2-256s-simple. Used to verify the server's
 * triple-hybrid identity signature on /api/v1/key-exchange-v2.
 *
 * If oqs.dll is not installed, all functions return FALSE and the caller
 * should fall back to identity-fingerprint-only pinning (which already
 * runs before this verification step in main.cpp). When oqs.dll IS
 * available, every handshake response is cryptographically bound to the
 * pinned identity — defeating MITM even with a corrupted pin file.
 */
#include "client.h"
#include <string.h>

static HMODULE g_oqs_dll = NULL;

/* liboqs C API uses an opaque OQS_SIG struct. We declare it as void to
   avoid pulling in oqs/oqs.h at build time. */
typedef void OQS_SIG;

typedef OQS_SIG *(*oqs_sig_new_fn)(const char *method_name);
typedef void     (*oqs_sig_free_fn)(OQS_SIG *sig);
typedef int      (*oqs_sig_verify_fn)(OQS_SIG *sig,
                                       const unsigned char *message, size_t message_len,
                                       const unsigned char *signature, size_t signature_len,
                                       const unsigned char *public_key);

static oqs_sig_new_fn    p_oqs_sig_new    = NULL;
static oqs_sig_free_fn   p_oqs_sig_free   = NULL;
static oqs_sig_verify_fn p_oqs_sig_verify = NULL;

static BOOL ensure_oqs_loaded(void) {
    if (g_oqs_dll && p_oqs_sig_new && p_oqs_sig_verify) return TRUE;
    if (!g_oqs_dll) {
        g_oqs_dll = LoadLibraryA("oqs.dll");
        if (!g_oqs_dll) g_oqs_dll = LoadLibraryA("D:\\GHOSTLINK\\oqs.dll");
        if (!g_oqs_dll) return FALSE;
    }
    p_oqs_sig_new    = (oqs_sig_new_fn)   GetProcAddress(g_oqs_dll, "OQS_SIG_new");
    p_oqs_sig_free   = (oqs_sig_free_fn)  GetProcAddress(g_oqs_dll, "OQS_SIG_free");
    p_oqs_sig_verify = (oqs_sig_verify_fn)GetProcAddress(g_oqs_dll, "OQS_SIG_verify");
    return p_oqs_sig_new && p_oqs_sig_free && p_oqs_sig_verify;
}

BOOL oqs_sig_available(void) {
    return ensure_oqs_loaded();
}

BOOL oqs_sig_verify(const char *algorithm,
                    const BYTE *message, DWORD message_len,
                    const BYTE *signature, DWORD signature_len,
                    const BYTE *public_key) {
    if (!ensure_oqs_loaded()) return FALSE;
    OQS_SIG *sig = p_oqs_sig_new(algorithm);
    if (!sig) return FALSE;
    int rc = p_oqs_sig_verify(sig, message, message_len, signature, signature_len, public_key);
    p_oqs_sig_free(sig);
    return rc == 0;  /* OQS_SUCCESS */
}

/* ────────────────────────────────────────────────────────────────────
 * GHOSTLINK triple-hybrid signature wire layout (matches crypto/hybrid_sig.py):
 *   PK_BLOB:   4B 'SKB2' | 32B Ed25519 | 2592B ML-DSA-87 | 64B SPHINCS+
 *              total 2692 bytes
 *   SIG_BLOB:  4B 'SGB2' | 64B Ed25519 | 4627B ML-DSA-87 | 29792B SPHINCS+
 *              total 34487 bytes
 *
 * Verifies ALL THREE signatures. Ed25519 is checked by the pure-C
 * implementation in ed25519.c (no DLL dependency). ML-DSA-87 and
 * SPHINCS+-SHA2-256s-simple are checked by liboqs.dll when present.
 *
 * Requires: Ed25519 OK AND (oqs.dll present AND ML-DSA OK AND SPHINCS+ OK).
 * If oqs.dll is missing, the function returns FALSE so the caller falls
 * back to identity-fingerprint-only pinning. An attacker would have to
 * forge all three signatures simultaneously — three independent hardness
 * assumptions (elliptic curve / lattice / hash).
 */
#define HSIG_PK_TOTAL    2692
#define HSIG_PK_ED       32
#define HSIG_PK_MLDSA    2592
#define HSIG_PK_SPHINCS  64
#define HSIG_SIG_TOTAL   34487
#define HSIG_SIG_ED      64
#define HSIG_SIG_MLDSA   4627
#define HSIG_SIG_SPHINCS 29792
#define HSIG_PK_MAGIC    0x32424B53UL  /* 'SKB2' LE */
#define HSIG_SIG_MAGIC   0x32424753UL  /* 'SGB2' LE */

BOOL ghostlink_verify_server_sig(const BYTE *pk_blob, DWORD pk_blob_len,
                                  const BYTE *sig_blob, DWORD sig_blob_len,
                                  const BYTE *message, DWORD message_len) {
    if (pk_blob_len != HSIG_PK_TOTAL || sig_blob_len != HSIG_SIG_TOTAL) return FALSE;
    if (*(const DWORD*)pk_blob  != HSIG_PK_MAGIC)  return FALSE;
    if (*(const DWORD*)sig_blob != HSIG_SIG_MAGIC) return FALSE;
    if (!ensure_oqs_loaded()) return FALSE;

    const BYTE *ed_pk      = pk_blob + 4;
    const BYTE *mldsa_pk   = ed_pk + HSIG_PK_ED;
    const BYTE *sphincs_pk = mldsa_pk + HSIG_PK_MLDSA;

    const BYTE *ed_sig      = sig_blob + 4;
    const BYTE *mldsa_sig   = ed_sig + HSIG_SIG_ED;
    const BYTE *sphincs_sig = mldsa_sig + HSIG_SIG_MLDSA;

    /* Ed25519 (classical) — pure C; must pass the RFC 8032 self-test. */
    if (!ed25519_verify(message, message_len, ed_sig, ed_pk)) return FALSE;

    /* ML-DSA-87 (lattice PQ). */
    if (!oqs_sig_verify("ML-DSA-87",
                        message, message_len,
                        mldsa_sig, HSIG_SIG_MLDSA, mldsa_pk)) return FALSE;

    /* SPHINCS+-256s (hash-based PQ). */
    if (!oqs_sig_verify("SPHINCS+-SHA2-256s-simple",
                        message, message_len,
                        sphincs_sig, HSIG_SIG_SPHINCS, sphincs_pk)) return FALSE;

    return TRUE;
}
