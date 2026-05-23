/*
 * GHOSTLINK Windows Kyber-1024 — Post-Quantum KEM via liboqs
 * Links against oqs.dll (NIST-validated ML-KEM-1024 implementation)
 */
#include "client.h"

/* oqs.dll function pointers loaded dynamically */
static HMODULE hOqsDll = NULL;

typedef int (*oqs_kem_keygen_fn)(unsigned char *pk, unsigned char *sk);
typedef int (*oqs_kem_encaps_fn)(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
typedef int (*oqs_kem_decaps_fn)(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

static oqs_kem_keygen_fn p_oqs_kyber_keygen = NULL;
static oqs_kem_encaps_fn p_oqs_kyber_encaps = NULL;
static oqs_kem_decaps_fn p_oqs_kyber_decaps = NULL;

#define KYBER_1024_PK_LEN  1568
#define KYBER_1024_SK_LEN  3168
#define KYBER_1024_CT_LEN  1568
#define KYBER_1024_SS_LEN  32

/* ── DLL Loading ──────────────────────────────────────────────────── */
BOOL kyber_init(void) {
    if (hOqsDll) return TRUE;

    hOqsDll = LoadLibraryA("oqs.dll");
    if (!hOqsDll) {
        /* Try alongside EXE */
        hOqsDll = LoadLibraryA("D:\\GHOSTLINK\\oqs.dll");
    }
    if (!hOqsDll) return FALSE;

    p_oqs_kyber_keygen = (oqs_kem_keygen_fn)GetProcAddress(hOqsDll, "OQS_KEM_ml_kem_1024_keypair");
    p_oqs_kyber_encaps = (oqs_kem_encaps_fn)GetProcAddress(hOqsDll, "OQS_KEM_ml_kem_1024_encaps");
    p_oqs_kyber_decaps = (oqs_kem_decaps_fn)GetProcAddress(hOqsDll, "OQS_KEM_ml_kem_1024_decaps");

    if (!p_oqs_kyber_keygen || !p_oqs_kyber_encaps || !p_oqs_kyber_decaps) {
        FreeLibrary(hOqsDll);
        hOqsDll = NULL;
        return FALSE;
    }

    return TRUE;
}

void kyber_cleanup(void) {
    if (hOqsDll) {
        FreeLibrary(hOqsDll);
        hOqsDll = NULL;
    }
    p_oqs_kyber_keygen = NULL;
    p_oqs_kyber_encaps = NULL;
    p_oqs_kyber_decaps = NULL;
}

BOOL kyber_available(void) {
    return hOqsDll != NULL;
}

/* ── Key Generation ───────────────────────────────────────────────── */
BOOL kyber_keygen(BYTE *pk_out, BYTE *sk_out) {
    if (!p_oqs_kyber_keygen) return FALSE;
    return p_oqs_kyber_keygen(pk_out, sk_out) == 0;  /* OQS_SUCCESS = 0 */
}

/* ── Encapsulation ────────────────────────────────────────────────── */
BOOL kyber_encaps(BYTE *ct_out, BYTE *ss_out, const BYTE *pk) {
    if (!p_oqs_kyber_encaps) return FALSE;
    return p_oqs_kyber_encaps(ct_out, ss_out, pk) == 0;
}

/* ── Decapsulation ────────────────────────────────────────────────── */
BOOL kyber_decaps(BYTE *ss_out, const BYTE *ct, const BYTE *sk) {
    if (!p_oqs_kyber_decaps) return FALSE;
    return p_oqs_kyber_decaps(ss_out, ct, sk) == 0;
}

/* ── Sizes ────────────────────────────────────────────────────────── */
DWORD kyber_pk_size(void)  { return KYBER_1024_PK_LEN; }
DWORD kyber_sk_size(void)  { return KYBER_1024_SK_LEN; }
DWORD kyber_ct_size(void)  { return KYBER_1024_CT_LEN; }
DWORD kyber_ss_size(void)  { return KYBER_1024_SS_LEN; }
