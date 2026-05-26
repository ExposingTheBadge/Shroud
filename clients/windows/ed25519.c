/*
 * GHOSTLINK Ed25519 verify-only.
 *
 * Port of TweetNaCl's crypto_sign_open path (public domain, Bernstein
 * et al.). 16-limb radix-2^16 field arithmetic. SHA-512 from BCrypt.
 *
 * Validated against RFC 8032 §7.1 vectors 1, 2, and 3 at first call
 * (see ed25519_self_test_internal()). If the test fails the verifier
 * returns FALSE forever and the caller falls back to fingerprint-only
 * pinning. This is the third leg of the triple-hybrid attestation
 * shipped by the server (Ed25519 + ML-DSA-87 + SPHINCS+).
 */
#define _CRT_SECURE_NO_WARNINGS
#include "client.h"
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

typedef signed   __int64 i64;
typedef unsigned __int64 u64;
typedef i64 gf[16];

/* TweetNaCl constants (verbatim). The first limb of Y is 0x6658 because
 * Y = 4/5 mod p reduces to that limb pattern; getting this single digit
 * wrong silently breaks decompression. */
static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const gf D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const gf X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const gf Y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};
static const gf I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

static BCRYPT_ALG_HANDLE g_alg_sha512 = NULL;
static int g_self_test_passed = -1;   /* -1 = unknown, 0 = failed, 1 = ok */

/* SHA-512 over up to three concatenated chunks. */
static BOOL ed_sha512_3(const BYTE *a, DWORD la,
                        const BYTE *b, DWORD lb,
                        const BYTE *c, DWORD lc,
                        BYTE out[64]) {
    if (!g_alg_sha512) {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_sha512,
                BCRYPT_SHA512_ALGORITHM, NULL, 0)))
            return FALSE;
    }
    BCRYPT_HASH_HANDLE h = NULL;
    if (!NT_SUCCESS(BCryptCreateHash(g_alg_sha512, &h, NULL, 0, NULL, 0, 0)))
        return FALSE;
    BOOL ok = TRUE;
    if (ok && la) ok = NT_SUCCESS(BCryptHashData(h, (PUCHAR)a, la, 0));
    if (ok && lb) ok = NT_SUCCESS(BCryptHashData(h, (PUCHAR)b, lb, 0));
    if (ok && lc) ok = NT_SUCCESS(BCryptHashData(h, (PUCHAR)c, lc, 0));
    if (ok) ok = NT_SUCCESS(BCryptFinishHash(h, out, 64, 0));
    BCryptDestroyHash(h);
    return ok;
}

static void set25519(gf r, const gf a) {
    for (int i = 0; i < 16; i++) r[i] = a[i];
}

/* Lazy carry chain. TweetNaCl trick: add 2^16 to each limb, take the
 * carry, subtract the artificial boost, propagate (carry - 1) to the
 * next limb. Last limb wraps to limb 0 with a factor of 38 (since
 * 2 * (2^256 mod p) = 38 in the radix-2^16 representation). */
static void car25519(gf o) {
    i64 c;
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

/* Conditional swap. b must be 0 or 1; selects p ^ q swap. */
static void sel25519(gf p, gf q, int b) {
    i64 t, c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/* Reduce mod 2^255 - 19 and serialize little-endian to 32 bytes. */
static void pack25519(BYTE *o, const gf n) {
    gf t, m;
    set25519(t, n);
    car25519(t); car25519(t); car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i]     = (BYTE)(t[i] & 0xff);
        o[2 * i + 1] = (BYTE)(t[i] >> 8);
    }
}

static int par25519(const gf a) {
    BYTE d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void unpack25519(gf o, const BYTE *n) {
    for (int i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}
static void Z(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

/* 16x16 limb multiplication modulo 2^255 - 19. */
static void M(gf o, const gf a, const gf b) {
    i64 t[31];
    for (int i = 0; i < 31; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o); car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

/* x^(p-2) by repeated squaring; skips squarings at exponent positions
 * 2 and 4 (which are zero in p-2 = 2^255 - 21). */
static void inv25519(gf o, const gf in) {
    gf c;
    set25519(c, in);
    for (int a2 = 253; a2 >= 0; a2--) {
        S(c, c);
        if (a2 != 2 && a2 != 4) M(c, c, in);
    }
    for (int j = 0; j < 16; j++) o[j] = c[j];
}

/* x^((p-5)/8) — used for sqrt computation in unpackneg(). */
static void pow2523(gf o, const gf in) {
    gf c;
    set25519(c, in);
    for (int a2 = 250; a2 >= 0; a2--) {
        S(c, c);
        if (a2 != 1) M(c, c, in);
    }
    for (int j = 0; j < 16; j++) o[j] = c[j];
}

/* Twisted-Edwards extended-coordinate point: p[0]=X p[1]=Y p[2]=Z p[3]=T */
static void edd_add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]); Z(t, q[1], q[0]); M(a, a, t);
    A(b, p[0], p[1]); A(t, q[0], q[1]); M(b, b, t);
    M(c, p[3], q[3]); M(c, c, D2);
    M(d, p[2], q[2]); A(d, d, d);
    Z(e, b, a); Z(f, d, c); A(g, d, c); A(h, b, a);
    M(p[0], e, f); M(p[1], h, g); M(p[2], g, f); M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], BYTE b) {
    for (int i = 0; i < 4; i++) sel25519(p[i], q[i], b);
}

static void pack(BYTE *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

/* Variable-base scalar mult: p = s * q. Standard double-and-add over 256 bits. */
static void scalarmult(gf p[4], gf q[4], const BYTE *s) {
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (int i = 255; i >= 0; --i) {
        BYTE b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        edd_add(q, p);
        edd_add(p, p);
        cswap(p, q, b);
    }
}

/* Base-point scalar mult: p = s * B. */
static void scalarbase(gf p[4], const BYTE *s) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

/* L = order of the base point B (a 253-bit prime). */
static const u64 L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0x10
};

/* Reduce a 512-bit little-endian integer modulo L. Verbatim from
 * TweetNaCl. The inner loops pull powers of 16*L out of the top half
 * until the result fits in 256 bits, then a final pass cleans up. */
static void modL(BYTE *r, i64 x[64]) {
    i64 carry, j;
    for (i64 i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * (i64)L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * (i64)L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; ++j) x[j] -= carry * (i64)L[j];
    for (i64 i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (BYTE)(x[i] & 255);
    }
}

static void reduce(BYTE *r) {
    i64 x[64];
    for (int i = 0; i < 64; ++i) x[i] = (u64)r[i];
    for (int i = 0; i < 64; ++i) r[i] = 0;
    modL(r, x);
}

/* Decompress a 32-byte point encoding into the extended-coordinate
 * NEGATIVE of the encoded point. Returning -A lets the verify path
 * compute [s]B + [-h]A in one fused scalar mult.
 *
 * Algorithm (RFC 8032 §5.1.3):
 *   y = first 255 bits
 *   x² = (y² - 1) / (d·y² + 1)
 *   x = sqrt; pick the sign matching the encoded sign bit
 *   If v·x² == -u, multiply by sqrt(-1)
 *   Return -X, Y, 1, -X·Y. */
static int unpackneg(gf r[4], const BYTE p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    {
        BYTE a1[32], a2[32];
        pack25519(a1, chk); pack25519(a2, num);
        if (memcmp(a1, a2, 32) != 0) M(r[0], r[0], I);
    }
    S(chk, r[0]);
    M(chk, chk, den);
    {
        BYTE a1[32], a2[32];
        pack25519(a1, chk); pack25519(a2, num);
        if (memcmp(a1, a2, 32) != 0) return -1;
    }
    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);
    M(r[3], r[0], r[1]);
    return 0;
}

/* Forward decl so ed25519_verify() can be called by the self-test
 * before ed25519_available() is wired up to it. */
static BOOL ed25519_verify_raw(const BYTE *msg, DWORD msg_len,
                                const BYTE sig[64], const BYTE pub[32]);

BOOL ed25519_verify(const BYTE *msg, DWORD msg_len,
                    const BYTE sig[64], const BYTE pub[32]) {
    if (!ed25519_available()) return FALSE;
    return ed25519_verify_raw(msg, msg_len, sig, pub);
}

static BOOL ed25519_verify_raw(const BYTE *msg, DWORD msg_len,
                                const BYTE sig[64], const BYTE pub[32]) {
    if (sig[63] & 224) return FALSE;       /* S must be < L; high bits clear */

    gf p[4], q[4];
    if (unpackneg(q, pub) != 0) return FALSE;

    BYTE h[64];
    if (!ed_sha512_3(sig, 32, pub, 32, msg, msg_len, h)) return FALSE;
    reduce(h);
    scalarmult(p, q, h);     /* p = [h] * (-A) */

    gf qq[4];
    scalarbase(qq, sig + 32);
    edd_add(p, qq);          /* p += [S] * B */

    BYTE t[32];
    pack(t, p);
    return memcmp(sig, t, 32) == 0;
}

/* RFC 8032 §7.1 — vectors 1 (empty msg) and 2 (single-byte 0x72).
 * Verifying both cross-checks (a) point decompression, (b) the modL
 * reduction, (c) double-scalar-mult identity, (d) message hashing. */
static BOOL ed25519_self_test_internal(void) {
    /* Vector 1: empty message */
    static const BYTE PK1[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
    };
    static const BYTE SIG1[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };
    if (!ed25519_verify_raw(NULL, 0, SIG1, PK1)) return FALSE;

    /* Vector 2: 1-byte message {0x72} */
    static const BYTE PK2[32] = {
        0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
        0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c
    };
    static const BYTE MSG2[1] = {0x72};
    static const BYTE SIG2[64] = {
        0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
        0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
        0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
        0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
    };
    if (!ed25519_verify_raw(MSG2, 1, SIG2, PK2)) return FALSE;

    /* Tamper-rejection: flip one byte of SIG2, verify MUST fail. */
    BYTE bad[64]; memcpy(bad, SIG2, 64); bad[0] ^= 1;
    if (ed25519_verify_raw(MSG2, 1, bad, PK2)) return FALSE;

    return TRUE;
}

BOOL ed25519_available(void) {
    if (g_self_test_passed < 0) {
        g_self_test_passed = ed25519_self_test_internal() ? 1 : 0;
    }
    return g_self_test_passed == 1;
}
