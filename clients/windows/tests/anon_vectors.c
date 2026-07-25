/* Pins the Windows C implementation against the reference vectors in
 * crypto/anon_routing.py. Drift is silent at runtime: sealed messages
 * land on a routing tag no recipient polls. Built and run by
 * tests/cross_client_vectors.py.
 *
 * cl /nologo /I.. tests\anon_vectors.c ..\anon_routing.c ..\ratchet.c
 *     ..\crypto.c ..\kyber1024.c ..\ed25519.c ..\oqs_sig.c
 *     bcrypt.lib ncrypt.lib crypt32.lib
 */
#include <stdio.h>
#include <string.h>
#include "anon_routing.h"

static int fail = 0;

static void expect_hex(const char *what, const BYTE *got, int len, const char *want) {
    char hex[129]; int i;
    for (i = 0; i < len; i++) sprintf(hex + i * 2, "%02x", got[i]);
    hex[len * 2] = 0;
    if (strcmp(hex, want) != 0) {
        printf("FAIL %s\n  got  %s\n  want %s\n", what, hex, want);
        fail = 1;
    } else {
        printf("ok   %s\n", what);
    }
}

int main(void) {
    BYTE a[32], b[32], root[32], tag[32];
    int i;
    for (i = 0; i < 32; i++) { a[i] = (BYTE)i; b[i] = (BYTE)(100 + i); root[i] = 0xAB; }

    uint64_t pair = anon_pair_id(a, b);
    if (pair != 14238346497009308455ULL) {
        printf("FAIL pair_id\n  got  %llu\n  want 14238346497009308455\n",
               (unsigned long long)pair);
        fail = 1;
    } else {
        printf("ok   pair_id\n");
    }

    if (!anon_routing_tag(root, pair, 0, tag)) { printf("FAIL routing_tag(0) returned FALSE\n"); return 1; }
    expect_hex("routing_tag epoch=0",
               tag, 32, "0878c6e14dea3a235c954bb9277e6570f6be47b45ac427c5bf83440e88304216");
    if (!anon_routing_tag(root, pair, 1, tag)) { printf("FAIL routing_tag(1) returned FALSE\n"); return 1; }
    expect_hex("routing_tag epoch=1",
               tag, 32, "c1ee572ddd805462bc00f0307996b9747dc9cc97f9fce3bb85a7f9ce3cbe3e6d");
    if (!anon_routing_tag(root, pair, 472000, tag)) { printf("FAIL routing_tag(472000) returned FALSE\n"); return 1; }
    expect_hex("routing_tag epoch=472000",
               tag, 32, "d9ccbe248ee1e6401eb76751638d06debb9262181fe936c3ff744a842f2a4057");

    if (anon_epoch_for(3600) != 1 || anon_epoch_for(7199) != 1 || anon_epoch_for(7200) != 2) {
        printf("FAIL epoch_for boundaries\n"); fail = 1;
    } else {
        printf("ok   epoch_for boundaries\n");
    }

    printf(fail ? "\nWINDOWS C: MISMATCH\n" : "\nWINDOWS C: all vectors match\n");
    return fail;
}
