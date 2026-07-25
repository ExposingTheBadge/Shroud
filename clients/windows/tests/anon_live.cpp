/* End-to-end check of the anonymous-routing path against a running
 * relay, exercising shroud::AnonClient — the same class main.cpp calls
 * after the Rules 1 & 2 wireup. Proves the sealed envelope leaves the
 * client, is accepted by /messages/send-anon, and comes back out of
 * /messages/fetch-anon decrypting to the original bytes.
 *
 * Usage: anon_live.exe [host] [port]
 */
#include <stdio.h>
#include <string.h>
#include "anon_client.h"
extern "C" {
#include "ratchet.h"
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 58443;
    wchar_t whost[128];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 128);

    BYTE aPriv[32], aPub[32], bPriv[32], bPub[32];
    if (!ratchet_x25519_keygen(aPriv, aPub) || !ratchet_x25519_keygen(bPriv, bPub)) {
        printf("FAIL keygen\n"); return 1;
    }

    /* Both sides derive the same root, exactly as buildRoutingContext does. */
    BYTE rootA[32], rootB[32];
    if (!ratchet_x25519_dh(aPriv, bPub, rootA) || !ratchet_x25519_dh(bPriv, aPub, rootB)) {
        printf("FAIL ecdh\n"); return 1;
    }
    if (memcmp(rootA, rootB, 32) != 0) { printf("FAIL roots disagree\n"); return 1; }
    printf("ok   shared root agrees on both sides\n");

    shroud::AnonClient ac(whost, port, /*tolerate_self_signed=*/true);

    shroud::RoutingContext ctx;
    memcpy(ctx.my_priv, aPriv, 32);
    memcpy(ctx.my_pub, aPub, 32);
    memcpy(ctx.peer_pub, bPub, 32);
    memcpy(ctx.shared_root, rootA, 32);

    const char *payload = "{\"envelope\":{\"body\":\"hello from the windows client\"}}";
    if (!ac.sendSealed(ctx, (const BYTE *)payload, (DWORD)strlen(payload), 0)) {
        printf("FAIL sendSealed (relay unreachable or rejected)\n"); return 1;
    }
    printf("ok   sealed send accepted by /messages/send-anon\n");

    std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE>>> contacts;
    contacts.emplace_back(std::vector<BYTE>(aPub, aPub + 32),
                          std::vector<BYTE>(rootB, rootB + 32));
    std::vector<shroud::IncomingAnon> in;
    if (!ac.fetchMessages(bPriv, bPub, contacts, in)) {
        printf("FAIL fetchMessages\n"); return 1;
    }
    printf("ok   fetch-anon returned %d message(s)\n", (int)in.size());

    for (size_t i = 0; i < in.size(); i++) {
        std::string got((const char *)in[i].plaintext.data(), in[i].plaintext.size());
        if (got == payload) {
            printf("ok   round-trip plaintext matches\n");
            printf("\nWINDOWS ANON PATH: OK\n");
            return 0;
        }
    }
    printf("FAIL no message decrypted to the original payload\n");
    return 1;
}
