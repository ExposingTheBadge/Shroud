/* Drives the Windows client's OWN auth encryption against a live relay:
 * the same crypto_generate_keypair / crypto_auth_derive_key /
 * crypto_aes_gcm_encrypt / network_post calls main.cpp makes on login.
 *
 * If this returns 200 with a known-good password, the client-side
 * encryption path is sound and any 401 is a genuine credential
 * mismatch rather than a crypto fault.
 *
 * Usage: auth_live.exe <username> <password>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "client.h"

static const char *json_field(const char *json, const char *key, char *out, size_t outsz) {
    char pat[128]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), '"');
    if (!p) return NULL;
    p++;
    const char *e = strchr(p, '"');
    if (!e) return NULL;
    size_t n = (size_t)(e - p);
    if (n >= outsz) n = outsz - 1;
    memcpy(out, p, n); out[n] = 0;
    return out;
}

int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: auth_live <username> <password>\n"); return 2; }
    const char *user = argv[1], *pass = argv[2];

    /* crypto_init() opens the global BCrypt AES-GCM and SHA-256 algorithm
     * handles. main.cpp calls it at startup; without it crypto_sha256 and
     * crypto_aes_gcm_encrypt fail, which makes crypto_auth_derive_key
     * return FALSE for reasons that have nothing to do with the keys. */
    if (!crypto_init()) { printf("FAIL crypto_init\n"); return 1; }
    printf("ok   crypto_init\n");
    if (!network_init()) { printf("FAIL network_init\n"); return 1; }
    printf("ok   network_init (targets the relay baked into client.h)\n");

    HttpResponse *r = network_get("/api/v1/key-exchange");
    if (!r || r->len == 0) { printf("FAIL key-exchange unreachable\n"); return 1; }
    char body[8192]; size_t n = r->len < sizeof(body)-1 ? r->len : sizeof(body)-1;
    memcpy(body, r->data, n); body[n] = 0;
    network_free_response(r);

    char sid[128] = {0}, blobHex[1024] = {0};
    if (!json_field(body, "session_id", sid, sizeof(sid)) ||
        !json_field(body, "server_public_key_blob", blobHex, sizeof(blobHex))) {
        printf("FAIL could not parse key-exchange\n"); return 1;
    }
    printf("ok   key-exchange session=%.12s\n", sid);

    KeyPair kp = crypto_generate_keypair();
    if (!kp.handle) { printf("FAIL keypair\n"); return 1; }

    printf("     keypair: handle=%s pub.len=%lu origin=%s\n",
           kp.handle ? "ok" : "NULL", (unsigned long)kp.pub.len,
           crypto_keypair_origin() ? "TPM" : "software");

    BYTE serverBlob[512]; DWORD blobLen = 0;
    crypto_hex_decode(blobHex, serverBlob, &blobLen);
    printf("     server blob: hexlen=%u -> %lu bytes, magic=%02x%02x%02x%02x\n",
           (unsigned)strlen(blobHex), (unsigned long)blobLen,
           serverBlob[0], serverBlob[1], serverBlob[2], serverBlob[3]);
    printf("     PUBLIC_KEY_MAX=%d\n", (int)PUBLIC_KEY_MAX);

    BYTE authKey[32];
    if (!crypto_auth_derive_key(kp.handle, serverBlob, blobLen, authKey)) {
        printf("FAIL crypto_auth_derive_key (blobLen=%lu)\n", (unsigned long)blobLen);
        return 1;
    }
    printf("ok   derived auth key from server blob (%lu bytes)\n", (unsigned long)blobLen);

    char *pubHex = crypto_hex_encode(kp.pub.data, kp.pub.len);
    char payload[2048];
    snprintf(payload, sizeof(payload),
        "{\"username\":\"%s\",\"password\":\"%s\",\"device_name\":\"AuthLive\","
        "\"platform\":\"windows\",\"register\":false,\"public_key\":\"%s\","
        "\"existing_device_id\":\"\"}", user, pass, pubHex);

    BYTE nonce[12], ct[4096], tag[16];
    crypto_random_bytes(nonce, 12);
    DWORD plen = (DWORD)strlen(payload);
    if (!crypto_aes_gcm_encrypt(authKey, (const BYTE*)payload, plen, nonce, ct, tag)) {
        printf("FAIL aes-gcm encrypt\n"); return 1;
    }
    printf("ok   encrypted payload (%lu bytes plaintext)\n", (unsigned long)plen);

    char *nh = crypto_hex_encode(nonce, 12);
    char *ch = crypto_hex_encode(ct, plen);
    char *th = crypto_hex_encode(tag, 16);
    char *authBody = (char*)malloc(strlen(ch) + 4096);
    sprintf(authBody,
        "{\"session_id\":\"%s\",\"client_public_key\":\"%s\",\"nonce\":\"%s\","
        "\"ciphertext\":\"%s\",\"tag\":\"%s\"}", sid, pubHex, nh, ch, th);

    r = network_post("/api/v1/auth", authBody);
    if (!r) { printf("FAIL auth POST no response\n"); return 1; }
    char resp[4096]; n = r->len < sizeof(resp)-1 ? r->len : sizeof(resp)-1;
    memcpy(resp, r->data, n); resp[n] = 0;
    printf("\nserver replied: %.400s\n", resp);
    int ok = strstr(resp, "device_id") != NULL;
    printf("\nCLIENT AUTH ENCRYPTION: %s\n",
           ok ? "ACCEPTED (200) - crypto path is sound"
              : "rejected - see reply above");
    network_free_response(r);
    return ok ? 0 : 1;
}
