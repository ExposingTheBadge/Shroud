/* Isolates whether NCryptDeleteKey() on the ephemeral peer key breaks the
 * subsequent NCryptDeriveKey(). Runs the identical sequence twice: once
 * freeing the peer key correctly, once deleting it as crypto.c does. */
#include <stdio.h>
#include "client.h"

static BOOL run(const BYTE *blob, DWORD blobLen, int delete_peer, SECURITY_STATUS *out) {
    KeyPair kp = crypto_generate_keypair();
    NCRYPT_PROV_HANDLE hProv = 0; DWORD got = 0;
    NCryptGetProperty(kp.handle, NCRYPT_PROVIDER_HANDLE_PROPERTY,
                      (PUCHAR)&hProv, sizeof(hProv), &got, 0);
    NCRYPT_KEY_HANDLE hPeer = 0;
    if (!BCRYPT_SUCCESS(NCryptImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
                                        &hPeer, (PBYTE)blob, blobLen, 0))) return FALSE;
    NCRYPT_SECRET_HANDLE hSecret = 0;
    if (!BCRYPT_SUCCESS(NCryptSecretAgreement(kp.handle, hPeer, &hSecret, 0))) return FALSE;

    if (delete_peer) NCryptDeleteKey(hPeer, 0);   /* what crypto.c does */
    else             NCryptFreeObject(hPeer);     /* correct for ephemeral */

    BCryptBuffer kdfBuf;
    kdfBuf.cbBuffer = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
    kdfBuf.BufferType = KDF_HASH_ALGORITHM;
    kdfBuf.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
    BCryptBufferDesc d; d.ulVersion = BCRYPTBUFFER_VERSION; d.cBuffers = 1; d.pBuffers = &kdfBuf;

    BYTE derived[64]; DWORD dl = sizeof(derived);
    SECURITY_STATUS s = NCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &d, derived, dl, &dl, 0);
    NCryptFreeObject(hSecret);
    *out = s;
    return BCRYPT_SUCCESS(s) && dl >= AES_KEY_LEN;
}

int main(void) {
    if (!network_init()) return 1;
    HttpResponse *r = network_get("/api/v1/key-exchange");
    if (!r || !r->len) { printf("relay unreachable\n"); return 1; }
    char body[8192]; size_t n = r->len < sizeof(body)-1 ? r->len : sizeof(body)-1;
    memcpy(body, r->data, n); body[n]=0; network_free_response(r);
    const char *p = strstr(body, "\"server_public_key_blob\"");
    p = strchr(p + 24, '"') + 1;
    const char *e = strchr(p, '"');
    char hex[1024]; size_t hn = (size_t)(e-p); memcpy(hex,p,hn); hex[hn]=0;
    BYTE blob[512]; DWORD blobLen=0; crypto_hex_decode(hex, blob, &blobLen);

    SECURITY_STATUS s1 = 0, s2 = 0;
    BOOL ok_free = run(blob, blobLen, 0, &s1);
    BOOL ok_del  = run(blob, blobLen, 1, &s2);
    printf("\n  NCryptFreeObject(peer)  -> DeriveKey 0x%08lX  %s\n",
           (unsigned long)s1, ok_free ? "OK" : "FAIL");
    printf("  NCryptDeleteKey(peer)   -> DeriveKey 0x%08lX  %s   <-- crypto.c\n",
           (unsigned long)s2, ok_del ? "OK" : "FAIL");
    printf("\n  verdict: %s\n",
           (ok_free && !ok_del) ? "DeleteKey on the ephemeral peer key breaks derivation"
         : (ok_free && ok_del)  ? "both work - fault is elsewhere"
                                : "derivation fails regardless");
    return 0;
}
