/* Pinpoints which CNG call fails inside crypto_derive_shared_secret when
 * the local key is TPM-backed. Mirrors the same sequence with the status
 * of every step printed. */
#include <stdio.h>
#include "client.h"

static void st(const char *what, SECURITY_STATUS s) {
    printf("  %-46s 0x%08lX %s\n", what, (unsigned long)s,
           BCRYPT_SUCCESS(s) ? "OK" : "FAIL");
}

int main(void) {
    if (!network_init()) { printf("network_init failed\n"); return 1; }
    HttpResponse *r = network_get("/api/v1/key-exchange");
    if (!r || !r->len) { printf("relay unreachable\n"); return 1; }
    char body[8192]; size_t n = r->len < sizeof(body)-1 ? r->len : sizeof(body)-1;
    memcpy(body, r->data, n); body[n]=0; network_free_response(r);
    const char *p = strstr(body, "\"server_public_key_blob\"");
    p = strchr(p + 24, '"') + 1;
    const char *e = strchr(p, '"');
    char hex[1024]; size_t hn = (size_t)(e-p); memcpy(hex,p,hn); hex[hn]=0;
    BYTE blob[512]; DWORD blobLen=0; crypto_hex_decode(hex, blob, &blobLen);

    printf("\n--- TPM-backed local key ---\n");
    KeyPair kp = crypto_generate_keypair();
    printf("  origin: %s, pub.len=%lu\n",
           crypto_keypair_origin() ? "TPM" : "software", (unsigned long)kp.pub.len);

    NCRYPT_PROV_HANDLE hProv = 0; DWORD got = 0;
    st("NCryptGetProperty(PROVIDER_HANDLE)",
       NCryptGetProperty(kp.handle, NCRYPT_PROVIDER_HANDLE_PROPERTY,
                         (PUCHAR)&hProv, sizeof(hProv), &got, 0));
    NCRYPT_KEY_HANDLE hPeer = 0;
    SECURITY_STATUS s = NCryptImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
                                        &hPeer, blob, blobLen, 0);
    st("NCryptImportKey(into key's own provider)", s);
    if (BCRYPT_SUCCESS(s)) {
        NCRYPT_SECRET_HANDLE sec = 0;
        st("NCryptSecretAgreement(TPM priv, same-prov pub)",
           NCryptSecretAgreement(kp.handle, hPeer, &sec, 0));
        if (sec) NCryptFreeObject(sec);
        NCryptFreeObject(hPeer);
    } else {
        NCRYPT_PROV_HANDLE sw = 0;
        st("NCryptOpenStorageProvider(software)",
           NCryptOpenStorageProvider(&sw, MS_KEY_STORAGE_PROVIDER, 0));
        s = NCryptImportKey(sw, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &hPeer, blob, blobLen, 0);
        st("NCryptImportKey(into SOFTWARE provider)", s);
        if (BCRYPT_SUCCESS(s)) {
            NCRYPT_SECRET_HANDLE sec = 0;
            st("NCryptSecretAgreement(TPM priv, SOFTWARE pub)",
               NCryptSecretAgreement(kp.handle, hPeer, &sec, 0));
            if (sec) NCryptFreeObject(sec);
            NCryptFreeObject(hPeer);
        }
        NCryptFreeObject(sw);
    }
    printf("  crypto_auth_derive_key(): %s\n",
           crypto_auth_derive_key(kp.handle, blob, blobLen, (BYTE[32]){0}) ? "OK" : "FAIL");
    return 0;
}
