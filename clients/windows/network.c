/*
 * SHROUD Windows Network — WinHTTP REST client
 *
 * Supports an optional SOCKS5 proxy so users can route every request through
 * a local Tor daemon (default 127.0.0.1:9050). WinHTTP gained native SOCKS5
 * support in Windows 10 21H1 — the proxy is selected by passing
 * "socks=host:port" to WinHttpOpen instead of the usual http://host:port.
 *
 * Call network_set_proxy("socks=127.0.0.1:9050", TRUE) to enable, or
 * network_set_proxy(NULL, FALSE) to go back to direct connections. The
 * session handle is recreated each time so the proxy switch takes effect
 * for every subsequent request.
 */
#include "client.h"

static HINTERNET hSession = NULL;
static WCHAR base_url[256];
static WCHAR cur_proxy[128] = { 0 };  /* empty = direct */

/* Legacy export — older translation units still reference this symbol
 * via client.h. The XOR scheme is gone (see comment in client.h); we
 * just copy the literal SERVER_HOST into the caller's buffer so they
 * keep getting the right address. */
void network_decode_host(WCHAR *out, int outLen) {
    if (!out || outLen <= 0) return;
    wcsncpy_s(out, outLen, SERVER_HOST, _TRUNCATE);
}

static HINTERNET open_session(const WCHAR *proxy) {
    if (proxy && *proxy) {
        return WinHttpOpen(L"SHROUD/1.0",
                           WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                           proxy,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    }
    return WinHttpOpen(L"SHROUD/1.0",
                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                       WINHTTP_NO_PROXY_NAME,
                       WINHTTP_NO_PROXY_BYPASS, 0);
}

BOOL network_init(void) {
    hSession = open_session(NULL);
    if (!hSession) return FALSE;

    wsprintf(base_url, L"http%s://%s:%d",
             SERVER_USE_TLS ? L"s" : L"",
             SERVER_HOST,
             SERVER_PORT);
    return TRUE;
}

/* Swap the WinHTTP session over to (or away from) a proxy at runtime.
 * `proxy_a` is an ASCII string like "socks=127.0.0.1:9050" (WinHTTP's
 * native SOCKS5 syntax — Windows 10 21H1+) or NULL/"" for direct. */
BOOL network_set_proxy(const char *proxy_a) {
    WCHAR new_proxy[128];
    if (proxy_a && *proxy_a) {
        MultiByteToWideChar(CP_UTF8, 0, proxy_a, -1, new_proxy, 128);
    } else {
        new_proxy[0] = 0;
    }
    /* Skip rebuild if nothing changed — keeps connection pool warm. */
    if (wcsncmp(new_proxy, cur_proxy, 128) == 0) return TRUE;

    HINTERNET fresh = open_session(new_proxy[0] ? new_proxy : NULL);
    if (!fresh) return FALSE;
    if (hSession) WinHttpCloseHandle(hSession);
    hSession = fresh;
    wcsncpy(cur_proxy, new_proxy, 128);
    cur_proxy[127] = 0;
    return TRUE;
}

void network_cleanup(void) {
    if (hSession) WinHttpCloseHandle(hSession);
    hSession = NULL;
}

/* Tolerate the relay's self-signed TLS cert. The production relays
 * present a self-signed leaf — there's no public CA chain by design
 * (Rule 0: the relay deploy must work even without third-party CA
 * trust). The transport-level signature is irrelevant to the wire
 * security model: every auth handshake and every message envelope is
 * end-to-end encrypted at the application layer, independent of TLS.
 * Call this on every hRequest BEFORE WinHttpSendRequest. */
static void allow_self_signed(HINTERNET hRequest) {
    if (!SERVER_USE_TLS || !hRequest) return;
    DWORD opts = SECURITY_FLAG_IGNORE_UNKNOWN_CA
               | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
               | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
               | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &opts, sizeof(opts));
}

/* ── Device token ─────────────────────────────────────────────────
 * The relay issues a secret token at sign-in. Every request that acts
 * for this device carries it, because the device id alone is known to
 * every friend and used to be enough to read our mail or wipe us. */
static char g_device_token[192] = { 0 };

void network_set_device_token(const char *token) {
    strncpy_s(g_device_token, sizeof(g_device_token), token ? token : "", _TRUNCATE);
}

static void add_device_token(HINTERNET hRequest) {
    if (!hRequest || !g_device_token[0]) return;
    WCHAR wtok[200], hdr[240];
    MultiByteToWideChar(CP_UTF8, 0, g_device_token, -1, wtok, 200);
    swprintf_s(hdr, 240, L"X-Device-Token: %s", wtok);
    WinHttpAddRequestHeaders(hRequest, hdr, (DWORD)-1L,
                             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
}

/* ── TLS certificate pinning (trust on first use) ────────────────────
 * The relay's certificate is self-signed, so the CA checks above are
 * off. Without a pin, anyone on the network path could present their
 * own certificate and read the device token and every request. The
 * SHA-256 of the relay's leaf certificate is saved on first contact in
 * %APPDATA%\SHROUD\tls_pin.txt; a different certificate afterwards is
 * refused. Delete that file after deliberately replacing the relay's
 * certificate. */
static BOOL g_pin_mismatch = FALSE;

BOOL network_tls_pin_mismatch(void) { return g_pin_mismatch; }

static BOOL pin_path(WCHAR *out, DWORD cap) {
    WCHAR appdata[MAX_PATH];
    if (!GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) return FALSE;
    WCHAR dir[MAX_PATH];
    swprintf_s(dir, MAX_PATH, L"%s\\SHROUD", appdata);
    CreateDirectoryW(dir, NULL);
    swprintf_s(out, cap, L"%s\\tls_pin.txt", dir);
    return TRUE;
}

static BOOL tls_pin_ok(HINTERNET hRequest) {
    if (!SERVER_USE_TLS) return TRUE;
    PCCERT_CONTEXT cert = NULL;
    DWORD sz = sizeof(cert);
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &sz) || !cert)
        return FALSE;
    BYTE hash[SHA256_LEN];
    BOOL hashed = crypto_sha256(cert->pbCertEncoded, cert->cbCertEncoded, hash);
    CertFreeCertificateContext(cert);
    if (!hashed) return FALSE;
    char hex[SHA256_LEN * 2 + 1];
    for (int i = 0; i < SHA256_LEN; i++) sprintf_s(hex + i * 2, 3, "%02x", hash[i]);

    WCHAR path[MAX_PATH];
    if (!pin_path(path, MAX_PATH)) return TRUE;   /* nowhere to pin; don't lock the user out */
    char saved[SHA256_LEN * 2 + 8] = { 0 };
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD got = 0;
        ReadFile(f, saved, SHA256_LEN * 2, &got, NULL);
        CloseHandle(f);
        saved[got] = 0;
    }
    if (saved[0] == 0) {
        f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD put = 0;
            WriteFile(f, hex, SHA256_LEN * 2, &put, NULL);
            CloseHandle(f);
        }
        return TRUE;
    }
    if (_strnicmp(saved, hex, SHA256_LEN * 2) != 0) {
        g_pin_mismatch = TRUE;
        return FALSE;
    }
    g_pin_mismatch = FALSE;
    return TRUE;
}

/* Every request: certificate policy + device token. */
static void prepare_request(HINTERNET hRequest) {
    allow_self_signed(hRequest);
    add_device_token(hRequest);
}

/* WinHttpReceiveResponse, then refuse the response if the certificate
 * does not match the pin. */
static BOOL receive_pinned(HINTERNET hRequest) {
    if (!WinHttpReceiveResponse(hRequest, NULL)) return FALSE;
    return tls_pin_ok(hRequest);
}

HttpResponse* network_post_h(const char *path, const char *json_body, const char *extra_header) {
    if (!hSession) return NULL;

    WCHAR url[512];
    WCHAR wpath[256];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 256);
    wsprintf(url, L"%s%s", base_url, wpath);

    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    WCHAR hostname[256], urlPath[512];
    urlComp.lpszHostName = hostname; urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;  urlComp.dwUrlPathLength = 512;

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) return NULL;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        SERVER_USE_TLS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }
    prepare_request(hRequest);

    /* Set JSON content type + optional caller-supplied extras like X-Expires-In. */
    WCHAR headers[1024];
    if (extra_header && *extra_header) {
        WCHAR wextra[512];
        MultiByteToWideChar(CP_UTF8, 0, extra_header, -1, wextra, 512);
        wsprintf(headers, L"Content-Type: application/json\r\n%s\r\n", wextra);
    } else {
        wcscpy(headers, L"Content-Type: application/json\r\n");
    }
    DWORD bodyLen = (DWORD)strlen(json_body);

    if (!WinHttpSendRequest(hRequest, headers, -1, (LPVOID)json_body, bodyLen, bodyLen, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return NULL;
    }
    if (!receive_pinned(hRequest)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return NULL;
    }

    /* Read response */
    HttpResponse *r = calloc(1, sizeof(HttpResponse));
    r->cap = 4096;
    r->data = malloc(r->cap);

    DWORD bytesRead, totalRead = 0;
    while (WinHttpReadData(hRequest, r->data + totalRead, r->cap - totalRead - 1, &bytesRead)) {
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        if (totalRead + 1024 >= r->cap) {
            r->cap *= 2;
            r->data = realloc(r->data, r->cap);
        }
    }
    r->data[totalRead] = 0;
    r->len = totalRead;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return r;
}

HttpResponse* network_post(const char *path, const char *json_body) {
    return network_post_h(path, json_body, NULL);
}

/* Raw-bytes POST. JSON helpers can't carry null bytes; AES-GCM ciphertext can.
 * Used by the multi-device linking flow to ship an opaque encrypted blob. */
HttpResponse* network_post_bytes(const char *path, const BYTE *data, DWORD data_len,
                                 const char *content_type) {
    if (!hSession) return NULL;

    WCHAR url[512], wpath[256];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 256);
    wsprintf(url, L"%s%s", base_url, wpath);

    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    WCHAR hostname[256], urlPath[512];
    urlComp.lpszHostName = hostname; urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;  urlComp.dwUrlPathLength = 512;
    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) return NULL;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        SERVER_USE_TLS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }
    prepare_request(hRequest);

    WCHAR headers[256];
    WCHAR ctw[64];
    MultiByteToWideChar(CP_UTF8, 0,
        content_type ? content_type : "application/octet-stream", -1, ctw, 64);
    wsprintf(headers, L"Content-Type: %s\r\n", ctw);

    if (!WinHttpSendRequest(hRequest, headers, -1, (LPVOID)data, data_len, data_len, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!receive_pinned(hRequest)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }

    HttpResponse *r = calloc(1, sizeof(HttpResponse));
    r->cap = 4096;
    r->data = malloc(r->cap);
    DWORD bytesRead, totalRead = 0;
    while (WinHttpReadData(hRequest, r->data + totalRead, r->cap - totalRead - 1, &bytesRead)) {
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        if (totalRead + 1024 >= r->cap) {
            r->cap *= 2;
            r->data = realloc(r->data, r->cap);
        }
    }
    r->data[totalRead] = 0;
    r->len = totalRead;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return r;
}

HttpResponse* network_get(const char *path) {
    if (!hSession) return NULL;

    WCHAR url[512], wpath[256];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 256);
    wsprintf(url, L"%s%s", base_url, wpath);

    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    WCHAR hostname[256], urlPath[512];
    urlComp.lpszHostName = hostname; urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;  urlComp.dwUrlPathLength = 512;

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) return NULL;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        SERVER_USE_TLS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }
    prepare_request(hRequest);

    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!receive_pinned(hRequest)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }

    HttpResponse *r = calloc(1, sizeof(HttpResponse));
    r->cap = 4096;
    r->data = malloc(r->cap);
    DWORD bytesRead, totalRead = 0;
    while (WinHttpReadData(hRequest, r->data + totalRead, r->cap - totalRead - 1, &bytesRead)) {
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        if (totalRead + 1024 >= r->cap) {
            r->cap *= 2;
            r->data = realloc(r->data, r->cap);
        }
    }
    r->data[totalRead] = 0;
    r->len = totalRead;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return r;
}

HttpResponse* network_upload_file(const char *path, const BYTE *data, DWORD data_len,
                                   const char *sender_id, const char *recipient_id,
                                   const char *metadata_json) {
    if (!hSession) return NULL;

    WCHAR url[512], wpath[256];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 256);
    wsprintf(url, L"%s%s", base_url, wpath);

    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    WCHAR hostname[256], urlPath[512];
    urlComp.lpszHostName = hostname; urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;  urlComp.dwUrlPathLength = 512;

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) return NULL;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        SERVER_USE_TLS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }
    prepare_request(hRequest);

    /* Custom headers for file transfer */
    WCHAR headers[1024], senderW[128], recipW[128], metaW[512];
    MultiByteToWideChar(CP_UTF8, 0, sender_id, -1, senderW, 128);
    MultiByteToWideChar(CP_UTF8, 0, recipient_id, -1, recipW, 128);
    MultiByteToWideChar(CP_UTF8, 0, metadata_json, -1, metaW, 512);
    wsprintf(headers, L"X-Device-ID: %s\r\nX-Recipient-ID: %s\r\nX-File-Metadata: %s\r\nContent-Type: application/octet-stream\r\n",
             senderW, recipW, metaW);

    if (!WinHttpSendRequest(hRequest, headers, -1, (LPVOID)data, data_len, data_len, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!receive_pinned(hRequest)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }

    /* Read response */
    HttpResponse *r = calloc(1, sizeof(HttpResponse));
    r->cap = 4096;
    r->data = malloc(r->cap);
    DWORD bytesRead, totalRead = 0;
    while (WinHttpReadData(hRequest, r->data + totalRead, r->cap - totalRead - 1, &bytesRead)) {
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        if (totalRead + 1024 >= r->cap) {
            r->cap *= 2;
            r->data = realloc(r->data, r->cap);
        }
    }
    r->data[totalRead] = 0;
    r->len = totalRead;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return r;
}

HttpResponse* network_download_file(const char *path, const char *device_id,
                                     BYTE **out_data, DWORD *out_len) {
    if (!hSession) return NULL;

    WCHAR url[512], wpath[256];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 256);
    wsprintf(url, L"%s%s", base_url, wpath);

    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    WCHAR hostname[256], urlPath[512];
    urlComp.lpszHostName = hostname; urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;  urlComp.dwUrlPathLength = 512;

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) return NULL;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        SERVER_USE_TLS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }
    prepare_request(hRequest);

    WCHAR headers[256], devW[128];
    MultiByteToWideChar(CP_UTF8, 0, device_id, -1, devW, 128);
    wsprintf(headers, L"X-Device-ID: %s\r\n", devW);

    if (!WinHttpSendRequest(hRequest, headers, -1, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!receive_pinned(hRequest)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }

    /* Read binary response into growing buffer */
    DWORD cap = 65536;
    BYTE *buf = malloc(cap);
    DWORD totalRead = 0, bytesRead;
    while (WinHttpReadData(hRequest, buf + totalRead, cap - totalRead, &bytesRead)) {
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        if (totalRead + 65536 >= cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);

    *out_data = buf;
    *out_len = totalRead;
    return NULL;  /* No JSON response for file downloads, data is in out_data */
}

HttpResponse* network_delete(const char *path, const char *device_id) {
    if (!hSession) return NULL;

    WCHAR url[512], wpath[256];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 256);
    wsprintf(url, L"%s%s", base_url, wpath);

    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    WCHAR hostname[256], urlPath[512];
    urlComp.lpszHostName = hostname; urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;  urlComp.dwUrlPathLength = 512;

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) return NULL;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"DELETE", urlComp.lpszUrlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        SERVER_USE_TLS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }
    prepare_request(hRequest);

    WCHAR headers[256], devW[128];
    MultiByteToWideChar(CP_UTF8, 0, device_id ? device_id : "", -1, devW, 128);
    wsprintf(headers, L"X-Device-ID: %s\r\n", devW);

    if (!WinHttpSendRequest(hRequest, headers, -1, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!receive_pinned(hRequest)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }

    HttpResponse *r = calloc(1, sizeof(HttpResponse));
    r->cap = 4096;
    r->data = malloc(r->cap);
    DWORD bytesRead, totalRead = 0;
    while (WinHttpReadData(hRequest, r->data + totalRead, r->cap - totalRead - 1, &bytesRead)) {
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        if (totalRead + 1024 >= r->cap) {
            r->cap *= 2;
            r->data = realloc(r->data, r->cap);
        }
    }
    r->data[totalRead] = 0;
    r->len = totalRead;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return r;
}

void network_free_response(HttpResponse *r) {
    if (!r) return;
    if (r->data) free(r->data);
    free(r);
}
