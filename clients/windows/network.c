/*
 * GHOSTLINK Windows Network — WinHTTP REST client
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

void network_decode_host(WCHAR *out, int outLen) {
    BYTE enc[] = SERVER_HOST_ENC;
    char key[] = "GHOSTLINK";
    int len = sizeof(enc) - 1; /* minus null terminator */
    for (int i = 0; i < len && i < outLen - 1; i++)
        out[i] = (WCHAR)(enc[i] ^ key[i % 8]);
    out[len < outLen ? len : outLen - 1] = 0;
}

static HINTERNET open_session(const WCHAR *proxy) {
    if (proxy && *proxy) {
        return WinHttpOpen(L"GHOSTLINK/1.0",
                           WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                           proxy,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    }
    return WinHttpOpen(L"GHOSTLINK/1.0",
                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                       WINHTTP_NO_PROXY_NAME,
                       WINHTTP_NO_PROXY_BYPASS, 0);
}

BOOL network_init(void) {
    hSession = open_session(NULL);
    if (!hSession) return FALSE;

    wsprintf(base_url, L"http%s://%s:%d", SERVER_USE_TLS ? L"s" : L"", L"150.195.114.185", SERVER_PORT);
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
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
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

    WCHAR headers[256];
    WCHAR ctw[64];
    MultiByteToWideChar(CP_UTF8, 0,
        content_type ? content_type : "application/octet-stream", -1, ctw, 64);
    wsprintf(headers, L"Content-Type: %s\r\n", ctw);

    if (!WinHttpSendRequest(hRequest, headers, -1, (LPVOID)data, data_len, data_len, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
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
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }

    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
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
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }

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
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
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
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return NULL; }

    WCHAR headers[256], devW[128];
    MultiByteToWideChar(CP_UTF8, 0, device_id, -1, devW, 128);
    wsprintf(headers, L"X-Device-ID: %s\r\n", devW);

    if (!WinHttpSendRequest(hRequest, headers, -1, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
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

    WCHAR headers[256], devW[128];
    MultiByteToWideChar(CP_UTF8, 0, device_id ? device_id : "", -1, devW, 128);
    wsprintf(headers, L"X-Device-ID: %s\r\n", devW);

    if (!WinHttpSendRequest(hRequest, headers, -1, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return NULL;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
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
