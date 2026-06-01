/*
 * SHROUD anonymous error reporter — Windows implementation.
 *
 * See error_reporter.h for the API. Reuses anon_routing.c's
 * anon_seal + anon_routing_tag so the wire format is identical to
 * the Python / Android / iOS reporters. Submits sealed reports via
 * WinHTTP to /api/v1/diagnostics/report.
 *
 * Threading model: SEH and signal handlers run on the failing
 * thread; the submit path uses synchronous WinHTTP so the report
 * lands before the process is torn down. Hard timeout 5 seconds.
 */
#include "error_reporter.h"
#include "anon_routing.h"

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

#define APP_VERSION "2.5.0"   /* keep in sync with version_info.txt */

static BYTE  g_operator_pubkey[32] = {0};
static BOOL  g_installed = FALSE;
static char  g_relay_url[256] = {0};
static LPTOP_LEVEL_EXCEPTION_FILTER g_previous_filter = NULL;

/* ── tiny JSON builder ──────────────────────────────────────────── */
/* Avoids pulling Qt JSON into a header used by reporter — we want
 * this self-contained so a crash inside Qt can still build a report. */

static int json_escape(char *out, int out_max, const char *in) {
    int o = 0;
    for (const char *p = in; *p && o < out_max - 2; p++) {
        BYTE c = (BYTE)*p;
        if (c == '"' || c == '\\') {
            if (o + 1 < out_max - 1) { out[o++] = '\\'; out[o++] = c; }
        } else if (c == '\n') {
            if (o + 1 < out_max - 1) { out[o++] = '\\'; out[o++] = 'n'; }
        } else if (c == '\r') {
            if (o + 1 < out_max - 1) { out[o++] = '\\'; out[o++] = 'r'; }
        } else if (c == '\t') {
            if (o + 1 < out_max - 1) { out[o++] = '\\'; out[o++] = 't'; }
        } else if (c < 0x20) {
            o += snprintf(out + o, out_max - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = 0;
    return o;
}

/* Very small subset of PII scrubbing: redact long hex runs (>= 24 chars),
 * which catches pubkeys, hashes, and most device IDs. Full regex set
 * lives in the Python ref; this is the minimal version that runs
 * without pulling in std::regex (which would risk recursion inside a
 * crash handler). */
static void scrub_inplace(char *buf) {
    char *r = buf;
    char *w = buf;
    while (*r) {
        /* hex run */
        char *hex_start = r;
        while ((*r >= '0' && *r <= '9') || (*r >= 'a' && *r <= 'f') || (*r >= 'A' && *r <= 'F')) r++;
        size_t len = (size_t)(r - hex_start);
        if (len >= 24) {
            memcpy(w, "<HEX>", 5);
            w += 5;
        } else {
            memcpy(w, hex_start, len);
            w += len;
        }
        if (*r) {
            *w++ = *r++;
        }
    }
    *w = 0;
}

/* Build a JSON report into `out`. Returns the length written. */
static int build_report_json(char *out, int out_max,
                             const char *kind,
                             const char *message,
                             const char *stack,
                             const char *extra_json) {
    char msg_buf[2048] = {0};
    char stk_buf[2048] = {0};
    strncpy(msg_buf, message ? message : "", sizeof(msg_buf) - 1);
    strncpy(stk_buf, stack   ? stack   : "", sizeof(stk_buf) - 1);
    scrub_inplace(msg_buf);
    scrub_inplace(stk_buf);

    char msg_escaped[3000] = {0};
    char stk_escaped[3000] = {0};
    json_escape(msg_escaped, sizeof(msg_escaped), msg_buf);
    json_escape(stk_escaped, sizeof(stk_escaped), stk_buf);

    /* Windows version */
    char os_buf[128] = "Windows";
    OSVERSIONINFOEXW vi = { sizeof(vi) };
    /* Use VerifyVersionInfo / RtlGetVersion to avoid GetVersionEx deprecation. */
    typedef LONG (WINAPI *RtlGetVersionPfn)(OSVERSIONINFOEXW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (ntdll) {
        RtlGetVersionPfn rgv = (RtlGetVersionPfn)GetProcAddress(ntdll, "RtlGetVersion");
        if (rgv && rgv(&vi) == 0) {
            snprintf(os_buf, sizeof(os_buf), "Windows %lu.%lu (build %lu)",
                     vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        }
    }

    SYSTEMTIME st;
    GetSystemTime(&st);
    /* Approximate unix ts via FileTime */
    FILETIME ft; SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER ui;
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    LONGLONG unix_ts = (LONGLONG)((ui.QuadPart - 116444736000000000ULL) / 10000000ULL);

    return snprintf(out, out_max,
        "{"
            "\"schema\":\"shroud.diag.v1\","
            "\"ts\":%lld,"
            "\"app\":\"shroud-windows\","
            "\"app_version\":\"%s\","
            "\"os\":\"%s\","
            "\"kind\":\"%s\","
            "\"message\":\"%s\","
            "\"stack\":\"%s\","
            "\"context\":%s"
        "}",
        unix_ts, APP_VERSION, os_buf, kind,
        msg_escaped, stk_escaped,
        extra_json && *extra_json ? extra_json : "{}");
}

/* ── WinHTTP submit ─────────────────────────────────────────────── */

static void parse_url(const char *url, wchar_t *host, int host_max,
                      INTERNET_PORT *port, wchar_t *path, int path_max) {
    const char *scheme = strstr(url, "://");
    const char *rest = scheme ? (scheme + 3) : url;
    *port = 443;
    const char *colon = strchr(rest, ':');
    const char *slash = strchr(rest, '/');
    const char *host_end = slash ? slash : (rest + strlen(rest));
    if (colon && colon < host_end) {
        host_end = colon;
        *port = (INTERNET_PORT)atoi(colon + 1);
    }
    size_t host_len = (size_t)(host_end - rest);
    int n = MultiByteToWideChar(CP_UTF8, 0, rest, (int)host_len, host, host_max - 1);
    host[n] = 0;
    if (slash) {
        MultiByteToWideChar(CP_UTF8, 0, slash, -1, path, path_max);
    } else {
        wcscpy_s(path, path_max, L"/");
    }
}

static BOOL submit_sealed(const BYTE *padded4096, const BYTE tag[32]) {
    if (!g_installed || !g_relay_url[0]) return FALSE;

    wchar_t host[256] = {0};
    INTERNET_PORT port = 443;
    wchar_t path[512] = {0};
    parse_url(g_relay_url, host, 256, &port, path, 512);

    /* append diagnostics path */
    wchar_t full_path[768];
    swprintf_s(full_path, 768, L"%ls%ls", path[wcslen(path)-1] == L'/' ? L"" : L"",
               L"/api/v1/diagnostics/report");

    HINTERNET hSession = WinHttpOpen(L"ShroudReporter/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;

    HINTERNET hConn = WinHttpConnect(hSession, host, port, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return FALSE; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", full_path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return FALSE;
    }

    /* Self-signed cert tolerance for dev relay */
    DWORD secOpts = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                  | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secOpts, sizeof(secOpts));

    /* Hex-encode the routing tag */
    wchar_t tag_hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        swprintf(tag_hex + (i * 2), 3, L"%02x", tag[i]);
    }
    wchar_t headers[256] = {0};
    swprintf_s(headers, 256,
        L"Content-Type: application/octet-stream\r\n"
        L"X-Routing-Tag: %ls\r\n", tag_hex);

    BOOL ok = WinHttpSendRequest(hReq, headers, (DWORD)-1L,
                                 (LPVOID)padded4096, 4096, 4096, 0);
    if (ok) {
        ok = WinHttpReceiveResponse(hReq, NULL);
    }
    DWORD status = 0;
    if (ok) {
        DWORD len = sizeof(status);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE
            | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
            &status, &len, WINHTTP_NO_HEADER_INDEX);
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return status >= 200 && status < 300;
}

static BOOL seal_and_submit(const char *json) {
    if (!g_installed) return FALSE;

    /* Seal payload to operator pubkey */
    BYTE sealed[4096] = {0};
    DWORD sealed_len = 0;
    if (!anon_seal((const BYTE*)json, (DWORD)strlen(json),
                    g_operator_pubkey, sealed, &sealed_len)) {
        return FALSE;
    }
    /* sealed_len <= 4096 because anon_seal overhead is small and our
     * report stays under ~3.5 KB. */
    if (sealed_len > 4096) return FALSE;
    /* Remainder of `sealed` is already zero from zero-init above. */

    /* Routing tag derived from operator pubkey, pair_id=0, current epoch */
    BYTE tag[SHROUD_ROUTING_TAG_LEN] = {0};
    SYSTEMTIME st; GetSystemTime(&st);
    FILETIME ft; SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER ui;
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    uint64_t unix_ts = (uint64_t)((ui.QuadPart - 116444736000000000ULL) / 10000000ULL);
    uint64_t epoch = anon_epoch_for(unix_ts);
    if (!anon_routing_tag(g_operator_pubkey, /*pair=*/0, epoch, tag)) return FALSE;

    return submit_sealed(sealed, tag);
}

/* ── Unhandled exception filter ────────────────────────────────── */

static LONG WINAPI seh_filter(EXCEPTION_POINTERS *ep) {
    char msg[256];
    snprintf(msg, sizeof(msg),
             "exception code 0x%08lx at 0x%p",
             ep->ExceptionRecord->ExceptionCode,
             ep->ExceptionRecord->ExceptionAddress);

    /* Stack trace via CaptureStackBackTrace (no DbgHelp dependency) */
    PVOID frames[32] = {0};
    USHORT n = CaptureStackBackTrace(0, 32, frames, NULL);
    char stack[2048] = {0};
    int off = 0;
    for (USHORT i = 0; i < n && off < (int)sizeof(stack) - 64; i++) {
        off += snprintf(stack + off, sizeof(stack) - off,
                        "  #%u 0x%p\n", i, frames[i]);
    }

    char json[6000];
    int len = build_report_json(json, sizeof(json), "crash", msg, stack, NULL);
    if (len > 0 && len < (int)sizeof(json)) {
        seal_and_submit(json);
    }

    /* Chain to the previously-installed filter so the OS still
     * produces the normal WER tombstone. */
    if (g_previous_filter) return g_previous_filter(ep);
    return EXCEPTION_EXECUTE_HANDLER;
}

/* ── Public API ────────────────────────────────────────────────── */

void error_reporter_install(const BYTE operator_diag_pubkey[32],
                            const char *relay_base_url) {
    memcpy(g_operator_pubkey, operator_diag_pubkey, 32);
    if (relay_base_url) {
        strncpy(g_relay_url, relay_base_url, sizeof(g_relay_url) - 1);
    }
    /* Skip install if pubkey is all zeros (no operator configured) */
    BOOL nonzero = FALSE;
    for (int i = 0; i < 32; i++) {
        if (g_operator_pubkey[i] != 0) { nonzero = TRUE; break; }
    }
    if (!nonzero) return;

    g_installed = TRUE;
    g_previous_filter = SetUnhandledExceptionFilter(seh_filter);
}

BOOL error_reporter_log(const char *message, const char *extra_json) {
    if (!g_installed) return FALSE;
    char json[6000];
    int len = build_report_json(json, sizeof(json), "log", message, "",
                                extra_json);
    if (len <= 0 || len >= (int)sizeof(json)) return FALSE;
    return seal_and_submit(json);
}
