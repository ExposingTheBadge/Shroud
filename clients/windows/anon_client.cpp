/*
 * anon_client.cpp - implementation. See header for API.
 */
#include "anon_client.h"

#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <set>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

namespace shroud {

static constexpr DWORD PAD_BUCKET = 4096;

AnonClient::AnonClient(const std::wstring &relay_host, int port, bool tolerate_self_signed)
    : m_host(relay_host), m_port(port), m_tolerate_self_signed(tolerate_self_signed) {}

std::string AnonClient::toHex(const BYTE *data, size_t len) {
    static const char *digits = "0123456789abcdef";
    std::string out(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = digits[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[ data[i]       & 0xF];
    }
    return out;
}

std::vector<BYTE> AnonClient::fromHex(const std::string &hex) {
    std::vector<BYTE> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto hi = hex[i], lo = hex[i + 1];
        auto nyb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nyb(hi), l = nyb(lo);
        if (h < 0 || l < 0) { out.clear(); return out; }
        out.push_back(static_cast<BYTE>((h << 4) | l));
    }
    return out;
}

std::vector<BYTE> AnonClient::httpPost(const char *path,
                                       const std::vector<BYTE> &body,
                                       const std::vector<std::wstring> &extra_headers,
                                       int *http_status_out) {
    std::vector<BYTE> result;
    if (http_status_out) *http_status_out = -1;

    HINTERNET hSess = WinHttpOpen(L"SHROUD/anon",
                                  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return result;

    HINTERNET hConn = WinHttpConnect(hSess, m_host.c_str(),
                                     static_cast<INTERNET_PORT>(m_port), 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return result; }

    std::wstring wpath(path, path + strlen(path));
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", wpath.c_str(),
                                        nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return result; }

    if (m_tolerate_self_signed) {
        DWORD opts = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &opts, sizeof(opts));
    }

    std::wstring hdrs;
    for (const auto &h : extra_headers) {
        hdrs += h;
        hdrs += L"\r\n";
    }
    LPCWSTR hdr_ptr = hdrs.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdrs.c_str();

    BOOL sent = WinHttpSendRequest(hReq, hdr_ptr,
                                   hdrs.empty() ? 0 : static_cast<DWORD>(-1L),
                                   const_cast<LPVOID>(static_cast<LPCVOID>(body.data())),
                                   static_cast<DWORD>(body.size()),
                                   static_cast<DWORD>(body.size()), 0);
    if (sent && WinHttpReceiveResponse(hReq, nullptr)) {
        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, nullptr);
        if (http_status_out) *http_status_out = static_cast<int>(status);

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            std::vector<BYTE> chunk(avail);
            DWORD read = 0;
            if (!WinHttpReadData(hReq, chunk.data(), avail, &read) || read == 0) break;
            result.insert(result.end(), chunk.begin(), chunk.begin() + read);
        }
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return result;
}

bool AnonClient::sendSealed(const RoutingContext &ctx,
                            const BYTE *inner, DWORD inner_len,
                            int expires_in_seconds) {
    BYTE sealed[PAD_BUCKET];
    DWORD sealedLen = 0;
    memset(sealed, 0, sizeof(sealed));
    if (!anon_seal(inner, inner_len, ctx.peer_pub, sealed, &sealedLen)) {
        return false;
    }
    if (sealedLen > PAD_BUCKET) return false;
    // Trailing bytes already zero from memset above (padding).

    uint64_t pid = anon_pair_id(ctx.my_pub, ctx.peer_pub);
    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    uint64_t epoch = anon_epoch_for(now);

    BYTE tag[SHROUD_ROUTING_TAG_LEN];
    if (!anon_routing_tag(ctx.shared_root, pid, epoch, tag)) return false;
    std::string tagHex = toHex(tag, SHROUD_ROUTING_TAG_LEN);

    std::vector<std::wstring> headers = {
        L"Content-Type: application/octet-stream",
        L"X-Envelope-Version: 2",
        std::wstring(L"X-Routing-Tag: ") +
            std::wstring(tagHex.begin(), tagHex.end()),
    };
    if (expires_in_seconds > 0) {
        wchar_t buf[64];
        swprintf(buf, 64, L"X-Expires-In: %d", expires_in_seconds);
        headers.push_back(buf);
    }

    std::vector<BYTE> body(sealed, sealed + PAD_BUCKET);
    int status = 0;
    httpPost("/api/v1/messages/send-anon", body, headers, &status);
    return status == 200;
}

bool AnonClient::fetchMessages(const BYTE my_priv[32], const BYTE my_pub[32],
                               const std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE>>> &contacts,
                               std::vector<IncomingAnon> &out) {
    if (contacts.empty()) return true;

    // Build tag list across {prev, current, next} epochs for every contact.
    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    uint64_t base = anon_epoch_for(now);

    std::set<std::string> seen;
    std::vector<std::string> tagsHex;
    for (const auto &c : contacts) {
        const auto &peer_pub = c.first;
        const auto &shared_root = c.second;
        if (peer_pub.size() != 32 || shared_root.size() != 32) continue;
        uint64_t pid = anon_pair_id(my_pub, peer_pub.data());
        for (int de = -1; de <= 1; ++de) {
            uint64_t e = base + static_cast<uint64_t>(static_cast<int64_t>(de));
            BYTE tag[SHROUD_ROUTING_TAG_LEN];
            if (!anon_routing_tag(shared_root.data(), pid, e, tag)) continue;
            std::string h = toHex(tag, SHROUD_ROUTING_TAG_LEN);
            if (seen.insert(h).second) tagsHex.push_back(h);
        }
    }
    if (tagsHex.empty()) return true;

    // Build JSON body: {"tags": ["hex1", "hex2", ...]}
    std::ostringstream js;
    js << "{\"tags\":[";
    for (size_t i = 0; i < tagsHex.size(); ++i) {
        if (i) js << ",";
        js << "\"" << tagsHex[i] << "\"";
    }
    js << "]}";
    std::string jsonStr = js.str();
    std::vector<BYTE> body(jsonStr.begin(), jsonStr.end());

    std::vector<std::wstring> headers = {
        L"Content-Type: application/json",
    };
    int status = 0;
    auto resp = httpPost("/api/v1/messages/fetch-anon", body, headers, &status);
    if (status != 200) return false;

    // Minimal JSON walk: find "messages":[ ... ] and extract each sealed/ts.
    // We avoid pulling in a JSON parser for this single use; for anything
    // more involved, link nlohmann/json or rapidjson.
    std::string respStr(resp.begin(), resp.end());
    size_t mPos = respStr.find("\"messages\"");
    if (mPos == std::string::npos) return true;
    size_t openBr = respStr.find('[', mPos);
    if (openBr == std::string::npos) return true;
    size_t cursor = openBr + 1;
    while (cursor < respStr.size()) {
        // Find the next "sealed" field
        size_t sPos = respStr.find("\"sealed\"", cursor);
        if (sPos == std::string::npos) break;
        size_t colon = respStr.find(':', sPos);
        if (colon == std::string::npos) break;
        size_t q1 = respStr.find('"', colon + 1);
        if (q1 == std::string::npos) break;
        size_t q2 = respStr.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        std::string sealedHex = respStr.substr(q1 + 1, q2 - q1 - 1);

        // Optional "ts" field for this message (find the same object's ts)
        std::string tsStr;
        size_t tsPos = respStr.find("\"ts\"", q2);
        size_t objClose = respStr.find('}', q2);
        if (tsPos != std::string::npos && (objClose == std::string::npos || tsPos < objClose)) {
            size_t tsColon = respStr.find(':', tsPos);
            size_t tq1 = respStr.find('"', tsColon + 1);
            size_t tq2 = respStr.find('"', tq1 + 1);
            if (tq1 != std::string::npos && tq2 != std::string::npos && tq1 < objClose) {
                tsStr = respStr.substr(tq1 + 1, tq2 - tq1 - 1);
            }
        }

        // Unseal with walk-forward trim — matches python_sdk + iOS.
        auto sealedBytes = fromHex(sealedHex);
        if (!sealedBytes.empty()) {
            int len = static_cast<int>(sealedBytes.size());
            while (len > 0 && sealedBytes[len - 1] == 0) len--;
            int maxLen = (len + 32 < static_cast<int>(sealedBytes.size()))
                         ? (len + 32) : static_cast<int>(sealedBytes.size());
            for (int tail = len; tail <= maxLen; ++tail) {
                BYTE plain[PAD_BUCKET];
                DWORD plainLen = 0;
                if (anon_unseal(sealedBytes.data(),
                                static_cast<DWORD>(tail),
                                my_priv, my_pub,
                                plain, &plainLen)) {
                    IncomingAnon msg;
                    msg.server_ts = tsStr;
                    msg.plaintext.assign(plain, plain + plainLen);
                    out.push_back(std::move(msg));
                    break;
                }
            }
        }

        cursor = q2 + 1;
    }
    return true;
}

} // namespace shroud
