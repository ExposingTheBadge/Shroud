/*
 * anon_client.{h,cpp} - C++ wrapper around the C anon_routing library.
 *
 * Exposes send-anon / fetch-anon as a clean class, mirroring the iOS
 * NetworkClientAnon and Android sendAnon/fetchAnonForContacts APIs.
 * Drop-in replacement for the legacy /messages/{send,fetch} path once
 * call sites are updated.
 *
 * Uses WinHTTP directly (no Qt dependency in the transport path) so it
 * can be called from any context including the SEH error reporter.
 */
#ifndef SHROUD_ANON_CLIENT_H
#define SHROUD_ANON_CLIENT_H

#include <windows.h>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#include "anon_routing.h"
}
#endif

namespace shroud {

struct RoutingContext {
    BYTE my_priv[32];
    BYTE my_pub[32];
    BYTE peer_pub[32];
    BYTE shared_root[32];
};

struct IncomingAnon {
    std::string server_ts;
    std::vector<BYTE> plaintext;
};

class AnonClient {
public:
    /* Tolerate self-signed relay certs (Rule 0: prod relays use self-
     * signed by default). Disable in environments where the relay has a
     * publicly-trusted cert. */
    explicit AnonClient(const std::wstring &relay_host,
                        int port = 58443,
                        bool tolerate_self_signed = true);

    /* Seal `inner` for `ctx.peer_pub`, pad to 4096-byte bucket, POST to
     * /api/v1/messages/send-anon with X-Routing-Tag. Returns true on
     * HTTP 200. */
    bool sendSealed(const RoutingContext &ctx,
                    const BYTE *inner, DWORD inner_len,
                    int expires_in_seconds = 0);

    /* Poll /api/v1/messages/fetch-anon for every routing tag across the
     * {prev, current, next} epoch window over each contact. Decrypt and
     * append to `out`. Returns true on HTTP 200. */
    bool fetchMessages(const BYTE my_priv[32], const BYTE my_pub[32],
                       const std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE>>> &contacts,
                       std::vector<IncomingAnon> &out);

private:
    std::wstring m_host;
    int          m_port;
    bool         m_tolerate_self_signed;

    std::vector<BYTE> httpPost(const char *path,
                               const std::vector<BYTE> &body,
                               const std::vector<std::wstring> &extra_headers,
                               int *http_status_out);

    static std::string toHex(const BYTE *data, size_t len);
    static std::vector<BYTE> fromHex(const std::string &hex);
};

} // namespace shroud

#endif // SHROUD_ANON_CLIENT_H
