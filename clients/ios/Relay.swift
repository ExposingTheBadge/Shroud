import CryptoKit
import Foundation
import Security

/// HTTPS client for the SHROUD relay.
///
/// The relay serves a self-signed certificate. A certificate the system
/// trusts is accepted as normal; otherwise the first certificate seen for a
/// host:port is pinned (SHA-256 of its DER) and any later, different one is
/// refused. Same trust-on-first-use policy as the Android client.
final class Relay: NSObject, URLSessionDelegate {
    static let shared = Relay()

    static let defaultURL = "https://173.245.244.180:58443"

    /// Overridable in Settings so self-hosters can point at their own relay.
    var baseURL: String {
        get { UserDefaults.standard.string(forKey: "relayURL") ?? Relay.defaultURL }
        set { UserDefaults.standard.set(newValue, forKey: "relayURL") }
    }

    /// Set when a pinned certificate no longer matches.
    private(set) var certificateChanged = false

    lazy var session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 30
        cfg.httpCookieStorage = nil
        cfg.urlCache = nil
        return URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }()

    enum RelayError: LocalizedError {
        case badURL, certificateChanged, notJSON
        var errorDescription: String? {
            switch self {
            case .badURL: return "The relay address is not valid."
            case .certificateChanged:
                return "The relay is presenting a different TLS certificate than before. " +
                       "Someone may be intercepting the connection, so SHROUD refused to connect."
            case .notJSON: return "The relay sent a response SHROUD couldn't read."
            }
        }
    }

    // MARK: TLS trust-on-first-use

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        if SecTrustEvaluateWithError(trust, nil) {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let der = SecCertificateCopyData(leaf) as Data
        let fp = Data(SHA256.hash(data: der)).hexEncoded
        let key = "tlspin.\(challenge.protectionSpace.host):\(challenge.protectionSpace.port)"
        let pinned = UserDefaults.standard.string(forKey: key)
        if pinned == nil {
            UserDefaults.standard.set(fp, forKey: key)
        } else if pinned != fp {
            certificateChanged = true
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    /// Forget pinned certificates (Settings, after the operator rotates TLS).
    func clearPins() {
        for k in UserDefaults.standard.dictionaryRepresentation().keys where k.hasPrefix("tlspin.") {
            UserDefaults.standard.removeObject(forKey: k)
        }
        certificateChanged = false
    }

    // MARK: Requests

    struct Response {
        let status: Int
        let json: [String: Any]
        var ok: Bool { (200..<300).contains(status) }
        /// The relay's human-readable error, if any.
        var detail: String {
            if let d = json["detail"] as? String { return d }
            if let d = json["detail"] as? [String: Any] {
                return (d["message"] as? String) ?? (d["title"] as? String) ?? "Error \(status)"
            }
            return "The relay returned error \(status)."
        }
    }

    func request(_ path: String, method: String = "POST", json body: [String: Any]? = nil,
                 raw: Data? = nil, headers: [String: String] = [:]) async throws -> Response {
        guard let url = URL(string: baseURL + path) else { throw RelayError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let b = body {
            req.httpBody = try JSONSerialization.data(withJSONObject: b)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        } else if let r = raw {
            req.httpBody = r
            req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        }
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        do {
            let (data, resp) = try await session.data(for: req)
            let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
            return Response(status: status, json: obj)
        } catch {
            if certificateChanged { throw RelayError.certificateChanged }
            throw error
        }
    }

    func post(_ path: String, _ body: [String: Any], headers: [String: String] = [:]) async throws -> Response {
        try await request(path, json: body, headers: headers)
    }

    func get(_ path: String) async throws -> Response {
        try await request(path, method: "GET")
    }

    /// Readable reason for a thrown network error.
    static func describe(_ error: Error) -> String {
        if let e = error as? LocalizedError, let d = e.errorDescription { return d }
        let ns = error as NSError
        if ns.domain == NSURLErrorDomain {
            switch ns.code {
            case NSURLErrorTimedOut: return "The relay didn't answer in time."
            case NSURLErrorNotConnectedToInternet: return "You're offline."
            case NSURLErrorCannotConnectToHost, NSURLErrorCannotFindHost:
                return "Can't reach the relay. Check the address in Settings."
            default: break
            }
        }
        return ns.localizedDescription
    }

    // MARK: Ratchet keys

    struct Bundle { let ik: Data; let opk: Data?; let opkId: UInt32 }

    /// Consumes one of the peer's one-time prekeys on the relay, so only call
    /// it when starting a new session.
    func fetchBundle(_ did: String) async -> Bundle? {
        guard let r = try? await get("/api/v1/ratchet/bundle/\(did)"), r.ok,
              let ik = Data(hexString: r.json["x25519_pub"] as? String ?? ""), ik.count == 32 else { return nil }
        if let o = r.json["one_time_prekey"] as? [String: Any],
           let pub = Data(hexString: o["pub"] as? String ?? ""), pub.count == 32,
           let id = o["prekey_id"] as? Int, id >= 0 {
            return Bundle(ik: ik, opk: pub, opkId: UInt32(id))
        }
        return Bundle(ik: ik, opk: nil, opkId: RatchetSession.noOtp)
    }

    /// The peer's long-term X25519 identity. Consumes nothing.
    func fetchIdentity(_ did: String) async -> Data? {
        guard let r = try? await get("/api/v1/ratchet/identity/\(did)"), r.ok,
              let k = Data(hexString: r.json["x25519_pub"] as? String ?? ""), k.count == 32 else { return nil }
        return k
    }
}
