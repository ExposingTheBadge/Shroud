//
//  NetworkClientAnon.swift
//  SHROUD — iOS Rule 1+2 compliant transport.
//
//  Sends sealed envelopes to /api/v1/messages/send-anon addressed to
//  per-pair routing tags, and polls /api/v1/messages/fetch-anon for
//  incoming sealed envelopes addressed to the local user's routing
//  tags. Wraps AnonRouting.swift for the crypto, mirroring the Python
//  python_sdk and Android NetworkClient.kt implementations.
//

import Foundation

public struct IncomingAnonMessage {
    public let serverTs: String
    public let plaintext: Data
}

public enum NetworkClientAnonError: Error {
    case payloadTooLarge
    case noBucketAvailable
    case badResponse(Int)
    case malformedResponse
}

public struct RoutingContext {
    public let myIdPriv: Data
    public let myIdPub:  Data
    public let peerIdPub: Data
    public let sharedRoot: Data

    public init(myIdPriv: Data, myIdPub: Data, peerIdPub: Data, sharedRoot: Data) {
        self.myIdPriv = myIdPriv
        self.myIdPub  = myIdPub
        self.peerIdPub = peerIdPub
        self.sharedRoot = sharedRoot
    }
}

public struct NetworkClientAnon {

    // Matches python_sdk's PAD_BUCKETS.
    public static let padBuckets: [Int] = [4096, 65536, 1048576, 16777216]

    private static func hex(_ d: Data) -> String {
        return d.map { String(format: "%02x", $0) }.joined()
    }

    private static func hexDecode(_ s: String) -> Data? {
        guard s.count % 2 == 0 else { return nil }
        var out = Data(capacity: s.count / 2)
        var index = s.startIndex
        while index < s.endIndex {
            let next = s.index(index, offsetBy: 2)
            guard let byte = UInt8(s[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }

    private static func routingTag(_ ctx: RoutingContext, epoch: UInt64? = nil) -> Data {
        let e = epoch ?? AnonRouting.epochFor()
        let pid = AnonRouting.pairId(myId: ctx.myIdPub, theirId: ctx.peerIdPub)
        return AnonRouting.routingTag(sharedRoot: ctx.sharedRoot, pair: pid, epoch: e)
    }

    /// Seal `innerEnvelopeJson` for the peer, pad to the smallest covering
    /// bucket, and POST to `/api/v1/messages/send-anon`. Rule 1+2 compliant.
    public static func sendSealedAnon(
        relayBaseURL: String,
        ctx: RoutingContext,
        innerEnvelopeJson: Data,
        expiresInSeconds: Int? = nil
    ) async throws {
        let sealed = try AnonRouting.seal(payload: innerEnvelopeJson, recipientPub: ctx.peerIdPub)
        guard let target = padBuckets.first(where: { $0 >= sealed.count }) else {
            throw NetworkClientAnonError.noBucketAvailable
        }
        var padded = sealed
        padded.append(Data(repeating: 0, count: target - sealed.count))

        let tag = routingTag(ctx)
        var req = URLRequest(url: URL(string: "\(relayBaseURL)/api/v1/messages/send-anon")!)
        req.httpMethod = "POST"
        req.timeoutInterval = 30
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.setValue(hex(tag), forHTTPHeaderField: "X-Routing-Tag")
        req.setValue("2", forHTTPHeaderField: "X-Envelope-Version")
        if let secs = expiresInSeconds, secs > 0 {
            req.setValue(String(secs), forHTTPHeaderField: "X-Expires-In")
        }

        let (_, resp) = try await URLSession.shared.upload(for: req, from: padded)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
        guard code == 200 else { throw NetworkClientAnonError.badResponse(code) }
    }

    /// Poll `/api/v1/messages/fetch-anon` for every routing tag across the
    /// {prev, current, next} epoch window for each contact, decrypt the
    /// sealed envelopes, and return plaintext bodies.
    public static func fetchMessagesAnon(
        relayBaseURL: String,
        myIdPriv: Data,
        myIdPub: Data,
        contacts: [(peerPub: Data, sharedRoot: Data)]
    ) async throws -> [IncomingAnonMessage] {
        if contacts.isEmpty { return [] }

        let pairs: [(UInt64, Data)] = contacts.map { c in
            (AnonRouting.pairId(myId: myIdPub, theirId: c.peerPub), c.sharedRoot)
        }
        let tags = AnonRouting.fetchTagsForWindow(pairs: pairs)
        let tagsHex = tags.map { hex($0) }

        var req = URLRequest(url: URL(string: "\(relayBaseURL)/api/v1/messages/fetch-anon")!)
        req.httpMethod = "POST"
        req.timeoutInterval = 30
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = try JSONSerialization.data(withJSONObject: ["tags": tagsHex])

        let (data, resp) = try await URLSession.shared.upload(for: req, from: body)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
        guard code == 200 else { throw NetworkClientAnonError.badResponse(code) }

        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let msgs = root["messages"] as? [[String: Any]] else {
            throw NetworkClientAnonError.malformedResponse
        }

        var out: [IncomingAnonMessage] = []
        for m in msgs {
            guard let sealedHex = m["sealed"] as? String,
                  let sealedBytes = hexDecode(sealedHex) else { continue }

            // Strip trailing zero padding, then walk-forward up to 32 bytes
            // to land on the legitimate sealed envelope tail (sealed seal
            // bytes can themselves end in 0x00).
            var len = sealedBytes.count
            while len > 0 && sealedBytes[sealedBytes.startIndex + len - 1] == 0 {
                len -= 1
            }
            let maxLen = min(len + 32, sealedBytes.count)
            var recovered: Data? = nil
            if maxLen >= len {
                for tail in len...maxLen {
                    let slice = sealedBytes.subdata(
                        in: sealedBytes.startIndex..<(sealedBytes.startIndex + tail)
                    )
                    if let pt = try? AnonRouting.unseal(slice, myPriv: myIdPriv, myPub: myIdPub) {
                        recovered = pt
                        break
                    }
                }
            }
            if let plain = recovered {
                let ts = (m["ts"] as? String) ?? ""
                out.append(IncomingAnonMessage(serverTs: ts, plaintext: plain))
            }
        }
        return out
    }
}

// MARK: - UserDefaults feature flag

public extension UserDefaults {
    /// Rule 1+2 path on by default for new installs.
    var useAnonRouting: Bool {
        get { (object(forKey: "useAnonRouting") as? Bool) ?? true }
        set { set(newValue, forKey: "useAnonRouting") }
    }
}
