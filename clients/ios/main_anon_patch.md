# iOS client: wireup to anonymous routing endpoints

Documented patch (review before applying) that turns the legacy
`POST /api/v1/messages/send` path in the iOS `NetworkClient.swift`
into a Rule 1+2 compliant `POST /api/v1/messages/send-anon` path
backed by `AnonRouting.swift`.

## Patch

### 1. Feature flag in user defaults

```swift
extension UserDefaults {
    var useAnonRouting: Bool {
        get { object(forKey: "useAnonRouting") as? Bool ?? true }
        set { set(newValue, forKey: "useAnonRouting") }
    }
}
```

### 2. Routing-tag helper

Add to `NetworkClient.swift`:

```swift
struct RoutingContext {
    let myIdPriv: Data
    let myIdPub: Data
    let peerIdPub: Data
    let sharedRoot: Data
}

extension NetworkClient {
    func routingTag(_ ctx: RoutingContext,
                    epoch: UInt64? = nil) -> Data {
        let e = epoch ?? AnonRouting.epochFor()
        let pid = AnonRouting.pairId(myId: ctx.myIdPub, theirId: ctx.peerIdPub)
        return AnonRouting.routingTag(sharedRoot: ctx.sharedRoot,
                                       pair: pid, epoch: e)
    }
}
```

### 3. Send via `/messages/send-anon`

```swift
extension NetworkClient {
    func sendSealedAnon(
        ctx: RoutingContext,
        innerEnvelopeJson: Data,
        expiresInSeconds: Int? = nil
    ) async throws {
        let sealed = try AnonRouting.seal(
            payload: innerEnvelopeJson,
            recipientPub: ctx.peerIdPub
        )
        let buckets: [Int] = [4096, 65536, 1048576, 16777216]
        guard let target = buckets.first(where: { $0 >= sealed.count }) else {
            throw NSError(domain: "shroud.send", code: 0)
        }
        var padded = sealed
        padded.append(Data(repeating: 0, count: target - sealed.count))

        let tag = routingTag(ctx)
        let tagHex = tag.map { String(format: "%02x", $0) }.joined()

        var req = URLRequest(url: URL(string: "\(relayBaseURL)/api/v1/messages/send-anon")!)
        req.httpMethod = "POST"
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.setValue(tagHex, forHTTPHeaderField: "X-Routing-Tag")
        req.setValue("2", forHTTPHeaderField: "X-Envelope-Version")
        if let secs = expiresInSeconds {
            req.setValue(String(secs), forHTTPHeaderField: "X-Expires-In")
        }

        let (_, resp) = try await URLSession.shared.upload(for: req, from: padded)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw NSError(domain: "shroud.send", code: 1)
        }
    }
}
```

### 4. Fetch via `/messages/fetch-anon`

```swift
struct IncomingMessage {
    let serverTs: String
    let plaintext: Data
}

extension NetworkClient {
    func fetchMessagesAnon(
        myIdPriv: Data, myIdPub: Data,
        contacts: [(peerPub: Data, sharedRoot: Data)]
    ) async throws -> [IncomingMessage] {
        let pairs = contacts.map { (
            AnonRouting.pairId(myId: myIdPub, theirId: $0.peerPub),
            $0.sharedRoot
        ) }
        let tags = AnonRouting.fetchTagsForWindow(pairs: pairs)
        let tagsHex = tags.map { tag in
            tag.map { String(format: "%02x", $0) }.joined()
        }

        var req = URLRequest(url: URL(string: "\(relayBaseURL)/api/v1/messages/fetch-anon")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = try JSONSerialization.data(withJSONObject: ["tags": tagsHex])
        let (data, _) = try await URLSession.shared.upload(for: req, from: body)
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        let msgs = obj["messages"] as? [[String: Any]] ?? []

        var out: [IncomingMessage] = []
        for m in msgs {
            guard let sealedHex = m["sealed"] as? String else { continue }
            let sealedBytes = Data(stride(from: 0, to: sealedHex.count, by: 2).compactMap {
                UInt8(sealedHex[sealedHex.index(sealedHex.startIndex, offsetBy: $0)...].prefix(2), radix: 16)
            })
            // Strip trailing zeros and try unseal across a small tail window.
            var len = sealedBytes.count
            while len > 0 && sealedBytes[sealedBytes.startIndex + len - 1] == 0 {
                len -= 1
            }
            for tail in len...(min(len + 32, sealedBytes.count)) {
                do {
                    let plain = try AnonRouting.unseal(
                        sealedBytes.subdata(in: sealedBytes.startIndex..<(sealedBytes.startIndex + tail)),
                        myPriv: myIdPriv, myPub: myIdPub
                    )
                    out.append(IncomingMessage(
                        serverTs: (m["ts"] as? String) ?? "",
                        plaintext: plain
                    ))
                    break
                } catch {
                    continue
                }
            }
        }
        return out
    }
}
```

### 5. Dispatch from `MessageListView` / app code

Same pattern as Windows: branch on `UserDefaults.standard.useAnonRouting`
and call either the new `sendSealedAnon` / `fetchMessagesAnon` or the
legacy methods. Parse the decrypted inner JSON envelope the same way
the legacy fetch handler does.

### 6. Build

```bash
cd clients/ios
xcodebuild -scheme Shroud -configuration Release
```

Test against the live AWS relay
`https://44.202.225.57:58443`. Verify the app's outbound traffic
arrives as sealed envelopes addressed to routing tags rather than
plaintext sender_device_id headers.
