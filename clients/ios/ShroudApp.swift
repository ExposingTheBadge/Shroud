import CryptoKit
import SwiftUI

// MARK: - App entry (iOS and macOS share this target's sources)

@main
struct ShroudApp: App {
    @StateObject private var client = ShroudClient()
    @Environment(\.scenePhase) private var phase

    /// Operator diagnostics X25519 pubkey. Anonymous crash reports sealed to
    /// it can only be opened with the operator's offline private key. Rotate
    /// with `python -m tools.diagnostics_inbox keygen`, then replace it here,
    /// in MainActivity.kt and in main.cpp.
    private static let operatorDiagPubkeyHex =
        "7191a786437e38ebe616b9508b3110afb1a635e08ac034a330093acca708fd54"

    init() {
        if let k = Data(hexString: Self.operatorDiagPubkeyHex), k.count == 32, k.contains(where: { $0 != 0 }) {
            ErrorReporter.install(operatorPubkey: k)
        }
    }

    var body: some Scene {
        WindowGroup {
            Group {
                if client.isRegistered {
                    ConversationsView(client: client)
                } else {
                    RegistrationView(client: client)
                }
            }
            .onChange(of: phase) { p in
                // Poll only while the app is in the foreground.
                if p == .active { client.resume() } else { client.pause() }
            }
        }
    }
}

// MARK: - Models

struct ChatMessage: Identifiable, Codable, Equatable {
    var id = UUID().uuidString
    var body: String
    var outgoing: Bool
    var ts: Date = Date()
    var pending = false
    var failed: String?
    var system = false
}

struct FriendRequest: Identifiable, Equatable {
    let id: String
    let from: String
    let reason: String
}

// MARK: - Client state

/// Everything the UI binds to. Mirrors ShroudVM on Android: encrypted
/// sign-in, X25519 ratchet bundle, friends, Double Ratchet messages over the
/// anonymous (sealed-sender, routing-tag) path with the legacy queue as a
/// fallback.
@MainActor
final class ShroudClient: ObservableObject {
    @Published var isRegistered = false
    @Published var deviceID = ""
    @Published var username = ""
    @Published var contacts: [String] = []
    @Published var incomingRequests: [FriendRequest] = []
    @Published var outgoingPending: [String] = []
    @Published var conversations: [String: [ChatMessage]] = [:]
    @Published var unread: [String: Int] = [:]
    @Published var openPeer: String?
    @Published var connection = "Connecting…"
    @Published var connected = false
    @Published var maintenance = false
    @Published var notice: String?
    @Published var disappearSeconds: Int = UserDefaults.standard.integer(forKey: "disappearSeconds") {
        didSet { UserDefaults.standard.set(disappearSeconds, forKey: "disappearSeconds") }
    }
    @Published var useAnonRouting: Bool = UserDefaults.standard.useAnonRouting {
        didSet { UserDefaults.standard.useAnonRouting = useAnonRouting }
    }

    private var identity: P384.KeyAgreement.PrivateKey
    private var peerCache: [String: (at: Date, peer: PeerDevice)] = [:]
    private var pollTask: Task<Void, Never>?
    private let relay = Relay.shared

    struct PeerDevice {
        let deviceId: String
        let publicKeyDer: Data
        let x25519: Data?
    }

    init() {
        identity = ShroudCrypto.loadOrCreateIdentity()
        if let did = KeychainStore.loadString(key: "device_id"),
           let user = KeychainStore.loadString(key: "username") {
            deviceID = did
            username = user
            isRegistered = true
            loadConversations()
            resume()
        }
    }

    // MARK: Sign in / create account

    /// Encrypted sign-in: the password only ever travels inside an
    /// AES-GCM payload keyed by ECDH with a one-time relay key.
    func auth(username raw: String, password: String, deviceName: String, register: Bool) async throws {
        let user = raw.trimmingCharacters(in: .whitespaces).lowercased()
        let kx = try await relay.get("/api/v1/key-exchange")
        guard kx.ok, let sid = kx.json["session_id"] as? String,
              let serverDer = Data(hexString: kx.json["server_public_key"] as? String ?? "") else {
            throw AuthError.message(kx.ok ? "The relay's key exchange was malformed." : kx.detail)
        }
        let myPub = ShroudCrypto.exportPublic(identity).hexEncoded
        let payload: [String: Any] = [
            "username": user, "password": password, "device_name": deviceName,
            "platform": "ios", "register": register, "public_key": myPub,
            // Reuse this device's row on the relay instead of adding one per sign-in.
            "existing_device_id": register ? "" : (KeychainStore.loadString(key: "last_device_id") ?? ""),
        ]
        let key = try ShroudCrypto.authKey(identity, serverPubDer: serverDer)
        let sealed = try ShroudCrypto.seal(key, try JSONSerialization.data(withJSONObject: payload))
        let r = try await relay.post("/api/v1/auth", [
            "session_id": sid, "client_public_key": myPub,
            "nonce": sealed.nonce.hexEncoded, "ciphertext": sealed.ciphertext.hexEncoded,
            "tag": sealed.tag.hexEncoded,
        ])
        guard r.ok, let did = r.json["device_id"] as? String, !did.isEmpty else {
            switch r.status {
            case 401 where !register:
                throw AuthError.message("Wrong username or password. Accounts belong to one relay, so if " +
                                        "you haven't created one on this relay yet, choose Create account.")
            case 409: throw AuthError.message("That username is taken. Pick another.")
            case 429: throw AuthError.message("Too many attempts. Wait a few minutes and try again.")
            default: throw AuthError.message(r.detail)
            }
        }
        // The password is not stored: every later call authenticates with the device id.
        KeychainStore.saveString(key: "device_id", value: did)
        KeychainStore.saveString(key: "last_device_id", value: did)
        KeychainStore.saveString(key: "username", value: user)
        deviceID = did
        username = user
        isRegistered = true
        await publishRatchetBundle()
        loadConversations()
        resume()
    }

    enum AuthError: LocalizedError {
        case message(String)
        var errorDescription: String? { if case .message(let m) = self { return m }; return nil }
    }

    func signOut() {
        pause()
        KeychainStore.delete(key: "device_id")
        KeychainStore.delete(key: "username")
        RatchetSession.wipe()
        try? FileManager.default.removeItem(at: Self.conversationsURL)
        conversations = [:]; contacts = []; incomingRequests = []; outgoingPending = []
        peerCache = [:]; openPeer = nil; isRegistered = false; deviceID = ""; username = ""
    }

    private func publishRatchetBundle() async {
        guard let body = RatchetSession.createBundleIfNeeded(deviceId: deviceID) else { return }
        _ = try? await relay.post("/api/v1/ratchet/publish-key", body)
    }

    // MARK: Polling

    func resume() {
        guard isRegistered, pollTask == nil else { return }
        pollTask = Task { [weak self] in
            var beat = 0
            while !Task.isCancelled {
                guard let self else { return }
                await self.tick(beat)
                beat += 1
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
        }
    }

    func pause() {
        pollTask?.cancel()
        pollTask = nil
    }

    private func tick(_ beat: Int) async {
        do {
            let r = try await relay.post("/api/v1/heartbeat", ["device_id": deviceID])
            maintenance = r.json["maintenance_mode"] as? Bool ?? false
            if r.status == 404 || r.status == 401 {
                connection = "This device is no longer signed in. Sign in again."
                connected = false
                return
            }
            connected = r.ok
            connection = maintenance ? "The relay is in maintenance. Sending is paused."
                                     : (r.ok ? "Connected" : "Connecting…")
            if beat == 0 { await publishRatchetBundle() }
            if beat % 8 == 0 { await refreshContacts() }
            await fetchMessages()
        } catch {
            connected = false
            connection = Relay.describe(error)
        }
    }

    // MARK: Contacts

    func refreshContacts() async {
        guard let r = try? await relay.post("/api/v1/friends/list", ["device_id": deviceID]), r.ok else { return }
        contacts = ((r.json["friends"] as? [[String: Any]]) ?? []).compactMap { $0["username"] as? String }
            .filter { !$0.isEmpty }.sorted()
        incomingRequests = ((r.json["incoming"] as? [[String: Any]]) ?? []).compactMap {
            guard let id = $0["id"] as? String, let from = $0["from"] as? String else { return nil }
            return FriendRequest(id: id, from: from, reason: $0["reason"] as? String ?? "")
        }
        outgoingPending = ((r.json["outgoing"] as? [[String: Any]]) ?? [])
            .filter { ($0["status"] as? String) == "pending" }
            .compactMap { $0["to"] as? String }
    }

    /// Returns nil on success, or a reason to show.
    func addContact(_ name: String) async -> String? {
        let target = name.trimmingCharacters(in: .whitespaces).lowercased()
        guard !target.isEmpty, target != username else { return "Enter someone else's username." }
        do {
            let r = try await relay.post("/api/v1/friends/request", ["device_id": deviceID, "target_username": target])
            if r.ok { await refreshContacts(); return nil }
            switch r.status {
            case 404: return "There's no one called \(target) on this relay."
            case 409: return r.detail
            default: return r.detail
            }
        } catch { return Relay.describe(error) }
    }

    func respond(_ req: FriendRequest, accept: Bool) async {
        _ = try? await relay.post("/api/v1/friends/respond",
                                  ["device_id": deviceID, "request_id": req.id, "accept": accept])
        await refreshContacts()
    }

    /// The contact's most recently active device and its keys. Cached for five minutes.
    private func resolvePeer(_ name: String, refresh: Bool = false) async -> PeerDevice? {
        if !refresh, let hit = peerCache[name], Date().timeIntervalSince(hit.at) < 300 { return hit.peer }
        guard let r = try? await relay.post("/api/v1/contacts/devices",
                                            ["device_id": deviceID, "contact_username": name]), r.ok,
              let d = (r.json["devices"] as? [[String: Any]])?.first,
              let id = d["id"] as? String else { return nil }
        let peer = PeerDevice(deviceId: id,
                              publicKeyDer: Data(hexString: d["public_key"] as? String ?? "") ?? Data(),
                              x25519: await relay.fetchIdentity(id))
        peerCache[name] = (Date(), peer)
        return peer
    }

    private var deviceOwners: [String: (at: Date, ids: Set<String>)] = [:]

    /// True when `did` is one of `name`'s devices on the relay. Cached for five minutes.
    private func device(_ did: String, belongsTo name: String) async -> Bool {
        if let hit = deviceOwners[name], Date().timeIntervalSince(hit.at) < 300, hit.ids.contains(did) { return true }
        guard let r = try? await relay.post("/api/v1/contacts/devices",
                                            ["device_id": deviceID, "contact_username": name]), r.ok else { return false }
        let ids = Set(((r.json["devices"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String })
        deviceOwners[name] = (Date(), ids)
        return ids.contains(did)
    }

    /// Which contact owns this device, if any.
    private func owner(of did: String) async -> String? {
        for c in contacts {
            if await device(did, belongsTo: c) { return c }
        }
        return nil
    }

    func safetyNumber(for name: String) async -> String? {
        guard let me = RatchetSession.loadMyIdentity(), let theirs = await resolvePeer(name)?.x25519 else { return nil }
        return SafetyNumber.compute(myPub: me.pub, theirPub: theirs)
    }

    // MARK: Conversations

    func open(_ peer: String) {
        openPeer = peer
        unread[peer] = 0
    }

    private func append(_ peer: String, _ m: ChatMessage) {
        conversations[peer, default: []].append(m)
        if !m.outgoing && openPeer != peer { unread[peer, default: 0] += 1 }
        saveConversations()
    }

    private func update(_ peer: String, _ id: String, _ f: (inout ChatMessage) -> Void) {
        guard var list = conversations[peer], let ix = list.firstIndex(where: { $0.id == id }) else { return }
        f(&list[ix])
        conversations[peer] = list
        saveConversations()
    }

    func deleteConversation(_ peer: String) {
        conversations[peer] = nil
        saveConversations()
    }

    private static var conversationsURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("conversations.json")
    }

    private func loadConversations() {
        guard let d = try? Data(contentsOf: Self.conversationsURL),
              let c = try? JSONDecoder().decode([String: [ChatMessage]].self, from: d) else { return }
        conversations = c
    }

    private func saveConversations() {
        guard let d = try? JSONEncoder().encode(conversations) else { return }
        #if os(iOS)
        try? d.write(to: Self.conversationsURL, options: [.atomic, .completeFileProtection])
        #else
        try? d.write(to: Self.conversationsURL, options: [.atomic])
        #endif
    }

    // MARK: Send

    func send(_ text: String, to peer: String) {
        let body = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty else { return }
        let m = ChatMessage(body: body, outgoing: true, pending: true)
        append(peer, m)
        deliver(m, to: peer)
    }

    func retry(_ m: ChatMessage, to peer: String) {
        update(peer, m.id) { $0.pending = true; $0.failed = nil }
        deliver(m, to: peer)
    }

    private func deliver(_ m: ChatMessage, to peer: String) {
        Task {
            let err: String?
            do { err = try await deliverText(m.body, to: peer) } catch { err = Relay.describe(error) }
            update(peer, m.id) { $0.pending = false; $0.failed = err }
        }
    }

    /// Encrypt and post one text message. nil on success, otherwise a reason.
    private func deliverText(_ body: String, to peer: String) async throws -> String? {
        guard let pd = await resolvePeer(peer) else { return "\(peer) hasn't signed in on any device yet." }
        let now = Int(Date().timeIntervalSince1970)
        let inner = try JSONSerialization.data(withJSONObject: [
            "body": body, "name": username, "sender": deviceID, "ts": now,
        ])

        let env: [String: Any]
        if let ratchetHex = await RatchetSession.encryptForPeer(pd.deviceId, inner) {
            let sig = Data(SHA256.hash(data: Data(hexString: ratchetHex) ?? Data())).hexEncoded
            env = ["ratchet": 1, "sender": deviceID, "ts": now,
                   "nonce": String(repeating: "0", count: 24), "ciphertext": ratchetHex,
                   "tag": String(repeating: "0", count: 32), "sig": sig]
        } else {
            guard !pd.publicKeyDer.isEmpty else { return "\(peer)'s device has no public key on the relay." }
            let sk = try ShroudCrypto.staticSessionKey(identity, peerPubDer: pd.publicKeyDer)
            let s = try ShroudCrypto.seal(sk, inner)
            env = ["sender": deviceID, "ts": now, "nonce": s.nonce.hexEncoded,
                   "ciphertext": s.ciphertext.hexEncoded, "tag": s.tag.hexEncoded,
                   "sig": ShroudCrypto.hmac(sk, s.ciphertext).hexEncoded]
        }
        let envData = try JSONSerialization.data(withJSONObject: env)
        let expires = disappearSeconds > 0 ? disappearSeconds : nil

        if useAnonRouting, let me = RatchetSession.loadMyIdentity(), let theirX = pd.x25519 {
            let root = try Ratchet.x25519Dh(me.priv, theirX)
            do {
                try await NetworkClientAnon.sendSealedAnon(
                    relayBaseURL: relay.baseURL,
                    ctx: RoutingContext(myIdPriv: me.priv, myIdPub: me.pub, peerIdPub: theirX, sharedRoot: root),
                    innerEnvelopeJson: envData, expiresInSeconds: expires)
                return nil
            } catch NetworkClientAnonError.badResponse(let code) {
                if code == 503 { maintenance = true; return "the relay is in maintenance." }
                return "the relay refused the message (error \(code))."
            }
        }

        var headers: [String: String] = [:]
        if let e = expires { headers["X-Expires-In"] = String(e) }
        let r = try await relay.post("/api/v1/messages/send", [
            "sender_device_id": deviceID, "recipient_device_id": pd.deviceId,
            "envelope": String(data: envData, encoding: .utf8) ?? "",
        ], headers: headers)
        if r.status == 503 { maintenance = true; return "the relay is in maintenance." }
        return r.ok ? nil : r.detail
    }

    // MARK: Receive

    private func fetchMessages() async {
        var incoming: [(sender: String, env: [String: Any])] = []

        if useAnonRouting, let me = RatchetSession.loadMyIdentity(), !contacts.isEmpty {
            var peers: [(peerPub: Data, sharedRoot: Data)] = []
            for c in contacts {
                if let x = await resolvePeer(c)?.x25519, let root = try? Ratchet.x25519Dh(me.priv, x) {
                    peers.append((x, root))
                }
            }
            if let got = try? await NetworkClientAnon.fetchMessagesAnon(
                relayBaseURL: relay.baseURL, myIdPriv: me.priv, myIdPub: me.pub, contacts: peers) {
                for m in got {
                    guard let outer = (try? JSONSerialization.jsonObject(with: m.plaintext)) as? [String: Any] else { continue }
                    // Windows seals {"envelope": env, "ts"}; Android and iOS seal the envelope itself.
                    let env = outer["envelope"] as? [String: Any] ?? outer
                    incoming.append((env["sender"] as? String ?? "", env))
                }
            }
        }

        if let r = try? await relay.post("/api/v1/messages/fetch", ["device_id": deviceID]), r.ok {
            for m in (r.json["messages"] as? [[String: Any]]) ?? [] {
                var env: [String: Any]?
                if let e = m["envelope"] as? [String: Any] { env = e }
                else if let s = m["envelope"] as? String {
                    env = (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [String: Any]
                }
                guard let e = env else { continue }
                incoming.append(((m["sender_device_id"] as? String) ?? (e["sender"] as? String ?? ""), e))
            }
        }

        for (sender, env) in incoming where !sender.isEmpty {
            await handle(sender: sender, env: env)
        }
    }

    private func handle(sender: String, env: [String: Any]) async {
        var plain: Data?
        if (env["ratchet"] as? Int) == 1, let hex = env["ciphertext"] as? String {
            plain = await RatchetSession.decryptFromPeer(sender, hex)
        } else if let n = Data(hexString: env["nonce"] as? String ?? ""),
                  let c = Data(hexString: env["ciphertext"] as? String ?? ""),
                  let t = Data(hexString: env["tag"] as? String ?? ""),
                  let pk = try? await relay.post("/api/v1/devices/\(sender)/pubkey", [:]),
                  let der = Data(hexString: pk.json["public_key"] as? String ?? ""),
                  let sk = try? ShroudCrypto.staticSessionKey(identity, peerPubDer: der) {
            plain = try? ShroudCrypto.open(sk, nonce: n, ciphertext: c, tag: t)
        }
        guard let p = plain, let obj = (try? JSONSerialization.jsonObject(with: p)) as? [String: Any] else {
            notice = "A message arrived that couldn't be decrypted."
            return
        }
        // The name inside the message is chosen by the sender, so it is only
        // trusted when the sending device really belongs to that account.
        // Otherwise anyone could write "alice" and land in Alice's chat.
        let name = (obj["name"] as? String ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        let peer: String
        let isFile = !(obj["file_id"] as? String ?? "").isEmpty
        if isFile {
            peer = await owner(of: sender) ?? "device \(sender.prefix(8))"
        } else if !name.isEmpty, await device(sender, belongsTo: name) {
            peer = name
        } else {
            peer = name.isEmpty ? "device \(sender.prefix(8))" : "\(name) (unverified)"
        }
        let ts = (obj["ts"] as? Double).map { Date(timeIntervalSince1970: $0) } ?? Date()
        if (obj["is_image"] as? Bool) == true || (obj["type"] as? String) == "image" {
            append(peer, ChatMessage(body: "\(peer) sent an image. Images aren't supported on iOS yet.",
                                     outgoing: false, ts: ts, system: true))
        } else if let body = obj["body"] as? String, !body.isEmpty {
            let gid = obj["group_id"] as? String ?? ""
            append(peer, ChatMessage(body: gid.isEmpty ? body : "[group] \(body)", outgoing: false, ts: ts))
        }
    }
}
