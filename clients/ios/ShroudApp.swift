import SwiftUI
import CryptoKit

// MARK: - App Entry
@main
struct ShroudApp: App {
    @StateObject private var client = ShroudClient()

    // Operator diagnostics X25519 pubkey (32 bytes hex).
    // Live operator key. Anonymous error reports sealed with this pubkey
    // land in the operator's diagnostics inbox; only the operator's
    // private key (held offline, never on a relay) can decrypt them.
    // To rotate: regenerate via `python -m tools.diagnostics_inbox keygen`,
    // replace the hex here AND in MainActivity.kt + main.cpp, ship a
    // release, retire the old key file. Future versions will fetch this
    // from a signed operator manifest instead of hardcoding it.
    private let OPERATOR_DIAG_PUBKEY_HEX =
        "7191a786437e38ebe616b9508b3110afb1a635e08ac034a330093acca708fd54"

    // SHA-256 pin of the operator's manifest-signing Ed25519 pubkey.
    // Clients fetch the signed manifest on first launch, verify its
    // signature with the published pubkey, and require
    // SHA-256(pubkey) == this pin before accepting any field
    // (relay URL, diag pubkey, federation roster, sticker CDN).
    // Rotation requires shipping a release with a new pin.
    private let SHROUD_MANIFEST_PIN =
        "2fb11de360a0cf6baa35d6785c3945658ae6d64823041729798a2b689ce00ca0"

    // Default-on Tor preference. The operator manifest (v2+) also
    // publishes prefer_tor_by_default = true. Clients honor it unless
    // the user explicitly disables Tor in Settings. iOS uses
    // OnionBrowser / TorURLSession; if Tor isn't reachable the client
    // falls back to the clearnet endpoint.
    private let PREFER_TOR_DEFAULT = true

    init() {
        // Install the anonymous crash + signal reporter once per app
        // launch. The pubkey is checked for non-zero inside install();
        // if zero, the reporter is wired but submission is a no-op.
        if let opPub = Data(hexString: OPERATOR_DIAG_PUBKEY_HEX),
           opPub.count == 32,
           opPub.contains(where: { $0 != 0 }) {
            ErrorReporter.install(operatorPubkey: opPub)
        }
    }

    var body: some Scene {
        WindowGroup {
            // Probe the relay first so users see a clear "Server
            // unavailable" screen when the relay is down — not a login
            // form they can't actually use.
            switch client.serverReachable {
            case .none:
                ServerCheckingView()
            case .some(false):
                ServerDownView {
                    Task { await client.checkServerHealth() }
                }
            case .some(true):
                if client.isRegistered {
                    MessageListView(client: client)
                } else {
                    RegistrationView(client: client)
                }
            }
        }
    }
}

// MARK: - Server-health screens

struct ServerCheckingView: View {
    var body: some View {
        VStack(spacing: 16) {
            ProgressView()
            Text("Connecting to server...")
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ServerDownView: View {
    let onRetry: () -> Void
    @State private var retrying = false

    var body: some View {
        VStack(spacing: 16) {
            Text("Server unavailable")
                .font(.title2.bold())
                .foregroundColor(.orange)
            Text("SHROUD can't reach the server right now. This is usually temporary — try again in a few minutes. If the problem persists, the operator may be doing scheduled maintenance.")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .padding(.horizontal, 24)
            Button {
                retrying = true
                onRetry()
                // The publisher on `serverReachable` will rebuild this
                // view; reset the local flag after a brief moment so
                // re-tap works if it's still down.
                DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
                    retrying = false
                }
            } label: {
                Text(retrying ? "Checking..." : "Retry")
                    .frame(minWidth: 120)
                    .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .disabled(retrying)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

// Hex helper used by ErrorReporter setup. Kept in this file because
// the existing Data hex helpers (if any) live elsewhere in the iOS app
// target and we want this file self-contained.
extension Data {
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let b = UInt8(String(chars[i...i + 1]), radix: 16) else { return nil }
            bytes.append(b)
        }
        self.init(bytes)
    }
}

// MARK: - Client State
class ShroudClient: ObservableObject {
    @Published var isRegistered = false
    @Published var deviceID = ""
    @Published var username = ""
    @Published var messages: [SecureMessage] = []
    @Published var contacts: [Contact] = []
    @Published var groups: [ChatGroup] = []
    // nil = probe in flight, true = reachable, false = server unavailable.
    // The root WindowGroup switches on this so registration/chat never
    // appears until we've confirmed the relay is up.
    @Published var serverReachable: Bool? = nil

    private var identityKey: P384.KeyAgreement.PrivateKey?
    private var sessionKeys: [String: SymmetricKey] = [:]
    let server = "http://127.0.0.1:58443"

    init() {
        loadOrCreateIdentity()
        Task { await checkServerHealth() }
    }

    @MainActor
    func checkServerHealth() async {
        // Force the publisher to fire so the splash re-appears between
        // retries even when the previous value was already `false`.
        serverReachable = nil
        guard let url = URL(string: "\(server)/health") else {
            serverReachable = false; return
        }
        var req = URLRequest(url: url)
        req.timeoutInterval = 5
        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let s = String(data: data, encoding: .utf8) ?? ""
            serverReachable = s.contains("\"status\":\"ok\"")
        } catch {
            serverReachable = false
        }
    }

    // MARK: - Identity
    private func loadOrCreateIdentity() {
        if let saved = KeychainStore.load(key: "identity_key") {
            identityKey = try? P384.KeyAgreement.PrivateKey(x963Representation: saved)
        }
        if let deviceID = KeychainStore.loadString(key: "device_id") {
            self.deviceID = deviceID
            self.isRegistered = true
        }
    }

    func register(username: String, password: String, deviceName: String, platform: String) async throws {
        // Generate ECDH P-384 identity keypair
        identityKey = P384.KeyAgreement.PrivateKey()
        let pubKey = identityKey!.publicKey.x963Representation

        // Register user
        let userResp = try await NetworkClient.post(
            url: "\(server)/api/v1/register",
            body: ["username": username, "password": password, "device_name": deviceName, "platform": platform, "public_key": pubKey.hexEncoded]
        )

        guard let did = userResp["device_id"] as? String else {
            throw ShroudError.registrationFailed
        }

        // Save securely
        KeychainStore.save(key: "identity_key", data: identityKey!.x963Representation)
        KeychainStore.saveString(key: "device_id", value: did)
        KeychainStore.saveString(key: "username", value: username)

        await MainActor.run {
            self.deviceID = did
            self.username = username
            self.isRegistered = true
        }
    }
}

// MARK: - Secure Message
struct SecureMessage: Identifiable, Codable {
    let id: String
    let senderDeviceID: String
    let envelope: MessageEnvelope
    let serverTS: String
    var decryptedBody: String?
}

struct MessageEnvelope: Codable {
    let sender: String
    let ts: Int64
    let nonce: String
    let ciphertext: String
    let sig: String
}

struct Contact: Identifiable, Codable {
    let id: String
    let username: String
}

struct ChatGroup: Identifiable, Codable {
    let id: String
    let name: String
    let createdAt: String
}

enum ShroudError: Error {
    case registrationFailed
    case encryptionFailed
    case decryptionFailed
    case integrityCheckFailed
}
