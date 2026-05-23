import SwiftUI
import CryptoKit

// MARK: - App Entry
@main
struct GhostlinkApp: App {
    @StateObject private var client = GhostlinkClient()

    var body: some Scene {
        WindowGroup {
            if client.isRegistered {
                MessageListView(client: client)
            } else {
                RegistrationView(client: client)
            }
        }
    }
}

// MARK: - Client State
class GhostlinkClient: ObservableObject {
    @Published var isRegistered = false
    @Published var deviceID = ""
    @Published var username = ""
    @Published var messages: [SecureMessage] = []
    @Published var contacts: [Contact] = []
    @Published var groups: [ChatGroup] = []

    private var identityKey: P384.KeyAgreement.PrivateKey?
    private var sessionKeys: [String: SymmetricKey] = [:]
    let server = "http://127.0.0.1:58443"

    init() {
        loadOrCreateIdentity()
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
            throw GhostlinkError.registrationFailed
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

enum GhostlinkError: Error {
    case registrationFailed
    case encryptionFailed
    case decryptionFailed
    case integrityCheckFailed
}
