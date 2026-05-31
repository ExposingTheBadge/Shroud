import CryptoKit
import Foundation

/// FIPS 140-2 compliant crypto operations using Apple CryptoKit (FIPS validated on A12+)
struct ShroudCrypto {

    // MARK: - ECDH P-384 Key Exchange
    static func generateIdentityKey() -> P384.KeyAgreement.PrivateKey {
        P384.KeyAgreement.PrivateKey()
    }

    static func deriveSessionKey(myPrivate: P384.KeyAgreement.PrivateKey,
                                 peerPublic: P384.KeyAgreement.PublicKey) throws -> SymmetricKey {
        let sharedSecret = try myPrivate.sharedSecretFromKeyAgreement(
            with: .init(rawRepresentation: peerPublic.rawRepresentation)
        )
        // HKDF-SHA256 to derive AES-256 key
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: "SHROUD-ECDH-v1".data(using: .utf8)!,
            outputByteCount: 32
        )
    }

    // MARK: - AES-256-GCM
    static func encryptAESGCM(key: SymmetricKey, plaintext: String) throws -> (nonce: Data, ciphertext: Data, tag: Data) {
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext.data(using: .utf8)!, using: key, nonce: nonce)
        return (Data(nonce), sealed.ciphertext, sealed.tag)
    }

    static func decryptAESGCM(key: SymmetricKey, nonce: Data, ciphertext: Data, tag: Data) throws -> String {
        let sealed = try AES.GCM.SealedBox(nonce: .init(data: nonce), ciphertext: ciphertext, tag: tag)
        let data = try AES.GCM.open(sealed, using: key)
        return String(data: data, encoding: .utf8) ?? ""
    }

    // MARK: - HMAC-SHA256
    static func hmacSign(key: SymmetricKey, data: Data) -> Data {
        let code = HMAC<SHA256>.authenticationCode(for: data, using: key)
        return Data(code)
    }

    static func hmacVerify(key: SymmetricKey, data: Data, signature: Data) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(signature, authenticating: data, using: key)
    }

    // MARK: - Random
    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }

    // MARK: - Message Seal/Open
    static func sealMessage(key: SymmetricKey, body: String, senderID: String) throws -> MessageEnvelope {
        let ts = Int64(Date().timeIntervalSince1970)
        let payload = try JSONEncoder().encode(MessagePayload(sender: senderID, ts: ts, body: body))
        let encrypted = try encryptAESGCM(key: key, plaintext: String(data: payload, encoding: .utf8)!)
        let cipherData = encrypted.ciphertext
        let sig = hmacSign(key: key, data: cipherData)
        return MessageEnvelope(
            sender: senderID, ts: ts,
            nonce: encrypted.nonce.hexEncoded,
            ciphertext: encrypted.ciphertext.hexEncoded,
            sig: sig.hexEncoded
        )
    }

    static func openMessage(key: SymmetricKey, envelope: MessageEnvelope) throws -> MessagePayload {
        let nonce = Data(hexEncoded: envelope.nonce)!
        let ciphertext = Data(hexEncoded: envelope.ciphertext)!
        let sig = Data(hexEncoded: envelope.sig)!

        guard hmacVerify(key: key, data: ciphertext, signature: sig) else {
            throw ShroudError.integrityCheckFailed
        }

        let plaintext = try decryptAESGCM(key: key, nonce: nonce, ciphertext: ciphertext, tag: Data()) // tag embedded
        return try JSONDecoder().decode(MessagePayload.self, from: plaintext.data(using: .utf8)!)
    }
}

struct MessagePayload: Codable {
    let sender: String
    let ts: Int64
    let body: String
}

// MARK: - Hex Encoding
extension Data {
    var hexEncoded: String { map { String(format: "%02x", $0) }.joined() }
    init?(hexEncoded: String) {
        let len = hexEncoded.count / 2
        var data = Data(capacity: len)
        var index = hexEncoded.startIndex
        for _ in 0..<len {
            let nextIndex = hexEncoded.index(index, offsetBy: 2)
            guard let b = UInt8(hexEncoded[index..<nextIndex], radix: 16) else { return nil }
            data.append(b)
            index = nextIndex
        }
        self = data
    }
}
