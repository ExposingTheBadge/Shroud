import CryptoKit
import Foundation

/// P-384 identity key, encrypted sign-in, and the static-key fallback
/// envelope. Every formula here matches clients/android/.../CryptoProvider.kt
/// and the sign-in code in MainActivity.auth, byte for byte.
enum ShroudCrypto {

    // MARK: Device identity (P-384), kept in the Keychain

    static func loadOrCreateIdentity() -> P384.KeyAgreement.PrivateKey {
        if let raw = KeychainStore.load(key: "identity_p384"),
           let k = try? P384.KeyAgreement.PrivateKey(rawRepresentation: raw) {
            return k
        }
        let k = P384.KeyAgreement.PrivateKey()
        KeychainStore.save(key: "identity_p384", data: k.rawRepresentation)
        return k
    }

    /// SubjectPublicKeyInfo DER, which is what the relay stores and what
    /// Android/Windows parse.
    static func exportPublic(_ k: P384.KeyAgreement.PrivateKey) -> Data {
        k.publicKey.derRepresentation
    }

    private static func ecdhRaw(_ me: P384.KeyAgreement.PrivateKey, _ peerDer: Data) throws -> Data {
        let peer = try P384.KeyAgreement.PublicKey(derRepresentation: peerDer)
        return try me.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }

    // MARK: Encrypted sign-in

    /// key = SHA-256(SHA-256(ecdh) || "SHROUD-AUTH-v1")
    static func authKey(_ me: P384.KeyAgreement.PrivateKey, serverPubDer: Data) throws -> SymmetricKey {
        let first = Data(SHA256.hash(data: try ecdhRaw(me, serverPubDer)))
        let second = SHA256.hash(data: first + Data("SHROUD-AUTH-v1".utf8))
        return SymmetricKey(data: Data(second))
    }

    // MARK: Static-key envelope (fallback when the peer has no ratchet bundle)

    /// HMAC-SHA256(key = "SHROUD-ECDH-v1", msg = ecdh)[:32], as Android does.
    static func staticSessionKey(_ me: P384.KeyAgreement.PrivateKey, peerPubDer: Data) throws -> SymmetricKey {
        let shared = try ecdhRaw(me, peerPubDer)
        let mac = HMAC<SHA256>.authenticationCode(for: shared,
                                                  using: SymmetricKey(data: Data("SHROUD-ECDH-v1".utf8)))
        return SymmetricKey(data: Data(mac))
    }

    struct Sealed { let nonce: Data; let ciphertext: Data; let tag: Data }

    static func seal(_ key: SymmetricKey, _ plaintext: Data) throws -> Sealed {
        let box = try AES.GCM.seal(plaintext, using: key)
        return Sealed(nonce: Data(box.nonce), ciphertext: box.ciphertext, tag: box.tag)
    }

    static func open(_ key: SymmetricKey, nonce: Data, ciphertext: Data, tag: Data) throws -> Data {
        let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: key)
    }

    static func hmac(_ key: SymmetricKey, _ data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
    }
}
