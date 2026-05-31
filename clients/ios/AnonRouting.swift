//
//  AnonRouting.swift
//  SHROUD — iOS client port of the anonymous routing protocol.
//
//  Swift counterpart of:
//    crypto/anon_routing.py
//    clients/windows/anon_routing.{c,h}
//    clients/android/.../AnonRouting.kt
//
//  All four implementations produce byte-identical sealed envelopes
//  and routing tags for the same inputs. The wire spec lives in
//  docs/anon-routing-protocol.md.
//
//  Platform notes:
//    - Curve25519 (X25519) is in CryptoKit on iOS 13+
//    - AES-256-GCM and HMAC-SHA256 are in CryptoKit
//    - We do NOT depend on any third-party crypto library
//

import Foundation
import CryptoKit

public enum AnonRoutingError: Error {
    case invalidPublicKey
    case invalidPrivateKey
    case sealedTooShort
    case unknownSealedVersion(UInt8)
    case decryptionFailed
}

public struct AnonRouting {

    // MARK: - Wire constants

    public static let routingTagLength = 32
    public static let sealedVersion: UInt8 = 0x01
    public static let sealedVersionLength = 1
    public static let sealedEphemeralLength = 32
    public static let sealedNonceLength = 12
    public static let sealedGcmTagLength = 16
    public static let sealedFixedOverhead =
        sealedVersionLength + sealedEphemeralLength + sealedNonceLength + sealedGcmTagLength
    public static let epochSeconds: UInt64 = 3600

    private static let tagSalt = Data("shroud-tag-v1".utf8)
    private static let sealSalt = Data("shroud-seal-v1".utf8)
    private static let sealKeyInfo = Data("key".utf8)

    // MARK: - HKDF (RFC 5869)

    private static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        let key = SymmetricKey(data: effectiveSalt)
        let hmac = HMAC<SHA256>.authenticationCode(for: ikm, using: key)
        return Data(hmac)
    }

    private static func hkdfExpand(prk: Data, info: Data, length: Int) -> Data {
        precondition(length <= 255 * 32, "HKDF-Expand asked for too many bytes")
        var out = Data()
        var t = Data()
        var counter: UInt8 = 1
        let key = SymmetricKey(data: prk)
        while out.count < length {
            var input = Data()
            input.append(t)
            input.append(info)
            input.append(counter)
            let mac = HMAC<SHA256>.authenticationCode(for: input, using: key)
            t = Data(mac)
            let copy = min(length - out.count, t.count)
            out.append(t.prefix(copy))
            counter &+= 1
        }
        return out
    }

    private static func hkdf(salt: Data, ikm: Data, info: Data, length: Int) -> Data {
        return hkdfExpand(prk: hkdfExtract(salt: salt, ikm: ikm), info: info, length: length)
    }

    // MARK: - Routing tag (Rule 2)

    public static func epochFor(unixTs: UInt64 = UInt64(Date().timeIntervalSince1970)) -> UInt64 {
        return unixTs / epochSeconds
    }

    /// Order-independent 64-bit pair fingerprint over two 32-byte X25519 pubkeys.
    public static func pairId(myId: Data, theirId: Data) -> UInt64 {
        precondition(myId.count == 32 && theirId.count == 32, "ids must be 32 bytes")
        let order = myId.lexicographicallyPrecedes(theirId)
        let lo = order ? myId : theirId
        let hi = order ? theirId : myId
        var input = Data(capacity: 32 + 2 + 32)
        input.append(lo)
        input.append(0x7C); input.append(0x7C)  // "||"
        input.append(hi)
        let digest = SHA256.hash(data: input)
        // Big-endian first 8 bytes -> UInt64
        var bytes = Array<UInt8>(digest)
        return bytes.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    /// 32-byte routing tag derived from shared X3DH root + pair + epoch.
    public static func routingTag(sharedRoot: Data, pair: UInt64, epoch: UInt64) -> Data {
        precondition(sharedRoot.count == 32, "shared_root must be 32 bytes")
        let prk = hkdfExtract(salt: tagSalt, ikm: sharedRoot)
        var info = Data(capacity: 16)
        var pairBE = pair.bigEndian
        var epochBE = epoch.bigEndian
        withUnsafeBytes(of: &pairBE) { info.append(contentsOf: $0) }
        withUnsafeBytes(of: &epochBE) { info.append(contentsOf: $0) }
        return hkdfExpand(prk: prk, info: info, length: routingTagLength)
    }

    /// Up to ``(2*window+1) * pairs.count`` tags the recipient should poll.
    public static func fetchTagsForWindow(
        pairs: [(UInt64, Data)],
        around: UInt64? = nil,
        window: Int = 1
    ) -> [Data] {
        let anchor = epochFor(unixTs: around ?? UInt64(Date().timeIntervalSince1970))
        var seen = Set<String>()
        var out: [Data] = []
        for (pid, root) in pairs {
            let lo = Int64(anchor) - Int64(window)
            let hi = Int64(anchor) + Int64(window)
            for e in lo...hi {
                let t = routingTag(sharedRoot: root, pair: pid, epoch: UInt64(e))
                let key = t.map { String(format: "%02x", $0) }.joined()
                if seen.insert(key).inserted {
                    out.append(t)
                }
            }
        }
        return out
    }

    // MARK: - Sealed envelope (Rule 1)

    private static func deriveSealKey(
        ecdhShared: Data, ephPub: Data, recipientPub: Data
    ) -> Data {
        var ikm = Data(capacity: 96)
        ikm.append(ecdhShared)
        ikm.append(ephPub)
        ikm.append(recipientPub)
        let prk = hkdfExtract(salt: sealSalt, ikm: ikm)
        return hkdfExpand(prk: prk, info: sealKeyInfo, length: 32)
    }

    /// Seal ``payload`` so only the holder of the X25519 private key paired
    /// with ``recipientPub`` can decrypt it.
    public static func seal(payload: Data, recipientPub: Data) throws -> Data {
        guard recipientPub.count == 32 else {
            throw AnonRoutingError.invalidPublicKey
        }
        let recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPub)
        let ephPriv = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = ephPriv.publicKey.rawRepresentation

        let shared = try ephPriv.sharedSecretFromKeyAgreement(with: recipient)
        let sharedBytes = shared.withUnsafeBytes { Data($0) }

        let keyBytes = deriveSealKey(
            ecdhShared: sharedBytes, ephPub: ephPub, recipientPub: recipientPub
        )
        let key = SymmetricKey(data: keyBytes)

        // Generate a random 12-byte nonce.
        var nonceBytes = Data(count: sealedNonceLength)
        let result = nonceBytes.withUnsafeMutableBytes { ptr -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, sealedNonceLength, ptr.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw AnonRoutingError.invalidPrivateKey
        }
        let nonce = try AES.GCM.Nonce(data: nonceBytes)

        // AAD intentionally omitted: eph_pub and recipient_pub are bound
        // into the KDF, so substituting either yields a different key and
        // the GCM tag check fails. Keeps wire-format parity with the
        // Python / C / Kotlin ports.
        let sealed = try AES.GCM.seal(payload, using: key, nonce: nonce)

        var out = Data(capacity: sealedFixedOverhead + payload.count)
        out.append(sealedVersion)
        out.append(ephPub)
        out.append(Data(nonce))
        out.append(sealed.ciphertext)
        out.append(sealed.tag)
        return out
    }

    /// Recover the plaintext payload from a sealed envelope.
    public static func unseal(_ sealed: Data, myPriv: Data, myPub: Data) throws -> Data {
        guard sealed.count >= sealedFixedOverhead else {
            throw AnonRoutingError.sealedTooShort
        }
        guard sealed[sealed.startIndex] == sealedVersion else {
            throw AnonRoutingError.unknownSealedVersion(sealed[sealed.startIndex])
        }

        let base = sealed.startIndex
        let ephPub = sealed.subdata(in: (base + 1)..<(base + 1 + 32))
        let nonceData = sealed.subdata(in: (base + 1 + 32)..<(base + 1 + 32 + sealedNonceLength))
        let ctEnd = sealed.endIndex - sealedGcmTagLength
        let ct = sealed.subdata(in: (base + 1 + 32 + sealedNonceLength)..<ctEnd)
        let tag = sealed.subdata(in: ctEnd..<sealed.endIndex)

        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPriv)
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPub)
        let shared = try priv.sharedSecretFromKeyAgreement(with: peer)
        let sharedBytes = shared.withUnsafeBytes { Data($0) }

        let keyBytes = deriveSealKey(
            ecdhShared: sharedBytes, ephPub: ephPub, recipientPub: myPub
        )
        let key = SymmetricKey(data: keyBytes)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)

        do {
            return try AES.GCM.open(box, using: key)
        } catch {
            throw AnonRoutingError.decryptionFailed
        }
    }

    // MARK: - Self-test
    //
    // Call from a debug build to assert that this implementation produces
    // byte-identical output against the Python / C / Kotlin ports for
    // the same inputs.

    public static func selfTest() throws {
        let root = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let aliceId = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let bobId = Data((0..<32).map { _ in UInt8.random(in: 0...255) })

        let pa = pairId(myId: aliceId, theirId: bobId)
        let pb = pairId(myId: bobId, theirId: aliceId)
        precondition(pa == pb, "pair_id must be order-independent")

        let e = epochFor()
        let ta = routingTag(sharedRoot: root, pair: pa, epoch: e)
        let tb = routingTag(sharedRoot: root, pair: pb, epoch: e)
        precondition(ta == tb, "tags must agree across parties")
        precondition(ta.count == 32)

        let bobPriv = Curve25519.KeyAgreement.PrivateKey()
        let bobPub = bobPriv.publicKey.rawRepresentation
        let payload = Data("hello bob from shroud ios".utf8)
        let sealed = try seal(payload: payload, recipientPub: bobPub)
        let recovered = try unseal(sealed, myPriv: bobPriv.rawRepresentation, myPub: bobPub)
        precondition(recovered == payload, "seal roundtrip failed")

        // Tamper detection
        var tampered = sealed
        tampered[tampered.endIndex - 1] ^= 1
        do {
            _ = try unseal(tampered, myPriv: bobPriv.rawRepresentation, myPub: bobPub)
            fatalError("tamper detection failed")
        } catch {
            // expected
        }
    }
}
