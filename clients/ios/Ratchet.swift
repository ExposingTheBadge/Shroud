import CryptoKit
import Foundation

/// SHROUD Double Ratchet, Swift port.
///
/// Byte-exact with crypto/double_ratchet.py, clients/windows/ratchet.c and
/// clients/android/.../Ratchet.kt:
///
///     magic    4B  le  0x32325244 ('DR22')
///     dh_pub   32B      sender's current X25519 public
///     pn       4B  le
///     n        4B  le
///     nonce    12B
///     ct       var      AES-256-GCM ciphertext + 16-byte tag (AAD = header)
enum Ratchet {
    static let magic: UInt32 = 0x3232_5244
    static let keyLen = 32
    static let nonceLen = 12
    static let tagLen = 16
    static let headerLen = 4 + 32 + 4 + 4
    static let maxSkip: UInt32 = 256

    private static let infoRK = Data("SHROUD-DR-RK".utf8)
    private static let infoX3DH = Data("SHROUD-X3DH-v1".utf8)

    enum RatchetError: Error {
        case noSendingChain, envelopeTooShort, badMagic, tooManySkipped, noReceivingChain, invalidKey
    }

    struct SkippedKey: Codable {
        var dhr: String   // hex
        var n: UInt32
        var mk: String    // hex
    }

    /// Value type on purpose: decrypt works on a copy and only writes it
    /// back once the tag verifies, so a forged message cannot move the state.
    struct State: Codable {
        var v = 1
        var rk: Data
        var cks: Data?
        var ckr: Data?
        var dhsPriv: Data
        var dhsPub: Data
        var dhrPub: Data?
        var ns: UInt32 = 0
        var nr: UInt32 = 0
        var pn: UInt32 = 0
        var skipped: [SkippedKey] = []
    }

    // MARK: X25519

    static func x25519Keygen() -> (priv: Data, pub: Data) {
        let k = Curve25519.KeyAgreement.PrivateKey()
        return (k.rawRepresentation, k.publicKey.rawRepresentation)
    }

    static func x25519Dh(_ priv: Data, _ pub: Data) throws -> Data {
        guard priv.count == 32, pub.count == 32 else { throw RatchetError.invalidKey }
        let k = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv)
        let p = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub)
        let s = try k.sharedSecretFromKeyAgreement(with: p)
        return s.withUnsafeBytes { Data($0) }
    }

    // MARK: HMAC / HKDF (SHA-512)

    static func hmacSha512(_ key: Data, _ data: Data) -> Data {
        Data(HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    static func hkdfSha512(salt: Data, ikm: Data, info: Data, length: Int) -> Data {
        let s = salt.isEmpty ? Data(repeating: 0, count: 64) : salt
        let prk = hmacSha512(s, ikm)
        var out = Data()
        var t = Data()
        var counter: UInt8 = 1
        while out.count < length {
            var input = t
            input.append(info)
            input.append(counter)
            t = hmacSha512(prk, input)
            out.append(t.prefix(length - out.count))
            counter &+= 1
        }
        return out
    }

    private static func kdfRk(_ rk: Data, _ dh: Data) -> (Data, Data) {
        let out = hkdfSha512(salt: rk, ikm: dh, info: infoRK, length: 64)
        return (out.bytes(0, 32), out.bytes(32, 64))
    }

    private static func kdfCk(_ ck: Data) -> (newCk: Data, mk: Data) {
        let mk = hmacSha512(ck, Data([1])).bytes(0, 32)
        let newCk = hmacSha512(ck, Data([2])).bytes(0, 32)
        return (newCk, mk)
    }

    // MARK: X3DH  (SK = HKDF-SHA512(0^64, 0xFF*32 || DH1 || DH2 [|| DH3 || DH4], "SHROUD-X3DH-v1"))

    static func x3dhAlice(myIkPriv: Data, myEkPriv: Data, peerIkPub: Data, peerOpkPub: Data?) throws -> Data {
        var km = Data(repeating: 0xFF, count: 32)
        km.append(try x25519Dh(myIkPriv, peerIkPub))
        km.append(try x25519Dh(myEkPriv, peerIkPub))
        if let opk = peerOpkPub {
            km.append(try x25519Dh(myEkPriv, opk))
            km.append(try x25519Dh(myIkPriv, opk))
        }
        return hkdfSha512(salt: Data(repeating: 0, count: 64), ikm: km, info: infoX3DH, length: 32)
    }

    static func x3dhBob(myIkPriv: Data, myOpkPriv: Data?, peerIkPub: Data, peerEkPub: Data) throws -> Data {
        var km = Data(repeating: 0xFF, count: 32)
        km.append(try x25519Dh(myIkPriv, peerIkPub))
        km.append(try x25519Dh(myIkPriv, peerEkPub))
        if let opk = myOpkPriv {
            km.append(try x25519Dh(opk, peerEkPub))
            km.append(try x25519Dh(opk, peerIkPub))
        }
        return hkdfSha512(salt: Data(repeating: 0, count: 64), ikm: km, info: infoX3DH, length: 32)
    }

    // MARK: Init

    static func initAlice(sharedSecret: Data, bobPub: Data) throws -> State {
        let (priv, pub) = x25519Keygen()
        let (rk, cks) = kdfRk(sharedSecret, try x25519Dh(priv, bobPub))
        return State(rk: rk, cks: cks, ckr: nil, dhsPriv: priv, dhsPub: pub, dhrPub: bobPub)
    }

    static func initBob(sharedSecret: Data, myPriv: Data, myPub: Data) -> State {
        State(rk: sharedSecret, cks: nil, ckr: nil, dhsPriv: myPriv, dhsPub: myPub, dhrPub: nil)
    }

    // MARK: Send / receive

    static func encrypt(_ st: inout State, _ plain: Data, aad: Data = Data()) throws -> Data {
        guard let cks = st.cks else { throw RatchetError.noSendingChain }
        let (newCks, mk) = kdfCk(cks)
        st.cks = newCks
        var header = Data()
        header.appendLE(magic)
        header.append(st.dhsPub)
        header.appendLE(st.pn)
        header.appendLE(st.ns)
        let nonce = Data.random(nonceLen)
        let box = try AES.GCM.seal(plain, using: SymmetricKey(data: mk),
                                   nonce: try AES.GCM.Nonce(data: nonce),
                                   authenticating: header + aad)
        st.ns += 1
        return header + nonce + box.ciphertext + box.tag
    }

    private static func skipMessageKeys(_ st: inout State, until: UInt32) throws {
        guard var ckr = st.ckr, let dhr = st.dhrPub else { return }
        guard UInt64(st.nr) + UInt64(maxSkip) >= UInt64(until) else { throw RatchetError.tooManySkipped }
        while st.nr < until {
            let (newCk, mk) = kdfCk(ckr)
            ckr = newCk
            st.skipped.append(SkippedKey(dhr: dhr.hexEncoded, n: st.nr, mk: mk.hexEncoded))
            st.nr += 1
        }
        st.ckr = ckr
        if st.skipped.count > Int(2 * maxSkip) {
            st.skipped.removeFirst(st.skipped.count - Int(2 * maxSkip))
        }
    }

    private static func dhRatchetStep(_ st: inout State, _ newDhr: Data) throws {
        st.pn = st.ns; st.ns = 0; st.nr = 0; st.dhrPub = newDhr
        let (rk1, ckr) = kdfRk(st.rk, try x25519Dh(st.dhsPriv, newDhr))
        st.rk = rk1; st.ckr = ckr
        let (priv, pub) = x25519Keygen()
        st.dhsPriv = priv; st.dhsPub = pub
        let (rk2, cks) = kdfRk(st.rk, try x25519Dh(priv, newDhr))
        st.rk = rk2; st.cks = cks
    }

    private static func open(_ mk: Data, nonce: Data, aad: Data, ctTag: Data) throws -> Data {
        let ct = ctTag.bytes(0, ctTag.count - tagLen)
        let tag = ctTag.bytes(ctTag.count - tagLen, ctTag.count)
        let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
        return try AES.GCM.open(box, using: SymmetricKey(data: mk), authenticating: aad)
    }

    static func decrypt(_ st: inout State, _ env: Data, aad: Data = Data()) throws -> Data {
        guard env.count >= headerLen + nonceLen + tagLen else { throw RatchetError.envelopeTooShort }
        guard env.readLE32(at: 0) == magic else { throw RatchetError.badMagic }
        let dhPub = env.bytes(4, 36)
        let pn = env.readLE32(at: 36)
        let n = env.readLE32(at: 40)
        let nonce = env.bytes(headerLen, headerLen + nonceLen)
        let ctTag = env.bytes(headerLen + nonceLen, env.count)
        let fullAad = env.bytes(0, headerLen) + aad

        // Skipped key: only remove it once it has actually decrypted.
        let dhHex = dhPub.hexEncoded
        if let ix = st.skipped.firstIndex(where: { $0.n == n && $0.dhr == dhHex }),
           let mk = Data(hexString: st.skipped[ix].mk) {
            let pt = try open(mk, nonce: nonce, aad: fullAad, ctTag: ctTag)
            st.skipped.remove(at: ix)
            return pt
        }

        var w = st
        if w.dhrPub != dhPub {
            if w.ckr != nil { try skipMessageKeys(&w, until: pn) }
            try dhRatchetStep(&w, dhPub)
        }
        try skipMessageKeys(&w, until: n)
        guard let ckr = w.ckr else { throw RatchetError.noReceivingChain }
        let (newCk, mk) = kdfCk(ckr)
        w.ckr = newCk
        w.nr += 1
        let pt = try open(mk, nonce: nonce, aad: fullAad, ctTag: ctTag)
        st = w
        return pt
    }
}

/// Safety number: SHA-512(0x01 || min(a,b) || max(a,b)), first 30 bytes as
/// six groups of five decimal digits. Matches Android and Windows.
enum SafetyNumber {
    static func compute(myPub: Data, theirPub: Data) -> String {
        let (a, b) = myPub.lexicographicallyPrecedes(theirPub) || myPub == theirPub
            ? (myPub, theirPub) : (theirPub, myPub)
        var input = Data([1])
        input.append(a)
        input.append(b)
        let d = Array(SHA512.hash(data: input))
        return (0..<6).map { g -> String in
            var v: UInt64 = 0
            for i in 0..<5 { v = v << 8 | UInt64(d[g * 5 + i]) }
            return String(format: "%05llu", v % 100_000)
        }.joined(separator: " ")
    }
}
