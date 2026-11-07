import Foundation

/// Per-peer Double Ratchet sessions with X3DH bootstrap, Swift port of
/// clients/android/.../RatchetSession.kt.
///
/// First message of a session (and every message until the peer replies):
///
///     [4B magic 'X3D1' LE = 0x31443358][32B EK_A pub][4B otp_id LE or 0xFFFFFFFF][DR22 envelope]
///
/// Files live in Application Support/ratchet with complete file protection:
///   identity.x25519            32B priv || 32B pub
///   one_time_prekeys.bin       N * (4B id LE || 32B priv)
///   sessions/peer_<did>.state  JSON Ratchet.State
///   sessions/peer_<did>.x3dh   32B EK_A pub || 4B otp_id (Alice retry crumb)
enum RatchetSession {
    static let x3dhMagic: UInt32 = 0x3144_3358
    static let preambleLen = 4 + 32 + 4
    static let noOtp: UInt32 = 0xFFFF_FFFF
    static let otpBatch = 32

    // MARK: Storage

    static var rootDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("ratchet", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir.appendingPathComponent("sessions"),
                                                 withIntermediateDirectories: true)
        return dir
    }
    private static var identityURL: URL { rootDir.appendingPathComponent("identity.x25519") }
    private static var otpURL: URL { rootDir.appendingPathComponent("one_time_prekeys.bin") }
    private static func safe(_ did: String) -> String {
        String(did.unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) })
    }
    private static func stateURL(_ did: String) -> URL {
        rootDir.appendingPathComponent("sessions/peer_\(safe(did)).state")
    }
    private static func x3dhURL(_ did: String) -> URL {
        rootDir.appendingPathComponent("sessions/peer_\(safe(did)).x3dh")
    }

    private static func write(_ data: Data, to url: URL) -> Bool {
        #if os(iOS)
        let opts: Data.WritingOptions = [.atomic, .completeFileProtection]
        #else
        let opts: Data.WritingOptions = [.atomic]
        #endif
        do { try data.write(to: url, options: opts); return true } catch { return false }
    }

    /// Wipe every ratchet file (sign-out).
    static func wipe() {
        try? FileManager.default.removeItem(at: rootDir)
    }

    // MARK: Identity + one-time prekeys

    static func loadMyIdentity() -> (priv: Data, pub: Data)? {
        guard let b = try? Data(contentsOf: identityURL), b.count >= 64 else { return nil }
        return (b.bytes(0, 32), b.bytes(32, 64))
    }

    /// Create the identity and a prekey batch if none exist yet. Returns the
    /// body for POST /api/v1/ratchet/publish-key, or nil if already published.
    static func createBundleIfNeeded(deviceId: String) -> [String: Any]? {
        if loadMyIdentity() != nil { return nil }
        let (ikPriv, ikPub) = Ratchet.x25519Keygen()
        var otpBlob = Data()
        var otps: [[String: Any]] = []
        for i in 0..<otpBatch {
            let (p, pub) = Ratchet.x25519Keygen()
            otpBlob.appendLE(UInt32(i))
            otpBlob.append(p)
            otps.append(["prekey_id": i, "pub": pub.hexEncoded])
        }
        guard write(ikPriv + ikPub, to: identityURL), write(otpBlob, to: otpURL) else { return nil }
        return ["device_id": deviceId, "x25519_pub": ikPub.hexEncoded, "one_time_prekeys": otps]
    }

    private static func otpEntries() -> [(UInt32, Data)] {
        guard let raw = try? Data(contentsOf: otpURL), !raw.isEmpty, raw.count % 36 == 0 else { return [] }
        return stride(from: 0, to: raw.count, by: 36).map { off in
            (raw.readLE32(at: off), raw.bytes(off + 4, off + 36))
        }
    }

    private static func deleteOtp(_ id: UInt32) {
        var blob = Data()
        for (eid, priv) in otpEntries() where eid != id {
            blob.appendLE(eid)
            blob.append(priv)
        }
        _ = write(blob, to: otpURL)
    }

    // MARK: Peer state

    private static func loadState(_ did: String) -> Ratchet.State? {
        guard let d = try? Data(contentsOf: stateURL(did)) else { return nil }
        return try? JSONDecoder().decode(Ratchet.State.self, from: d)
    }

    private static func saveState(_ did: String, _ st: Ratchet.State) -> Bool {
        guard let d = try? JSONEncoder().encode(st) else { return false }
        return write(d, to: stateURL(did))
    }

    // MARK: Encrypt / decrypt

    /// Hex wire bytes for `plaintext`, or nil when the peer has no ratchet
    /// bundle (the caller then falls back to the static-key envelope).
    static func encryptForPeer(_ did: String, _ plaintext: Data) async -> String? {
        var st = loadState(did)
        var ekPub: Data?
        var otpId = noOtp
        var emitPreamble = false

        if st == nil {
            guard let me = loadMyIdentity(),
                  let bundle = await Relay.shared.fetchBundle(did) else { return nil }
            let (ekPriv, ekPubLocal) = Ratchet.x25519Keygen()
            guard let sk = try? Ratchet.x3dhAlice(myIkPriv: me.priv, myEkPriv: ekPriv,
                                                  peerIkPub: bundle.ik, peerOpkPub: bundle.opk),
                  let s = try? Ratchet.initAlice(sharedSecret: sk, bobPub: bundle.ik) else { return nil }
            st = s
            ekPub = ekPubLocal
            otpId = bundle.opk != nil ? bundle.opkId : noOtp
            var crumb = ekPubLocal
            crumb.appendLE(otpId)
            _ = write(crumb, to: x3dhURL(did))
            emitPreamble = true
        } else if st?.ckr == nil, let crumb = try? Data(contentsOf: x3dhURL(did)), crumb.count == 36 {
            ekPub = crumb.bytes(0, 32)
            otpId = crumb.readLE32(at: 32)
            emitPreamble = true
        }

        guard var state = st else { return nil }
        guard let dr = try? Ratchet.encrypt(&state, plaintext), saveState(did, state) else { return nil }
        if emitPreamble, let ek = ekPub {
            var out = Data()
            out.appendLE(x3dhMagic)
            out.append(ek)
            out.appendLE(otpId)
            out.append(dr)
            return out.hexEncoded
        }
        return dr.hexEncoded
    }

    static func decryptFromPeer(_ did: String, _ hex: String) async -> Data? {
        guard var env = Data(hexString: hex) else { return nil }
        let minSize = Ratchet.headerLen + Ratchet.nonceLen + Ratchet.tagLen
        guard env.count >= minSize else { return nil }

        var peerEk: Data?
        var peerOtp = noOtp
        if env.count >= preambleLen + minSize, env.readLE32(at: 0) == x3dhMagic {
            peerEk = env.bytes(4, 36)
            peerOtp = env.readLE32(at: 36)
            env = env.bytes(preambleLen, env.count)
        }

        var st = loadState(did)
        var usedOtp = false
        var bootstrapped = false
        if st == nil {
            guard let ek = peerEk, let me = loadMyIdentity(),
                  let peerIk = await Relay.shared.fetchIdentity(did) else { return nil }
            var opkPriv: Data?
            if peerOtp != noOtp {
                guard let p = otpEntries().first(where: { $0.0 == peerOtp })?.1 else { return nil }
                opkPriv = p
                usedOtp = true
            }
            guard let sk = try? Ratchet.x3dhBob(myIkPriv: me.priv, myOpkPriv: opkPriv,
                                                peerIkPub: peerIk, peerEkPub: ek) else { return nil }
            st = Ratchet.initBob(sharedSecret: sk, myPriv: me.priv, myPub: me.pub)
            bootstrapped = true
        }

        guard var state = st else { return nil }
        guard let plain = try? Ratchet.decrypt(&state, env) else { return nil }
        let saved = saveState(did, state)
        if saved && bootstrapped && usedOtp { deleteOtp(peerOtp) }
        if saved && state.ckr != nil { try? FileManager.default.removeItem(at: x3dhURL(did)) }
        return plain
    }
}
