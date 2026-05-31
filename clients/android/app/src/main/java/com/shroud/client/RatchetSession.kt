package com.shroud.client

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Per-peer Double Ratchet session manager — Kotlin port of the Windows
 * v2.2.0 ratchetEncryptForPeer / ratchetDecryptFromPeer flow.
 *
 * Wire format on the first message of every session:
 *
 *     [4B  magic 'X3D1' LE = 0x31443358]
 *     [32B EK_A pub]
 *     [4B  otp_id LE, or 0xFFFFFFFF if no OTP was consumed]
 *     [   ...DR22 envelope continues...        ]
 *
 * After Bob replies (state.ckr becomes non-null), Alice drops the preamble
 * and emits a bare DR22 envelope.
 *
 * On-disk state files (all under ctx.filesDir/ratchet):
 *   identity.x25519               — 32B priv || 32B pub   (written by publishRatchetBundle)
 *   one_time_prekeys.bin          — N * (4B id || 32B priv)
 *   sessions/peer_<did>.state     — JSON-serialized Ratchet.State
 *   sessions/peer_<did>.x3dh      — 32B EK_A pub || 4B otp_id  (Alice retry crumb)
 *
 * Maintenance and security:
 *   - On successful first decrypt as Bob, the consumed OTP is deleted
 *     locally to lock in forward secrecy.
 *   - State is persisted BEFORE the OTP is deleted so a write failure
 *     can't orphan our chain.
 */
object RatchetSession {

    const val X3DH_MAGIC: Int = 0x31443358   // 'X3D1' LE
    const val X3DH_PREAMBLE_LEN: Int = 4 + 32 + 4
    const val X3DH_NO_OTP: Int = -1          // 0xFFFFFFFF as Int

    private fun rootDir(ctx: Context): File =
        File(ctx.filesDir, "ratchet").apply { mkdirs() }
    private fun sessionsDir(ctx: Context): File =
        File(rootDir(ctx), "sessions").apply { mkdirs() }
    private fun identityFile(ctx: Context): File =
        File(rootDir(ctx), "identity.x25519")
    private fun otpStoreFile(ctx: Context): File =
        File(rootDir(ctx), "one_time_prekeys.bin")
    private fun statePath(ctx: Context, peerDid: String): File =
        File(sessionsDir(ctx), "peer_${peerDid}.state")
    private fun x3dhSidePath(ctx: Context, peerDid: String): File =
        File(sessionsDir(ctx), "peer_${peerDid}.x3dh")

    // ── Local identity + OTP store ─────────────────────────────────
    /** Returns Pair(priv, pub) or null if the identity hasn't been published yet. */
    fun loadMyIdentity(ctx: Context): Pair<ByteArray, ByteArray>? {
        val f = identityFile(ctx)
        if (!f.exists() || f.length() < 64) return null
        val b = f.readBytes()
        return b.copyOfRange(0, 32) to b.copyOfRange(32, 64)
    }

    private fun otpEntries(ctx: Context): MutableList<Pair<Int, ByteArray>> {
        val f = otpStoreFile(ctx)
        if (!f.exists()) return mutableListOf()
        val raw = f.readBytes()
        val entrySize = 4 + 32
        if (raw.isEmpty() || raw.size % entrySize != 0) return mutableListOf()
        val out = mutableListOf<Pair<Int, ByteArray>>()
        var off = 0
        while (off < raw.size) {
            val id = ByteBuffer.wrap(raw, off, 4).order(ByteOrder.LITTLE_ENDIAN).int
            val priv = raw.copyOfRange(off + 4, off + 4 + 32)
            out += id to priv
            off += entrySize
        }
        return out
    }

    /** Locate the priv key for a given OTP id; null if already consumed. */
    fun lookupOtpPriv(ctx: Context, otpId: Int): ByteArray? =
        otpEntries(ctx).firstOrNull { it.first == otpId }?.second

    /** Remove the OTP from disk. Idempotent. */
    fun deleteOtp(ctx: Context, otpId: Int) {
        val entries = otpEntries(ctx).filter { it.first != otpId }
        if (entries.isEmpty()) {
            otpStoreFile(ctx).writeBytes(ByteArray(0))
            return
        }
        val buf = ByteBuffer.allocate(entries.size * (4 + 32)).order(ByteOrder.LITTLE_ENDIAN)
        for ((id, priv) in entries) { buf.putInt(id); buf.put(priv) }
        otpStoreFile(ctx).writeBytes(buf.array())
    }

    // ── Peer state files ───────────────────────────────────────────
    fun loadPeerState(ctx: Context, peerDid: String): Ratchet.State? {
        val f = statePath(ctx, peerDid)
        if (!f.exists()) return null
        return Ratchet.State.fromBytes(f.readBytes())
    }

    fun savePeerState(ctx: Context, peerDid: String, st: Ratchet.State): Boolean = try {
        statePath(ctx, peerDid).writeBytes(st.toBytes()); true
    } catch (_: Throwable) { false }

    fun loadX3dhSide(ctx: Context, peerDid: String): Pair<ByteArray, Int>? {
        val f = x3dhSidePath(ctx, peerDid)
        if (!f.exists() || f.length() != 36L) return null
        val b = f.readBytes()
        val ek = b.copyOfRange(0, 32)
        val otp = ByteBuffer.wrap(b, 32, 4).order(ByteOrder.LITTLE_ENDIAN).int
        return ek to otp
    }
    fun saveX3dhSide(ctx: Context, peerDid: String, ekPub: ByteArray, otpId: Int) {
        val buf = ByteBuffer.allocate(36).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(ekPub); buf.putInt(otpId)
        x3dhSidePath(ctx, peerDid).writeBytes(buf.array())
    }
    fun deleteX3dhSide(ctx: Context, peerDid: String) {
        x3dhSidePath(ctx, peerDid).delete()
    }

    // ── Peer bundle / identity fetch ───────────────────────────────
    /** Fetch the peer's bundle. Server CONSUMES one of their OTPs atomically,
     *  so this should only be called by the first-message-as-Alice path. */
    data class PeerBundle(val ikPub: ByteArray, val opkPub: ByteArray?, val opkId: Int)

    suspend fun fetchPeerBundle(peerDid: String): PeerBundle? = try {
        val r = NetworkClient.get("/api/v1/ratchet/bundle/$peerDid")
        val ikHex = r.optString("x25519_pub", "")
        if (ikHex.isBlank()) null
        else {
            val ik = ikHex.hexToBytes()
            val otpObj = r.optJSONObject("one_time_prekey")
            if (otpObj == null) PeerBundle(ik, null, X3DH_NO_OTP)
            else {
                val pub = otpObj.optString("pub").hexToBytes()
                val id = otpObj.optInt("prekey_id", X3DH_NO_OTP)
                PeerBundle(ik, pub, id)
            }
        }
    } catch (_: Throwable) { null }

    /** Fetch the peer's long-term X25519 without consuming an OTP.
     *  Used by Bob to find Alice's IK during X3DH bootstrap. */
    suspend fun fetchPeerIdentity(peerDid: String): ByteArray? = try {
        val r = NetworkClient.get("/api/v1/ratchet/identity/$peerDid")
        val hex = r.optString("x25519_pub", "")
        if (hex.isBlank()) null else hex.hexToBytes()
    } catch (_: Throwable) { null }

    // ── Encrypt / Decrypt ──────────────────────────────────────────
    /**
     * Encrypt a plaintext for a peer. On first session-send, runs X3DH
     * as Alice and prepends the X3D1 preamble; re-emits the preamble on
     * every subsequent send until the peer replies (state.ckr != null);
     * after the reply, emits a bare DR22 envelope.
     *
     * Returns hex-encoded wire bytes or null if the peer hasn't
     * published a bundle yet (caller should fall back to legacy path).
     */
    suspend fun encryptForPeer(ctx: Context, peerDid: String, plaintext: ByteArray): String? {
        var st = loadPeerState(ctx, peerDid)
        var bootstrappedNow = false
        var ekPub: ByteArray? = null
        var otpId: Int = X3DH_NO_OTP

        if (st == null) {
            val (myIkPriv, _) = loadMyIdentity(ctx) ?: return null
            val pb = fetchPeerBundle(peerDid) ?: return null
            val (ekPriv, ekPubLocal) = Ratchet.x25519Keygen()
            val sk = Ratchet.x3dhAlice(myIkPriv, ekPriv, pb.ikPub, pb.opkPub)
            st = Ratchet.initAlice(sk, pb.ikPub)
            ekPub = ekPubLocal
            otpId = if (pb.opkPub != null) pb.opkId else X3DH_NO_OTP
            saveX3dhSide(ctx, peerDid, ekPub, otpId)
            bootstrappedNow = true
        }

        // Decide whether to emit the X3DH preamble. Keep doing so until
        // we've received Bob's first reply (st.ckr != null).
        var emitPreamble = bootstrappedNow
        if (!emitPreamble && st.ckr == null) {
            val side = loadX3dhSide(ctx, peerDid)
            if (side != null) {
                ekPub = side.first; otpId = side.second; emitPreamble = true
            }
        }

        val drEnv = Ratchet.encrypt(st, plaintext)
        if (!savePeerState(ctx, peerDid, st)) return null

        val out: ByteArray = if (emitPreamble && ekPub != null) {
            val buf = ByteBuffer.allocate(X3DH_PREAMBLE_LEN + drEnv.size)
                .order(ByteOrder.LITTLE_ENDIAN)
            buf.putInt(X3DH_MAGIC); buf.put(ekPub); buf.putInt(otpId); buf.put(drEnv)
            buf.array()
        } else drEnv

        return out.toHex()
    }

    /**
     * Decrypt a hex-encoded wire envelope from a known peer. Detects an
     * X3DH preamble and bootstraps state as Bob the first time. If state
     * already exists and a preamble came along anyway, the preamble is
     * silently stripped (Alice's retry — we're past it).
     *
     * Returns plaintext bytes, or null on failure (caller should keep the
     * old static-key fallback path available).
     */
    suspend fun decryptFromPeer(ctx: Context, peerDid: String, hex: String): ByteArray? {
        var env = hex.hexToBytes()
        val minSize = Ratchet.HEADER_LEN + Ratchet.NONCE_LEN + Ratchet.TAG_LEN
        if (env.size < minSize) return null

        var peerEkPub: ByteArray? = null
        var peerOtpId: Int = X3DH_NO_OTP
        var hasPreamble = false
        if (env.size >= X3DH_PREAMBLE_LEN + minSize) {
            val bb = ByteBuffer.wrap(env).order(ByteOrder.LITTLE_ENDIAN)
            val magic = bb.int
            if (magic == X3DH_MAGIC) {
                peerEkPub = ByteArray(32); bb.get(peerEkPub)
                peerOtpId = bb.int
                env = env.copyOfRange(X3DH_PREAMBLE_LEN, env.size)
                hasPreamble = true
            }
        }

        var st = loadPeerState(ctx, peerDid)
        var usedOtp = false
        var bootstrappedNow = false

        if (st == null) {
            if (!hasPreamble) return null   // can't bootstrap from a bare DR22
            val (myIkPriv, myIkPub) = loadMyIdentity(ctx) ?: return null
            val peerIkPub = fetchPeerIdentity(peerDid) ?: return null
            var myOpkPriv: ByteArray? = null
            if (peerOtpId != X3DH_NO_OTP) {
                myOpkPriv = lookupOtpPriv(ctx, peerOtpId)
                if (myOpkPriv == null) return null   // already-consumed OPK
                usedOtp = true
            }
            val sk = Ratchet.x3dhBob(myIkPriv, myOpkPriv, peerIkPub, peerEkPub!!)
            st = Ratchet.initBob(sk, myIkPriv, myIkPub)
            bootstrappedNow = true
        }

        val plain = try { Ratchet.decrypt(st, env) } catch (_: Throwable) { return null }

        val saved = savePeerState(ctx, peerDid, st)
        if (saved && bootstrappedNow && usedOtp) deleteOtp(ctx, peerOtpId)

        // If this side was Alice and we just received Bob's first reply,
        // shred the X3DH side-file — no more preambles needed.
        if (saved && st.ckr != null) deleteX3dhSide(ctx, peerDid)

        return plain
    }
}
