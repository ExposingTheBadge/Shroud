package com.ghostlink.client

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * GHOSTLINK Double Ratchet — Kotlin port.
 *
 * Mirrors crypto/double_ratchet.py and clients/windows/ratchet.c. The
 * wire format is byte-exact across all three implementations:
 *
 *     magic    4B  le  0x32325244 ('DR22')
 *     dh_pub   32B      sender's current X25519 public
 *     pn       4B  le
 *     n        4B  le
 *     nonce    12B
 *     ct       var      AES-256-GCM ciphertext + 16-byte tag
 *
 * Forward + future secrecy: every send rotates the sending chain; every
 * receive after a peer DH rotation rotates the root.
 *
 * Requires Android API 26+ for the XDH key agreement (already the project's minSdk).
 */
object Ratchet {
    const val MAGIC: Int = 0x32325244
    const val X25519_LEN = 32
    const val KEY_LEN = 32
    const val NONCE_LEN = 12
    const val TAG_LEN = 16
    const val HEADER_LEN = 4 + X25519_LEN + 4 + 4
    const val MAX_SKIP = 256

    private val INFO_RK = "GHOSTLINK-DR-RK".toByteArray()
    private val rng = SecureRandom()

    data class SkippedKey(val dhrPub: ByteArray, val n: Int, val mk: ByteArray)

    class State {
        var rk: ByteArray = ByteArray(KEY_LEN)
        var cks: ByteArray? = null
        var ckr: ByteArray? = null
        var dhsPriv: ByteArray = ByteArray(X25519_LEN)
        var dhsPub: ByteArray = ByteArray(X25519_LEN)
        var dhrPub: ByteArray? = null
        var ns: Int = 0
        var nr: Int = 0
        var pn: Int = 0
        val skipped: MutableList<SkippedKey> = mutableListOf()
    }

    // ── X25519 ───────────────────────────────────────────────────────
    fun x25519Keygen(): Pair<ByteArray, ByteArray> {
        val kpg = KeyPairGenerator.getInstance("XDH")
        kpg.initialize(java.security.spec.NamedParameterSpec("X25519"))
        val kp: KeyPair = kpg.generateKeyPair()
        val pubEnc = kp.public.encoded     // X.509 wrap — extract last 32 bytes
        val privEnc = kp.private.encoded   // PKCS#8 wrap
        val pub = pubEnc.copyOfRange(pubEnc.size - X25519_LEN, pubEnc.size)
        // Round-trip the priv via PKCS#8 so DH below can rebuild it; for
        // ratchet state we store the raw scalar by stripping the wrapper.
        // PKCS#8 X25519 = 16-byte ASN.1 prefix + 32 bytes private key.
        val priv = privEnc.copyOfRange(privEnc.size - X25519_LEN, privEnc.size)
        return priv to pub
    }

    fun x25519Dh(priv: ByteArray, pub: ByteArray): ByteArray {
        // Reconstruct PKCS#8 and X.509 wrappers so JCA can consume the raw bytes.
        val privDer = byteArrayOf(
            0x30, 0x2e, 0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x04, 0x22, 0x04, 0x20,
        ) + priv
        val pubDer = byteArrayOf(
            0x30, 0x2a,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x03, 0x21, 0x00,
        ) + pub
        val kf = KeyFactory.getInstance("XDH")
        val privKey = kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(privDer))
        val pubKey = kf.generatePublic(java.security.spec.X509EncodedKeySpec(pubDer))
        val ka = javax.crypto.KeyAgreement.getInstance("XDH")
        ka.init(privKey)
        ka.doPhase(pubKey, true)
        return ka.generateSecret()
    }

    // ── HMAC + HKDF ──────────────────────────────────────────────────
    private fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }

    internal fun hkdfSha512(salt: ByteArray, ikm: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        val s = if (salt.isEmpty()) ByteArray(64) else salt
        val prk = hmacSha512(s, ikm)
        val out = ByteArray(outLen)
        var t = ByteArray(0)
        var off = 0
        var counter: Byte = 1
        while (off < outLen) {
            val input = t + info + byteArrayOf(counter)
            t = hmacSha512(prk, input)
            val copy = minOf(64, outLen - off)
            System.arraycopy(t, 0, out, off, copy)
            off += copy
            counter++
        }
        return out
    }

    private fun kdfRk(rk: ByteArray, dh: ByteArray): Pair<ByteArray, ByteArray> {
        val out = hkdfSha512(rk, dh, INFO_RK, 64)
        return out.copyOfRange(0, 32) to out.copyOfRange(32, 64)
    }

    private fun kdfCk(ck: ByteArray): Pair<ByteArray, ByteArray> {
        val mk = hmacSha512(ck, byteArrayOf(1)).copyOfRange(0, 32)
        val newCk = hmacSha512(ck, byteArrayOf(2)).copyOfRange(0, 32)
        return newCk to mk
    }

    // ── AES-256-GCM ──────────────────────────────────────────────────
    private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(pt)
    }

    private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ctTag: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(ctTag)
    }

    // ── Initialization ───────────────────────────────────────────────
    fun initAlice(sharedSecret: ByteArray, bobPub: ByteArray): State {
        require(sharedSecret.size == KEY_LEN)
        require(bobPub.size == X25519_LEN)
        val (priv, pub) = x25519Keygen()
        val dh = x25519Dh(priv, bobPub)
        val (rk, cks) = kdfRk(sharedSecret, dh)
        return State().apply {
            this.rk = rk; this.cks = cks
            this.dhsPriv = priv; this.dhsPub = pub
            this.dhrPub = bobPub
        }
    }

    fun initBob(sharedSecret: ByteArray, myPriv: ByteArray, myPub: ByteArray): State {
        require(sharedSecret.size == KEY_LEN)
        return State().apply {
            this.rk = sharedSecret.copyOf()
            this.dhsPriv = myPriv.copyOf()
            this.dhsPub = myPub.copyOf()
        }
    }

    // ── Send / Receive ───────────────────────────────────────────────
    fun encrypt(st: State, plain: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        val cks = st.cks ?: error("No sending chain — cannot send")
        val (newCks, mk) = kdfCk(cks)
        st.cks = newCks
        val nonce = ByteArray(NONCE_LEN).also { rng.nextBytes(it) }

        val header = ByteBuffer.allocate(HEADER_LEN).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(MAGIC).put(st.dhsPub).putInt(st.pn).putInt(st.ns).array()
        val fullAad = header + aad
        val ct = aesGcmEncrypt(mk, nonce, fullAad, plain)
        st.ns += 1
        return header + nonce + ct
    }

    private fun skipMessageKeys(st: State, until: Int) {
        if (st.ckr == null) return
        require(st.nr + MAX_SKIP >= until) { "Too many skipped messages" }
        while (st.nr < until) {
            val (newCkr, mk) = kdfCk(st.ckr!!)
            st.ckr = newCkr
            st.skipped += SkippedKey(st.dhrPub!!.copyOf(), st.nr, mk)
            st.nr += 1
        }
    }

    private fun dhRatchetStep(st: State, newDhrPub: ByteArray) {
        st.pn = st.ns; st.ns = 0; st.nr = 0; st.dhrPub = newDhrPub
        val dh1 = x25519Dh(st.dhsPriv, newDhrPub)
        val (rk1, ckr) = kdfRk(st.rk, dh1)
        st.rk = rk1; st.ckr = ckr
        val (priv, pub) = x25519Keygen(); st.dhsPriv = priv; st.dhsPub = pub
        val dh2 = x25519Dh(priv, newDhrPub)
        val (rk2, cks) = kdfRk(st.rk, dh2)
        st.rk = rk2; st.cks = cks
    }

    fun decrypt(st: State, envelope: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(envelope.size >= HEADER_LEN + NONCE_LEN + TAG_LEN) { "Envelope too short" }
        val bb = ByteBuffer.wrap(envelope).order(ByteOrder.LITTLE_ENDIAN)
        val magic = bb.int
        require(magic == MAGIC) { "Bad magic 0x${Integer.toHexString(magic)}" }
        val dhPub = ByteArray(X25519_LEN); bb.get(dhPub)
        val pn = bb.int; val n = bb.int
        val nonce = ByteArray(NONCE_LEN); bb.get(nonce)
        val ct = envelope.copyOfRange(HEADER_LEN + NONCE_LEN, envelope.size)
        val header = envelope.copyOfRange(0, HEADER_LEN)
        val fullAad = header + aad

        // Skipped-key cache
        val skIx = st.skipped.indexOfFirst { it.n == n && it.dhrPub.contentEquals(dhPub) }
        if (skIx >= 0) {
            val sk = st.skipped.removeAt(skIx)
            return aesGcmDecrypt(sk.mk, nonce, fullAad, ct)
        }

        if (st.dhrPub == null || !st.dhrPub.contentEquals(dhPub)) {
            if (st.ckr != null) skipMessageKeys(st, pn)
            dhRatchetStep(st, dhPub)
        }
        skipMessageKeys(st, n)

        val (newCkr, mk) = kdfCk(st.ckr!!)
        st.ckr = newCkr
        st.nr += 1
        return aesGcmDecrypt(mk, nonce, fullAad, ct)
    }
}

private fun ByteArray?.contentEquals(other: ByteArray): Boolean =
    this != null && this.size == other.size && this.indices.all { this[it] == other[it] }

/**
 * Safety number for out-of-band verification (Signal-style).
 *
 * Both sides compute SHA-512(version || sorted(a, b)) over the two
 * X25519 identity pubkeys, take 30 bytes, and emit 6 groups of 5
 * decimal digits. Users compare in person, on a phone call, etc. to
 * defeat MITM — same number on both ends means no impersonation.
 */
object SafetyNumber {
    fun compute(myPub: ByteArray, theirPub: ByteArray): String {
        require(myPub.size == 32 && theirPub.size == 32)
        val (a, b) = if (lessOrEqual(myPub, theirPub)) myPub to theirPub else theirPub to myPub
        val md = java.security.MessageDigest.getInstance("SHA-512")
        md.update(1)        // protocol version
        md.update(a)
        md.update(b)
        val digest = md.digest()
        val sb = StringBuilder()
        for (g in 0 until 6) {
            var v = 0L
            for (i in 0 until 5) v = (v shl 8) or (digest[g * 5 + i].toLong() and 0xff)
            if (g > 0) sb.append(' ')
            sb.append("%05d".format(v % 100_000L))
        }
        return sb.toString()
    }

    private fun lessOrEqual(a: ByteArray, b: ByteArray): Boolean {
        for (i in a.indices) {
            val ai = a[i].toInt() and 0xff
            val bi = b[i].toInt() and 0xff
            if (ai < bi) return true
            if (ai > bi) return false
        }
        return true
    }
}
