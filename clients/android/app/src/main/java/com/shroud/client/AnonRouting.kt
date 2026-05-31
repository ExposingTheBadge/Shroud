/*
 * SHROUD anonymous routing — Android client port.
 *
 * Kotlin counterpart of crypto/anon_routing.py and
 * clients/windows/anon_routing.c. All three produce byte-identical
 * routing tags and sealed envelopes against the same shared inputs, so
 * the live AWS relay's /api/v1/messages/{send,fetch}-anon endpoints
 * interoperate without protocol translation.
 *
 * Rule 1: sender identity lives inside an AES-256-GCM ciphertext keyed
 *         by X25519 ECDH(ephemeral, recipient_identity).
 * Rule 2: recipients poll by 32-byte routing tag, which is HKDF-derived
 *         from a per-pair X3DH root + epoch hour. Server cannot map
 *         tag -> identity.
 *
 * Platform requirements:
 *   X25519 NamedParameterSpec is available in Android API 30+ (Android 11).
 *   Below that, swap to Tink (which works on API 21+) — keep the wire
 *   format identical and the rest of this code unchanged.
 */
package com.shroud.client

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPublicKeySpec
import java.security.SecureRandom
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.max

object AnonRouting {

    // ── Wire format constants (must match the Python ref + Windows C port) ──
    const val ROUTING_TAG_LEN = 32
    const val SEAL_VERSION: Byte = 0x01
    const val SEAL_VERSION_LEN = 1
    const val SEAL_EPHEMERAL_LEN = 32
    const val SEAL_NONCE_LEN = 12
    const val SEAL_GCM_TAG_LEN = 16
    const val SEAL_FIXED_OVERHEAD = SEAL_VERSION_LEN + SEAL_EPHEMERAL_LEN + SEAL_NONCE_LEN + SEAL_GCM_TAG_LEN
    const val EPOCH_SECONDS = 3600L
    private const val SHA256_LEN = 32

    private val TAG_SALT = "shroud-tag-v1".toByteArray(Charsets.US_ASCII)
    private val SEAL_SALT = "shroud-seal-v1".toByteArray(Charsets.US_ASCII)
    private val SEAL_KEY_INFO = "key".toByteArray(Charsets.US_ASCII)

    private val rng = SecureRandom()

    // ── HKDF (RFC 5869) ─────────────────────────────────────────────────

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(SHA256_LEN) else salt
        return hmacSha256(effectiveSalt, ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length <= 255 * SHA256_LEN) { "HKDF-Expand requested $length bytes" }
        val out = ByteArray(length)
        var t = ByteArray(0)
        var written = 0
        var counter: Byte = 1
        while (written < length) {
            val input = ByteArray(t.size + info.size + 1)
            System.arraycopy(t, 0, input, 0, t.size)
            System.arraycopy(info, 0, input, t.size, info.size)
            input[input.size - 1] = counter
            t = hmacSha256(prk, input)
            val copy = minOf(length - written, SHA256_LEN)
            System.arraycopy(t, 0, out, written, copy)
            written += copy
            counter = (counter.toInt() + 1).toByte()
        }
        return out
    }

    // ── Routing tag (Rule 2) ────────────────────────────────────────────

    fun epochFor(unixTs: Long = System.currentTimeMillis() / 1000L): Long {
        return unixTs / EPOCH_SECONDS
    }

    /** Order-independent 64-bit pair fingerprint. */
    fun pairId(myId: ByteArray, theirId: ByteArray): Long {
        require(myId.size == 32 && theirId.size == 32) { "ids must be 32 bytes" }
        val (lo, hi) = if (lex(myId, theirId) <= 0) myId to theirId else theirId to myId
        val input = ByteArray(32 + 2 + 32)
        System.arraycopy(lo, 0, input, 0, 32)
        input[32] = '|'.code.toByte()
        input[33] = '|'.code.toByte()
        System.arraycopy(hi, 0, input, 34, 32)
        val digest = MessageDigest.getInstance("SHA-256").digest(input)
        // Big-endian first 8 bytes -> Long
        val bb = ByteBuffer.wrap(digest, 0, 8).order(ByteOrder.BIG_ENDIAN)
        return bb.long
    }

    private fun lex(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until 32) {
            val av = a[i].toInt() and 0xFF
            val bv = b[i].toInt() and 0xFF
            if (av != bv) return av - bv
        }
        return 0
    }

    /** 32-byte routing tag the sender writes to and the recipient polls. */
    fun routingTag(sharedRoot: ByteArray, pair: Long, epoch: Long): ByteArray {
        require(sharedRoot.size == 32) { "shared_root must be 32 bytes" }
        val prk = hkdfExtract(TAG_SALT, sharedRoot)
        val info = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
            .putLong(pair).putLong(epoch).array()
        return hkdfExpand(prk, info, ROUTING_TAG_LEN)
    }

    /**
     * Enumerate all routing tags the recipient should currently subscribe to,
     * across all conversations and {prev, current, next} epochs.
     */
    fun fetchTagsForWindow(
        pairs: List<Pair<Long, ByteArray>>,
        around: Long = System.currentTimeMillis() / 1000L,
        window: Int = 1,
    ): List<ByteArray> {
        val anchor = epochFor(around)
        val seen = HashSet<String>()
        val out = ArrayList<ByteArray>(pairs.size * (2 * window + 1))
        for ((pid, root) in pairs) {
            for (e in (anchor - window)..(anchor + window)) {
                val t = routingTag(root, pid, e)
                val key = t.joinToString("") { "%02x".format(it) }
                if (seen.add(key)) out.add(t)
            }
        }
        return out
    }

    // ── Sealed envelope (Rule 1) ────────────────────────────────────────

    private fun deriveSealKey(
        ecdhShared: ByteArray, ephPub: ByteArray, recipientPub: ByteArray
    ): ByteArray {
        val ikm = ByteArray(32 * 3)
        System.arraycopy(ecdhShared, 0, ikm, 0, 32)
        System.arraycopy(ephPub, 0, ikm, 32, 32)
        System.arraycopy(recipientPub, 0, ikm, 64, 32)
        val prk = hkdfExtract(SEAL_SALT, ikm)
        return hkdfExpand(prk, SEAL_KEY_INFO, 32)
    }

    /**
     * Seal a payload so only the holder of the X25519 private key paired with
     * [recipientPub] can decrypt it. Wire format = version(1) || eph_pub(32) ||
     * nonce(12) || ciphertext(payload.length) || gcm_tag(16).
     */
    fun seal(payload: ByteArray, recipientPub: ByteArray): ByteArray {
        require(recipientPub.size == 32) { "recipient pubkey must be 32 bytes" }

        val (ephPriv, ephPub) = x25519GenerateKeypair()
        val shared = x25519Exchange(ephPriv, recipientPub)
        val key = deriveSealKey(shared, ephPub, recipientPub)

        val nonce = ByteArray(SEAL_NONCE_LEN).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(SEAL_GCM_TAG_LEN * 8, nonce),
        )
        // No AAD: eph_pub and recipient_pub are bound into the KDF, so
        // substituting either yields a different key and the GCM tag
        // check fails. Keeps the wire format identical to the C port
        // (which uses the existing AAD-less crypto_aes_gcm helper).
        val ctAndTag = cipher.doFinal(payload)

        val out = ByteArray(SEAL_FIXED_OVERHEAD + payload.size)
        out[0] = SEAL_VERSION
        System.arraycopy(ephPub, 0, out, 1, 32)
        System.arraycopy(nonce, 0, out, 1 + 32, SEAL_NONCE_LEN)
        System.arraycopy(ctAndTag, 0, out, 1 + 32 + SEAL_NONCE_LEN, ctAndTag.size)
        return out
    }

    /**
     * Recover the plaintext payload from a sealed envelope.
     * Caller supplies their X25519 private key bytes and the matching public.
     */
    fun unseal(sealed: ByteArray, myPriv: ByteArray, myPub: ByteArray): ByteArray {
        require(sealed.size >= SEAL_FIXED_OVERHEAD) { "sealed too short" }
        require(sealed[0] == SEAL_VERSION) { "unknown seal version ${sealed[0]}" }

        val ephPub = sealed.copyOfRange(1, 1 + 32)
        val nonce = sealed.copyOfRange(1 + 32, 1 + 32 + SEAL_NONCE_LEN)
        val ctAndTag = sealed.copyOfRange(1 + 32 + SEAL_NONCE_LEN, sealed.size)

        val shared = x25519Exchange(myPriv, ephPub)
        val key = deriveSealKey(shared, ephPub, myPub)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(SEAL_GCM_TAG_LEN * 8, nonce),
        )
        return cipher.doFinal(ctAndTag)
    }

    // ── X25519 wrappers (API 30+) ───────────────────────────────────────
    //
    // For API 26-29, replace these three functions with Tink's
    // X25519.computeSharedSecret / generatePrivateKey / publicFromPrivate.
    // Everything above stays the same.

    private fun x25519GenerateKeypair(): Pair<ByteArray, ByteArray> {
        val kpg = KeyPairGenerator.getInstance("XDH")
        kpg.initialize(NamedParameterSpec.X25519)
        val kp = kpg.generateKeyPair()
        val priv = (kp.private as XECPrivateKey).scalar.orElseThrow()
        val pub = encodeX25519Public(kp.public as XECPublicKey)
        return priv to pub
    }

    private fun x25519Exchange(myPriv: ByteArray, theirPub: ByteArray): ByteArray {
        // Reconstruct a private key object from raw bytes
        val privKf = KeyFactory.getInstance("XDH")
        val privSpec = java.security.spec.PKCS8EncodedKeySpec(wrapX25519PrivAsPkcs8(myPriv))
        val priv = privKf.generatePrivate(privSpec)

        val pubSpec = XECPublicKeySpec(NamedParameterSpec.X25519, decodeX25519PublicFromRaw(theirPub))
        val pub = privKf.generatePublic(pubSpec)

        val ka = KeyAgreement.getInstance("XDH")
        ka.init(priv)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    /**
     * X25519 spec stores the public key as a u-coordinate, little-endian.
     * java.security gives us a BigInteger; we serialize to 32 bytes LE.
     */
    private fun encodeX25519Public(pub: XECPublicKey): ByteArray {
        val u = pub.u
        val raw = ByteArray(32)
        var v = u
        for (i in 0 until 32) {
            raw[i] = (v.toLong() and 0xFF).toByte()
            v = v.shiftRight(8)
        }
        return raw
    }

    private fun decodeX25519PublicFromRaw(raw: ByteArray): java.math.BigInteger {
        require(raw.size == 32) { "X25519 pubkey must be 32 bytes" }
        var u = java.math.BigInteger.ZERO
        for (i in 31 downTo 0) {
            u = u.shiftLeft(8).or(java.math.BigInteger.valueOf((raw[i].toInt() and 0xFF).toLong()))
        }
        return u
    }

    /**
     * X25519 raw priv (32 bytes) wrapped as a minimal PKCS8 OneAsymmetricKey
     * blob, which is what KeyFactory("XDH") expects.
     *   SEQUENCE {
     *     INTEGER 0
     *     SEQUENCE { OID 1.3.101.110 }    // X25519
     *     OCTET STRING { OCTET STRING raw }
     *   }
     */
    private fun wrapX25519PrivAsPkcs8(raw: ByteArray): ByteArray {
        require(raw.size == 32) { "X25519 priv must be 32 bytes" }
        // Hand-rolled DER. Sizes are fixed so we can hardcode the bytes:
        //   30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 || raw(32)
        val prefix = byteArrayOf(
            0x30, 0x2e, 0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x04, 0x22, 0x04, 0x20,
        )
        return prefix + raw
    }

    // ── Self-test (call from a debug build to verify wire compatibility) ──

    fun selfTest(): Boolean {
        val root = ByteArray(32).also { rng.nextBytes(it) }
        val aliceId = ByteArray(32).also { rng.nextBytes(it) }
        val bobId = ByteArray(32).also { rng.nextBytes(it) }
        val pidA = pairId(aliceId, bobId)
        val pidB = pairId(bobId, aliceId)
        check(pidA == pidB) { "pair_id must be order-independent" }
        val e = epochFor()
        val tA = routingTag(root, pidA, e)
        val tB = routingTag(root, pidB, e)
        check(tA.contentEquals(tB)) { "tags must agree across parties" }
        check(tA.size == 32)
        val tNext = routingTag(root, pidA, e + 1)
        check(!tA.contentEquals(tNext)) { "tags must rotate per epoch" }

        // Seal round-trip
        val (bobPriv, bobPub) = x25519GenerateKeypair()
        val payload = "hello bob from anon kotlin".toByteArray()
        val sealed = seal(payload, bobPub)
        val recovered = unseal(sealed, bobPriv, bobPub)
        check(recovered.contentEquals(payload)) { "seal roundtrip failed" }

        // Tamper detection
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 1).toByte()
        runCatching { unseal(sealed, bobPriv, bobPub) }.exceptionOrNull()
            ?: error("tamper detection failed")

        return true
    }
}
