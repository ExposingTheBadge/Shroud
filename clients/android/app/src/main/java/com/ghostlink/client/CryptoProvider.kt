package com.ghostlink.client

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ── Hex extension functions (package-level) ────────────────────────
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** FIPS 140-2 compliant crypto via Android Keystore */
object CryptoProvider {

    private const val KEYSTORE = "AndroidKeyStore"
    private const val IDENTITY_ALIAS = "ghostlink_identity_p384"
    private const val AES_KEY_LEN = 32

    // ── ECDH P-384 Identity Keypair ────────────────────────────────
    fun generateIdentityKey(): KeyPair {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        kpg.initialize(
            KeyGenParameterSpec.Builder(IDENTITY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_AGREE_KEY)
                .setKeySize(384)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
        return kpg.generateKeyPair()
    }

    fun getIdentityKey(): KeyPair? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(IDENTITY_ALIAS)) return null
        val entry = ks.getEntry(IDENTITY_ALIAS, null) as KeyStore.PrivateKeyEntry
        return KeyPair(entry.certificate.publicKey, entry.privateKey)
    }

    fun exportPublicKey(keyPair: KeyPair): ByteArray =
        keyPair.public.encoded

    fun importPublicKey(data: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePublic(java.security.spec.X509EncodedKeySpec(data))
    }

    // ── ECDH Shared Secret → AES-256 via HKDF-SHA256 ───────────────
    fun deriveSessionKey(myPrivate: PrivateKey, peerPublic: PublicKey): SecretKey {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(myPrivate)
        ka.doPhase(peerPublic, true)
        val shared = ka.generateSecret()
        val hkdf = Mac.getInstance("HmacSHA256")
        hkdf.init(SecretKeySpec("GHOSTLINK-ECDH-v1".toByteArray(), "HmacSHA256"))
        val prk = hkdf.doFinal(shared)
        return SecretKeySpec(prk.copyOf(AES_KEY_LEN), "AES")
    }

    // ── AES-256-GCM ────────────────────────────────────────────────
    fun encryptAESGCM(key: SecretKey, plaintext: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ct = cipher.doFinal(plaintext)
        val tag = ct.copyOfRange(ct.size - 16, ct.size)
        val ciphertext = ct.copyOfRange(0, ct.size - 16)
        return Triple(iv, ciphertext, tag)
    }

    fun decryptAESGCM(key: SecretKey, iv: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val combined = ciphertext + tag
        return cipher.doFinal(combined)
    }

    // ── HMAC-SHA256 ────────────────────────────────────────────────
    fun hmacSign(key: SecretKey, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        return mac.doFinal(data)
    }
}
