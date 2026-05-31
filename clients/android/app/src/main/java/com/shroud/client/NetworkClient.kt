package com.shroud.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

object NetworkClient {
    private const val ENC = "2f 3c 3b 23 6e 63 66 7f 7e 77 66 7e 6a 61 62 78 7f 7f 69 79 77 66 6e 79 71 7a 7f 74"
    private val BASE: String by lazy { decode(ENC) }
    private fun decode(hex: String): String {
        val key = "SHROUD"
        val bytes = hex.split(" ").map { it.toInt(16) }.toIntArray()
        for (i in bytes.indices) bytes[i] = bytes[i] xor key[i % key.length].code
        return String(bytes.map { it.toChar() }.toCharArray())
    }
    private const val TIMEOUT = 10_000

    suspend fun post(path: String, body: JSONObject): JSONObject =
        post(path, body, emptyMap())

    /** POST with extra request headers (e.g. X-Expires-In for
     *  disappearing messages). Header names with a single value each. */
    suspend fun post(path: String, body: JSONObject,
                     headers: Map<String, String>): JSONObject = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Connection", "close")
            for ((k, v) in headers) setRequestProperty(k, v)
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
        }
        OutputStreamWriter(conn.outputStream).use { it.write(body.toString()) }

        val status = conn.responseCode
        val response = BufferedReader(InputStreamReader(
            if (status in 200..299) conn.inputStream else conn.errorStream
        )).readText()

        conn.disconnect()
        // Stash the HTTP status so callers can detect 503 maintenance
        // without re-issuing the request. Best-effort — if parsing fails
        // we just return what we have.
        val obj = try { JSONObject(response) } catch (_: Throwable) { JSONObject() }
        obj.put("_status", status)
        obj
    }

    suspend fun get(path: String): JSONObject = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT
        }
        val response = BufferedReader(InputStreamReader(conn.inputStream)).readText()
        conn.disconnect()
        JSONObject(response)
    }

    /** Upload encrypted file bytes via raw POST. Returns JSON response body. */
    suspend fun uploadFile(
        path: String,
        bytes: ByteArray,
        senderId: String,
        recipientId: String,
        metadataJson: String,
    ): JSONObject = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/octet-stream")
            setRequestProperty("X-Device-ID", senderId)
            setRequestProperty("X-Recipient-ID", recipientId)
            setRequestProperty("X-File-Metadata", metadataJson)
            connectTimeout = TIMEOUT
            readTimeout = 30_000
            doOutput = true
            setFixedLengthStreamingMode(bytes.size)
        }
        conn.outputStream.use { it.write(bytes) }
        val resp = BufferedReader(InputStreamReader(
            if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
        )).readText()
        conn.disconnect()
        JSONObject(resp)
    }

    /** POST raw bytes with arbitrary content-type. Used by the multi-device
     *  linking flow to ship an opaque AES-GCM ciphertext through the
     *  server relay. Returns the JSON response body. */
    suspend fun postBytes(path: String, bytes: ByteArray,
                          contentType: String = "application/octet-stream"): JSONObject = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", contentType)
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT
            doOutput = true
            setFixedLengthStreamingMode(bytes.size)
        }
        conn.outputStream.use { it.write(bytes) }
        val resp = BufferedReader(InputStreamReader(
            if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
        )).readText()
        conn.disconnect()
        JSONObject(resp)
    }

    /** GET raw bytes. Returns null on non-2xx (caller can poll). */
    suspend fun getBytes(path: String): ByteArray? = getBytes(path, emptyMap())

    /** GET raw bytes with extra headers. The /api/v1/files/{id} endpoint
     *  requires X-Device-ID so the server can authorize the download. */
    suspend fun getBytes(path: String, headers: Map<String, String>): ByteArray? = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            for ((k, v) in headers) setRequestProperty(k, v)
            connectTimeout = TIMEOUT
            readTimeout = 30_000
        }
        try {
            if (conn.responseCode !in 200..299) return@withContext null
            val data = conn.inputStream.readBytes()
            conn.disconnect()
            data
        } catch (_: Throwable) {
            try { conn.disconnect() } catch (_: Throwable) {}
            null
        }
    }

    /** DELETE a file by id. Server requires X-Device-ID for authorization. */
    suspend fun deleteFile(path: String, deviceId: String): Boolean = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "DELETE"
            setRequestProperty("X-Device-ID", deviceId)
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT
        }
        val ok = conn.responseCode in 200..299
        conn.disconnect()
        ok
    }

    // ── Anonymous routing (Rule 1 + Rule 2 compliant) ────────────────
    //
    // These call the relay's /api/v1/messages/send-anon and
    // /messages/fetch-anon endpoints, sealing payloads via
    // AnonRouting.seal/unseal. The legacy `post("/api/v1/messages/send", ...)`
    // path is still available for backwards compatibility but new code
    // should prefer the anon variants.

    private val PAD_BUCKETS = listOf(4096, 65536, 1048576, 16777216)

    /**
     * POST a sealed envelope to /api/v1/messages/send-anon.
     *
     * @param recipientPubkey 32-byte X25519 identity pubkey of the recipient
     * @param myIdPubkey      32-byte X25519 identity pubkey of the sender
     * @param sharedRoot      32-byte per-pair X3DH root chain key
     * @param innerEnvelope   the bytes to seal (typically a JSON envelope)
     * @param expiresInSeconds optional disappearing-message TTL
     */
    suspend fun sendAnon(
        recipientPubkey: ByteArray,
        myIdPubkey: ByteArray,
        sharedRoot: ByteArray,
        innerEnvelope: ByteArray,
        expiresInSeconds: Int? = null,
    ): JSONObject = withContext(Dispatchers.IO) {
        require(recipientPubkey.size == 32) { "recipientPubkey must be 32 bytes" }
        require(myIdPubkey.size == 32) { "myIdPubkey must be 32 bytes" }
        require(sharedRoot.size == 32) { "sharedRoot must be 32 bytes" }

        val pid = AnonRouting.pairId(myIdPubkey, recipientPubkey)
        val tag = AnonRouting.routingTag(sharedRoot, pid, AnonRouting.epochFor())

        val sealed = AnonRouting.seal(innerEnvelope, recipientPubkey)
        val target = PAD_BUCKETS.first { it >= sealed.size }
        val padded = ByteArray(target)
        System.arraycopy(sealed, 0, padded, 0, sealed.size)

        val url = URL(BASE + "/api/v1/messages/send-anon")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/octet-stream")
            setRequestProperty("X-Routing-Tag", tag.joinToString("") { "%02x".format(it) })
            setRequestProperty("X-Envelope-Version", "2")
            if (expiresInSeconds != null) {
                setRequestProperty("X-Expires-In", expiresInSeconds.toString())
            }
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT
            doOutput = true
            setFixedLengthStreamingMode(padded.size)
        }
        conn.outputStream.use { it.write(padded) }
        val status = conn.responseCode
        val response = BufferedReader(InputStreamReader(
            if (status in 200..299) conn.inputStream else conn.errorStream
        )).readText()
        conn.disconnect()
        val obj = try { JSONObject(response) } catch (_: Throwable) { JSONObject() }
        obj.put("_status", status)
        obj
    }

    /**
     * POST /api/v1/messages/fetch-anon with a list of routing tags.
     * Returns a list of (sealed_envelope_bytes, server_ts) tuples for
     * messages addressed to any of the supplied tags.
     */
    suspend fun fetchAnon(tags: List<ByteArray>): List<Pair<ByteArray, String>> =
        withContext(Dispatchers.IO) {
            if (tags.isEmpty()) return@withContext emptyList()
            require(tags.size <= 1024) { "submit at most 1024 tags per call" }
            for (t in tags) require(t.size == 32) { "tags must be 32 bytes each" }

            val tagsHex = org.json.JSONArray()
            for (t in tags) {
                tagsHex.put(t.joinToString("") { "%02x".format(it) })
            }
            val payload = JSONObject().apply { put("tags", tagsHex) }.toString().toByteArray()

            val url = URL(BASE + "/api/v1/messages/fetch-anon")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                connectTimeout = TIMEOUT
                readTimeout = TIMEOUT
                doOutput = true
            }
            OutputStreamWriter(conn.outputStream).use { it.write(String(payload)) }
            val responseText = BufferedReader(InputStreamReader(
                if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
            )).readText()
            conn.disconnect()

            val resp = JSONObject(responseText)
            val msgs = resp.optJSONArray("messages") ?: return@withContext emptyList()
            val out = ArrayList<Pair<ByteArray, String>>(msgs.length())
            for (i in 0 until msgs.length()) {
                val m = msgs.getJSONObject(i)
                val sealedHex = m.getString("sealed")
                val sealedBytes = ByteArray(sealedHex.length / 2)
                for (j in sealedBytes.indices) {
                    sealedBytes[j] = sealedHex.substring(j * 2, j * 2 + 2).toInt(16).toByte()
                }
                out.add(Pair(sealedBytes, m.optString("ts", "")))
            }
            out
        }

    /**
     * Convenience: fetch-anon across all contacts' {prev, current, next}
     * epochs, then unseal each returned envelope and return only the
     * plaintexts we could successfully decrypt.
     */
    suspend fun fetchAnonForContacts(
        myIdPriv: ByteArray, myIdPub: ByteArray,
        contacts: List<Triple<ByteArray, ByteArray, String>>,  // (their_pub, shared_root, name)
    ): List<Pair<String, ByteArray>> {
        val pairs = contacts.map { (theirPub, root, _) ->
            Pair(AnonRouting.pairId(myIdPub, theirPub), root)
        }
        val tags = AnonRouting.fetchTagsForWindow(pairs)
        val sealedList = fetchAnon(tags)
        val out = ArrayList<Pair<String, ByteArray>>()
        for ((sealedBytes, ts) in sealedList) {
            // Strip trailing zeros and try unseal across a small tail window.
            var len = sealedBytes.size
            while (len > 0 && sealedBytes[len - 1] == 0.toByte()) len--
            for (tail in len..(len + 32).coerceAtMost(sealedBytes.size)) {
                try {
                    val plaintext = AnonRouting.unseal(
                        sealed = sealedBytes.copyOfRange(0, tail),
                        myPriv = myIdPriv,
                        myPub = myIdPub,
                    )
                    out.add(Pair(ts, plaintext))
                    break
                } catch (_: Throwable) {
                    continue
                }
            }
        }
        return out
    }
}
