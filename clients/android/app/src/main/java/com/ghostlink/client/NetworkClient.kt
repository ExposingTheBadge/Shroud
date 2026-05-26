package com.ghostlink.client

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
        val key = "GHOSTLINK"
        val bytes = hex.split(" ").map { it.toInt(16) }.toIntArray()
        for (i in bytes.indices) bytes[i] = bytes[i] xor key[i % key.length].code
        return String(bytes.map { it.toChar() }.toCharArray())
    }
    private const val TIMEOUT = 10_000

    suspend fun post(path: String, body: JSONObject): JSONObject = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Connection", "close")
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
        }
        OutputStreamWriter(conn.outputStream).use { it.write(body.toString()) }

        val response = BufferedReader(InputStreamReader(
            if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
        )).readText()

        conn.disconnect()
        JSONObject(response)
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
    suspend fun getBytes(path: String): ByteArray? = withContext(Dispatchers.IO) {
        val url = URL(BASE + path)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = TIMEOUT
            readTimeout = TIMEOUT
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
}
