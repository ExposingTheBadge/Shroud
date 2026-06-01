/*
 * SHROUD anonymous error reporter — Android port.
 *
 * Hooks Thread.UncaughtExceptionHandler. Builds a PII-scrubbed report
 * sealed to the operator's published diagnostics pubkey and submits
 * it through the relay's /api/v1/diagnostics/report endpoint.
 *
 * The operator decrypts privately. Neither the relay nor GitHub ever
 * sees who reported what.
 *
 * Wire format matches crypto/error_reporting.py.
 */
package com.shroud.client

import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL


object ErrorReporter {
    private const val TAG = "ShroudErrorReporter"
    private const val SCHEMA = "shroud.diag.v1"
    // Keep in sync with VERSION file at repo root. Bumped at release time.
    private const val APP_VERSION = "2.5.0"

    /** The operator's X25519 pubkey used to seal reports. Loaded from
     *  a manifest the client pins at install time (or from a hard-coded
     *  default for v1). 32 bytes. */
    @Volatile
    private var operatorDiagPubkey: ByteArray? = null

    @Volatile
    private var relayBaseUrl: String = "https://44.202.225.57:58443"

    private var defaultHandler: Thread.UncaughtExceptionHandler? = null

    /** One-time install. Call from MyApplication.onCreate() AFTER the
     *  user has configured their relay URL + pinned the operator
     *  manifest. */
    fun install(
        appContext: Context,
        operatorPubkey: ByteArray,
        baseUrl: String? = null,
    ) {
        require(operatorPubkey.size == 32) { "operator pubkey must be 32 bytes" }
        operatorDiagPubkey = operatorPubkey
        baseUrl?.let { relayBaseUrl = it }

        defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            // Run fast, then chain to the real handler so the OS still
            // tombstones the process.
            try {
                val report = buildReport(
                    kind = "crash",
                    message = throwable.message ?: throwable.javaClass.simpleName,
                    stack = throwable.stackTraceToString(),
                    extra = mapOf("thread" to thread.name),
                )
                submitSync(report)
            } catch (t: Throwable) {
                Log.w(TAG, "report submit failed", t)
            }
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    /** Submit a non-fatal log report from anywhere in the app. */
    fun log(message: String, extra: Map<String, String> = emptyMap()) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                submitSync(buildReport(kind = "log", message = message, stack = "", extra = extra))
            } catch (t: Throwable) {
                Log.w(TAG, "log report failed", t)
            }
        }
    }

    private fun buildReport(
        kind: String,
        message: String,
        stack: String,
        extra: Map<String, String>,
    ): JSONObject {
        val ts = System.currentTimeMillis() / 1000
        return JSONObject().apply {
            put("schema", SCHEMA)
            put("ts", ts)
            put("app", "shroud-android")
            put("app_version", APP_VERSION)
            put("os", "Android ${Build.VERSION.RELEASE} (api ${Build.VERSION.SDK_INT})")
            put("kind", kind)
            put("message", scrub(message))
            put("stack", scrub(stack))
            put("context", JSONObject().apply {
                for ((k, v) in extra) put(k, scrub(v))
            })
        }
    }

    /** Synchronous submit so the uncaught-exception handler can finish
     *  before the OS tears the process down. Returns true on success. */
    private fun submitSync(report: JSONObject): Boolean {
        val opPub = operatorDiagPubkey ?: return false

        val payload = report.toString().toByteArray()
        val sealed = AnonRouting.seal(payload, opPub)
        // Diagnostic reports use the 4096-byte bucket exclusively.
        val padded = ByteArray(4096)
        if (sealed.size > padded.size) return false
        System.arraycopy(sealed, 0, padded, 0, sealed.size)

        // Routing tag derived from the operator pubkey itself (well-
        // known pair_id = 0).
        val tag = AnonRouting.routingTag(
            sharedRoot = opPub,
            pair = 0L,
            epoch = AnonRouting.epochFor(),
        )

        val url = URL(relayBaseUrl.trimEnd('/') + "/api/v1/diagnostics/report")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/octet-stream")
            setRequestProperty(
                "X-Routing-Tag",
                tag.joinToString("") { "%02x".format(it) },
            )
            connectTimeout = 5000
            readTimeout = 5000
            doOutput = true
            setFixedLengthStreamingMode(padded.size)
        }
        return try {
            conn.outputStream.use { it.write(padded) }
            val ok = conn.responseCode in 200..299
            conn.disconnect()
            ok
        } catch (_: Throwable) {
            try { conn.disconnect() } catch (_: Throwable) {}
            false
        }
    }

    // ── PII scrubber ─────────────────────────────────────────────────

    private val PATTERNS = listOf(
        // UUIDs
        Regex("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b") to "<UUID>",
        // Long hex strings (pubkeys, hashes, derived ids)
        Regex("\\b[0-9a-fA-F]{24,}\\b") to "<HEX>",
        // Emails
        Regex("\\b[\\w.+-]+@[\\w.-]+\\.\\w+\\b") to "<EMAIL>",
        // IPv4
        Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b") to "<IPV4>",
        // IPv6 (simplified)
        Regex("\\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}\\b") to "<IPV6>",
        // POSIX user paths
        Regex("(/(?:home|Users)/)[^/\\s\"']+") to "$1<USER>",
        // Android per-app dirs (keep package, redact deeper paths)
        Regex("(/data/(?:data|user/\\d+)/[\\w.]+/)[\\w./-]+") to "$1<DATA>",
        // JWTs
        Regex("\\beyJ[\\w-]+\\.[\\w-]+\\.[\\w-]+\\b") to "<JWT>",
        // Phone numbers (loose)
        Regex("\\+?\\d[\\d\\s().-]{7,}\\d") to "<PHONE>",
    )

    private fun scrub(text: String): String {
        if (text.isEmpty()) return text
        var out = text
        for ((regex, replacement) in PATTERNS) {
            out = regex.replace(out, replacement)
        }
        return out
    }
}
