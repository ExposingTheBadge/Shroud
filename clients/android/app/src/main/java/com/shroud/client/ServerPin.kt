package com.shroud.client

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Trust-on-first-use pinning of the server identity fingerprint.
 *
 * Mirrors the Windows client: on every login attempt we fetch
 * /api/v1/server-identity and compare against the locally-saved
 * fingerprint. On first connect we save it; on later connects we refuse
 * if the fingerprint differs (alerts the user — most often this means a
 * legitimate operator rotation OR a MITM trying to impersonate the
 * server). The server-signature suite is Ed25519 + ML-DSA-87 +
 * SPHINCS+-256s.
 */
object ServerPin {
    private const val PIN_FILE = "server.pin"

    private fun pinFile(ctx: Context): File =
        File(ctx.filesDir, PIN_FILE)

    fun loadPinned(ctx: Context): String? {
        val f = pinFile(ctx)
        if (!f.exists()) return null
        return f.readText().trim().ifBlank { null }
    }

    fun savePinned(ctx: Context, fingerprint: String) {
        pinFile(ctx).writeText(fingerprint.trim())
    }

    fun clear(ctx: Context) {
        pinFile(ctx).delete()
    }

    /** Result codes mirror the Windows verifyServerIdentity() return values. */
    enum class Verdict { OK, FIRST_PIN_SAVED, MISMATCH, ENDPOINT_MISSING, NETWORK_ERROR }

    /**
     * @return Pair(verdict, fingerprintFromServerOrEmpty)
     * Caller should treat MISMATCH as fatal — refuse to authenticate.
     */
    suspend fun verify(ctx: Context): Pair<Verdict, String> {
        val obj: JSONObject = try {
            NetworkClient.get("/api/v1/server-identity")
        } catch (_: Throwable) {
            return Verdict.NETWORK_ERROR to ""
        }
        val fp = obj.optString("fingerprint", "")
        if (fp.isBlank()) return Verdict.ENDPOINT_MISSING to ""
        val pinned = loadPinned(ctx)
        if (pinned.isNullOrBlank()) {
            savePinned(ctx, fp)
            return Verdict.FIRST_PIN_SAVED to fp
        }
        return if (pinned == fp) Verdict.OK to fp else Verdict.MISMATCH to fp
    }
}
