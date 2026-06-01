package com.shroud.client

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.KeyPair as JavaKeyPair

private val DarkColors = darkColorScheme(
    primary = Color(0xFFff8c1e), background = Color(0xFF1A1A1A),
    surface = Color(0xFF222222), surfaceVariant = Color(0xFF2D2D2D),
    onPrimary = Color.Black, onBackground = Color(0xFFCCCCCC),
    onSurface = Color(0xFFCCCCCC), onSurfaceVariant = Color(0xFF888888),
    outline = Color(0xFF3D3D3D),
)

/* Theme presets parallel to the Windows v2.1 picker. Switched at runtime
 * via colorSchemeFor(name); the choice is persisted in prefs. */
private fun colorSchemeFor(name: String): androidx.compose.material3.ColorScheme = when (name) {
    "SHROUD Light" -> androidx.compose.material3.lightColorScheme(
        primary = Color(0xFFff8c1e), background = Color(0xFFFFFFFF),
        surface = Color(0xFFF5F5F0), surfaceVariant = Color(0xFFF0F0E8),
        onPrimary = Color.White, onBackground = Color(0xFF1A1A1A),
        onSurface = Color(0xFF1A1A1A), onSurfaceVariant = Color(0xFF666666),
    )
    "Solarized Dark" -> darkColorScheme(
        primary = Color(0xFF268BD2), background = Color(0xFF002B36),
        surface = Color(0xFF073642), surfaceVariant = Color(0xFF073642),
        onPrimary = Color.Black, onBackground = Color(0xFF93A1A1),
        onSurface = Color(0xFF93A1A1), onSurfaceVariant = Color(0xFF586E75),
    )
    "Nord" -> darkColorScheme(
        primary = Color(0xFF5E81AC), background = Color(0xFF2E3440),
        surface = Color(0xFF3B4252), surfaceVariant = Color(0xFF434C5E),
        onPrimary = Color.White, onBackground = Color(0xFFECEFF4),
        onSurface = Color(0xFFECEFF4), onSurfaceVariant = Color(0xFF88C0D0),
    )
    "Dracula" -> darkColorScheme(
        primary = Color(0xFFBD93F9), background = Color(0xFF282A36),
        surface = Color(0xFF1E1F29), surfaceVariant = Color(0xFF44475A),
        onPrimary = Color.Black, onBackground = Color(0xFFF8F8F2),
        onSurface = Color(0xFFF8F8F2), onSurfaceVariant = Color(0xFF6272A4),
    )
    "Monokai" -> darkColorScheme(
        primary = Color(0xFFA6E22E), background = Color(0xFF272822),
        surface = Color(0xFF1E1F1C), surfaceVariant = Color(0xFF3E3D32),
        onPrimary = Color.Black, onBackground = Color(0xFFF8F8F2),
        onSurface = Color(0xFFF8F8F2), onSurfaceVariant = Color(0xFF75715E),
    )
    "Tokyo Night" -> darkColorScheme(
        primary = Color(0xFF7AA2F7), background = Color(0xFF1A1B26),
        surface = Color(0xFF16161E), surfaceVariant = Color(0xFF24283B),
        onPrimary = Color.Black, onBackground = Color(0xFFC0CAF5),
        onSurface = Color(0xFFC0CAF5), onSurfaceVariant = Color(0xFF565F89),
    )
    "Gruvbox Dark" -> darkColorScheme(
        primary = Color(0xFFFE8019), background = Color(0xFF282828),
        surface = Color(0xFF3C3836), surfaceVariant = Color(0xFF504945),
        onPrimary = Color.Black, onBackground = Color(0xFFEBDBB2),
        onSurface = Color(0xFFEBDBB2), onSurfaceVariant = Color(0xFFA89984),
    )
    "High Contrast" -> darkColorScheme(
        primary = Color(0xFFFFFF00), background = Color.Black,
        surface = Color(0xFF0A0A0A), surfaceVariant = Color(0xFF101010),
        onPrimary = Color.Black, onBackground = Color.White,
        onSurface = Color.White, onSurfaceVariant = Color(0xFFBBBBBB),
    )
    else -> DarkColors
}

val THEME_NAMES = listOf(
    "SHROUD Dark", "SHROUD Light",
    "Solarized Dark", "Nord", "Dracula", "Monokai",
    "Tokyo Night", "Gruvbox Dark", "High Contrast",
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Block screenshots + screen-share from recording the chat. Most
        // OS-level malware and "screen recorder" apps will see a black
        // frame instead of message content.
        window.setFlags(
            android.view.WindowManager.LayoutParams.FLAG_SECURE,
            android.view.WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent {
            val vm: ShroudVM = viewModel(factory = ShroudVM.Factory(application))

            // Re-lock the app whenever the process goes to background
            // (also fires on screen-off if the app is foregrounded). The
            // observer is bound to the process lifecycle so it survives
            // configuration changes.
            DisposableEffect(Unit) {
                val owner = androidx.lifecycle.ProcessLifecycleOwner.get()
                val obs = androidx.lifecycle.LifecycleEventObserver { _, event ->
                    if (event == androidx.lifecycle.Lifecycle.Event.ON_STOP) vm.lock()
                }
                owner.lifecycle.addObserver(obs)
                onDispose { owner.lifecycle.removeObserver(obs) }
            }
            // 60-second inactivity timer. Runs only while unlocked.
            LaunchedEffect(vm.isRegistered, vm.pinLocked) {
                while (vm.isRegistered && !vm.pinLocked) {
                    kotlinx.coroutines.delay(5_000)
                    if (vm.inactivityExpired()) vm.lock()
                }
            }

            MaterialTheme(colorScheme = colorSchemeFor(vm.themeName)) {
                when {
                    !vm.isRegistered             -> AuthScreen(vm)
                    vm.pinHash == null           -> PinSetupScreen(vm)
                    vm.pinLocked                 -> PinUnlockScreen(vm)
                    else                         -> ChatScreen(vm)
                }
            }
        }
    }
}

class ShroudVM(application: Application) : AndroidViewModel(application) {
    var isRegistered by mutableStateOf(false)
    var deviceID by mutableStateOf("")
    var username by mutableStateOf("")
    var messages by mutableStateOf(listOf<Msg>())
    var sideList by mutableStateOf(listOf<String>())
    var selectedRecipient by mutableStateOf("")
    var currentMessage by mutableStateOf("")
    var connStatus by mutableStateOf("Connecting...")
    /** Server-wide maintenance flag. Flipped by the heartbeat poll +
     *  by any send-attempt that returns 503 detail=maintenance. UI
     *  uses this to red-border the input, disable send, and show a
     *  banner identical in wording to the Windows v2.4.1 client. */
    var maintenanceMode by mutableStateOf(false)
    /** Disappearing-message timer. Persisted in prefs. When enabled,
     *  outgoing sends carry X-Expires-In: disappearSeconds. Default off
     *  matches Windows v2.1.0 behaviour. Initialized in init { } below
     *  because `prefs` is declared further down the class body. */
    var disappearEnabled by mutableStateOf(false)
    var disappearSeconds by mutableStateOf(60)
    /** Use Rule 1+2 compliant /messages/send-anon + /messages/fetch-anon
     *  endpoints. Default ON for new installs; existing users can flip
     *  off via Settings if they hit a regression. Loaded from prefs in
     *  the init block below. */
    var useAnonRouting by mutableStateOf(true)
    /** Theme persisted in prefs. Names match the Windows presets. */
    var themeName by mutableStateOf("Nord")

    /* ── PIN lock (v2.4.5) ───────────────────────────────────────────
     * Mandatory PIN, set on first launch after auth. Screen-off and a
     * 60-second inactivity window relock the app; 3 wrong unlock
     * attempts wipe the session and bounce back to the login screen.
     *
     * Stored as PBKDF2-HMAC-SHA256(pin, salt, 60000 iter, 256 bits) so
     * an attacker who steals the prefs file still has to brute-force
     * the PIN — but PINs are short by definition so this is best-effort
     * defense-in-depth on top of EncryptedSharedPreferences.       */
    var pinHash by mutableStateOf<String?>(null)   // "iter:salt_hex:hash_hex"
    var pinLocked by mutableStateOf(false)
    var pinFailCount by mutableStateOf(0)
    private var lastInteractionMs = System.currentTimeMillis()

    /** Called by ChatScreen on every user gesture to keep the app
     *  unlocked. Also resets the auto-lock timer. */
    fun touch() { lastInteractionMs = System.currentTimeMillis() }

    /** Returns true if the auto-lock window has expired. Called by the
     *  ticker that runs alongside the heartbeat. */
    fun inactivityExpired(windowMs: Long = 60_000L): Boolean =
        System.currentTimeMillis() - lastInteractionMs > windowMs

    /** Called from the lifecycle observer when the app goes to
     *  background (screen-off, switch app, etc.). */
    fun lock() { if (pinHash != null) pinLocked = true }

    /** Hash a PIN with PBKDF2. Returns "iter:salt_hex:hash_hex". */
    private fun hashPin(pin: String, saltHex: String? = null, iter: Int = 60_000): String {
        val salt = saltHex?.hexToBytes() ?: java.security.SecureRandom().run {
            val b = ByteArray(16); nextBytes(b); b
        }
        val spec = javax.crypto.spec.PBEKeySpec(pin.toCharArray(), salt, iter, 256)
        val skf  = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val key  = skf.generateSecret(spec).encoded
        return "$iter:${salt.toHex()}:${key.toHex()}"
    }

    fun setPin(pin: String) {
        val h = hashPin(pin)
        pinHash = h
        pinFailCount = 0
        pinLocked = false
        prefs.edit().putString("pin_hash", h).putInt("pin_fail", 0).apply()
    }

    /** Try to unlock with the supplied pin. Returns true on success.
     *  After 3 failed attempts in a row, the entire session is wiped. */
    fun tryUnlock(pin: String): Boolean {
        val saved = pinHash ?: return true
        val parts = saved.split(":")
        if (parts.size != 3) return false
        val iter = parts[0].toIntOrNull() ?: return false
        val attempt = hashPin(pin, saltHex = parts[1], iter = iter)
        if (attempt == saved) {
            pinFailCount = 0
            pinLocked = false
            prefs.edit().putInt("pin_fail", 0).apply()
            touch()
            return true
        }
        pinFailCount += 1
        prefs.edit().putInt("pin_fail", pinFailCount).apply()
        if (pinFailCount >= 3) {
            // Out — wipe local session state and force a fresh login.
            isRegistered = false
            deviceID = ""; username = ""; savedPassword = ""
            pinHash = null; pinFailCount = 0; pinLocked = false
            prefs.edit().clear().apply()
        }
        return false
    }

    /* Persistence helpers — the Settings dialog calls these so the
     * choice survives process death. */
    fun setTheme(name: String) {
        themeName = name
        prefs.edit().putString("theme_name", name).apply()
    }
    fun setDisappearing(enabled: Boolean, secs: Int) {
        disappearEnabled = enabled
        disappearSeconds = secs.coerceAtLeast(1)
        prefs.edit()
            .putBoolean("disappear_enabled", enabled)
            .putInt("disappear_secs", disappearSeconds)
            .apply()
    }

    var connColor by mutableStateOf(Color(0xFF888888))

    private var identityKey: JavaKeyPair? = null
    private var savedPassword = ""
    /** Encrypted shared prefs — backed by androidx.security.crypto with an
     *  AES-256 master key from the Android Keystore. Values are encrypted
     *  at rest; a stolen device image is useless without keystore access. */
    private val prefs = try {
        val masterKey = androidx.security.crypto.MasterKey.Builder(application)
            .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM).build()
        androidx.security.crypto.EncryptedSharedPreferences.create(
            application,
            "shroud_prefs_enc",
            masterKey,
            androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (e: Throwable) {
        application.getSharedPreferences("shroud_prefs", Context.MODE_PRIVATE)
    }

    init {
        identityKey = CryptoProvider.getIdentityKey()
        // Hydrate Settings-tab state from prefs. Done here so it runs
        // after `prefs` itself is initialized (Kotlin class-member init
        // order: declarations top-down, so prefs must be declared before
        // these lines — see below).
        disappearEnabled = prefs.getBoolean("disappear_enabled", false)
        disappearSeconds = prefs.getInt("disappear_secs", 60)
        useAnonRouting   = prefs.getBoolean("anon_routing", true)
        themeName = prefs.getString("theme_name", "Nord") ?: "Nord"
        pinHash = prefs.getString("pin_hash", null)
        pinFailCount = prefs.getInt("pin_fail", 0)
        // Always start LOCKED if a PIN was previously set, so an attacker
        // grabbing the unlocked phone can't open the chat by tapping the
        // launcher icon.
        pinLocked = pinHash != null

        val sid = prefs.getString("device_id", "") ?: ""
        val su = prefs.getString("username", "") ?: ""
        val sp = prefs.getString("password", "") ?: ""
        if (sid.isNotEmpty() && su.isNotEmpty() && sp.isNotEmpty() && identityKey != null) {
            deviceID = sid; username = su; savedPassword = sp; isRegistered = true
            startHeartbeat()
        }
    }

    /** Load my X25519 identity (priv, pub) from disk. Returns null if
     *  not yet generated. */
    private fun loadMyX25519Identity(): Pair<ByteArray, ByteArray>? {
        val idFile = java.io.File(java.io.File(getApplication<Application>().filesDir, "ratchet"), "identity.x25519")
        if (!idFile.exists() || idFile.length() < 64) return null
        val bytes = idFile.readBytes()
        return Pair(bytes.copyOfRange(0, 32), bytes.copyOfRange(32, 64))
    }

    /** Fetch the peer's X25519 identity pubkey from /ratchet/bundle.
     *  Returns null if the peer hasn't published a bundle yet. */
    private suspend fun fetchPeerX25519(deviceId: String): ByteArray? {
        return try {
            val bundle = NetworkClient.get("/api/v1/ratchet/bundle/$deviceId")
            val hex = bundle.optString("x25519_pub", "")
            if (hex.isBlank()) null else hex.hexToBytes()
        } catch (_: Throwable) {
            null
        }
    }

    /** Compute the per-contact safety number for the currently-selected
     *  recipient. Fetches their ratchet bundle, loads our own X25519 pub
     *  from local files, and runs SafetyNumber.compute on the pair. */
    fun computeSafetyNumber(onResult: (String?) -> Unit) {
        val recip = selectedRecipient
        if (recip.isBlank()) { onResult(null); return }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val bundle = NetworkClient.get("/api/v1/ratchet/bundle/$recip")
                val theirHex = bundle.optString("x25519_pub", "")
                if (theirHex.isBlank()) { withContext(Dispatchers.Main) { onResult(null) }; return@launch }
                val theirPub = theirHex.hexToBytes()
                val idFile = java.io.File(java.io.File(getApplication<Application>().filesDir, "ratchet"), "identity.x25519")
                if (!idFile.exists() || idFile.length() < 64) { withContext(Dispatchers.Main) { onResult(null) }; return@launch }
                val bytes = idFile.readBytes()
                val myPub = bytes.copyOfRange(32, 64)
                val fp = SafetyNumber.compute(myPub, theirPub)
                withContext(Dispatchers.Main) { onResult(fp) }
            } catch (_: Throwable) { withContext(Dispatchers.Main) { onResult(null) } }
        }
    }

    /** Generate + persist this device's long-term X25519 ratchet identity
     *  and a batch of one-time prekeys, then upload the pubs to the server.
     *  Subsequent peers can fetch the bundle to bootstrap a Double Ratchet
     *  session. Idempotent — skipped if we already have an identity file. */
    private suspend fun publishRatchetBundle(deviceId: String) {
        try {
            val dir = java.io.File(getApplication<Application>().filesDir, "ratchet")
            dir.mkdirs()
            val idFile = java.io.File(dir, "identity.x25519")
            if (idFile.exists()) return

            val (idPriv, idPub) = Ratchet.x25519Keygen()
            idFile.writeBytes(idPriv + idPub)

            val otpFile = java.io.File(dir, "one_time_prekeys.bin")
            val otps = org.json.JSONArray()
            otpFile.outputStream().use { os ->
                for (i in 0 until 32) {
                    val (pkPriv, pkPub) = Ratchet.x25519Keygen()
                    os.write(byteArrayOf((i and 0xff).toByte(), 0, 0, 0))
                    os.write(pkPriv)
                    otps.put(JSONObject().apply {
                        put("prekey_id", i)
                        put("pub", pkPub.toHex())
                    })
                }
            }

            withContext(Dispatchers.IO) {
                NetworkClient.post("/api/v1/ratchet/publish-key", JSONObject().apply {
                    put("device_id", deviceId)
                    put("x25519_pub", idPub.toHex())
                    put("one_time_prekeys", otps)
                })
            }
        } catch (_: Throwable) { /* non-fatal */ }
    }

    private fun startHeartbeat() {
        viewModelScope.launch {
            while (isRegistered) {
                delay(4000)
                try {
                    val r = withContext(Dispatchers.IO) {
                        NetworkClient.post("/api/v1/heartbeat", JSONObject().apply { put("device_id", deviceID) })
                    }
                    val beatOk = r.optString("beat") == "ok"
                    // Server v2.4.1+ surfaces maintenance_mode on every beat.
                    maintenanceMode = r.optBoolean("maintenance_mode", false)
                    if (maintenanceMode) {
                        connStatus = "Server in maintenance — sending disabled"
                        connColor  = Color(0xFFff8a8a)
                    } else if (beatOk) {
                        connStatus = "Online — AES-256-GCM | ECDH P-384"
                        connColor  = Color(0xFF2ed573)
                    } else {
                        connStatus = "Waiting..."
                        connColor  = Color(0xFF888888)
                    }
                    // v2.4.3 — actually fetch + decrypt inbound messages.
                    // Pre-v2.4.3 Android was send-only.
                    fetchAndDecrypt()
                } catch (_: Exception) {
                    connStatus = "Server offline"; connColor = Color(0xFFff4757)
                }
            }
        }
    }

    /**
     * Poll the server for queued messages and decrypt them. Detects the
     * v3 ratchet envelope by the "ratchet":1 marker and routes through
     * RatchetSession.decryptFromPeer; otherwise falls back to the legacy
     * static-AES path. Plaintext is the same {body,name,sender,ts} JSON
     * shape send() produces on both clients.
     */
    private suspend fun fetchAndDecrypt() {
        if (deviceID.isBlank()) return
        val ctx = getApplication<Application>()

        // ── Rule 1+2 compliant anon-routing fetch (scoped to the
        //    currently-selected recipient for v1; multi-contact cache
        //    will land alongside the local contact list). ──
        if (useAnonRouting && selectedRecipient.isNotBlank()) {
            try {
                val myId = loadMyX25519Identity()
                val peerPubX = fetchPeerX25519(selectedRecipient)
                if (myId != null && peerPubX != null) {
                    val (myPriv, myPub) = myId
                    val sharedRoot = Ratchet.x25519Dh(myPriv, peerPubX)
                    val anonResults = NetworkClient.fetchAnonForContacts(
                        myIdPriv = myPriv,
                        myIdPub  = myPub,
                        contacts = listOf(Triple(peerPubX, sharedRoot, selectedRecipient)),
                    )
                    for ((_, plaintextBytes) in anonResults) {
                        val plainJson = try {
                            JSONObject(String(plaintextBytes, Charsets.UTF_8))
                        } catch (_: Throwable) { continue }
                        // Dispatch through the same handler legacy uses.
                        val senderId = plainJson.optString("sender", selectedRecipient)
                        val body = plainJson.optString("body", "")
                        if (body.isNotEmpty()) {
                            messages = messages + Msg(senderId, body)
                        }
                    }
                }
            } catch (_: Throwable) { /* fall through to legacy fetch */ }
        }

        val r = withContext(Dispatchers.IO) {
            NetworkClient.post("/api/v1/messages/fetch",
                JSONObject().apply { put("device_id", deviceID) })
        }
        val arr = r.optJSONArray("messages") ?: return
        for (i in 0 until arr.length()) {
            val m = arr.optJSONObject(i) ?: continue
            val sender = m.optString("sender_device_id", "")
            val envField = m.opt("envelope")
            val env: JSONObject = when (envField) {
                is JSONObject -> envField
                is String     -> try { JSONObject(envField) } catch (_: Throwable) { continue }
                else -> continue
            }
            val plain: ByteArray? = if (env.optInt("ratchet", 0) == 1) {
                val hex = env.optString("ciphertext", "")
                if (hex.isBlank()) null
                else RatchetSession.decryptFromPeer(ctx, sender, hex)
            } else {
                // Legacy static-AES path. Symmetric to send()'s fallback.
                runCatching {
                    val pkResp = withContext(Dispatchers.IO) {
                        NetworkClient.post("/api/v1/devices/$sender/pubkey", JSONObject())
                    }
                    val pubHex = pkResp.optString("public_key", "")
                    if (pubHex.isBlank()) null
                    else {
                        val peerPub = CryptoProvider.importPublicKey(pubHex.hexToBytes())
                        val sk = CryptoProvider.deriveSessionKey(identityKey!!.private, peerPub)
                        val iv  = env.getString("nonce").hexToBytes()
                        val ct  = env.getString("ciphertext").hexToBytes()
                        val tag = env.getString("tag").hexToBytes()
                        CryptoProvider.decryptAESGCM(sk, iv, ct, tag)
                    }
                }.getOrNull()
            }
            if (plain == null) continue

            try {
                val obj = JSONObject(String(plain))
                val body = obj.optString("body", "")
                val name = obj.optString("name", "")
                val isImage = obj.optBoolean("is_image", false) ||
                              obj.optString("type", "") == "image"

                if (isImage) {
                    // v2.4.4 — match Windows downloadAndDecryptImage().
                    // Sender encrypted the file with SHA-256(sender pubkey
                    // blob); the recipient hashes the same blob fetched
                    // from /api/v1/devices/{sender}/pubkey, downloads the
                    // ciphertext from /api/v1/files/{fid}, AES-GCM decrypts,
                    // and caches the plaintext for inline display.
                    val fid = obj.optString("file_id", "")
                    if (fid.isNotBlank()) {
                        val localPath = decryptInlineImage(sender, fid, obj.optString("name", ""))
                        if (localPath != null) {
                            messages = messages + Msg(
                                sender = sender,
                                body = "",
                                imagePath = localPath,
                                fileId = fid,
                                name = name.ifBlank { null },
                            )
                            continue
                        }
                    }
                    // Couldn't fetch / decrypt — fall through to a text
                    // placeholder so the user knows something arrived.
                    if (body.isNotBlank()) {
                        messages = messages + Msg(sender, body, name = name.ifBlank { null })
                    } else {
                        messages = messages + Msg(sender, "[image unavailable]",
                            name = name.ifBlank { null })
                    }
                } else if (body.isNotBlank()) {
                    // group_id may or may not be present. Display it as a
                    // small prefix so the user can tell apart 1:1 vs group
                    // messages without a dedicated group screen.
                    val gid = obj.optString("group_id", "")
                    val finalBody = if (gid.isNotBlank()) "[group] $body" else body
                    messages = messages + Msg(sender, finalBody,
                        name = name.ifBlank { null })
                }
            } catch (_: Throwable) {
                // Unparseable plaintext — drop silently.
            }
        }
    }

    /**
     * Download an encrypted image-attachment, decrypt with the sender's
     * pub-derived key, and save to filesDir/images/<file_id>.<ext>.
     * Returns the local absolute path on success; null if any step
     * fails (network, decrypt, write). Idempotent — re-uses an already
     * cached file if present.
     */
    private suspend fun decryptInlineImage(senderDid: String, fileId: String, origName: String): String? {
        val ctx = getApplication<Application>()
        val imagesDir = java.io.File(ctx.filesDir, "images").apply { mkdirs() }
        // Pick the extension from the sender-supplied filename so
        // intent-viewers know what to do; default to .jpg.
        val ext = origName.substringAfterLast('.', "jpg").lowercase().take(5)
        val out = java.io.File(imagesDir, "$fileId.$ext")
        if (out.exists() && out.length() > 0) return out.absolutePath

        // Get the sender's pubkey blob — server returns whatever bytes
        // were registered (Android: X.509 SubjectPublicKeyInfo). Hash
        // those bytes to derive the symmetric file key. The Windows
        // sender does the same on its end with its own pub blob, and
        // the server stores both verbatim — so cross-platform works as
        // long as everyone hashes the exact bytes the server stores.
        val pubResp = withContext(Dispatchers.IO) {
            NetworkClient.post("/api/v1/devices/$senderDid/pubkey", JSONObject())
        }
        val pubHex = pubResp.optString("public_key", "")
        if (pubHex.isBlank()) return null
        val pubBytes = pubHex.hexToBytes()
        val fileKey = java.security.MessageDigest.getInstance("SHA-256")
            .digest(pubBytes).copyOf(32)
        val keySpec = javax.crypto.spec.SecretKeySpec(fileKey, "AES")

        // Pull the encrypted blob. X-Device-ID is required by the server
        // for authorization on /api/v1/files/{id}.
        val blob = withContext(Dispatchers.IO) {
            NetworkClient.getBytes("/api/v1/files/$fileId",
                mapOf("X-Device-ID" to deviceID))
        } ?: return null
        if (blob.size < 12 + 16 + 1) return null

        // Layout matches the sender: [12B iv || ct || 16B tag].
        val iv  = blob.copyOfRange(0, 12)
        val ct  = blob.copyOfRange(12, blob.size - 16)
        val tag = blob.copyOfRange(blob.size - 16, blob.size)
        val plain = try {
            CryptoProvider.decryptAESGCM(keySpec, iv, ct, tag)
        } catch (_: Throwable) { return null }

        return try {
            out.writeBytes(plain); out.absolutePath
        } catch (_: Throwable) { null }
    }

    fun auth(uIn: String, p: String, d: String, isReg: Boolean, onError: (String) -> Unit) {
        // v2.4.5 — usernames are case-insensitive end-to-end. Lowercase before
        // hashing/encrypting so the server's normalize step matches what we
        // computed locally, regardless of what the user typed.
        val u = uIn.trim().lowercase()
        viewModelScope.launch {
            try {
                // 0. Verify the server's long-term identity fingerprint (TOFU).
                //    Suite: Ed25519 + ML-DSA-87 + SPHINCS+-256s. If the
                //    fingerprint differs from the one we pinned earlier, refuse.
                val (verdict, fp) = ServerPin.verify(getApplication())
                when (verdict) {
                    ServerPin.Verdict.MISMATCH -> {
                        val pinned = ServerPin.loadPinned(getApplication()) ?: "(none)"
                        onError("Server identity changed.\nPinned: $pinned\nServer: $fp\nRefusing.")
                        return@launch
                    }
                    ServerPin.Verdict.NETWORK_ERROR -> { onError("Cannot reach server"); return@launch }
                    else -> { /* OK, FIRST_PIN_SAVED, or ENDPOINT_MISSING (legacy) — continue */ }
                }

                // 1. Get server's ECDH public key
                val keyEx = withContext(Dispatchers.IO) { NetworkClient.get("/api/v1/key-exchange") }
                val sessionId = keyEx.getString("session_id")
                val serverPubHex = keyEx.getString("server_public_key")
                val serverPub = CryptoProvider.importPublicKey(serverPubHex.hexToBytes())

                // 2. Generate our ECDH keypair
                identityKey = withContext(Dispatchers.IO) { CryptoProvider.generateIdentityKey() }
                val ourPubHex = CryptoProvider.exportPublicKey(identityKey!!).toHex()

                // 3. Derive auth key: SHA-256(ECDH_shared + "SHROUD-AUTH-v1")[:32]
                val ka = javax.crypto.KeyAgreement.getInstance("ECDH")
                ka.init(identityKey!!.private)
                ka.doPhase(serverPub, true)
                val shared = ka.generateSecret()
                val md = java.security.MessageDigest.getInstance("SHA-256")
                md.update(shared); val hashed = md.digest()
                md.reset(); md.update(hashed); md.update("SHROUD-AUTH-v1".toByteArray())
                val authKey = javax.crypto.spec.SecretKeySpec(md.digest().copyOf(32), "AES")

                // 4. Build + encrypt auth payload
                //    v2.4.6 — include the persisted device_id on login so the
                //    server reuses our existing row instead of inserting a
                //    new one every time (which would burn through the
                //    25-device-per-user cap on relogin).
                val existingDid = if (isReg) "" else (prefs.getString("device_id", "") ?: "")
                val payload = JSONObject().apply {
                    put("username", u); put("password", p)
                    put("device_name", d); put("platform", "android")
                    put("register", isReg); put("public_key", ourPubHex)
                    put("existing_device_id", existingDid)
                }.toString().toByteArray()
                val (nonce, ct, tag) = CryptoProvider.encryptAESGCM(authKey, payload)

                // 5. Send encrypted auth
                val authR = withContext(Dispatchers.IO) {
                    NetworkClient.post("/api/v1/auth", JSONObject().apply {
                        put("session_id", sessionId)
                        put("client_public_key", ourPubHex)
                        put("nonce", nonce.toHex())
                        put("ciphertext", ct.toHex())
                        put("tag", tag.toHex())
                    })
                }

                val did = authR.optString("device_id", "")
                if (did.isNotEmpty()) {
                    deviceID = did; username = u; savedPassword = p; isRegistered = true
                    prefs.edit().putString("device_id", did).putString("username", u).putString("password", p).apply()
                    publishRatchetBundle(did)
                    startHeartbeat()
                } else {
                    onError(authR.optString("detail", "Server rejected"))
                }
            } catch (ex: Exception) { onError(ex.message ?: "Connection error") }
        }
    }

    fun send() {
        val body = currentMessage; val recip = selectedRecipient
        if (body.isBlank() || recip.isBlank()) return
        currentMessage = ""
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pkResp = NetworkClient.post("/api/v1/contacts/devices", JSONObject().apply { put("device_id", deviceID); put("contact_username", username) })
                val devs = pkResp.optJSONArray("devices") ?: return@launch
                var peerPub: java.security.PublicKey? = null
                for (i in 0 until devs.length()) {
                    val dv = devs.getJSONObject(i)
                    if (dv.getString("id") == recip) { peerPub = CryptoProvider.importPublicKey(dv.getString("public_key").hexToBytes()); break }
                }
                if (peerPub == null) return@launch
                val pl = JSONObject().apply { put("body",body); put("name",username); put("sender",deviceID); put("ts",System.currentTimeMillis()/1000) }.toString().toByteArray()

                // v2.4.3: prefer the Double Ratchet path. Falls back to the
                // legacy static-AES envelope when the peer hasn't published
                // a ratchet bundle yet (pre-v1.6 peer, or never logged in
                // post-upgrade) — same logic as Windows v2.2.0.
                val ctx = getApplication<Application>()
                val ratchetHex = RatchetSession.encryptForPeer(ctx, recip, pl)
                val env = if (ratchetHex != null) {
                    val bin = ratchetHex.hexToBytes()
                    val sig = java.security.MessageDigest.getInstance("SHA-256").digest(bin)
                    JSONObject().apply {
                        put("ratchet", 1)
                        put("sender", deviceID); put("ts", System.currentTimeMillis()/1000)
                        put("nonce",      "0".repeat(24))    // unused on ratchet path; schema-padding
                        put("ciphertext", ratchetHex)
                        put("tag",        "0".repeat(32))
                        put("sig",        sig.toHex())
                    }
                } else {
                    val sk = CryptoProvider.deriveSessionKey(identityKey!!.private, peerPub)
                    val (iv,ct,tg) = CryptoProvider.encryptAESGCM(sk, pl)
                    val sg = CryptoProvider.hmacSign(sk, ct)
                    JSONObject().apply { put("sender",deviceID); put("ts",System.currentTimeMillis()/1000); put("nonce",iv.toHex()); put("ciphertext",ct.toHex()); put("tag",tg.toHex()); put("sig",sg.toHex()) }
                }
                val expiresIn = if (disappearEnabled && disappearSeconds > 0) disappearSeconds else null
                val resp: JSONObject = if (useAnonRouting) {
                    // Rule 1+2 compliant path: sealed envelope addressed
                    // to a per-pair routing tag. Server never sees
                    // sender_device_id or recipient_device_id.
                    val myId = loadMyX25519Identity()
                    val peerPubX = fetchPeerX25519(recip)
                    if (myId == null || peerPubX == null) {
                        // Can't go anon yet (no ratchet bundle on either
                        // side). Fall through to legacy.
                        val headers = if (expiresIn != null) mapOf("X-Expires-In" to expiresIn.toString()) else emptyMap()
                        NetworkClient.post(
                            "/api/v1/messages/send",
                            JSONObject().apply { put("sender_device_id",deviceID); put("recipient_device_id",recip); put("envelope",env.toString()) },
                            headers,
                        )
                    } else {
                        val (myPriv, myPub) = myId
                        val sharedRoot = Ratchet.x25519Dh(myPriv, peerPubX)
                        NetworkClient.sendAnon(
                            recipientPubkey = peerPubX,
                            myIdPubkey      = myPub,
                            sharedRoot      = sharedRoot,
                            innerEnvelope   = env.toString().toByteArray(Charsets.UTF_8),
                            expiresInSeconds= expiresIn,
                        )
                    }
                } else {
                    val headers = if (expiresIn != null) mapOf("X-Expires-In" to expiresIn.toString()) else emptyMap()
                    NetworkClient.post(
                        "/api/v1/messages/send",
                        JSONObject().apply { put("sender_device_id",deviceID); put("recipient_device_id",recip); put("envelope",env.toString()) },
                        headers,
                    )
                }
                // Server v2.4.1+ returns 503 + {"detail":"maintenance"} when locked.
                if (resp.optInt("_status") == 503 && resp.optString("detail") == "maintenance") {
                    maintenanceMode = true
                    connStatus = "Send refused — server in maintenance"
                    connColor  = Color(0xFFff8a8a)
                    return@launch
                }
                messages = messages + Msg(deviceID, body)
            } catch (_: Exception) {}
        }
    }

    /** Send an image from a content Uri. Saves a local plaintext copy so the
     *  sender sees the image inline in their own chat, uploads an
     *  encrypted blob to /api/v1/files/upload, and sends a file-type
     *  message envelope to the recipient. */
    fun sendImage(uri: android.net.Uri) {
        val recip = selectedRecipient
        if (recip.isBlank()) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val app = getApplication<Application>()
                val bytes = app.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return@launch

                // Derive symmetric file key = SHA-256(my public-key blob).
                val pub = identityKey?.public?.encoded ?: return@launch
                val md = java.security.MessageDigest.getInstance("SHA-256")
                val sk = javax.crypto.spec.SecretKeySpec(md.digest(pub).copyOf(32), "AES")

                val (iv, ct, tag) = CryptoProvider.encryptAESGCM(sk, bytes)
                val combined = iv + ct + tag

                // Resolve a filename + mime; default to .jpg if unknown.
                val mime = app.contentResolver.getType(uri) ?: "image/jpeg"
                val ext = when {
                    mime.endsWith("png") -> "png"
                    mime.endsWith("gif") -> "gif"
                    mime.endsWith("webp") -> "webp"
                    mime.endsWith("bmp") -> "bmp"
                    else -> "jpg"
                }
                val fname = "img_${System.currentTimeMillis()}.$ext"

                val meta = JSONObject().apply {
                    put("name", fname); put("size", bytes.size)
                    put("mime", mime); put("is_image", true)
                }
                val ur = NetworkClient.uploadFile("/api/v1/files/upload", combined,
                    deviceID, recip, meta.toString())
                val fileId = ur.optString("file_id", "")
                if (fileId.isEmpty()) return@launch

                // Cache plaintext locally for inline display + viewer.
                val dir = java.io.File(app.filesDir, "images").apply { mkdirs() }
                val local = java.io.File(dir, "$fileId.$ext")
                local.writeBytes(bytes)

                // Send file message envelope mirroring Windows' format.
                val pkResp = NetworkClient.post("/api/v1/contacts/devices", JSONObject().apply { put("device_id", deviceID); put("contact_username", username) })
                val devs = pkResp.optJSONArray("devices")
                var peerPub: java.security.PublicKey? = null
                if (devs != null) for (i in 0 until devs.length()) {
                    val dv = devs.getJSONObject(i)
                    if (dv.getString("id") == recip) { peerPub = CryptoProvider.importPublicKey(dv.getString("public_key").hexToBytes()); break }
                }
                if (peerPub != null) {
                    val sessionKey = CryptoProvider.deriveSessionKey(identityKey!!.private, peerPub)
                    val pl = JSONObject().apply {
                        put("type", "image"); put("file_id", fileId)
                        put("name", fname); put("size", bytes.size)
                        put("mime", mime); put("is_image", true)
                        put("body", "Sent image: $fname")
                    }.toString().toByteArray()
                    val (eiv, ect, etag) = CryptoProvider.encryptAESGCM(sessionKey, pl)
                    val esg = CryptoProvider.hmacSign(sessionKey, ect)
                    val env = JSONObject().apply {
                        put("sender", deviceID); put("ts", System.currentTimeMillis() / 1000)
                        put("nonce", eiv.toHex()); put("ciphertext", ect.toHex())
                        put("tag", etag.toHex()); put("sig", esg.toHex())
                    }
                    val imgHeaders = if (disappearEnabled && disappearSeconds > 0)
                        mapOf("X-Expires-In" to disappearSeconds.toString()) else emptyMap()
                    val imgResp = NetworkClient.post(
                        "/api/v1/messages/send",
                        JSONObject().apply {
                            put("sender_device_id", deviceID)
                            put("recipient_device_id", recip)
                            put("envelope", env.toString())
                        },
                        imgHeaders,
                    )
                    if (imgResp.optInt("_status") == 503 && imgResp.optString("detail") == "maintenance") {
                        maintenanceMode = true
                        connStatus = "Upload refused — server in maintenance"
                        connColor  = Color(0xFFff8a8a)
                        return@launch
                    }
                }

                messages = messages + Msg(deviceID, "", imagePath = local.absolutePath,
                    fileId = fileId, name = username)
            } catch (_: Exception) {}
        }
    }

    /** Delete an image both locally and on the server. */
    fun deleteImage(msg: Msg) {
        val fid = msg.fileId ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                NetworkClient.deleteFile("/api/v1/files/$fid", deviceID)
                msg.imagePath?.let { java.io.File(it).delete() }
                messages = messages.map {
                    if (it.fileId == fid) it.copy(imagePath = null, body = "[image deleted]") else it
                }
            } catch (_: Exception) {}
        }
    }

    fun search(q: String) {
        // Lowercase server-side match — keep client behaviour consistent.
        val query = q.trim().lowercase()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/contacts/search", JSONObject().apply { put("device_id",deviceID); put("query",query) })
                val arr = r.optJSONArray("users"); val l = mutableListOf<String>()
                if (arr != null) for (i in 0 until arr.length()) l.add(arr.getString(i))
                sideList = l
            } catch (_: Exception) {}
        }
    }

    fun ownDevices() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/devices/list", JSONObject().apply { put("device_id",deviceID) })
                val arr = r.optJSONArray("devices"); val l = mutableListOf<String>()
                if (arr != null) for (i in 0 until arr.length()) { val d = arr.getJSONObject(i); l.add("${d.getString("name")} (${d.getString("id").take(12)})") }
                sideList = l
            } catch (_: Exception) {}
        }
    }

    fun loadGroups() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.get("/api/v1/groups/$deviceID")
                val arr = r.optJSONArray("groups"); val l = mutableListOf<String>()
                if (arr != null) for (i in 0 until arr.length()) { val g = arr.getJSONObject(i); l.add("# ${g.getString("name")} [${g.getString("id").take(12)}]") }
                sideList = l
            } catch (_: Exception) {}
        }
    }

    // ── Multi-device linking (sealed-Sesame style) ───────────────────
    // Symmetric to the Windows client (see clients/windows/main.cpp
    // linkStartPrimary / linkAcceptSecondary). End-to-end encrypted via
    // ephemeral X25519; server only relays opaque ciphertext.
    //
    //   Primary: posts ekP_pub, polls for ekS_pub, then PUTs
    //            iv ‖ tag ‖ AES-GCM(HKDF(X25519(ekP_priv, ekS_pub))) over
    //            the snapshot bundle.
    //   Secondary: parses the link code, posts ekS_pub, polls /payload,
    //              decrypts, imports.
    //
    // The bundle is import-only (username + contact list); it does not
    // grant credentials — secondary must still register normally before
    // accepting the code. Credential grant lands in v2.4.
    var linkCode by mutableStateOf("")              // primary's generated code
    var linkStatus by mutableStateOf("")            // user-visible status line
    private var linkPrimaryPriv: ByteArray? = null
    private var linkPrimaryId: String? = null

    fun generateLinkCode(onError: (String) -> Unit = {}) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val (priv, pub) = Ratchet.x25519Keygen()
                val r = NetworkClient.post("/api/v1/devices/link/init", JSONObject().apply {
                    put("device_id", deviceID)
                    put("primary_pubkey_hex", pub.toHex())
                })
                val id = r.optString("link_id", "")
                if (id.isEmpty()) { withContext(Dispatchers.Main) { onError("Server rejected the link request") }; return@launch }
                linkPrimaryPriv = priv
                linkPrimaryId = id
                withContext(Dispatchers.Main) {
                    linkCode = "$id:${pub.toHex()}"
                    linkStatus = "Waiting for the other device to enter this code (5 min)…"
                }
                // Poll for secondary pubkey, then ship the bundle.
                for (tick in 0 until 150) {
                    delay(2000)
                    val poll = try { NetworkClient.get("/api/v1/devices/link/$id") } catch (_: Throwable) { continue }
                    val secHex = poll.optString("secondary_pubkey_hex", "")
                    if (secHex.isBlank() || secHex == "null") continue
                    val shared = Ratchet.x25519Dh(priv, secHex.hexToBytes())
                    val key = Ratchet.hkdfSha512(ByteArray(64), shared, "SHROUD-DEVLINK-v1".toByteArray(), 32)
                    val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
                    val friendsResp = NetworkClient.post("/api/v1/friends/list", JSONObject().apply { put("device_id", deviceID) })
                    val bundle = JSONObject().apply {
                        put("v", 1)
                        put("username", username)
                        put("primary_device_id", deviceID)
                        put("friends", friendsResp.optJSONArray("friends") ?: org.json.JSONArray())
                        put("note", "SHROUD device-link snapshot. Import-only; does not grant credentials.")
                    }.toString().toByteArray()
                    val (iv, ct, tag) = CryptoProvider.encryptAESGCM(keySpec, bundle)
                    val blob = iv + tag + ct
                    NetworkClient.postBytes("/api/v1/devices/link/$id/payload", blob)
                    withContext(Dispatchers.Main) {
                        linkStatus = "Linked. Sent ${blob.size}-byte encrypted bundle."
                    }
                    return@launch
                }
                withContext(Dispatchers.Main) { linkStatus = "Link code expired. Generate a new one." }
            } catch (e: Throwable) {
                withContext(Dispatchers.Main) { onError(e.message ?: "Link failed") }
            }
        }
    }

    fun acceptLinkCode(code: String, onError: (String) -> Unit = {}) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val sep = code.indexOf(':')
                if (sep != 32 || code.length != 32 + 1 + 64) {
                    withContext(Dispatchers.Main) { onError("Expected 32 hex chars, a colon, then 64 hex chars.") }
                    return@launch
                }
                val id = code.substring(0, 32)
                val primaryPub = code.substring(33).hexToBytes()
                val (priv, pub) = Ratchet.x25519Keygen()
                val r = NetworkClient.post("/api/v1/devices/link/$id/secondary", JSONObject().apply {
                    put("secondary_pubkey_hex", pub.toHex())
                })
                if (r.optBoolean("ok", false) != true) {
                    withContext(Dispatchers.Main) { onError("Server rejected (expired or already consumed)") }
                    return@launch
                }
                withContext(Dispatchers.Main) { linkStatus = "Waiting for the other device to send the bundle…" }
                for (tick in 0 until 150) {
                    delay(2000)
                    val blob = NetworkClient.getBytes("/api/v1/devices/link/$id/payload") ?: continue
                    if (blob.size < 12 + 16 + 1) continue
                    val shared = Ratchet.x25519Dh(priv, primaryPub)
                    val key = Ratchet.hkdfSha512(ByteArray(64), shared, "SHROUD-DEVLINK-v1".toByteArray(), 32)
                    val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
                    val iv = blob.copyOfRange(0, 12)
                    val tag = blob.copyOfRange(12, 28)
                    val ct = blob.copyOfRange(28, blob.size)
                    val plain = try { CryptoProvider.decryptAESGCM(keySpec, iv, ct, tag) }
                                catch (_: Throwable) { null }
                    if (plain == null) {
                        withContext(Dispatchers.Main) { onError("Decrypt failed — auth tag mismatch") }
                        return@launch
                    }
                    val bundle = JSONObject(String(plain))
                    val n = bundle.optJSONArray("friends")?.length() ?: 0
                    val from = bundle.optString("username", "")
                    withContext(Dispatchers.Main) {
                        linkStatus = "Imported $n contacts from $from's primary device."
                    }
                    return@launch
                }
                withContext(Dispatchers.Main) { linkStatus = "Timed out waiting for the bundle." }
            } catch (e: Throwable) {
                withContext(Dispatchers.Main) { onError(e.message ?: "Accept failed") }
            }
        }
    }

    class Factory(private val app: Application) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T = ShroudVM(app) as T
    }
}

data class Msg(
    val sender: String,
    val body: String,
    val imagePath: String? = null,   // local plaintext path for inline display
    val fileId: String? = null,      // server file id (for delete)
    val name: String? = null,        // sender display name
)

/**
 * PIN setup — mandatory on first launch after auth (no skip path).
 * 4+ digits, confirm. Stores PBKDF2 hash in EncryptedSharedPreferences.
 */
@Composable
fun PinSetupScreen(vm: ShroudVM) {
    var p1 by remember { mutableStateOf("") }
    var p2 by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background),
        contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally,
               modifier = Modifier.padding(24.dp).fillMaxWidth(0.9f)) {
            Text("Set an app PIN",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            Text("4+ digits. You'll re-enter this whenever the screen turns " +
                 "off or the app sits idle. 3 wrong attempts log you out.",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center)
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = p1, onValueChange = { p1 = it.filter(Char::isDigit) },
                label = { Text("PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = p2, onValueChange = { p2 = it.filter(Char::isDigit) },
                label = { Text("Confirm PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )
            if (err != null) {
                Spacer(Modifier.height(8.dp))
                Text(err!!, color = MaterialTheme.colorScheme.error, fontSize = 12.sp)
            }
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = {
                    when {
                        p1.length < 4 -> err = "PIN must be at least 4 digits"
                        p1 != p2      -> err = "PINs don't match"
                        else          -> { vm.setPin(p1); err = null }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Save PIN") }
        }
    }
}

/**
 * PIN unlock screen — shown on app resume / inactivity timeout. 3 wrong
 * attempts call vm.tryUnlock which wipes the session on the third miss.
 */
@Composable
fun PinUnlockScreen(vm: ShroudVM) {
    var pin by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background),
        contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally,
               modifier = Modifier.padding(24.dp).fillMaxWidth(0.9f)) {
            Icon(Icons.Filled.Lock, "Locked",
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(48.dp))
            Spacer(Modifier.height(12.dp))
            Text("Enter PIN to unlock",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = pin,
                onValueChange = {
                    pin = it.filter(Char::isDigit)
                    err = null
                },
                label = { Text("PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (err != null) {
                Spacer(Modifier.height(8.dp))
                Text(err!!, color = MaterialTheme.colorScheme.error, fontSize = 12.sp,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier = Modifier.fillMaxWidth())
            }
            Text("Wrong attempts: ${vm.pinFailCount} / 3",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = {
                    if (!vm.tryUnlock(pin)) {
                        err = "Wrong PIN"
                        pin = ""
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock") }
        }
    }
}

/**
 * IconButton with a long-press tooltip ("hover description"). Mirrors the
 * Windows Qt toolTip behaviour. On Android, accessibility services (e.g.
 * TalkBack) read the tip via `contentDescription`, and the platform's
 * built-in long-press content-description tooltip surfaces it visually
 * for sighted users without a mouse.
 *
 * We intentionally don't use Material 3's TooltipBox/PlainTooltip here:
 * those are gated behind ExperimentalMaterial3Api and weren't promoted
 * out of `private` until material3 1.2.0. This project pins Compose BOM
 * 2024.01.00 (material3 1.1.2), so we use the stable contentDescription
 * path — which Android already turns into a tooltip on long-press.
 */
@Composable
fun TooltipIconButton(
    tip: String,
    onClick: () -> Unit,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDesc: String,
    enabled: Boolean = true,
) {
    // Concatenate the short contentDescription and the longer tip so
    // accessibility services announce the full intent. Android shows the
    // contentDescription as a long-press tooltip on API 26+.
    val merged = if (contentDesc.isBlank() || tip == contentDesc) tip
                 else "$contentDesc — $tip"
    IconButton(onClick = onClick, enabled = enabled) {
        Icon(icon, contentDescription = merged)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthScreen(vm: ShroudVM) {
    var u by remember { mutableStateOf("") }; var p by remember { mutableStateOf("") }
    var d by remember { mutableStateOf(android.os.Build.MODEL) }
    var showReg by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    Scaffold { pad ->
        Column(Modifier.fillMaxSize().padding(pad).padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            Text("SHROUD", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(24.dp))
            OutlinedTextField(u, { u = it }, label = { Text("Username") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(p, { p = it }, label = { Text("Password (12+)") }, modifier = Modifier.fillMaxWidth(), singleLine = true, visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
            if (showReg) { Spacer(Modifier.height(8.dp)); OutlinedTextField(d, { d = it }, label = { Text("Device Name") }, modifier = Modifier.fillMaxWidth(), singleLine = true) }
            if (err != null) { Spacer(Modifier.height(8.dp)); Text(err!!, color = MaterialTheme.colorScheme.error) }
            Spacer(Modifier.height(16.dp))
            Button(onClick = { loading = true; err = null; vm.auth(u, p, d, showReg) { msg -> err = msg; loading = false } }, enabled = u.length >= 3 && p.length >= 12 && !loading, modifier = Modifier.fillMaxWidth().height(48.dp)) {
                Text(if (loading) "Please wait..." else if (showReg) "Create Account" else "Login")
            }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = { showReg = !showReg; err = null }) { Text(if (showReg) "Already registered? Login" else "Don't have an account? Register", color = MaterialTheme.colorScheme.primary) }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class,
       androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
fun ChatScreen(vm: ShroudVM) {
    var showSide by remember { mutableStateOf(false) }
    var tab by remember { mutableIntStateOf(0) }
    var searchQ by remember { mutableStateOf("") }
    var fullscreenMsg by remember { mutableStateOf<Msg?>(null) }
    var pendingDelete by remember { mutableStateOf<Msg?>(null) }
    var safetyNumber by remember { mutableStateOf<String?>(null) }
    var showLink by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }
    val ctx = androidx.compose.ui.platform.LocalContext.current

    if (showSettings) {
        SettingsDialog(vm, onDismiss = { showSettings = false }, onLinkDevice = {
            showSettings = false; showLink = true
        })
    }

    if (showLink) {
        var pasted by remember { mutableStateOf("") }
        var err by remember { mutableStateOf<String?>(null) }
        val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
        AlertDialog(
            onDismissRequest = { showLink = false },
            confirmButton = { TextButton(onClick = { showLink = false }) { Text("Close") } },
            title = { Text("Link another device") },
            text = {
                Column {
                    Text(
                        "End-to-end encrypted via ephemeral X25519. The server only " +
                        "relays opaque ciphertext and forgets it after pickup. 5-min TTL.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                    Text("Generate code (on the existing device)", fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
                    Button(
                        onClick = { vm.generateLinkCode { msg -> err = msg } },
                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                    ) { Text("Generate link code") }
                    if (vm.linkCode.isNotEmpty()) {
                        OutlinedTextField(
                            value = vm.linkCode,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Link code") },
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            singleLine = false,
                            maxLines = 3,
                        )
                        TextButton(
                            onClick = {
                                clipboard.setText(androidx.compose.ui.text.AnnotatedString(vm.linkCode))
                            },
                            modifier = Modifier.padding(top = 4.dp),
                        ) { Text("Copy", color = MaterialTheme.colorScheme.primary) }
                    }
                    Spacer(Modifier.height(16.dp))
                    Text("Accept code (on the new device)", fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
                    OutlinedTextField(
                        value = pasted,
                        onValueChange = { pasted = it },
                        label = { Text("Paste link code") },
                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                        singleLine = false,
                    )
                    Button(
                        onClick = { vm.acceptLinkCode(pasted.trim()) { msg -> err = msg } },
                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                    ) { Text("Accept code") }
                    if (vm.linkStatus.isNotEmpty()) {
                        Spacer(Modifier.height(12.dp))
                        Text(vm.linkStatus, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurface)
                    }
                    if (err != null) {
                        Text(err!!, color = MaterialTheme.colorScheme.error, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
                    }
                }
            },
        )
    }

    safetyNumber?.let { number ->
        AlertDialog(
            onDismissRequest = { safetyNumber = null },
            confirmButton = { TextButton(onClick = { safetyNumber = null }) { Text("OK") } },
            title = { Text("Safety number") },
            text = {
                Column {
                    Text(
                        text = number,
                        fontSize = 24.sp,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(vertical = 12.dp),
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    )
                    Text(
                        "Compare this number with the other person in person, over a phone call, or any other trusted channel. If both sides see the same number, the connection is free of MITM.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
        )
    }

    // v2.4.5 — switched from GetContent() to PickVisualMedia(): the
    // legacy content picker requires READ_MEDIA_IMAGES on Android 13+
    // and was silently no-op'ing on some devices. PickVisualMedia is
    // the modern photo-picker that needs no runtime permission.
    val pickImage = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        if (uri != null) vm.sendImage(uri)
    }
    val ctxLocal = androidx.compose.ui.platform.LocalContext.current

    LaunchedEffect(Unit) { vm.ownDevices() }

    Scaffold(
        topBar = {
            TopAppBar(
                // v2.4.5 — title removed per user request; signed-in username
                // remains in the trailing actions row so people know which
                // account they're using.
                title = { },
                actions = {
                    Text(vm.username, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    TooltipIconButton(
                        tip = "Verify safety number with this contact",
                        onClick = { vm.computeSafetyNumber { fp -> safetyNumber = fp } },
                        enabled = vm.selectedRecipient.isNotBlank(),
                        icon = Icons.Filled.Lock,
                        contentDesc = "Verify safety number",
                    )
                    TooltipIconButton(
                        tip = "Search and pick a contact",
                        onClick = { vm.ownDevices(); tab = 0; showSide = true },
                        icon = Icons.Filled.Search,
                        contentDesc = "Contacts",
                    )
                    TooltipIconButton(
                        tip = "Open groups",
                        onClick = { vm.loadGroups(); tab = 2; showSide = true },
                        icon = Icons.Filled.Share,
                        contentDesc = "Groups",
                    )
                    TooltipIconButton(
                        tip = "App settings",
                        onClick = { showSettings = true },
                        icon = Icons.Filled.Settings,
                        contentDesc = "Settings",
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface)
            )
        },
        bottomBar = {
            Column {
                // v2.4.2 — maintenance banner identical wording to Windows
                // v2.4.1. Sits above the input; only visible while the
                // server has flipped the maintenance flag.
                if (vm.maintenanceMode) {
                    Surface(
                        color = Color(0xFFB00020),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            "Server is undergoing maintenance — messaging is disabled for security.",
                            modifier = Modifier.fillMaxWidth().padding(8.dp),
                            color = Color.White,
                            fontSize = 13.sp,
                            fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        )
                    }
                }
                Text(vm.connStatus, fontSize = 10.sp, color = vm.connColor, modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp))
                Surface(color = MaterialTheme.colorScheme.surface, tonalElevation = 3.dp) {
                    Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        IconButton(
                            onClick = {
                                if (vm.selectedRecipient.isBlank()) {
                                    android.widget.Toast.makeText(
                                        ctxLocal, "Pick a contact first", android.widget.Toast.LENGTH_SHORT
                                    ).show()
                                } else {
                                    pickImage.launch(
                                        androidx.activity.result.PickVisualMediaRequest(
                                            ActivityResultContracts.PickVisualMedia.ImageOnly
                                        )
                                    )
                                }
                            },
                            enabled = !vm.maintenanceMode,
                        ) { Icon(Icons.Filled.Add, "Attach image", tint = MaterialTheme.colorScheme.primary) }
                        // 3x taller multi-line input matching the Windows v2.4.1
                        // 108px bump. minLines=3 gives ~3 lines of visible text;
                        // user can keep typing past that and the field scrolls.
                        OutlinedTextField(
                            value = vm.currentMessage,
                            onValueChange = { vm.currentMessage = it },
                            placeholder = {
                                Text(if (vm.maintenanceMode)
                                    "Server in maintenance — messaging disabled for security"
                                    else "Message...")
                            },
                            modifier = Modifier.weight(1f),
                            minLines = 3,
                            maxLines = 6,
                            enabled = !vm.maintenanceMode,
                            colors = if (vm.maintenanceMode) {
                                androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                                    disabledTextColor = Color(0xFFff8a8a),
                                    disabledBorderColor = Color(0xFFB00020),
                                    disabledContainerColor = Color(0x33B00020),
                                )
                            } else androidx.compose.material3.OutlinedTextFieldDefaults.colors(),
                        )
                        IconButton(
                            onClick = { vm.send() },
                            enabled = vm.currentMessage.isNotBlank() && !vm.maintenanceMode,
                        ) { Icon(Icons.Filled.Send, "Send", tint = MaterialTheme.colorScheme.primary) }
                    }
                }
            }
        }
    ) { pad ->
        Box(Modifier.fillMaxSize().padding(pad)) {
            LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                items(vm.messages) { msg ->
                    val isMe = msg.sender == vm.deviceID
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (isMe) Arrangement.End else Arrangement.Start) {
                        Surface(color = if (isMe) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.medium, modifier = Modifier.widthIn(max = 280.dp)) {
                            Column(Modifier.padding(8.dp)) {
                                if (msg.imagePath != null) {
                                    val bm = remember(msg.imagePath) {
                                        android.graphics.BitmapFactory.decodeFile(msg.imagePath)
                                    }
                                    if (bm != null) {
                                        Image(
                                            bitmap = bm.asImageBitmap(),
                                            contentDescription = "Sent image",
                                            modifier = Modifier
                                                .sizeIn(maxWidth = 260.dp, maxHeight = 320.dp)
                                                .clip(MaterialTheme.shapes.small)
                                                .combinedClickable(
                                                    onClick = { fullscreenMsg = msg },
                                                    onLongClick = { pendingDelete = msg }
                                                ),
                                            contentScale = ContentScale.Fit
                                        )
                                    } else {
                                        Text("[image unavailable]", color = if (isMe) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface)
                                    }
                                } else if (msg.body.isNotEmpty()) {
                                    val onCol = if (isMe) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
                                    Text(
                                        text = mdToAnnotated(msg.body, onCol),
                                        color = onCol,
                                    )
                                }
                                Text((msg.name ?: vm.username).take(16), fontSize = 9.sp, color = (if (isMe) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface).copy(alpha = 0.5f))
                            }
                        }
                    }
                }
            }
            if (showSide) {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background.copy(alpha = 0.95f)) {
                    Column(Modifier.padding(16.dp)) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(if (tab == 0) "Contacts" else "Groups", style = MaterialTheme.typography.titleMedium)
                            IconButton(onClick = { showSide = false }) { Icon(Icons.Filled.Close, "Close") }
                        }
                        if (tab == 0) {
                            OutlinedTextField(searchQ, { searchQ = it; if (it.length >= 2) vm.search(it) }, placeholder = { Text("Search...") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                            Spacer(Modifier.height(8.dp))
                        }
                        LazyColumn { items(vm.sideList) { item ->
                            TextButton(onClick = {
                                vm.selectedRecipient = item.substringAfter("(").substringBefore(")")
                                if (vm.selectedRecipient.isEmpty()) vm.selectedRecipient = item
                                showSide = false
                            }) { Text(item, color = MaterialTheme.colorScheme.onSurface) }
                        }}
                    }
                }
            }
        }
    }

    /* Fullscreen image viewer with a clearly-visible orange X close button
       in the top-right corner and a Delete button in the bottom-right. */
    fullscreenMsg?.let { msg ->
        Dialog(
            onDismissRequest = { fullscreenMsg = null },
            properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnBackPress = true)
        ) {
            Box(Modifier.fillMaxSize().background(Color(0xEE000000))) {
                val bm = remember(msg.imagePath) {
                    msg.imagePath?.let { android.graphics.BitmapFactory.decodeFile(it) }
                }
                if (bm != null) {
                    Image(
                        bitmap = bm.asImageBitmap(),
                        contentDescription = "Image",
                        modifier = Modifier.fillMaxSize().padding(32.dp),
                        contentScale = ContentScale.Fit
                    )
                }
                /* X close button — bright orange, white border, top-right. */
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(16.dp)
                        .size(56.dp)
                        .clip(androidx.compose.foundation.shape.CircleShape)
                        .background(Color(0xFFff8c1e))
                        .combinedClickable(
                            onClick = { fullscreenMsg = null },
                            onLongClick = { fullscreenMsg = null }
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Filled.Close, contentDescription = "Close",
                         tint = Color.Black, modifier = Modifier.size(32.dp))
                }
                /* Delete button — bottom-right. */
                Button(
                    onClick = { pendingDelete = msg; fullscreenMsg = null },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xCC551515), contentColor = Color(0xFFffaaaa)),
                    modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
                ) { Text("Delete") }
            }
        }
    }

    pendingDelete?.let { msg ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Delete image") },
            text = { Text("Permanently delete this image for both you and the recipient?") },
            confirmButton = {
                TextButton(onClick = { vm.deleteImage(msg); pendingDelete = null }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("Cancel") } }
        )
    }
}

/**
 * Markdown → AnnotatedString. Mirrors the Windows v2.1 mdToHtml subset:
 * **bold**, *italic*, `code`, and bare https URLs styled distinctly so
 * users can spot them. URLs aren't clickable yet — same level as the
 * Windows client which only styles them.
 */
private fun mdToAnnotated(s: String, baseColor: androidx.compose.ui.graphics.Color): androidx.compose.ui.text.AnnotatedString {
    data class Span(val start: Int, val end: Int, val style: androidx.compose.ui.text.SpanStyle, val text: String)
    val out = StringBuilder()
    val spans = mutableListOf<Span>()

    // Walk char by char. Heuristic, not a CommonMark parser — same level
    // of fidelity the Windows mdToHtml() helper provides.
    var i = 0
    while (i < s.length) {
        if (i + 1 < s.length && s[i] == '*' && s[i + 1] == '*') {
            val close = s.indexOf("**", i + 2)
            if (close > i + 2) {
                val body = s.substring(i + 2, close)
                val st = out.length; out.append(body)
                spans += Span(st, out.length, androidx.compose.ui.text.SpanStyle(fontWeight = androidx.compose.ui.text.font.FontWeight.Bold), body)
                i = close + 2; continue
            }
        }
        if (s[i] == '*') {
            val close = s.indexOf('*', i + 1)
            if (close > i + 1 && !s.substring(i + 1, close).contains('\n')) {
                val body = s.substring(i + 1, close)
                val st = out.length; out.append(body)
                spans += Span(st, out.length, androidx.compose.ui.text.SpanStyle(fontStyle = androidx.compose.ui.text.font.FontStyle.Italic), body)
                i = close + 1; continue
            }
        }
        if (s[i] == '`') {
            val close = s.indexOf('`', i + 1)
            if (close > i + 1) {
                val body = s.substring(i + 1, close)
                val st = out.length; out.append(body)
                spans += Span(st, out.length, androidx.compose.ui.text.SpanStyle(
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    background = androidx.compose.ui.graphics.Color(0x33888888),
                ), body)
                i = close + 1; continue
            }
        }
        if (s.startsWith("https://", i) || s.startsWith("http://", i)) {
            val end = s.substring(i).indexOfFirst { it == ' ' || it == '\n' || it == '\t' }.let {
                if (it < 0) s.length else i + it
            }
            val body = s.substring(i, end)
            val st = out.length; out.append(body)
            spans += Span(st, out.length, androidx.compose.ui.text.SpanStyle(
                color = androidx.compose.ui.graphics.Color(0xFF6FB6FF),
                textDecoration = androidx.compose.ui.text.style.TextDecoration.Underline,
            ), body)
            i = end; continue
        }
        out.append(s[i]); i++
    }

    return androidx.compose.ui.text.buildAnnotatedString {
        append(out.toString())
        for (sp in spans) addStyle(sp.style, sp.start, sp.end)
    }
}

/**
 * Settings dialog — mirror of the Windows v2.1.0 Settings dialog. Three
 * tabs:
 *   Appearance — theme preset picker. Selection persists via vm.setTheme().
 *   Messages   — disappearing-messages toggle + minutes/seconds spinners.
 *   Security   — link a new device + safety-number reminder.
 *   Help       — quick documentation matching the Windows Help tab.
 */
@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun SettingsDialog(vm: ShroudVM, onDismiss: () -> Unit, onLinkDevice: () -> Unit) {
    var tab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Appearance", "Messages", "Security", "Help")

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        title = { Text("Settings") },
        text = {
            Column(Modifier.fillMaxWidth().heightIn(min = 380.dp, max = 560.dp)) {
                // v2.4.5 — TabRow can squeeze tab labels until they wrap
                // character-by-character (looks like vertical text). Fix:
                // ScrollableTabRow gives each tab its natural width; the
                // Text() inside uses maxLines=1 + softWrap=false as a belt.
                androidx.compose.material3.ScrollableTabRow(
                    selectedTabIndex = tab,
                    edgePadding = 0.dp,
                ) {
                    tabs.forEachIndexed { i, label ->
                        androidx.compose.material3.Tab(
                            selected = tab == i,
                            onClick = { tab = i },
                            text = {
                                Text(
                                    label,
                                    fontSize = 12.sp,
                                    maxLines = 1,
                                    softWrap = false,
                                )
                            },
                        )
                    }
                }
                Spacer(Modifier.height(12.dp))
                Box(Modifier.fillMaxWidth().weight(1f)
                    .verticalScroll(rememberScrollState())) {
                    when (tab) {
                        0 -> AppearanceTab(vm)
                        1 -> MessagesTab(vm)
                        2 -> SecurityTab(vm, onLinkDevice)
                        else -> HelpTab()
                    }
                }
            }
        },
    )
}

@Composable
private fun AppearanceTab(vm: ShroudVM) {
    Column {
        Text("Theme", style = MaterialTheme.typography.titleSmall)
        Text("Applies on next app open for the full effect, but most surfaces update immediately.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 8.dp))
        THEME_NAMES.forEach { name ->
            Row(
                Modifier.fillMaxWidth().clickable { vm.setTheme(name) }.padding(vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = vm.themeName == name, onClick = { vm.setTheme(name) })
                Spacer(Modifier.width(8.dp))
                Text(name)
            }
        }
    }
}

@Composable
private fun MessagesTab(vm: ShroudVM) {
    var enabled by remember { mutableStateOf(vm.disappearEnabled) }
    var mins by remember { mutableIntStateOf(vm.disappearSeconds / 60) }
    var secs by remember { mutableIntStateOf(vm.disappearSeconds % 60) }
    LaunchedEffect(enabled, mins, secs) {
        vm.setDisappearing(enabled, mins * 60 + secs)
    }

    Column {
        Text("Disappearing messages", style = MaterialTheme.typography.titleSmall)
        Text("Outgoing messages auto-delete after the timer. Server enforces; clients pick the timer.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            androidx.compose.material3.Switch(checked = enabled, onCheckedChange = { enabled = it })
            Spacer(Modifier.width(8.dp))
            Text(if (enabled) "Enabled" else "Disabled (default)")
        }
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("After: ", modifier = Modifier.padding(end = 4.dp))
            NumberStepper(value = mins, onChange = { mins = it.coerceIn(0, 1440) }, suffix = "min", enabled = enabled)
            Spacer(Modifier.width(8.dp))
            NumberStepper(value = secs, onChange = { secs = it.coerceIn(0, 59) }, suffix = "sec", enabled = enabled)
        }
        Spacer(Modifier.height(18.dp))
        Text("Rich text", style = MaterialTheme.typography.titleSmall)
        Text("Incoming messages render **bold**, *italic*, `code`, and clickable URLs.\nWindows users get the same. Emoji works via your system keyboard.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun NumberStepper(value: Int, onChange: (Int) -> Unit, suffix: String, enabled: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = { onChange(value - 1) }, enabled = enabled) {
            Icon(Icons.Filled.Close, "decrement", modifier = Modifier.rotate(45f))
        }
        Text(
            "$value $suffix",
            modifier = Modifier.widthIn(min = 60.dp),
            color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
        IconButton(onClick = { onChange(value + 1) }, enabled = enabled) {
            Icon(Icons.Filled.Add, "increment")
        }
    }
}

@Composable
private fun SecurityTab(vm: ShroudVM, onLinkDevice: () -> Unit) {
    Column {
        Text("Multi-device", style = MaterialTheme.typography.titleSmall)
        Text("Link this account to another device using a short code. The server only sees ephemeral X25519 pubkeys + opaque ciphertext.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(8.dp))
        Button(onClick = onLinkDevice) { Text("Link another device…") }
        Spacer(Modifier.height(18.dp))
        Text("Safety numbers", style = MaterialTheme.typography.titleSmall)
        Text("Tap the shield icon at the top of the chat with a contact selected to see a 30-digit number. Compare it with them in person to defeat MITM.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(18.dp))
        Text("Screen-capture protection", style = MaterialTheme.typography.titleSmall)
        Text("FLAG_SECURE is set on this activity — screenshots and screen-share record a black frame instead of the chat.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun HelpTab() {
    Column {
        Text("SHROUD — Quick reference", style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(8.dp))
        @Composable fun section(t: String, body: String) {
            Text(t, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            Text(body, fontSize = 12.sp, modifier = Modifier.padding(top = 2.dp, bottom = 10.dp))
        }
        section("How conversations work",
            "Every message is encrypted on your device before it touches the server. The server can route ciphertext and not read it.")
        section("Verifying contacts",
            "Open a chat → tap the shield icon at the top. A 30-digit number appears. Compare it out-of-band; same on both sides means no MITM.")
        section("Disappearing messages",
            "Settings → Messages. Toggle on, pick minutes/seconds. The server's sweeper deletes expired messages. Default is OFF.")
        section("Theme",
            "Settings → Appearance. Pick from preset palettes. Choice survives app restart.")
        section("Linking a second device",
            "Settings → Security → Link another device. Follow the short-code prompts. 5-minute TTL.")
        section("If you suspect coercion",
            "Five wrong-password attempts auto-wipes the account on the server side. Cannot be undone.")
        section("Troubleshooting",
            "'Server in maintenance' — operator paused the system, sends are 503'd. Wait + retry.\n" +
            "'Server offline' — heartbeat is failing; check connectivity.")
        section("Source",
            "https://github.com/ExposingTheBadge/Shroud")
    }
}
