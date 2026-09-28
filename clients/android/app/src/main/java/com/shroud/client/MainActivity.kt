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
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
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
    /** Operator diagnostics X25519 pubkey, 32 bytes hex.
     *  Live operator key. Anonymous error reports sealed with this
     *  pubkey land in the operator's diagnostics inbox; only the
     *  operator's private key (held offline, never on a relay) can
     *  decrypt them. To rotate: regenerate via
     *  `python -m tools.diagnostics_inbox keygen`, replace the hex
     *  here AND in ShroudApp.swift + main.cpp, ship a release,
     *  retire the old key file. Future versions will fetch this from
     *  a signed operator manifest instead of hardcoding it. */
    private val OPERATOR_DIAG_PUBKEY_HEX =
        "7191a786437e38ebe616b9508b3110afb1a635e08ac034a330093acca708fd54"

    /** SHA-256 pin of the operator's manifest-signing Ed25519 pubkey.
     *  Clients fetch the signed manifest on first launch, verify its
     *  signature with the published pubkey, and require
     *  SHA-256(pubkey) == this pin before accepting any field
     *  (relay URL, diag pubkey, federation roster, sticker CDN).
     *  Rotation requires shipping a release with a new pin. */
    private val SHROUD_MANIFEST_PIN =
        "2fb11de360a0cf6baa35d6785c3945658ae6d64823041729798a2b689ce00ca0"

    /** Default-on Tor preference. The operator manifest (v2+) also
     *  publishes prefer_tor_by_default = true. Clients honor it unless
     *  the user explicitly disables Tor in Settings. The client needs a
     *  reachable SOCKS5 proxy (Orbot or equivalent on Android) to ride
     *  the .onion endpoints; if the proxy isn't reachable the client
     *  falls back to the clearnet endpoint. */
    private val PREFER_TOR_DEFAULT = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        NetworkClient.init(applicationContext)
        // Install the anonymous error reporter ONCE per process so any
        // uncaught exception during composition / IO triggers a sealed
        // report to the operator's diagnostics pubkey. Best-effort —
        // failure to install never blocks app startup.
        try {
            val opPub = OPERATOR_DIAG_PUBKEY_HEX.chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
            if (opPub.any { it != 0.toByte() }) {
                ErrorReporter.install(applicationContext, opPub)
            }
        } catch (_: Throwable) { /* never block startup */ }

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
    /* Conversations: one history per contact, keyed by username. There
     * used to be a single list shared by every contact, so switching chats
     * showed everyone's messages mixed together. In memory only, as before. */
    var conversations by mutableStateOf(mapOf<String, List<Msg>>())
    var unread by mutableStateOf(mapOf<String, Int>())
    var openPeer by mutableStateOf<String?>(null)
    /** One-line notices for the snackbar ("Message not sent: …"). */
    var notice by mutableStateOf<String?>(null)
    var contacts by mutableStateOf(listOf<Contact>())
    var incomingRequests by mutableStateOf(listOf<FriendRequest>())
    var outgoingPending by mutableStateOf(listOf<String>())
    var searchResult by mutableStateOf<String?>(null)
    var searchDone by mutableStateOf(false)
    val messages: List<Msg> get() = conversations[openPeer] ?: emptyList()
    var myDevices by mutableStateOf(listOf<String>())
    private val peerCache = java.util.concurrent.ConcurrentHashMap<String, Pair<Long, PeerDevice>>()
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

    /** Fetch a peer device's long-term X25519 identity.
     *
     *  This used /ratchet/bundle, which hands out and permanently consumes
     *  one of the peer's one-time prekeys on every call. It ran on every
     *  4-second heartbeat, so an open chat burned through a contact's
     *  whole prekey supply in about two minutes. /ratchet/identity returns
     *  the same key and consumes nothing. */
    private suspend fun fetchPeerX25519(deviceId: String): ByteArray? {
        return try {
            val r = NetworkClient.get("/api/v1/ratchet/identity/$deviceId")
            val hex = r.optString("x25519_pub", "")
            if (hex.isBlank()) null else hex.hexToBytes()
        } catch (_: Throwable) {
            null
        }
    }

    /** A contact's most recently active device, with the keys needed to
     *  write to it. Cached for five minutes. */
    data class PeerDevice(val deviceId: String, val publicKeyHex: String, val x25519: ByteArray?)

    private suspend fun resolvePeer(username: String, refresh: Boolean = false): PeerDevice? {
        val now = System.currentTimeMillis()
        val hit = peerCache[username]
        if (!refresh && hit != null && now - hit.first < 300_000) return hit.second
        val r = NetworkClient.post("/api/v1/contacts/devices", JSONObject().apply {
            put("device_id", deviceID); put("contact_username", username)
        })
        val devs = r.optJSONArray("devices") ?: return null
        if (devs.length() == 0) return null
        val d = devs.getJSONObject(0)   // relay lists the most recently active device first
        val id = d.getString("id")
        val pd = PeerDevice(id, d.optString("public_key", ""), fetchPeerX25519(id))
        peerCache[username] = now to pd
        return pd
    }

    /** Safety number for the open conversation. */
    fun computeSafetyNumber(onResult: (String?) -> Unit) {
        val peer = openPeer ?: run { onResult(null); return }
        viewModelScope.launch(Dispatchers.IO) {
            val fp = try {
                val theirPub = resolvePeer(peer)?.x25519
                val mine = loadMyX25519Identity()
                if (theirPub == null || mine == null) null else SafetyNumber.compute(mine.second, theirPub)
            } catch (_: Throwable) { null }
            withContext(Dispatchers.Main) { onResult(fp) }
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
            var beat = 0
            while (isRegistered) {
                try {
                    val r = withContext(Dispatchers.IO) {
                        NetworkClient.post("/api/v1/heartbeat", JSONObject().apply { put("device_id", deviceID) })
                    }
                    val beatOk = r.optString("beat") == "ok"
                    maintenanceMode = r.optBoolean("maintenance_mode", false)
                    when {
                        maintenanceMode -> { connStatus = "The relay is in maintenance. Sending is paused."; connColor = Color(0xFFE0A030) }
                        beatOk          -> { connStatus = "Connected"; connColor = Color(0xFF2ED573) }
                        r.optInt("_status") == 401 -> { connStatus = "This device is no longer signed in. Sign in again."; connColor = Color(0xFFFF4757) }
                        else            -> { connStatus = "Connecting…"; connColor = Color(0xFF888888) }
                    }
                    if (beat % 8 == 0) refreshContacts()
                    fetchAndDecrypt()
                } catch (e: Exception) {
                    connStatus = NetworkClient.describe(e); connColor = Color(0xFFFF4757)
                }
                beat++
                delay(4000)
            }
        }
    }

    /**
     * Collect queued envelopes from both delivery paths and decrypt them.
     *
     * The anonymous path hands back the sealed *envelope* (still ratchet-
     * or AES-encrypted). This used to be parsed as if it were the final
     * plaintext, found no "body", and was dropped, so every message that
     * arrived over the anonymous path vanished. Both paths now feed the
     * same envelope handler.
     */
    private suspend fun fetchAndDecrypt() {
        if (deviceID.isBlank()) return
        val incoming = mutableListOf<Pair<String, JSONObject>>()   // (sender device, envelope)

        if (useAnonRouting) {
            try {
                val myId = loadMyX25519Identity()
                if (myId != null) {
                    val (myPriv, myPub) = myId
                    val peers = contacts.mapNotNull { c ->
                        val x = try { resolvePeer(c.username)?.x25519 } catch (_: Throwable) { null }
                        x?.let { Triple(it, Ratchet.x25519Dh(myPriv, it), c.username) }
                    }
                    if (peers.isNotEmpty()) {
                        for ((_, bytes) in NetworkClient.fetchAnonForContacts(myPriv, myPub, peers)) {
                            val env = try { JSONObject(String(bytes, Charsets.UTF_8)) } catch (_: Throwable) { continue }
                            incoming += env.optString("sender", "") to env
                        }
                    }
                }
            } catch (_: Throwable) { /* the legacy queue below still runs */ }
        }

        val r = withContext(Dispatchers.IO) {
            NetworkClient.post("/api/v1/messages/fetch", JSONObject().apply { put("device_id", deviceID) })
        }
        val arr = r.optJSONArray("messages")
        if (arr != null) for (i in 0 until arr.length()) {
            val m = arr.optJSONObject(i) ?: continue
            val env: JSONObject = when (val f = m.opt("envelope")) {
                is JSONObject -> f
                is String -> try { JSONObject(f) } catch (_: Throwable) { continue }
                else -> continue
            }
            incoming += m.optString("sender_device_id", env.optString("sender", "")) to env
        }

        for ((sender, env) in incoming) {
            if (sender.isBlank()) continue
            try { handleEnvelope(sender, env) } catch (_: Throwable) {
                notice = "A message arrived that couldn't be decrypted."
            }
        }
    }

    private suspend fun handleEnvelope(sender: String, env: JSONObject) {
        val ctx = getApplication<Application>()
        val plain: ByteArray? = if (env.optInt("ratchet", 0) == 1) {
            val hex = env.optString("ciphertext", "")
            if (hex.isBlank()) null else RatchetSession.decryptFromPeer(ctx, sender, hex)
        } else runCatching {
            val pkResp = NetworkClient.post("/api/v1/devices/$sender/pubkey", JSONObject())
            val pubHex = pkResp.optString("public_key", "")
            if (pubHex.isBlank()) null else {
                val peerPub = CryptoProvider.importPublicKey(pubHex.hexToBytes())
                val sk = CryptoProvider.deriveSessionKey(identityKey!!.private, peerPub)
                CryptoProvider.decryptAESGCM(sk, env.getString("nonce").hexToBytes(),
                    env.getString("ciphertext").hexToBytes(), env.getString("tag").hexToBytes())
            }
        }.getOrNull()
        if (plain == null) {
            notice = "A message arrived that couldn't be decrypted."
            return
        }
        val obj = JSONObject(String(plain))
        val name = obj.optString("name", "").trim().lowercase()
        val peer = name.ifBlank { sender }
        val body = obj.optString("body", "")
        val ts = obj.optLong("ts", 0L).let { if (it > 0) it * 1000 else System.currentTimeMillis() }
        val isImage = obj.optBoolean("is_image", false) || obj.optString("type", "") == "image"
        if (isImage) {
            val fid = obj.optString("file_id", "")
            val localPath = if (fid.isNotBlank()) decryptInlineImage(sender, fid, obj.optString("name", "")) else null
            if (localPath != null) {
                addMsg(peer, Msg(sender, "", imagePath = localPath, fileId = fid, name = name.ifBlank { null }, ts = ts))
            } else {
                addMsg(peer, Msg(sender, "An image arrived but couldn't be downloaded.", name = name.ifBlank { null }, ts = ts, system = true))
            }
        } else if (body.isNotBlank()) {
            val gid = obj.optString("group_id", "")
            addMsg(peer, Msg(sender, if (gid.isNotBlank()) "[group] $body" else body, name = name.ifBlank { null }, ts = ts))
        }
    }

    /* ── Conversations ───────────────────────────────────────────────── */

    fun addMsg(peer: String, msg: Msg) {
        conversations = conversations + (peer to ((conversations[peer] ?: emptyList()) + msg))
        if (peer != openPeer && !msg.outgoing && !msg.system) unread = unread + (peer to ((unread[peer] ?: 0) + 1))
        if (contacts.none { it.username == peer }) contacts = contacts + Contact(peer, friend = false)
    }

    private fun updateMsg(peer: String, id: String, f: (Msg) -> Msg) {
        val list = conversations[peer] ?: return
        conversations = conversations + (peer to list.map { if (it.id == id) f(it) else it })
    }

    fun openChat(peer: String) {
        openPeer = peer
        unread = unread - peer
        selectedRecipient = ""
        viewModelScope.launch(Dispatchers.IO) {
            val pd = try { resolvePeer(peer, refresh = true) } catch (e: Throwable) { notice = NetworkClient.describe(e); null }
            selectedRecipient = pd?.deviceId ?: ""
            if (pd == null) notice = "$peer hasn't signed in on any device yet, so messages can't be delivered."
        }
    }
    fun closeChat() { openPeer = null; selectedRecipient = "" }

    /* ── Contacts and friend requests ──────────────────────────────── */
    data class Contact(val username: String, val friend: Boolean)
    data class FriendRequest(val id: String, val from: String, val reason: String)

    fun refreshContacts() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/friends/list", JSONObject().apply { put("device_id", deviceID) })
                if (r.optInt("_status") !in 200..299) return@launch
                val friends = r.optJSONArray("friends")
                val names = mutableListOf<String>()
                if (friends != null) for (i in 0 until friends.length()) names += friends.getJSONObject(i).optString("username")
                val inc = r.optJSONArray("incoming")
                val reqs = mutableListOf<FriendRequest>()
                if (inc != null) for (i in 0 until inc.length()) inc.getJSONObject(i).let {
                    reqs += FriendRequest(it.optString("id"), it.optString("from"), it.optString("reason"))
                }
                val out = r.optJSONArray("outgoing")
                val pending = mutableListOf<String>()
                if (out != null) for (i in 0 until out.length()) out.getJSONObject(i).let {
                    if (it.optString("status") == "pending") pending += it.optString("to")
                }
                val others = contacts.filter { c -> !c.friend && c.username !in names }
                contacts = names.filter { it.isNotBlank() }.map { Contact(it, friend = true) } + others
                incomingRequests = reqs
                outgoingPending = pending
            } catch (_: Throwable) { }
        }
    }

    fun addContact(target: String) {
        val t = target.trim().lowercase()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/friends/request", JSONObject().apply {
                    put("device_id", deviceID); put("target_username", t); put("reason", "")
                })
                notice = when (r.optInt("_status")) {
                    in 200..299 -> "Contact request sent to $t"
                    404 -> "There's no account called $t on this relay"
                    409 -> r.optString("detail", "Already requested")
                    else -> "Couldn't send the request: ${detailOf(r)}"
                }
                refreshContacts()
            } catch (e: Throwable) { notice = NetworkClient.describe(e) }
        }
    }

    fun respondRequest(req: FriendRequest, accept: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/friends/respond", JSONObject().apply {
                    put("device_id", deviceID); put("request_id", req.id); put("accept", accept)
                })
                notice = if (r.optInt("_status") in 200..299)
                    (if (accept) "${req.from} is now a contact" else "Request from ${req.from} declined")
                    else "Couldn't answer the request: ${detailOf(r)}"
                refreshContacts()
            } catch (e: Throwable) { notice = NetworkClient.describe(e) }
        }
    }

    /** Human-readable reason from a relay error response. Catalogued
     *  errors arrive as {error_code, title, detail}; others as a string. */
    private fun detailOf(r: JSONObject): String {
        val d = r.opt("detail")
        return when (d) {
            is JSONObject -> listOf(d.optString("title"), d.optString("reason")).filter { it.isNotBlank() }
                .joinToString(": ").ifBlank { d.optString("error_code", "error") } +
                d.optString("error_code").let { if (it.isNotBlank()) " ($it)" else "" }
            is String -> d
            else -> "HTTP ${r.optInt("_status")}"
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
                        onError("The relay's identity has changed since you last connected, which can mean " +
                                "someone is impersonating it. Not signing in.\n\nExpected $pinned\nGot $fp")
                        return@launch
                    }
                    ServerPin.Verdict.NETWORK_ERROR -> { onError("Can't reach the relay at ${NetworkClient.RELAY}. Check your connection and try again."); return@launch }
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
                    refreshContacts()
                } else {
                    onError(when (authR.optInt("_status")) {
                        401 -> if (isReg) detailOf(authR) else
                               "Wrong username or password. Accounts belong to one relay, so if you haven't " +
                               "created one on this relay yet, choose Create account."
                        409 -> "That username is taken. Pick another."
                        403 -> detailOf(authR)
                        429 -> "Too many attempts. Wait a few minutes and try again."
                        else -> detailOf(authR)
                    })
                }
            } catch (ex: Exception) { onError(NetworkClient.describe(ex)) }
        }
    }

    /**
     * Send the composer text to the open conversation.
     *
     * This used to look the recipient up with contact_username = *our own*
     * username, i.e. among our own devices, and silently return when it
     * wasn't found. Picking a person from search stored their username
     * where a device id belonged. Net effect: messages to anyone but your
     * own other devices were dropped without a word. The recipient is now
     * resolved from the contact's username, and the message shows as
     * sending, sent or failed (with a reason and a retry).
     */
    fun send() {
        val body = currentMessage.trim()
        val peer = openPeer ?: return
        if (body.isEmpty()) return
        currentMessage = ""
        val local = Msg(deviceID, body, name = username, outgoing = true, pending = true)
        addMsg(peer, local)
        deliverInBackground(peer, local)
    }

    fun retry(msg: Msg) {
        val peer = openPeer ?: return
        updateMsg(peer, msg.id) { it.copy(pending = true, failed = null) }
        deliverInBackground(peer, msg)
    }

    private fun deliverInBackground(peer: String, msg: Msg) {
        viewModelScope.launch(Dispatchers.IO) {
            val err = try { deliverText(peer, msg.body) } catch (e: Throwable) { NetworkClient.describe(e) }
            updateMsg(peer, msg.id) { it.copy(pending = false, failed = err) }
            if (err != null) notice = "Message not sent: $err"
        }
    }

    /** Encrypt and post one text message. Returns null on success or a
     *  readable reason on failure. */
    private suspend fun deliverText(peer: String, body: String): String? {
        val pd = resolvePeer(peer) ?: return "$peer hasn't signed in on any device yet."
        val pl = JSONObject().apply {
            put("body", body); put("name", username); put("sender", deviceID); put("ts", System.currentTimeMillis() / 1000)
        }.toString().toByteArray()
        val ctx = getApplication<Application>()
        // Prefer the Double Ratchet; fall back to the static-key envelope
        // when the peer has never published a ratchet identity.
        val ratchetHex = RatchetSession.encryptForPeer(ctx, pd.deviceId, pl)
        val env = if (ratchetHex != null) {
            val sig = java.security.MessageDigest.getInstance("SHA-256").digest(ratchetHex.hexToBytes())
            JSONObject().apply {
                put("ratchet", 1); put("sender", deviceID); put("ts", System.currentTimeMillis() / 1000)
                put("nonce", "0".repeat(24)); put("ciphertext", ratchetHex); put("tag", "0".repeat(32)); put("sig", sig.toHex())
            }
        } else {
            if (pd.publicKeyHex.isBlank()) return "$peer's device has no public key on the relay."
            val sk = CryptoProvider.deriveSessionKey(identityKey!!.private,
                CryptoProvider.importPublicKey(pd.publicKeyHex.hexToBytes()))
            val (iv, ct, tg) = CryptoProvider.encryptAESGCM(sk, pl)
            JSONObject().apply {
                put("sender", deviceID); put("ts", System.currentTimeMillis() / 1000)
                put("nonce", iv.toHex()); put("ciphertext", ct.toHex()); put("tag", tg.toHex())
                put("sig", CryptoProvider.hmacSign(sk, ct).toHex())
            }
        }
        val expiresIn = if (disappearEnabled && disappearSeconds > 0) disappearSeconds else null
        val myId = loadMyX25519Identity()
        val resp = if (useAnonRouting && myId != null && pd.x25519 != null) {
            NetworkClient.sendAnon(
                recipientPubkey = pd.x25519, myIdPubkey = myId.second,
                sharedRoot = Ratchet.x25519Dh(myId.first, pd.x25519),
                innerEnvelope = env.toString().toByteArray(Charsets.UTF_8),
                expiresInSeconds = expiresIn,
            )
        } else {
            NetworkClient.post("/api/v1/messages/send",
                JSONObject().apply { put("sender_device_id", deviceID); put("recipient_device_id", pd.deviceId); put("envelope", env.toString()) },
                if (expiresIn != null) mapOf("X-Expires-In" to expiresIn.toString()) else emptyMap())
        }
        val st = resp.optInt("_status", 200)
        if (st == 503) { maintenanceMode = true; return "the relay is in maintenance." }
        if (st !in 200..299) return detailOf(resp)
        return null
    }

    /** Send an image to the open conversation. Same recipient fix as send(). */
    fun sendImage(uri: android.net.Uri) {
        val peer = openPeer ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val app = getApplication<Application>()
                val pd = resolvePeer(peer) ?: run { notice = "$peer hasn't signed in on any device yet."; return@launch }
                val bytes = app.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return@launch
                if (bytes.size > 20 * 1024 * 1024) { notice = "That image is over 20 MB."; return@launch }

                // File key = SHA-256(my public-key blob); the recipient
                // derives the same key from the blob the relay stores.
                val pub = identityKey?.public?.encoded ?: return@launch
                val sk = javax.crypto.spec.SecretKeySpec(
                    java.security.MessageDigest.getInstance("SHA-256").digest(pub).copyOf(32), "AES")
                val (iv, ct, tag) = CryptoProvider.encryptAESGCM(sk, bytes)

                val mime = app.contentResolver.getType(uri) ?: "image/jpeg"
                val ext = when {
                    mime.endsWith("png") -> "png"; mime.endsWith("gif") -> "gif"
                    mime.endsWith("webp") -> "webp"; mime.endsWith("bmp") -> "bmp"; else -> "jpg"
                }
                val fname = "img_${System.currentTimeMillis()}.$ext"
                val meta = JSONObject().apply { put("name", fname); put("size", bytes.size); put("mime", mime); put("is_image", true) }
                val ur = NetworkClient.uploadFile("/api/v1/files/upload", iv + ct + tag, deviceID, pd.deviceId, meta.toString())
                val fileId = ur.optString("file_id", "")
                if (fileId.isEmpty()) { notice = "Image upload failed: ${detailOf(ur)}"; return@launch }

                val local = java.io.File(java.io.File(app.filesDir, "images").apply { mkdirs() }, "$fileId.$ext")
                local.writeBytes(bytes)

                if (pd.publicKeyHex.isBlank()) { notice = "$peer's device has no public key on the relay."; return@launch }
                val sessionKey = CryptoProvider.deriveSessionKey(identityKey!!.private,
                    CryptoProvider.importPublicKey(pd.publicKeyHex.hexToBytes()))
                val pl = JSONObject().apply {
                    put("type", "image"); put("file_id", fileId); put("name", fname); put("size", bytes.size)
                    put("mime", mime); put("is_image", true); put("body", "Sent image: $fname")
                }.toString().toByteArray()
                val (eiv, ect, etag) = CryptoProvider.encryptAESGCM(sessionKey, pl)
                val env = JSONObject().apply {
                    put("sender", deviceID); put("ts", System.currentTimeMillis() / 1000)
                    put("nonce", eiv.toHex()); put("ciphertext", ect.toHex())
                    put("tag", etag.toHex()); put("sig", CryptoProvider.hmacSign(sessionKey, ect).toHex())
                }
                val resp = NetworkClient.post("/api/v1/messages/send",
                    JSONObject().apply { put("sender_device_id", deviceID); put("recipient_device_id", pd.deviceId); put("envelope", env.toString()) },
                    if (disappearEnabled && disappearSeconds > 0) mapOf("X-Expires-In" to disappearSeconds.toString()) else emptyMap())
                val st = resp.optInt("_status", 200)
                if (st !in 200..299) {
                    if (st == 503) maintenanceMode = true
                    notice = "Image not sent: ${detailOf(resp)}"; return@launch
                }
                addMsg(peer, Msg(deviceID, "", imagePath = local.absolutePath, fileId = fileId, name = username, outgoing = true))
            } catch (e: Exception) { notice = "Image not sent: ${NetworkClient.describe(e)}" }
        }
    }

    /** Delete an image both locally and on the server. */
    fun deleteImage(msg: Msg) {
        val fid = msg.fileId ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                NetworkClient.deleteFile("/api/v1/files/$fid", deviceID)
                msg.imagePath?.let { java.io.File(it).delete() }
                conversations = conversations.mapValues { (_, list) ->
                    list.map { if (it.fileId == fid) it.copy(imagePath = null, body = "Image deleted", system = true) else it }
                }
            } catch (e: Exception) { notice = "Couldn't delete the image: ${NetworkClient.describe(e)}" }
        }
    }

    /** Exact-username lookup; the relay never lists or enumerates users. */
    fun search(q: String) {
        val query = q.trim().lowercase()
        searchDone = false; searchResult = null
        if (query.length < 3) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/contacts/search", JSONObject().apply { put("device_id", deviceID); put("query", query) })
                val arr = r.optJSONArray("users")
                searchResult = if (arr != null && arr.length() > 0) arr.getString(0) else null
            } catch (e: Exception) { notice = NetworkClient.describe(e) }
            searchDone = true
        }
    }

    /** This account's devices, for Settings → Security. */
    fun ownDevices() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/devices/list", JSONObject().apply { put("device_id", deviceID) })
                val arr = r.optJSONArray("devices"); val l = mutableListOf<String>()
                if (arr != null) for (i in 0 until arr.length()) arr.getJSONObject(i).let { d ->
                    val me = if (d.getString("id") == deviceID) " (this device)" else ""
                    l.add("${d.optString("name").ifBlank { "Unnamed" }} · ${d.optString("platform")}$me")
                }
                myDevices = l
            } catch (_: Exception) {}
        }
    }

    /** Forget this account on this phone. The account itself stays on
     *  the relay; sign in again with the same username and password. */
    fun signOut() {
        isRegistered = false
        deviceID = ""; username = ""; savedPassword = ""
        pinHash = null; pinFailCount = 0; pinLocked = false
        conversations = emptyMap(); unread = emptyMap(); contacts = emptyList(); openPeer = null
        incomingRequests = emptyList(); outgoingPending = emptyList()
        peerCache.clear()
        val theme = themeName
        prefs.edit().clear().putString("theme_name", theme).apply()
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
    val ts: Long = System.currentTimeMillis(),
    val outgoing: Boolean = false,
    val pending: Boolean = false,    // still being sent
    val failed: String? = null,      // why it wasn't sent, if it wasn't
    val system: Boolean = false,     // a notice, not something anyone wrote
    val id: String = java.util.UUID.randomUUID().toString(),
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
            Text("At least 4 digits. You'll enter it whenever the screen turns off " +
                 "or the app sits idle for a minute. Three wrong tries sign you out of this phone.",
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
            if (vm.pinFailCount > 0) Text(
                "${3 - vm.pinFailCount} attempt${if (3 - vm.pinFailCount == 1) "" else "s"} left before you're signed out of this phone",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.error)
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

/* ── Small shared pieces ─────────────────────────────────────────────── */

/** Letter avatar with a stable colour per name. */
@Composable
fun Avatar(name: String, size: androidx.compose.ui.unit.Dp = 40.dp) {
    val palette = listOf(0xFF5E81AC, 0xFFBF616A, 0xFFA3BE8C, 0xFFD08770, 0xFFB48EAD, 0xFF88C0D0, 0xFFEBCB8B, 0xFF8FBCBB)
    val c = Color(palette[(name.hashCode() and 0x7fffffff) % palette.size])
    Box(
        Modifier.size(size).clip(androidx.compose.foundation.shape.CircleShape).background(c),
        contentAlignment = Alignment.Center,
    ) {
        Text(name.take(1).uppercase().ifBlank { "?" }, color = Color.White,
            fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
            fontSize = (size.value * 0.42f).sp)
    }
}

@Composable
private fun CountBadge(n: Int) {
    Box(
        Modifier.clip(androidx.compose.foundation.shape.RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.primary)
            .padding(horizontal = 7.dp, vertical = 2.dp),
    ) { Text(if (n > 99) "99+" else n.toString(), color = MaterialTheme.colorScheme.onPrimary, fontSize = 11.sp) }
}

private val timeFmt = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
private val dayFmt = java.text.SimpleDateFormat("EEE d MMM", java.util.Locale.getDefault())
private fun dayLabel(ts: Long): String {
    val cal = java.util.Calendar.getInstance()
    val today = cal.get(java.util.Calendar.DAY_OF_YEAR) to cal.get(java.util.Calendar.YEAR)
    cal.timeInMillis = ts
    val d = cal.get(java.util.Calendar.DAY_OF_YEAR) to cal.get(java.util.Calendar.YEAR)
    return when {
        d == today -> "Today"
        d.second == today.second && d.first == today.first - 1 -> "Yesterday"
        else -> dayFmt.format(java.util.Date(ts))
    }
}

/* ── Sign in / create account ────────────────────────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthScreen(vm: ShroudVM) {
    var register by remember { mutableStateOf(false) }
    var u by remember { mutableStateOf("") }
    var p by remember { mutableStateOf("") }
    var p2 by remember { mutableStateOf("") }
    var d by remember { mutableStateOf(android.os.Build.MODEL ?: "Android") }
    var show by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    val uOk = u.trim().length >= 3
    val pOk = p.length >= 12
    val matchOk = !register || p == p2
    val canSubmit = uOk && pOk && matchOk && !loading
    val strength = when {
        p.isEmpty() -> ""
        p.length < 12 -> "Too short: ${12 - p.length} more character${if (12 - p.length == 1) "" else "s"}"
        p.length >= 20 || (p.any(Char::isDigit) && p.any(Char::isUpperCase) && p.any { !it.isLetterOrDigit() }) -> "Strong"
        else -> "OK. Longer is stronger."
    }

    Scaffold { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(32.dp))
            Icon(Icons.Filled.Lock, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(44.dp))
            Spacer(Modifier.height(10.dp))
            Text("SHROUD", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary,
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
            Text("Private messages the relay can't read.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
            Spacer(Modifier.height(24.dp))

            TabRow(selectedTabIndex = if (register) 1 else 0, containerColor = Color.Transparent) {
                Tab(selected = !register, onClick = { register = false; err = null }, text = { Text("Sign in") })
                Tab(selected = register, onClick = { register = true; err = null }, text = { Text("Create account") })
            }
            Spacer(Modifier.height(16.dp))

            OutlinedTextField(u, { u = it.trim(); err = null }, label = { Text("Username") },
                supportingText = { if (u.isNotEmpty() && !uOk) Text("At least 3 characters") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            OutlinedTextField(p, { p = it; err = null }, label = { Text("Password") },
                supportingText = { if (register || (p.isNotEmpty() && !pOk)) Text(if (register) strength.ifEmpty { "At least 12 characters" } else "At least 12 characters") },
                trailingIcon = { TextButton(onClick = { show = !show }) { Text(if (show) "Hide" else "Show") } },
                visualTransformation = if (show) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            if (register) {
                OutlinedTextField(p2, { p2 = it; err = null }, label = { Text("Confirm password") },
                    isError = p2.isNotEmpty() && !matchOk,
                    supportingText = { if (p2.isNotEmpty() && !matchOk) Text("Passwords don't match") },
                    visualTransformation = if (show) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(), singleLine = true)
                OutlinedTextField(d, { d = it }, label = { Text("Name for this device") },
                    supportingText = { Text("Shown in your device list") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true)
                Text("Your password never leaves this phone unencrypted, and nobody can reset it. Write it down somewhere safe.",
                    fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 4.dp))
            }

            if (err != null) {
                Surface(color = MaterialTheme.colorScheme.errorContainer, shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                        Icon(Icons.Filled.Warning, null, tint = MaterialTheme.colorScheme.onErrorContainer, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(err!!, color = MaterialTheme.colorScheme.onErrorContainer, fontSize = 13.sp)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { loading = true; err = null; vm.auth(u, p, d, register) { msg -> err = msg; loading = false } },
                enabled = canSubmit, modifier = Modifier.fillMaxWidth().height(50.dp),
            ) {
                if (loading) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.width(10.dp))
                    Text(if (register) "Creating your account…" else "Signing in…")
                } else Text(if (register) "Create account" else "Sign in")
            }
            Spacer(Modifier.height(24.dp))
            Text("Relay: ${NetworkClient.RELAY.removePrefix("https://")}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/* ── Main screen: conversation list or an open conversation ─────────── */

@OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
fun ChatScreen(vm: ShroudVM) {
    var fullscreenMsg by remember { mutableStateOf<Msg?>(null) }
    var pendingDelete by remember { mutableStateOf<Msg?>(null) }
    var safetyNumber by remember { mutableStateOf<String?>(null) }
    var safetyLoading by remember { mutableStateOf(false) }
    var showLink by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }
    var showAdd by remember { mutableStateOf(false) }
    val snack = remember { SnackbarHostState() }

    LaunchedEffect(vm.notice) {
        vm.notice?.let { snack.showSnackbar(it); vm.notice = null }
    }
    LaunchedEffect(Unit) { vm.refreshContacts(); vm.ownDevices() }
    androidx.activity.compose.BackHandler(enabled = vm.openPeer != null) { vm.closeChat() }

    if (showSettings) SettingsDialog(vm, onDismiss = { showSettings = false }, onLinkDevice = { showSettings = false; showLink = true })
    if (showLink) LinkDeviceDialog(vm) { showLink = false }
    if (showAdd) AddContactDialog(vm, onDismiss = { showAdd = false }, onMessage = { showAdd = false; vm.openChat(it) })
    if (safetyLoading || safetyNumber != null) {
        AlertDialog(
            onDismissRequest = { safetyNumber = null; safetyLoading = false },
            confirmButton = { TextButton(onClick = { safetyNumber = null; safetyLoading = false }) { Text("Done") } },
            title = { Text("Verify ${vm.openPeer ?: ""}") },
            text = {
                Column {
                    if (safetyLoading) CircularProgressIndicator(Modifier.padding(12.dp))
                    else if (safetyNumber == "") Text("${vm.openPeer} hasn't set up encryption keys yet. Ask them to open SHROUD once, then try again.")
                    else {
                        Text(safetyNumber!!.chunked(5).joinToString(" "), fontSize = 20.sp,
                            color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(vertical = 12.dp),
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                        Text("Compare this number with ${vm.openPeer} in person or on a call you trust. " +
                             "If you both see the same number, nobody is intercepting your messages.",
                            fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            },
        )
    }

    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) vm.sendImage(uri)
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snack) },
        topBar = {
            val peer = vm.openPeer
            TopAppBar(
                navigationIcon = {
                    if (peer != null) IconButton(onClick = { vm.closeChat() }) { Icon(Icons.Filled.ArrowBack, "Back to conversations") }
                },
                title = {
                    if (peer == null) Text("Conversations")
                    else Row(verticalAlignment = Alignment.CenterVertically) {
                        Avatar(peer, 34.dp)
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(peer, fontSize = 17.sp, maxLines = 1)
                            Text(if (vm.selectedRecipient.isBlank()) "Looking up their device…" else "End-to-end encrypted",
                                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                },
                actions = {
                    if (peer != null) {
                        TooltipIconButton(tip = "Check that nobody is intercepting this conversation",
                            onClick = { safetyLoading = true; vm.computeSafetyNumber { fp -> safetyLoading = false; safetyNumber = fp ?: "" } },
                            icon = Icons.Filled.Lock, contentDesc = "Verify contact")
                    } else {
                        TooltipIconButton(tip = "Add a contact", onClick = { showAdd = true },
                            icon = Icons.Filled.Add, contentDesc = "Add contact")
                    }
                    TooltipIconButton(tip = "Settings", onClick = { vm.ownDevices(); showSettings = true },
                        icon = Icons.Filled.Settings, contentDesc = "Settings")
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
            )
        },
        bottomBar = {
            Column {
                if (vm.maintenanceMode) {
                    Surface(color = Color(0xFF8A5A00), modifier = Modifier.fillMaxWidth()) {
                        Text("The relay is in maintenance. Messages can't be sent until it's back.",
                            modifier = Modifier.fillMaxWidth().padding(10.dp), color = Color.White, fontSize = 13.sp,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                    }
                }
                if (vm.openPeer != null) Composer(vm, onAttach = {
                    pickImage.launch(androidx.activity.result.PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                })
                Row(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(horizontal = 12.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(7.dp).clip(androidx.compose.foundation.shape.CircleShape).background(vm.connColor))
                    Spacer(Modifier.width(6.dp))
                    Text(vm.connStatus, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
                }
            }
        },
    ) { pad ->
        Box(Modifier.fillMaxSize().padding(pad).background(MaterialTheme.colorScheme.background)) {
            if (vm.openPeer == null) ConversationList(vm, onAdd = { showAdd = true })
            else MessageList(vm, onOpenImage = { fullscreenMsg = it }, onDeleteImage = { pendingDelete = it })
        }
    }

    fullscreenMsg?.let { msg ->
        Dialog(onDismissRequest = { fullscreenMsg = null },
            properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnBackPress = true)) {
            Box(Modifier.fillMaxSize().background(Color(0xF0000000))) {
                val bm = remember(msg.imagePath) { msg.imagePath?.let { android.graphics.BitmapFactory.decodeFile(it) } }
                if (bm != null) Image(bm.asImageBitmap(), "Image", Modifier.fillMaxSize().padding(24.dp), contentScale = ContentScale.Fit)
                IconButton(onClick = { fullscreenMsg = null },
                    modifier = Modifier.align(Alignment.TopEnd).padding(12.dp).size(48.dp)
                        .clip(androidx.compose.foundation.shape.CircleShape).background(Color(0x99000000))) {
                    Icon(Icons.Filled.Close, "Close", tint = Color.White)
                }
                if (msg.fileId != null) OutlinedButton(onClick = { pendingDelete = msg; fullscreenMsg = null },
                    modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)) {
                    Icon(Icons.Filled.Delete, null, tint = Color(0xFFFF8A8A), modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp)); Text("Delete", color = Color(0xFFFF8A8A))
                }
            }
        }
    }
    pendingDelete?.let { msg ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Delete this image?") },
            text = { Text("It will be removed from the relay and from this phone. If ${vm.openPeer ?: "the other person"} already downloaded it, their copy stays.") },
            confirmButton = { TextButton(onClick = { vm.deleteImage(msg); pendingDelete = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun ConversationList(vm: ShroudVM, onAdd: () -> Unit) {
    LazyColumn(Modifier.fillMaxSize()) {
        if (vm.incomingRequests.isNotEmpty()) {
            item { SectionLabel("Contact requests") }
            items(vm.incomingRequests, key = { "req-" + it.id }) { r ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(r.from)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(r.from, fontWeight = androidx.compose.ui.text.font.FontWeight.Medium)
                        Text(r.reason.ifBlank { "Wants to add you as a contact" }, fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
                    }
                    TextButton(onClick = { vm.respondRequest(r, false) }) { Text("Decline") }
                    Button(onClick = { vm.respondRequest(r, true) }) { Text("Accept") }
                }
            }
            item { Divider() }
        }
        val names = vm.contacts.map { it.username }
        val ordered = names.sortedByDescending { vm.conversations[it]?.lastOrNull()?.ts ?: 0L }
        if (ordered.isEmpty()) {
            item {
                Column(Modifier.fillMaxWidth().padding(top = 72.dp, start = 32.dp, end = 32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Filled.Person, null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("No conversations yet", style = MaterialTheme.typography.titleMedium)
                    Text("Add someone by their exact username. They'll get a request to accept, and you can message them right away.",
                        fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center, modifier = Modifier.padding(top = 6.dp, bottom = 16.dp))
                    Button(onClick = onAdd) { Icon(Icons.Filled.Add, null); Spacer(Modifier.width(6.dp)); Text("Add a contact") }
                }
            }
        } else {
            item { SectionLabel("Contacts") }
            items(ordered, key = { "c-$it" }) { name ->
                val last = vm.conversations[name]?.lastOrNull()
                val unread = vm.unread[name] ?: 0
                val pending = name in vm.outgoingPending
                Row(Modifier.fillMaxWidth().clickable { vm.openChat(name) }.padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Avatar(name)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(name, fontWeight = if (unread > 0) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.Medium)
                        Text(
                            when {
                                last == null && pending -> "Request sent. You can message them already."
                                last == null -> "Say hello"
                                last.imagePath != null -> (if (last.outgoing) "You: " else "") + "Image"
                                else -> (if (last.outgoing) "You: " else "") + last.body
                            },
                            fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        )
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        if (last != null) Text(timeFmt.format(java.util.Date(last.ts)), fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (unread > 0) { Spacer(Modifier.height(4.dp)); CountBadge(unread) }
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(text.uppercase(), fontSize = 11.sp, letterSpacing = 0.8.sp, color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp))
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun MessageList(vm: ShroudVM, onOpenImage: (Msg) -> Unit, onDeleteImage: (Msg) -> Unit) {
    val msgs = vm.messages
    val state = androidx.compose.foundation.lazy.rememberLazyListState()
    LaunchedEffect(msgs.size) { if (msgs.isNotEmpty()) state.animateScrollToItem(msgs.size - 1) }
    if (msgs.isEmpty()) {
        Column(Modifier.fillMaxSize().padding(32.dp), verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Filled.Lock, null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(40.dp))
            Spacer(Modifier.height(10.dp))
            Text("Messages with ${vm.openPeer} are end-to-end encrypted.", textAlign = androidx.compose.ui.text.style.TextAlign.Center)
            Text("The relay only ever sees scrambled bytes. Tap the lock above to verify you're really talking to them.",
                fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center, modifier = Modifier.padding(top = 6.dp))
        }
        return
    }
    LazyColumn(Modifier.fillMaxSize(), state = state, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)) {
        items(msgs.size, key = { msgs[it].id }) { i ->
            val msg = msgs[i]
            val prev = msgs.getOrNull(i - 1)
            if (prev == null || dayLabel(prev.ts) != dayLabel(msg.ts)) {
                Box(Modifier.fillMaxWidth().padding(vertical = 10.dp), contentAlignment = Alignment.Center) {
                    Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = androidx.compose.foundation.shape.RoundedCornerShape(50)) {
                        Text(dayLabel(msg.ts), fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp))
                    }
                }
            }
            if (msg.system) {
                Text(msg.body, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp))
                return@items
            }
            val grouped = prev != null && !prev.system && prev.outgoing == msg.outgoing && msg.ts - prev.ts < 120_000
            Bubble(vm, msg, grouped, onOpenImage, onDeleteImage)
        }
    }
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun Bubble(vm: ShroudVM, msg: Msg, grouped: Boolean, onOpenImage: (Msg) -> Unit, onDeleteImage: (Msg) -> Unit) {
    val me = msg.outgoing
    val bg = if (me) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant
    val fg = if (me) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
    val shape = androidx.compose.foundation.shape.RoundedCornerShape(
        topStart = 16.dp, topEnd = 16.dp, bottomStart = if (me) 16.dp else 4.dp, bottomEnd = if (me) 4.dp else 16.dp)
    Column(Modifier.fillMaxWidth().padding(top = if (grouped) 2.dp else 8.dp),
        horizontalAlignment = if (me) Alignment.End else Alignment.Start) {
        Surface(color = bg, shape = shape, modifier = Modifier.widthIn(max = 300.dp)) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                if (msg.imagePath != null) {
                    val bm = remember(msg.imagePath) { android.graphics.BitmapFactory.decodeFile(msg.imagePath) }
                    if (bm != null) Image(bm.asImageBitmap(), "Image",
                        Modifier.sizeIn(maxWidth = 260.dp, maxHeight = 320.dp).clip(MaterialTheme.shapes.small)
                            .combinedClickable(onClick = { onOpenImage(msg) }, onLongClick = { onDeleteImage(msg) }),
                        contentScale = ContentScale.Fit)
                    else Text("Image unavailable", color = fg)
                } else {
                    Text(mdToAnnotated(msg.body, fg), color = fg, fontSize = 15.sp)
                }
                Row(Modifier.align(Alignment.End).padding(top = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(timeFmt.format(java.util.Date(msg.ts)), fontSize = 10.sp, color = fg.copy(alpha = 0.7f))
                    if (me) {
                        Spacer(Modifier.width(4.dp))
                        when {
                            msg.pending -> Text("sending", fontSize = 10.sp, color = fg.copy(alpha = 0.7f))
                            msg.failed != null -> Icon(Icons.Filled.Warning, "Not sent", tint = Color(0xFFFFD0D0), modifier = Modifier.size(12.dp))
                            else -> Icon(Icons.Filled.Check, "Sent", tint = fg.copy(alpha = 0.8f), modifier = Modifier.size(12.dp))
                        }
                    }
                }
            }
        }
        if (msg.failed != null) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                Text("Not sent: ${msg.failed}", fontSize = 11.sp, color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.widthIn(max = 220.dp))
                TextButton(onClick = { vm.retry(msg) }) {
                    Icon(Icons.Filled.Refresh, null, modifier = Modifier.size(14.dp)); Spacer(Modifier.width(4.dp)); Text("Retry", fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
private fun Composer(vm: ShroudVM, onAttach: () -> Unit) {
    val blocked = vm.maintenanceMode
    Surface(color = MaterialTheme.colorScheme.surface, tonalElevation = 3.dp) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 6.dp, vertical = 6.dp), verticalAlignment = Alignment.Bottom) {
            IconButton(onClick = onAttach, enabled = !blocked && vm.selectedRecipient.isNotBlank()) {
                Icon(Icons.Filled.Add, "Send an image", tint = MaterialTheme.colorScheme.primary)
            }
            OutlinedTextField(
                value = vm.currentMessage, onValueChange = { vm.currentMessage = it; vm.touch() },
                placeholder = { Text(if (blocked) "Sending is paused during maintenance" else "Message ${vm.openPeer ?: ""}") },
                modifier = Modifier.weight(1f), minLines = 1, maxLines = 6, enabled = !blocked,
                shape = androidx.compose.foundation.shape.RoundedCornerShape(22.dp),
            )
            IconButton(onClick = { vm.send() }, enabled = vm.currentMessage.isNotBlank() && !blocked) {
                Icon(Icons.Filled.Send, "Send", tint = if (vm.currentMessage.isNotBlank() && !blocked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun AddContactDialog(vm: ShroudVM, onDismiss: () -> Unit, onMessage: (String) -> Unit) {
    var q by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { vm.searchResult = null; vm.searchDone = false }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        title = { Text("Add a contact") },
        text = {
            Column {
                Text("Enter their exact username. For privacy the relay only confirms exact matches; it never lists accounts.",
                    fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(q, { q = it.trim(); vm.searchResult = null; vm.searchDone = false },
                    label = { Text("Username") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                    trailingIcon = { IconButton(onClick = { vm.search(q) }, enabled = q.length >= 3) { Icon(Icons.Filled.Search, "Look up") } },
                    keyboardOptions = KeyboardOptions(imeAction = androidx.compose.ui.text.input.ImeAction.Search),
                    keyboardActions = androidx.compose.foundation.text.KeyboardActions(onSearch = { vm.search(q) }))
                Spacer(Modifier.height(12.dp))
                val found = vm.searchResult
                when {
                    found != null -> Row(verticalAlignment = Alignment.CenterVertically) {
                        Avatar(found, 36.dp); Spacer(Modifier.width(10.dp))
                        Text(found, Modifier.weight(1f), fontWeight = androidx.compose.ui.text.font.FontWeight.Medium)
                        val known = vm.contacts.any { it.username == found && it.friend }
                        if (!known) TextButton(onClick = { vm.addContact(found) }) { Text("Add") }
                        Button(onClick = { onMessage(found) }) { Text("Message") }
                    }
                    vm.searchDone -> Text("No account called \"$q\" on this relay.", fontSize = 13.sp, color = MaterialTheme.colorScheme.error)
                }
            }
        },
    )
}

@Composable
private fun LinkDeviceDialog(vm: ShroudVM, onDismiss: () -> Unit) {
    var pasted by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        title = { Text("Link another device") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("Copies your contact list to a new device. The code expires after 5 minutes.",
                    fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(14.dp))
                Text("1. On this device", fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
                Button(onClick = { vm.generateLinkCode { msg -> err = msg } }, modifier = Modifier.fillMaxWidth().padding(top = 6.dp)) { Text("Create a link code") }
                if (vm.linkCode.isNotEmpty()) {
                    OutlinedTextField(vm.linkCode, {}, readOnly = true, label = { Text("Link code") },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp), maxLines = 3)
                    TextButton(onClick = { clipboard.setText(androidx.compose.ui.text.AnnotatedString(vm.linkCode)) }) { Text("Copy code") }
                }
                Spacer(Modifier.height(14.dp))
                Text("2. On the new device", fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
                OutlinedTextField(pasted, { pasted = it }, label = { Text("Paste the link code") },
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
                Button(onClick = { vm.acceptLinkCode(pasted.trim()) { msg -> err = msg } }, enabled = pasted.isNotBlank(),
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp)) { Text("Use this code") }
                if (vm.linkStatus.isNotEmpty()) Text(vm.linkStatus, fontSize = 13.sp, modifier = Modifier.padding(top = 10.dp))
                if (err != null) Text(err!!, color = MaterialTheme.colorScheme.error, fontSize = 13.sp, modifier = Modifier.padding(top = 4.dp))
            }
        },
    )
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
        Text("Messages show **bold**, *italic* and `code`, and highlight links. The Windows app does the same.",
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
        if (vm.myDevices.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            Text("Your devices", style = MaterialTheme.typography.labelLarge)
            vm.myDevices.forEach { Text(it, fontSize = 12.sp, modifier = Modifier.padding(top = 2.dp)) }
        }
        Spacer(Modifier.height(18.dp))
        Text("Verifying contacts", style = MaterialTheme.typography.titleSmall)
        Text("Open a conversation and tap the lock at the top to see a safety number. Compare it with the other person in person or on a call you trust.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(18.dp))
        Text("Screen-capture protection", style = MaterialTheme.typography.titleSmall)
        Text("Screenshots and screen recordings of SHROUD come out black.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(18.dp))
        Text("Signed in as ${vm.username}", style = MaterialTheme.typography.titleSmall)
        Text("Relay ${NetworkClient.RELAY.removePrefix("https://")}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        var confirm by remember { mutableStateOf(false) }
        OutlinedButton(onClick = { confirm = true }, modifier = Modifier.padding(top = 8.dp)) { Text("Sign out of this phone") }
        if (confirm) AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Sign out?") },
            text = { Text("Conversations on this phone are cleared. Your account stays on the relay; sign in again with the same username and password.") },
            confirmButton = { TextButton(onClick = { confirm = false; vm.signOut() }) { Text("Sign out") } },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
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
        section("Adding people",
            "On the Conversations screen tap + and enter their exact username. They get a contact request; you can message them straight away.")
        section("Verifying contacts",
            "Open a conversation and tap the lock at the top. Compare the number with the other person in person or on a call you trust. The same number on both sides means nobody is intercepting.")
        section("Disappearing messages",
            "Settings → Messages. Toggle on, pick minutes/seconds. The server's sweeper deletes expired messages. Default is OFF.")
        section("Theme",
            "Settings → Appearance. Pick from preset palettes. Choice survives app restart.")
        section("Linking a second device",
            "Settings → Security → Link another device. Follow the short-code prompts. 5-minute TTL.")
        section("Your PIN",
            "Three wrong PIN attempts sign you out of this phone. Your account stays on the relay.")
        section("Troubleshooting",
            "\"The relay is in maintenance\": the operator has paused sending. Wait and try again.\n" +
            "\"Can't reach the relay\": check your connection. A message that fails shows why, with a Retry button.")
        section("Source",
            "https://github.com/ExposingTheBadge/Shroud")
    }
}
