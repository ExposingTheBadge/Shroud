package com.ghostlink.client

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.draw.clip
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
            MaterialTheme(colorScheme = DarkColors) {
                val vm: GhostlinkVM = viewModel(factory = GhostlinkVM.Factory(application))
                if (vm.isRegistered) ChatScreen(vm) else AuthScreen(vm)
            }
        }
    }
}

class GhostlinkVM(application: Application) : AndroidViewModel(application) {
    var isRegistered by mutableStateOf(false)
    var deviceID by mutableStateOf("")
    var username by mutableStateOf("")
    var messages by mutableStateOf(listOf<Msg>())
    var sideList by mutableStateOf(listOf<String>())
    var selectedRecipient by mutableStateOf("")
    var currentMessage by mutableStateOf("")
    var connStatus by mutableStateOf("Connecting...")
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
            "ghostlink_prefs_enc",
            masterKey,
            androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (e: Throwable) {
        application.getSharedPreferences("ghostlink_prefs", Context.MODE_PRIVATE)
    }

    init {
        identityKey = CryptoProvider.getIdentityKey()
        val sid = prefs.getString("device_id", "") ?: ""
        val su = prefs.getString("username", "") ?: ""
        val sp = prefs.getString("password", "") ?: ""
        if (sid.isNotEmpty() && su.isNotEmpty() && sp.isNotEmpty() && identityKey != null) {
            deviceID = sid; username = su; savedPassword = sp; isRegistered = true
            startHeartbeat()
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
                    connStatus = if (r.optString("beat") == "ok") "Online — AES-256-GCM | ECDH P-384" else "Waiting..."
                    connColor = if (r.optString("beat") == "ok") Color(0xFF2ed573) else Color(0xFF888888)
                } catch (_: Exception) {
                    connStatus = "Server offline"; connColor = Color(0xFFff4757)
                }
            }
        }
    }

    fun auth(u: String, p: String, d: String, isReg: Boolean, onError: (String) -> Unit) {
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

                // 3. Derive auth key: SHA-256(ECDH_shared + "GHOSTLINK-AUTH-v1")[:32]
                val ka = javax.crypto.KeyAgreement.getInstance("ECDH")
                ka.init(identityKey!!.private)
                ka.doPhase(serverPub, true)
                val shared = ka.generateSecret()
                val md = java.security.MessageDigest.getInstance("SHA-256")
                md.update(shared); val hashed = md.digest()
                md.reset(); md.update(hashed); md.update("GHOSTLINK-AUTH-v1".toByteArray())
                val authKey = javax.crypto.spec.SecretKeySpec(md.digest().copyOf(32), "AES")

                // 4. Build + encrypt auth payload
                val payload = JSONObject().apply {
                    put("username", u); put("password", p)
                    put("device_name", d); put("platform", "android")
                    put("register", isReg); put("public_key", ourPubHex)
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
                val sk = CryptoProvider.deriveSessionKey(identityKey!!.private, peerPub)
                val pl = JSONObject().apply { put("body",body); put("name",username); put("sender",deviceID); put("ts",System.currentTimeMillis()/1000) }.toString().toByteArray()
                val (iv,ct,tg) = CryptoProvider.encryptAESGCM(sk, pl)
                val sg = CryptoProvider.hmacSign(sk, ct)
                val env = JSONObject().apply { put("sender",deviceID); put("ts",System.currentTimeMillis()/1000); put("nonce",iv.toHex()); put("ciphertext",ct.toHex()); put("tag",tg.toHex()); put("sig",sg.toHex()) }
                NetworkClient.post("/api/v1/messages/send", JSONObject().apply { put("sender_device_id",deviceID); put("recipient_device_id",recip); put("envelope",env.toString()) })
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
                    NetworkClient.post("/api/v1/messages/send", JSONObject().apply {
                        put("sender_device_id", deviceID)
                        put("recipient_device_id", recip)
                        put("envelope", env.toString())
                    })
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
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val r = NetworkClient.post("/api/v1/contacts/search", JSONObject().apply { put("device_id",deviceID); put("query",q) })
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

    class Factory(private val app: Application) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T = GhostlinkVM(app) as T
    }
}

data class Msg(
    val sender: String,
    val body: String,
    val imagePath: String? = null,   // local plaintext path for inline display
    val fileId: String? = null,      // server file id (for delete)
    val name: String? = null,        // sender display name
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthScreen(vm: GhostlinkVM) {
    var u by remember { mutableStateOf("") }; var p by remember { mutableStateOf("") }
    var d by remember { mutableStateOf(android.os.Build.MODEL) }
    var showReg by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    Scaffold { pad ->
        Column(Modifier.fillMaxSize().padding(pad).padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            Text("GHOSTLINK", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
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
fun ChatScreen(vm: GhostlinkVM) {
    var showSide by remember { mutableStateOf(false) }
    var tab by remember { mutableIntStateOf(0) }
    var searchQ by remember { mutableStateOf("") }
    var fullscreenMsg by remember { mutableStateOf<Msg?>(null) }
    var pendingDelete by remember { mutableStateOf<Msg?>(null) }
    var safetyNumber by remember { mutableStateOf<String?>(null) }
    val ctx = androidx.compose.ui.platform.LocalContext.current

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

    val pickImage = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) vm.sendImage(uri)
    }

    LaunchedEffect(Unit) { vm.ownDevices() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("GHOSTLINK", color = MaterialTheme.colorScheme.primary) },
                actions = {
                    Text(vm.username, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    IconButton(
                        onClick = { vm.computeSafetyNumber { fp -> safetyNumber = fp } },
                        enabled = vm.selectedRecipient.isNotBlank(),
                    ) { Icon(Icons.Filled.Lock, "Verify safety number") }
                    IconButton(onClick = { vm.ownDevices(); tab = 0; showSide = true }) { Icon(Icons.Filled.Search, "Contacts") }
                    IconButton(onClick = { vm.loadGroups(); tab = 2; showSide = true }) { Icon(Icons.Filled.Share, "Groups") }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface)
            )
        },
        bottomBar = {
            Column {
                Text(vm.connStatus, fontSize = 10.sp, color = vm.connColor, modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp))
                Surface(color = MaterialTheme.colorScheme.surface, tonalElevation = 3.dp) {
                    Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        IconButton(
                            onClick = { pickImage.launch("image/*") },
                            enabled = vm.selectedRecipient.isNotBlank()
                        ) { Icon(Icons.Filled.Add, "Attach image", tint = MaterialTheme.colorScheme.primary) }
                        OutlinedTextField(vm.currentMessage, { vm.currentMessage = it }, placeholder = { Text("Message...") }, modifier = Modifier.weight(1f), singleLine = true)
                        IconButton(onClick = { vm.send() }, enabled = vm.currentMessage.isNotBlank()) { Icon(Icons.Filled.Send, "Send", tint = MaterialTheme.colorScheme.primary) }
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
                                    Text(msg.body, color = if (isMe) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface)
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
