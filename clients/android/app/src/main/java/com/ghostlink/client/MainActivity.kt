package com.ghostlink.client

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
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
    primary = Color(0xFF0066CC), background = Color(0xFF1A1A1A),
    surface = Color(0xFF222222), surfaceVariant = Color(0xFF2D2D2D),
    onPrimary = Color.White, onBackground = Color(0xFFCCCCCC),
    onSurface = Color(0xFFCCCCCC), onSurfaceVariant = Color(0xFF888888),
    outline = Color(0xFF3D3D3D),
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
    private val prefs = application.getSharedPreferences("ghostlink_prefs", Context.MODE_PRIVATE)

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

data class Msg(val sender: String, val body: String)

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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(vm: GhostlinkVM) {
    var showSide by remember { mutableStateOf(false) }
    var tab by remember { mutableIntStateOf(0) }
    var searchQ by remember { mutableStateOf("") }

    LaunchedEffect(Unit) { vm.ownDevices() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("GHOSTLINK", color = MaterialTheme.colorScheme.primary) },
                actions = {
                    Text(vm.username, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
                            Column(Modifier.padding(12.dp)) {
                                Text(msg.body, color = if (isMe) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface)
                                Text(vm.username.take(16), fontSize = 9.sp, color = (if (isMe) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface).copy(alpha = 0.5f))
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
}
