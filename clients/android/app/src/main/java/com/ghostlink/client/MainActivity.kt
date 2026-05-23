package com.ghostlink.client

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.security.KeyPair as JavaKeyPair
import javax.crypto.SecretKey

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                val vm: GhostlinkVM = viewModel(
                    factory = GhostlinkVM.Factory(application)
                )
                if (vm.isRegistered) MessagesScreen(vm) else RegistrationScreen(vm)
            }
        }
    }
}

class GhostlinkVM(application: Application) : AndroidViewModel(application) {
    var isRegistered by mutableStateOf(false)
        private set
    var deviceID by mutableStateOf("")
        private set
    var username by mutableStateOf("")
        private set
    var messages by mutableStateOf(listOf<SecureMessage>())
    var contacts by mutableStateOf(listOf<Contact>())
    var groups by mutableStateOf(listOf<ChatGroup>())

    private var identityKey: JavaKeyPair? = null
    private val sessionKeys = mutableMapOf<String, SecretKey>()
    private val prefs = application.getSharedPreferences("ghostlink_prefs", Context.MODE_PRIVATE)

    init { loadIdentity() }

    private fun loadIdentity() {
        identityKey = CryptoProvider.getIdentityKey()
        identityKey?.let {
            isRegistered = true
            deviceID = prefs.getString("device_id", "") ?: ""
            username = prefs.getString("username", "") ?: ""
        }
    }

    fun register(username: String, password: String, deviceName: String) {
        viewModelScope.launch {
            identityKey = CryptoProvider.generateIdentityKey()
            val pubKey = CryptoProvider.exportPublicKey(identityKey!!)

            val resp = NetworkClient.post("/api/v1/devices", JSONObject().apply {
                put("username", username)
                put("password", password)
                put("device_name", deviceName)
                put("platform", "android")
                put("public_key", pubKey.toHex())
            })

            deviceID = resp.getString("device_id")
            this@GhostlinkVM.username = username
            isRegistered = true

            prefs.edit()
                .putString("device_id", deviceID)
                .putString("username", username)
                .apply()
        }
    }

    fun sendMessage(recipientDeviceID: String, body: String) {
        viewModelScope.launch {
            val recipientPubKey = lookupRecipientKey(recipientDeviceID) ?: return@launch
            val sessionKey = CryptoProvider.deriveSessionKey(
                identityKey!!.private, recipientPubKey
            )
            val envelope = buildEnvelope(sessionKey, body)

            NetworkClient.post("/api/v1/messages/send", JSONObject().apply {
                put("sender_device_id", deviceID)
                put("recipient_device_id", recipientDeviceID)
                put("envelope", JSONObject(envelope).toString())
            })
        }
    }

    private suspend fun lookupRecipientKey(deviceID: String): java.security.PublicKey? {
        val resp = NetworkClient.post("/api/v1/contacts/devices", JSONObject().apply {
            put("username", username)
        })
        val devices = resp.optJSONArray("devices") ?: return null
        for (i in 0 until devices.length()) {
            val d = devices.getJSONObject(i)
            if (d.getString("id") == deviceID) {
                return CryptoProvider.importPublicKey(
                    d.getString("public_key").hexToBytes()
                )
            }
        }
        return null
    }

    private fun buildEnvelope(key: SecretKey, body: String): Map<String, Any> {
        val payload = JSONObject().apply {
            put("sender", deviceID)
            put("ts", System.currentTimeMillis() / 1000)
            put("body", body)
        }.toString().toByteArray()
        val (nonce, ct, tag) = CryptoProvider.encryptAESGCM(key, payload)
        val sig = CryptoProvider.hmacSign(key, ct)
        return mapOf(
            "sender" to deviceID,
            "ts" to (System.currentTimeMillis() / 1000),
            "nonce" to nonce.toHex(),
            "ciphertext" to ct.toHex(),
            "tag" to tag.toHex(),
            "sig" to sig.toHex()
        )
    }

    class Factory(private val app: Application) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return GhostlinkVM(app) as T
        }
    }
}

data class SecureMessage(
    val id: String,
    val senderDeviceID: String,
    val envelope: JSONObject,
    val decryptedBody: String? = null
)
data class Contact(val id: String, val username: String)
data class ChatGroup(val id: String, val name: String, val createdAt: String)
