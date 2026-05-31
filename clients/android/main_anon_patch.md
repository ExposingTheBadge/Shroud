# Android client: wireup to anonymous routing endpoints

Documented patch (review before applying) that turns the legacy
`POST /api/v1/messages/send` path in `NetworkClient.kt` into a Rule 1+2
compliant `POST /api/v1/messages/send-anon` path backed by the Kotlin
`AnonRouting` port at
[`clients/android/app/src/main/java/com/shroud/client/AnonRouting.kt`](app/src/main/java/com/shroud/client/AnonRouting.kt).

## Patch

### 1. Add a feature flag to `MainActivity` settings

In the `Settings` data class (or wherever the user preferences live):

```kotlin
val useAnonRouting: MutableState<Boolean> = mutableStateOf(true)
```

Persist with the existing SharedPreferences glue.

### 2. Helper: per-contact routing tag

Add to `NetworkClient.kt`:

```kotlin
fun computeRoutingTag(
    myIdPriv: ByteArray, myIdPub: ByteArray,
    peerIdPub: ByteArray, sharedRoot: ByteArray,
    epoch: Long = AnonRouting.epochFor(),
): ByteArray {
    val pairId = AnonRouting.pairId(myId = myIdPub, theirId = peerIdPub)
    return AnonRouting.routingTag(sharedRoot = sharedRoot, pair = pairId, epoch = epoch)
}
```

`sharedRoot` should be the X3DH root chain key for this pair. If
your client doesn't yet persist that, use the ECDH(my_id_priv,
peer_id_pub) value as a conservative substitute (matches the
Windows main_anon_patch.md approach).

### 3. Send via `/messages/send-anon`

Replace the body of `NetworkClient.sendMessage(...)` (the one that
currently posts to `/api/v1/messages/send`) with:

```kotlin
suspend fun sendMessage(
    recipientPubkey: ByteArray,
    sharedRoot: ByteArray,
    innerEnvelopeJson: ByteArray,
    expiresInSeconds: Int? = null,
): Boolean = withContext(Dispatchers.IO) {
    val tag = computeRoutingTag(
        myIdPriv = identityPrivKey,
        myIdPub = identityPubKey,
        peerIdPub = recipientPubkey,
        sharedRoot = sharedRoot,
    )
    val sealed = AnonRouting.seal(payload = innerEnvelopeJson, recipientPub = recipientPubkey)
    val target = listOf(4096, 65536, 1048576, 16777216).first { it >= sealed.size }
    val padded = ByteArray(target)
    System.arraycopy(sealed, 0, padded, 0, sealed.size)

    val url = URL("${relayBaseUrl}/api/v1/messages/send-anon")
    val conn = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        doOutput = true
        setRequestProperty("Content-Type", "application/octet-stream")
        setRequestProperty("X-Routing-Tag", tag.joinToString("") { "%02x".format(it) })
        setRequestProperty("X-Envelope-Version", "2")
        if (expiresInSeconds != null) {
            setRequestProperty("X-Expires-In", expiresInSeconds.toString())
        }
    }
    conn.outputStream.use { it.write(padded) }
    val code = conn.responseCode
    conn.disconnect()
    code == 200
}
```

### 4. Fetch via `/messages/fetch-anon`

Add:

```kotlin
data class IncomingSealed(val sealed: ByteArray, val ts: String)

suspend fun fetchMessagesAnon(
    knownContacts: List<Pair<ByteArray, ByteArray>>,  // (peer_id_pub, shared_root)
): List<Pair<String, ByteArray>> = withContext(Dispatchers.IO) {
    // Build the tag list across {prev, current, next} epochs per contact.
    val pairs = knownContacts.map { (peerPub, root) ->
        Pair(AnonRouting.pairId(identityPubKey, peerPub), root)
    }
    val tags = AnonRouting.fetchTagsForWindow(pairs = pairs)
    val tagsHex = tags.map { it.joinToString("") { byte -> "%02x".format(byte) } }

    val payload = JSONObject().apply {
        put("tags", JSONArray(tagsHex))
    }.toString().toByteArray()

    val url = URL("${relayBaseUrl}/api/v1/messages/fetch-anon")
    val conn = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
    }
    conn.outputStream.use { it.write(payload) }
    val responseText = conn.inputStream.bufferedReader().readText()
    conn.disconnect()

    val resp = JSONObject(responseText)
    val msgs = resp.optJSONArray("messages") ?: return@withContext emptyList()
    val out = mutableListOf<Pair<String, ByteArray>>()
    for (i in 0 until msgs.length()) {
        val m = msgs.getJSONObject(i)
        val sealedHex = m.getString("sealed")
        val sealedBytes = sealedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        // Trim trailing zeros and try unseal.
        var len = sealedBytes.size
        while (len > 0 && sealedBytes[len - 1] == 0.toByte()) len--
        for (tail in len..(len + 32).coerceAtMost(sealedBytes.size)) {
            try {
                val plaintext = AnonRouting.unseal(
                    sealed = sealedBytes.copyOfRange(0, tail),
                    myPriv = identityPrivKey,
                    myPub = identityPubKey,
                )
                out.add(Pair(m.optString("ts"), plaintext))
                break
            } catch (e: Exception) {
                continue
            }
        }
    }
    out
}
```

### 5. UI dispatch

Where `MainActivity` currently calls the legacy `sendMessage` and
processes the legacy `fetch` response, branch on the
`useAnonRouting` flag:

```kotlin
if (settings.useAnonRouting.value) {
    networkClient.sendMessage(
        recipientPubkey = contact.identityPubkey,
        sharedRoot = contact.sharedRoot,
        innerEnvelopeJson = innerJson,
        expiresInSeconds = if (settings.disappearingEnabled.value) settings.disappearingSeconds.value else null,
    )
} else {
    networkClient.sendMessageLegacy(...)
}
```

And the fetch side calls `fetchMessagesAnon(contactsWithRoots)`,
then for each `(ts, plaintext)`, parses the inner JSON envelope the
same way the legacy fetch handler does.

### 6. minSdk

`AnonRouting.kt` uses `java.security` XDH which requires API 30+.
If you must support older Android, swap the three `x25519*` helpers
in `AnonRouting.kt` for Tink's `subtle.X25519`. The rest of the
module is unchanged.

## After applying

```bash
cd clients/android
./gradlew :app:assembleRelease
```

Run the assembled APK against the live AWS relay
(https://44.202.225.57:58443). The app's outbound messages should
now arrive on the relay as opaque sealed envelopes addressed to
routing tags rather than as `/messages/send` payloads with
plaintext `sender_device_id`.

## Backward compatibility

The relay accepts both endpoints. Pre-anon Android clients keep
working; they just don't get the Rule 1+2 upgrade until they
update.
