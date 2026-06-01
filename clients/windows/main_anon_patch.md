# Windows client: wireup to anonymous routing endpoints

Adapter patch turning the Windows Qt6 client's legacy `/messages/send` +
`/messages/fetch` path into a Rule-1 + Rule-2 compliant one using
`/messages/send-anon` + `/messages/fetch-anon`, backed by the C
library at [`clients/windows/anon_routing.c`](anon_routing.c).

## ⚠ Required helpers not yet in main.cpp

Before applying this patch, three helpers it references must exist in
the surrounding `ShroudWindow` class. They do **not** currently exist
and must be added first:

| Reference | What it does | Adapter strategy |
|---|---|---|
| `activeContactDeviceIds()` | Returns a `QStringList` of every contact's device_id | Walk `m_contactList`'s items, pulling `data(Qt::UserRole)` |
| `handleIncoming(sender, env)` | Dispatch a decoded envelope through the existing display pipeline | Refactor the body of `fetchMessages()`'s `for (const QJsonValue &mv : msgs)` loop into a named method, then call it from both legacy and anon paths |
| `setting_set(key, value)` | Persist a key/value setting across launches | Either add via `QSettings` or extend the existing `storage_save_blob` API; check the patterns already used for theme/anon flags |

Without these three adapters, the patch will not compile.

This is **a reviewed-before-apply patch**, not a committed code change.
The Windows client compiles in CI today; applying the patch without
the small fixups documented below could break the build. Review
carefully, then apply.

## Why a patch document instead of a code commit

The Windows client's per-contact ratchet state lives in encrypted
blobs managed by `storage_save_blob` / `storage_load_blob`. Getting at
the per-pair X3DH root for routing-tag derivation requires inspecting
the existing ratchet session file format, which I can't reliably do
without a working build. A wrong cast or layout assumption silently
corrupts the encrypted blobs in production.

The patch below uses a conservative substitute for the shared root —
the ECDH output of `(my_identity_priv, peer_identity_pub)` — which:

  - is well-defined for any pair of devices that have completed X3DH
  - already exists in the Windows codebase via `ratchet_x25519_dh`
  - yields the same value on both sides without any extra storage
  - costs forward secrecy on the *routing tag* specifically (the
    ratchet's chain-key root would be better; this is a known
    follow-up).

The sealed envelope itself (Rule 1) is unaffected by this choice —
that uses the recipient's identity pubkey directly.

## Patch

### 1. Add include + extern declaration at the top of main.cpp

```cpp
extern "C" {
#include "anon_routing.h"
}
```

### 2. Add per-instance settings to ShroudWindow

In the private member section (search for `bool m_registered = false`):

```cpp
bool m_useAnonRouting = true;  // Rule 1+2 compliant path; off = legacy
```

### 3. Add a helper that derives the per-contact routing tag

In the private methods section, after `fetchPeerX25519`:

```cpp
/* Derive the routing tag the sender writes to / receiver polls.
 * Uses ECDH(my_id_priv, peer_id_pub) as the shared root — substitute
 * for the X3DH ratchet root, which is on the roadmap for a more
 * forward-secret version. */
bool computeRoutingTag(const QString &peerDeviceId,
                       qint64 epochOverride,
                       BYTE tag_out[SHROUD_ROUTING_TAG_LEN]) {
    BYTE peer_pub[32];
    if (!fetchPeerX25519(peerDeviceId, peer_pub)) return false;

    DeviceConfig cfg;
    if (!storage_load_config(&cfg)) return false;
    if (!storage_load_keypair(cfg.id, &cfg.identity_key)) return false;

    BYTE my_priv[32], my_pub[32];
    memcpy(my_priv, cfg.identity_key.priv.data, 32);
    memcpy(my_pub, cfg.identity_key.pub.data, 32);

    BYTE shared[32];
    if (!ratchet_x25519_dh(my_priv, peer_pub, shared)) {
        SecureZeroMemory(my_priv, 32);
        return false;
    }
    SecureZeroMemory(my_priv, 32);

    uint64_t pid = anon_pair_id(my_pub, peer_pub);
    uint64_t epoch = (epochOverride > 0)
        ? (uint64_t)epochOverride
        : anon_epoch_for((uint64_t)QDateTime::currentSecsSinceEpoch());

    return anon_routing_tag(shared, pid, epoch, tag_out);
}
```

### 4. Add a sealed-send method alongside the existing send path

In the same private methods section:

```cpp
/* Build + POST a sealed envelope addressed to the per-pair routing
 * tag. Replaces /api/v1/messages/send for Rule 1+2 compliance.
 * Returns true on HTTP 200 from the server. */
bool sendSealedTo(const QString &peerDeviceId, const QByteArray &innerJson,
                  qint64 expiresInSeconds) {
    BYTE peer_pub[32];
    if (!fetchPeerX25519(peerDeviceId, peer_pub)) return false;

    /* Allocate enough room for the largest padding bucket we'd use. */
    static constexpr DWORD MAX_INNER = 4096 - SHROUD_SEAL_FIXED_OVERHEAD;
    if ((DWORD)innerJson.size() > MAX_INNER) return false;

    BYTE sealed[4096];
    DWORD sealedLen = 0;
    if (!anon_seal((const BYTE*)innerJson.constData(), (DWORD)innerJson.size(),
                   peer_pub, sealed, &sealedLen)) {
        return false;
    }
    /* Pad up to the 4 KB bucket. */
    memset(sealed + sealedLen, 0, sizeof(sealed) - sealedLen);

    BYTE tag[SHROUD_ROUTING_TAG_LEN];
    if (!computeRoutingTag(peerDeviceId, 0, tag)) return false;

    QByteArray tagHex;
    for (int i = 0; i < SHROUD_ROUTING_TAG_LEN; ++i) {
        tagHex.append(QString::asprintf("%02x", tag[i]).toUtf8());
    }

    QByteArray header;
    header.append("X-Routing-Tag: ").append(tagHex).append("\r\n");
    header.append("X-Envelope-Version: 2\r\n");
    if (expiresInSeconds > 0) {
        header.append("X-Expires-In: ")
              .append(QByteArray::number(expiresInSeconds))
              .append("\r\n");
    }

    QByteArray body((char*)sealed, 4096);
    QByteArray resp = httpPost("/api/v1/messages/send-anon", body, header);
    return resp.contains("\"anon\":true");
}
```

### 5. Branch the existing sendMessage on the feature flag

Find the existing send path (around line 2105):

```cpp
QByteArray sendResp = httpPost("/api/v1/messages/send", jb, expHdr);
```

Wrap it:

```cpp
bool sent;
if (m_useAnonRouting) {
    /* Inner envelope is the same JSON we used to send unwrapped. */
    QByteArray inner = QJsonDocument(QJsonObject::fromVariantMap(env)).toJson(QJsonDocument::Compact);
    sent = sendSealedTo(m_selectedRecip, inner,
                        (gDisappearEnabled && gDisappearSeconds > 0) ? gDisappearSeconds : 0);
} else {
    QByteArray sendResp = httpPost("/api/v1/messages/send", jb, expHdr);
    sent = !sendResp.contains("\"detail\":\"maintenance\"");
}

if (!sent) {
    setMaintenanceMode(true);
    m_statusBar->setText("Send refused — server in maintenance");
    m_statusBar->setStyleSheet("color: #ff8a8a; font-size: 11px; font-weight: bold;");
    return;
}
```

### 6. Add a fetch-anon path

Currently the fetch path (around line 2188) posts to `/messages/fetch`:

```cpp
QByteArray r = httpPost("/api/v1/messages/fetch", jsonBody({{"device_id", m_deviceId}}));
```

Add an anon variant:

```cpp
void fetchMessagesAnon() {
    if (m_deviceId.isEmpty()) return;

    /* Build the tag list across all active contacts × {prev, current, next} */
    QJsonArray tagsArr;
    QStringList contactIds = activeContactDeviceIds(); // adapter — list known peers
    qint64 now = QDateTime::currentSecsSinceEpoch();
    uint64_t epoch = anon_epoch_for((uint64_t)now);
    for (const QString &pid : contactIds) {
        for (int de = -1; de <= 1; ++de) {
            BYTE tag[SHROUD_ROUTING_TAG_LEN];
            if (computeRoutingTag(pid, (qint64)epoch + de, tag)) {
                QByteArray h;
                for (int i = 0; i < SHROUD_ROUTING_TAG_LEN; ++i)
                    h.append(QString::asprintf("%02x", tag[i]).toUtf8());
                tagsArr.append(QString::fromUtf8(h));
            }
        }
    }

    QByteArray body = QJsonDocument(QJsonObject{{"tags", tagsArr}}).toJson(QJsonDocument::Compact);
    QByteArray r = httpPost("/api/v1/messages/fetch-anon", body);
    QJsonArray msgs = QJsonDocument::fromJson(r).object().value("messages").toArray();
    for (const QJsonValue &mv : msgs) {
        QString sealedHex = mv.toObject().value("sealed").toString();
        QByteArray sealedBytes = QByteArray::fromHex(sealedHex.toUtf8());

        /* Trim trailing zeros down to the actual sealed envelope length. */
        int j = sealedBytes.size();
        while (j > 0 && sealedBytes[j-1] == 0) j--;
        for (int k = j; k <= qMin(j + 32, sealedBytes.size()); ++k) {
            DeviceConfig cfg;
            if (!storage_load_config(&cfg)) break;
            if (!storage_load_keypair(cfg.id, &cfg.identity_key)) break;

            BYTE plain[4096];
            DWORD plainLen = 0;
            if (anon_unseal((const BYTE*)sealedBytes.constData(), (DWORD)k,
                            cfg.identity_key.priv.data, cfg.identity_key.pub.data,
                            plain, &plainLen)) {
                QByteArray plainJson((const char*)plain, plainLen);
                QJsonObject env = QJsonDocument::fromJson(plainJson).object();
                /* Dispatch to the same downstream handler the legacy
                 * fetchMessages() uses. Sender is now inside the
                 * envelope's "sender" field rather than the outer
                 * sender_device_id. */
                QString sender = env.value("sender").toString();
                handleIncoming(sender, env);
                break;
            }
        }
    }
}
```

### 7. Wire the feature flag into Settings

In the Settings dialog (search for "Theme" or "Disappearing"):

```cpp
QCheckBox *anonChk = new QCheckBox("Use anonymous routing (recommended)");
anonChk->setChecked(m_useAnonRouting);
connect(anonChk, &QCheckBox::toggled, this, [this](bool v) {
    m_useAnonRouting = v;
    /* Persist to settings file so it survives restart. */
    setting_set("anon_routing", v ? "1" : "0");
});
settingsLayout->addRow(anonChk);
```

### 8. CMake

`clients/windows/CMakeLists.txt` already lists `anon_routing.c` in
`WIN_MODULES`, so no change there.

## After applying

```pwsh
# From repo root:
gh workflow run release-windows.yml --ref master -f bump=patch
```

If the build is green, sign + release a v2.x.x+1. The anon path is
on by default for new installs; existing users can toggle it on via
Settings.

## Backward compatibility

The relay accepts both `/messages/send` and `/messages/send-anon`
indefinitely (the former with a deprecation header). Users running
pre-anon clients still work; they just don't get the Rule 1+2
upgrade until they update.

## Future work

- Replace the ECDH-only shared root with the X3DH chain-key root for
  forward-secrecy on the routing tag itself. Requires plumbing into
  the existing ratchet session storage.
- Move the inner envelope's `sender_device_id` field to a derived
  signature instead of a plaintext id, so even a compromised
  recipient cannot leak the device_id mapping in their UI.
- Strip-metadata integration on image uploads (currently happens via
  the inline path in `sendImageAttachment`; needs to call the C
  port of `crypto/strip_metadata`).
