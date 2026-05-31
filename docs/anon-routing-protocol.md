# Anonymous routing protocol

Wire format for Rule 1 + Rule 2 compliant message delivery on SHROUD.
Every client implementation MUST produce and accept bytes that match
this spec exactly, otherwise the network forks.

Reference implementations:

| Language | File                                                              |
|----------|-------------------------------------------------------------------|
| Python   | `crypto/anon_routing.py`                                          |
| C        | `clients/windows/anon_routing.{c,h}`                              |
| Kotlin   | `clients/android/app/src/main/java/com/shroud/client/AnonRouting.kt` |

The Python ref is the canonical version; the others MUST produce
byte-identical output for the same inputs.

---

## Threat model recap

| Goal | Mechanism |
|------|-----------|
| Server cannot identify sender (Rule 1) | Sender identity lives inside an X25519+AES-GCM sealed envelope. Server sees an ephemeral pubkey it cannot link to any device. |
| Server cannot identify receiver (Rule 2) | Messages are queued by a 32-byte routing tag derived from a per-pair X3DH root + epoch hour. Server never holds the secret needed to map tag → identity. |
| No content metadata leaks (Rule 3) | Every media attachment passes through `crypto/strip_metadata.py` (and language ports) before the sealing step. |
| Project survives takedown (Rule 0) | Anonymous routing is stateless on the server. Spinning up a new relay anywhere recovers full functionality. |

---

## Primitives

- `HKDF-SHA256` (RFC 5869). `Extract(salt, ikm) -> 32 B PRK`. `Expand(prk, info, L) -> L B OKM`.
- `X25519` ECDH (RFC 7748).
- `AES-256-GCM`. 12-byte nonce, 16-byte tag, **no AAD**. (The KDF binds the relevant pubkeys.)
- `SHA-256`.
- Big-endian for all multi-byte integers.

---

## Routing tag (Rule 2)

### Inputs
- `shared_root` — 32 bytes. The X3DH root chain key the two parties share for this conversation.
- `pair_id` — 64-bit integer. Deterministic order-independent fingerprint of the two identity public keys (see below).
- `epoch` — 64-bit integer. `unix_time // 3600`.

### Pair ID
```
def pair_id(id_a: bytes, id_b: bytes) -> int:
    lo, hi = sorted([id_a, id_b])
    return int.from_bytes(sha256(lo + b"||" + hi).digest()[:8], "big")
```

Both identity pubkeys are X25519 32-byte raw representations. Sorted
byte-lexicographically so either party computes the same value.

### Tag derivation
```
prk = HKDF-Extract(salt = "shroud-tag-v1", ikm = shared_root)
info = pair_id (big-endian uint64) || epoch (big-endian uint64)   // 16 bytes
tag = HKDF-Expand(prk, info, 32)
```

### Poll window
Recipients SHOULD poll with `{prev, current, next}` epoch tags per
contact, to absorb up to ±1 hour clock skew:

```python
[ routing_tag(root_i, pair_i, e) for i in contacts for e in [current-1, current, current+1] ]
```

Server caps a single poll at **1024 tags** to bound flood cost.

---

## Sealed envelope (Rule 1)

### Wire format

```
+-----------------+---------------+---------------+------------------+---------+
| version (1 B)   | eph_pub (32)  | nonce (12)    | ciphertext (var) | tag (16)|
| 0x01            | X25519 pub    | AES-GCM IV    |                  |         |
+-----------------+---------------+---------------+------------------+---------+
```

Total overhead = 61 bytes plus the AES-GCM tag (already counted).

### Sealing
```
eph_priv = X25519 keygen
eph_pub  = X25519 pubkey(eph_priv)
shared   = X25519(eph_priv, recipient_pub)

prk = HKDF-Extract("shroud-seal-v1", shared || eph_pub || recipient_pub)
key = HKDF-Expand(prk, "key", 32)

nonce = 12 random bytes
ct, tag = AES-256-GCM(key, nonce, payload)   # no AAD

return 0x01 || eph_pub || nonce || ct || tag
```

### Unsealing
```
parse: version, eph_pub, nonce, ct, tag
require version == 0x01

shared = X25519(my_priv, eph_pub)
prk = HKDF-Extract("shroud-seal-v1", shared || eph_pub || my_pub)
key = HKDF-Expand(prk, "key", 32)

payload = AES-256-GCM-Decrypt(key, nonce, ct, tag)
```

The KDF input commits `eph_pub` and `recipient_pub`/`my_pub` to the
session key. Substituting either causes the derived key to change, and
the GCM tag check fails. This provides the same tamper-detection that
GCM AAD would, without the helper-function complexity.

### Payload contents
The plaintext `payload` is application-defined. The SHROUD message
client uses a JSON object identical in shape to the legacy unsealed
envelope, so existing parsers continue to work after decryption:

```json
{
  "sender":     "<sender_device_id>",
  "ts":         1700000000,
  "nonce":      "<hex>",
  "ciphertext": "<hex>",
  "tag":        "<hex>",
  "sig":        "<hex>"
}
```

The `sender` field is the only identifying value, and it lives inside
the AES-GCM ciphertext. The server cannot read it.

---

## Server endpoints

### `POST /api/v1/messages/send-anon`

Headers:
- `X-Routing-Tag: <64 hex chars>` (32 bytes) — required
- `X-Envelope-Version: 2` — v2 envelopes MUST be padded to a bucket size
- `X-Expires-In: <seconds>` — optional disappearing-message TTL

Body: raw bytes of the sealed envelope, padded to a `PAD_BUCKETS` value
(`4096, 65536, 1048576, 16777216`) for v2.

Response 200:
```json
{"message_id": "<hex>", "anon": true, "expires_at": "<iso or null>"}
```

### `POST /api/v1/messages/fetch-anon`

Body:
```json
{"tags": ["<hex>", "<hex>", ...]}
```

Cap: 1024 tags. Each must be exactly 32 bytes (64 hex chars).

Response 200:
```json
{
  "messages": [
    {"id": "<hex>", "sealed": "<hex>", "ts": "<iso>"},
    ...
  ],
  "count": <int>
}
```

`messages` may be empty. **Every returned message is deleted from the
server immediately and unconditionally**, in the same transaction as
the SELECT. No retention. No copy. No audit row beyond an aggregate
delivery counter.

---

## Why this satisfies the rules

**Rule 1.** The server only ever sees the ephemeral X25519 pubkey, the
nonce, and the ciphertext. None of those link to a long-term identity.
The KDF binding plus the AES-GCM authenticator prevent a passive
observer from substituting a different ephemeral pubkey to coerce a
known key.

**Rule 2.** The server only ever sees 32-byte routing tags. The tags are
HKDF outputs of secrets the server never possesses — the X3DH chain key
shared between the two parties. A relay restart with an empty database
restores Rule 2 fully. Messages are deleted on first fetch, so the
"who fetched what" question cannot be answered after the fact.

**Rule 3.** Orthogonal to this protocol — any attachments inside the
sealed payload pass through `crypto/strip_metadata.py` before sealing.

**Rule 0.** This protocol is stateless on the server side. Bringing up
a fresh relay in a new jurisdiction recovers full Rule 1 + Rule 2
guarantees without any migration.
