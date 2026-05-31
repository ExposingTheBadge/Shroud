# SHROUD security FAQ

A walkthrough of the project's threat model, presented as the
questions a careful user, journalist, lawyer, or auditor would
actually ask. Cross-references each claim to the code that backs it,
so anyone can verify by reading source rather than trusting prose.

If you spot a claim here that isn't backed by code, that's a bug —
open an issue or a PR.

---

## 1. Who can read my messages?

**Only the recipient.** SHROUD uses end-to-end encryption: the
sender's client encrypts each message under a key derived between
the sender and recipient devices. The relay sees only ciphertext.

Code paths that establish keys:

- Initial handshake: PQXDH-style hybrid (X25519 + ML-KEM-1024). See
  `clients/windows/ratchet.c` (`ratchet_x3dh_initiator` /
  `ratchet_x3dh_responder`) and `crypto/pq_hybrid.py`.
- Per-message ratchet: Signal-style Double Ratchet, extended in
  SHROUD to push a fresh ML-KEM contribution into every chain step.
  See `crypto/pq_double_ratchet.py`.
- Sealed envelope (sender hidden from relay): `crypto/anon_routing.py`
  and the C/Kotlin/Swift ports.

---

## 2. Can the relay operator identify the sender?

**No.** Outgoing messages are sealed envelopes. The wire format is:

```
version(1) || ephemeral_X25519_pub(32) || nonce(12) || ciphertext || gcm_tag(16)
```

The sender's identity lives *inside* the AES-256-GCM ciphertext,
keyed by ECDH(ephemeral, recipient_identity). The relay sees:

- a random-looking ephemeral pubkey (fresh per message)
- a random-looking 12-byte nonce
- opaque ciphertext

It cannot link the ephemeral pubkey to any device because the
ephemeral key was generated for this one message and never used
again.

Code: `crypto/anon_routing.py:seal`.

---

## 3. Can the relay operator identify the recipient?

**No.** Incoming routing uses 32-byte tags derived from per-pair
X3DH-established secrets that the relay never sees:

```
tag = HKDF-Expand(HKDF-Extract("shroud-tag-v1", shared_root),
                  pair_id_be8 || epoch_hour_be8,
                  32)
```

The recipient polls by submitting a list of tags (current contacts
× current/prev/next epoch). The server returns matching messages
**and deletes them in the same SQL transaction as the SELECT**
(`server/server.py`'s `fetch_anon_messages`). No retention, no copy.

Tags rotate every hour, so even if a tag leaks via a passive
observer, only that hour's window is exposed.

Code: `crypto/anon_routing.py:routing_tag` and the server endpoint
`POST /api/v1/messages/fetch-anon`.

---

## 4. Will SHROUD comply with a subpoena / warrant / court order?

**No.** See README's
[Government Requests / Warrant Policy](../README.md#government-requests--warrant-policy).
We will not comply, and we will not shut down. The architecture is
designed so that "comply" is technically meaningless — the data the
court would order us to surrender does not exist on our servers in
a form anyone (including us) can read.

If somehow compelled, we have:

- multi-region federation (`crypto/federation.py`), so a takedown of
  one operator does not take down the network
- reproducible builds + multi-signer threshold release attestation
  (`docs/multisig-releases.md`), so a coerced backdoor changes
  measurable build artifacts and clients can refuse the new release

---

## 5. What if the SHROUD developers are compromised?

The multi-signer threshold scheme (M-of-N) requires multiple
independent signers' keys to authorize a release. A single
developer compromise cannot ship a malicious build.

Reproducible builds let *anyone* rebuild from source and verify the
SHA-256 matches what was signed. If you don't trust the developers,
build yourself; your locally-built binary is the trust root.

Code: `release/sign_manifest.py`, `release/multisig.py`,
`scripts/repro-check.{sh,ps1}`.

---

## 6. What if my device is compromised?

**Out of scope.** SHROUD protects messages *in transit* and *at
rest on the relay*. It cannot protect plaintext that the OS, the
hardware, or other applications running on the same device can
access.

Mitigations the project does ship:

- TPM-sealed identity keys on Windows (`clients/windows/tpm.c`) and
  AndroidKeyStore-sealed keys on Android — non-extractable from the
  host even by malware running as root.
- Secure local wipe on disappearing messages
  (`crypto/disappearing.py`), with `PRAGMA secure_delete` + `VACUUM`
  so deleted SQLite rows don't linger in the free-page list.
- Searchable encryption (`crypto/local_search.py`) so the search
  index reveals only blinded token hashes, not message content.
- Encrypted backup (`crypto/backup.py`) so cold-storage copies are
  Argon2id-encrypted at rest.

What we cannot defend against: a screen-recording trojan, a
keylogger, an evil-maid TPM-bypass attack, or a state-level
hardware exploit. Full-disk encryption + cautious app installation
is the right defence.

---

## 7. What does Apple / Google see when I get a push notification?

**The fact that you got a push, and an opaque rendezvous token.**
That's it. See `crypto/anon_push.py`. The push payload is the
literal bytes `{"shroud":1,"rendezvous":"<hex>"}`. Apple/Google do
NOT see:

- who sent the message
- what it says
- how many messages are waiting
- which conversation it's part of

They DO see that this device runs SHROUD (the OS push system has to
know which app to wake) and the device-level push token they
themselves minted. That's information they already have because
they're the push provider.

For full Rule-2 push, install via UnifiedPush (on Android) or run a
foreground service that polls directly without OS push. Both are
client settings, not protocol changes.

---

## 8. What information leaks during a voice call?

**Per-leg media metadata, no content.** Voice and video calls use
DTLS-SRTP over WebRTC, with the DTLS keys negotiated through
sealed-envelope signaling. Code: `crypto/calls.py` +
`crypto/group_calls.py`.

What leaks:

- to a STUN server (if you use one): both endpoints' public IPs.
  Mitigation: use TURN-only (configured in the client) routed via
  Tor.
- to a TURN/SFU server: opaque encrypted UDP packets. Cannot
  decrypt the media because DTLS-SRTP keys are derived in the
  signaling phase between the endpoints directly.
- voice biometrics: a recording of your voice obviously identifies
  you to anyone who already knows your voice. This is in-content,
  not in-protocol; mitigate with the in-app voice changer (planned)
  or by choosing not to do voice calls.

---

## 9. What about traffic analysis?

**Mitigated, not eliminated.** SHROUD ships:

- Padded envelope sizes (4 KB / 64 KB / 1 MB / 16 MB buckets) so the
  relay cannot distinguish a 100-byte text message from a 4 KB
  voice note by length alone.
- Cover-traffic loop (`server/server.py`'s `/api/v1/messages/cover`
  endpoint and the client-side loops) so the constant rate of
  client → relay traffic is not informative about real send activity.
- Tor / hidden-service routing as an option (`docs/tor.md`) so the
  client's IP is hidden from the relay entirely.
- Adaptive polling cadence (`crypto/polling.py`) so device polling
  intervals are predictable rather than spiking on real activity.

A global passive adversary (think nation-state with full ISP-level
visibility on both ends of a session) can still do statistical
attacks. SHROUD's defenses raise the cost of that attack
significantly but cannot make it impossible without a mixnet, which
is a different design point we may pursue later.

---

## 10. What if the X25519 elliptic curve is broken?

**Hybrid mode covers you.** Every key exchange in SHROUD runs
X25519 *alongside* ML-KEM-1024 (post-quantum). The resulting shared
secret is a KDF over both inputs, so an attacker has to break
**both** to recover the session key. If X25519 falls tomorrow but
ML-KEM doesn't, you're safe. If ML-KEM falls but X25519 doesn't,
you're safe. If both fall, that's a worst-case civilization event
and your messaging app is the least of anyone's concerns.

Code: `crypto/pq_hybrid.py` and `crypto/pq_double_ratchet.py`.

---

## 11. How do I know the relay I'm talking to is the real SHROUD relay?

**Two layers.**

- TLS: the relay presents a self-signed cert that the client pins
  on first connection.
- Server identity: the relay signs every login with its long-term
  Ed25519 identity key. Clients pin this key on first connection
  and refuse to talk to a relay claiming the same hostname but a
  different key.

For Nitro-enclave-hosted relays (`deploy/aws-nitro/`), there's a
third layer: the client requests a Nitro attestation document from
the relay before sending any traffic, verifies that the document is
signed by AWS's hardware root, and refuses to connect if the
attested PCR0 doesn't match the value published in the signed
release manifest. See `deploy/aws-nitro/attestation_verifier.py`.

---

## 12. What about metadata in attachments?

**Stripped before encryption.** Every media path runs through
`crypto/strip_metadata.py`:

- JPEG: APPn segments (EXIF, XMP, IPTC, Photoshop IRBs), COM
- PNG: tEXt / iTXt / zTXt / eXIf / time
- WebP: EXIF / XMP / ICCP chunks
- GIF: comment + application extensions (including XMP)
- MP3: ID3v1 + ID3v2
- WAV: LIST/INFO/bext chunks
- MP4/QuickTime: meta/udta/tref/free/skip/uuid

Unsupported MIMEs raise `UnsupportedMimeError` and the caller is
required to refuse the upload rather than ship unknown metadata.

This is enforced at the protocol module level, not just the UI —
`crypto/voice_notes.py`, `crypto/stickers.py`, and
`crypto/link_preview.py` all call `strip()` before sealing, and a
test asserts plaintext metadata strings don't survive (e.g.
"Software=Some Phone Camera" in a PNG tEXt chunk).

---

## 13. Where are the bugs?

Probably here. SHROUD is young and small. Specific known gaps:

- Windows Qt6 main.cpp still uses the legacy `/api/v1/messages/send`
  path (Rule 1 partially-compliant on current released clients).
  The new `/messages/send-anon` path exists server-side, the C
  library exists, but the UI wireup hasn't shipped yet.
- The OGG/Vorbis-comment strip in `strip_metadata.py` is stubbed.
  Voice notes currently only accept WAV.
- The Linux client is still on the v2.4 rewrite roadmap. The crypto
  layer is ready; the GTK4 UI shell isn't.
- Federation gossip works under SHROUD_FEDERATION=1 but the public
  network currently runs a single relay.

Open issues at https://github.com/ExposingTheBadge/Shroud/issues.

---

## 14. How do I report a security bug?

Email `security@fuseobd.com`. Do not open a public issue for
security-impacting bugs. We aim to acknowledge within 72 hours and
ship a fix within 14 days for high-severity findings. We do not
currently run a bug bounty.

---

## 15. Should I trust SHROUD with my life?

**Not yet.** SHROUD is a young project. Trust it with anything you
would say to a friend over Signal. Don't yet trust it with anything
you would say only behind a face-to-face meeting in a Faraday cage.
That comes after multiple independent audits, multi-year track
record, and federation across operators with no overlapping legal
exposure. We're working toward that. Until then: layer SHROUD
*alongside* other tools, don't depend on it as your only line of
defense.
