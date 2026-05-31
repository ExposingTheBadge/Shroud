# SHROUD protocol modules index

Every cryptographic and protocol building block ships as a self-
contained Python module in `crypto/`, with byte-compatible ports in
`clients/windows/`, `clients/android/`, `clients/ios/`, and
`clients/linux/` (re-export) wherever a client needs to interop with
the bytes the Python ref produces.

This index is the single source of truth for what exists. Use it as a
map when wiring up a new client, when auditing for completeness, or
when deciding what to extend next.

| Module | Purpose | Server | Python | C / Win | Kotlin / Android | Swift / iOS | Linux |
|---|---|---|---|---|---|---|---|
| `crypto/anon_routing.py` | Sealed sender + per-pair epoch routing tags (Rule 1+2). Wire spec in `docs/anon-routing-protocol.md`. | endpoints live | ref | port | port | port | re-export |
| `crypto/strip_metadata.py` | Universal metadata strip for JPEG, PNG, WebP, GIF, MP3, WAV, MP4 (Rule 3). | self-test on box | ref | — | — | — | via py |
| `crypto/pq_hybrid.py` | Hybrid X25519 + ML-KEM-1024 KEM construction. | uses for auth | ref | ratchet.c | crypto provider | CryptoKit + Tink | via py |
| `crypto/pq_double_ratchet.py` | Post-quantum Double Ratchet — beyond Signal PQXDH, mixes ML-KEM into per-message keys. | n/a | ref | follow-up port | follow-up port | follow-up port | via py |
| `crypto/calls.py` | 1-on-1 voice/video signaling, SDP sanitization. | n/a | ref | follow-up port | follow-up port | follow-up port | via py |
| `crypto/group_calls.py` | N-party voice/video signaling (full-mesh / SFU / hybrid). | n/a | ref | follow-up port | follow-up port | follow-up port | via py |
| `crypto/link_preview.py` | Privately-fetched URL previews; preview ships inside sealed payload, URL never touches recipient network. | n/a | ref | — | — | — | via py |
| `crypto/stickers.py` | Content-addressed sticker packs (Rule 3 — no per-user packs). | static CDN | ref | — | — | — | via py |
| `crypto/disappearing.py` | TTL + secure local wipe of media + SQLite rows. | server TTL sweeper | ref | — | — | — | via py |
| `crypto/anon_push.py` | Rendezvous-token-based push that hides sender/recipient/content from Apple/Google. | n/a | ref | — | — | — | via py |
| `crypto/federation.py` + `server/server.py` federation endpoints | Multi-relay gossip with operator-vetted Ed25519-signed peer roster (Rule 0). | live | ref | — | — | — | via py |
| `crypto/voice_notes.py` | Voice-note packaging (WAV today, OGG when strip_metadata catches up). | n/a | ref | — | — | — | via py |
| `crypto/reactions.py` | Emoji reactions referencing parent message_id. | n/a | ref | — | — | — | via py |
| `crypto/file_transfer.py` | Chunked sealed file transfer with per-file SHA-256 integrity. | n/a | ref | — | — | — | via py |
| `crypto/backup.py` | Argon2id + AES-GCM password-encrypted vault export / restore. | n/a | ref | — | — | — | via py |
| `crypto/local_search.py` | Searchable symmetric encryption (HMAC token hashes) for local search index. | n/a | ref | — | — | — | via py |
| `crypto/presence.py` | Read receipts + typing indicators (opt-in, opt-out). | n/a | ref | — | — | — | via py |
| `crypto/safety_numbers.py` | Per-pair identity fingerprint (Signal-style 30-digit display) + QR. | n/a | ref | algo in main.cpp | follow-up port | follow-up port | via py |
| `crypto/forward_quote.py` | Forwarding (without signature chain) + quoting (with excerpt cap). | n/a | ref | — | — | — | via py |
| `crypto/device_link.py` | Multi-device linking flow on top of existing server `/devices/link/*` endpoints. | endpoints live | ref | — | — | — | via py |
| `crypto/polling.py` | Adaptive battery-aware poll cadence (foreground / background / low-battery / doze / offline). | n/a | ref | — | — | — | via py |
| `crypto/archive.py` | SQLite-backed per-conversation archive / mute / pin / unread state. | n/a | ref | — | — | — | via py |
| `crypto/treekem.py` | TreeKEM group key agreement. | endpoints live | ref | — | — | — | via py |
| `crypto/anon_creds.py` | Blind RSA anonymous credentials for rate-limited anonymous tokens. | endpoints live | ref | — | — | — | via py |
| `crypto/srp6a.py` | SRP-6a password-authenticated key exchange (server never sees password). | endpoints live | ref | — | — | — | via py |
| `crypto/double_ratchet.py` | Classical Signal Double Ratchet (pre-PQ; legacy compatibility). | n/a | ref | ratchet.c | full port | follow-up port | via py |
| `crypto/at_rest.py` | At-rest encryption helpers for local SQLite vault. | uses for data.key | ref | — | — | — | via py |
| `crypto/hybrid_sig.py` | Ed25519 + ML-DSA-87 + SPHINCS+ triple-hybrid signatures. | identity signing | ref | follow-up port | follow-up port | follow-up port | via py |
| `crypto/fips_crypto.py` | FIPS 140-2 validated subset of the crypto surface. | enforces on FIPS mode | ref | — | — | — | via py |

## Reference client SDK

`clients/python_sdk/shroud_client.py` wraps the above into a minimal
high-level client that round-trips messages end-to-end against the
live relay. Use it as a reference for what each platform's native
client should look like at the API layer.

## Integration tests

`tests/e2e_anon_protocol.py` runs against the deployed relay and
asserts the wire-format-critical behaviors:

- `send-anon` + `fetch-anon` roundtrip
- Rule 2 delete-on-delivery
- routing tag rotation across epochs
- federation `/announce` rejection of unknown pubkey
- federation `/broadcast` dedup

Run via `python -m tests.e2e_anon_protocol`. CI-friendly: skips
silently if the relay is unreachable.

## What's still owed

This index is honest about gaps. Specific items not yet shipped:

- Windows / Android / iOS UI integration — the legacy `/messages/send`
  path still drives the running clients. The C / Kotlin / Swift libs
  exist; wiring them into `main.cpp` / `MainActivity.kt` /
  `GhostlinkApp.swift` is the next major piece of work.
- WebRTC media stacks for voice + video calls — the signaling is
  fully specified and tested; the actual platform integration is
  left to the per-platform builds.
- An SFU implementation for group calls — currently only full-mesh
  group calls are practical without a SHROUD-operated SFU.
- The Linux GTK4 + libadwaita UI — roadmap doc in
  `docs/linux-roadmap.md`; crypto layer ready via the Python re-export.
