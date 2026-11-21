# SHROUD session notes (handoff before context compaction)

> SHROUD runs as a single relay at `173.245.244.180:58443` on the
> operator's own machine, with federation off. **No cloud provider is
> used** (the 2026 AWS relays were retired on 2026-09-28 and every AWS
> deploy recipe was removed on 2026-11-21).

## Current status (2026-11-21)

Full-project pass on branch `claude/project-thread-azdzka`, stacked on
PRs #4 (admin sign-in) and #5 (iOS + cross-platform fixes).

- **Device tokens.** A device id used to be the only credential, and
  friends learn it from `/contacts/devices`. Every password sign-in now
  returns `device_token`; clients send `X-Device-Token` (WebSocket:
  `?token=`). The first correct token binds the device; after that the
  bare id is refused. Unbound (old-app) devices keep working until the
  admin console's *Relay Policy > Require device tokens* is turned on.
  Watch the "N / M devices use a token" pill before turning it on.
- `/contacts/devices` is friends-only (and self).
- WebSocket deletes on delivery and is woken instantly by sends.
- Retention: undelivered mail is dropped after `undelivered_retention_days`
  (default 30); upload cap `max_upload_mb` (default 100). Both are in the
  admin Relay Policy panel.
- Windows pins the relay TLS certificate (`%APPDATA%\SHROUD\tls_pin.txt`,
  delete it after deliberately replacing the relay certificate).
- The relay root `/` serves a landing page to browsers; the admin console
  and sign-in were redesigned (sidebar, violet/teal palette, light theme).
- Browser extension now actually loads (vendored `lib/anon_routing.js`,
  icons, module options page). `tests/repo_consistency.py` keeps the copy
  in sync.

## Earlier status (2026-11-07)

Everything below this section is history from September. What is true now:

- One relay at `173.245.244.180:58443`, federation off.
- The "outstanding user asks" further down are all closed:
  1. MSI: done (`clients/windows/installer/`, uploaded by `tools/make-msi-release.ps1`).
  2. Diagnostics key: real key `7191a786…fd54` is in Android, iOS and Windows.
  3. Windows anon routing: text, images and file notices all go sealed.
  4. iOS: now a complete client (sign-in, contacts, Double Ratchet, anon
     routing, TLS pinning), shared with macOS. See `clients/ios/README.md`.
  5. Federation gossip on live relays: moot while federation is off; the
     two-relay test (`tests.federation_e2e`) covers it.
- Anonymous payload shape differs by sender: Windows seals
  `{"envelope": env, "ts"}`, Android and iOS seal `env` itself. Every
  receiver accepts both. Keep it that way, or pick one and change all three.
- A message's `name` field is sender-chosen. Clients file a message under a
  contact only if the sending device belongs to that account
  (`/contacts/devices`); otherwise it shows as "(unverified)".
- Static-key fallback envelopes are not interoperable across platforms
  (Android HMAC-SHA256(label, ecdh), Python HKDF, Windows SHA-256(ecdh)).
  It only matters when a peer never published a ratchet bundle, which every
  current client does on sign-in.
- Not built or run here: the Swift, Kotlin and C++ changes. CI covers the
  Python relay; the clients need a build on a machine with Xcode, the
  Android SDK, and Qt6/MSVC.

## Hard rules (saved in memory, must NOT be violated)

- **Rule 0:** project never shuts down for any reason (federation,
  Tor, self-hosted mirrors)
- **Rule 1:** server cannot identify sender (sealed envelopes)
- **Rule 2:** server cannot identify receiver (per-pair routing tags,
  delete-on-delivery)
- **Rule 3:** no transmitted content carries identifying metadata
  (mandatory `strip_metadata` for every media path)
- Plus: no Co-Authored-By Claude trailers, no asking about partial
  enforcement, no long status checkpoints during "keep going" sessions

These are in `~/.claude/projects/D--GHOSTLINK/memory/` if you need to
re-load them.

---

## What was shipped this session (high level)

### Protocol layer (`crypto/`)
- `anon_routing` — sealed envelopes + per-pair epoch routing tags
- `pq_double_ratchet` — beyond Signal: ML-KEM mixed into per-message keys
- `calls` + `group_calls` — voice/video signaling with SDP scrubbing
- `link_preview`, `stickers`, `voice_notes`, `reactions`, `file_transfer`
- `disappearing`, `anon_push`, `presence`, `safety_numbers`, `forward_quote`
- `device_link`, `polling`, `archive`
- `backup` (Argon2id + AES-GCM), `local_search` (SSE)
- `error_reporting`, `operator_manifest`, `abuse`, `disk_quota`
- `federation` + server endpoints + background gossip loop
- `strip_metadata` (JPEG/PNG/WebP/GIF/MP3/WAV/MP4)
- All ship with `_self_test`; 21+ pass in <1s via `tests.run_all`

### Server
- Anonymous routing endpoints `/messages/send-anon`, `/messages/fetch-
  anon` (delete-on-delivery)
- Federation endpoints `/federation/{announce,broadcast,delete,peers}`
- Diagnostics endpoints `/diagnostics/{report,fetch}` (sealed, 4096-byte
  padded)
- Background gossip loop + sweeper (TTL'd messages, expired link
  sessions, expired diag reports)
- `SHROUD_DB_PATH` env var override for multi-instance testing

### Platform clients
- **Windows** Qt6 / C++17 — `anon_routing.c` + `error_reporter.c`
  shipped; main.cpp anon wireup via patch doc; error reporter installs
  at app start
- **Android** Kotlin — `AnonRouting.kt` + `ErrorReporter.kt` shipped;
  `NetworkClient.kt` has `sendAnon`/`fetchAnonForContacts`; MainActivity
  branches on `useAnonRouting` flag (default true); **compiles green +
  installs on real device verified**
- **iOS** Swift — `AnonRouting.swift` + `ErrorReporter.swift` shipped;
  `ShroudApp.swift` wires `ErrorReporter.install`; UI patch doc
- **macOS** Swift/AppKit — shell + `NetworkClient.swift` stubs
- **Linux** GTK4 — `clients/linux/shroud_gtk.py` UI + Python re-export
- **Browser** — `clients/web/anon_routing.js` (WebCrypto) + browser
  extension (popup + options page)
- **CLI** — `tools/shroud_cli.py` REPL on Python SDK
- **Python SDK** — `clients/python_sdk/` end-to-end verified
- **Rust** — `clients/rust_sdk/` (x25519-dalek + aes-gcm)
- **Go** — `clients/go_sdk/` (golang.org/x/crypto)

### Operator tools
- `tools/diagnostics_inbox.py` — keygen + poll + decrypt anon reports
- `tools/operator_dashboard.py` — live relay stats
- `tools/federation_join.py` — peer onboarding interactive script
- `tools/tor_setup.sh` — v3 hidden service one-shot installer
- `tools/shroud_doctor.py` — pre-bug-report sanity checker
- `tools/sticker_authoring.py` — content-addressed pack builder
- `tools/echo_bot.py` — minimal demo bot
- `tools/matrix_bridge.py` + `tools/discord_bridge.py` — opt-in
  bridges
- `tools/voice_call_demo.py` — aiortc reference for crypto/calls.py
- `tools/shroud_cli.py` — interactive REPL

### Deploy options
- Docker Compose (`deploy/docker-compose/`) for self-hosters
- Plain Python on the operator's machine (`server/server.py`)

### Tests + CI
- `tests/run_all.py` — runs every module self-test (21+ green in
  <1s)
- `tests/repo_consistency.py` — extension library copy, icons, no retired relays
- `tests/e2e_anon_protocol.py` — 7/7 against live relay (anon send/
  fetch + Rule 2 delete + tag rotation + federation 403 + federation
  dedup + diagnostics roundtrip)
- `tests/federation_e2e.py` — boots 2 in-process relays, federates
  them, verifies gossip works (PASS)
- `tests/benchmark.py` — micro-perf sanity
- `.github/workflows/tests.yml` — CI on every push, green

### Docs
- `README.md` updated with all features + warrant policy
- `docs/anon-routing-protocol.md` — wire format spec
- `docs/security-faq.md` — 15-question threat model walkthrough
- `docs/protocol-modules.md` — single-source index
- `docs/multisig-releases.md`, `docs/tor.md`
- `CONTRIBUTING.md`, `SECURITY.md`, GitHub issue/PR templates
- `CHANGELOG.md` updated with full v2.5.x summary

---
