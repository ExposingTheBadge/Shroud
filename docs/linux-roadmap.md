# Linux Client — Roadmap (deferred to v2.4)

## Current state (v2.3)

`clients/linux/main.c` is **stale**. It was written when the project was
still using a single-shot SHA-256-of-pubkey "key" with raw AES-GCM and
predates almost everything we've shipped since:

| Capability                       | Windows 2.3 | Android 2.3 | Linux today |
|----------------------------------|-------------|-------------|-------------|
| X3DH initial handshake           | yes         | yes         | NO          |
| Double Ratchet per-message keys  | yes         | yes         | NO          |
| Real prekey consumption (v2.2)   | yes         | yes         | NO          |
| Multi-device linking UI (v2.3)   | yes         | yes         | NO          |
| Tor SOCKS5 routing (v2.3)        | yes         | (uses Orbot)| NO          |
| Persistent contacts & groups     | yes         | yes         | NO (volatile only) |
| Cover-traffic loop               | yes         | yes         | NO          |
| Server stats endpoint surfaced   | yes         | yes         | NO          |

It still uses `EC_KEY_new_by_curve_name(NID_secp384r1)` (we moved to
X25519/Ed25519 in v1.8), it uses `SHA256(identity_pub)` as the AES key
(no DH, no ratchet — every message to the same peer has the same key),
and the HTTP layer is synchronous on the GTK main loop (it freezes the
UI on every network call).

We are **not** shipping the existing binary with v2.3. The Makefile and
`main.c` stay in the tree for git history but are not built or
distributed.

## Why we're deferring (and what we're deferring TO)

The Linux client is a ground-up rewrite, not a port. The right plan:

### v2.4 — clients/linux rewrite

1. **Drop GTK3, use GTK4 + libadwaita.** GTK3 is end-of-life upstream;
   libadwaita gives us a modern look-and-feel that matches the
   "messenger app" pattern users expect.
2. **Replace the crypto.** Pull `clients/windows/ratchet.c` /
   `ratchet.h` (the same code that already powers the Windows client)
   into a small static library:
     - `clients/common/ratchet/` — platform-independent X3DH + Double
       Ratchet implementation (libsodium under the hood).
     - Linked into Windows, Linux, future macOS clients.
   The Android client keeps Kotlin for now (its `Ratchet.kt` is the
   reference implementation), but ports its behaviour from the same test
   vectors.
3. **Replace the storage.** SQLite-backed contacts, conversations,
   prekeys, and ratchet state — matching the schema we already use on
   Windows. Encrypted at rest with a key derived from the user's
   password via Argon2id.
4. **Async network layer.** libcurl multi handle + GLib `GTask`, so HTTP
   never blocks the GTK main loop. Optional Tor SOCKS5 toggle (read from
   the same env var or config setting as Windows uses).
5. **Multi-device linking.** Reuse the X25519 + AES-GCM linking flow
   already shipped on Windows and Android in v2.3.

### v2.5 — packaging

- Flatpak manifest in `clients/linux/flatpak/`.
- AppImage build via `linuxdeploy`.
- Both built reproducibly per `BUILD-REPRODUCIBILITY.md` and signed
  alongside Windows / Android in the multi-sig bundle.

### v2.6 — feature parity polish

- Cover-traffic loop, matching Windows.
- Sidebar Groups tab (placeholder exists in the stale C code but doesn't
  do anything).
- Notifications via libnotify.
- System-tray integration (libayatana-appindicator).

## Why not "just upgrade the existing C client"?

Two reasons:

1. **The C client never had the Double Ratchet.** Adding it on top of
   the existing structure means hand-porting `ratchet.c` to GTK, then
   ALSO hand-porting prekey consumption, multi-device linking, etc. The
   surface area we'd touch is ~80% of the file. At that point a clean
   rewrite is cheaper.
2. **GTK3 vs GTK4 is a parallel disruption.** Doing the crypto rewrite
   on GTK3 just to redo it for GTK4 next release wastes effort. Better
   to land both at once.

## Threat-model gap until v2.4

A user who runs **today's** stale Linux client gets:
- Identity-key reuse across messages (no forward secrecy, no break-in
  recovery — a full ratchet rollback if anyone leaks the identity key
  exposes every prior conversation).
- Plaintext HTTP only (`http://150.195.114.185:58443` was hardcoded
  before we required TLS; this is its own problem).
- No Tor support, even though the v1.5 onion-only server setting exists.

This is materially weaker than the iron-clad model the Windows and
Android clients deliver in v2.3. **Do not use the legacy Linux client in
production.** Wait for v2.4, or use the Windows client under Wine /
Crossover until then.

## What to do RIGHT NOW if you're a Linux user

Three options, in order of preference:

1. **Use the Android client.** It is feature-complete and ships with the
   v2.3 changes.
2. **Run the Windows client under Wine.** It works under recent
   wine-staging; the Qt6 stack ships fine. We'll provide tested install
   notes when v2.3 hits the release page.
3. **Wait for v2.4.** ETA is "next minor release after v2.3"; no
   firmer date because we'd rather ship something correct than something
   on a schedule.

## When this doc gets deleted

When `clients/linux/` contains a libadwaita / GTK4 client that uses the
common `ratchet` library, supports all v2.3 features, and is bundled in
`scripts/repro-check.sh`, delete this roadmap. Until then, it's the
canonical answer to "where's the Linux client?"
