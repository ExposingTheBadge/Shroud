# SHROUD Changelog

## v2.6 — Tor-default, federation dashboard, MSI, operator manifest v2

**Windows**

- **MSI installer** alongside the portable zip. Built with Advanced
  Installer 19.x and Authenticode-signed by Azure Artifact Signing —
  Windows shows *Verified publisher: Brent Gordon* both for the MSI
  itself and the `shroud.exe` it installs. Adds Start Menu + Desktop
  shortcuts, proper *Apps & Features* uninstall, and Major Upgrade
  semantics.
- Anonymous-routing wrapper (`shroud::AnonClient` in `anon_client.{h,cpp}`)
  exposes `sendSealed` / `fetchMessages` with the same shape as the
  Android and iOS ports. Lives next to the existing legacy paths so
  call sites can adopt it incrementally without a risky in-place flip.

**Server / federation**

- New public `GET /api/v1/relay-stats` per relay — operational
  telemetry: version, git SHA, uptime, federation peer count, Tor
  .onion address, traffic counters, disk + load. No PII, no auth.
- New admin `GET /api/v1/admin/federation` — fans out to every peer's
  `/relay-stats` plus self and returns an aggregated health view.
  Tolerates per-peer outages (marked unreachable rather than blowing
  up the response).
- New **Federation** tab in the admin dashboard renders the live grid
  with one card per relay: version, uptime, traffic, disk/load, and
  the Tor v3 hidden service address.
- Tor v3 hidden services provisioned on all 4 production relays
  (us-east-1, us-east-2, us-west-2, eu-west-1). `tools/tor_setup.sh`
  now handles Amazon Linux 2023 (installs from `rpm.torproject.org`
  with `--nodeps` to skip the EPEL-only `torsocks` dep).
- **Username + HWID banning system** (`/api/v1/admin/bans`).
  Banning a username cascades the ban to every hardware ID seen on
  devices linked to that user — banned accounts can't just re-register
  from the same machine. Enforcement runs at the top of `/api/v1/auth`
  and `/api/v1/register` before any password check.
- **Anonymous error reporting** has a real operator key (no longer all
  zeros): reports filed by shipped clients are sealed to a published
  X25519 pubkey and decryptable via
  `python -m tools.diagnostics_inbox poll`. End-to-end verified
  against production: Rule 3 PII scrub (UUIDs, emails, IPv4, POSIX
  usernames) confirmed.

**Operator manifest → v2 (`shroud.operator.v2`)**

- Per-peer optional `onion_endpoint`
- `relay_onion_endpoint` for the home relay
- `tor_socks_proxy` (default `127.0.0.1:9050`)
- `prefer_tor_by_default` — `true`; clients honour this and ride
  `.onion` endpoints when the local SOCKS5 proxy is reachable,
  falling back to clearnet otherwise.

**Clients (Tor on by default)**

- Android `MainActivity.kt`, iOS `ShroudApp.swift`, Windows `main.cpp`
  all bake `PREFER_TOR_DEFAULT = true` plus the manifest pin
  `2fb11de360a0cf6baa35d6785c3945658ae6d64823041729798a2b689ce00ca0`.
- iOS gets a new `NetworkClientAnon.swift` (static `sendSealedAnon` /
  `fetchMessagesAnon`) mirroring the Android and Windows wrappers.

**Release pipeline**

- Major version bumps in `release-windows.yml` now require typing
  `CONFIRM-MAJOR-BUMP` in a separate input — patch/minor still
  single-click.
- Release notes Markdown now actually renders. PowerShell
  array-to-string with `$OFS = ' '` was collapsing every commit onto
  one line; switched to explicit `-join "\`n"` and array-built body
  with ASCII (no BOM) output.
- Version-check endpoint now returns the real `CHANGELOG.md` as the
  `changelog` field instead of a hand-curated wall of text — the
  client's update screen renders proper Markdown again.

**Docs**

- [`docs/federation-deploy.md`](docs/federation-deploy.md) — operator
  runbook for the live deploy: roster, peer onboarding, pubkey
  rotation, us-east-2 IGW gotcha, file-perms troubleshooting.
- [`docs/windows-installer.md`](docs/windows-installer.md) — what the
  MSI does and does not do, identifiers, verify recipe.
- [`tests/federation_live.py`](tests/federation_live.py) — sealed
  envelope to us-east-1 lands at the other 3 regions in ~3s.
- [`tests/diagnostics_live.py`](tests/diagnostics_live.py) — sealed
  PII-laden report decrypts cleanly with the operator's key; Rule 3
  scrub verified.

## v2.5.x — Anonymous routing protocol + 8 platform clients

The shape of the project changed substantially. Headline additions:

**Server**
- Anonymous routing: `/api/v1/messages/send-anon` (sealed envelope,
  per-pair X3DH-derived routing tag, padding buckets) +
  `/messages/fetch-anon` (delete-on-delivery) — Rule 1+2 compliant.
- Federation: `/api/v1/federation/announce` (operator-vetted) +
  `/broadcast` (gossip) + `/delete` (delivery notice). Background loop
  drains the outbox to peer relays. Feature-gated by
  `SHROUD_FEDERATION=1`.
- Anonymous diagnostics: `/api/v1/diagnostics/report` (sealed) +
  `/fetch` (operator-only). Reports never leave the relay in
  plaintext; operator decrypts privately with their X25519 key.
- Disk quota enforcement + abuse rate limiting + diagnostic-report
  sweeper (7-day retention).

**Protocol modules in `crypto/`**
- `anon_routing` (sealed sender + per-pair routing tags), `pq_double_
  ratchet` (ML-KEM mixed into per-message keys, beyond Signal),
  `calls` + `group_calls` (voice/video signaling), `link_preview`
  (sender-side fetch), `stickers` (content-addressed), `disappearing`
  (TTL + secure local wipe), `anon_push` (rendezvous tokens),
  `voice_notes`, `reactions`, `file_transfer` (chunked sealed),
  `backup` (Argon2id + AES-GCM), `local_search` (SSE), `presence`,
  `safety_numbers`, `forward_quote`, `device_link`, `polling`,
  `archive`, `error_reporting`, `operator_manifest`, `abuse`,
  `disk_quota`, `federation`. All ship with self-tests; 21+ green
  in `tests.run_all`.

**Cross-language ports**
- Python (canonical), C (Windows client), Kotlin (Android), Swift
  (iOS + macOS), JavaScript (browser + Node), Rust (single-binary
  CLIs / WASM), Go (server-side workers). Five-way wire-compatible.

**Platform clients**
- Windows Qt6 / C++17 (anon endpoints wired via patch doc;
  anon_routing.c lib shipped)
- Android Kotlin (anon endpoints wired in NetworkClient.kt +
  MainActivity, feature-flagged, compiles + installs + launches)
- iOS Swift (AnonRouting.swift + ErrorReporter.swift; wireup patch)
- macOS AppKit shell
- Linux GTK4 + libadwaita shell (wraps the Python SDK)
- Browser extension (popup + options page) using WebCrypto
- Python SDK (`clients/python_sdk/`) round-trips against the live
  AWS relay
- CLI (`tools/shroud_cli.py`)
- Demo bots + Matrix/Discord bridges

**Operator tools**
- `tools/diagnostics_inbox.py` — anonymous crash report decryption
- `tools/operator_dashboard.py` — live relay stats
- `tools/federation_join.py` — peer onboarding
- `tools/tor_setup.sh` — v3 hidden service in one command
- `tools/shroud_doctor.py` — pre-bug-report sanity checker
- `tools/sticker_authoring.py` — content-addressed pack builder

**Deploy**
- AWS Nitro Enclave (`deploy/aws-nitro/` Terraform + Dockerfile +
  attestation verifier)
- AWS plain (`deploy/aws-simple/` user-data for free-tier t3.micro)
- Docker Compose (`deploy/docker-compose/`)
- Live production relay: `https://44.202.225.57:58443` (us-east-1)

**Tests + CI**
- `tests/run_all.py` runs every module's `_self_test` (21+ green)
- `tests/e2e_anon_protocol.py` round-trips against the live relay
  (7/7 green)
- `tests/benchmark.py` micro-perf sanity
- `.github/workflows/tests.yml` CI on every push

**Docs**
- `docs/anon-routing-protocol.md` (wire-format spec)
- `docs/security-faq.md` (15-question threat model walkthrough)
- `docs/protocol-modules.md` (single-source index)
- `docs/aws-nitro.md` (Nitro deploy runbook)
- `docs/multisig-releases.md`, `docs/tor.md`, `docs/linux-roadmap.md`
- `CONTRIBUTING.md` + `SECURITY.md`

**Hard rules carried through everywhere**
- Rule 0: federation + Docker Compose self-host + Tor + multi-region
  + no-shutdown policy
- Rule 1: sealed envelopes throughout
- Rule 2: per-pair routing tags + delete-on-delivery
- Rule 3: mandatory metadata strip in every media path

## v2.5.0 — Renamed from GHOSTLINK to SHROUD

The project has been renamed. All identifiers, file names, package names,
release artifacts, and documentation now refer to SHROUD. Historical
release archives in `releases/` have been renamed in place; commit
history before this point still references the prior name.

## v1.3.0 — May 24, 2026
**Windows Client (Qt6)**
- Inline image attachments with fullscreen viewer
- Delete message functionality
- Chat UI refinements

**Server**
- Fingerprint grid admin authentication (256-char grid, 3 fails = IP ban)
- Security headers middleware (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy)
- Rate limiting middleware (per-IP request throttling)
- CORS middleware
- Audit logging to audit.log
- Encrypted auth endpoint `/api/v1/auth` (ECDH + AES-256-GCM)

**Android Client**
- Complete Jetpack Compose Material3 rewrite
- Dark theme with orange accent
- Encrypted auth handshake (ECDH P-384 key exchange + AES-256-GCM)
- XOR-obfuscated server IP at rest
- Login/register toggle UI

## v1.2.0 — May 23, 2026
**Windows Client (Qt6)**
- Animated splash screen
- Orange theme (dark/light toggle via Qt Style Sheets)
- Redesigned lattice icon
- Menu bar with File/Edit/View/Help
- Settings dialog (theme, password change, nuke account)
- Stacked widget layout (auth/chat views)
- Connection status indicator (green/red)

**Cryptography**
- Quantum-resistant hybrid key exchange: P-384 ECDH + ML-KEM-1024 (Kyber)
- AES-256-GCM message encryption
- Key derivation: SHA-256(SHA-256(ECDH_raw) + "SHROUD-AUTH-v1")[:32]
- Windows CNG backend via NCrypt (BCRYPT_ECDH_P384_ALGORITHM)
- AndroidKeyStore ECDH key exchange
- liboqs Python bindings for ML-KEM-1024

**Server**
- Blind relay architecture — server never sees plaintext
- Messages destroyed on delivery
- Ephemeral key exchange endpoint `/api/v1/key-exchange`
- Encrypted device registration (no plaintext passwords over wire)
- Device-based authentication (device_id instead of password)

## v1.1.0 — May 23, 2026
- Friends/group contact management
- Exact-match contact search
- Key derivation fix for auth handshake
- Group invite system

## v1.0.1 — May 23, 2026
- Menu bar added
- Settings dialog with theme toggle
- Dark/light theme support via Qt Style Sheets
- Linux client (Makefile + main.c)

## v1.0.0 — May 22, 2026
**Initial Release**
- Windows client: Qt6/C++ with CMake + MSVC
- Android client: Jetpack Compose with Material3
- Blind relay server: Python/FastAPI
- End-to-end encrypted messaging
- XOR-obfuscated server IP in client binaries
- Contact sidebar with search
- Chat area with message input
- Polling-based message fetch
