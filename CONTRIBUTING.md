# Contributing to SHROUD

SHROUD has hard constraints that override every other consideration.
Before you open a PR, read these — anything that violates them gets
closed without negotiation.

## The four inviolable rules

**Rule 0 — The project never shuts down.** No court order, no
government demand, no hosting takedown will result in the project
ceasing operation. Code, infrastructure, and contributors are
designed to be replaceable / mirrorable so that no single actor can
silence the network.

**Rule 1 — The server cannot identify the sender.** Every message
leaves the client as a sealed envelope where the sender's identity
lives inside the AES-256-GCM ciphertext, not in any header or
routing field.

**Rule 2 — The server cannot identify the receiver.** Messages are
queued by a per-pair routing tag derived from secrets the server
never sees. The server deletes messages on first fetch in the same
transaction as the SELECT.

**Rule 3 — No content can carry identifying metadata.** Every media
attachment passes through `crypto/strip_metadata.py` (or a port
thereof) before it's sealed. EXIF, IPTC, XMP, ID3, LIST/INFO,
file modification times, container-level "author" fields — all
stripped.

PRs that weaken any of these for any reason — even temporarily, even
behind a feature flag, even for "compatibility" — will be closed.

## What to read first

1. [`README.md`](README.md) — high-level project intro.
2. [`docs/security-faq.md`](docs/security-faq.md) — the threat model
   in concrete terms, with code references.
3. [`docs/protocol-modules.md`](docs/protocol-modules.md) — index of
   every protocol module with its purpose and per-platform status.
4. [`docs/anon-routing-protocol.md`](docs/anon-routing-protocol.md) —
   wire format spec.
5. [`docs/multisig-releases.md`](docs/multisig-releases.md) — release
   signing trust model.

## Repository layout

```
crypto/                Python reference implementations of every
                       protocol building block. Canonical.
clients/windows/       Qt6 + C++17 desktop client
clients/android/       Jetpack Compose Android client
clients/ios/           SwiftUI iOS client (experimental)
clients/linux/         Linux client (rewrite roadmap in docs/)
clients/python_sdk/    High-level Python client SDK + reference impl
server/                FastAPI relay server
release/               Release signing tooling
deploy/aws-nitro/      Terraform + Docker for Nitro Enclave deployment
deploy/aws-simple/     Plain t3.micro deploy (no enclave)
docs/                  Specs, runbooks, FAQs
tests/                 Self-test runner + e2e integration tests
tools/                 Demo bots / CLI utilities
```

## Setting up

```bash
git clone https://github.com/ExposingTheBadge/Shroud
cd Shroud

# Python deps for the server + ref impls + tests
pip install -r requirements-server.txt
pip install argon2-cffi liboqs-python

# Run every module self-test in one shot
python -m tests.run_all

# Run the e2e tests against the live AWS relay
python -m tests.e2e_anon_protocol
```

For platform clients, see their per-directory READMEs.

## What's worth contributing

In priority order (highest impact first):

1. **Windows/Android/iOS UI integration with the anon endpoints.**
   The Python/C/Kotlin/Swift libs exist; what's missing is the
   actual UI wireup in `clients/windows/main.cpp`,
   `clients/android/.../MainActivity.kt`, and
   `clients/ios/GhostlinkApp.swift`. This is the highest-impact open
   work — it makes the running production clients fully Rule 1+2
   compliant.

2. **WebRTC media stacks** for `crypto/calls.py` and
   `crypto/group_calls.py`. Signaling is fully specified and tested.
   Per-platform WebRTC integration (libwebrtc / WebRTC.framework /
   org.webrtc) is required to actually move audio/video bytes.

3. **A SFU implementation** so group calls scale past 6 participants.
   `crypto/group_calls.py` defines the wire format; a Python SFU
   server stub is in `server/sfu.py` (todo: connect to a real
   media-relay library like aiortc).

4. **Linux GTK4 + libadwaita UI**. Crypto layer is ready via the
   Python re-export at `clients/linux/shroud_anon_routing.py`. The
   roadmap doc at `docs/linux-roadmap.md` lays out the plan.

5. **Cross-language ports of `pq_double_ratchet`, `calls`,
   `safety_numbers`** for C / Kotlin / Swift. Currently only the
   Python ref exists; clients need byte-compatible ports.

6. **More media format coverage in `strip_metadata`** — particularly
   OGG/Vorbis comments and WebM (Matroska) box stripping. Voice
   notes currently only accept WAV because of this gap.

7. **Audit + test coverage** — every module ships a `_self_test()`,
   but those are sanity checks, not fuzz/property tests. Adding
   hypothesis-style property tests around the wire formats would
   meaningfully harden the codebase.

## How to send a PR

1. Fork, branch off `master`.
2. Make the change. If it's a protocol-level change, update the
   relevant doc in `docs/` and the canonical Python ref before
   touching any client port.
3. Run `python -m tests.run_all` and `python -m tests.e2e_anon_protocol`
   locally. Both must be green.
4. Run the per-platform self-tests if you touched a client port.
5. Open the PR against `master`. Tag the relevant area in the title
   (e.g., `crypto:`, `server:`, `clients/windows:`).
6. Expect crypto-touching PRs to be reviewed slowly and skeptically.
   We treat the cryptographic surface as adversarial — every change
   gets thought experiments around how it could be a subtle weaken.

## Code style

- Python: PEP 8, `from __future__ import annotations` at the top of
  every file. Use stdlib + `cryptography` whenever possible; avoid
  pulling new deps unless there's no alternative.
- C (Windows client): match the existing style in `clients/windows/`.
  Use BCrypt, not OpenSSL — Windows native crypto means the client
  doesn't carry a giant OpenSSL DLL around.
- Kotlin: idiomatic Kotlin + AndroidX. Don't pull Google Play
  Services as a dependency; we ship without GMS dependency on
  purpose.
- Swift: CryptoKit only. No third-party crypto.

## Things we will not accept

- Any feature that requires Apple/Google/Microsoft cooperation to
  function (e.g., a centralized push gateway, App Store-only
  distribution dependency).
- Telemetry of any kind. Anonymous, aggregated, or otherwise. No.
- A `--disable-encryption` flag.
- Code that depends on a single CA chain or a single root of trust
  for identity verification.
- "Just trust us" arguments for cryptographic changes. Show the
  threat model + the math.

## Security disclosure

Do NOT open public GitHub issues for security-impacting bugs. Email
`security@fuseobd.com` with:

- A description of the issue
- Reproduction steps or PoC
- Your read on impact severity
- Affected client / server version

We aim to acknowledge within 72 hours and ship a fix within 14 days
for high-severity findings. We do not currently run a bug bounty.

## License

Contributions are licensed under GPL-3.0-or-later (see
[`LICENSE`](LICENSE)). By submitting a PR you confirm you have the
right to license your contribution under that license.
