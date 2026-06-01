# SHROUD session notes (handoff before context compaction)

## Where things stand

The SHROUD project (renamed from GHOSTLINK earlier this session) now
runs a **4-region federated AWS deploy**, full protocol stack across
8 platforms, anonymous error reporting with operator-side decryption,
and 21+ self-tested crypto modules. All work pushed to
`https://github.com/ExposingTheBadge/Shroud` on `master`.

This file is the snapshot you need to resume work after context
compaction.

---

## Live infrastructure

### Production relays (all healthy, all federated 4-way)

| Region | Public IP | Instance ID | SSH key file | Operator Ed25519 pubkey |
|---|---|---|---|---|
| us-east-1 (Virginia) | `44.202.225.57` | `i-017e9f45b02f31d04` | `Documents\AWS-Keys\shroud-relay.pem` | `3e82643a345451f867b2d336c97f12def70c59afb4fd95e7714f8a72920ef374` |
| us-east-2 (Ohio) | `3.142.185.104` | `i-09802917ea14f357a` | `Documents\AWS-Keys\shroud-relay-useast2.pem` | `958f11b92f4ae1b8f3b03cfbf020efd67d89afb8a65a51674f146145f8262d93` |
| us-west-2 (Oregon) | `54.214.75.14` | `i-0dc3f833728c551df` | `Documents\AWS-Keys\shroud-relay-uswest2.pem` | `2cf90ad74ca6ac49de311dd481994735e47a61ad148234621c19edd498ba40f2` |
| eu-west-1 (Ireland) | `54.171.165.223` | `i-032f9c65978e3a7a5` | `Documents\AWS-Keys\shroud-relay-euwest1.pem` | `79f49802d116f91ba70f4079b967e0c89532d0b3dbce65f1b6d8436699eb0417` |

Each relay has:
- t3.micro (1 vCPU, 1 GiB RAM, 8 GB gp3 EBS)
- Python 3.11 venv at `/opt/shroud/venv`
- Source tree pulled from `master` at `/opt/shroud/src`
- Self-signed TLS at port 58443
- `SHROUD_FEDERATION=1` in `/etc/systemd/system/shroud-relay.service.d/federation.conf`
- Operator Ed25519 keypair at `/opt/shroud/data/operator_ed25519.json` (chmod 600)
- 3 peer pubkeys pre-approved in `federation_peers` table
- Active 3-peer roster verified via `/api/v1/federation/peers`

### us-east-2 SG fix worth remembering
The default subnet in us-east-2 was missing the IGW route in its custom route
table. Manually added: `aws ec2 create-route --region us-east-2
--route-table-id rtb-0369c2dbabadba03b --destination-cidr-block 0.0.0.0/0
--gateway-id igw-09a8298a9fbc7e535`. If you create more relays in this
region, watch for this.

### Costs
- Each t3.micro: free tier covers first 12 months; ~$8.50/mo each after
- 4 relays = ~$34/mo after free tier expires
- 8 GB EBS each: minimal cost
- Data transfer: free for inbound, $0.09/GB outbound after the free tier

To tear down a relay:
```pwsh
aws ec2 terminate-instances --region <region> --instance-ids <id>
```

---

## Outstanding user asks (unfinished)

1. **Advanced Installer 19.9 integration for Windows MSI builds.** User
   mentioned they installed it. Not yet wired into the Windows build
   pipeline. Suggested next: create `clients/windows/installer/` with
   an Advanced Installer `.aip` project that consumes the existing
   Authenticode-signed `shroud.exe` from `.github/workflows/release-
   windows.yml` and produces an MSI. The signed exe lives in the GitHub
   Release artifacts.

2. **Real diagnostics keypair publication.** The Android / iOS / Windows
   error reporters are wired and compile but their `OPERATOR_DIAG_
   PUBKEY_HEX` is all zeros (placeholder). To activate:
   - Run `python -m tools.diagnostics_inbox keygen --keyfile ~/.config/
     shroud/diag.keypair.json` to mint a real operator diagnostics
     keypair
   - Replace the all-zero constant in:
     - `clients/android/.../MainActivity.kt` `OPERATOR_DIAG_PUBKEY_HEX`
     - `clients/ios/ShroudApp.swift` `OPERATOR_DIAG_PUBKEY_HEX`
     - `clients/windows/main.cpp` `g_operator_diag_pubkey` array
   - Ship a release containing the new constants
   - Run `python -m tools.diagnostics_inbox poll --keyfile ~/.config/
     shroud/diag.keypair.json` whenever you want to drain reports

3. **Windows main.cpp anon endpoint wireup** — patch doc exists at
   `clients/windows/main_anon_patch.md`. Android version is **already
   committed** (NetworkClient.kt + MainActivity.kt) and compiles green
   on the connected device (`R5CTA2BWYCH`). Windows still uses the
   patch doc approach because we can't compile here without Visual
   Studio + Qt6 SDK.

4. **iOS UI integration** — `ErrorReporter.swift` and
   `AnonRouting.swift` are committed; `ShroudApp.swift` wires
   `ErrorReporter.install`. The legacy send/fetch path in iOS still
   uses `/messages/send` though — patch doc at
   `clients/ios/main_anon_patch.md` lays out the swap.

5. **Real federation gossip e2e** — local in-process test passes
   (`python -m tests.federation_e2e`). On the live 4-relay federation,
   gossip should work but **hasn't been smoke-tested yet** since the
   federation roster only just got verified. Next: post a sealed
   message to us-east-1's `/send-anon`, poll the same tag at the other
   3 relays, confirm it gossiped.

---

## Hard rules (saved in memory, must NOT be violated)

- **Rule 0:** project never shuts down for any reason (federation
  + multi-region + non-AWS mirrors)
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
- AWS Nitro Enclave (`deploy/aws-nitro/` Terraform + Dockerfile +
  attestation verifier)
- AWS plain user-data (`deploy/aws-simple/user-data.sh`) — what the 4
  live relays use
- Docker Compose (`deploy/docker-compose/`) for self-hosters

### Tests + CI
- `tests/run_all.py` — runs every module self-test (21+ green in
  <1s)
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
- `docs/aws-nitro.md`, `docs/multisig-releases.md`, `docs/tor.md`
- `CONTRIBUTING.md`, `SECURITY.md`, GitHub issue/PR templates
- `CHANGELOG.md` updated with full v2.5.x summary

---

## Suggested next concrete actions when context resumes

1. **Smoke-test the live 4-relay federation gossip.** Post a sealed
   envelope to us-east-1, poll the same tag at us-east-2/us-west-2/
   eu-west-1, verify it arrives. Should take <30s end-to-end.

2. **Wire Advanced Installer for Windows MSI.** Create
   `clients/windows/installer/shroud.aip` and update the Windows
   release workflow to produce an MSI alongside the .zip.

3. **Apply the Windows anon patch doc** from
   `clients/windows/main_anon_patch.md` to `clients/windows/main.cpp`
   so the production Windows client sends Rule 1+2 compliantly.

4. **Mint and publish the real operator diagnostics keypair** (see
   "Outstanding user asks" above).

5. **Document the live federation deployment** in `docs/federation-
   deploy.md` — operator handles, pubkey rotation procedure, the
   us-east-2 IGW gotcha, etc.

---

## Quick reference commands

### SSH to any relay
```pwsh
$key = "$env:USERPROFILE\Documents\AWS-Keys\shroud-relay-<region>.pem"
ssh -o StrictHostKeyChecking=no -i $key ec2-user@<IP>
```

### Restart a relay
```bash
# On the box:
sudo systemctl restart shroud-relay.service
```

### Update a relay to latest master
```bash
# On the box:
cd /opt/shroud/src && sudo git pull origin master && sudo systemctl restart shroud-relay.service
```

### Federate a NEW operator
```pwsh
python -m tools.federation_join `
  --my-endpoint https://<new-relay>:58443 `
  --existing-relay-url https://44.202.225.57:58443 `
  --keyfile ~/.config/shroud/operator.ed25519.json
```

### Drain anonymous error reports
```pwsh
python -m tools.diagnostics_inbox poll `
  --keyfile ~/.config/shroud/diag.keypair.json
```

### Tear everything down (NUCLEAR)
```pwsh
foreach ($i in @(
  @{Region="us-east-1"; Id="i-017e9f45b02f31d04"}
  @{Region="us-east-2"; Id="i-09802917ea14f357a"}
  @{Region="us-west-2"; Id="i-0dc3f833728c551df"}
  @{Region="eu-west-1"; Id="i-032f9c65978e3a7a5"}
)) {
    aws ec2 terminate-instances --region $i.Region --instance-ids $i.Id
}
```
