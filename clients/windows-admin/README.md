# SHROUD Admin (Windows)

**PRIVATE — not for public distribution.**

`shroud-admin.exe` is the SHROUD operator's local desktop tool. It talks
to your own relay's admin API and your local operator key files. It is
**not** the end-user client (`shroud.exe`), and it must not ship in any
public release.

## What it does

| Tab | Purpose |
|---|---|
| **Federation** | Live grid of all relays in your federation — version, git SHA, uptime, traffic counters, .onion address, capacity. Polls `/api/v1/admin/federation`. |
| **Stats** | This relay's own overview: messages/24h, users, devices, error counters, top endpoints, transport split (clearnet vs .onion). |
| **Controls** | Server controls — toggle maintenance / registration / onion-only, VACUUM DB, purge files, clear ECDH cache, reset rate limits, kill other admin sessions, drop undelivered messages. |
| **Logs** | Live audit / error / failed-login stream over `/ws/admin` WebSocket. Filter by event type. |
| **Users** | User management — list, search, edit, delete, bulk actions. |
| **Diagnostics** | Drain the anonymous error-report inbox. Shells out to `python -m tools.diagnostics_inbox poll` and displays decrypted reports inline. |
| **Manifest** | Build + sign the operator manifest. Shells out to `python -m tools.build_operator_manifest build`. |
| **Relays (SSH)** | One-click SSH commands to each relay: pull master, restart service, view tor status, vacuum DB remotely. |
| **Claude Chat** | Full Anthropic API chat. Pre-loads SHROUD context so the operator can ask "what does the federation roster look like right now?" or "draft me a release notes blurb". |
| **Settings** | Relay URL, admin credentials, Anthropic API key, paths to operator keyfiles. |

## Build (local only)

You need: Qt 6.5+, CMake 3.16+, MSVC 2022, Ninja.

```pwsh
cd clients/windows-admin
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
# Output: build/shroud-admin.exe
```

**Do not** add this directory to `.github/workflows/release-windows.yml`.
The CI workflow ignores it on purpose. The output binary lives only on
your operator workstation.

## Configuration

On first launch the app prompts for:

- Home relay URL (default `https://44.202.225.57:58443`)
- Admin login (passwordless fingerprint enrollment uses the standard
  SHROUD admin flow — your fingerprint must already be registered on
  the relay)
- Path to your manifest signing keyfile
  (`~/.config/shroud/manifest.ed25519.json`)
- Path to your diagnostics keypair
  (`~/.config/shroud/diag.keypair.json`)
- Anthropic API key (read from `$env:ANTHROPIC_API_KEY` if set, or
  prompted)

Settings persist via `QSettings` in `HKCU\Software\SHROUD\admin`.
Sensitive values (API key, admin session token) are stored using
DPAPI; everything else is plaintext.

## What it does NOT do

- Does NOT bundle operator private keys into the binary
- Does NOT sign manifests or decrypt diagnostics on its own — defers to
  the existing Python tooling, which the operator can audit
- Does NOT relay messages, run a federation peer, or accept user
  connections — it's purely an admin client
- Does NOT phone home anywhere except: (1) your configured SHROUD
  relays, (2) Anthropic's API when you send a chat message
