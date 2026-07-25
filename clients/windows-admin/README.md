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

- Home relay URL (default `https://100.30.51.8:58443`)
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

## Building

MSVC 2022 + Qt 6.9.2 `msvc2022_64`. Qt lives on `E:` because `C:` and
`D:` are both down to ~10 GB free.

```pwsh
pip install aqtinstall
aqt install-qt windows desktop 6.9.2 win64_msvc2022_64 -O E:\Qt -m qtwebsockets

$vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "call `"$vcvars`" && cmake -S . -B build-msvc -G `"NMake Makefiles`" ^
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=E:/Qt/6.9.2/msvc2022_64"
cmd /c "call `"$vcvars`" && cmake --build build-msvc"
```

Produces `build-msvc/shroud-admin.exe`. `qtwebsockets` is optional —
CMake defines `SHROUD_ADMIN_HAS_WS` only when it's present.

To refresh the runnable bundle in `dist/` (untracked, local only):

```pwsh
Copy-Item build-msvc\shroud-admin.exe dist\ -Force
cmd /c "call `"$vcvars`" && E:\Qt\6.9.2\msvc2022_64\bin\windeployqt.exe ^
        --release --no-translations dist\shroud-admin.exe"
```

Note: `vswhere.exe` does not report the 2022 installs on this machine —
it only lists SQL Server Management Studio. Point CMake at `vcvars64.bat`
directly rather than trusting toolchain auto-detection. Both
`...\2022\Community` and `...\2022\Enterprise` are present with MSVC
14.44.35207.

### MinGW fallback

If Visual Studio is ever unavailable, MinGW builds the client cleanly and
needs no VS at all:

```pwsh
aqt install-qt   windows desktop 6.9.2 win64_mingw -O E:\Qt -m qtwebsockets
aqt install-tool windows desktop tools_mingw1310   -O E:\Qt

$env:PATH = "E:\Qt\Tools\mingw1310_64\bin;E:\Qt\6.9.2\mingw_64\bin;$env:PATH"
cmake -S . -B build-mingw -G "MinGW Makefiles" `
      -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_PREFIX_PATH="E:/Qt/6.9.2/mingw_64" `
      -DCMAKE_CXX_COMPILER="E:/Qt/Tools/mingw1310_64/bin/g++.exe" `
      -DCMAKE_MAKE_PROGRAM="E:/Qt/Tools/mingw1310_64/bin/mingw32-make.exe"
cmake --build build-mingw --parallel 4
```
