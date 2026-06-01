# SHROUD Windows MSI installer

Builds an MSI for the desktop client using **Advanced Installer 19.x**.

The MSI:

- Installs to `Program Files\SHROUD\` (per-machine, requires admin)
- Bundles `shroud.exe`, Qt6 runtime DLLs, and resources from `dist/`
- Creates Start Menu + Desktop shortcuts
- Registers in *Apps & Features* with a working uninstaller
- Performs a Major Upgrade on reinstall (old version is removed first)
- Pinned `UpgradeCode` — never change it, or upgrades will break

## Prerequisites

| Tool | Why |
|---|---|
| Advanced Installer 19.x | Authors and builds the MSI |
| Windows SDK (signtool.exe) | Optional — local signing |
| PowerShell 7+ (`pwsh`) | Build script runtime (Windows PowerShell 5.1 also works) |
| A populated `clients/windows/dist/` | Source content — produce it via `windeployqt` after `cmake --build` |

If `AdvancedInstaller.com` isn't on PATH, the script auto-detects it under
`Program Files (x86)\Caphyon\Advanced Installer 19.9\bin\`. Override with
`$env:ADVINST = "C:\path\to\AdvancedInstaller.com"`.

## Local build

From the repo root, after you've built `shroud.exe` and run `windeployqt`:

```pwsh
# Default: builds clients/windows/installer/out/SHROUD-v<ver>-win64.msi
pwsh -File clients/windows/installer/build-msi.ps1

# Sign with signtool (uses default cert in user store)
pwsh -File clients/windows/installer/build-msi.ps1 -Sign

# Open the generated .aip in the GUI for visual editing
pwsh -File clients/windows/installer/build-msi.ps1 -Gui
```

Or double-click `build-msi.bat`.

## How it works

`build-msi.ps1` drives Advanced Installer's CLI (`AdvancedInstaller.com`) to:

1. Create `shroud.aip` if absent (`/newproject`)
2. Set product metadata, version (from `VERSION` file), UpgradeCode (`/SetVersion`, `/SetProperty`, `/SetUpgradeOptions`)
3. Sync `dist/` into `APPDIR` (`/DelFolder` + `/AddFolder`)
4. Add Start Menu and Desktop shortcuts (`/NewShortcut`)
5. Build (`/build`)
6. Optionally signtool-sign the resulting MSI

`shroud.aip` is committed once the user runs the script for the first time —
checking it in lets the GUI be used for visual edits later. The script is
**idempotent**: every CLI command can be re-run safely; the .aip converges to
the declared state.

## CI integration

The release workflow (`.github/workflows/release-windows.yml`) installs
Advanced Installer via the [caphyon/advinst-github-action](https://github.com/caphyon/advinst-github-action)
action, runs this same `build-msi.ps1`, then signs the MSI with Azure Artifact
Signing (the same cert that signs `shroud.exe`).

## Stable identifiers

| Field | Value |
|---|---|
| `UpgradeCode` | `{8C7A4F1E-3B2D-4A95-9F1C-7E5B0D6A2F84}` |
| `ProductCode` | regenerated per build (Major Upgrade) |
| `Manufacturer` | `Brent Gordon` |
| `ProductName` | `SHROUD` |
| `InstallDir` | `[ProgramFiles64Folder]SHROUD` |

**Never change `UpgradeCode`** — it's how Windows recognises this is the same
product across versions. If you ever change it, every existing install becomes
a "different product" and won't upgrade.

## What the MSI does NOT do

By design:

- **No autostart at boot.** SHROUD launches only when the user opens it.
- **No telemetry registration.** Diagnostics are anonymous and opt-in.
- **No bundled relay URL hardcoded into MSI registry.** Configured per-user.
- **No firewall rule changes.** TLS to relays uses standard 58443.

Keeps the install minimal and reversible.
