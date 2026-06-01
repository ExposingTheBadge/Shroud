# Windows MSI installer

SHROUD ships two Windows artifacts per release:

| Artifact | Purpose |
|---|---|
| `SHROUD-v<ver>-win64.msi` | Full installer (recommended) |
| `SHROUD-v<ver>-win64.zip` | Portable build (extract + run) |

Both are Authenticode-signed by **Brent Gordon** via Azure Artifact Signing.

## What the MSI does

- Installs to `C:\Program Files\SHROUD\` (per-machine; admin elevation)
- Drops `shroud.exe`, all required Qt6 runtime DLLs, plugins, and resources
- Creates a Start Menu shortcut and a Desktop shortcut
- Registers in *Apps & Features* under **SHROUD** publisher *Brent Gordon*
- Provides a working uninstaller — `shroud.exe` and all bundled files are
  removed; per-user `%APPDATA%\SHROUD\` config is **kept**
- Performs a clean **Major Upgrade** if an older version is present: the old
  install is removed first, then the new one goes in

## What the MSI does NOT do (by design)

- Does not autostart SHROUD at boot
- Does not register a system service
- Does not modify Windows Firewall rules
- Does not write anything to `HKEY_LOCAL_MACHINE` beyond standard
  uninstall metadata
- Does not phone home — diagnostics are anonymous, opt-in, and sealed to the
  operator's diagnostic key (see [security-faq.md](security-faq.md))
- Does not bundle a hardcoded relay URL — first launch prompts for one

This keeps the install minimal, audit-friendly, and fully reversible.

## How it's built

Source lives at [`clients/windows/installer/`](../clients/windows/installer/).
The build is driven by `build-msi.ps1`, which uses **Advanced Installer 19.x**'s
CLI (`AdvancedInstaller.com`) to:

1. Create the `.aip` project if absent (`/newproject`)
2. Set version, product name, manufacturer, UpgradeCode (`/SetVersion`, `/SetProperty`)
3. Configure Major Upgrade behavior (`/SetUpgradeOptions`)
4. Sync `clients/windows/dist/` into `APPDIR` (`/DelFolder` + `/AddFolder`)
5. Add Start Menu + Desktop shortcuts (`/NewShortcut`)
6. Build (`/build`)

The script is **idempotent** — every CLI command can be re-run, and the
`.aip` converges to the declared state. That means the same script produces
local builds and CI builds, both yielding identical MSI contents (modulo
the per-build `ProductCode` GUID, which is required for Major Upgrade).

## Verifying a release

```pwsh
# Verify Authenticode signature
Get-AuthenticodeSignature SHROUD-v2.5.0-win64.msi
# Status should be Valid, SignerCertificate.Subject should include CN=Brent Gordon

# Verify SHA-256 hash matches SHA256SUMS.txt
$expected = (Get-Content SHA256SUMS.txt | Where-Object { $_ -match 'msi' }) -replace '\s.*'
$actual   = (Get-FileHash SHROUD-v2.5.0-win64.msi -Algorithm SHA256).Hash.ToLower()
if ($expected -eq $actual) { "OK" } else { "MISMATCH" }
```

## Identifiers

These are stable across all SHROUD releases:

| Field | Value |
|---|---|
| **UpgradeCode** | `{8C7A4F1E-3B2D-4A95-9F1C-7E5B0D6A2F84}` |
| **Manufacturer** | `Brent Gordon` |
| **ProductName** | `SHROUD` |
| **InstallDir** | `[ProgramFiles64Folder]SHROUD` |
| **ProductCode** | regenerated per build (Major Upgrade behavior) |

The `UpgradeCode` is **load-bearing**. Never change it: Windows uses it to
recognise that a new MSI is the same product as an older install. Changing
it would orphan every existing install on every user's machine.

## Why Advanced Installer (and not WiX)

- Authoring is faster and the GUI is a useful debugging aid for the maintainer
- Built-in major-upgrade scaffolding
- CLI is fully scriptable for CI — no GUI required for CI builds
- Sign step is decoupled (Azure Artifact Signing wraps the MSI after build),
  so there's no Advanced Installer-specific signing config to maintain

The .aip file is checked in once the maintainer has run `build-msi.ps1` for
the first time. After that, both the GUI and the CLI script edit the same
file, and either path can produce a release-quality MSI.

## See also

- [`clients/windows/installer/README.md`](../clients/windows/installer/README.md) — build instructions
- [`docs/multisig-releases.md`](multisig-releases.md) — reproducibility + signature verification
- [`.github/workflows/release-windows.yml`](../.github/workflows/release-windows.yml) — CI integration
