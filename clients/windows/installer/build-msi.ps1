# build-msi.ps1 — build a signed SHROUD MSI from a populated dist/ folder.
#
# Usage:
#   pwsh -File clients/windows/installer/build-msi.ps1
#       [-DistDir clients/windows/dist]
#       [-OutDir clients/windows/installer/out]
#       [-Version 2.5.0]      # defaults to repo VERSION
#       [-Sign]                # add signtool step (Azure Artifact Signing wraps the MSI)
#       [-Gui]                 # open the generated .aip in the Advanced Installer GUI
#
# Requires Advanced Installer 19.x installed locally. The script auto-detects
# AdvancedInstaller.com in the standard install path; override with $env:ADVINST.

[CmdletBinding()]
param(
    [string]$DistDir   = "$PSScriptRoot/../dist",
    [string]$OutDir    = "$PSScriptRoot/out",
    [string]$Version   = "",
    [switch]$Sign,
    [switch]$Gui,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$InstallerDir = $PSScriptRoot
$RepoRoot     = (Resolve-Path "$InstallerDir/../../..").Path
$AipPath      = Join-Path $InstallerDir "shroud.aip"

# ---------------------------------------------------------------------------
# Locate AdvancedInstaller.com
# ---------------------------------------------------------------------------
function Find-AdvInst {
    if ($env:ADVINST -and (Test-Path $env:ADVINST)) { return $env:ADVINST }
    $candidates = @(
        "C:\Program Files (x86)\Caphyon\Advanced Installer 19.9\bin\x86\AdvancedInstaller.com",
        "C:\Program Files (x86)\Caphyon\Advanced Installer 19.9\bin\x64\AdvancedInstaller.com",
        "C:\Program Files\Caphyon\Advanced Installer 19.9\bin\x86\AdvancedInstaller.com",
        "C:\Program Files\Caphyon\Advanced Installer 19.9\bin\x64\AdvancedInstaller.com"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }

    # Fallback: glob any 19.x install
    $globs = @(
        "C:\Program Files (x86)\Caphyon\Advanced Installer*\bin\x86\AdvancedInstaller.com",
        "C:\Program Files\Caphyon\Advanced Installer*\bin\x86\AdvancedInstaller.com"
    )
    foreach ($g in $globs) {
        $hit = Get-ChildItem -Path $g -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    throw "AdvancedInstaller.com not found. Set `$env:ADVINST or install Advanced Installer 19.x."
}

$AdvInst = Find-AdvInst
Write-Host "[shroud-msi] Advanced Installer: $AdvInst"

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
if (-not $Version) {
    $verFile = Join-Path $RepoRoot "VERSION"
    if (-not (Test-Path $verFile)) { throw "VERSION file missing at $verFile" }
    $Version = (Get-Content $verFile -Raw).Trim()
}
Write-Host "[shroud-msi] Version: $Version"

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
$DistDir = (Resolve-Path $DistDir).Path
if (-not (Test-Path (Join-Path $DistDir "shroud.exe"))) {
    throw "shroud.exe not found in $DistDir. Build the Windows client first."
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
Write-Host "[shroud-msi] Source: $DistDir"
Write-Host "[shroud-msi] Output: $OutDir"

if ($Clean -and (Test-Path $AipPath)) {
    Write-Host "[shroud-msi] Removing existing shroud.aip"
    Remove-Item -Force $AipPath
}

# Stable GUIDs — DO NOT regenerate, MSI upgrade logic depends on these.
# Generated once via [guid]::NewGuid() and pinned here.
$UpgradeCode  = "{8C7A4F1E-3B2D-4A95-9F1C-7E5B0D6A2F84}"
$ProductGuid  = "*"   # auto-generated per build, required for Major Upgrade
$ManufactName = "Brent Gordon"
$AppName      = "SHROUD"
$AppShortName = "shroud"
$DescShort    = "SHROUD — anonymous post-quantum messenger"

# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------
function Invoke-AdvInst {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
    Write-Host "[advinst] $($Args -join ' ')"
    & $AdvInst @Args
    if ($LASTEXITCODE -ne 0) {
        throw "AdvancedInstaller.com failed (exit $LASTEXITCODE): $($Args -join ' ')"
    }
}

# ---------------------------------------------------------------------------
# 1. Create project from scratch if missing
# ---------------------------------------------------------------------------
if (-not (Test-Path $AipPath)) {
    Write-Host "[shroud-msi] Creating new Advanced Installer project: $AipPath"
    Invoke-AdvInst /newproject $AipPath -type "professional" -lang "en"
}

# ---------------------------------------------------------------------------
# 2. Configure project metadata (idempotent — safe to re-run)
# ---------------------------------------------------------------------------
Invoke-AdvInst /edit $AipPath /SetPackageType x64
Invoke-AdvInst /edit $AipPath /SetVersion $Version
Invoke-AdvInst /edit $AipPath /SetProperty "ProductName=$AppName"
Invoke-AdvInst /edit $AipPath /SetProperty "Manufacturer=$ManufactName"
Invoke-AdvInst /edit $AipPath /SetProperty "ARPCOMMENTS=$DescShort"
Invoke-AdvInst /edit $AipPath /SetProperty "ARPURLINFOABOUT=https://github.com/ExposingTheBadge/Shroud"
Invoke-AdvInst /edit $AipPath /SetProperty "ARPHELPLINK=https://github.com/ExposingTheBadge/Shroud/issues"
Invoke-AdvInst /edit $AipPath /SetProperty "ARPCONTACT=$ManufactName"
Invoke-AdvInst /edit $AipPath /SetProperty "UpgradeCode=$UpgradeCode"

# Major Upgrade — same UpgradeCode, new ProductCode every build, removes old before install
Invoke-AdvInst /edit $AipPath /SetUpgradeOptions -upgrade-code $UpgradeCode -major

# Install to Program Files\SHROUD by default
Invoke-AdvInst /edit $AipPath /SetAppdir -buildname DefaultBuild -path "[ProgramFiles64Folder]$AppName"

# Per-machine, admin install
Invoke-AdvInst /edit $AipPath /SetPackageType x64
Invoke-AdvInst /edit $AipPath /SetIcon -icon "$InstallerDir\..\shroud.ico" 2>$null

# ---------------------------------------------------------------------------
# 3. Sync dist/ folder into APPDIR (drops any previous files, adds current)
# ---------------------------------------------------------------------------
Invoke-AdvInst /edit $AipPath /DelFolder APPDIR
Invoke-AdvInst /edit $AipPath /AddFolder APPDIR $DistDir

# ---------------------------------------------------------------------------
# 4. Shortcuts (Start Menu + Desktop)
# ---------------------------------------------------------------------------
$ExePath = "[APPDIR]shroud.exe"
Invoke-AdvInst /edit $AipPath /NewShortcut -name $AppName -dir SHORTCUTDIR -target $ExePath -icon "$InstallerDir\..\shroud.ico" 2>$null
Invoke-AdvInst /edit $AipPath /NewShortcut -name $AppName -dir DesktopFolder -target $ExePath -icon "$InstallerDir\..\shroud.ico" 2>$null

# ---------------------------------------------------------------------------
# 5. Build output path
# ---------------------------------------------------------------------------
$MsiName = "SHROUD-v$Version-win64.msi"
Invoke-AdvInst /edit $AipPath /SetOutputLocation -buildname DefaultBuild -path $OutDir
Invoke-AdvInst /edit $AipPath /SetPackageName -buildname DefaultBuild $MsiName

# ---------------------------------------------------------------------------
# 6. Build
# ---------------------------------------------------------------------------
if ($Gui) {
    Write-Host "[shroud-msi] Opening project in Advanced Installer GUI..."
    & $AdvInst $AipPath
    return
}

Invoke-AdvInst /build $AipPath
$MsiPath = Join-Path $OutDir $MsiName
if (-not (Test-Path $MsiPath)) {
    # Advanced Installer may nest under a build subdir
    $found = Get-ChildItem -Path $OutDir -Recurse -Filter $MsiName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $MsiPath = $found.FullName }
}
if (-not (Test-Path $MsiPath)) { throw "MSI build succeeded but output not found at $MsiPath" }
Write-Host "[shroud-msi] Built: $MsiPath"

# ---------------------------------------------------------------------------
# 7. Sign (optional, local — CI signs separately via Azure action)
# ---------------------------------------------------------------------------
if ($Sign) {
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        $sdkSigntool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($sdkSigntool) { $signtool = $sdkSigntool.FullName } else { throw "signtool.exe not found" }
    } else { $signtool = $signtool.Source }

    Write-Host "[shroud-msi] Signing with signtool..."
    & $signtool sign /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 $MsiPath
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE)" }
}

# ---------------------------------------------------------------------------
# 8. SHA-256 sidecar
# ---------------------------------------------------------------------------
$hash = (Get-FileHash $MsiPath -Algorithm SHA256).Hash.ToLower()
$shaFile = "$MsiPath.sha256"
"$hash  $MsiName" | Set-Content $shaFile -NoNewline
Write-Host "[shroud-msi] SHA-256: $hash"
Write-Host "[shroud-msi] Done."

# Return the path for downstream tooling
[PSCustomObject]@{
    Msi    = $MsiPath
    Sha256 = $hash
    Sidecar = $shaFile
} | Format-List
