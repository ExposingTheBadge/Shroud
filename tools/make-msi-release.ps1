#requires -Version 7
<#
.SYNOPSIS
    Pull the signed `shroud.exe` zip from a SHROUD GitHub release, build an
    MSI around it with Advanced Installer, sign the MSI with the same
    Azure Artifact Signing cert CI uses on the exe, append the MSI hash
    to `SHA256SUMS.txt`, and upload everything back to the release.

.DESCRIPTION
    Why this exists: the public GitHub-hosted runner has no Advanced
    Installer install and no licensable path to one. CI builds + signs
    `shroud.exe` and ships the portable zip. This script — run on the
    maintainer's workstation right after each release publishes — does
    the MSI half locally, signs it with the SAME Azure cert the CI
    workflow used on the exe (so users see one identity, not two), and
    uploads the signed MSI to the same release tag.

    The flow:

      1.  Look up the target release tag (default: latest).
      2.  Download `SHROUD-v<ver>-win64.zip` from that release into a
          temp dir and extract it. Everything inside is already signed.
      3.  Run `clients/windows/installer/build-msi.ps1` against the
          extracted `dist/` directory. Produces an UNSIGNED MSI.
      4.  Sign the MSI via Azure Trusted Signing — same endpoint /
          account / certificate-profile the CI workflow uses. Auth is
          via `az login` (interactive or service principal); no creds
          ever touch this script.
      5.  Recompute SHA-256 for the MSI, append it to the release's
          `SHA256SUMS.txt`, re-upload the updated checksums file.
      6.  `gh release upload <tag> SHROUD-v<ver>-win64.msi` so the MSI
          appears as a release asset.

.PARAMETER Tag
    Release tag to process (e.g. `v2.6.1`). Defaults to the latest
    release on the SHROUD repo. The script extracts the version from
    the tag — `v2.6.1` -> `2.6.1` — and uses that to name the MSI.

.PARAMETER WorkDir
    Where to stage the download + unpack + MSI build. Defaults to a
    fresh temp directory under `$env:TEMP`. The directory is cleaned
    on exit unless `-Keep` is set.

.PARAMETER SkipUpload
    Build + sign but don't upload. Useful for sanity-checking before
    a real release.

.PARAMETER Endpoint
    Azure Trusted Signing endpoint URL. Defaults to the repo's GitHub
    Actions variable AZURE_ARTIFACT_SIGNING_ENDPOINT — i.e. the same
    value CI uses for signing `shroud.exe`. Override if you've
    rotated.

.PARAMETER Account
    Azure Trusted Signing account name. Defaults to the value of
    AZURE_ARTIFACT_SIGNING_ACCOUNT repo variable.

.PARAMETER CertProfile
    Azure Trusted Signing certificate-profile name. Defaults to the
    value of AZURE_ARTIFACT_SIGNING_CERT_PROFILE repo variable.

.PARAMETER Keep
    Don't delete the work directory at the end. Useful for debugging.

.EXAMPLE
    pwsh -File tools/make-msi-release.ps1
    # Processes the latest SHROUD release end-to-end.

.EXAMPLE
    pwsh -File tools/make-msi-release.ps1 -Tag v2.6.1 -SkipUpload -Keep
    # Builds + signs the MSI for v2.6.1 locally and stops — no upload.
    # Leaves the work directory in place so you can inspect the output.

.NOTES
    Prerequisites on the build machine:
      - PowerShell 7+ (`pwsh`)
      - GitHub CLI (`gh`) — authenticated via `gh auth login`
      - Advanced Installer 19.x with a valid commercial license — the
        existing one already installed on this box is fine
      - Azure CLI (`az`) — authenticated via `az login` for an account
        that has Signer access to the Trusted Signing cert profile
      - `signtool.exe` from the Windows SDK PLUS the Azure Trusted
        Signing client DLL (`Azure.CodeSigning.Dlib.dll`). If signtool
        can't find it, install the NuGet package
        `Microsoft.Trusted.Signing.Client` and pass the dlib path via
        `-DlibPath`.

    No secrets are passed on the command line. Azure auth happens
    through the standard Azure CLI credential chain.
#>
[CmdletBinding()]
param(
    [string]$Tag = "",
    [string]$WorkDir = "",
    [switch]$SkipUpload,
    [string]$Endpoint    = "",
    [string]$Account     = "",
    [string]$CertProfile = "",
    [string]$DlibPath    = "",
    [switch]$Keep
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoSlug = "ExposingTheBadge/Shroud"
$RepoRoot = Resolve-Path "$PSScriptRoot/.."

# ─── 1. Resolve target tag ───────────────────────────────────────────
if (-not $Tag) {
    Write-Host "[msi-release] Resolving latest release tag..."
    $Tag = (gh release view --repo $RepoSlug --json tagName --jq '.tagName').Trim()
    if (-not $Tag) { throw "Could not resolve latest release tag." }
}
$Version = $Tag.TrimStart('v')
$ZipName = "SHROUD-v$Version-win64.zip"
$MsiName = "SHROUD-v$Version-win64.msi"
Write-Host "[msi-release] Target tag:  $Tag"
Write-Host "[msi-release] Version:     $Version"

# ─── 2. Work dir ─────────────────────────────────────────────────────
if (-not $WorkDir) {
    $WorkDir = Join-Path $env:TEMP ("shroud-msi-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
Write-Host "[msi-release] Work dir:    $WorkDir"

$cleanup = {
    if (-not $Keep -and (Test-Path $WorkDir)) {
        Write-Host "[msi-release] Cleaning $WorkDir"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $WorkDir
    }
}
trap { & $cleanup; throw }

try {
    # ─── 3. Download the signed zip ──────────────────────────────────
    $zipPath = Join-Path $WorkDir $ZipName
    Write-Host "[msi-release] Downloading $ZipName from $Tag..."
    gh release download $Tag --repo $RepoSlug --pattern $ZipName --dir $WorkDir --clobber
    if (-not (Test-Path $zipPath)) {
        throw "Zip not found in release: $ZipName. Did CI complete?"
    }

    $extractDir = Join-Path $WorkDir "extracted"
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    if (-not (Test-Path (Join-Path $extractDir "shroud.exe"))) {
        throw "shroud.exe not found inside $ZipName — bad upload?"
    }
    Write-Host "[msi-release] Extracted shroud.exe (Authenticode-signed) + Qt DLLs."

    # ─── 4. Build MSI ────────────────────────────────────────────────
    $msiOutDir = Join-Path $WorkDir "msi-out"
    New-Item -ItemType Directory -Force -Path $msiOutDir | Out-Null
    Write-Host "[msi-release] Building MSI via clients/windows/installer/build-msi.ps1..."
    pwsh -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $RepoRoot "clients/windows/installer/build-msi.ps1") `
        -DistDir $extractDir `
        -OutDir $msiOutDir `
        -Version $Version
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed (exit $LASTEXITCODE)" }

    $msiPath = Get-ChildItem -Path $msiOutDir -Recurse -Filter $MsiName | Select-Object -First 1
    if (-not $msiPath) { throw "MSI not produced — expected $MsiName under $msiOutDir" }
    $msiPath = $msiPath.FullName
    Write-Host "[msi-release] MSI built: $msiPath"

    # ─── 5. Sign the MSI with the same Azure cert CI uses on the exe ─
    if (-not $Endpoint -or -not $Account -or -not $CertProfile) {
        Write-Host "[msi-release] Reading Azure Trusted Signing config from GitHub repo vars..."
        if (-not $Endpoint) {
            $Endpoint = (gh variable get AZURE_ARTIFACT_SIGNING_ENDPOINT --repo $RepoSlug 2>$null)
        }
        if (-not $Account) {
            $Account = (gh variable get AZURE_ARTIFACT_SIGNING_ACCOUNT --repo $RepoSlug 2>$null)
        }
        if (-not $CertProfile) {
            $CertProfile = (gh variable get AZURE_ARTIFACT_SIGNING_CERT_PROFILE --repo $RepoSlug 2>$null)
        }
    }
    if (-not $Endpoint -or -not $Account -or -not $CertProfile) {
        throw "Azure Trusted Signing config missing — pass -Endpoint / -Account / -CertProfile, or set the matching gh repo variables."
    }

    # Locate signtool.exe
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)?.Source
    if (-not $signtool) {
        $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" `
            -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $signtool) { throw "signtool.exe not found — install the Windows 10/11 SDK." }
    Write-Host "[msi-release] signtool: $signtool"

    # Locate the Trusted Signing dlib
    if (-not $DlibPath) {
        $candidates = @(
            "$env:ProgramFiles\Microsoft\Trusted Signing Client\Azure.CodeSigning.Dlib.dll",
            "$env:USERPROFILE\.nuget\packages\microsoft.trusted.signing.client\*\bin\x64\Azure.CodeSigning.Dlib.dll"
        )
        foreach ($c in $candidates) {
            $hit = Get-ChildItem $c -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { $DlibPath = $hit.FullName; break }
        }
    }
    if (-not $DlibPath) {
        throw @"
Trusted Signing dlib not found.
Install it via:
    Install-Package Microsoft.Trusted.Signing.Client -Scope CurrentUser
or download the NuGet package and pass the dlib path via -DlibPath.
"@
    }
    Write-Host "[msi-release] dlib:     $DlibPath"

    # Build the dlib metadata JSON (signtool /dmdf format)
    $metadata = @{
        Endpoint               = $Endpoint
        CodeSigningAccountName = $Account
        CertificateProfileName = $CertProfile
    } | ConvertTo-Json -Depth 5
    $metadataPath = Join-Path $WorkDir "trusted-signing-metadata.json"
    Set-Content -Path $metadataPath -Value $metadata -Encoding ascii
    Write-Host "[msi-release] metadata: $metadataPath"

    Write-Host "[msi-release] Signing MSI (this prompts for `az login` if needed)..."
    & $signtool sign `
        /v `
        /fd SHA256 `
        /tr http://timestamp.acs.microsoft.com `
        /td SHA256 `
        /dlib $DlibPath `
        /dmdf $metadataPath `
        $msiPath
    if ($LASTEXITCODE -ne 0) { throw "signtool failed (exit $LASTEXITCODE)" }

    # Verify
    & $signtool verify /pa /v $msiPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signtool verify FAILED — MSI is unsigned or signature invalid." }
    Write-Host "[msi-release] MSI signature verified."

    # ─── 6. SHA-256 + upload ─────────────────────────────────────────
    $msiHash = (Get-FileHash $msiPath -Algorithm SHA256).Hash.ToLower()
    Write-Host "[msi-release] MSI SHA-256: $msiHash"

    # Fetch existing SHA256SUMS, append our line, re-upload
    $sumsRemote = Join-Path $WorkDir "SHA256SUMS.txt"
    gh release download $Tag --repo $RepoSlug --pattern "SHA256SUMS.txt" --dir $WorkDir --clobber
    if (Test-Path $sumsRemote) {
        $existing = (Get-Content $sumsRemote -Raw).TrimEnd("`n", "`r")
        $newLine  = "$msiHash  $MsiName"
        if ($existing -notmatch [regex]::Escape($newLine)) {
            $combined = $existing + "`n" + $newLine
            Set-Content $sumsRemote -Value $combined -NoNewline -Encoding ascii
            Write-Host "[msi-release] Appended MSI hash to SHA256SUMS.txt."
        } else {
            Write-Host "[msi-release] MSI hash already present in SHA256SUMS.txt (re-run)."
        }
    } else {
        Set-Content $sumsRemote -Value "$msiHash  $MsiName" -NoNewline -Encoding ascii
        Write-Host "[msi-release] No remote SHA256SUMS.txt — created fresh."
    }

    if ($SkipUpload) {
        Write-Host "[msi-release] -SkipUpload set — leaving MSI at $msiPath, SHA256SUMS at $sumsRemote."
        return
    }

    Write-Host "[msi-release] Uploading MSI + updated SHA256SUMS.txt to release $Tag..."
    gh release upload $Tag --repo $RepoSlug --clobber $msiPath $sumsRemote
    if ($LASTEXITCODE -ne 0) { throw "gh release upload failed (exit $LASTEXITCODE)" }

    Write-Host "[msi-release] Done. https://github.com/$RepoSlug/releases/tag/$Tag"

} finally {
    & $cleanup
}
