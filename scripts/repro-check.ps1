# scripts/repro-check.ps1 — Windows companion to repro-check.sh.
#
# Run after fetching the release manifest. Verifies:
#   1. multi-sig bundle signatures (delegates to release/multisig_verify.py)
#   2. server image SHA-256        (requires Docker Desktop)
#   3. android APK SHA-256         (requires JDK + Android SDK; uses gradlew)
#   4. windows EXE                 (NOT REPRODUCIBLE today; see BUILD-REPRODUCIBILITY.md)
#
# Exit code 0 iff every supported component reproduces.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$Version,
    [string]$Manifest = "",
    [switch]$IncludeWindows,
    [switch]$SkipServer,
    [switch]$SkipAndroid
)

$ErrorActionPreference = 'Stop'

if (-not $Manifest) { $Manifest = "RELEASES-$Version.multisig.json" }
if (-not (Test-Path $Manifest)) {
    Write-Error "[repro] manifest not found: $Manifest"
    exit 2
}

Write-Host "[repro] target version: $Version"
Write-Host "[repro] manifest:       $Manifest"

function Get-ExpectedSha([string]$ArtifactName) {
    $obj = Get-Content $Manifest -Raw | ConvertFrom-Json
    foreach ($a in $obj.manifest.artifacts) {
        if ($a.name -eq $ArtifactName) { return $a.sha256 }
    }
    return $null
}

$fail = 0

Write-Host "`n[repro] verifying multi-sig bundle..."
& python release/multisig_verify.py --bundle $Manifest --roster release/roster.json
if ($LASTEXITCODE -ne 0) {
    Write-Error "[repro] multi-sig verification failed; refusing to continue"
    exit 3
}

if (-not $SkipServer) {
    Write-Host "`n[repro] building server image..."
    docker buildx build --no-cache --pull `
        --output type=docker `
        -f Dockerfile.repro `
        -t "ghostlink-server:repro-$Version" .  2>&1 | Tee-Object -FilePath "$env:TEMP\repro-server.log"
    if ($LASTEXITCODE -eq 0) {
        $id = (docker image inspect --format='{{.Id}}' "ghostlink-server:repro-$Version").Trim()
        $localSha = $id -replace '^sha256:', ''
        $want = Get-ExpectedSha "ghostlink-server.docker"
        if ($localSha -eq $want) {
            Write-Host "[repro] server: OK  ($localSha)"
        } else {
            Write-Warning "[repro] server: MISMATCH`n  local  = $localSha`n  wanted = $want"
            $fail = 1
        }
    } else {
        Write-Warning "[repro] server build failed; see $env:TEMP\repro-server.log"
        $fail = 1
    }
}

if (-not $SkipAndroid) {
    Write-Host "`n[repro] building Android APK..."
    Push-Location clients\android
    & .\gradlew.bat --no-daemon assembleRelease `
        -Pkotlin.compiler.execution.strategy=in-process `
        -PsourceDateEpoch=1700000000 2>&1 | Tee-Object -FilePath "$env:TEMP\repro-android.log"
    $androidExit = $LASTEXITCODE
    Pop-Location

    if ($androidExit -ne 0) {
        Write-Warning "[repro] android build failed; see $env:TEMP\repro-android.log"
        $fail = 1
    } else {
        $apk = "clients\android\app\build\outputs\apk\release\app-release-unsigned.apk"
        if (Test-Path $apk) {
            $localSha = (Get-FileHash -Algorithm SHA256 $apk).Hash.ToLower()
            $want = Get-ExpectedSha "ghostlink-android.unsigned.apk"
            if ($localSha -eq $want) {
                Write-Host "[repro] android: OK  ($localSha)"
            } else {
                Write-Warning "[repro] android: MISMATCH`n  local  = $localSha`n  wanted = $want"
                $fail = 1
            }
        }
    }
}

if ($IncludeWindows) {
    Write-Host "`n[repro] Windows reproducibility not implemented yet (tracked for v2.4)."
    Write-Host "        See BUILD-REPRODUCIBILITY.md."
    $fail = 1
}

if ($fail -eq 0) {
    Write-Host "`n[repro] all checks passed."
    exit 0
}

Write-Error "[repro] one or more checks FAILED — do not trust published binaries until resolved."
exit 4
