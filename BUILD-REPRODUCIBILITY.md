# Reproducible Builds

GHOSTLINK's threat model assumes upstream binaries themselves could be
tampered with. To defend against that, anyone (you, an auditor, a paranoid
user) should be able to compile the same source and get the same binary.
This document covers what's reproducible today, what isn't, and the path
to fix the gaps.

## Status at a glance

| Component       | Status                | Notes                                              |
|-----------------|-----------------------|----------------------------------------------------|
| Server (Docker) | reproducible          | pinned base image, `--require-hashes` deps         |
| Android APK     | reproducible (unsigned) | sign separately so key isn't in the repro path   |
| Windows EXE     | NOT reproducible yet  | MSVC + Qt host install dependency; tracked v2.4    |
| Linux client    | not built in CI yet   | reproducible target once v2.4 GTK rewrite lands    |

## Server (Docker)

```
docker buildx build \
    --no-cache \
    --pull \
    --output type=docker \
    -f Dockerfile.repro \
    -t ghostlink-server:repro \
    .

docker image inspect --format='{{.Id}}' ghostlink-server:repro
```

The reported `sha256:...` must match the value published with the release.
If it doesn't, **do not run that binary** — investigate the upstream
release.

Mechanisms used:
- `Dockerfile.repro` pins the base image by digest, not tag.
- All Python dependencies install `--require-hashes` from
  `requirements-server.txt` (a wheel hash mismatch fails the build).
- `SOURCE_DATE_EPOCH=1700000000` is fixed so `python -m compileall`
  produces bit-identical `.pyc` files across machines.
- We never run `pip install --upgrade pip` (an upgrade would change the
  installer and might invalidate the hash check).

## Android APK

```bash
# Run from clients/android/ with a pinned SDK in the container of your choice.
./gradlew --no-daemon assembleRelease \
    -Pkotlin.compiler.execution.strategy=in-process \
    -PsourceDateEpoch=1700000000
```

This produces `app/build/outputs/apk/release/app-release-unsigned.apk`.
The unsigned APK is what's reproducible; the signing step adds a
keystore-specific block that varies across signers (and you DO want it to
vary, otherwise you couldn't tell who signed what).

To verify a release:

```bash
# 1. Build unsigned, locally.
./gradlew --no-daemon assembleRelease -PsourceDateEpoch=1700000000

# 2. Strip the signature block off the published signed APK.
apksigner sign --remove-signing-block \
    -ks /dev/null \
    --in app-release-signed.apk \
    --out app-release-stripped.apk

# 3. Compare sha256.
sha256sum app/build/outputs/apk/release/app-release-unsigned.apk \
          app-release-stripped.apk
```

(Strictly: we ship `signed APK + signing-block hash` so verifiers don't
need to strip. Both numbers go in the release manifest.)

Notes:
- `assembleRelease` already uses `isMinifyEnabled = true` and ProGuard;
  the rules file is committed at `clients/android/app/proguard-rules.pro`.
- Gradle's daemon and incremental compile add nondeterminism; the
  `--no-daemon` + `kotlin.compiler.execution.strategy=in-process` combo
  removes them.
- The Android SDK version is pinned by `compileSdk` / `targetSdk` in
  `app/build.gradle.kts`; CI uses an SDK image that matches.

## Windows EXE — known non-reproducible

The Windows build (Qt6 + CMake + MSVC + bcrypt/ncrypt) currently depends
on the host's Qt install and Windows SDK. Two sources of non-determinism:

1. `link.exe` embeds a 4-byte timestamp into the PE header by default.
   `link /Brepro` (introduced in VS 2017) suppresses this. We pass it,
   but it doesn't catch every embedded timestamp (e.g. resource files
   compiled by `rc.exe`).
2. Qt's `windeployqt` bundles whatever DLLs the host Qt install has,
   which differ across machines / Qt patch versions.

Plan to fix in v2.4:
- Pin Qt to a fixed binary release of Qt 6.9.2 mirrored to our own
  release bucket.
- Move the build into a Windows-on-Linux container (Wine + MSVC build
  tools) so the host doesn't matter.
- Strip timestamps with `mt.exe /clean` and a custom resource compile
  that omits version-info timestamps.

Until then, the Windows release is "trust the build server + threshold
multi-sig over the SHA-256" (see `docs/multisig-releases.md`).

## Driver script

`scripts/repro-check.ps1` (Windows) and `scripts/repro-check.sh` (Linux)
walk through every component end-to-end:

```
./scripts/repro-check.sh --version 2.3.0
```

The script:
  1. Builds the server image.
  2. Builds the unsigned APK.
  3. (Where supported) strips the signed APK signature block.
  4. Compares each SHA-256 against the entries in
     `RELEASES-<version>.multisig.json`.
  5. Verifies the multisig bundle separately via
     `release/multisig_verify.py`.

Exit code 0 iff every component matches. Run it before trusting any
binary on your machine.

## Transparency log

Every tagged release ships with `RELEASES-<version>.txt` (the
single-signature manifest from `release/sign_manifest.py`) AND
`RELEASES-<version>.multisig.json` (the threshold-of-N attestation from
`release/multisig.py`). Both contain:
- git commit hash
- server image sha256
- Windows zip sha256
- APK sha256
- their respective signatures

Verifiers cross-check against the public transparency log (currently
`https://github.com/ExposingTheBadge/GhostLink/releases`). Conflicting
hashes are evidence of compromise — alert maintainers and refuse the
binary.

## Building from source without trust

If you don't trust *anyone*, including the release server:

1. Clone the repo at the tagged commit:
   ```
   git clone https://github.com/ExposingTheBadge/GhostLink
   git -C GhostLink checkout v2.3.0
   ```
2. Build each component with the commands above.
3. Hash your binaries.
4. Run them. The published SHA-256s are advisory — your locally-built
   binary is the trust root.

The multi-signer attestation only matters when you choose to skip step 2.
