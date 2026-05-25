# Reproducible Builds

GHOSTLINK's threat model assumes the upstream binaries themselves could be
tampered with. To defend against that, anyone (you, an auditor, a paranoid
user) should be able to compile the same source and get the same binary.

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

The reported `sha256:...` must match the value in `RELEASES.md` for the
corresponding tag. If it doesn't, **do not run that binary** — investigate
the upstream release.

Notes:
- `Dockerfile.repro` pins the base image by digest.
- All Python dependencies are installed `--require-hashes` from
  `requirements-server.txt` (a wheel hash mismatch fails the build).
- `SOURCE_DATE_EPOCH` is fixed so `python -m compileall` produces
  bit-identical `.pyc` files across machines.

## Windows client

The Windows build (Qt6 + CMake + bcrypt/ncrypt) currently depends on the
host's Qt install and Windows SDK — it isn't byte-reproducible across
machines yet. Target for that work: container-based MinGW build with pinned
Qt, mirrored MS SDK, and `mt.exe` timestamp stripping. Tracked in
[[reproducible-builds-windows]].

## Android client

`./gradlew --no-daemon assembleRelease -Pkotlin.compiler.execution.strategy=in-process`
in a pinned Android SDK container produces a deterministic APK if the
keystore is held constant. Plan: ship the unsigned APK reproducibly,
sign separately (so reproducibility doesn't depend on holding the key).

## Transparency log

Every tagged release ships with `RELEASES.md` containing:
- git commit hash
- server image sha256
- Windows installer sha256
- APK sha256
- triple signature over the manifest (Ed25519 + ML-DSA-87 + SPHINCS+-256s)

Verifiers cross-check against the public transparency log. Conflicting
hashes are evidence of compromise.
