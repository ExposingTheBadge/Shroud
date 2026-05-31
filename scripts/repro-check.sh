#!/usr/bin/env bash
# scripts/repro-check.sh — verify that a released SHROUD build can be
# reproduced byte-for-byte from this repository.
#
# Run AFTER you have a release manifest locally (RELEASES-<ver>.multisig.json).
# Exit 0 iff every supported component reproduces.

set -euo pipefail

VERSION=""
MANIFEST=""
SKIP_SERVER=0
SKIP_ANDROID=0
SKIP_WINDOWS=1   # Windows reproducibility not supported yet; see BUILD-REPRODUCIBILITY.md

usage() {
    cat <<EOF
Usage: $0 --version <ver> [--manifest <path>] [--include-windows]

  --version <ver>     Release version, e.g. 2.3.0.
  --manifest <path>   Override path to RELEASES-<ver>.multisig.json.
  --include-windows   Attempt Windows EXE comparison (will fail on Linux).
  --skip-server       Don't try the Docker server build.
  --skip-android      Don't try the Android APK build.
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --include-windows) SKIP_WINDOWS=0; shift ;;
        --skip-server) SKIP_SERVER=1; shift ;;
        --skip-android) SKIP_ANDROID=1; shift ;;
        *) usage ;;
    esac
done

[[ -z "$VERSION" ]] && usage
[[ -z "$MANIFEST" ]] && MANIFEST="RELEASES-${VERSION}.multisig.json"

if [[ ! -f "$MANIFEST" ]]; then
    echo "[repro] manifest not found: $MANIFEST" >&2
    exit 2
fi

echo "[repro] target version: $VERSION"
echo "[repro] manifest:       $MANIFEST"

# Pull expected hashes out of the manifest. Each artifact lives under
# .manifest.artifacts[].sha256 with a .name field.
expected_sha() {
    local name="$1"
    python3 - "$MANIFEST" "$name" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
for art in manifest["manifest"].get("artifacts", []):
    if art["name"] == sys.argv[2]:
        print(art["sha256"])
        break
PY
}

fail=0

# 1. Multi-sig signature check first — if signatures don't verify, the
#    expected hashes are untrustworthy and there's no point comparing.
echo
echo "[repro] verifying multi-sig bundle..."
if ! python3 release/multisig_verify.py --bundle "$MANIFEST" --roster release/roster.json; then
    echo "[repro] multi-sig verification failed; refusing to continue" >&2
    exit 3
fi

# 2. Server image.
if [[ $SKIP_SERVER -eq 0 ]]; then
    echo
    echo "[repro] building server image..."
    docker buildx build --no-cache --pull \
        --output type=docker \
        -f Dockerfile.repro \
        -t "shroud-server:repro-${VERSION}" \
        . >/tmp/repro-server.log 2>&1 || {
            echo "[repro] server build failed; see /tmp/repro-server.log" >&2
            fail=1
        }
    if [[ $fail -eq 0 ]]; then
        local_id=$(docker image inspect --format='{{.Id}}' "shroud-server:repro-${VERSION}")
        local_sha=${local_id#sha256:}
        want=$(expected_sha "shroud-server.docker")
        if [[ "$local_sha" == "$want" ]]; then
            echo "[repro] server: OK  ($local_sha)"
        else
            echo "[repro] server: MISMATCH"
            echo "        local  = $local_sha"
            echo "        wanted = $want"
            fail=1
        fi
    fi
fi

# 3. Android APK.
if [[ $SKIP_ANDROID -eq 0 ]]; then
    echo
    echo "[repro] building Android APK..."
    pushd clients/android >/dev/null
    ./gradlew --no-daemon assembleRelease \
        -Pkotlin.compiler.execution.strategy=in-process \
        -PsourceDateEpoch=1700000000 >/tmp/repro-android.log 2>&1 || {
            echo "[repro] android build failed; see /tmp/repro-android.log" >&2
            fail=1
        }
    popd >/dev/null
    apk=clients/android/app/build/outputs/apk/release/app-release-unsigned.apk
    if [[ -f "$apk" ]]; then
        local_sha=$(sha256sum "$apk" | awk '{print $1}')
        want=$(expected_sha "shroud-android.unsigned.apk")
        if [[ "$local_sha" == "$want" ]]; then
            echo "[repro] android: OK  ($local_sha)"
        else
            echo "[repro] android: MISMATCH"
            echo "        local  = $local_sha"
            echo "        wanted = $want"
            fail=1
        fi
    fi
fi

# 4. Windows — bail loudly. We document non-reproducibility in
#    BUILD-REPRODUCIBILITY.md; verifiers should rely on multi-sig until v2.4.
if [[ $SKIP_WINDOWS -eq 0 ]]; then
    echo
    echo "[repro] Windows reproducibility not implemented yet (tracked for v2.4)."
    echo "        See BUILD-REPRODUCIBILITY.md."
    fail=1
fi

echo
if [[ $fail -eq 0 ]]; then
    echo "[repro] all checks passed."
    exit 0
fi

echo "[repro] one or more checks FAILED — do not trust published binaries until resolved." >&2
exit 4
