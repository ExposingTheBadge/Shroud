"""
SHROUD multi-party signature verifier.

Verifies a combined attestation bundle produced by `multisig.py gather`.
Exits 0 only when:
    1. Every signature is over the *same* canonicalized manifest.
    2. Every signing pubkey is present in the bundled roster.
    3. The number of valid signatures meets or exceeds roster.threshold.
    4. (Optional) Manifest's artifact SHA-256s match the local files.

Usage:
    python release/multisig_verify.py --bundle RELEASES-2.3.0.multisig.json
    python release/multisig_verify.py --bundle ... --windows-zip SHROUD.zip

We intentionally avoid trusting CLI flags for the roster — the verifier
reads it from inside the bundle. That binds the roster to the same
attestation event the signatures cover. Cross-check against
release/roster.json in git history if you want to catch roster swap
attacks.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("multisig_verify.py requires `cryptography`. Install with: pip install cryptography")
    sys.exit(2)


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--windows-zip", default="")
    ap.add_argument("--windows-exe", default="")
    ap.add_argument("--android-apk", default="")
    args = ap.parse_args()

    bundle = json.loads(Path(args.bundle).read_text())
    if bundle.get("format") != "shroud-multisig-v1":
        sys.exit("FAIL: unknown bundle format")

    roster = bundle["roster"]
    manifest = bundle["manifest"]
    sigs = bundle["signatures"]

    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    pubkey_by_name = {s["name"]: s["pub"] for s in roster["signers"]}

    seen = set()
    valid = []
    for sig in sigs:
        name = sig["signer"]
        if name in seen:
            print(f"FAIL: duplicate signer {name}")
            sys.exit(1)
        seen.add(name)
        pub_b64 = pubkey_by_name.get(name)
        if pub_b64 is None:
            print(f"FAIL: signer {name} not in roster")
            sys.exit(1)
        pub = Ed25519PublicKey.from_public_bytes(b64d(pub_b64))
        try:
            pub.verify(b64d(sig["sig"]), payload)
        except InvalidSignature:
            print(f"FAIL: bad sig from {name}")
            sys.exit(1)
        valid.append(name)

    threshold = roster["threshold"]
    if len(valid) < threshold:
        print(f"FAIL: {len(valid)} valid signatures, need {threshold}")
        sys.exit(1)

    # Optional: cross-check artefacts on disk.
    artefact_checks = [
        ("windows_zip_sha256", args.windows_zip),
        ("windows_exe_sha256", args.windows_exe),
        ("android_apk_sha256", args.android_apk),
    ]
    for field, path in artefact_checks:
        if not path:
            continue
        expected = manifest.get(field)
        if not expected:
            print(f"FAIL: manifest has no {field} to compare against")
            sys.exit(1)
        actual = file_sha256(path)
        if actual != expected:
            print(f"FAIL: {path} sha256={actual} != manifest {expected}")
            sys.exit(1)
        print(f"  ✓ {field} matches {path}")

    print(f"OK: {len(valid)} of {len(roster['signers'])} signers attest "
          f"v{manifest['version']} (threshold={threshold})")
    print(f"   signers: {', '.join(valid)}")


if __name__ == "__main__":
    main()
