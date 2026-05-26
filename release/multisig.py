"""
GHOSTLINK multi-party release signing — N-of-M threshold attestation.

Why this exists
---------------
`release/sign_manifest.py` produces a single-key triple-hybrid signature
(Ed25519 + ML-DSA-87 + SPHINCS+-256s) over the release manifest. That binds
the manifest to the server-identity key — but it's still one key on one
machine. If that key is stolen the attacker can forge any future release.

Multi-party signing turns "trust this one machine" into "trust at least M
out of N humans". Each signer holds an independent Ed25519 keypair on their
own machine; releases are only considered valid when M signers attest the
same manifest. Threshold (M) and signer roster (N) are written into the
manifest itself, so a verifier doesn't have to trust an out-of-band list.

We deliberately do NOT use a true threshold signature scheme (FROST,
Schnorr-MuSig2). Each signer simply produces an independent detached
Ed25519 sig and the verifier counts valid signatures. This is operationally
boring on purpose — no DKG ceremony, no online round-robin, each signer can
sign offline at their own pace.

Trust model (what threshold-vs-not buys you)
--------------------------------------------
  - Compromise of < M signing keys cannot forge a release.
  - Loss of (N - M) keys still lets the project ship.
  - Adding/removing signers requires (rotating) the roster on the next
    release; no key-resharing ceremony.
  - Roster rotation is itself attested by the previous roster, giving a
    cryptographic chain from genesis. See docs/multisig-releases.md.

Files
-----
  release/multisig.py                — this file (signer-side and roster ops)
  release/multisig_verify.py         — verifier-side (counts sigs vs roster)
  release/signers/<signer>.pub       — public Ed25519 keys, checked in
  release/signers/<signer>.key       — private Ed25519 keys, NEVER checked in
                                       (chmod 600, kept on signer's box)
  release/roster.json                — { threshold: M, signers: [pubkey, …] }
                                       checked in, attested by previous roster
"""
import argparse
import base64
import hashlib
import json
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
except ImportError:
    print("multisig.py requires the `cryptography` package. Install with:")
    print("    pip install cryptography")
    sys.exit(1)


REPO_ROOT = Path(__file__).resolve().parent.parent
SIGNERS_DIR = Path(__file__).resolve().parent / "signers"
ROSTER_PATH = Path(__file__).resolve().parent / "roster.json"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_keygen(args):
    """Generate a fresh signer keypair. The private key MUST NOT be checked
    in; the public key goes under release/signers/<name>.pub and gets added
    to the roster by whoever runs cmd_roster."""
    SIGNERS_DIR.mkdir(parents=True, exist_ok=True)
    name = args.name
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_path = SIGNERS_DIR / f"{name}.key"
    pub_path = SIGNERS_DIR / f"{name}.pub"
    if priv_path.exists() and not args.force:
        sys.exit(f"refusing to overwrite {priv_path}; pass --force to clobber")
    priv_path.write_bytes(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    pub_path.write_text(b64(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)) + "\n")
    try:
        priv_path.chmod(0o600)
    except Exception:
        pass  # Windows: best effort
    print(f"signer:  {name}")
    print(f"private: {priv_path}  (chmod 600, NEVER commit)")
    print(f"public:  {pub_path}   (commit this; add to roster.json)")


def cmd_roster(args):
    """Initialize or re-emit the active signer roster. Threshold M MUST be
    <= number of signers; conventional choice is ceil((N+1)/2)."""
    SIGNERS_DIR.mkdir(parents=True, exist_ok=True)
    signers = []
    for p in sorted(SIGNERS_DIR.glob("*.pub")):
        pub_b64 = p.read_text().strip()
        signers.append({"name": p.stem, "pub": pub_b64})
    if args.threshold < 1 or args.threshold > len(signers):
        sys.exit(f"threshold {args.threshold} out of range for {len(signers)} signers")
    roster = {
        "version": 1,
        "threshold": args.threshold,
        "signers": signers,
        "issued_at": int(time.time()),
    }
    ROSTER_PATH.write_text(json.dumps(roster, indent=2, sort_keys=True) + "\n")
    print(f"wrote {ROSTER_PATH}: M={args.threshold} of N={len(signers)}")


def _build_manifest(args):
    """Same envelope shape as sign_manifest.py so the two can coexist."""
    manifest = {
        "product": "GHOSTLINK",
        "version": args.version,
        "git_commit": args.git_commit,
        "built_at_utc": int(time.time()),
        "server_image_digest": args.server_image,
    }
    if args.windows_exe:
        manifest["windows_exe_sha256"] = file_sha256(args.windows_exe)
    if args.android_apk:
        manifest["android_apk_sha256"] = file_sha256(args.android_apk)
    if args.windows_zip:
        manifest["windows_zip_sha256"] = file_sha256(args.windows_zip)
    return manifest


def cmd_attest(args):
    """Produce ONE signer's detached Ed25519 signature over the manifest.
    Run this on each signer's machine. Each output sig is independent;
    they're combined by `gather`."""
    priv_path = SIGNERS_DIR / f"{args.signer}.key"
    if not priv_path.exists():
        sys.exit(f"no private key at {priv_path} — run keygen first")
    priv = Ed25519PrivateKey.from_private_bytes(priv_path.read_bytes())

    manifest = _build_manifest(args)
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    sig = priv.sign(payload)

    attestation = {
        "signer": args.signer,
        "manifest": manifest,
        "sig": b64(sig),
    }
    out = Path(args.output)
    out.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")
    print(f"  signer={args.signer} bytes_signed={len(payload)}")


def cmd_gather(args):
    """Bundle multiple signers' attestations + the active roster into one
    RELEASES-<version>.multisig.json. The verifier just needs this file
    (plus the artefacts) — no other state."""
    if not ROSTER_PATH.exists():
        sys.exit(f"missing roster at {ROSTER_PATH}; run `multisig.py roster --threshold N` first")
    roster = json.loads(ROSTER_PATH.read_text())
    attestations = []
    manifests_seen = set()
    for p in args.attestations:
        a = json.loads(Path(p).read_text())
        canon = json.dumps(a["manifest"], sort_keys=True, separators=(",", ":"))
        manifests_seen.add(canon)
        attestations.append(a)
    if len(manifests_seen) != 1:
        sys.exit(f"attestations cover {len(manifests_seen)} distinct manifests — refusing to combine")

    combined = {
        "format": "ghostlink-multisig-v1",
        "roster": roster,
        "manifest": attestations[0]["manifest"],
        "signatures": [
            {"signer": a["signer"], "sig": a["sig"]}
            for a in attestations
        ],
    }
    out = Path(args.output)
    out.write_text(json.dumps(combined, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")
    print(f"  manifest version={combined['manifest']['version']}")
    print(f"  signers={[a['signer'] for a in attestations]}")
    print(f"  threshold required={roster['threshold']} of {len(roster['signers'])}")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="Generate a new signer keypair")
    pk.add_argument("--name", required=True, help="Signer identifier (e.g. 'alice', 'bob')")
    pk.add_argument("--force", action="store_true")
    pk.set_defaults(func=cmd_keygen)

    pr = sub.add_parser("roster", help="Emit roster.json from public keys on disk")
    pr.add_argument("--threshold", type=int, required=True, help="M (minimum sigs)")
    pr.set_defaults(func=cmd_roster)

    pa = sub.add_parser("attest", help="Produce one signer's detached sig over a manifest")
    pa.add_argument("--signer", required=True)
    pa.add_argument("--version", required=True)
    pa.add_argument("--git-commit", required=True)
    pa.add_argument("--server-image", default="")
    pa.add_argument("--windows-exe", default="")
    pa.add_argument("--windows-zip", default="")
    pa.add_argument("--android-apk", default="")
    pa.add_argument("--output", required=True, help="Where to write the attestation JSON")
    pa.set_defaults(func=cmd_attest)

    pg = sub.add_parser("gather", help="Combine independent attestations into one bundle")
    pg.add_argument("--attestations", nargs="+", required=True)
    pg.add_argument("--output", required=True)
    pg.set_defaults(func=cmd_gather)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
