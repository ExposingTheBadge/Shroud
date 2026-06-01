"""
Verify a SHROUD GitHub release against the multisig roster.

For a given <owner/repo> and tag, this:

  1. Downloads the release's `manifest.json` + `signatures.json` (the
     M-of-N Ed25519 signature bundle) via the GitHub Releases API.
  2. Loads the signer roster from `release/signers.json` in the same
     repo (whatever HEAD of master has — we do NOT trust the release's
     own copy of the roster, that would be circular).
  3. Verifies that at least M distinct, in-roster signers have valid
     Ed25519 signatures over the canonical manifest body.
  4. For each artifact named in the manifest, downloads it from the
     release page and checks its SHA-256 against the manifest's claim.

Exits 0 on full pass, non-zero on any failure. Suitable to shell out to
from the shroud-admin Multisig tab.

Usage::

    python -m release.verify_release --repo ExposingTheBadge/Shroud --tag v2.6.6
    python -m release.verify_release --tag v2.6.6           # repo defaults
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
import urllib.error


GITHUB_API = "https://api.github.com"


def _http_get(url: str, accept: str = "application/json", token: str = "") -> bytes:
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "shroud-verify/1"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _gh_release_assets(repo: str, tag: str, token: str) -> tuple[dict, list[dict]]:
    url = f"{GITHUB_API}/repos/{repo}/releases/tags/{tag}"
    rel = json.loads(_http_get(url, token=token))
    return rel, rel.get("assets", [])


def _download_asset(asset: dict, dest_dir: str, token: str) -> str:
    name = asset["name"]
    url  = asset["browser_download_url"]
    path = os.path.join(dest_dir, name)
    with open(path, "wb") as f:
        f.write(_http_get(url, accept="application/octet-stream", token=token))
    return path


def _load_roster() -> list[dict]:
    """signers.json shape (committed at repo HEAD):
       [{"name": "alice", "ed25519_pub_hex": "..."}, ...]
       Plus a top-level "threshold" via signers_threshold.json or
       inline meta — we accept either."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "signers.json")
    if not os.path.exists(path):
        raise FileNotFoundError(
            "release/signers.json is missing. Without a published roster "
            "the verifier cannot know which Ed25519 pubkeys to trust."
        )
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "signers" in data:
        return data["signers"]
    if isinstance(data, list):
        return data
    raise ValueError("signers.json must be a list or {signers:[...]}")


def _load_threshold(default: int = 2) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("signers_threshold.json", "multisig_threshold.json"):
        p = os.path.join(here, name)
        if os.path.exists(p):
            with open(p) as f:
                d = json.load(f)
            return int(d.get("M") or d.get("threshold") or default)
    return default


def _verify_signatures(manifest_body: bytes,
                       signatures: list[dict],
                       roster: list[dict],
                       threshold: int) -> tuple[bool, list[str], list[str]]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    pub_by_hex = { s["ed25519_pub_hex"].lower(): s.get("name", "") for s in roster }
    ok_names: list[str] = []
    failed: list[str] = []
    seen_pubs: set[str] = set()
    for sig in signatures:
        pub_hex = (sig.get("ed25519_pub_hex") or "").lower()
        sig_hex = sig.get("sig_hex") or ""
        if not pub_hex or not sig_hex:
            failed.append(f"malformed entry {sig}")
            continue
        if pub_hex not in pub_by_hex:
            failed.append(f"pub {pub_hex[:16]}... not in roster")
            continue
        if pub_hex in seen_pubs:
            failed.append(f"duplicate signer {pub_by_hex[pub_hex]}")
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
                bytes.fromhex(sig_hex), manifest_body
            )
        except (InvalidSignature, ValueError) as e:
            failed.append(f"{pub_by_hex[pub_hex]} sig verify failed ({e.__class__.__name__})")
            continue
        ok_names.append(pub_by_hex[pub_hex])
        seen_pubs.add(pub_hex)
    return (len(ok_names) >= threshold), ok_names, failed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="ExposingTheBadge/Shroud")
    ap.add_argument("--tag", required=True)
    ap.add_argument("--token", default=os.environ.get("GH_TOKEN", ""))
    args = ap.parse_args()

    print(f"[verify] repo={args.repo} tag={args.tag}")
    try:
        rel, assets = _gh_release_assets(args.repo, args.tag, args.token)
    except urllib.error.HTTPError as e:
        print(f"[verify] github API error {e.code}: {e.read()[:200]!r}")
        return 1

    asset_by_name = { a["name"]: a for a in assets }
    if "manifest.json" not in asset_by_name:
        print("[verify] release has no manifest.json asset — nothing to verify")
        return 1
    if "signatures.json" not in asset_by_name:
        print("[verify] release has no signatures.json asset")
        return 1

    with tempfile.TemporaryDirectory() as td:
        manifest_path   = _download_asset(asset_by_name["manifest.json"], td, args.token)
        signatures_path = _download_asset(asset_by_name["signatures.json"], td, args.token)
        manifest_body   = open(manifest_path, "rb").read()
        signatures = json.loads(open(signatures_path).read())
        if isinstance(signatures, dict):
            signatures = signatures.get("signatures") or signatures.get("entries") or []

        roster    = _load_roster()
        threshold = _load_threshold()
        ok, ok_names, failed = _verify_signatures(
            manifest_body, signatures, roster, threshold)

        print(f"[verify] roster size: {len(roster)}  threshold: {threshold}")
        print(f"[verify] valid signatures from in-roster signers:")
        for n in ok_names: print(f"          + {n}")
        if failed:
            print(f"[verify] rejected entries:")
            for f in failed: print(f"          - {f}")
        if not ok:
            print(f"[verify] FAIL — only {len(ok_names)} valid signature(s); need {threshold}")
            return 1

        # Per-artifact hash check
        manifest = json.loads(manifest_body)
        artifacts = manifest.get("artifacts") or manifest.get("files") or []
        if not artifacts:
            print("[verify] manifest has no artifacts list to check")
        else:
            print(f"[verify] checking {len(artifacts)} artifact hash(es):")
            for art in artifacts:
                name   = art.get("name") or art.get("file")
                sha    = (art.get("sha256") or art.get("hash") or "").lower()
                if not (name and sha):
                    print(f"          - {name or '(?)'}: bad manifest entry")
                    return 1
                if name not in asset_by_name:
                    print(f"          - {name}: missing from release")
                    return 1
                blob = _download_asset(asset_by_name[name], td, args.token)
                actual = hashlib.sha256(open(blob, "rb").read()).hexdigest().lower()
                if actual != sha:
                    print(f"          x {name}: HASH MISMATCH (expected {sha[:16]}... got {actual[:16]}...)")
                    return 1
                print(f"          OK {name}  {sha[:16]}...")

    print(f"[verify] PASS — release {args.tag} verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
