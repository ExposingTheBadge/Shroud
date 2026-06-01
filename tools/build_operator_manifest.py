"""
Build + sign the SHROUD operator manifest.

The manifest is the single signed object clients fetch on first launch
(or refresh periodically) to learn:

  - the relay URL(s) they should send through
  - the operator's anonymous-diagnostics X25519 pubkey
  - the sticker pack CDN base
  - the current federation peer roster (operator's view)

A separate **manifest-signing Ed25519 key** signs the manifest. This key
is distinct from the per-relay operator keys (which stay on each relay
and never leave). Clients pin SHA-256 of the manifest pubkey at install
time; rotating the manifest key requires shipping a client release with
the new pin hash.

Usage::

    # First time — generate the manifest-signing keypair
    python -m tools.build_operator_manifest keygen \\
        --keyfile ~/.config/shroud/manifest.ed25519.json

    # Build + sign a manifest. Pulls federation peers from the home relay.
    python -m tools.build_operator_manifest build \\
        --keyfile ~/.config/shroud/manifest.ed25519.json \\
        --home-relay https://44.202.225.57:58443 \\
        --diag-pubkey 7191a786437e38ebe616b9508b3110afb1a635e08ac034a330093acca708fd54 \\
        --stickers-cdn https://stickers.example/ \\
        --ttl-days 30 \\
        --out operator_manifest.signed.json

    # Print the pinned hash for baking into clients
    python -m tools.build_operator_manifest pin \\
        --keyfile ~/.config/shroud/manifest.ed25519.json
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto.operator_manifest import (  # noqa: E402
    FederationPeerInfo,
    OperatorManifest,
    pinned_hash,
    sign_manifest,
    verify_manifest,
)


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cmd_keygen(args) -> int:
    if os.path.exists(args.keyfile) and not args.force:
        print(f"refusing to overwrite {args.keyfile} without --force")
        return 1
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    out = {
        "priv_hex": sk.private_bytes_raw().hex(),
        "pub_hex":  pub.hex(),
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.keyfile)) or ".", exist_ok=True)
    with open(args.keyfile, "w") as f:
        json.dump(out, f)
    try:
        os.chmod(args.keyfile, 0o600)
    except (OSError, NotImplementedError):
        # Windows chmod is best-effort
        pass
    print(f"wrote keypair to {args.keyfile}")
    print(f"manifest pubkey:  {pub.hex()}")
    print(f"pinned hash:      {pinned_hash(pub)}")
    print()
    print("Bake the pinned hash into clients before shipping a release:")
    print("  - Android: SHROUD_MANIFEST_PIN constant in MainActivity.kt")
    print("  - iOS:     SHROUD_MANIFEST_PIN constant in ShroudApp.swift")
    print("  - Windows: g_manifest_pin constant in main.cpp")
    return 0


def _fetch_federation_peers(home_relay: str) -> list[FederationPeerInfo]:
    url = f"{home_relay.rstrip('/')}/api/v1/federation/peers"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, context=_ctx(), timeout=15) as resp:
        data = json.loads(resp.read())
    peers = data.get("peers") or data.get("federation_peers") or []
    out: list[FederationPeerInfo] = []
    for p in peers:
        pub = p.get("pubkey_hex") or p.get("pubkey") or ""
        endpoint = p.get("endpoint") or ""
        if not pub or not endpoint:
            continue
        if not p.get("active", True):
            continue
        out.append(FederationPeerInfo(pubkey_hex=pub, endpoint=endpoint))
    return out


def cmd_build(args) -> int:
    if not os.path.exists(args.keyfile):
        print(f"keyfile missing: {args.keyfile} (run keygen first)")
        return 1
    with open(args.keyfile) as f:
        kp = json.load(f)
    priv = bytes.fromhex(kp["priv_hex"])
    pub  = bytes.fromhex(kp["pub_hex"])

    if len(args.diag_pubkey) != 64:
        print("--diag-pubkey must be 32 bytes hex (64 chars)")
        return 1
    try:
        bytes.fromhex(args.diag_pubkey)
    except ValueError:
        print("--diag-pubkey is not valid hex")
        return 1

    peers = _fetch_federation_peers(args.home_relay)
    print(f"Fetched {len(peers)} federation peer(s) from {args.home_relay}")

    now = int(time.time())
    m = OperatorManifest(
        relay_url=args.home_relay,
        diagnostics_pubkey_hex=args.diag_pubkey,
        stickers_cdn=args.stickers_cdn,
        issued_at=now,
        expires_at=now + (args.ttl_days * 86400),
        federation_peers=peers,
    )
    sign_manifest(m, priv)
    assert verify_manifest(m, pub), "self-verify failed immediately after signing"

    # Pretty-print for human review, then dump canonical for distribution
    print()
    print("Signed manifest:")
    print(json.dumps(m.to_dict(), indent=2))
    print()
    print(f"Pinned hash:      {pinned_hash(pub)}")
    print(f"TTL:              {args.ttl_days} days  (expires {time.ctime(m.expires_at)})")
    print(f"Output:           {args.out}")

    with open(args.out, "w") as f:
        json.dump(m.to_dict(), f, separators=(",", ":"))
    return 0


def cmd_pin(args) -> int:
    if not os.path.exists(args.keyfile):
        print(f"keyfile missing: {args.keyfile}")
        return 1
    with open(args.keyfile) as f:
        kp = json.load(f)
    pub = bytes.fromhex(kp["pub_hex"])
    print(f"pubkey:       {pub.hex()}")
    print(f"pinned hash:  {pinned_hash(pub)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD operator-manifest authoring tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="Generate a manifest-signing Ed25519 keypair")
    kg.add_argument("--keyfile", required=True)
    kg.add_argument("--force", action="store_true",
                    help="overwrite existing keyfile")

    bd = sub.add_parser("build", help="Build + sign a manifest")
    bd.add_argument("--keyfile", required=True)
    bd.add_argument("--home-relay", required=True,
                    help="Home relay URL to pull federation peers from")
    bd.add_argument("--diag-pubkey", required=True,
                    help="Operator diagnostics X25519 pubkey (64 hex chars)")
    bd.add_argument("--stickers-cdn", default="https://stickers.shroud.example/")
    bd.add_argument("--ttl-days", type=int, default=30)
    bd.add_argument("--out", default="operator_manifest.signed.json")

    pn = sub.add_parser("pin", help="Print the SHA-256 pin for a manifest keyfile")
    pn.add_argument("--keyfile", required=True)

    args = ap.parse_args()
    if args.cmd == "keygen":
        return cmd_keygen(args)
    if args.cmd == "build":
        return cmd_build(args)
    if args.cmd == "pin":
        return cmd_pin(args)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
