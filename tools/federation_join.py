"""
SHROUD federation: peer onboarding helper.

Walks a new federation operator through the steps to join an
existing relay's federation:

  1. Generate a fresh Ed25519 keypair (the operator's long-term
     identity).
  2. Build + sign a PeerAnnouncement.
  3. Print the pre-approval instructions the existing operator
     needs to run on their relay BEFORE the announcement will be
     accepted.
  4. POST the announcement.
  5. Verify the announcement landed by polling the existing
     relay's /api/v1/federation/peers.

The existing operator vets the new pubkey out-of-band (over a secure
channel — Signal, in-person, whatever). This script is just the
mechanical packaging.

Usage::

    python -m tools.federation_join \\
        --my-endpoint https://relay-b.example:58443 \\
        --existing-relay-url https://44.202.225.57:58443 \\
        --keyfile ~/.config/shroud/operator.ed25519.json
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class OperatorKeypair:
    priv_hex: str
    pub_hex: str

    @classmethod
    def generate(cls) -> "OperatorKeypair":
        sk = Ed25519PrivateKey.generate()
        return cls(
            priv_hex=sk.private_bytes_raw().hex(),
            pub_hex=sk.public_key().public_bytes_raw().hex(),
        )

    @classmethod
    def load(cls, path: str) -> "OperatorKeypair":
        with open(path, "r") as f:
            d = json.load(f)
        return cls(**d)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump({"priv_hex": self.priv_hex, "pub_hex": self.pub_hex}, f)
        os.chmod(path, 0o600)


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD federation onboarding helper")
    ap.add_argument("--my-endpoint", required=True,
                    help="The public URL of YOUR new relay")
    ap.add_argument("--existing-relay-url", required=True,
                    help="A relay already in the target federation")
    ap.add_argument("--keyfile", default="~/.config/shroud/operator.ed25519.json")
    ap.add_argument("--operator-handle", default=None,
                    help="A friendly handle for your operator. Defaults to first 16 hex of pubkey")
    ap.add_argument("--ttl-seconds", type=int, default=86400,
                    help="How long this announcement is valid")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    args.keyfile = os.path.expanduser(args.keyfile)

    # ── 1. Generate or load operator keypair ──
    if os.path.exists(args.keyfile):
        kp = OperatorKeypair.load(args.keyfile)
        print(f"[1] loaded existing operator keypair from {args.keyfile}")
    else:
        kp = OperatorKeypair.generate()
        kp.save(args.keyfile)
        print(f"[1] generated new operator keypair, saved to {args.keyfile}")
    print(f"    pubkey: {kp.pub_hex}")

    handle = args.operator_handle or kp.pub_hex[:16]

    # ── 2. Build announcement ──
    ann = {
        "operator": handle,
        "endpoint": args.my_endpoint,
        "pubkey": kp.pub_hex,
        "ttl_seconds": args.ttl_seconds,
        "ts": int(time.time()),
    }
    canonical = json.dumps(ann, sort_keys=True, separators=(",", ":")).encode()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(kp.priv_hex))
    sig_hex = sk.sign(canonical).hex()
    print(f"[2] built signed announcement (ts={ann['ts']}, ttl={ann['ttl_seconds']}s)")

    # ── 3. Pre-approval instructions ──
    print()
    print("─" * 72)
    print("BEFORE you post this announcement, the existing operator must")
    print("approve your pubkey on their relay. Have them run this SQL on")
    print("their relay's database:")
    print()
    print("    INSERT OR IGNORE INTO federation_peers")
    print("    (pubkey_hex, operator, endpoint, ttl_seconds, ts, sig_hex)")
    print(f"    VALUES ('{kp.pub_hex}', '{handle}', '', 0, 0, '');")
    print()
    print("They DO NOT need to fill in endpoint/ts/sig; the /announce")
    print("call updates those once they exist.")
    print("─" * 72)
    print()

    proceed = input("Has the existing operator pre-approved? [y/N] ").strip().lower()
    if proceed != "y":
        print("aborted. Re-run after pre-approval is in place.")
        return 0

    # ── 4. POST announcement ──
    post = {
        "operator": ann["operator"],
        "endpoint": ann["endpoint"],
        "pubkey_hex": kp.pub_hex,
        "ttl_seconds": ann["ttl_seconds"],
        "ts": ann["ts"],
        "sig_hex": sig_hex,
    }

    ctx = ssl.create_default_context()
    if not args.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    url = args.existing_relay_url.rstrip("/") + "/api/v1/federation/announce"
    req = urllib.request.Request(url, data=json.dumps(post).encode(),
                                  method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            body = json.loads(resp.read())
        print(f"[4] announce -> {body}")
    except urllib.error.HTTPError as e:
        print(f"[4] announce FAILED -> HTTP {e.code}: {e.read().decode()[:200]}")
        return 1
    except Exception as e:
        print(f"[4] announce FAILED -> {e}")
        return 1

    # ── 5. Verify peer roster ──
    roster_url = args.existing_relay_url.rstrip("/") + "/api/v1/federation/peers"
    req = urllib.request.Request(roster_url)
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        peers = json.loads(resp.read()).get("peers", [])
    found = any(p.get("pubkey_hex") == kp.pub_hex for p in peers)
    if found:
        print(f"[5] verified: this operator now appears in the peer roster")
        return 0
    print(f"[5] WARNING: pubkey {kp.pub_hex} not in peer roster after announce")
    return 1


if __name__ == "__main__":
    sys.exit(main())
