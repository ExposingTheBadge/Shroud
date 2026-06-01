"""
SHROUD operator diagnostics inbox.

The relay operator runs this to drain pending anonymous error reports
filed by SHROUD clients via the /api/v1/diagnostics/report endpoint.

The operator needs:
  - their X25519 *diagnostics keypair* (32-byte priv + pub). Generate
    with --keygen if you don't have one yet.
  - the operator's published pubkey baked into every client (currently
    the OPERATOR_DIAG_PUBKEY_HEX constant in each client's main).
    Operator publishes a real pubkey once and ships it in clients.

Usage:

    # Generate a fresh keypair (do this once):
    python -m tools.diagnostics_inbox keygen \\
        --keyfile ~/.config/shroud/diag.keypair.json

    # Poll the relay:
    python -m tools.diagnostics_inbox poll \\
        --keyfile ~/.config/shroud/diag.keypair.json \\
        --relay-url https://44.202.225.57:58443

    # Operator inspects the decrypted reports, then optionally files
    # GitHub issues for the underlying bugs (manually, deduplicated).
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

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from crypto.anon_routing import unseal
from crypto.error_reporting import fetch_window_tags_for_operator


def keygen(args) -> int:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    out = {
        "priv_hex": sk.private_bytes_raw().hex(),
        "pub_hex": pk.hex(),
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.keyfile)) or ".", exist_ok=True)
    with open(args.keyfile, "w") as f:
        json.dump(out, f)
    os.chmod(args.keyfile, 0o600)
    print(f"wrote keypair to {args.keyfile}")
    print(f"diagnostics pubkey: {pk.hex()}")
    print()
    print("Bake this pubkey into your clients (each platform's main:")
    print("  - clients/android/.../MainActivity.kt   OPERATOR_DIAG_PUBKEY_HEX")
    print("  - clients/ios/.../ShroudApp.swift       ErrorReporter.install(...)")
    print("  - clients/windows/main.cpp              error_reporter_install(...)")
    print()
    print("then ship a release. Reports filed by those clients will be")
    print("decryptable here.")
    return 0


def _trim_sealed_tail(sealed_padded: bytes) -> bytes:
    """Diagnostic reports are padded to exactly 4096 bytes. The actual
    sealed envelope is shorter; strip the trailing zeros."""
    # Sealed envelope = 1 (version) + 32 (eph_pub) + 12 (nonce) + ct + 16 (tag)
    # We don't know ct length from outside, so walk back from 4096 and
    # try unseal at decreasing lengths. The auth tag check tells us
    # when we found the right boundary.
    i = len(sealed_padded)
    while i > 0 and sealed_padded[i - 1] == 0:
        i -= 1
    return sealed_padded[:i]


def poll(args) -> int:
    if not os.path.exists(args.keyfile):
        print(f"keyfile not found: {args.keyfile}", file=sys.stderr)
        print("run 'keygen' first.", file=sys.stderr)
        return 1
    with open(args.keyfile, "r") as f:
        kp = json.load(f)
    priv_bytes = bytes.fromhex(kp["priv_hex"])
    pub_bytes = bytes.fromhex(kp["pub_hex"])

    # Enumerate routing tags for the polling window
    tags = fetch_window_tags_for_operator(pub_bytes, window=args.window)
    tags_hex = [t.hex() for t in tags]

    ctx = ssl.create_default_context()
    if not args.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        f"{args.relay_url.rstrip('/')}/api/v1/diagnostics/fetch",
        data=json.dumps({"tags": tags_hex, "limit": args.limit}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        body = json.loads(resp.read())

    reports = body.get("reports", [])
    if not reports:
        print(f"no pending reports across {len(tags)} tag(s)")
        return 0

    print(f"=== {len(reports)} pending report(s) ===")
    print()
    for i, r in enumerate(reports):
        sealed_bytes = bytes.fromhex(r["sealed"])
        sealed_trimmed = _trim_sealed_tail(sealed_bytes)
        # Try unsealing with a 32-byte tail window since the trim heuristic
        # can stop too early on payloads that happen to end in a zero.
        decoded = None
        last_err = None
        for tail in range(len(sealed_trimmed), min(len(sealed_trimmed) + 33, 4097)):
            try:
                plain = unseal(sealed_bytes[:tail], priv_bytes)
                decoded = json.loads(plain.decode("utf-8"))
                break
            except Exception as e:
                last_err = e
        if decoded is None:
            print(f"[{i+1}] id={r['id']}  ts={r['ts']}  DECRYPT FAILED ({last_err})")
            continue

        print(f"[{i+1}] id={r['id']}  ts={r['ts']}")
        print(f"    app:         {decoded.get('app')}  v{decoded.get('app_version')}")
        print(f"    os:          {decoded.get('os')}")
        print(f"    kind:        {decoded.get('kind')}")
        print(f"    message:     {decoded.get('message')}")
        stk = decoded.get("stack", "").strip()
        if stk:
            print("    stack:")
            for line in stk.splitlines()[:20]:
                print(f"      {line}")
            if len(stk.splitlines()) > 20:
                print(f"      ... ({len(stk.splitlines()) - 20} more lines)")
        ctxd = decoded.get("context", {})
        if ctxd:
            print("    context:")
            for k, v in ctxd.items():
                print(f"      {k} = {v}")
        print()

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD operator diagnostics inbox")
    sub = ap.add_subparsers(dest="command", required=True)

    kp = sub.add_parser("keygen", help="generate a fresh diagnostics keypair")
    kp.add_argument("--keyfile", required=True)
    kp.set_defaults(fn=keygen)

    pl = sub.add_parser("poll", help="drain pending reports")
    pl.add_argument("--keyfile", required=True)
    pl.add_argument("--relay-url", default="https://44.202.225.57:58443")
    pl.add_argument("--window", type=int, default=24,
                    help="how many past epochs to scan (1 epoch = 1 hour)")
    pl.add_argument("--limit", type=int, default=100)
    pl.add_argument("--verify-tls", action="store_true")
    pl.set_defaults(fn=poll)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
