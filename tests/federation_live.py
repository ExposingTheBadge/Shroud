"""
Federation gossip smoke test against the live 4-region AWS deployment.

Verifies that a sealed envelope posted to ONE relay reaches the OTHER three
via the operator-vetted federation gossip loop.

Procedure
---------
1. Compute a routing tag T for a fresh shared root + ephemeral pair.
2. Seal a small marker payload to a fresh recipient X25519 keypair.
3. POST the sealed envelope to relay A (us-east-1) at /messages/send-anon.
4. Poll relay B (us-east-2), C (us-west-2), D (eu-west-1) for tag T at
   /messages/fetch-anon for up to ``--timeout`` seconds.
5. PASS iff all three peers serve back the same sealed envelope.

This is the live counterpart to ``tests/federation_e2e.py`` (which uses
in-process relays). Run when you've changed federation code, when the
federation_peers roster changes, or as a periodic production sanity check.

Usage::

    python -m tests.federation_live
    python -m tests.federation_live --timeout 30
    python -m tests.federation_live --quiet
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

from crypto.anon_routing import (  # noqa: E402
    epoch_for,
    pair_id,
    routing_tag,
    seal,
    unseal,
)

# Source of truth lives in SESSION_NOTES.md
RELAYS = {
    "us-east-1 (Virginia)":  "https://44.202.225.57:58443",
    "us-east-2 (Ohio)":      "https://3.142.185.104:58443",
    "us-west-2 (Oregon)":    "https://54.214.75.14:58443",
    "eu-west-1 (Ireland)":   "https://54.171.165.223:58443",
}
ORIGIN = "us-east-1 (Virginia)"

# Match server padding bucket (smallest one — every relay accepts 4096)
PAD_BUCKET = 4096


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _pad(payload: bytes, size: int) -> bytes:
    if len(payload) > size:
        raise ValueError(f"payload {len(payload)}B exceeds bucket {size}B")
    return payload + b"\x00" * (size - len(payload))


def _post(url: str, body: bytes, headers: dict) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ctx(), timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _get(url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=_ctx(), timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def health_all() -> bool:
    print("Health-check:")
    all_ok = True
    for label, url in RELAYS.items():
        try:
            code, body = _get(f"{url}/health")
            ok = code == 200 and b'"status":"ok"' in body
            print(f"  {'PASS' if ok else 'FAIL'}  {label:<24}  {code}")
            if not ok:
                all_ok = False
        except Exception as e:
            print(f"  FAIL  {label:<24}  {e}")
            all_ok = False
    print()
    return all_ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=30,
                    help="seconds to wait for gossip to arrive")
    ap.add_argument("--poll-interval", type=float, default=2.0)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not health_all():
        print("Aborting: not all relays healthy.")
        return 1

    # Generate a one-shot recipient + sender identity pair
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization

    def kp():
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ), pub

    sender_priv, sender_pub = kp()
    recip_priv, recip_pub = kp()

    shared_root = os.urandom(32)
    pid = pair_id(sender_pub, recip_pub)
    e = epoch_for()
    tag = routing_tag(shared_root, pid, e)
    tag_hex = tag.hex()

    marker = f"shroud-fed-live-{os.urandom(6).hex()}"
    payload = json.dumps({"marker": marker, "ts": int(time.time())}).encode()
    sealed = seal(payload, recip_pub)
    padded = _pad(sealed, PAD_BUCKET)

    print(f"Test marker:    {marker}")
    print(f"Routing tag:    {tag_hex[:16]}... ({len(tag)}B)")
    print(f"Sealed size:    {len(sealed)}B (padded to {PAD_BUCKET}B)")
    print(f"Origin relay:   {ORIGIN}  ->  {RELAYS[ORIGIN]}")
    print()

    # 1) POST to origin
    code, body = _post(
        f"{RELAYS[ORIGIN]}/api/v1/messages/send-anon",
        padded,
        {
            "Content-Type": "application/octet-stream",
            "X-Routing-Tag": tag_hex,
        },
    )
    if code not in (200, 202):
        print(f"FAIL  POST send-anon at origin returned {code}: {body[:200]!r}")
        return 1
    print(f"PASS  POST send-anon at origin  ({code})")
    print()

    # 2) Poll the other 3 relays
    peers = [(label, url) for label, url in RELAYS.items() if label != ORIGIN]
    arrived: dict[str, float] = {}
    start = time.time()
    deadline = start + args.timeout

    print(f"Polling {len(peers)} peer relays for tag (up to {args.timeout}s):")
    while time.time() < deadline and len(arrived) < len(peers):
        for label, url in peers:
            if label in arrived:
                continue
            try:
                code, body = _post(
                    f"{url}/api/v1/messages/fetch-anon",
                    json.dumps({"tags": [tag_hex]}).encode(),
                    {"Content-Type": "application/json"},
                )
                if code == 200:
                    data = json.loads(body.decode() or "{}")
                    msgs = data.get("messages") or []
                    for m in msgs:
                        hex_str = m.get("sealed") or m.get("sealed_hex") or ""
                        if not hex_str:
                            continue
                        sealed_b = bytes.fromhex(hex_str)
                        # Walk-forward unpad: strip trailing zeros, then try
                        # successive tail offsets in case the seal itself
                        # ends in 0x00 bytes (matches python_sdk behavior).
                        i = len(sealed_b)
                        while i > 0 and sealed_b[i - 1] == 0:
                            i -= 1
                        pt = None
                        for j in range(i, min(i + 32, len(sealed_b)) + 1):
                            try:
                                pt = unseal(sealed_b[:j], recip_priv)
                                break
                            except Exception:
                                continue
                        if pt and marker.encode() in pt:
                            arrived[label] = time.time() - start
                            if not args.quiet:
                                print(f"  PASS  {label:<24}  {arrived[label]:.1f}s")
                            break
                elif not args.quiet:
                    # show first miss only
                    pass
            except Exception as e:
                if not args.quiet:
                    print(f"  ERR   {label:<24}  {e}")
        if len(arrived) < len(peers):
            time.sleep(args.poll_interval)

    missing = [label for label, _ in peers if label not in arrived]
    print()
    if missing:
        print("FAIL  gossip did not arrive at:")
        for m in missing:
            print(f"        - {m}")
        return 1

    print(f"PASS  gossip reached all {len(peers)} peers")
    worst = max(arrived.values())
    print(f"      slowest peer:  {worst:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
