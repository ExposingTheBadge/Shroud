"""
End-to-end smoke test of the anonymous diagnostics path against the live
production federation.

Procedure
---------
1. Load the operator's private diagnostics keypair from a file (default
   ``~/.config/shroud/diag.keypair.json``).
2. Build a synthetic DiagnosticReport with PII embedded in every field
   we care about scrubbing.
3. Seal it to the operator pubkey, pad to 4096 bytes, POST to
   ``/api/v1/diagnostics/report`` at us-east-1.
4. Poll ``/api/v1/diagnostics/fetch`` with the routing-tag window and
   confirm the operator can decrypt + recover the report.
5. Verify PII fields were scrubbed (UUID -> ``<UUID>``, email ->
   ``<EMAIL>``, etc.) — Rule 3 enforcement.

This is the live counterpart to the in-process ``test_diagnostics_
round_trip`` in ``tests/e2e_anon_protocol.py``.

Usage::

    python -m tests.diagnostics_live
    python -m tests.diagnostics_live --keyfile path/to/diag.keypair.json
    python -m tests.diagnostics_live --relay-url https://3.142.185.104:58443
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from crypto.anon_routing import unseal  # noqa: E402
from crypto.error_reporting import (  # noqa: E402
    DiagnosticReport,
    fetch_window_tags_for_operator,
    seal_report,
)

DEFAULT_RELAY = "https://44.202.225.57:58443"
DEFAULT_KEYFILE = os.path.expanduser("~/.config/shroud/diag.keypair.json")
PAD_BUCKET = 4096


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _pad(payload: bytes, size: int) -> bytes:
    if len(payload) > size:
        raise ValueError(f"payload {len(payload)}B > bucket {size}")
    return payload + b"\x00" * (size - len(payload))


def _trim_to_unseal(sealed_padded: bytes, priv: bytes) -> bytes:
    i = len(sealed_padded)
    while i > 0 and sealed_padded[i - 1] == 0:
        i -= 1
    for j in range(i, min(i + 32, len(sealed_padded)) + 1):
        try:
            return unseal(sealed_padded[:j], priv)
        except Exception:
            continue
    raise ValueError("could not locate sealed envelope tail")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay-url", default=DEFAULT_RELAY)
    ap.add_argument("--keyfile", default=DEFAULT_KEYFILE)
    args = ap.parse_args()

    if not os.path.exists(args.keyfile):
        print(f"FAIL  keyfile missing: {args.keyfile}")
        print("      Generate one with: python -m tools.diagnostics_inbox keygen --keyfile " + args.keyfile)
        return 1

    with open(args.keyfile) as f:
        kp = json.load(f)
    op_priv = bytes.fromhex(kp["priv_hex"])
    op_pub  = bytes.fromhex(kp["pub_hex"])
    print(f"Operator pubkey:  {op_pub.hex()[:16]}...")
    print(f"Relay:            {args.relay_url}")

    # --- 1. Build a report with PII embedded ---------------------------
    test_uuid  = "5b4f8c2a-3e1d-4f7b-9a82-1c4e8b1f6d33"
    test_email = "alice.tester@example.com"
    test_ipv4  = "192.168.42.7"
    test_path  = "/home/alicetest/.config/shroud/identity.json"
    test_marker = f"diag-live-{os.urandom(4).hex()}"

    report = DiagnosticReport(
        app="shroud-live-test",
        app_version="2.5.0",
        os="Linux 6.7",
        kind="log",
        message=f"test marker={test_marker} uuid={test_uuid} email={test_email}",
        stack=(
            "Traceback (most recent call last):\n"
            f"  File \"{test_path}\", line 42, in handler\n"
            f"    fetch_from({test_ipv4})\n"
            "RuntimeError: synthetic failure"
        ),
        context={"client_ip": test_ipv4, "user_email": test_email},
    )
    tag, sealed = seal_report(report, op_pub)
    padded = _pad(sealed, PAD_BUCKET)

    print(f"Marker:           {test_marker}")
    print(f"Routing tag:      {tag.hex()[:16]}...")
    print(f"Sealed size:      {len(sealed)}B (padded to {PAD_BUCKET}B)")
    print()

    # --- 2. POST to relay ----------------------------------------------
    req = urllib.request.Request(
        f"{args.relay_url}/api/v1/diagnostics/report",
        data=padded,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Routing-Tag": tag.hex(),
        },
    )
    try:
        with urllib.request.urlopen(req, context=_ctx(), timeout=15) as resp:
            print(f"PASS  POST /diagnostics/report  ({resp.status})")
    except urllib.error.HTTPError as e:
        print(f"FAIL  POST /diagnostics/report  ({e.code}): {e.read()[:200]!r}")
        return 1

    # --- 3. Poll as operator -------------------------------------------
    tags = [t.hex() for t in fetch_window_tags_for_operator(op_pub, window=2)]
    req = urllib.request.Request(
        f"{args.relay_url}/api/v1/diagnostics/fetch",
        data=json.dumps({"tags": tags}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=_ctx(), timeout=15) as resp:
        body = json.loads(resp.read())

    msgs = body.get("messages") or body.get("reports") or []
    if not msgs:
        print(f"FAIL  /diagnostics/fetch returned 0 messages for {len(tags)} tags")
        print(f"      response keys: {list(body.keys())}")
        return 1
    print(f"PASS  /diagnostics/fetch returned {len(msgs)} sealed envelope(s)")

    # --- 4. Decrypt and verify ----------------------------------------
    matched = None
    for m in msgs:
        sealed_hex = m.get("sealed") or m.get("sealed_hex") or ""
        if not sealed_hex:
            continue
        sealed_b = bytes.fromhex(sealed_hex)
        try:
            plaintext = _trim_to_unseal(sealed_b, op_priv)
        except Exception:
            continue
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if test_marker in decoded.get("message", ""):
            matched = decoded
            break

    if not matched:
        print(f"FAIL  could not find our marker {test_marker} in decrypted reports")
        return 1
    print("PASS  decrypted our submitted report")

    # --- 5. Verify PII was scrubbed -----------------------------------
    msg = matched.get("message", "")
    stack = matched.get("stack", "")
    ctx_obj = matched.get("context", {})

    failures = []
    if test_uuid in msg or test_uuid in stack:
        failures.append("UUID leaked through scrub")
    if test_email in msg or test_email in stack or test_email in str(ctx_obj):
        failures.append("email leaked through scrub")
    if test_ipv4 in stack or test_ipv4 in str(ctx_obj):
        failures.append("IPv4 leaked through scrub")
    if "alicetest" in stack:
        failures.append("POSIX username leaked through scrub")
    if "<UUID>" not in msg:
        failures.append("UUID replacement marker missing from message")
    if "<EMAIL>" not in msg:
        failures.append("EMAIL replacement marker missing from message")

    if failures:
        print("FAIL  PII scrub verification:")
        for f in failures:
            print(f"      - {f}")
        print()
        print(f"      message: {msg!r}")
        print(f"      stack:   {stack!r}")
        print(f"      context: {ctx_obj!r}")
        return 1
    print("PASS  Rule 3 enforcement — all PII scrubbed")

    print()
    print(f"Report (scrubbed): {json.dumps(matched, indent=2)[:400]}...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
