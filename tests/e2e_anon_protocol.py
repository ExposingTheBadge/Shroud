"""
End-to-end integration tests for the SHROUD anonymous routing protocol.

Hits a real live relay (defaults to https://44.202.225.57:58443, the
us-east-1 t3.micro free-tier deploy) and exercises:

  - send-anon / fetch-anon sealed envelope round-trip
  - Rule 2: server deletes on first fetch
  - Tag rotation across epochs
  - Federation peer rejection (operator vetting)
  - Federation broadcast deduplication

Run as a standalone script:

    python -m tests.e2e_anon_protocol

Or via pytest:

    pip install pytest
    pytest tests/e2e_anon_protocol.py -v

Override the relay URL with the SHROUD_RELAY_URL env var. If the relay
is unreachable, tests skip (so CI doesn't false-fail when the network
is down).
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

# Allow this file to run from anywhere relative to the repo root.
HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from crypto.anon_routing import (
    seal,
    unseal,
    routing_tag,
    pair_id,
    epoch_for,
    fetch_tags_for_window,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


RELAY_URL = os.environ.get("SHROUD_RELAY_URL", "https://44.202.225.57:58443")
PAD_BUCKETS = (4096, 65536, 1048576, 16777216)

# Self-signed certs in the test relay — disable hostname/cert check.
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def _http_post(path: str, body: bytes, headers: Optional[Dict[str, str]] = None) -> bytes:
    req = urllib.request.Request(
        f"{RELAY_URL}{path}", data=body, method="POST",
        headers=headers or {},
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
        return resp.read()


def _http_get(path: str) -> bytes:
    req = urllib.request.Request(f"{RELAY_URL}{path}", method="GET")
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
        return resp.read()


def _relay_reachable() -> bool:
    try:
        _http_get("/health")
        return True
    except Exception:
        return False


# ── Test cases ───────────────────────────────────────────────────────


def test_health_endpoint() -> None:
    body = json.loads(_http_get("/health"))
    assert body.get("status") == "ok", body


def test_anon_send_fetch_roundtrip() -> None:
    """The headline e2e: Alice seals, server stores, Bob fetches, Bob unseals."""
    bob_priv = X25519PrivateKey.generate()
    bob_pub = bob_priv.public_key().public_bytes_raw()
    bob_sk = bob_priv.private_bytes_raw()

    alice_id = os.urandom(32)
    shared_root = os.urandom(32)
    pid = pair_id(alice_id, bob_pub)
    tag = routing_tag(shared_root, pid, epoch_for())

    payload = b'{"sender":"alice","msg":"e2e test ' + os.urandom(4).hex().encode() + b'"}'
    sealed = seal(payload, bob_pub)
    sealed += b"\x00" * (PAD_BUCKETS[0] - len(sealed))

    _http_post("/api/v1/messages/send-anon", sealed, {
        "X-Routing-Tag": tag.hex(),
        "X-Envelope-Version": "2",
        "Content-Type": "application/octet-stream",
    })

    poll_tags = fetch_tags_for_window([(pid, shared_root)])
    body = json.loads(_http_post(
        "/api/v1/messages/fetch-anon",
        json.dumps({"tags": [t.hex() for t in poll_tags]}).encode(),
        {"Content-Type": "application/json"},
    ))
    msgs = body.get("messages", [])
    assert len(msgs) == 1, f"expected 1 message, got {len(msgs)}"

    sealed_back = bytes.fromhex(msgs[0]["sealed"])
    expected_len = 1 + 32 + 12 + len(payload) + 16
    recovered = unseal(sealed_back[:expected_len], bob_sk)
    assert recovered == payload, "decrypt mismatch"


def test_rule2_delete_on_delivery() -> None:
    """Rule 2: a second poll for the same tags returns nothing because
    the server deleted the message in the same transaction as the
    first SELECT."""
    bob_priv = X25519PrivateKey.generate()
    bob_pub = bob_priv.public_key().public_bytes_raw()

    alice_id = os.urandom(32)
    shared_root = os.urandom(32)
    pid = pair_id(alice_id, bob_pub)
    tag = routing_tag(shared_root, pid, epoch_for())

    payload = b'{"sender":"alice","msg":"rule2"}'
    sealed = seal(payload, bob_pub)
    sealed += b"\x00" * (PAD_BUCKETS[0] - len(sealed))

    _http_post("/api/v1/messages/send-anon", sealed, {
        "X-Routing-Tag": tag.hex(), "X-Envelope-Version": "2",
    })

    poll_tags = fetch_tags_for_window([(pid, shared_root)])

    # First fetch retrieves.
    body1 = json.loads(_http_post(
        "/api/v1/messages/fetch-anon",
        json.dumps({"tags": [t.hex() for t in poll_tags]}).encode(),
        {"Content-Type": "application/json"},
    ))
    assert len(body1.get("messages", [])) == 1

    # Second fetch must be empty.
    body2 = json.loads(_http_post(
        "/api/v1/messages/fetch-anon",
        json.dumps({"tags": [t.hex() for t in poll_tags]}).encode(),
        {"Content-Type": "application/json"},
    ))
    assert len(body2.get("messages", [])) == 0, (
        "Rule 2 violation: server returned deleted message on second fetch"
    )


def test_tag_rotation_across_epochs() -> None:
    """A tag computed for epoch N != tag computed for epoch N+1 with the
    same root + pair. This is what prevents long-term correlation."""
    root = os.urandom(32)
    pid = 0x1122_3344_5566_7788
    e = epoch_for()
    assert routing_tag(root, pid, e) != routing_tag(root, pid, e + 1)
    assert routing_tag(root, pid, e) != routing_tag(root, pid, e - 1)


def test_federation_rejects_unknown_pubkey() -> None:
    """Operator vetting: unknown pubkey on /announce returns 403."""
    sk = Ed25519PrivateKey.generate()
    pk_hex = sk.public_key().public_bytes_raw().hex()
    ann = {
        "operator": "test-unknown",
        "endpoint": "https://stranger.example:58443",
        "pubkey": pk_hex,
        "ttl_seconds": 3600,
        "ts": int(time.time()),
    }
    canonical = json.dumps(ann, sort_keys=True, separators=(",", ":")).encode()
    sig_hex = sk.sign(canonical).hex()
    post = {
        "operator": ann["operator"],
        "endpoint": ann["endpoint"],
        "pubkey_hex": pk_hex,
        "ttl_seconds": ann["ttl_seconds"],
        "ts": ann["ts"],
        "sig_hex": sig_hex,
    }
    try:
        _http_post(
            "/api/v1/federation/announce",
            json.dumps(post).encode(),
            {"Content-Type": "application/json"},
        )
        raise AssertionError("expected 403")
    except urllib.error.HTTPError as e:
        assert e.code == 403, f"got {e.code}"


def test_diagnostics_round_trip() -> None:
    """Submit a sealed diagnostic report and decrypt it via the inbox flow."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from crypto.error_reporting import DiagnosticReport, seal_report, fetch_window_tags_for_operator
    from crypto.anon_routing import unseal

    op_priv = X25519PrivateKey.generate()
    op_pub = op_priv.public_key().public_bytes_raw()
    op_sk = op_priv.private_bytes_raw()

    rep = DiagnosticReport(
        app="shroud-e2etest",
        app_version="2.5.0",
        os="ci-runner",
        kind="log",
        message="e2e: hello with UUID 12345678-1234-1234-1234-123456789012",
        stack="",
    )
    tag, sealed = seal_report(rep, op_pub)
    padded = sealed + b"\x00" * (4096 - len(sealed))

    # Submit
    req = urllib.request.Request(
        f"{RELAY_URL}/api/v1/diagnostics/report",
        data=padded, method="POST",
        headers={"X-Routing-Tag": tag.hex(), "Content-Type": "application/octet-stream"},
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=10) as resp:
        body = json.loads(resp.read())
    assert body.get("received") is True, body

    # Fetch
    tags = fetch_window_tags_for_operator(op_pub, window=2)
    req = urllib.request.Request(
        f"{RELAY_URL}/api/v1/diagnostics/fetch",
        data=json.dumps({"tags": [t.hex() for t in tags]}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=10) as resp:
        result = json.loads(resp.read())
    assert result.get("count", 0) >= 1, "expected at least 1 report"

    # Decrypt + verify scrubbing
    found_e2e = False
    for r in result["reports"]:
        sealed_bytes = bytes.fromhex(r["sealed"])
        # Trim trailing zeros + try unseal across a tail window.
        j = len(sealed_bytes)
        while j > 0 and sealed_bytes[j - 1] == 0:
            j -= 1
        for tail in range(j, min(j + 32, len(sealed_bytes)) + 1):
            try:
                plain = unseal(sealed_bytes[:tail], op_sk)
                doc = json.loads(plain)
                if doc.get("app") == "shroud-e2etest":
                    # PII scrubbed
                    assert "12345678-1234-1234-1234-123456789012" not in doc.get("message", ""), (
                        "scrubber failed to redact UUID"
                    )
                    assert "<UUID>" in doc.get("message", ""), "expected UUID placeholder"
                    found_e2e = True
                break
            except Exception:
                continue
        if found_e2e:
            break
    assert found_e2e, "did not find our submitted report after fetch"


def test_federation_broadcast_dedup() -> None:
    """A second gossip broadcast for the same message_id is rejected
    with accepted=false reason=duplicate."""
    fake = {
        "type": "shroud.fed.broadcast",
        "message_id": "e2etest-" + os.urandom(8).hex(),
        "routing_tag_hex": os.urandom(32).hex(),
        "envelope_hex": os.urandom(64).hex(),
        "ttl_at": None,
    }
    body = fake.copy()
    r1 = json.loads(_http_post(
        "/api/v1/federation/broadcast",
        json.dumps(body).encode(),
        {"Content-Type": "application/json"},
    ))
    assert r1 == {"accepted": True}, r1

    r2 = json.loads(_http_post(
        "/api/v1/federation/broadcast",
        json.dumps(body).encode(),
        {"Content-Type": "application/json"},
    ))
    assert r2 == {"accepted": False, "reason": "duplicate"}, r2


# ── Runner ───────────────────────────────────────────────────────────


TESTS = [
    test_health_endpoint,
    test_anon_send_fetch_roundtrip,
    test_rule2_delete_on_delivery,
    test_tag_rotation_across_epochs,
    test_federation_rejects_unknown_pubkey,
    test_federation_broadcast_dedup,
    test_diagnostics_round_trip,
]


def main() -> int:
    if not _relay_reachable():
        print(f"SKIP: relay at {RELAY_URL} not reachable")
        return 0

    failures: List[str] = []
    for fn in TESTS:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except Exception as e:
            failures.append(f"{fn.__name__}: {e}")
            print(f"  FAIL  {fn.__name__}: {e}")
    if failures:
        print(f"\n{len(failures)}/{len(TESTS)} tests FAILED")
        return 1
    print(f"\n{len(TESTS)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
