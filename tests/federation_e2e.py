"""
Federation gossip end-to-end test using two in-process relays.

Boots two uvicorn instances of server.server on different ports,
pre-approves each as a peer of the other, posts a sealed envelope
to one, polls the other, and verifies the message arrives via
gossip — proving the federation broadcast loop actually moves bytes
across relays.

Run::

    python -m tests.federation_e2e

Useful both as a regression test for the gossip protocol and as a
demo of what a 2-relay federation looks like operationally.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from crypto.anon_routing import (
    seal, unseal, routing_tag, pair_id, epoch_for, fetch_tags_for_window,
)

PAD_BUCKETS = (4096, 65536, 1048576, 16777216)


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn_relay(port: int, workdir: str) -> subprocess.Popen:
    """Start a uvicorn server.server process serving on the given port,
    pointed at an isolated chdir so its SQLite + identity files don't
    collide with the canonical relay or each other.

    The server.py module lives at REPO_ROOT/server/server.py; we
    import it as `server.server:app` and let it write its data files
    into the supplied `workdir` via cwd.
    """
    env = os.environ.copy()
    env["SHROUD_FEDERATION"] = "1"
    env["PYTHONPATH"] = REPO_ROOT
    env["SHROUD_DB_PATH"] = os.path.join(workdir, "shroud.db")
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn",
         "server.server:app", "--host", "127.0.0.1", "--port", str(port),
         "--log-level", "warning"],
        cwd=workdir, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )


def _wait_healthy(port: int, deadline_seconds: float = 30) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    end = time.time() + deadline_seconds
    while time.time() < end:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=2
            ) as resp:
                if json.loads(resp.read()).get("status") == "ok":
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def _pre_approve_peer(workdir: str, peer_pubkey_hex: str) -> None:
    """Operator side: insert the peer's pubkey into federation_peers
    so /announce will be accepted later."""
    db_path = os.path.join(workdir, "shroud.db")
    # Wait for DB to exist + table to be created
    for _ in range(20):
        if os.path.exists(db_path):
            break
        time.sleep(0.3)
    conn = sqlite3.connect(db_path, timeout=5)
    conn.execute(
        "INSERT OR IGNORE INTO federation_peers "
        "(pubkey_hex, operator, endpoint, ttl_seconds, ts, sig_hex) "
        "VALUES (?, '', '', 0, 0, '')",
        (peer_pubkey_hex,),
    )
    conn.commit()
    conn.close()


def _announce(my_url: str, peer_url: str, my_priv: Ed25519PrivateKey,
              my_pubkey_hex: str) -> None:
    """Have this relay POST a signed PeerAnnouncement to its peer."""
    ann = {
        "operator": "test-peer-" + my_pubkey_hex[:8],
        "endpoint": my_url,
        "pubkey": my_pubkey_hex,
        "ttl_seconds": 3600,
        "ts": int(time.time()),
    }
    canonical = json.dumps(ann, sort_keys=True, separators=(",", ":")).encode()
    sig_hex = my_priv.sign(canonical).hex()
    post = {
        "operator": ann["operator"], "endpoint": ann["endpoint"],
        "pubkey_hex": my_pubkey_hex, "ttl_seconds": ann["ttl_seconds"],
        "ts": ann["ts"], "sig_hex": sig_hex,
    }
    req = urllib.request.Request(
        f"{peer_url}/api/v1/federation/announce",
        data=json.dumps(post).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10).read()


def _send_anon(relay_url: str, recipient_pub: bytes,
               tag: bytes, payload: bytes) -> dict:
    sealed = seal(payload, recipient_pub)
    target = next(b for b in PAD_BUCKETS if b >= len(sealed))
    sealed += b"\x00" * (target - len(sealed))
    req = urllib.request.Request(
        f"{relay_url}/api/v1/messages/send-anon",
        data=sealed, method="POST",
        headers={
            "X-Routing-Tag": tag.hex(),
            "X-Envelope-Version": "2",
            "Content-Type": "application/octet-stream",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _fetch_anon(relay_url: str, tags: list[bytes]) -> list[dict]:
    req = urllib.request.Request(
        f"{relay_url}/api/v1/messages/fetch-anon",
        data=json.dumps({"tags": [t.hex() for t in tags]}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read()).get("messages", [])


def main() -> int:
    portA = _free_port()
    portB = _free_port()
    urlA = f"http://127.0.0.1:{portA}"
    urlB = f"http://127.0.0.1:{portB}"

    tmpA = tempfile.mkdtemp(prefix="shroudA_")
    tmpB = tempfile.mkdtemp(prefix="shroudB_")

    # Operator keypairs for each relay
    privA = Ed25519PrivateKey.generate()
    pubA_hex = privA.public_key().public_bytes_raw().hex()
    privB = Ed25519PrivateKey.generate()
    pubB_hex = privB.public_key().public_bytes_raw().hex()

    procA = procB = None
    try:
        print(f"booting relay A at {urlA} (cwd={tmpA})")
        procA = _spawn_relay(portA, tmpA)
        print(f"booting relay B at {urlB} (cwd={tmpB})")
        procB = _spawn_relay(portB, tmpB)

        if not _wait_healthy(portA) or not _wait_healthy(portB):
            print("relays did not become healthy")
            return 1
        print("both relays healthy")

        # Each operator pre-approves the other's pubkey
        _pre_approve_peer(tmpA, pubB_hex)
        _pre_approve_peer(tmpB, pubA_hex)

        # Each relay announces itself to the other
        _announce(urlA, urlB, privA, pubA_hex)
        _announce(urlB, urlA, privB, pubB_hex)
        print("federation roster updated on both sides")

        # Verify each peer is in the other's roster
        rosterA = json.loads(
            urllib.request.urlopen(f"{urlA}/api/v1/federation/peers", timeout=5).read()
        )["peers"]
        rosterB = json.loads(
            urllib.request.urlopen(f"{urlB}/api/v1/federation/peers", timeout=5).read()
        )["peers"]
        assert any(p["pubkey_hex"] == pubB_hex for p in rosterA), "B not in A's roster"
        assert any(p["pubkey_hex"] == pubA_hex for p in rosterB), "A not in B's roster"
        print("peer rosters verified")

        # Send a message to relay A, addressed to a tag we'll poll on B
        recipient_priv = X25519PrivateKey.generate()
        recipient_pub = recipient_priv.public_key().public_bytes_raw()
        recipient_sk = recipient_priv.private_bytes_raw()

        alice_id = os.urandom(32)
        shared_root = os.urandom(32)
        pid = pair_id(alice_id, recipient_pub)
        tag = routing_tag(shared_root, pid, epoch_for())

        marker = f"fed-e2e-{os.urandom(4).hex()}"
        payload = json.dumps({"sender": "alice", "body": marker}).encode()
        send_resp = _send_anon(urlA, recipient_pub, tag, payload)
        print(f"sent to A: {send_resp}")

        # Wait for the gossip loop on A to forward to B
        print("waiting up to 10s for gossip...")
        found = None
        deadline = time.time() + 10
        poll_tags = fetch_tags_for_window([(pid, shared_root)])
        while time.time() < deadline:
            inbox = _fetch_anon(urlB, poll_tags)
            if inbox:
                found = inbox
                break
            time.sleep(1)

        if not found:
            # Diagnostic: see if A still has the message (delete on
            # delivery means A doesn't drop until polled, but if the
            # gossip hadn't fired yet, the message may still be at A)
            inbox_a = _fetch_anon(urlA, poll_tags)
            print(f"FAIL: B never saw the message. A has: {len(inbox_a)} msg(s)")
            return 1

        sealed_bytes = bytes.fromhex(found[0]["sealed"])
        # Trim trailing zeros and try unseal across small tail window
        i = len(sealed_bytes)
        while i > 0 and sealed_bytes[i - 1] == 0:
            i -= 1
        recovered = None
        for tail in range(i, min(i + 32, len(sealed_bytes)) + 1):
            try:
                recovered = unseal(sealed_bytes[:tail], recipient_sk)
                break
            except Exception:
                continue
        assert recovered is not None, "could not unseal forwarded message"
        body = json.loads(recovered)["body"]
        assert body == marker, f"got marker={body!r}, expected {marker!r}"
        print(f"PASS: gossiped envelope arrived at B with marker {marker}")
        return 0

    finally:
        for p in (procA, procB):
            if p is None:
                continue
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        for d in (tmpA, tmpB):
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
