"""
The relay contract the mobile clients (Android, iOS/macOS) depend on.

Plays two phone clients against an in-process relay, using the exact
formulas and field names the apps use, so a server change that would break
the apps fails here first:

  * encrypted sign-in: P-384 SPKI DER key, auth key
    SHA-256(SHA-256(ecdh) || "SHROUD-AUTH-v1"), AES-GCM payload
  * X25519 ratchet bundle publish, /ratchet/identity, /ratchet/bundle
  * friend request -> accept -> /friends/list -> /contacts/devices
  * anonymous delivery: a sealed *bare* envelope (Android/iOS shape) and a
    sealed {"envelope": ...} wrapper (Windows shape) both come back from
    /messages/fetch-anon, and each delete on delivery
  * /devices/{id}/pubkey with an empty JSON body (the static fallback)
  * legacy /messages/send takes the envelope as a JSON string

Run::

    python -m tests.mobile_client_contract
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, REPO)

from tests.server_regressions import _load_server  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, x25519  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from crypto import anon_routing as ar  # noqa: E402

PAD_BUCKETS = [4096, 65536, 1048576, 16777216]


def _raw(k) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Phone:
    """One mobile client, doing what ShroudClient / ShroudVM do."""

    def __init__(self, c, username: str):
        self.c, self.username = c, username
        self.p384 = ec.generate_private_key(ec.SECP384R1())
        self.x_priv = x25519.X25519PrivateKey.generate()
        self.x_pub = _raw(self.x_priv.public_key())
        self.did = ""

    def spki_hex(self) -> str:
        return self.p384.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()

    def auth(self, password: str, register: bool) -> int:
        kx = self.c.get("/api/v1/key-exchange").json()
        server_pub = serialization.load_der_public_key(bytes.fromhex(kx["server_public_key"]))
        shared = self.p384.exchange(ec.ECDH(), server_pub)
        key = hashlib.sha256(hashlib.sha256(shared).digest() + b"SHROUD-AUTH-v1").digest()
        payload = json.dumps({
            "username": self.username, "password": password, "device_name": "phone",
            "platform": "ios", "register": register, "public_key": self.spki_hex(),
            "existing_device_id": "" if register else self.did,
        }).encode()
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, payload, None)
        r = self.c.post("/api/v1/auth", json={
            "session_id": kx["session_id"], "client_public_key": self.spki_hex(),
            "nonce": nonce.hex(), "ciphertext": ct[:-16].hex(), "tag": ct[-16:].hex()})
        if r.status_code == 200:
            self.did = r.json()["device_id"]
        return r.status_code

    def publish(self) -> dict:
        otps = [{"prekey_id": i, "pub": _raw(x25519.X25519PrivateKey.generate().public_key()).hex()}
                for i in range(4)]
        r = self.c.post("/api/v1/ratchet/publish-key", json={
            "device_id": self.did, "x25519_pub": self.x_pub.hex(), "one_time_prekeys": otps})
        assert r.status_code == 200, r.text
        return r.json()

    def root_with(self, other: "Phone") -> bytes:
        return self.x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(other.x_pub))

    def send_anon(self, to: "Phone", plaintext: bytes) -> int:
        tag = ar.routing_tag(self.root_with(to), ar.pair_id(self.x_pub, to.x_pub), ar.epoch_for())
        sealed = ar.seal(plaintext, to.x_pub)
        target = next(b for b in PAD_BUCKETS if b >= len(sealed))
        r = self.c.post("/api/v1/messages/send-anon", content=sealed + b"\0" * (target - len(sealed)),
                        headers={"Content-Type": "application/octet-stream",
                                 "X-Routing-Tag": tag.hex(), "X-Envelope-Version": "2"})
        return r.status_code

    def fetch_anon(self, frm: "Phone") -> list[bytes]:
        pid = ar.pair_id(self.x_pub, frm.x_pub)
        tags = ar.fetch_tags_for_window([(pid, self.root_with(frm))])
        r = self.c.post("/api/v1/messages/fetch-anon", json={"tags": [t.hex() for t in tags]})
        assert r.status_code == 200, r.text
        out = []
        for m in r.json()["messages"]:
            blob = bytes.fromhex(m["sealed"])
            n = len(blob.rstrip(b"\0"))
            for tail in range(n, min(n + 32, len(blob)) + 1):
                try:
                    out.append(ar.unseal(blob[:tail], self.x_priv.private_bytes(
                        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                        serialization.NoEncryption())))
                    break
                except Exception:
                    continue
        return out


_N = [0]


def _pair(c):
    _N[0] += 1
    a, b = Phone(c, f"alice{_N[0]}"), Phone(c, f"bob{_N[0]}")
    assert a.auth("correct-horse-battery-1", True) == 200
    assert b.auth("correct-horse-battery-2", True) == 200
    a.publish(); b.publish()
    r = c.post("/api/v1/friends/request", json={"device_id": a.did, "target_username": b.username})
    assert r.status_code == 200, r.text
    inc = c.post("/api/v1/friends/list", json={"device_id": b.did}).json()["incoming"]
    assert [i["from"] for i in inc] == [a.username], inc
    r = c.post("/api/v1/friends/respond", json={"device_id": b.did, "request_id": inc[0]["id"], "accept": True})
    assert r.status_code == 200, r.text
    return a, b


def check_auth_and_relogin(c):
    p = Phone(c, "relogincc")
    assert p.auth("correct-horse-battery-3", True) == 200
    first = p.did
    assert p.auth("correct-horse-battery-3", False) == 200
    assert p.did == first, "existing_device_id must reuse the device row"
    assert p.auth("wrong-password-entirely", False) == 401
    assert Phone(c, "relogincc").auth("x" * 14, True) == 409


def check_contacts_and_keys(c):
    a, b = _pair(c)
    friends = c.post("/api/v1/friends/list", json={"device_id": a.did}).json()["friends"]
    assert {"username": b.username} in friends, friends
    devs = c.post("/api/v1/contacts/devices",
                  json={"device_id": a.did, "contact_username": b.username}).json()["devices"]
    assert devs[0]["id"] == b.did and devs[0]["public_key"] == b.spki_hex(), devs
    ident = c.get(f"/api/v1/ratchet/identity/{b.did}").json()
    assert ident["x25519_pub"] == b.x_pub.hex()
    bundle = c.get(f"/api/v1/ratchet/bundle/{b.did}").json()
    assert bundle["x25519_pub"] == b.x_pub.hex() and "prekey_id" in bundle["one_time_prekey"], bundle
    pk = c.post(f"/api/v1/devices/{b.did}/pubkey", json={})
    assert pk.status_code == 200 and pk.json()["public_key"] == b.spki_hex(), pk.text


def check_anon_both_payload_shapes(c):
    a, b = _pair(c)
    bare = {"ratchet": 1, "sender": a.did, "ts": 1, "ciphertext": "00" * 60}
    wrapped = {"envelope": {"sender": a.did, "nonce": "00" * 12, "ciphertext": "00", "tag": "00" * 16}, "ts": 1}
    assert a.send_anon(b, json.dumps(bare).encode()) == 200
    assert a.send_anon(b, json.dumps(wrapped).encode()) == 200
    got = [json.loads(p) for p in b.fetch_anon(a)]
    assert bare in got and wrapped in got, got
    # What the clients now do with either shape:
    senders = {(g.get("envelope") or g)["sender"] for g in got}
    assert senders == {a.did}, senders
    assert b.fetch_anon(a) == [], "anonymous messages must be deleted on delivery"


def check_legacy_send_string_envelope(c):
    a, b = Phone(c, "legacya"), Phone(c, "legacyb")
    assert a.auth("correct-horse-battery-4", True) == 200
    assert b.auth("correct-horse-battery-5", True) == 200
    env = {"sender": a.did, "ts": 1, "nonce": "00" * 12, "ciphertext": "ab", "tag": "00" * 16, "sig": "00"}
    r = c.post("/api/v1/messages/send", json={
        "sender_device_id": a.did, "recipient_device_id": b.did, "envelope": json.dumps(env)})
    assert r.status_code == 200 and "message_id" in r.json(), r.text
    msgs = c.post("/api/v1/messages/fetch", json={"device_id": b.did}).json()["messages"]
    assert msgs and msgs[0]["envelope"] == env and msgs[0]["sender_device_id"] == a.did, msgs


CHECKS = [v for k, v in list(globals().items()) if k.startswith("check_")]


def main() -> int:
    from fastapi.testclient import TestClient
    srv, _ = _load_server()
    c = TestClient(srv.app)
    failed = 0
    for fn in CHECKS:
        try:
            fn(c)
            print(f"  PASS  {fn.__name__[6:]}")
        except Exception:
            failed += 1
            print(f"  FAIL  {fn.__name__[6:]}")
            traceback.print_exc()
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
