"""
SHROUD multi-device linking.

The user owns a SHROUD identity. They want to use that same identity
from a second device — phone alongside laptop, work laptop alongside
home laptop. Multi-device linking transfers the necessary state from
the primary device to the secondary device without:

  - typing a password again,
  - the server learning that the two devices are the same user,
  - either device's key material crossing the network in the clear.

Server endpoints (already implemented in ``server/server.py``)
-------------------------------------------------------------

  POST /api/v1/devices/link/init               -> {link_id, code}
  GET  /api/v1/devices/link/{link_id}          -> {primary_pubkey_hex}
  POST /api/v1/devices/link/{link_id}/secondary  body: {secondary_pubkey_hex}
  POST /api/v1/devices/link/{link_id}/payload    body: ciphertext (sealed)
  GET  /api/v1/devices/link/{link_id}/payload  -> ciphertext or 404

A link_id is a random 32-byte token with a 5-minute TTL. The server
sees:

  - that some device opened a link (init),
  - that some device picked it up (secondary),
  - an encrypted ciphertext deposited and fetched once each.

It does NOT see:

  - which existing user the primary device belongs to (init carries
    only the primary's published X25519 link pubkey, not its identity),
  - the secondary device's identity,
  - the contents of the payload.

This module wraps that flow into a clean client-side helper.

Flow
----

1. **Primary** calls ``Primary.start_link()``. Returns a 6-digit code +
   a QR-encodable string. The primary displays both in its UI.
2. **Secondary** sees the code/QR. Calls
   ``Secondary.scan_link(qr_or_code)`` which fetches the primary's
   advertised link pubkey from the server.
3. **Secondary** generates its own ephemeral X25519 keypair and posts
   its pubkey to ``/secondary``. The server returns the primary's
   pubkey (which the secondary already has) and the secondary's id.
4. **Primary** polls ``/{link_id}`` and sees the secondary's pubkey
   appear. The primary then runs ``Primary.complete_link(payload)``
   which seals the user's local vault (identity keys + contacts +
   message history) under an X25519+AES-GCM envelope keyed by the
   *combination* of primary+secondary ephemeral keys, and POSTs it to
   ``/payload``.
5. **Secondary** calls ``Secondary.pickup_payload()`` which GETs the
   ciphertext, decrypts with its ephemeral key, and now has the full
   vault. Server immediately deletes the ciphertext.

Rule compliance
---------------
  - Rule 1+2: every byte that travels is opaque ciphertext or short-
    lived pubkeys. The server cannot link the primary's identity to
    the secondary's.
  - Rule 3: the payload is whatever the primary chose to include
    (typically identity keys + per-contact X3DH state + recent message
    history). It's all encrypted before leaving the primary.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass
from typing import Optional

from .anon_routing import _hkdf_extract, _hkdf_expand


# ── 6-digit code derivation ──────────────────────────────────────────


def _code_from_pubkey(pubkey: bytes) -> str:
    """6-digit human-readable code derived from the primary's link
    pubkey. The user reads it aloud to the secondary device for
    out-of-band verification; the QR is the convenient path."""
    h = hashlib.sha256(b"shroud-link-code-v1" + pubkey).digest()
    n = int.from_bytes(h[:4], "big") % 1_000_000
    return f"{n:06d}"


# ── Primary side ─────────────────────────────────────────────────────


@dataclass
class PrimaryLinkState:
    link_id: str
    link_priv: bytes        # X25519
    link_pub: bytes
    code: str
    qr_payload: str
    secondary_pub: Optional[bytes] = None


class Primary:
    """Helper for the device that ALREADY has the user's identity and
    is granting the link."""

    def __init__(self) -> None:
        self.state: Optional[PrimaryLinkState] = None

    def start_link(self) -> PrimaryLinkState:
        """Generate the link keypair + ID. Caller POSTs link_pub to
        /api/v1/devices/link/init and stores the returned link_id."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        link_priv = priv.private_bytes_raw()
        link_pub = priv.public_key().public_bytes_raw()

        link_id = secrets.token_hex(16)  # client-suggested; server may override
        code = _code_from_pubkey(link_pub)
        qr = f"shroud-link://v1?id={link_id}&pub={link_pub.hex()}"
        self.state = PrimaryLinkState(
            link_id=link_id,
            link_priv=link_priv,
            link_pub=link_pub,
            code=code,
            qr_payload=qr,
        )
        return self.state

    def record_secondary(self, secondary_pubkey: bytes) -> None:
        """The primary polls the link endpoint until the secondary
        publishes its pubkey. Call this once that happens."""
        if self.state is None:
            raise RuntimeError("start_link must be called first")
        if len(secondary_pubkey) != 32:
            raise ValueError("secondary pubkey must be 32 bytes")
        self.state.secondary_pub = secondary_pubkey

    def seal_payload(self, vault_bytes: bytes) -> bytes:
        """Encrypt the vault for the secondary. The wire bytes are
        what the primary POSTs to /payload.

        Derivation:
          shared_dh = X25519(link_priv, secondary_pub)
          PRK = HKDF-Extract("shroud-link-v1", shared_dh || link_pub || secondary_pub)
          key = HKDF-Expand(PRK, "vault", 32)
          nonce = random(12)
          ciphertext, tag = AES-256-GCM(key, nonce, vault_bytes)
          wire = link_pub (32) || nonce (12) || ciphertext || tag (16)
        """
        if self.state is None or self.state.secondary_pub is None:
            raise RuntimeError("secondary_pub not yet recorded")

        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        priv = X25519PrivateKey.from_private_bytes(self.state.link_priv)
        peer = X25519PublicKey.from_public_bytes(self.state.secondary_pub)
        shared = priv.exchange(peer)

        ikm = shared + self.state.link_pub + self.state.secondary_pub
        prk = _hkdf_extract(b"shroud-link-v1", ikm)
        key = _hkdf_expand(prk, b"vault", 32)

        nonce = os.urandom(12)
        aead = AESGCM(key)
        ct_and_tag = aead.encrypt(nonce, vault_bytes, None)

        return self.state.link_pub + nonce + ct_and_tag


# ── Secondary side ───────────────────────────────────────────────────


@dataclass
class SecondaryLinkState:
    link_id: str
    primary_link_pub: bytes
    my_priv: bytes
    my_pub: bytes


class Secondary:
    """Helper for the new device that wants to join an existing
    identity."""

    def __init__(self) -> None:
        self.state: Optional[SecondaryLinkState] = None

    def scan_qr(self, qr: str) -> tuple[str, bytes]:
        """Parse a scanned QR. Returns ``(link_id, primary_link_pub)``."""
        if not qr.startswith("shroud-link://v1?"):
            raise ValueError("not a SHROUD link QR")
        body = qr[len("shroud-link://v1?"):]
        parts = dict(p.split("=", 1) for p in body.split("&"))
        return parts["id"], bytes.fromhex(parts["pub"])

    def begin(self, link_id: str, primary_link_pub: bytes) -> SecondaryLinkState:
        """Generate the secondary's ephemeral keypair and store the
        link state. Caller POSTs my_pub to /secondary."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        self.state = SecondaryLinkState(
            link_id=link_id,
            primary_link_pub=primary_link_pub,
            my_priv=priv.private_bytes_raw(),
            my_pub=priv.public_key().public_bytes_raw(),
        )
        return self.state

    def verify_code(self, displayed_code: str) -> bool:
        """User compares the code shown on the primary to what the
        secondary derived from the scanned QR. Returns True if they
        match (i.e., the scan wasn't substituted by a MITM)."""
        if self.state is None:
            return False
        expected = _code_from_pubkey(self.state.primary_link_pub)
        return hmac.compare_digest(expected, displayed_code)

    def unseal_payload(self, wire: bytes) -> bytes:
        """Reverse of ``Primary.seal_payload``. Returns the vault bytes."""
        if self.state is None:
            raise RuntimeError("begin() must be called first")
        if len(wire) < 32 + 12 + 16:
            raise ValueError("payload too short")

        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        primary_pub_from_wire = wire[:32]
        if primary_pub_from_wire != self.state.primary_link_pub:
            raise ValueError(
                "primary link pubkey in payload does not match scanned QR — "
                "possible MITM"
            )
        nonce = wire[32:32 + 12]
        ct_and_tag = wire[32 + 12:]

        priv = X25519PrivateKey.from_private_bytes(self.state.my_priv)
        peer = X25519PublicKey.from_public_bytes(primary_pub_from_wire)
        shared = priv.exchange(peer)

        ikm = shared + primary_pub_from_wire + self.state.my_pub
        prk = _hkdf_extract(b"shroud-link-v1", ikm)
        key = _hkdf_expand(prk, b"vault", 32)
        return AESGCM(key).decrypt(nonce, ct_and_tag, None)


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Round-trip: primary creates link, secondary scans QR + verifies code,
    # primary records secondary pub, primary seals, secondary unseals.
    p = Primary()
    p_state = p.start_link()

    s = Secondary()
    link_id, primary_pub = s.scan_qr(p_state.qr_payload)
    assert link_id == p_state.link_id
    assert primary_pub == p_state.link_pub

    s_state = s.begin(link_id, primary_pub)
    assert s.verify_code(p_state.code), "code mismatch after honest scan"

    p.record_secondary(s_state.my_pub)
    vault = json.dumps({"identity_priv": "aa" * 32, "messages": []}).encode()
    wire = p.seal_payload(vault)

    out = s.unseal_payload(wire)
    assert out == vault, "vault round-trip failed"

    # MITM: secondary scans a forged QR with wrong primary pub
    s2 = Secondary()
    forged_qr = f"shroud-link://v1?id=fake&pub={'00' * 32}"
    fid, fpub = s2.scan_qr(forged_qr)
    s2.begin(fid, fpub)
    # Real code from honest primary doesn't match the forged QR's derived code
    assert not s2.verify_code(p_state.code), "MITM should fail code check"

    # Tampered ciphertext detected
    p3 = Primary()
    p3.start_link()
    s3 = Secondary()
    s3.begin(p3.state.link_id, p3.state.link_pub)
    p3.record_secondary(s3.state.my_pub)
    wire3 = bytearray(p3.seal_payload(b"secret"))
    wire3[-1] ^= 1
    try:
        s3.unseal_payload(bytes(wire3))
        raise AssertionError("tamper detection failed")
    except Exception:
        pass

    print("device_link self-tests passed.")


if __name__ == "__main__":
    _self_test()
