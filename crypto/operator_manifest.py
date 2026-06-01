"""
SHROUD operator manifest.

The operator runs the public relay and the diagnostics inbox. They
publish ONE signed manifest at a well-known URL that clients fetch on
first launch (or periodically) to learn:

  - the relay URL
  - the operator's diagnostics X25519 pubkey (for sealing error reports)
  - the operator's sticker pack CDN base
  - federation peer roster (operator's view)

The manifest is signed by the operator's long-term Ed25519 identity
key, which clients pin at install time and never accept replacement
of. Manifests with bad signatures get rejected and the client falls
back to the last-known-good manifest cached on disk.

Wire format::

    {
      "schema":              "shroud.operator.v1",
      "relay_url":           "https://44.202.225.57:58443",
      "diagnostics_pubkey_hex": "<32 byte X25519 pubkey>",
      "stickers_cdn":        "https://stickers.shroud.example/",
      "issued_at":           1700000000,
      "expires_at":          1700864000,
      "federation_peers":    [
          {"pubkey_hex": "...", "endpoint": "https://relay-b.example:58443"},
          ...
      ],
      "sig_hex":             "<Ed25519 sig over the canonicalized body>"
    }

Clients pin the operator's Ed25519 pubkey HASH (SHA-256) at install
time. The full pubkey is fetched on first launch; the client verifies
SHA-256(pubkey) == pinned_hash before accepting any manifest signed
by it. This lets the operator rotate the underlying key without
shipping a client update, as long as the new key gets a new hash
pin in a new release.

Rule compliance
---------------
  - Rule 1+2: manifest is fetched over HTTPS or Tor; relay doesn't
    see fetch requests. Clients should fetch via the same anonymizing
    transport they use for messages.
  - Rule 3: manifest carries no user data.
  - Rule 0: operator can republish on any URL the manifest's signing
    key has covered. If the well-known URL goes down, clients fall
    back to a list of mirrors baked at release time.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional


SCHEMA = "shroud.operator.v1"


@dataclass
class FederationPeerInfo:
    pubkey_hex: str
    endpoint: str


@dataclass
class OperatorManifest:
    relay_url: str
    diagnostics_pubkey_hex: str
    stickers_cdn: str
    issued_at: int
    expires_at: int
    federation_peers: List[FederationPeerInfo] = field(default_factory=list)
    sig_hex: str = ""
    schema: str = SCHEMA

    def canonical_body(self) -> bytes:
        """Bytes the operator signs. sig_hex is excluded from
        canonicalization (it's the output)."""
        body = {
            "schema": self.schema,
            "relay_url": self.relay_url,
            "diagnostics_pubkey_hex": self.diagnostics_pubkey_hex,
            "stickers_cdn": self.stickers_cdn,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "federation_peers": [
                {"pubkey_hex": p.pubkey_hex, "endpoint": p.endpoint}
                for p in self.federation_peers
            ],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["federation_peers"] = [asdict(p) for p in self.federation_peers]
        return d


def sign_manifest(m: OperatorManifest, ed25519_priv: bytes) -> OperatorManifest:
    """Sign a manifest in place with the operator's Ed25519 private
    key. Returns the same object with sig_hex set."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(ed25519_priv)
    m.sig_hex = sk.sign(m.canonical_body()).hex()
    return m


def verify_manifest(m: OperatorManifest, ed25519_pub: bytes) -> bool:
    """Verify a manifest's Ed25519 signature against the operator's
    public key. Returns False on bad sig or expired manifest."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    if not m.sig_hex:
        return False
    now = int(time.time())
    if m.expires_at and m.expires_at < now:
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(ed25519_pub)
        pk.verify(bytes.fromhex(m.sig_hex), m.canonical_body())
        return True
    except (InvalidSignature, ValueError):
        return False


def pinned_hash(ed25519_pub: bytes) -> str:
    """The SHA-256 hash clients pin at install time. Replacing the
    operator key requires a client update that ships a new pinned
    hash."""
    return hashlib.sha256(ed25519_pub).hexdigest()


def verify_pubkey_against_pin(ed25519_pub: bytes, pinned: str) -> bool:
    return pinned_hash(ed25519_pub).lower() == pinned.lower()


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    op_priv = Ed25519PrivateKey.generate()
    op_pub = op_priv.public_key().public_bytes_raw()
    op_priv_bytes = op_priv.private_bytes_raw()

    now = int(time.time())
    m = OperatorManifest(
        relay_url="https://44.202.225.57:58443",
        diagnostics_pubkey_hex="aa" * 32,
        stickers_cdn="https://stickers.example/",
        issued_at=now,
        expires_at=now + 86400,
        federation_peers=[
            FederationPeerInfo(pubkey_hex="bb" * 32, endpoint="https://relay-b.example:58443"),
        ],
    )
    sign_manifest(m, op_priv_bytes)
    assert verify_manifest(m, op_pub)

    # Tampered manifest fails
    m.relay_url = "https://attacker.example:58443"
    assert not verify_manifest(m, op_pub)
    sign_manifest(m, op_priv_bytes)
    assert verify_manifest(m, op_pub)

    # Expired manifest fails
    expired = OperatorManifest(
        relay_url="x", diagnostics_pubkey_hex="0" * 64, stickers_cdn="x",
        issued_at=now - 1000, expires_at=now - 100,
    )
    sign_manifest(expired, op_priv_bytes)
    assert not verify_manifest(expired, op_pub)

    # Pinned-hash check
    pin = pinned_hash(op_pub)
    assert verify_pubkey_against_pin(op_pub, pin)
    assert not verify_pubkey_against_pin(b"\x00" * 32, pin)

    print("operator_manifest self-tests passed.")


if __name__ == "__main__":
    _self_test()
