"""
SHROUD federated multi-relay protocol.

Why federate
------------
The Rule 0 commitment is that the project never goes dark. A single
relay (even an AWS Nitro Enclave one) is a single point of compulsion:
seize the hosting account, kill the network. Federation distributes
the network across multiple independent operators so that:

  1. Compromise of any single operator does not break message flow.
  2. Subpoena of any single operator yields no usable data (sealed +
     tag-routed payloads remain opaque).
  3. New operators can join the federation without coordinating with
     existing ones — there is no central admission control.

Design
------
Relays gossip the **same kind of sealed envelopes** they queue locally
to peer relays. A sender talks to whichever relay is fastest from
their network position; the relay then gossips the envelope to a quorum
of peer relays. A recipient polls any relay it can reach; if its
routing tag has an envelope at any relay in the federation, that relay
returns it (and broadcasts a delete to the federation).

The gossip protocol uses the same /api/v1/messages/send-anon and
/api/v1/messages/fetch-anon endpoints — relays look identical to
clients for the purpose of message movement. The only additional
endpoint relays expose to each other is /api/v1/federation/* which
tracks peer-relay membership and a delete-on-deliver broadcast bus.

Trust model
-----------
We deliberately use a **gossip-everywhere model** instead of a routing
table. Every relay forwards every envelope to every peer it knows
about. This makes:

  - Operators NEVER see who their users are talking to, because every
    envelope they hold is also at every other relay.
  - Take-down resistance maximal: an attacker who wants to suppress a
    message must seize every relay simultaneously, not just one.
  - The protocol stateless and trivially horizontally scalable.

Cost: each envelope is replicated O(n) times across the federation.
For SHROUD's message volumes (text-sized) this is comfortable. For
large media attachments we use content-addressed CDN storage instead
of in-message bytes (see ``crypto.stickers`` for the pattern).

Wire format
-----------

Federation peer announcement (signed by the operator's long-term key):

::

    {
      "operator":   "<operator handle, opaque>",
      "endpoint":   "https://relay.example.com:58443",
      "pubkey":     "<32-byte X25519 hex>",
      "ttl_seconds": 86400,
      "ts":         1700000000,
      "sig":        "<Ed25519 over the canonicalized fields>"
    }

Gossip broadcast bus message (envelope arrived; peers should also store):

::

    {
      "type":       "shroud.fed.broadcast",
      "envelope":   "<sealed-envelope bytes, hex>",
      "routing_tag":"<32 byte hex>",
      "ttl_at":     <unix sec or null>,
      "from":       "<origin relay's pubkey hex>"
    }

Delete-on-deliver:

::

    {
      "type":       "shroud.fed.delete",
      "routing_tag":"<32 byte hex>",
      "message_id": "<hex>",
      "delivered_by": "<relay pubkey>"
    }

Operator handles
----------------
Federation peers identify each other by a long-term Ed25519 pubkey.
Operator "handles" are opaque strings (typically a hash of the pubkey)
that humans use to talk about peers without revealing operator legal
identity. Cross-relay attacks would have to forge an Ed25519 signature.

Rule compliance
---------------
  - Rule 0: federation is the structural Rule 0 mechanism. No single
    operator can shut the network down.
  - Rule 1+2: gossip carries the same sealed envelopes + routing tags
    the original send-anon used. Federation peers see the same
    opaque bytes the origin relay sees — no additional metadata leak.
  - Rule 3: orthogonal.

This module ships the wire-format dataclasses and signing/verification
helpers. Actual federation transport is a small server addition (a
broadcast loop that POSTs to peer endpoints) — implementation lives in
``server/federation.py`` once peer-discovery is wired.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ── Wire types ───────────────────────────────────────────────────────


SHROUD_FED_BROADCAST = "shroud.fed.broadcast"
SHROUD_FED_DELETE    = "shroud.fed.delete"
SHROUD_FED_ANNOUNCE  = "shroud.fed.announce"


@dataclass
class PeerAnnouncement:
    operator: str
    endpoint: str
    pubkey_hex: str
    ttl_seconds: int
    ts: int
    sig_hex: str = ""    # Ed25519 sig over canonicalized fields

    def canonical_bytes(self) -> bytes:
        """Bytes signed by the operator's Ed25519 key. Sig field is
        excluded from the canonicalization (it's the output)."""
        body = {
            "operator":    self.operator,
            "endpoint":    self.endpoint,
            "pubkey":      self.pubkey_hex,
            "ttl_seconds": self.ttl_seconds,
            "ts":          self.ts,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class FedBroadcast:
    envelope_hex: str
    routing_tag_hex: str
    ttl_at: Optional[int]   # unix sec or None
    from_pubkey_hex: str    # origin relay's pubkey

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = SHROUD_FED_BROADCAST
        return d


@dataclass
class FedDelete:
    routing_tag_hex: str
    message_id: str
    delivered_by_hex: str   # pubkey of the relay that handed off to the recipient

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = SHROUD_FED_DELETE
        return d


# ── Signing / verification ───────────────────────────────────────────


def sign_announcement(ann: PeerAnnouncement, ed25519_priv: bytes) -> PeerAnnouncement:
    """Sign a peer announcement with the operator's Ed25519 private
    key. Mutates ``ann`` in place to set sig_hex and returns it.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(ed25519_priv)
    sig = sk.sign(ann.canonical_bytes())
    ann.sig_hex = sig.hex()
    return ann


def verify_announcement(ann: PeerAnnouncement, ed25519_pub: bytes) -> bool:
    """Verify a peer announcement against the claimed operator pubkey."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    if not ann.sig_hex:
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(ed25519_pub)
        pk.verify(bytes.fromhex(ann.sig_hex), ann.canonical_bytes())
        return True
    except (InvalidSignature, ValueError):
        return False


# ── Peer roster ──────────────────────────────────────────────────────


@dataclass
class FederationRoster:
    """Local view of the federation roster. Each relay maintains its
    own; rosters are gossiped via signed announcements and reconciled
    by Ed25519 pubkey."""
    peers: dict[str, PeerAnnouncement] = field(default_factory=dict)

    def add(self, ann: PeerAnnouncement) -> bool:
        existing = self.peers.get(ann.pubkey_hex)
        if existing is not None and existing.ts >= ann.ts:
            # We already have a newer or equal announcement for this peer.
            return False
        self.peers[ann.pubkey_hex] = ann
        return True

    def prune_expired(self, now: Optional[int] = None) -> int:
        t = now if now is not None else int(time.time())
        removed = []
        for k, p in self.peers.items():
            if p.ts + p.ttl_seconds < t:
                removed.append(k)
        for k in removed:
            del self.peers[k]
        return len(removed)

    def active(self, now: Optional[int] = None) -> List[PeerAnnouncement]:
        t = now if now is not None else int(time.time())
        return [p for p in self.peers.values() if p.ts + p.ttl_seconds >= t]


# ── Operator handle ─────────────────────────────────────────────────


def operator_handle(pubkey: bytes) -> str:
    """Public, opaque, deterministic handle for an operator: first 16
    hex chars of SHA-256(pubkey). Used in logs and UI in place of any
    PII the operator might want to attach to themselves."""
    return hashlib.sha256(pubkey).hexdigest()[:16]


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    op_priv = Ed25519PrivateKey.generate()
    op_pub = op_priv.public_key().public_bytes_raw()
    op_priv_bytes = op_priv.private_bytes_raw()

    handle = operator_handle(op_pub)
    assert len(handle) == 16

    ann = PeerAnnouncement(
        operator=handle,
        endpoint="https://relay-a.example:58443",
        pubkey_hex=op_pub.hex(),
        ttl_seconds=86400,
        ts=int(time.time()),
    )
    sign_announcement(ann, op_priv_bytes)
    assert verify_announcement(ann, op_pub)

    # Tampered announcement should not verify.
    ann.endpoint = "https://attacker.example:58443"
    assert not verify_announcement(ann, op_pub)

    # Re-sign after tampering and reverify.
    sign_announcement(ann, op_priv_bytes)
    assert verify_announcement(ann, op_pub)

    # Roster reconciles by newer ts.
    roster = FederationRoster()
    assert roster.add(ann)
    older = PeerAnnouncement(
        operator=handle,
        endpoint="https://relay-a.example:58443",
        pubkey_hex=op_pub.hex(),
        ttl_seconds=86400,
        ts=ann.ts - 100,
    )
    sign_announcement(older, op_priv_bytes)
    assert not roster.add(older), "older ts must be rejected"

    # Expiry sweep
    expired = PeerAnnouncement(
        operator=handle,
        endpoint="https://gone.example",
        pubkey_hex=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
        ttl_seconds=10,
        ts=int(time.time()) - 1000,
    )
    expired.sig_hex = "00" * 64
    roster.peers[expired.pubkey_hex] = expired
    n = roster.prune_expired()
    assert n == 1
    assert len(roster.active()) == 1  # only the still-fresh original

    # Broadcast + delete wire shapes
    bx = FedBroadcast(
        envelope_hex="00" * 64,
        routing_tag_hex="aa" * 32,
        ttl_at=int(time.time()) + 3600,
        from_pubkey_hex=op_pub.hex(),
    )
    d = bx.to_dict()
    assert d["type"] == SHROUD_FED_BROADCAST

    dl = FedDelete(routing_tag_hex="aa" * 32, message_id="msg-1", delivered_by_hex=op_pub.hex())
    d = dl.to_dict()
    assert d["type"] == SHROUD_FED_DELETE

    print("federation self-tests passed.")


if __name__ == "__main__":
    _self_test()
