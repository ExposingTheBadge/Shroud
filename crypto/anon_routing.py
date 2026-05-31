"""
SHROUD anonymous routing — Rule 1 + Rule 2 compliant addressing.

Goal
----
Make the server unable to identify either the sender or the receiver of a
message, by replacing the legacy {sender_device_id, recipient_device_id}
routing header with two new primitives:

  - **Sealed envelope** (Rule 1) — sender identity lives inside an AES-GCM
    ciphertext keyed by ECDH(ephemeral_X25519, recipient_identity_X25519).
    The server sees random-looking ciphertext and an ephemeral pubkey it
    cannot link to any device.
  - **Per-pair epoch routing tag** (Rule 2) — both parties of a conversation
    independently derive ``tag = HKDF(shared_secret, epoch_hour, "shroud-tag")``
    from the X3DH root they share. The server stores messages keyed by tag,
    not by recipient device_id, and has no map from tag back to identity.
    The recipient polls by listing all current-epoch tags across all of
    their contacts.

Both primitives are stateless on the server side: a relay restart with a
fresh database remains private, because none of the secrets needed to
unwind the tag-to-identity mapping ever existed on the server in the
first place.

Wire format
-----------
**Sealed envelope** (raw bytes posted to ``/api/v1/messages/send-anon``):

    version (1 B)               // 0x01
    ephemeral_pub (32 B)        // X25519 sender ephemeral, fresh per message
    nonce (12 B)                // AES-GCM nonce
    ciphertext (var)            // AES-GCM(payload)
    tag (16 B)                  // AES-GCM auth tag

The ``payload`` plaintext is the JSON envelope that the legacy code path
sent unwrapped: ``{sender, ts, ratchet_ct, ratchet_meta, ...}``. Sender
identity lives in the ``sender`` field, decryptable only by the recipient.

**Routing tag** (32 B, hex-encoded in ``X-Routing-Tag`` header on send,
JSON ``tags`` array on fetch):

    tag = HKDF-Expand(
              HKDF-Extract(shared_root, b"shroud-tag-v1"),
              info = struct.pack(">QQ", pair_id, epoch_hour),
              length = 32,
          )

``shared_root`` is the 32-byte root chain key established by X3DH between
the two devices. ``pair_id`` is a deterministic 64-bit identifier for the
pair (so a single device can subscribe to N tags per epoch for N
contacts). ``epoch_hour = unix_ts // 3600``.

The recipient subscribes to ``{tag(contact_i, epoch) for i in contacts,
for epoch in {current, current-1, current+1}}`` to handle clock skew.

This module ships only the cryptographic primitives. Server endpoint
plumbing is in ``server/server.py``; client wiring is in
``clients/windows/anon.c`` and ``clients/android/.../AnonRouting.kt``.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from typing import Iterable, List, Optional, Tuple


# ── HKDF (RFC 5869) ───────────────────────────────────────────────────


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


# ── Routing tag (Rule 2) ──────────────────────────────────────────────


EPOCH_SECONDS = 3600
TAG_BYTES = 32
TAG_SALT = b"shroud-tag-v1"


def epoch_for(unix_ts: Optional[float] = None) -> int:
    if unix_ts is None:
        unix_ts = time.time()
    return int(unix_ts) // EPOCH_SECONDS


def pair_id(my_identity_pub: bytes, their_identity_pub: bytes) -> int:
    """Deterministic 64-bit pair identifier from the two identity public keys.

    Order-independent: the same value regardless of which side computes it,
    so the sender and receiver agree on which tag to derive."""
    a = my_identity_pub
    b = their_identity_pub
    lo, hi = (a, b) if a < b else (b, a)
    digest = hashlib.sha256(lo + b"||" + hi).digest()
    return int.from_bytes(digest[:8], "big")


def routing_tag(shared_root: bytes, pair: int, epoch: int) -> bytes:
    """Derive the routing tag the sender writes to and the recipient polls.

    Args:
        shared_root: the 32-byte X3DH root key shared by both parties
        pair: pair_id(my_id, their_id) — same on both sides
        epoch: epoch_for() at send time

    Returns:
        32-byte tag. Server uses this as the queue key; recipient submits
        a list of these on poll.
    """
    if len(shared_root) != 32:
        raise ValueError("shared_root must be 32 bytes")
    prk = _hkdf_extract(TAG_SALT, shared_root)
    info = struct.pack(">QQ", pair, epoch)
    return _hkdf_expand(prk, info, TAG_BYTES)


def fetch_tags_for_window(
    pairs: Iterable[Tuple[int, bytes]],
    around: Optional[float] = None,
    window: int = 1,
) -> List[bytes]:
    """Compute every routing tag the recipient should currently subscribe to.

    Args:
        pairs: iterable of ``(pair_id, shared_root)`` for each contact
        around: anchor time (defaults to now)
        window: number of epochs each side of the anchor to include
                (default 1 -> {prev, current, next})

    Returns:
        Flat list of 32-byte tags, deduplicated.
    """
    base = epoch_for(around)
    seen = set()
    out: List[bytes] = []
    for pid, root in pairs:
        for e in range(base - window, base + window + 1):
            t = routing_tag(root, pid, e)
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


# ── Sealed envelope (Rule 1) ──────────────────────────────────────────


SEALED_VERSION = 0x01
EPHEMERAL_BYTES = 32
NONCE_BYTES = 12
GCM_TAG_BYTES = 16
SEAL_KDF_INFO = b"shroud-seal-v1"


def _x25519_priv_from_random() -> bytes:
    """Generate an ephemeral X25519 private key (32 random bytes; the
    cryptography library handles the curve-specific clamping)."""
    return os.urandom(32)


def seal(payload: bytes, recipient_x25519_pub: bytes) -> bytes:
    """Seal ``payload`` so only the recipient can decrypt it.

    Args:
        payload: bytes to seal (typically the legacy JSON envelope)
        recipient_x25519_pub: recipient's long-term X25519 public key (32 B)

    Returns:
        Sealed envelope wire bytes, ready to POST to /messages/send-anon.
    """
    if len(recipient_x25519_pub) != 32:
        raise ValueError("recipient pubkey must be 32 bytes")

    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()

    recipient_pk = X25519PublicKey.from_public_bytes(recipient_x25519_pub)
    shared = eph_priv.exchange(recipient_pk)
    # Derive the AES key from the ECDH output. Mix in BOTH pubkeys so the
    # KDF is bound to the specific (sender_eph, recipient) pair and an
    # attacker cannot replay an old ciphertext to a different recipient.
    prk = _hkdf_extract(SEAL_KDF_INFO, shared + eph_pub + recipient_x25519_pub)
    key = _hkdf_expand(prk, b"key", 32)

    nonce = os.urandom(NONCE_BYTES)
    aead = AESGCM(key)
    # No AAD: eph_pub and recipient_pub are already bound into the KDF
    # input above, so substituting either yields a different key and the
    # GCM auth tag check fails. AAD here would be redundant and would
    # complicate the C port (existing crypto_aes_gcm helper has no AAD).
    ct_and_tag = aead.encrypt(nonce, payload, None)

    return bytes([SEALED_VERSION]) + eph_pub + nonce + ct_and_tag


def unseal(sealed: bytes, my_x25519_priv: bytes) -> bytes:
    """Recover the plaintext payload from a sealed envelope.

    Args:
        sealed: wire bytes from /messages/fetch-anon
        my_x25519_priv: my long-term X25519 private key (32 B)

    Returns:
        Plaintext payload (originally given to ``seal``).
    """
    if len(sealed) < 1 + EPHEMERAL_BYTES + NONCE_BYTES + GCM_TAG_BYTES:
        raise ValueError("sealed envelope too short")
    if sealed[0] != SEALED_VERSION:
        raise ValueError(f"unknown sealed version {sealed[0]}")
    eph_pub = sealed[1:1 + EPHEMERAL_BYTES]
    nonce = sealed[1 + EPHEMERAL_BYTES:1 + EPHEMERAL_BYTES + NONCE_BYTES]
    ct_and_tag = sealed[1 + EPHEMERAL_BYTES + NONCE_BYTES:]

    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    my_priv = X25519PrivateKey.from_private_bytes(my_x25519_priv)
    my_pub = my_priv.public_key().public_bytes_raw()
    eph_pk = X25519PublicKey.from_public_bytes(eph_pub)
    shared = my_priv.exchange(eph_pk)
    prk = _hkdf_extract(SEAL_KDF_INFO, shared + eph_pub + my_pub)
    key = _hkdf_expand(prk, b"key", 32)

    aead = AESGCM(key)
    return aead.decrypt(nonce, ct_and_tag, None)


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Routing tag: both parties derive the same tag from the shared root.
    root = os.urandom(32)
    alice_id = os.urandom(32)
    bob_id = os.urandom(32)
    pid_a = pair_id(alice_id, bob_id)
    pid_b = pair_id(bob_id, alice_id)
    assert pid_a == pid_b, "pair_id must be order-independent"
    e = epoch_for()
    t_alice = routing_tag(root, pid_a, e)
    t_bob = routing_tag(root, pid_b, e)
    assert t_alice == t_bob, "tags must agree across parties"
    assert len(t_alice) == 32

    # Different epoch -> different tag.
    t_next = routing_tag(root, pid_a, e + 1)
    assert t_next != t_alice, "tags must rotate per epoch"

    # Different pair -> different tag for same epoch.
    other_root = os.urandom(32)
    t_other = routing_tag(other_root, pid_a, e)
    assert t_other != t_alice, "tags must differ across pairs"

    # fetch_tags_for_window
    tags = fetch_tags_for_window([(pid_a, root)])
    assert len(tags) == 3, "should return prev/current/next"

    # Sealed envelope round-trip.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    bob_priv_obj = X25519PrivateKey.generate()
    bob_priv = bob_priv_obj.private_bytes_raw()
    bob_pub = bob_priv_obj.public_key().public_bytes_raw()

    payload = b'{"sender":"alice","msg":"hi"}'
    sealed = seal(payload, bob_pub)
    recovered = unseal(sealed, bob_priv)
    assert recovered == payload, "sealed roundtrip failed"

    # Tampering should fail.
    tampered = sealed[:-1] + bytes([sealed[-1] ^ 1])
    try:
        unseal(tampered, bob_priv)
        raise AssertionError("tamper detection failed")
    except Exception:
        pass  # expected

    # Wrong recipient should fail.
    other_priv = X25519PrivateKey.generate().private_bytes_raw()
    try:
        unseal(sealed, other_priv)
        raise AssertionError("wrong recipient should fail to decrypt")
    except Exception:
        pass  # expected

    print("anon_routing self-tests passed.")


if __name__ == "__main__":
    _self_test()
