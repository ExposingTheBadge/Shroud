"""
SHROUD safety numbers — per-pair identity fingerprint.

A safety number is a short, deterministic, human-readable fingerprint
of two parties' identity public keys. Two users can compare their
safety numbers out-of-band (over a phone call, in person, on a sticky
note) to confirm that the keys they each have for the other person
are the actual keys — defeating any active MITM on the relay or
network path.

This module matches the algorithm the v2.0 Windows client introduced
(per ``CHANGELOG.md``: "SHA-512 over sorted X25519 pubkeys, 30 visible
decimal digits") and ports it to every client so they all compute
byte-identical numbers for the same pair.

Design
------

  - Input: both parties' X25519 identity public keys (32 bytes each).
  - Sort the two byte strings so the safety number is the same on both
    sides regardless of which side computes it.
  - SHA-512 the concatenation along with a domain-separation tag.
  - Take the first 60 bits of the digest (5 chunks of 12 bits each →
    fits in 60 decimal digits when displayed as 5 groups of 5).
  - Wait, we display 30 digits. Six 5-digit chunks of 16-bit values
    truncated to the 0..99999 range. We pick 16-bit chunks because:
        * 16 bits per chunk × 6 chunks = 96 bits of entropy, well
          beyond the 60-80 bits that Signal et al consider adequate
          for off-band comparison.
        * 5 decimal digits per chunk is enough to encode 0..65535
          without giving up entropy in the encoding.

Final wire form: "12345 67890 13579 24680 11223 33445" — six groups
of five digits separated by spaces. Easy to read over a phone call.

Threat model
------------

A safety number guards against:

  - Server / network MITM during X3DH: an attacker swaps the
    pubkeys mid-handshake. The user's locally-stored key for Bob
    differs from Bob's actual key; their safety numbers don't match
    when compared out of band; the user detects the substitution.
  - Silent key rotation: SHROUD rotates session keys via the Double
    Ratchet, but the *identity* key is long-lived. If a peer's identity
    key changes, the safety number changes. The UI surfaces this to
    the user as a "safety number changed" prompt; they re-verify.

It does NOT guard against:

  - The OTHER PARTY being compromised. A safety number only proves
    that you and the person you think you're talking to share a key.
    If the OTHER PERSON's device is owned, the key is theirs but
    they're not really in control.

Rule compliance
---------------
  - Orthogonal to all four rules — purely a client-side fingerprint
    computation. Never sent over the wire.
"""
from __future__ import annotations

import hashlib
from typing import Tuple


SAFETY_NUMBER_GROUPS = 6
SAFETY_NUMBER_DIGITS_PER_GROUP = 5
SAFETY_NUMBER_TOTAL_DIGITS = SAFETY_NUMBER_GROUPS * SAFETY_NUMBER_DIGITS_PER_GROUP

# Domain-separation tag
SAFETY_NUMBER_TAG = b"SHROUD-SAFETY-NUMBER-v1"


def compute(my_identity_pub: bytes, their_identity_pub: bytes) -> str:
    """Deterministic 30-digit safety number for a pair of X25519 pubkeys.

    Both sides compute the same value because we sort the inputs first.
    Output is six groups of five digits separated by spaces, e.g.::

        12345 67890 13579 24680 11223 33445
    """
    if len(my_identity_pub) != 32 or len(their_identity_pub) != 32:
        raise ValueError("identity pubkeys must be 32 bytes")

    lo, hi = sorted([my_identity_pub, their_identity_pub])
    digest = hashlib.sha512(SAFETY_NUMBER_TAG + lo + hi).digest()

    groups = []
    for i in range(SAFETY_NUMBER_GROUPS):
        # Take 16 bits per group from the digest, in order
        word = (digest[i * 2] << 8) | digest[i * 2 + 1]
        groups.append(f"{word:05d}")
    return " ".join(groups)


def render_qr_payload(my_identity_pub: bytes, their_identity_pub: bytes) -> str:
    """QR-encodable string that includes the pair fingerprint *and*
    both pubkeys so the verifier can detect a key-substitution attack
    that only happens at one party.

    Wire form: ``shroud-safety://v1?lo=<hex>&hi=<hex>&n=<digits>``
    """
    lo, hi = sorted([my_identity_pub, their_identity_pub])
    digits = compute(my_identity_pub, their_identity_pub).replace(" ", "")
    return f"shroud-safety://v1?lo={lo.hex()}&hi={hi.hex()}&n={digits}"


def parse_qr_payload(qr: str) -> Tuple[bytes, bytes, str]:
    """Reverse of ``render_qr_payload``. Returns (lo_pubkey, hi_pubkey,
    digits)."""
    if not qr.startswith("shroud-safety://v1?"):
        raise ValueError("not a SHROUD safety QR")
    body = qr[len("shroud-safety://v1?"):]
    parts = dict(p.split("=", 1) for p in body.split("&"))
    return bytes.fromhex(parts["lo"]), bytes.fromhex(parts["hi"]), parts["n"]


def verify_qr_against_known(qr: str, my_pub: bytes, their_pub: bytes) -> bool:
    """Verify that a scanned QR matches the keys the local client
    already has for the pair. If it doesn't, surface a "safety number
    mismatch" warning to the user."""
    try:
        lo, hi, digits = parse_qr_payload(qr)
    except (KeyError, ValueError):
        return False
    expected_lo, expected_hi = sorted([my_pub, their_pub])
    if lo != expected_lo or hi != expected_hi:
        return False
    expected_digits = compute(my_pub, their_pub).replace(" ", "")
    return digits == expected_digits


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    alice = bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111"
    )
    bob = bytes.fromhex(
        "2222222222222222222222222222222222222222222222222222222222222222"
    )

    # Order-independent
    a_view = compute(alice, bob)
    b_view = compute(bob, alice)
    assert a_view == b_view, "safety number must be the same on both sides"

    # Format
    parts = a_view.split(" ")
    assert len(parts) == SAFETY_NUMBER_GROUPS
    for p in parts:
        assert len(p) == SAFETY_NUMBER_DIGITS_PER_GROUP
        int(p)  # must be all digits

    # Different pair = different number
    eve = bytes.fromhex(
        "3333333333333333333333333333333333333333333333333333333333333333"
    )
    assert compute(alice, eve) != a_view

    # QR round-trip
    qr = render_qr_payload(alice, bob)
    lo, hi, digits = parse_qr_payload(qr)
    assert lo == bytes.fromhex("11" * 32)
    assert hi == bytes.fromhex("22" * 32)
    assert digits == a_view.replace(" ", "")

    # Verification: matching keys = True
    assert verify_qr_against_known(qr, alice, bob)
    assert verify_qr_against_known(qr, bob, alice)
    # MITM detection: substituted key = False
    assert not verify_qr_against_known(qr, alice, eve)
    # Bad QR = False
    assert not verify_qr_against_known("not a qr", alice, bob)

    # Wrong-size keys raise
    try:
        compute(b"\x00" * 16, bob)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    print("safety_numbers self-tests passed.")


if __name__ == "__main__":
    _self_test()
