"""
SHROUD anonymous push notifications.

The problem
-----------
Mobile push is provided by Apple Push Notification service (APNs) and
Google's Firebase Cloud Messaging (FCM). Every push goes through
Apple/Google. A naive implementation tells them:

  * which user is being pushed to (via the device-specific push token),
  * who the sender is, and
  * a content snippet ("New message from Alice: ...").

That hands Apple and Google more identifying information than the
SHROUD relay itself has. All three rules broken.

Design
------
Anonymous push protocol that pairs with anon_routing:

  1. **Rotating, server-blind push tokens.** The recipient device
     obtains its APNs/FCM device token once. It then uses ``crypto.
     anon_creds`` (blind RSA) to mint a batch of *server-issued
     rendezvous tokens*. Each token is a 32-byte opaque value the
     server can verify (via the RSA signature) but cannot link to a
     device, because the issuance was blind. The recipient privately
     binds rendezvous_token -> APNs_device_token in its local state.

  2. **Push payload is opaque.** When a sender wants to wake a peer,
     they include the rendezvous_token in the sealed envelope, NOT
     in the routing tag. The recipient's pull (fetch-anon) picks the
     message up; if the device is online, it processes inline. If the
     device is offline, the relay walks its short queue of
     rendezvous_tokens that have unfetched messages and emits a single
     push containing only:

         {
           "shroud": 1,
           "rendezvous": "<random 32-byte hex>"
         }

     APNs/FCM see the rendezvous token, the device token (Apple/Google
     know which device that points to), and the literal bytes
     ``{"shroud":1,"rendezvous":...}``. They learn:
       * this device runs SHROUD,
       * something is waiting in the queue.
     They do NOT learn the sender, the content, or even how many
     messages are waiting.

  3. **Recipient redeems on wake.** On waking from push, the device
     looks up its private map ``rendezvous_token -> [device's routing
     tags to poll]`` and fetches via /api/v1/messages/fetch-anon. The
     rendezvous_token's role ends as soon as the device pulls — the
     server never gets to associate it with a real device identifier.

Why use a separate rendezvous token instead of just using routing tags
for push?
  Because Apple/Google would then see the routing tags, which is
  attack-equivalent to the relay itself having them. Rendezvous
  tokens are a single-purpose proxy that pushes notify on but cannot
  be polled with.

Wire format
-----------

Pack format for the push payload (delivered via APNs/FCM):

  {
    "shroud": 1,
    "rendezvous": "<64 hex>"
  }

The "shroud":1 sentinel lets the OS-level push handler decide whether
to even hand this off to SHROUD's wake-up service. Anything not
matching this exact shape is dropped silently.

Rule compliance
---------------
  - Rule 1: Apple/Google never see the sender. The rendezvous token is
    issued anonymously via blind RSA.
  - Rule 2: Apple/Google know the device token (they minted it) so
    they know WHICH device gets the push. We can't hide that from
    them without re-architecting the entire OS-level push system.
    But they cannot link the rendezvous token to a SHROUD identity or
    to a real-world user beyond what they already know about the device.
  - Rule 3: payload is two static keys and a random token. No content.

This is the strongest Rule-2-style story achievable while still using
the OS-provided push channel. Truly Rule-2-clean push would require
either dropping APNs/FCM entirely (and running a foreground service /
background polling, draining battery), or a third-party push relay
like UnifiedPush that the user explicitly trusts. We surface both as
options in the client settings.
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from typing import Dict, Optional


# ── Wire format ──────────────────────────────────────────────────────


SHROUD_PUSH_SENTINEL = 1
RENDEZVOUS_BYTES = 32


@dataclass
class PushPayload:
    rendezvous: str  # 64 hex chars

    def to_json(self) -> str:
        return json.dumps(
            {"shroud": SHROUD_PUSH_SENTINEL, "rendezvous": self.rendezvous},
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, blob: str) -> Optional["PushPayload"]:
        try:
            d = json.loads(blob)
        except (TypeError, ValueError):
            return None
        if d.get("shroud") != SHROUD_PUSH_SENTINEL:
            return None
        r = d.get("rendezvous")
        if not isinstance(r, str) or len(r) != 2 * RENDEZVOUS_BYTES:
            return None
        try:
            bytes.fromhex(r)
        except ValueError:
            return None
        return cls(rendezvous=r)


def generate_rendezvous() -> bytes:
    """Generate a fresh 32-byte rendezvous token (random, unguessable)."""
    return secrets.token_bytes(RENDEZVOUS_BYTES)


# ── Recipient-side rendezvous registry ───────────────────────────────


@dataclass
class RendezvousEntry:
    rendezvous_hex: str
    routing_tags_hex: list[str]  # tags the recipient should poll on wake
    issued_at: float
    used_at: Optional[float] = None


class RendezvousRegistry:
    """Recipient-side map of rendezvous_token -> the routing tags to poll
    when a push notification with that token arrives.

    A given rendezvous token MUST be used at most once. After redemption
    the recipient publishes the next batch of fresh tokens to the relay
    via the anon-creds protocol."""

    def __init__(self) -> None:
        self._entries: Dict[str, RendezvousEntry] = {}

    def register(self, rendezvous: bytes, routing_tags: list[bytes]) -> None:
        h = rendezvous.hex()
        if h in self._entries:
            raise ValueError("rendezvous already registered")
        self._entries[h] = RendezvousEntry(
            rendezvous_hex=h,
            routing_tags_hex=[t.hex() for t in routing_tags],
            issued_at=__import__("time").time(),
        )

    def consume(self, push: PushPayload) -> Optional[list[str]]:
        """On waking from a push, look up the rendezvous and return the
        list of routing tags to poll. Marks the entry used; returns
        None on unknown or already-used tokens."""
        entry = self._entries.get(push.rendezvous)
        if entry is None or entry.used_at is not None:
            return None
        entry.used_at = __import__("time").time()
        return list(entry.routing_tags_hex)

    def purge_expired(self, max_age_seconds: float = 86400) -> int:
        """Delete entries older than ``max_age_seconds``. Returns count
        removed. Prevents the registry from growing without bound and
        bounds the window in which a leaked rendezvous can be used."""
        import time as _time
        cutoff = _time.time() - max_age_seconds
        removed = [h for h, e in self._entries.items() if e.issued_at < cutoff]
        for h in removed:
            del self._entries[h]
        return len(removed)


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # PushPayload encode / decode
    r = generate_rendezvous()
    p = PushPayload(rendezvous=r.hex())
    blob = p.to_json()
    parsed = PushPayload.from_json(blob)
    assert parsed is not None and parsed.rendezvous == p.rendezvous

    # Reject garbage
    assert PushPayload.from_json("not json") is None
    assert PushPayload.from_json("{}") is None
    assert PushPayload.from_json('{"shroud":1}') is None
    assert PushPayload.from_json('{"shroud":1,"rendezvous":"xyz"}') is None  # bad hex
    assert PushPayload.from_json('{"shroud":2,"rendezvous":"' + "00" * 32 + '"}') is None  # wrong sentinel

    # Registry round trip
    reg = RendezvousRegistry()
    tag1 = os.urandom(32)
    tag2 = os.urandom(32)
    reg.register(r, [tag1, tag2])
    out = reg.consume(PushPayload(rendezvous=r.hex()))
    assert out == [tag1.hex(), tag2.hex()], out

    # Second consume on same rendezvous returns None (single-use)
    assert reg.consume(PushPayload(rendezvous=r.hex())) is None

    # Unknown rendezvous returns None
    other = generate_rendezvous()
    assert reg.consume(PushPayload(rendezvous=other.hex())) is None

    # Purge expired (force by making issued_at old)
    reg2 = RendezvousRegistry()
    r2 = generate_rendezvous()
    reg2.register(r2, [tag1])
    import time as _t
    reg2._entries[r2.hex()].issued_at = _t.time() - 100000
    assert reg2.purge_expired(max_age_seconds=86400) == 1

    print("anon_push self-tests passed.")


if __name__ == "__main__":
    _self_test()
