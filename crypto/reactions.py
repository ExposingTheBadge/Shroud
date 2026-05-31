"""
SHROUD message reactions — emoji reactions to specific messages.

Reactions ride the standard sealed envelope, just like any other
SHROUD message. A reaction references a *parent* message by its
``message_id`` (the sender's local ID, which is also the value the
sender included in the outgoing envelope so the recipient can match).

The wire payload is tiny — a few bytes for the emoji + the parent ID —
so reactions cost nothing to ship and inherit Rule 1 + Rule 2 from
the underlying anon_routing layer.

Wire format (inside a sealed envelope)
--------------------------------------

::

    {
      "type":          "shroud.message.reaction",
      "parent_id":     "<sender-local message id, hex>",
      "action":        "add" | "remove",
      "emoji":         "👍" | "❤️" | ... (Unicode codepoint(s))
      "ts":            <unix sec>
    }

Recipients aggregate reactions per-parent into a count + the list of
reactors. The relay sees only the sealed envelope.

Rule compliance
---------------
  - Rule 1+2: standard sealed envelope routing.
  - Rule 3: emoji is itself a Unicode character — no metadata. We
    cap emoji length at 16 bytes to refuse weird zalgo-style abuse
    that could embed identifiers in combining characters.

Module surface
--------------
  build_reaction(parent_id, emoji, action="add") -> bytes payload
  parse_reaction(blob) -> Reaction or None
  ReactionLedger — local aggregator for received reactions
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


SHROUD_REACTION = "shroud.message.reaction"
EMOJI_BYTE_CAP = 16  # bounded so multi-codepoint shenanigans can't grow unbounded


@dataclass
class Reaction:
    parent_id: str
    action: str       # "add" or "remove"
    emoji: str
    ts: int
    # Sender pubkey is NOT inside the payload — it's recovered from the
    # sealed envelope's sender field by the unsealer and supplied
    # externally to ReactionLedger.apply().


def build_reaction(parent_id: str, emoji: str, action: str = "add",
                   ts: Optional[int] = None) -> bytes:
    if action not in ("add", "remove"):
        raise ValueError(f"bad action: {action}")
    if not emoji or len(emoji.encode("utf-8")) > EMOJI_BYTE_CAP:
        raise ValueError(f"emoji must be 1..{EMOJI_BYTE_CAP} UTF-8 bytes")
    if not parent_id or len(parent_id) > 128:
        raise ValueError("parent_id missing or too long")
    payload = {
        "type":      SHROUD_REACTION,
        "parent_id": parent_id,
        "action":    action,
        "emoji":     emoji,
        "ts":        int(ts if ts is not None else time.time()),
    }
    return json.dumps(payload, sort_keys=True).encode()


def parse_reaction(blob: bytes) -> Optional[Reaction]:
    try:
        d = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if d.get("type") != SHROUD_REACTION:
        return None
    try:
        return Reaction(
            parent_id=d["parent_id"],
            action=d.get("action", "add"),
            emoji=d["emoji"],
            ts=int(d.get("ts", 0)),
        )
    except (KeyError, TypeError, ValueError):
        return None


# ── Aggregator (recipient-side) ──────────────────────────────────────


@dataclass
class ReactionSummary:
    emoji: str
    reactor_pubkey_hexes: Set[str] = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.reactor_pubkey_hexes)


class ReactionLedger:
    """Per-conversation aggregator. Apply reactions in arrival order;
    queries return the current state per-parent.

    The ledger is duplicate-tolerant (idempotent "add" + matching
    "remove" leave the state empty) and order-insensitive within a
    same-emoji burst from the same reactor.
    """

    def __init__(self) -> None:
        # parent_id -> emoji -> ReactionSummary
        self._by_parent: Dict[str, Dict[str, ReactionSummary]] = {}

    def apply(self, reaction: Reaction, reactor_pubkey_hex: str) -> None:
        if not reactor_pubkey_hex:
            return
        bucket = self._by_parent.setdefault(reaction.parent_id, {})
        summary = bucket.setdefault(reaction.emoji, ReactionSummary(emoji=reaction.emoji))
        if reaction.action == "add":
            summary.reactor_pubkey_hexes.add(reactor_pubkey_hex)
        elif reaction.action == "remove":
            summary.reactor_pubkey_hexes.discard(reactor_pubkey_hex)
        # Tidy up empty entries
        if not summary.reactor_pubkey_hexes:
            del bucket[reaction.emoji]
        if not bucket:
            del self._by_parent[reaction.parent_id]

    def for_parent(self, parent_id: str) -> List[ReactionSummary]:
        bucket = self._by_parent.get(parent_id, {})
        return sorted(bucket.values(), key=lambda s: (-s.count, s.emoji))


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    pid = "msg-0123456789abcdef"

    blob = build_reaction(pid, "👍")
    r = parse_reaction(blob)
    assert r is not None and r.parent_id == pid and r.emoji == "👍" and r.action == "add"

    # Refuses oversized emoji (zalgo bomb)
    try:
        build_reaction(pid, "👍" * 20)
        raise AssertionError("oversized emoji should fail")
    except ValueError:
        pass

    # Ledger applies idempotently
    ledger = ReactionLedger()
    alice_pk = "a" * 64
    bob_pk = "b" * 64

    ledger.apply(r, alice_pk)
    ledger.apply(r, alice_pk)   # dup add from same reactor
    ledger.apply(parse_reaction(build_reaction(pid, "👍")), bob_pk)
    summary = ledger.for_parent(pid)
    assert len(summary) == 1
    assert summary[0].emoji == "👍"
    assert summary[0].count == 2
    assert summary[0].reactor_pubkey_hexes == {alice_pk, bob_pk}

    # Add a different emoji, ranking moves
    ledger.apply(parse_reaction(build_reaction(pid, "❤️")), alice_pk)
    summary = ledger.for_parent(pid)
    assert len(summary) == 2
    assert summary[0].count >= summary[1].count   # sorted by count desc

    # Remove
    ledger.apply(parse_reaction(build_reaction(pid, "👍", action="remove")), alice_pk)
    summary = ledger.for_parent(pid)
    thumbs = [s for s in summary if s.emoji == "👍"][0]
    assert thumbs.count == 1
    assert alice_pk not in thumbs.reactor_pubkey_hexes

    # Remove the rest, parent disappears
    ledger.apply(parse_reaction(build_reaction(pid, "👍", action="remove")), bob_pk)
    ledger.apply(parse_reaction(build_reaction(pid, "❤️", action="remove")), alice_pk)
    assert ledger.for_parent(pid) == []

    print("reactions self-tests passed.")


if __name__ == "__main__":
    _self_test()
