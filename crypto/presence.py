"""
SHROUD presence signals — read receipts + typing indicators.

These are *ephemeral*: opt-in, opt-out per-chat, never persisted, ride
the standard sealed envelope. The server has no idea any of this is
happening — to the server it's just another anon message.

What's here
-----------

  - Read receipts: when a recipient finishes rendering a message, they
    optionally send back a tiny ``shroud.presence.read`` payload to
    the sender. The sender's UI shows a "seen" indicator next to the
    original message.
  - Typing indicators: while the user is typing, the client emits one
    ``shroud.presence.typing`` payload every ``TYPING_HEARTBEAT_S`` to
    each recipient in the active chat. Receivers expire the indicator
    after ``TYPING_TIMEOUT_S`` if they don't get a refresh.

Both are entirely optional. The receiver who doesn't want to leak read-
state simply doesn't emit receipts. The sender who doesn't trust
typing-state doesn't render the indicators. They negotiate via the
client's local UI settings — never via a wire flag.

Wire format
-----------

Read receipt:
::

    {
      "type":      "shroud.presence.read",
      "for_message_id": "<sender-local id>",
      "ts":        <unix sec>
    }

Typing indicator:
::

    {
      "type":     "shroud.presence.typing",
      "chat_id":  "<opaque sender-chosen id>",   // e.g. recipient pubkey
      "until":    <unix sec; expires at this time>,
      "ts":       <unix sec>
    }

Rule compliance
---------------
  - Rule 1+2: standard sealed envelope.
  - Rule 3: a read receipt leaks "I read message X" to the sender —
    that's intentional and the user opts in. No third party (not the
    relay, not Apple/Google) sees it.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional


SHROUD_READ   = "shroud.presence.read"
SHROUD_TYPING = "shroud.presence.typing"

TYPING_HEARTBEAT_S = 4    # emit one indicator every N seconds while typing
TYPING_TIMEOUT_S   = 10   # expire indicator if not refreshed within N seconds


# ── Wire types ───────────────────────────────────────────────────────


@dataclass
class ReadReceipt:
    for_message_id: str
    ts: int


@dataclass
class TypingIndicator:
    chat_id: str
    until: int
    ts: int


def build_read_receipt(message_id: str, ts: Optional[int] = None) -> bytes:
    return json.dumps({
        "type": SHROUD_READ,
        "for_message_id": message_id,
        "ts": int(ts if ts is not None else time.time()),
    }, sort_keys=True).encode()


def build_typing(chat_id: str, ts: Optional[int] = None,
                 timeout_s: int = TYPING_TIMEOUT_S) -> bytes:
    now = int(ts if ts is not None else time.time())
    return json.dumps({
        "type": SHROUD_TYPING,
        "chat_id": chat_id,
        "until": now + timeout_s,
        "ts": now,
    }, sort_keys=True).encode()


def parse(blob: bytes):
    try:
        d = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    t = d.get("type")
    try:
        if t == SHROUD_READ:
            return ReadReceipt(
                for_message_id=d["for_message_id"],
                ts=int(d.get("ts", 0)),
            )
        if t == SHROUD_TYPING:
            return TypingIndicator(
                chat_id=d["chat_id"],
                until=int(d.get("until", 0)),
                ts=int(d.get("ts", 0)),
            )
    except (KeyError, TypeError, ValueError):
        return None
    return None


# ── Typing-state tracker ─────────────────────────────────────────────


class TypingState:
    """In-memory map of chat_id -> until_ts. Expired indicators are
    pruned on access so UI queries always return live state.

    Usage::

        state = TypingState()
        # On incoming typing indicator
        state.on_indicator(parsed)
        # In UI tick (60 fps or whatever)
        for chat_id in state.active():
            ui.show_typing_dots(chat_id)
    """

    def __init__(self) -> None:
        self._until: dict[str, int] = {}

    def on_indicator(self, ind: TypingIndicator) -> None:
        # Don't store an indicator that's already expired
        if ind.until <= int(time.time()):
            return
        # Update only if newer than what we have
        existing = self._until.get(ind.chat_id, 0)
        if ind.until > existing:
            self._until[ind.chat_id] = ind.until

    def active(self, now: Optional[int] = None) -> list[str]:
        t = int(now if now is not None else time.time())
        expired = [k for k, until in self._until.items() if until <= t]
        for k in expired:
            del self._until[k]
        return list(self._until.keys())

    def clear(self, chat_id: str) -> None:
        self._until.pop(chat_id, None)


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Read receipt round-trip
    blob = build_read_receipt("msg-abc")
    r = parse(blob)
    assert isinstance(r, ReadReceipt)
    assert r.for_message_id == "msg-abc"

    # Typing indicator round-trip
    blob = build_typing("chat-xyz")
    t = parse(blob)
    assert isinstance(t, TypingIndicator)
    assert t.chat_id == "chat-xyz"
    assert t.until > t.ts

    # Tracker: active works + expiry prunes
    state = TypingState()
    state.on_indicator(t)
    assert state.active() == ["chat-xyz"]
    # Simulate time after expiry
    assert state.active(now=t.until + 1) == []
    # After expiry the entry is gone
    assert state.active() == []

    # Newer indicator extends, older indicator ignored
    state.on_indicator(parse(build_typing("c2", timeout_s=10)))
    short = parse(build_typing("c2", timeout_s=2))
    state.on_indicator(short)
    # Should still be the 10s one, not the 2s one
    active = state.active(now=t.ts + 5)
    assert active == ["c2"]

    # Bad input doesn't crash
    assert parse(b"not json") is None
    assert parse(b'{"type":"other"}') is None

    print("presence self-tests passed.")


if __name__ == "__main__":
    _self_test()
