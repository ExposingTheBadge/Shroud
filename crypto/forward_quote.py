"""
SHROUD message forwarding + quoting.

Forwarding
----------
Take a message you received from Alice and send it to Carol. Carol's
client renders it as "Forwarded from <alice's_display_name>" with the
original body.

The forwarded payload includes:

  - The original message body
  - The original sender's display name (NOT their identity pubkey — we
    don't want to leak the social graph beyond Alice -> me -> Carol)
  - A ``forwarded: true`` flag so Carol's UI can distinguish a forward
    from an original

Forwarding does NOT carry the original sender's signature. Carol
trusts that *I* forwarded it; she does not get to verify it was
originally from Alice. This is the intentional design choice — full
attribution chains would build a long-lived correlation graph across
conversations. The Signal-style "forwarded once removed" pattern is
preferable for privacy.

Quoting
-------
Reference an earlier message in the same conversation by including a
short excerpt and the original message_id. Receivers can scroll to
the original or just see the inline preview.

Wire formats
------------

Forward payload:
::

    {
      "type":              "shroud.message.forward",
      "body":              "<original message text>",
      "from_display_name": "<original sender display name>",
      "original_ts":       <unix sec of original message>,
      "ts":                <unix sec of this forward>
    }

Quote payload:
::

    {
      "type":              "shroud.message.quote",
      "body":              "<this user's reply text>",
      "quote_excerpt":     "<short snippet of original, <= 200 chars>",
      "quote_message_id":  "<original message id>",
      "quote_author":      "<display name of original author>",
      "ts":                <unix sec>
    }

Rule compliance
---------------
  - Rule 1+2: standard sealed envelope.
  - Rule 3: display name is whatever the user picked (often pseudonymous);
    no PII added beyond what the user already discloses in their handle.
    Quote excerpts capped at 200 chars to bound the leakage if a future
    feature lets recipients reverse-search excerpts against a corpus.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional


SHROUD_FORWARD = "shroud.message.forward"
SHROUD_QUOTE   = "shroud.message.quote"

QUOTE_EXCERPT_MAX_CHARS = 200


# ── Wire types ───────────────────────────────────────────────────────


@dataclass
class ForwardedMessage:
    body: str
    from_display_name: str
    original_ts: int
    ts: int


@dataclass
class QuotedMessage:
    body: str               # my reply
    quote_excerpt: str      # short snippet of what I'm quoting
    quote_message_id: str   # id of the original I'm quoting
    quote_author: str       # display name of original author
    ts: int


# ── Build ────────────────────────────────────────────────────────────


def build_forward(body: str, from_display_name: str,
                  original_ts: int, ts: Optional[int] = None) -> bytes:
    if not body:
        raise ValueError("forward body cannot be empty")
    payload = {
        "type": SHROUD_FORWARD,
        "body": body,
        "from_display_name": from_display_name or "",
        "original_ts": int(original_ts),
        "ts": int(ts if ts is not None else time.time()),
    }
    return json.dumps(payload, sort_keys=True).encode()


def build_quote(reply_body: str, quote_excerpt: str,
                quote_message_id: str, quote_author: str = "",
                ts: Optional[int] = None) -> bytes:
    if not reply_body:
        raise ValueError("quote reply cannot be empty")
    if not quote_message_id:
        raise ValueError("quote_message_id required")
    excerpt = quote_excerpt or ""
    if len(excerpt) > QUOTE_EXCERPT_MAX_CHARS:
        excerpt = excerpt[: QUOTE_EXCERPT_MAX_CHARS - 1] + "…"
    payload = {
        "type": SHROUD_QUOTE,
        "body": reply_body,
        "quote_excerpt": excerpt,
        "quote_message_id": quote_message_id,
        "quote_author": quote_author or "",
        "ts": int(ts if ts is not None else time.time()),
    }
    return json.dumps(payload, sort_keys=True).encode()


# ── Parse ────────────────────────────────────────────────────────────


def parse(blob: bytes):
    try:
        d = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    t = d.get("type")
    try:
        if t == SHROUD_FORWARD:
            return ForwardedMessage(
                body=d["body"],
                from_display_name=d.get("from_display_name", ""),
                original_ts=int(d.get("original_ts", 0)),
                ts=int(d.get("ts", 0)),
            )
        if t == SHROUD_QUOTE:
            return QuotedMessage(
                body=d["body"],
                quote_excerpt=d.get("quote_excerpt", ""),
                quote_message_id=d["quote_message_id"],
                quote_author=d.get("quote_author", ""),
                ts=int(d.get("ts", 0)),
            )
    except (KeyError, TypeError, ValueError):
        return None
    return None


# ── Excerpt helper ───────────────────────────────────────────────────


def make_excerpt(original_body: str) -> str:
    """Strip leading whitespace, collapse runs of whitespace to one
    space, truncate to QUOTE_EXCERPT_MAX_CHARS with an ellipsis."""
    import re
    s = re.sub(r"\s+", " ", original_body).strip()
    if len(s) > QUOTE_EXCERPT_MAX_CHARS:
        s = s[: QUOTE_EXCERPT_MAX_CHARS - 1] + "…"
    return s


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Forward
    blob = build_forward("hi from alice", "Alice", original_ts=1700000000)
    parsed = parse(blob)
    assert isinstance(parsed, ForwardedMessage)
    assert parsed.body == "hi from alice"
    assert parsed.from_display_name == "Alice"
    assert parsed.original_ts == 1700000000

    # Quote
    blob = build_quote("agreed", "Should we ship this Tuesday?", "msg-7",
                       quote_author="Bob")
    parsed = parse(blob)
    assert isinstance(parsed, QuotedMessage)
    assert parsed.body == "agreed"
    assert parsed.quote_excerpt == "Should we ship this Tuesday?"
    assert parsed.quote_message_id == "msg-7"
    assert parsed.quote_author == "Bob"

    # Long quote excerpt truncates
    long_body = "x" * 1000
    blob = build_quote("ok", long_body, "msg-x")
    parsed = parse(blob)
    assert len(parsed.quote_excerpt) <= QUOTE_EXCERPT_MAX_CHARS
    assert parsed.quote_excerpt.endswith("…")

    # make_excerpt collapses whitespace
    assert make_excerpt("hello\n  world  ") == "hello world"
    assert make_excerpt("y" * 500).endswith("…")

    # Validation
    try:
        build_forward("", "Alice", 0)
        raise AssertionError("empty body should raise")
    except ValueError:
        pass
    try:
        build_quote("hi", "x", "")
        raise AssertionError("missing message_id should raise")
    except ValueError:
        pass

    print("forward_quote self-tests passed.")


if __name__ == "__main__":
    _self_test()
