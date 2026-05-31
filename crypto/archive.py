"""
SHROUD conversation archive.

A conversation is "archived" when the user wants to keep its history
but doesn't want it cluttering the active chat list or generating
notifications. The conversation continues to receive messages — new
ones just land silently and the chat moves to the archived view.

This is purely a local UI helper. The relay doesn't know what
conversations are archived; routing tags continue to be polled for
both archived and active conversations.

Schema
------

::

    CREATE TABLE conversation_state (
        contact_pubkey_hex TEXT PRIMARY KEY,
        archived           INTEGER NOT NULL DEFAULT 0,
        muted_until        INTEGER,            -- unix sec
        pinned             INTEGER NOT NULL DEFAULT 0,
        last_active_ts     INTEGER NOT NULL,
        unread_count       INTEGER NOT NULL DEFAULT 0
    );

Caller manages the surrounding ``messages`` and ``contacts`` tables.

Why per-state rows
------------------

We could store archive flags as columns on the contacts table, but
keeping them in a separate ``conversation_state`` table makes it easy
to:

  - clear all archived flags in one statement (e.g., after a "show
    archived" toggle)
  - join with messages for fast unread counters without recomputing
  - migrate the UI feature without touching the identity / contact
    schema

Rule compliance
---------------
Orthogonal — purely local.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import List, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS conversation_state (
    contact_pubkey_hex TEXT PRIMARY KEY,
    archived           INTEGER NOT NULL DEFAULT 0,
    muted_until        INTEGER,
    pinned             INTEGER NOT NULL DEFAULT 0,
    last_active_ts     INTEGER NOT NULL DEFAULT 0,
    unread_count       INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass
class ConversationState:
    contact_pubkey_hex: str
    archived: bool
    muted_until: Optional[int]
    pinned: bool
    last_active_ts: int
    unread_count: int


class ConversationStore:
    """SQLite-backed conversation state. Caller-owned connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        conn.executescript(SCHEMA)
        conn.commit()

    def ensure(self, contact_pubkey_hex: str) -> None:
        """Insert a default state row if none exists."""
        self.conn.execute(
            "INSERT OR IGNORE INTO conversation_state "
            "(contact_pubkey_hex, last_active_ts) VALUES (?,?)",
            (contact_pubkey_hex, int(time.time())),
        )
        self.conn.commit()

    def archive(self, contact_pubkey_hex: str) -> None:
        self.ensure(contact_pubkey_hex)
        self.conn.execute(
            "UPDATE conversation_state SET archived = 1, pinned = 0 "
            "WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        )
        self.conn.commit()

    def unarchive(self, contact_pubkey_hex: str) -> None:
        self.ensure(contact_pubkey_hex)
        self.conn.execute(
            "UPDATE conversation_state SET archived = 0 "
            "WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        )
        self.conn.commit()

    def pin(self, contact_pubkey_hex: str) -> None:
        self.ensure(contact_pubkey_hex)
        self.conn.execute(
            "UPDATE conversation_state SET pinned = 1, archived = 0 "
            "WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        )
        self.conn.commit()

    def unpin(self, contact_pubkey_hex: str) -> None:
        self.ensure(contact_pubkey_hex)
        self.conn.execute(
            "UPDATE conversation_state SET pinned = 0 "
            "WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        )
        self.conn.commit()

    def mute(self, contact_pubkey_hex: str, until_ts: int) -> None:
        self.ensure(contact_pubkey_hex)
        self.conn.execute(
            "UPDATE conversation_state SET muted_until = ? "
            "WHERE contact_pubkey_hex = ?",
            (until_ts, contact_pubkey_hex),
        )
        self.conn.commit()

    def unmute(self, contact_pubkey_hex: str) -> None:
        self.ensure(contact_pubkey_hex)
        self.conn.execute(
            "UPDATE conversation_state SET muted_until = NULL "
            "WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        )
        self.conn.commit()

    def is_muted(self, contact_pubkey_hex: str, now: Optional[int] = None) -> bool:
        t = int(now if now is not None else time.time())
        row = self.conn.execute(
            "SELECT muted_until FROM conversation_state WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        ).fetchone()
        if row is None or row[0] is None:
            return False
        return row[0] > t

    def on_incoming(self, contact_pubkey_hex: str, ts: int) -> None:
        """Called when a message arrives. Bumps last_active_ts and
        unread_count. Unarchive-on-incoming is *not* done by default —
        archived conversations stay archived but rise to the top of
        the archived list."""
        self.ensure(contact_pubkey_hex)
        self.conn.execute(
            "UPDATE conversation_state "
            "SET last_active_ts = ?, unread_count = unread_count + 1 "
            "WHERE contact_pubkey_hex = ?",
            (ts, contact_pubkey_hex),
        )
        self.conn.commit()

    def mark_read(self, contact_pubkey_hex: str) -> None:
        self.conn.execute(
            "UPDATE conversation_state SET unread_count = 0 "
            "WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        )
        self.conn.commit()

    def get(self, contact_pubkey_hex: str) -> Optional[ConversationState]:
        row = self.conn.execute(
            "SELECT contact_pubkey_hex, archived, muted_until, pinned, "
            "last_active_ts, unread_count FROM conversation_state "
            "WHERE contact_pubkey_hex = ?",
            (contact_pubkey_hex,),
        ).fetchone()
        if row is None:
            return None
        return ConversationState(
            contact_pubkey_hex=row[0],
            archived=bool(row[1]),
            muted_until=row[2],
            pinned=bool(row[3]),
            last_active_ts=row[4],
            unread_count=row[5],
        )

    def list_active(self) -> List[ConversationState]:
        """Pinned first, then by last_active_ts desc. Excludes archived."""
        rows = self.conn.execute(
            "SELECT contact_pubkey_hex, archived, muted_until, pinned, "
            "last_active_ts, unread_count FROM conversation_state "
            "WHERE archived = 0 "
            "ORDER BY pinned DESC, last_active_ts DESC"
        ).fetchall()
        return [
            ConversationState(
                contact_pubkey_hex=r[0], archived=bool(r[1]), muted_until=r[2],
                pinned=bool(r[3]), last_active_ts=r[4], unread_count=r[5],
            )
            for r in rows
        ]

    def list_archived(self) -> List[ConversationState]:
        rows = self.conn.execute(
            "SELECT contact_pubkey_hex, archived, muted_until, pinned, "
            "last_active_ts, unread_count FROM conversation_state "
            "WHERE archived = 1 "
            "ORDER BY last_active_ts DESC"
        ).fetchall()
        return [
            ConversationState(
                contact_pubkey_hex=r[0], archived=bool(r[1]), muted_until=r[2],
                pinned=bool(r[3]), last_active_ts=r[4], unread_count=r[5],
            )
            for r in rows
        ]


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    conn = sqlite3.connect(":memory:")
    store = ConversationStore(conn)

    a = "aa" * 32
    b = "bb" * 32
    c = "cc" * 32

    store.ensure(a)
    store.ensure(b)
    store.ensure(c)

    store.on_incoming(a, ts=100)
    store.on_incoming(b, ts=200)
    store.on_incoming(c, ts=300)

    # Active list: most recent first
    active = store.list_active()
    assert [s.contact_pubkey_hex for s in active] == [c, b, a]

    # Pin a -> jumps to top
    store.pin(a)
    active = store.list_active()
    assert active[0].contact_pubkey_hex == a
    assert active[0].pinned is True

    # Archive b -> disappears from active, appears in archived
    store.archive(b)
    active = store.list_active()
    assert b not in [s.contact_pubkey_hex for s in active]
    archived = store.list_archived()
    assert [s.contact_pubkey_hex for s in archived] == [b]

    # Unread count
    state_a = store.get(a)
    assert state_a.unread_count == 1
    store.mark_read(a)
    assert store.get(a).unread_count == 0

    # Mute
    store.mute(c, until_ts=int(time.time()) + 60)
    assert store.is_muted(c)
    assert not store.is_muted(a)
    # After mute expiry
    assert not store.is_muted(c, now=int(time.time()) + 120)

    # Pin clears archive
    store.archive(a)
    assert store.get(a).archived
    store.pin(a)
    assert not store.get(a).archived

    conn.close()
    print("archive self-tests passed.")


if __name__ == "__main__":
    _self_test()
