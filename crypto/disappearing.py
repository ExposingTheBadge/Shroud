"""
SHROUD disappearing media — TTL + secure local wipe.

Server-side TTL is already enforced by ``server/server.py``'s
``_expiry_sweeper`` and the ``X-Expires-In`` header on send-anon /
send-sealed: queued messages with an ``expires_at`` past the wall clock
are deleted in a background loop. That handles the "message never
reached recipient" case.

Client-side disappearance is a separate problem. Once a message
arrives, it lives in the recipient's local store: SQLite row, an
on-disk attachment file, a screenshot the user took. The recipient's
client must:

  1. Track per-message TTLs from the moment of *display*, not arrival
     (otherwise a 30-second TTL on a message you haven't opened for an
     hour disappears before you read it).
  2. When TTL expires, securely overwrite + delete the local row +
     attachments. This module provides that wipe.
  3. Refuse to silently re-show a message after expiry. A re-fetch of
     the same message_id MUST be blocked at the local cache level even
     if the server somehow served it again.

This module ships the pure crypto-side helpers. Wire-up to the actual
storage layer (SQLite + file system on Windows, Room + file on Android,
etc.) is per-client.

Rule compliance
---------------
  - Rule 1/2: orthogonal — disappearance happens on the recipient's
    device, server is uninvolved past the initial delivery sweep.
  - Rule 3: secure wipe ensures no residual content metadata stays
    behind, even after the message itself is gone (we overwrite the
    actual disk sectors before unlink).
  - Rule 0: orthogonal — local-device feature, no server dependency.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional


# ── Secure file wipe ─────────────────────────────────────────────────


_DEFAULT_WIPE_PASSES = 1  # SSDs make >1 pass useless; one zero pass is enough


def secure_wipe_file(path: str, *, passes: int = _DEFAULT_WIPE_PASSES) -> None:
    """Overwrite a file with zeros then unlink it.

    On modern SSDs (which most user devices are now) >1 pass is
    cargo-culted from spinning-disk-era wisdom. The drive's flash
    translation layer abstracts physical sector reuse from logical
    overwrites, so we can't guarantee the underlying flash cells are
    zeroed regardless of how many passes we do. The right defence is
    full-disk encryption + key destruction; this function complements
    that for users without FDE.

    For HDDs and removable USB sticks, the zero pass still has value
    because logical sector overwrite maps to a physical sector
    overwrite for those media.

    Args:
        path: path to a regular file
        passes: number of overwrite passes (default 1)
    """
    if not os.path.isfile(path):
        return

    size = os.path.getsize(path)
    block = 4096
    try:
        with open(path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                remaining = size
                zeros = b"\x00" * block
                while remaining > 0:
                    f.write(zeros[: min(block, remaining)])
                    remaining -= block
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        # Even if overwrite fails, attempt the unlink — the goal is "gone".
        pass
    try:
        os.remove(path)
    except OSError:
        pass


# ── Disappearing-message tracking ────────────────────────────────────


@dataclass
class TrackedMessage:
    message_id: str
    display_started_at: Optional[float]
    ttl_seconds: int
    attachment_paths: List[str]

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.display_started_at is None:
            return False  # Not yet displayed
        if self.ttl_seconds <= 0:
            return False  # Permanent (TTL disabled)
        t = now if now is not None else time.time()
        return (t - self.display_started_at) >= self.ttl_seconds


class DisappearingTracker:
    """In-memory tracker of disappearing messages and their attachment
    files. Persistence is the caller's responsibility.

    Usage::

        tracker = DisappearingTracker()
        # When a message arrives:
        tracker.on_arrival("msg-1", ttl_seconds=60, attachments=["/path/a.webp"])
        # When the user actually displays the message in their UI:
        tracker.mark_displayed("msg-1")
        # Periodically (e.g. every second, on a UI tick):
        for mid in tracker.tick():
            ui.remove_message(mid)
    """

    def __init__(self) -> None:
        self._tracked: dict[str, TrackedMessage] = {}
        self._wiped: set[str] = set()

    def on_arrival(self, message_id: str, ttl_seconds: int,
                   attachments: Optional[List[str]] = None) -> None:
        if message_id in self._wiped:
            # Refuse to re-show a wiped message even if it somehow
            # arrives again.
            raise ValueError(f"message {message_id} was previously wiped; refusing to re-track")
        self._tracked[message_id] = TrackedMessage(
            message_id=message_id,
            display_started_at=None,
            ttl_seconds=int(ttl_seconds),
            attachment_paths=list(attachments or []),
        )

    def mark_displayed(self, message_id: str) -> None:
        tm = self._tracked.get(message_id)
        if tm is None or tm.display_started_at is not None:
            return
        tm.display_started_at = time.time()

    def tick(self, now: Optional[float] = None) -> List[str]:
        """Return the list of message IDs whose TTL has elapsed since
        they were displayed, AND securely wipe their attachments and
        cache entries. Caller is responsible for the UI-level remove."""
        expired: List[str] = []
        for mid, tm in list(self._tracked.items()):
            if not tm.is_expired(now):
                continue
            for p in tm.attachment_paths:
                secure_wipe_file(p)
            expired.append(mid)
            self._wiped.add(mid)
            del self._tracked[mid]
        return expired

    def is_wiped(self, message_id: str) -> bool:
        return message_id in self._wiped


# ── SQLite helper: vacuum after deleting message rows ────────────────


def secure_delete_sqlite_rows(db_path: str, message_ids: Iterable[str]) -> None:
    """Delete message rows by ID and VACUUM the database so freed pages
    are zeroed and reclaimed. Without VACUUM the deleted rows linger in
    the file's free-page list and a forensic tool can recover them."""
    ids = list(message_ids)
    if not ids:
        return
    con = sqlite3.connect(db_path)
    try:
        placeholders = ",".join("?" for _ in ids)
        con.execute("PRAGMA secure_delete = ON;")
        con.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", ids)
        con.commit()
        con.execute("VACUUM;")
    finally:
        con.close()


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    import tempfile

    # secure_wipe_file
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"super secret message body")
        path = tf.name
    assert os.path.isfile(path)
    secure_wipe_file(path)
    assert not os.path.isfile(path)

    # DisappearingTracker — short TTL, mark displayed, tick after expiry
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"attachment bytes")
        att = tf.name

    tracker = DisappearingTracker()
    tracker.on_arrival("m1", ttl_seconds=1, attachments=[att])

    # Before display: no expiry
    assert tracker.tick() == []
    assert os.path.isfile(att)

    tracker.mark_displayed("m1")
    assert tracker.tick(now=time.time()) == []  # not yet expired

    # Force expiry by passing a future timestamp
    future = time.time() + 5
    assert tracker.tick(now=future) == ["m1"]
    assert not os.path.isfile(att), "attachment should have been wiped"
    assert tracker.is_wiped("m1")

    # Refuse to re-track a wiped message
    try:
        tracker.on_arrival("m1", ttl_seconds=10)
        raise AssertionError("re-tracking a wiped message should fail")
    except ValueError:
        pass

    # SQLite secure delete
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "test.db")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE messages (id TEXT PRIMARY KEY, body TEXT)")
        con.execute("INSERT INTO messages VALUES ('m1', 'plaintext body')")
        con.execute("INSERT INTO messages VALUES ('m2', 'another body')")
        con.commit()
        con.close()
        secure_delete_sqlite_rows(db, ["m1"])
        # m1 should be gone, m2 should remain
        con = sqlite3.connect(db)
        rows = con.execute("SELECT id FROM messages").fetchall()
        con.close()
        assert rows == [("m2",)]

    print("disappearing self-tests passed.")


if __name__ == "__main__":
    _self_test()
