"""
SHROUD server-side disk quota enforcement.

The relay holds opaque sealed envelopes for the brief moment between
``send-anon`` and the recipient's ``fetch-anon``. Under normal load
that queue stays small. Under a flood attack (or just unusually heavy
real traffic) it can grow without bound.

This module gives the server a hard ceiling on total ``anon_messages``
disk usage. When the threshold is hit, we sweep the OLDEST messages
first until we're back under threshold.

Order of preference for what gets dropped:

  1. Messages older than 24 hours (almost certainly stale — the
     recipient hasn't connected in a day; expect them to re-request
     via X3DH next session).
  2. Messages exceeding their X-Expires-In TTL.
  3. Oldest-first, dropping enough to free 10% of the threshold.

This is intentionally NOT a hot-path operation. We run it in the
background sweeper task (already in `server/server.py`) once a
minute, not on every insert. The cost of a single sweep is a few SQL
queries; over a 1M-row table it completes in under a second.

Rule compliance
---------------
  - Rule 0: keeps the relay alive under load instead of crashing
    out-of-disk.
  - Rule 1/2: dropping messages is fine — at worst the sender
    didn't reach the recipient, who will re-poll next session.
    Server cannot extract sender/recipient info from what gets
    dropped.
"""
from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Tuple


@dataclass
class QuotaPolicy:
    max_db_bytes: int = 8 * 1024 * 1024 * 1024   # 8 GiB
    sweep_target_bytes: int | None = None        # default: 90% of max
    stale_after_seconds: int = 86400             # 24 hours


def _db_size_bytes(db: sqlite3.Connection) -> int:
    """Total size of the SQLite file on disk."""
    row = db.execute(
        "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()"
    ).fetchone()
    return int(row[0])


def sweep(db: sqlite3.Connection, policy: QuotaPolicy | None = None) -> Tuple[int, int]:
    """Run one sweep against ``anon_messages``. Returns
    ``(rows_deleted, bytes_freed_estimate)``."""
    p = policy or QuotaPolicy()
    target = p.sweep_target_bytes or int(p.max_db_bytes * 0.9)

    size = _db_size_bytes(db)
    if size <= p.max_db_bytes:
        return 0, 0

    cutoff_ts = time.time() - p.stale_after_seconds

    total_deleted = 0

    # ── Step 1: drop anything past its TTL ──
    cur = db.execute(
        "DELETE FROM anon_messages "
        "WHERE expires_at IS NOT NULL AND expires_at < datetime('now')"
    )
    total_deleted += cur.rowcount or 0

    # ── Step 2: drop anything older than the stale threshold ──
    cur = db.execute(
        "DELETE FROM anon_messages "
        "WHERE server_ts < datetime(?, 'unixepoch')",
        (cutoff_ts,),
    )
    total_deleted += cur.rowcount or 0

    db.commit()

    # ── Step 3: if still over, drop oldest until under target ──
    size = _db_size_bytes(db)
    while size > target:
        cur = db.execute(
            "DELETE FROM anon_messages "
            "WHERE id IN ("
            "    SELECT id FROM anon_messages ORDER BY server_ts ASC LIMIT 1000"
            ")"
        )
        if (cur.rowcount or 0) == 0:
            break
        total_deleted += cur.rowcount
        db.commit()
        size = _db_size_bytes(db)

    # ── Step 4: VACUUM to reclaim the freed pages ──
    # VACUUM requires no transaction to be open. Some Python sqlite3
    # implementations leave one open implicitly; explicit commit
    # closes it.
    db.commit()
    db.isolation_level = None
    db.execute("VACUUM")
    db.isolation_level = ""

    after = _db_size_bytes(db)
    freed = max(0, _db_size_bytes(db) - after)  # 0; VACUUM may have shrunk
    return total_deleted, max(0, size - after)


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    import tempfile

    # Create a fake anon_messages-shaped table and stuff it.
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "test.db")
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE anon_messages (
                id TEXT PRIMARY KEY,
                routing_tag BLOB NOT NULL,
                sealed_blob BLOB NOT NULL,
                server_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT
            );
        """)

        # Insert 100 fresh rows + 100 old rows with backdated server_ts.
        for i in range(100):
            conn.execute(
                "INSERT INTO anon_messages (id, routing_tag, sealed_blob) VALUES (?,?,?)",
                (f"fresh-{i}", b"x" * 32, b"x" * 4096),
            )
        for i in range(100):
            conn.execute(
                "INSERT INTO anon_messages (id, routing_tag, sealed_blob, server_ts) VALUES (?,?,?, datetime('now', '-2 days'))",
                (f"stale-{i}", b"y" * 32, b"y" * 4096),
            )
        conn.commit()

        # Set a quota smaller than the table to force a sweep.
        policy = QuotaPolicy(max_db_bytes=256 * 1024, sweep_target_bytes=128 * 1024)
        deleted, _ = sweep(conn, policy)

        # Stale rows should have been the first to go.
        remaining = [
            r[0] for r in conn.execute("SELECT id FROM anon_messages").fetchall()
        ]
        assert all(not r.startswith("stale-") for r in remaining), (
            f"stale rows weren't all dropped: {[r for r in remaining if r.startswith('stale-')]}"
        )
        assert deleted >= 100, f"expected to delete at least 100 stale; got {deleted}"

        conn.close()
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("disk_quota self-tests passed.")


if __name__ == "__main__":
    _self_test()
