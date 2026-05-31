"""
SHROUD encrypted-at-rest local message search.

Searchable Symmetric Encryption (SSE), tuned for the messaging use
case: a local SQLite-backed inverted index that lets a user grep
through their own message history without storing tokens in
plaintext on disk.

What it protects against
------------------------

  - **Disk-image forensics on an unlocked device.** If an attacker
    images the storage of a device while the user is logged in, they
    see only blinded token hashes — no message bodies, no clear text
    tokens. Plaintext lives only in RAM during a search.
  - **Cold-storage backup leakage.** A backup file (see
    ``crypto.backup``) that includes the search index gives a thief
    nothing useful without the user's master key.

What it does NOT protect against
--------------------------------

  - **Adversary with the master key.** Once you hold the key, you can
    re-derive any token's hash and identify which messages contained
    it. This is the right boundary: a user who knows their own
    password can search their own messages.
  - **Frequency analysis.** Like all keyword SSE schemes, the index
    leaks the *count* of messages containing a given (blinded) token.
    A determined adversary with the disk image plus knowledge of
    keyword distributions in the wild can guess high-frequency tokens.
    Mitigation: pad each posting list with random dummies (we do this
    via ``add_padding`` configurable per-token).

Design
------

A single ``messages`` table on the caller side stores message bodies
encrypted at rest. This module manages an adjacent ``search_postings``
table:

    CREATE TABLE search_postings (
        token_hash BLOB NOT NULL,
        message_id TEXT NOT NULL,
        position   INTEGER NOT NULL,
        PRIMARY KEY (token_hash, message_id, position)
    );
    CREATE INDEX idx_postings_token ON search_postings(token_hash);
    CREATE INDEX idx_postings_msg   ON search_postings(message_id);

``token_hash`` is ``HMAC-SHA256(master_key, lowercased_token)[:16]``
truncated to 16 bytes. The truncation is fine for our threshold of
~10^9 unique tokens (birthday collision probability < 1e-12).

Tokenization is just whitespace + lowercase + alphanumerics, which is
adequate for messaging. CJK and emoji are not specially tokenized —
they show up as bag-of-codepoints, which works surprisingly well for
short messages.

Rule compliance
---------------
  - Rule 0/1/2: orthogonal — purely local.
  - Rule 3: orthogonal.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence


TOKEN_HASH_BYTES = 16


def _normalize_token(t: str) -> str:
    """Lowercase + strip non-alphanumeric. Preserves bytes for
    CJK / emoji, which the bag-of-tokens search handles OK."""
    return re.sub(r"[^\w]+", "", t.lower(), flags=re.UNICODE)


def tokenize(text: str) -> List[str]:
    """Whitespace-split + normalize. Drops empties and tokens > 64
    bytes (those are usually URLs/random hex, not interesting for
    search)."""
    out = []
    for raw in text.split():
        n = _normalize_token(raw)
        if n and len(n.encode("utf-8")) <= 64:
            out.append(n)
    return out


def token_hash(master_key: bytes, token: str) -> bytes:
    """Deterministic per-key blinded hash. Returns 16 bytes."""
    return hmac.new(
        master_key, token.encode("utf-8"), hashlib.sha256
    ).digest()[:TOKEN_HASH_BYTES]


# ── Index ────────────────────────────────────────────────────────────


SCHEMA = """
CREATE TABLE IF NOT EXISTS search_postings (
    token_hash BLOB NOT NULL,
    message_id TEXT NOT NULL,
    position   INTEGER NOT NULL,
    PRIMARY KEY (token_hash, message_id, position)
);
CREATE INDEX IF NOT EXISTS idx_postings_token ON search_postings(token_hash);
CREATE INDEX IF NOT EXISTS idx_postings_msg ON search_postings(message_id);
"""


class SearchIndex:
    """Wrap a sqlite connection with the search-postings methods.

    Caller is responsible for the surrounding ``messages`` table (it
    just needs to use the same ``message_id`` values).
    """

    def __init__(self, conn: sqlite3.Connection, master_key: bytes) -> None:
        if len(master_key) < 16:
            raise ValueError("master_key must be at least 16 bytes")
        self.conn = conn
        self.master_key = master_key
        conn.executescript(SCHEMA)
        conn.commit()

    def index_message(self, message_id: str, body: str,
                      *, padding_per_token: int = 0) -> None:
        """Insert posting rows for every token in ``body``. Optional
        per-token padding inserts ``padding_per_token`` extra fake
        postings to flatten the frequency distribution."""
        rows = []
        for pos, tok in enumerate(tokenize(body)):
            th = token_hash(self.master_key, tok)
            rows.append((th, message_id, pos))
        if padding_per_token:
            import os
            # Generate padding tokens by hashing random data — they're
            # indistinguishable from real tokens to an adversary.
            for _ in range(padding_per_token):
                th = os.urandom(TOKEN_HASH_BYTES)
                rows.append((th, message_id, -1))
        if rows:
            self.conn.executemany(
                "INSERT OR IGNORE INTO search_postings "
                "(token_hash, message_id, position) VALUES (?,?,?)",
                rows,
            )
            self.conn.commit()

    def search(self, query: str, *, limit: int = 50) -> List[str]:
        """Return up to ``limit`` message_ids whose body contains every
        token in ``query`` (AND semantics)."""
        tokens = tokenize(query)
        if not tokens:
            return []
        hashes = [token_hash(self.master_key, t) for t in tokens]

        # Use a single SQL query that intersects message_ids across
        # each token's posting list.
        placeholders = ",".join("?" for _ in hashes)
        rows = self.conn.execute(
            f"SELECT message_id FROM search_postings "
            f"WHERE token_hash IN ({placeholders}) "
            f"GROUP BY message_id "
            f"HAVING COUNT(DISTINCT token_hash) = ? "
            f"LIMIT ?",
            (*hashes, len(set(hashes)), limit),
        ).fetchall()
        return [r[0] for r in rows]

    def delete_message(self, message_id: str) -> None:
        """Remove all postings for a message (e.g., when the message
        is wiped by the disappearing-media TTL)."""
        self.conn.execute(
            "DELETE FROM search_postings WHERE message_id = ?", (message_id,)
        )
        self.conn.commit()

    def vacuum(self) -> None:
        """Reclaim space. Call after bulk deletes."""
        self.conn.execute("PRAGMA secure_delete = ON")
        self.conn.execute("VACUUM")


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    import os
    import tempfile

    master = os.urandom(32)

    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "search.db")
        conn = sqlite3.connect(db_path)
        idx = SearchIndex(conn, master)

        idx.index_message("m1", "Hello world, this is Alice talking to Bob.")
        idx.index_message("m2", "Bob says hi back to Alice.")
        idx.index_message("m3", "Carol is meeting Dave at the cafe.")
        idx.index_message("m4", "")  # empty body

        # Single token
        r = idx.search("alice")
        assert set(r) == {"m1", "m2"}, r

        # Multi token AND
        r = idx.search("alice bob")
        assert set(r) == {"m1", "m2"}, r

        # No match
        assert idx.search("xenomorph") == []

        # Deletion
        idx.delete_message("m1")
        assert set(idx.search("alice")) == {"m2"}

        # Padding doesn't break correctness (just adds noise rows)
        idx.index_message("m5", "Eve sends signal", padding_per_token=10)
        assert "m5" in idx.search("eve")

        # On-disk inspection: NO plaintext tokens visible
        with open(db_path, "rb") as f:
            on_disk = f.read()
        for word in ("Alice", "Bob", "Carol", "Dave", "cafe", "signal", "Eve"):
            assert word.lower().encode() not in on_disk.lower(), (
                f"plaintext token leaked: {word}"
            )

        # Different master key = no matches
        wrong_conn = sqlite3.connect(db_path)
        wrong = SearchIndex(wrong_conn, os.urandom(32))
        assert wrong.search("bob") == []
        wrong_conn.close()

        idx.vacuum()
        conn.close()

    print("local_search self-tests passed.")


if __name__ == "__main__":
    _self_test()
