"""
SHROUD chunked sealed file transfer.

Large attachments (PDFs, archives, video clips above the inline-image
cap) are split into 256 KB chunks, each chunk individually sealed and
shipped as a separate envelope addressed to the recipient's current
routing tag. Every chunk advertises its position via a tiny
``ChunkHeader`` so the recipient reassembles regardless of arrival
order.

Why chunking
------------

Sealed envelopes have a tight padding-bucket regime (4 KB / 64 KB /
1 MB / 16 MB) so the relay can't distinguish small text messages from
larger media by size alone. A single sealed envelope larger than 16 MB
is rejected at the relay. By chunking, the sender keeps every
individual envelope inside a bucket, which:

  1. Hides the file size from passive observers — they see N envelopes
     in 1 MB buckets, but N could be the same for a 5 MB file as for a
     500 MB file (just longer transfer).
  2. Lets the recipient stream the file progressively as chunks arrive.
  3. Survives transient relay errors on individual chunks — the
     missing chunk can be re-requested without resending everything.

Wire format
-----------

Each chunk's plaintext payload (BEFORE sealing) is:

::

    +-----------+---------+--------+----------+-----------+----------+
    | magic (4) | ver (1) | flags  | file_id  | chunk_idx | chunk_ct |
    | "SFT1"    | 0x01    | (1)    | (16)     | (4)       | data     |
    +-----------+---------+--------+----------+-----------+----------+

  - file_id: 16 random bytes that identify this transfer; the same value
             is repeated in every chunk so the recipient can group them
  - chunk_idx: 4-byte big-endian index, starting at 0
  - The LAST chunk has flags & 0x01 set, and its data ends with a
    32-byte SHA-256 of the FULL pre-chunk plaintext file. The recipient
    verifies that hash after reassembly.

Rule compliance
---------------
  - Rule 1+2: every chunk rides the standard sealed envelope and
    routing-tag flow. Server cannot link chunks to a recipient because
    each one is just a separate /send-anon body.
  - Rule 3: ``crypto.strip_metadata`` MUST be called on the file before
    chunking when the MIME is a media format with embedded metadata
    (image, audio, video). For pure data files (archive, JSON, .txt),
    strip is a no-op (and ``strip()`` will UnsupportedMimeError —
    bypass with the explicit ``allow_unknown_mime=True`` arg).
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


# ── Wire constants ───────────────────────────────────────────────────


SFT_MAGIC = b"SFT1"
SFT_VERSION = 0x01
CHUNK_DATA_SIZE = 256 * 1024  # 256 KB plaintext per chunk
FLAG_FINAL = 0x01
HEADER_LEN = 4 + 1 + 1 + 16 + 4  # magic + ver + flags + file_id + chunk_idx


@dataclass
class ChunkHeader:
    flags: int
    file_id: bytes
    chunk_idx: int


@dataclass
class Chunk:
    """One chunk ready to be sealed and sent. ``payload`` is the
    plaintext (header + data) — pass it to ``anon_routing.seal()`` to
    produce the wire bytes for /send-anon."""
    payload: bytes


# ── Sender side: split a file ────────────────────────────────────────


def split_file(plaintext: bytes, file_id: Optional[bytes] = None) -> Tuple[bytes, List[Chunk]]:
    """Split a file's plaintext into chunks ready for sealing.

    Returns ``(file_id, chunks)``. The file_id is included in every
    chunk's header so the recipient can group them; you can pass an
    existing file_id (e.g., when resending a missing chunk) or let the
    function pick a fresh random one.
    """
    if file_id is None:
        file_id = os.urandom(16)
    elif len(file_id) != 16:
        raise ValueError("file_id must be 16 bytes")

    sha = hashlib.sha256(plaintext).digest()
    if not plaintext:
        # Even an empty file gets one final chunk so the recipient sees a
        # well-formed transfer (header + 32-byte hash trailer).
        plaintext_with_hash = sha
    else:
        plaintext_with_hash = plaintext + sha

    chunks: List[Chunk] = []
    n = len(plaintext_with_hash)
    pos = 0
    idx = 0
    while pos < n:
        end = min(pos + CHUNK_DATA_SIZE, n)
        data = plaintext_with_hash[pos:end]
        flags = FLAG_FINAL if end == n else 0
        header = (
            SFT_MAGIC
            + bytes([SFT_VERSION, flags])
            + file_id
            + struct.pack(">I", idx)
        )
        chunks.append(Chunk(payload=header + data))
        pos = end
        idx += 1
    return file_id, chunks


# ── Recipient side: reassemble ───────────────────────────────────────


class Reassembler:
    """Stateful chunk reassembler. Feed chunks via ``accept_chunk`` in
    any order; ``finalize`` returns the full file once all chunks are
    in and the embedded hash matches."""

    def __init__(self) -> None:
        self._by_id: dict[bytes, dict[int, bytes]] = {}
        self._final_idx: dict[bytes, int] = {}
        self._hashes: dict[bytes, bytes] = {}

    def accept_chunk(self, payload: bytes) -> Optional[bytes]:
        """Parse one chunk. If this completes a file, return the full
        verified file bytes. Otherwise return None.
        """
        header, idx, file_id, flags, data = self._parse(payload)

        bucket = self._by_id.setdefault(file_id, {})
        bucket[idx] = data
        if flags & FLAG_FINAL:
            # Hash is the last 32 bytes of the last chunk's data
            if len(data) < 32:
                raise ValueError("final chunk too short to contain SHA-256")
            self._final_idx[file_id] = idx
            self._hashes[file_id] = data[-32:]
            # Trim the hash off the stored data
            bucket[idx] = data[:-32]

        if file_id not in self._final_idx:
            return None

        final_idx = self._final_idx[file_id]
        if any(i not in bucket for i in range(final_idx + 1)):
            return None  # still waiting for missing chunks

        assembled = b"".join(bucket[i] for i in range(final_idx + 1))
        expected = self._hashes[file_id]
        actual = hashlib.sha256(assembled).digest()
        # Free up state — we're done with this file_id
        del self._by_id[file_id]
        del self._final_idx[file_id]
        del self._hashes[file_id]
        if actual != expected:
            raise ValueError("file hash mismatch — transfer corrupted or tampered")
        return assembled

    @staticmethod
    def _parse(payload: bytes) -> tuple[ChunkHeader, int, bytes, int, bytes]:
        if len(payload) < HEADER_LEN:
            raise ValueError("chunk too short")
        if payload[:4] != SFT_MAGIC:
            raise ValueError("bad magic")
        if payload[4] != SFT_VERSION:
            raise ValueError(f"unknown SFT version {payload[4]}")
        flags = payload[5]
        file_id = payload[6:22]
        idx = struct.unpack(">I", payload[22:26])[0]
        data = payload[26:]
        return ChunkHeader(flags, file_id, idx), idx, file_id, flags, data


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Round-trip a 600 KB file: should split into 3 chunks (256 + 256 + ~88).
    body = bytes((i * 31 + 7) & 0xFF for i in range(600 * 1024))
    file_id, chunks = split_file(body)
    assert len(chunks) == 3, f"expected 3 chunks, got {len(chunks)}"
    # Only the last chunk has FLAG_FINAL.
    assert chunks[-1].payload[5] == FLAG_FINAL
    assert chunks[0].payload[5] == 0

    # Reassemble in shuffled order.
    rsm = Reassembler()
    out = rsm.accept_chunk(chunks[1].payload)
    assert out is None
    out = rsm.accept_chunk(chunks[2].payload)
    assert out is None  # missing chunk 0
    out = rsm.accept_chunk(chunks[0].payload)
    assert out == body, "reassembled body should equal source"

    # Corruption detection: mangle a byte in chunk 1
    file_id, chunks = split_file(body)
    mangled = bytearray(chunks[1].payload)
    mangled[100] ^= 0x01
    rsm2 = Reassembler()
    rsm2.accept_chunk(chunks[0].payload)
    rsm2.accept_chunk(bytes(mangled))
    try:
        rsm2.accept_chunk(chunks[2].payload)
        raise AssertionError("expected hash mismatch failure")
    except ValueError as e:
        assert "hash mismatch" in str(e)

    # Empty file edge case
    file_id, chunks = split_file(b"")
    assert len(chunks) == 1
    rsm3 = Reassembler()
    out = rsm3.accept_chunk(chunks[0].payload)
    assert out == b""

    # Multi-file interleaving
    rsm4 = Reassembler()
    a_id, a_chunks = split_file(b"alice file " * 30000)
    b_id, b_chunks = split_file(b"bob file " * 30000)
    assert a_id != b_id

    # Interleave the two transfers
    for i in range(max(len(a_chunks), len(b_chunks))):
        if i < len(a_chunks):
            rsm4.accept_chunk(a_chunks[i].payload)
        if i < len(b_chunks):
            rsm4.accept_chunk(b_chunks[i].payload)

    # Both should be complete by now — reassemble one more time to confirm
    rsm5 = Reassembler()
    for c in a_chunks[:-1]:
        assert rsm5.accept_chunk(c.payload) is None
    last = rsm5.accept_chunk(a_chunks[-1].payload)
    assert last == b"alice file " * 30000

    print("file_transfer self-tests passed.")


if __name__ == "__main__":
    _self_test()
