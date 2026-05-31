"""
SHROUD content-addressed stickers.

Why content-addressed
---------------------
A "sticker pack" in most messengers is keyed by a pack-owner identifier
(Telegram pack name, WhatsApp pack URL). The act of downloading a
sticker pack tells the server / CDN which user is interested in that
pack. Worse: bespoke per-user stickers (Telegram custom emoji etc.)
let the server enumerate exactly which custom artwork each user owns —
a perfect identifying fingerprint per Rule 3.

SHROUD removes the per-user dimension entirely: stickers are
identified by their content hash (SHA-256 of the cleaned image bytes).
A "sticker pack" is a static JSON manifest on a public CDN listing
``{hash, label, mime}`` triples. Anyone who already knows a hash can
fetch the sticker; the CDN sees only ``GET /<sha256>`` and cannot
attribute which user wanted it (especially over Tor).

Sticker selection in the UI never tells the server which sticker the
user picked. The sticker hash rides inside the sealed envelope of an
outgoing message; the recipient renders from a local content-addressed
cache, fetching only if the hash isn't cached.

Rule compliance
---------------
  - Rule 1: irrelevant — sticker ride inside sealed envelope.
  - Rule 2: irrelevant — sticker ride inside sealed envelope.
  - Rule 3: every sticker passes through ``strip_metadata.strip`` at
    pack-build time. There is no per-user identification anywhere.

Pack manifest format
--------------------

A sticker pack is a static JSON file::

    {
      "id":   "shroud-default-pack-v1",
      "name": "Shroud Default",
      "stickers": [
        {"hash": "<sha256 hex>", "label": "hello", "mime": "image/webp"},
        {"hash": "<sha256 hex>", "label": "thumbsup", "mime": "image/webp"},
        ...
      ]
    }

Hashes are over the *cleaned* (metadata-stripped) bytes the CDN will
serve. The CDN stores objects at ``/stickers/<hash>``, content-typed
per the ``mime`` field. Manifest URLs are hard-coded in the client (or
discovered via signed updates) — there is no per-user manifest
distribution.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Tuple

from .strip_metadata import strip, UnsupportedMimeError


# ── Data classes ─────────────────────────────────────────────────────


@dataclass
class StickerEntry:
    hash: str   # sha256 hex of the cleaned bytes
    label: str  # short alphanumeric label (used in UI, never sent server-side)
    mime: str   # image/webp, image/png, image/gif


@dataclass
class StickerPack:
    id: str
    name: str
    stickers: List[StickerEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["stickers"] = [asdict(s) for s in self.stickers]
        return d

    def to_json(self, *, sort_keys: bool = True, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=sort_keys, indent=indent)


@dataclass
class StickerSelection:
    """The token that rides inside a sealed envelope when a user sends
    a sticker. Includes the pack ID so the recipient knows which CDN
    base URL to fetch from; never includes anything user-identifying."""
    pack_id: str
    hash: str


# ── Pack building (sender-side authoring) ────────────────────────────


def build_pack(
    pack_id: str,
    pack_name: str,
    sticker_files: Iterable[Tuple[str, str, bytes]],  # (label, mime, raw_bytes)
) -> Tuple[StickerPack, Dict[str, bytes]]:
    """Construct a sticker pack from raw image bytes. Each sticker is
    metadata-stripped before being hashed.

    Returns:
        (pack manifest, dict of {hash -> cleaned bytes} for CDN upload).
    """
    pack = StickerPack(id=pack_id, name=pack_name)
    cdn_assets: Dict[str, bytes] = {}

    for label, mime, raw in sticker_files:
        cleaned = strip(raw, mime).cleaned
        digest = hashlib.sha256(cleaned).hexdigest()
        pack.stickers.append(StickerEntry(hash=digest, label=label, mime=mime))
        cdn_assets[digest] = cleaned
    return pack, cdn_assets


# ── Sender-side: pick a sticker for sending ──────────────────────────


def make_selection(pack: StickerPack, label: str) -> Optional[StickerSelection]:
    """Look up a sticker by label in a pack and return the wire token
    to embed in the outgoing message. Returns None if no such label."""
    for s in pack.stickers:
        if s.label == label:
            return StickerSelection(pack_id=pack.id, hash=s.hash)
    return None


# ── Recipient-side: local content-addressed cache ────────────────────


class LocalStickerCache:
    """Filesystem-backed cache keyed by content hash. The recipient
    populates it lazily on first sight of a sticker hash; subsequent
    sightings hit the cache without any network activity."""

    def __init__(self, root_dir: str) -> None:
        self.root = root_dir
        os.makedirs(root_dir, exist_ok=True)

    def has(self, hash_hex: str) -> bool:
        return os.path.exists(self._path(hash_hex))

    def get(self, hash_hex: str) -> Optional[bytes]:
        try:
            with open(self._path(hash_hex), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def put(self, hash_hex: str, body: bytes) -> None:
        actual = hashlib.sha256(body).hexdigest()
        if actual != hash_hex:
            raise ValueError(
                f"hash mismatch: expected {hash_hex}, got {actual} "
                "(server is lying or content is tampered)"
            )
        path = self._path(hash_hex)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, path)

    def _path(self, hash_hex: str) -> str:
        # Shard by first 2 chars to bound directory size.
        return os.path.join(self.root, hash_hex[:2], hash_hex)


# ── Self-test ───────────────────────────────────────────────────────


def _self_test() -> None:
    # Hand-built JPEG with EXIF that strip_metadata will trim.
    import struct
    jpeg = (
        b"\xff\xd8"
        + b"\xff\xe1" + struct.pack(">H", 8) + b"Exif\x00\x00"  # APP1/EXIF
        + b"\xff\xdb" + struct.pack(">H", 4) + b"qq"            # DQT (legit)
        + b"\xff\xd9"
    )
    pack, cdn = build_pack(
        pack_id="test-pack-v1",
        pack_name="Test Pack",
        sticker_files=[("hi", "image/jpeg", jpeg)],
    )
    assert len(pack.stickers) == 1
    h = pack.stickers[0].hash
    assert h in cdn
    # Cleaned bytes should not contain the EXIF marker.
    assert b"Exif" not in cdn[h]

    # Selection token
    sel = make_selection(pack, "hi")
    assert sel is not None
    assert sel.pack_id == "test-pack-v1"
    assert sel.hash == h

    # Cache round-trip
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        cache = LocalStickerCache(tmp)
        assert not cache.has(h)
        cache.put(h, cdn[h])
        assert cache.has(h)
        assert cache.get(h) == cdn[h]

        # Tampered content rejected
        try:
            cache.put(h, b"not the original")
            raise AssertionError("hash mismatch should have raised")
        except ValueError:
            pass

    print("stickers self-tests passed.")


if __name__ == "__main__":
    _self_test()
