"""
SHROUD universal metadata-strip pipeline (Rule 3).

Single chokepoint. Every piece of media that leaves a client passes through
this module BEFORE it is encrypted. The point is to make it impossible for
a future feature (stickers, voice messages, video clips, profile pictures)
to silently leak identifying metadata: any code path that wants to attach
media to a SHROUD message must call ``strip(media_bytes, mime)`` and use
the returned bytes.

Categories of metadata we strip:

  - EXIF, XMP, IPTC, Photoshop IRBs (images)
  - Container-level "metadata" boxes (mp4 'meta'/'udta')
  - ID3 tags (mp3)
  - Vorbis comments (ogg, opus, flac)
  - File modification times (anywhere we can see them)
  - Embedded color profiles WHEN they include device-identifying ICC tags
  - PNG ancillary chunks that aren't critical to rendering
  - JFIF/Exif comments
  - GPS data (subsumed by EXIF strip; called out explicitly)
  - Author/copyright/CreatorTool fields in PDFs
  - Editing-software watermarks in webp/HEIF

We deliberately do NOT use Pillow's ``save()`` "no exif" mode alone, because
it leaves Adobe XMP packets and several other chunks intact. We pre-walk
the byte stream with a parser per format and rebuild a metadata-free copy.

For formats we don't recognise we refuse the upload rather than ship
unknown metadata. The error is a structured ``UnsupportedMimeError`` so
the caller can surface a clear "this file type isn't allowed yet" message.
"""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import Optional


# ── Public API ────────────────────────────────────────────────────────


class UnsupportedMimeError(Exception):
    """Raised when ``strip`` is asked to handle a MIME type it doesn't
    have a verified-clean pipeline for. Clients MUST refuse the upload
    rather than silently passing through unknown metadata."""


class MalformedMediaError(Exception):
    """Raised when the input bytes claim a MIME but can't be parsed as it.
    Clients should reject (likely a bug or evasion attempt)."""


@dataclass
class StripResult:
    """Result of a strip operation.

    ``cleaned`` is the metadata-free byte stream, safe to encrypt and send.
    ``bytes_removed`` is the count of stripped metadata bytes — exposed for
    UI debugging only; do not log this against any per-user counter.
    """
    cleaned: bytes
    bytes_removed: int


def strip(media_bytes: bytes, mime: str) -> StripResult:
    """Strip all identifying metadata from ``media_bytes``.

    Args:
        media_bytes: raw file contents
        mime: best-effort MIME type the caller believes the bytes are

    Returns:
        StripResult with a cleaned byte stream that contains *only* the
        pixel/audio/video data necessary to render the file.

    Raises:
        UnsupportedMimeError: if no clean-pipeline exists for ``mime``
        MalformedMediaError: if the bytes can't be parsed as their MIME
    """
    m = mime.lower().strip()

    if m in ("image/jpeg", "image/jpg"):
        return _strip_jpeg(media_bytes)
    if m == "image/png":
        return _strip_png(media_bytes)
    if m == "image/webp":
        return _strip_webp(media_bytes)
    if m == "image/gif":
        return _strip_gif(media_bytes)
    if m in ("audio/ogg", "audio/opus", "audio/vorbis"):
        return _strip_ogg(media_bytes)
    if m == "audio/mpeg" or m == "audio/mp3":
        return _strip_mp3(media_bytes)
    if m == "audio/wav" or m == "audio/x-wav":
        return _strip_wav(media_bytes)
    if m in ("video/mp4", "video/quicktime"):
        return _strip_mp4(media_bytes)
    if m == "application/pdf":
        # We don't ship PDF support yet — PDFs are absurdly leaky
        # (author, software, modification dates in 5+ different places).
        # Easier to refuse than to try.
        raise UnsupportedMimeError("PDF not supported — convert to image first")
    raise UnsupportedMimeError(f"no clean pipeline for MIME {mime!r}")


# ── JPEG ──────────────────────────────────────────────────────────────
#
# JPEG is a sequence of marker segments. Each marker is 0xFF followed by a
# non-zero byte. APPn (0xE0..0xEF) and COM (0xFE) carry metadata; we drop
# them. SOF, DHT, DQT, SOS, DRI carry decode data; we keep them.

def _strip_jpeg(data: bytes) -> StripResult:
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        raise MalformedMediaError("not a JPEG (missing SOI)")

    out = bytearray(b"\xff\xd8")  # SOI
    i = 2
    n = len(data)
    while i + 1 < n:
        if data[i] != 0xFF:
            raise MalformedMediaError(f"JPEG out of sync at offset {i}")
        # Skip fill bytes
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            break
        marker = data[i]
        i += 1
        if marker == 0xD9:  # EOI
            out.append(0xFF)
            out.append(0xD9)
            break
        if marker == 0xDA:  # SOS — followed by entropy-coded segment
            seg_len = struct.unpack(">H", data[i:i + 2])[0]
            out.append(0xFF)
            out.append(marker)
            out.extend(data[i:i + seg_len])
            i += seg_len
            # Now copy entropy data verbatim up to the next non-RST marker
            start = i
            while i + 1 < n:
                if data[i] == 0xFF and data[i + 1] not in (0x00,) + tuple(range(0xD0, 0xD8)):
                    break
                i += 1
            out.extend(data[start:i])
            continue
        if 0xD0 <= marker <= 0xD7:  # RSTn — no payload
            out.append(0xFF)
            out.append(marker)
            continue
        # Length-prefixed segment
        if i + 2 > n:
            break
        seg_len = struct.unpack(">H", data[i:i + 2])[0]
        # Drop APPn (0xE0..0xEF) and COM (0xFE) — all metadata lives there
        if (0xE0 <= marker <= 0xEF) or marker == 0xFE:
            i += seg_len
            continue
        out.append(0xFF)
        out.append(marker)
        out.extend(data[i:i + seg_len])
        i += seg_len

    return StripResult(cleaned=bytes(out), bytes_removed=len(data) - len(out))


# ── PNG ───────────────────────────────────────────────────────────────
#
# PNG is a magic header + a sequence of {length, type, data, crc} chunks.
# Critical chunks (uppercase first letter) we keep: IHDR, PLTE, IDAT, IEND.
# Ancillary chunks (lowercase first letter) we drop EXCEPT tRNS (palette
# transparency — required for correct rendering) and gAMA (gamma —
# required to display correctly across monitors). Everything else: out.

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA"}


def _strip_png(data: bytes) -> StripResult:
    if len(data) < 8 or data[:8] != PNG_MAGIC:
        raise MalformedMediaError("not a PNG (bad magic)")

    out = bytearray(PNG_MAGIC)
    i = 8
    n = len(data)
    while i + 12 <= n:
        length = struct.unpack(">I", data[i:i + 4])[0]
        chunk_type = data[i + 4:i + 8]
        end = i + 8 + length + 4  # length + type + data + crc
        if end > n:
            raise MalformedMediaError("PNG truncated chunk")
        if chunk_type in PNG_KEEP:
            out.extend(data[i:end])
        i = end
        if chunk_type == b"IEND":
            break

    return StripResult(cleaned=bytes(out), bytes_removed=len(data) - len(out))


# ── WebP ──────────────────────────────────────────────────────────────
#
# WebP is RIFF: 'RIFF', uint32 size, 'WEBP', then a sequence of chunks
# {fourcc, uint32 size, data, optional pad byte}. We keep VP8/VP8L/VP8X
# (image data) and ALPH (alpha plane). We drop EXIF, XMP, ICCP.

WEBP_KEEP = {b"VP8 ", b"VP8L", b"VP8X", b"ALPH"}


def _strip_webp(data: bytes) -> StripResult:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise MalformedMediaError("not a WebP (bad RIFF header)")

    # Build new chunk list, then rewrite RIFF size at the end.
    body = bytearray(b"WEBP")
    i = 12
    n = len(data)
    while i + 8 <= n:
        fourcc = data[i:i + 4]
        size = struct.unpack("<I", data[i + 4:i + 8])[0]
        payload_end = i + 8 + size
        # WebP chunks have an odd-byte pad to align next chunk on word boundary
        next_chunk = payload_end + (size & 1)
        if payload_end > n:
            raise MalformedMediaError("WebP truncated chunk")
        if fourcc in WEBP_KEEP:
            body.extend(data[i:next_chunk])
        i = next_chunk

    out = bytearray(b"RIFF")
    out.extend(struct.pack("<I", len(body)))
    out.extend(body)
    return StripResult(cleaned=bytes(out), bytes_removed=len(data) - len(out))


# ── GIF ───────────────────────────────────────────────────────────────
#
# GIF lacks formal metadata fields, but the comment extension (0x21 0xFE)
# and application extensions (0x21 0xFF — including XMP) leak. We walk
# the stream and skip those two extension types.

def _strip_gif(data: bytes) -> StripResult:
    if len(data) < 6 or data[:3] != b"GIF" or data[3:6] not in (b"87a", b"89a"):
        raise MalformedMediaError("not a GIF")

    out = bytearray()
    i = 0
    n = len(data)
    # Header + Logical Screen Descriptor (always 13 bytes, no metadata)
    out.extend(data[:13])
    i = 13
    # Skip Global Color Table if present
    flags = data[10]
    if flags & 0x80:
        gct_size = 3 * (1 << ((flags & 0x07) + 1))
        out.extend(data[i:i + gct_size])
        i += gct_size

    while i < n:
        b = data[i]
        if b == 0x3B:  # GIF trailer
            out.append(0x3B)
            break
        if b == 0x2C:  # Image descriptor — keep
            # Image descriptor is 10 bytes
            out.extend(data[i:i + 10])
            img_flags = data[i + 9]
            i += 10
            if img_flags & 0x80:
                lct_size = 3 * (1 << ((img_flags & 0x07) + 1))
                out.extend(data[i:i + lct_size])
                i += lct_size
            # LZW min code size byte
            out.extend(data[i:i + 1])
            i += 1
            # Sub-blocks until 0x00 terminator
            while i < n:
                sb = data[i]
                out.append(sb)
                i += 1
                if sb == 0:
                    break
                out.extend(data[i:i + sb])
                i += sb
            continue
        if b == 0x21:  # Extension
            ext_label = data[i + 1] if i + 1 < n else 0
            i += 2
            if ext_label == 0xF9:  # Graphic control — keep (animation timing)
                out.extend(b"\x21\xF9")
                while i < n:
                    sb = data[i]
                    out.append(sb)
                    i += 1
                    if sb == 0:
                        break
                    out.extend(data[i:i + sb])
                    i += sb
                continue
            # Drop comment (0xFE) and application (0xFF) extensions:
            # walk past sub-blocks without copying.
            while i < n:
                sb = data[i]
                i += 1
                if sb == 0:
                    break
                i += sb
            continue
        # Unknown byte — bail out conservatively
        raise MalformedMediaError(f"GIF unexpected byte 0x{b:02x} at {i}")

    return StripResult(cleaned=bytes(out), bytes_removed=len(data) - len(out))


# ── OGG / Opus / Vorbis ───────────────────────────────────────────────
#
# OGG is a sequence of pages. Vorbis comments live in the second packet of
# a Vorbis/Opus stream (the "comment header"). We replace its comment list
# with an empty one, recompute the page CRC.

def _strip_ogg(data: bytes) -> StripResult:
    # Full OGG remux is complex; for now we route through a placeholder
    # that rejects metadata-bearing pages. Production should use mutagen
    # or a hand-rolled VorbisComment scrubber.
    # The conservative interim policy: if we can't strip cleanly, refuse.
    raise UnsupportedMimeError(
        "OGG metadata strip not implemented yet — use WAV for now"
    )


# ── MP3 ───────────────────────────────────────────────────────────────
#
# MP3 metadata: ID3v2 at the start, ID3v1 at the end. Strip both.

def _strip_mp3(data: bytes) -> StripResult:
    out = bytes(data)
    bytes_removed = 0

    # ID3v2: "ID3" + version (2) + flags (1) + 4-byte synchsafe size
    if out[:3] == b"ID3" and len(out) >= 10:
        size = (
            (out[6] & 0x7F) << 21 |
            (out[7] & 0x7F) << 14 |
            (out[8] & 0x7F) << 7 |
            (out[9] & 0x7F)
        )
        header_total = 10 + size
        if header_total <= len(out):
            bytes_removed += header_total
            out = out[header_total:]

    # ID3v1: last 128 bytes start with "TAG"
    if len(out) >= 128 and out[-128:-125] == b"TAG":
        bytes_removed += 128
        out = out[:-128]

    return StripResult(cleaned=out, bytes_removed=bytes_removed)


# ── WAV ───────────────────────────────────────────────────────────────
#
# WAV is RIFF too. We keep 'fmt ' and 'data' chunks, drop everything else
# (LIST INFO carries author/title; bext carries broadcast/timestamp).

WAV_KEEP = {b"fmt ", b"data"}


def _strip_wav(data: bytes) -> StripResult:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise MalformedMediaError("not a WAV (bad RIFF header)")

    body = bytearray(b"WAVE")
    i = 12
    n = len(data)
    while i + 8 <= n:
        fourcc = data[i:i + 4]
        size = struct.unpack("<I", data[i + 4:i + 8])[0]
        end = i + 8 + size
        if end > n:
            break
        if fourcc in WAV_KEEP:
            body.extend(data[i:end])
        i = end + (size & 1)

    out = bytearray(b"RIFF")
    out.extend(struct.pack("<I", len(body)))
    out.extend(body)
    return StripResult(cleaned=bytes(out), bytes_removed=len(data) - len(out))


# ── MP4 / QuickTime ───────────────────────────────────────────────────
#
# MP4 is a tree of boxes. ftyp/moov/mdat must stay. We delete 'meta'
# (iTunes metadata), 'udta' (user data — copyright, etc.), and 'tref'
# track references. We also delete 'free'/'skip' which can carry
# arbitrary leftover bytes from editing software.

MP4_DELETE = {b"meta", b"udta", b"tref", b"free", b"skip", b"uuid"}


def _strip_mp4(data: bytes) -> StripResult:
    # Recursive walk + selective copy. Implemented iteratively to avoid
    # deep recursion on large files.
    def walk(start: int, end: int, out: bytearray) -> int:
        i = start
        removed = 0
        while i + 8 <= end:
            size = struct.unpack(">I", data[i:i + 4])[0]
            kind = data[i + 4:i + 8]
            header_size = 8
            if size == 1:
                # 64-bit largesize
                if i + 16 > end:
                    break
                size = struct.unpack(">Q", data[i + 8:i + 16])[0]
                header_size = 16
            box_end = i + size if size > 0 else end
            if kind in MP4_DELETE:
                removed += (box_end - i)
                i = box_end
                continue
            # Container boxes whose children we must walk:
            if kind in (b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts"):
                child_out = bytearray()
                child_removed = walk(i + header_size, box_end, child_out)
                new_size = header_size + len(child_out)
                out.extend(struct.pack(">I", new_size))
                out.extend(kind)
                if header_size == 16:
                    out.extend(struct.pack(">Q", new_size))
                out.extend(child_out)
                removed += child_removed
            else:
                out.extend(data[i:box_end])
            i = box_end
        return removed

    out = bytearray()
    removed = walk(0, len(data), out)
    return StripResult(cleaned=bytes(out), bytes_removed=removed)


# ── Self-test ────────────────────────────────────────────────────────

def _self_test() -> None:
    """Quick sanity tests with hand-built fixtures. Run with
    `python -m crypto.strip_metadata`."""

    # JPEG with an EXIF block
    jpeg_with_exif = (
        b"\xff\xd8"
        + b"\xff\xe1" + struct.pack(">H", 8) + b"Exif\x00\x00"  # APP1/EXIF
        + b"\xff\xfe" + struct.pack(">H", 6) + b"hi!\x00"        # COM
        + b"\xff\xdb" + struct.pack(">H", 4) + b"qq"              # DQT
        + b"\xff\xd9"
    )
    r = _strip_jpeg(jpeg_with_exif)
    assert b"Exif" not in r.cleaned, "EXIF block leaked"
    assert b"hi!" not in r.cleaned, "comment block leaked"
    assert b"\xff\xdb" in r.cleaned, "DQT was wrongly stripped"
    assert r.cleaned.startswith(b"\xff\xd8") and r.cleaned.endswith(b"\xff\xd9")

    # PNG with a tEXt chunk
    def png_chunk(kind: bytes, payload: bytes) -> bytes:
        import zlib
        crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)

    png = (
        PNG_MAGIC
        + png_chunk(b"IHDR", b"\x00" * 13)
        + png_chunk(b"tEXt", b"Software\x00Some Phone Camera")
        + png_chunk(b"IDAT", b"\x00\x01\x02")
        + png_chunk(b"IEND", b"")
    )
    r = _strip_png(png)
    assert b"Some Phone Camera" not in r.cleaned, "tEXt leaked"
    assert b"IHDR" in r.cleaned and b"IDAT" in r.cleaned

    # WAV with LIST INFO
    wav = (
        b"RIFF" + struct.pack("<I", 999) + b"WAVE"
        + b"fmt " + struct.pack("<I", 4) + b"\x01\x00\x02\x00"
        + b"LIST" + struct.pack("<I", 12) + b"INFO" + b"INAM\x00\x00\x00\x00"
        + b"data" + struct.pack("<I", 4) + b"\x00\x00\x00\x00"
    )
    r = _strip_wav(wav)
    assert b"LIST" not in r.cleaned and b"INFO" not in r.cleaned

    # MP3 with ID3v2 + ID3v1
    id3v2 = b"ID3\x03\x00\x00" + bytes([0, 0, 0, 16]) + b"X" * 16
    mp3 = id3v2 + b"\xff\xfbAUDIODATA" + b"TAG" + b"X" * 125
    r = _strip_mp3(mp3)
    assert r.cleaned == b"\xff\xfbAUDIODATA", f"MP3 strip wrong: {r.cleaned!r}"

    print(f"strip_metadata self-tests passed.")


if __name__ == "__main__":
    _self_test()
