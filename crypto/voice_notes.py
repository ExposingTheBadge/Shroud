"""
SHROUD voice notes — recorded audio messages.

A voice note is just an audio attachment carried inside a sealed
envelope. This module:

  - Validates the supplied audio container against the metadata-strip
    pipeline (``crypto.strip_metadata``) so EXIF-style identifiers in
    audio containers (ID3, LIST/INFO, Vorbis comments — see
    strip_metadata.py for the per-format coverage) cannot leak.
  - Extracts duration metadata client-side so the recipient UI can
    show "0:32" without having to decode the entire audio stream.
  - Builds the JSON payload that goes inside the sealed envelope.

Recipient side reverses the process: decrypts the sealed envelope,
extracts the audio bytes + duration, hands the audio bytes to the
platform audio decoder.

Recommended formats
-------------------

WAV (audio/wav)
  Smallest dependency surface. Fully supported by strip_metadata. Best
  for short notes; bandwidth heavy.

Opus in OGG (audio/ogg)
  Modern, compact. strip_metadata's OGG pipeline is currently
  partial — voice_notes refuses OGG until that's finished, with a
  clear error so the caller can fall back to WAV.

WebM with Opus (audio/webm)
  Future. Needs strip_metadata support for the Matroska container
  family; planned alongside the GTK4 Linux client work.

Rule compliance
---------------
  - Rule 1+2: ride the standard sealed envelope.
  - Rule 3: strip_metadata.strip() is mandatory on the audio bytes
    before they're inserted into the payload. The wrapper refuses
    formats that strip_metadata can't fully sanitize, so the rule
    cannot be bypassed by passing a novel container.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass

from .strip_metadata import strip, UnsupportedMimeError, MalformedMediaError


# ── Public payload schema ────────────────────────────────────────────


SHROUD_MEDIA_VOICE_NOTE = "shroud.media.voice_note"


@dataclass
class VoiceNotePayload:
    audio_mime: str            # validated, currently only "audio/wav"
    audio_bytes: bytes         # metadata-stripped audio
    duration_ms: int           # rounded duration in milliseconds
    sample_rate: int           # for client-side UI / playback hints
    channels: int

    def to_json(self) -> bytes:
        import base64
        d = {
            "type":        SHROUD_MEDIA_VOICE_NOTE,
            "mime":        self.audio_mime,
            "audio_b64":   base64.b64encode(self.audio_bytes).decode("ascii"),
            "duration_ms": int(self.duration_ms),
            "sample_rate": int(self.sample_rate),
            "channels":    int(self.channels),
        }
        return json.dumps(d, sort_keys=True).encode()

    @classmethod
    def from_json(cls, blob: bytes) -> "VoiceNotePayload":
        import base64
        d = json.loads(blob.decode("utf-8"))
        if d.get("type") != SHROUD_MEDIA_VOICE_NOTE:
            raise ValueError("not a SHROUD voice note payload")
        return cls(
            audio_mime=d["mime"],
            audio_bytes=base64.b64decode(d["audio_b64"]),
            duration_ms=int(d["duration_ms"]),
            sample_rate=int(d["sample_rate"]),
            channels=int(d["channels"]),
        )


# ── Sender-side: prepare a voice note ────────────────────────────────


SUPPORTED_INPUT_MIMES = ("audio/wav", "audio/x-wav")


def build(raw_audio: bytes, mime: str) -> VoiceNotePayload:
    """Build a voice-note payload from raw recorded audio bytes.

    Pipeline: validate mime -> strip_metadata -> parse duration / format
    properties -> return payload object ready for sealing.
    """
    m = mime.lower().strip()
    if m not in SUPPORTED_INPUT_MIMES:
        raise UnsupportedMimeError(
            f"voice notes currently only accept WAV (got {mime}); "
            "OGG support tracked in strip_metadata.py"
        )

    cleaned = strip(raw_audio, m).cleaned
    rate, channels, duration_ms = _wav_properties(cleaned)
    return VoiceNotePayload(
        audio_mime="audio/wav",
        audio_bytes=cleaned,
        duration_ms=duration_ms,
        sample_rate=rate,
        channels=channels,
    )


# ── WAV property extraction ──────────────────────────────────────────


def _wav_properties(wav: bytes) -> tuple[int, int, int]:
    """Return (sample_rate_hz, channels, duration_ms).

    Implements just enough RIFF/WAVE parsing to read the 'fmt ' and
    'data' chunks. Refuses non-PCM formats (audio_format != 1) since
    voice notes shouldn't carry compressed payloads here.
    """
    if len(wav) < 12 or wav[:4] != b"RIFF" or wav[8:12] != b"WAVE":
        raise MalformedMediaError("not a WAV (bad RIFF header)")

    i = 12
    rate = 0
    channels = 0
    bits_per_sample = 0
    data_len = 0
    n = len(wav)
    while i + 8 <= n:
        fourcc = wav[i:i + 4]
        size = struct.unpack("<I", wav[i + 4:i + 8])[0]
        if fourcc == b"fmt ":
            audio_format = struct.unpack("<H", wav[i + 8:i + 10])[0]
            channels     = struct.unpack("<H", wav[i + 10:i + 12])[0]
            rate         = struct.unpack("<I", wav[i + 12:i + 16])[0]
            bits_per_sample = struct.unpack("<H", wav[i + 22:i + 24])[0]
            if audio_format != 1:
                raise MalformedMediaError(
                    f"WAV audio_format {audio_format} not supported (PCM only)"
                )
        elif fourcc == b"data":
            data_len = size
        i = i + 8 + size + (size & 1)

    if rate == 0 or channels == 0 or bits_per_sample == 0:
        raise MalformedMediaError("WAV header missing rate/channels/bits")

    bytes_per_sample = bits_per_sample // 8
    if bytes_per_sample == 0 or data_len == 0:
        return rate, channels, 0
    samples = data_len // (channels * bytes_per_sample)
    duration_ms = int(samples * 1000 / rate)
    return rate, channels, duration_ms


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Build a tiny synthetic WAV (sine wave-ish, doesn't matter).
    # 8000 Hz, mono, 16-bit, 100 ms = 800 samples * 2 bytes = 1600 bytes data
    rate = 8000
    channels = 1
    bps = 16
    num_samples = 800
    data = b"\x00\x10" * num_samples
    fmt_chunk = struct.pack("<HHIIHH",
        1,                                  # PCM
        channels,
        rate,
        rate * channels * (bps // 8),       # byte rate
        channels * (bps // 8),              # block align
        bps,
    )
    wav = (
        b"RIFF" + struct.pack("<I", 4 + 8 + len(fmt_chunk) + 8 + len(data)) + b"WAVE"
        + b"fmt " + struct.pack("<I", len(fmt_chunk)) + fmt_chunk
        + b"LIST" + struct.pack("<I", 12) + b"INFO" + b"INAM\x00\x00\x00\x00"  # leaky
        + b"data" + struct.pack("<I", len(data)) + data
    )

    pl = build(wav, "audio/wav")
    assert pl.sample_rate == rate
    assert pl.channels == channels
    # 800 samples / 8000 Hz = 100 ms
    assert pl.duration_ms == 100
    # LIST/INFO leak removed by strip_metadata
    assert b"LIST" not in pl.audio_bytes
    assert b"INFO" not in pl.audio_bytes

    # JSON round-trip
    blob = pl.to_json()
    parsed = VoiceNotePayload.from_json(blob)
    assert parsed.duration_ms == pl.duration_ms
    assert parsed.audio_bytes == pl.audio_bytes

    # Refuse unsupported format
    try:
        build(b"OggS\x00...", "audio/ogg")
        raise AssertionError("OGG should be refused for now")
    except UnsupportedMimeError:
        pass

    print("voice_notes self-tests passed.")


if __name__ == "__main__":
    _self_test()
