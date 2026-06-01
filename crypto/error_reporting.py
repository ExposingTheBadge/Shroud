"""
SHROUD anonymous error reporting.

Clients catch uncaught exceptions, scrub all PII out of the report,
seal the result to the operator's diagnostics pubkey, and submit it
through the relay. The relay queues sealed reports under a well-known
routing tag the operator polls; the operator decrypts privately and
triages.

Properties:
  - Rule 1: report rides a sealed envelope; relay sees only opaque
    bytes. No sender device_id.
  - Rule 2: routing tag is derived from the operator's diagnostics
    pubkey + a fixed pair_id (0). All clients write to the same
    bucket; the operator polls the same bucket. Server cannot tell
    one report from another beyond "some client filed a report".
  - Rule 3: PII scrubber removes usernames, device IDs, paths,
    addresses, UUIDs, and anything matching a heuristic identifier
    pattern before sealing.

The operator publishes a static JSON manifest at a well-known URL
(e.g. https://shroud.fuseobd.com/operator.json) containing:

::

    {
      "diagnostics_pubkey_hex": "<32 byte X25519 pubkey>",
      "expires_at": <unix ts>,
      "sig_hex": "<ed25519 sig over the canonicalized object>"
    }

Clients pin the operator's Ed25519 identity key at install time and
verify the diagnostics pubkey is signed by it before using.

Wire format (plaintext, before sealing)::

    {
      "schema":      "shroud.diag.v1",
      "ts":          <unix sec>,
      "app":         "shroud-android" | "shroud-windows" | "shroud-ios" | ...
      "app_version": "2.5.0",
      "os":          "Android 14 / Windows 11 / iOS 17 / Linux 6.7",
      "kind":        "crash" | "assert" | "log" | "feature",
      "message":     "<scrubbed exception message>",
      "stack":       "<scrubbed stack trace>",
      "context":     {<extra k/v scrubbed before insertion>}
    }
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

from .anon_routing import seal, routing_tag, pair_id, epoch_for


SCHEMA_VERSION = "shroud.diag.v1"
DIAG_PAIR_ID = 0  # well-known: all clients use 0 so the operator can
                  # poll a single bucket without knowing the senders


# ── PII scrubber ─────────────────────────────────────────────────────


# Regexes for identifying patterns we want to redact from stack traces
# and free-text fields. Pre-compiled for speed.
_PATTERNS = [
    # UUIDs (deviceIDs etc.) — 8-4-4-4-12 hex
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
     "<UUID>"),
    # Long hex strings (>=24 chars) — pubkeys, hashes, derived ids
    (re.compile(r"\b[0-9a-fA-F]{24,}\b"), "<HEX>"),
    # Email addresses
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b"), "<EMAIL>"),
    # IPv4 addresses
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IPV4>"),
    # IPv6 addresses (simplified)
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}\b"), "<IPV6>"),
    # Windows paths starting with C:\Users\<name> — keep the structure but drop the name
    (re.compile(r"([A-Za-z]:\\Users\\)[^\\\s\"']+"), r"\1<USER>"),
    # POSIX user paths /home/<name> or /Users/<name>
    (re.compile(r"(/(?:home|Users)/)[^/\s\"']+"), r"\1<USER>"),
    # Android paths /data/data/com.shroud.client/files/... keep the package, redact the rest beyond a depth
    (re.compile(r"(/data/(?:data|user/\d+)/[\w.]+/)[\w./-]+"), r"\1<DATA>"),
    # JWTs (three base64url segments separated by dots, long)
    (re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b"), "<JWT>"),
    # Phone numbers (very loose; matches +1 555-555-5555 etc.)
    (re.compile(r"\+?\d[\d\s().-]{7,}\d"), "<PHONE>"),
]


def scrub(text: str) -> str:
    """Replace every match of every pattern with the corresponding
    placeholder. Returns the redacted text."""
    if not text:
        return text
    out = text
    for regex, replacement in _PATTERNS:
        out = regex.sub(replacement, out)
    return out


def scrub_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively scrub strings inside a dict. Lists and nested dicts
    are walked; non-string scalars are passed through."""
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            out[k] = scrub(v)
        elif isinstance(v, dict):
            out[k] = scrub_dict(v)
        elif isinstance(v, list):
            out[k] = [scrub(x) if isinstance(x, str) else x for x in v]
        else:
            out[k] = v
    return out


# ── Report builder ───────────────────────────────────────────────────


@dataclass
class DiagnosticReport:
    app: str
    app_version: str
    os: str
    kind: str            # "crash" | "assert" | "log" | "feature"
    message: str
    stack: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    ts: int = field(default_factory=lambda: int(time.time()))
    schema: str = SCHEMA_VERSION

    def serialize(self) -> bytes:
        """Build the wire-format JSON bytes, scrubbing every text field
        on the way out."""
        body = {
            "schema":      self.schema,
            "ts":          self.ts,
            "app":         self.app,                # not scrubbed: known string
            "app_version": self.app_version,        # not scrubbed: known string
            "os":          self.os,                 # not scrubbed: short version string
            "kind":        self.kind,
            "message":     scrub(self.message),
            "stack":       scrub(self.stack),
            "context":     scrub_dict(self.context),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


# ── Sealing for delivery ─────────────────────────────────────────────


@dataclass
class OperatorManifest:
    """The pinned operator-published diagnostics endpoint config."""
    diagnostics_pubkey_hex: str
    expires_at: int
    sig_hex: str = ""


def seal_report(
    report: DiagnosticReport,
    operator_diag_pubkey: bytes,
) -> tuple[bytes, bytes]:
    """Build the sealed bytes + routing tag to which the report should
    be POSTed.

    Returns ``(routing_tag_bytes, sealed_envelope_bytes)``.
    """
    if len(operator_diag_pubkey) != 32:
        raise ValueError("operator diagnostics pubkey must be 32 bytes")

    body = report.serialize()
    sealed = seal(body, operator_diag_pubkey)

    # The routing tag is derived from a fixed pair (0) so all reports
    # land in the same operator bucket. Shared "root" is the operator's
    # diagnostics pubkey itself — known to clients and operator.
    tag = routing_tag(operator_diag_pubkey, DIAG_PAIR_ID, epoch_for())
    return tag, sealed


def fetch_window_tags_for_operator(
    operator_diag_pubkey: bytes,
    window: int = 24,
) -> list[bytes]:
    """Operator-side: enumerate the routing tags for the last ``window``
    epochs so the operator can drain pending reports."""
    base = epoch_for()
    return [
        routing_tag(operator_diag_pubkey, DIAG_PAIR_ID, e)
        for e in range(base - window, base + 1)
    ]


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Scrubber covers the main classes of identifiers
    text = (
        "User abc-1234-foo from 192.168.1.5 hit a NullPointerException "
        "at /home/brent/projects/shroud/main.cpp:42 with token "
        "deadbeef" + "ab" * 40 + " and uuid 12345678-1234-1234-1234-123456789012"
    )
    s = scrub(text)
    assert "192.168.1.5" not in s
    assert "/home/brent/" not in s
    assert "deadbeef" + "ab" * 40 not in s
    assert "12345678-1234-1234-1234-123456789012" not in s

    # Dict scrubber walks recursively
    d = scrub_dict({
        "user": "alice@example.com",
        "nested": {"path": r"C:\Users\brent\Documents"},
        "ids": ["12345678-1234-1234-1234-123456789012", "static"],
        "count": 42,
    })
    assert "alice@example.com" not in json.dumps(d)
    assert "brent" not in json.dumps(d)
    assert d["count"] == 42
    assert d["ids"][1] == "static"

    # Round-trip: build, seal, recover via X25519 keypair
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from .anon_routing import unseal as _unseal
    op_priv = X25519PrivateKey.generate()
    op_pub = op_priv.public_key().public_bytes_raw()
    op_sk = op_priv.private_bytes_raw()

    rep = DiagnosticReport(
        app="shroud-test",
        app_version="2.5.0",
        os="Linux 6.7",
        kind="crash",
        message="NullPointerException at /home/brent/main.cpp:42",
        stack="java.lang.NullPointerException\n  at /home/brent/foo.kt:99",
        context={"selected_chat_id": "12345678-1234-1234-1234-123456789012"},
    )

    tag, sealed = seal_report(rep, op_pub)
    assert len(tag) == 32
    plaintext = _unseal(sealed, op_sk)
    body = json.loads(plaintext)
    assert "brent" not in plaintext.decode()
    assert "12345678-1234-1234-1234-123456789012" not in plaintext.decode()
    assert body["app"] == "shroud-test"
    assert body["kind"] == "crash"

    # Operator-side: poll window
    tags = fetch_window_tags_for_operator(op_pub, window=3)
    assert len(tags) == 4  # window + 1 (inclusive)
    assert tag in tags

    print("error_reporting self-tests passed.")


if __name__ == "__main__":
    _self_test()
