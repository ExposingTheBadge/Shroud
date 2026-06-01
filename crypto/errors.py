"""
SHROUD system-wide error code catalog.

Every error surfaced to a human — in an HTTP response detail, in a
client dialog, in a log file, in the admin event stream, in a CLI tool
exit — carries one of these codes. A user reporting a bug can quote
the code and the operator can look up the exact failure mode without
guessing.

Code shape:  E + 1-letter category + 3-digit serial.

Categories
----------
A — authentication / session / registration
B — bans / abuse / rate-limit
C — crypto: ECDH / ratchet / X25519 / AES-GCM / Ed25519 / PQ hybrid
D — diagnostics / error reports
F — federation / gossip / peer roster / operator manifest
M — messaging: send / fetch / sealed envelopes / routing tags
N — network / transport / TLS / WinHTTP / proxy
S — server-internal: DB, config, identity, lifecycle
T — Tor / SOCKS / onion service
U — user-facing client (UI / install / update / version mismatch)
X — catch-all unexpected

Each entry exposes:

    code      — "EA001" etc; opaque to humans but stable forever
    http      — HTTP status the server uses when surfacing this
    title     — short, human-readable summary (one line, no period)
    detail    — sentence the user sees in dialogs / docs

How to use
----------

Server (FastAPI):

    from crypto.errors import errors, raise_http
    raise_http(errors.A001_BAD_SESSION)            # default HTTP from entry
    raise_http(errors.A002_DECRYPT_FAILED,
               extra={"hint": "re-key-exchange"}) # extra fields merged in

Client / CLI / docs:

    # Reverse lookup
    e = errors.by_code("EA002")
    print(e.code, e.title, e.detail)

Stability
---------
Code numbers NEVER change once shipped. Removing an entry is OK only
when no released client references it. Adding entries is always safe.
Keep this module pure-stdlib so every language port can compile a
parallel table from the same source of truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class Err:
    code: str
    http: int
    title: str
    detail: str

    def as_dict(self, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "error_code": self.code,
            "title":      self.title,
            "detail":     self.detail,
        }
        if extra:
            out.update(extra)
        return out


class _Catalog:
    """Ordered catalog. Attribute access (errors.A001_BAD_SESSION) returns
    the Err instance. Numeric/string lookup via by_code()."""

    def __init__(self) -> None:
        self._by_code: Dict[str, Err] = {}

    def add(self, attr: str, code: str, http: int, title: str, detail: str) -> Err:
        if code in self._by_code:
            raise ValueError(f"duplicate error code {code}")
        e = Err(code=code, http=http, title=title, detail=detail)
        self._by_code[code] = e
        setattr(self, attr, e)
        return e

    def by_code(self, code: str) -> Err | None:
        return self._by_code.get(code.upper().strip())

    def all(self) -> list[Err]:
        return list(self._by_code.values())


errors = _Catalog()

# ── A: authentication, session, registration ─────────────────────────
errors.add("A001_BAD_SESSION",            "EA001", 401,
           "Invalid or expired session",
           "The auth session token was not found on the server. Re-run "
           "the key-exchange step and try again.")
errors.add("A002_DECRYPT_FAILED",         "EA002", 400,
           "Auth payload decryption failed",
           "The server could not decrypt the auth payload. Most often "
           "this means the client and server derived different session "
           "keys — check that both sides use the same KDF label "
           "(\"SHROUD-AUTH-v1\", 14 bytes, no trailing NUL).")
errors.add("A003_BAD_CREDENTIALS",        "EA003", 401,
           "Invalid credentials",
           "Username or password did not match a registered account.")
errors.add("A004_REGISTRATION_DISABLED",  "EA004", 403,
           "Registration disabled",
           "New-account registration is currently disabled by the "
           "operator.")
errors.add("A005_USERNAME_TAKEN",         "EA005", 409,
           "Username already registered",
           "That username is already in use. Pick a different one.")
errors.add("A006_PQ_UNAVAILABLE",         "EA006", 503,
           "PQ hybrid handshake unavailable",
           "The server isn't built with liboqs, so the post-quantum "
           "hybrid key exchange is not available. Clients should fall "
           "back to the v1 classical handshake.")
errors.add("A007_ATTESTATION_FAILED",     "EA007", 502,
           "Server attestation signature did not verify",
           "The server's PQ handshake signature did not verify against "
           "the pinned server identity. Treat as a MITM-grade error — "
           "do not enter credentials.")
errors.add("A008_DEVICE_LIMIT",           "EA008", 400,
           "Per-user device limit reached",
           "This account already has the maximum number of devices "
           "registered. Remove an old device before linking a new one.")
errors.add("A009_KEY_DERIVE_FAILED",      "EA009", 500,
           "Auth key derivation failed",
           "The server could not derive the session key from the "
           "client's ECDH share. Usually means a malformed client "
           "public-key blob.")

# ── B: bans, abuse, rate-limit ───────────────────────────────────────
errors.add("B001_BANNED_USERNAME",        "EB001", 403,
           "Account banned",
           "The username is banned. If the operator set a reason, it is "
           "returned in the response body.")
errors.add("B002_BANNED_HWID",            "EB002", 403,
           "Hardware banned",
           "The hardware ID associated with this device is banned, even "
           "though the username may not be.")
errors.add("B003_BANNED_IP",              "EB003", 403,
           "IP address banned",
           "Connections from this IP are temporarily blocked due to too "
           "many failed authentication attempts. Wait an hour or use a "
           "different network.")
errors.add("B004_RATE_LIMITED",           "EB004", 429,
           "Too many requests",
           "You're sending too many requests to this endpoint. Back off "
           "and try again in a few seconds.")
errors.add("B005_MAINTENANCE",            "EB005", 503,
           "Server in maintenance mode",
           "The operator put the relay in maintenance. Sending is paused "
           "until the relay returns to normal operation.")

# ── C: crypto ────────────────────────────────────────────────────────
errors.add("C001_BAD_PUBKEY",             "EC001", 400,
           "Invalid public-key format",
           "The supplied public key could not be parsed as a valid key "
           "of the expected curve / algorithm.")
errors.add("C002_ECDH_FAILED",            "EC002", 500,
           "ECDH shared-secret derivation failed",
           "The ECDH operation between the server and client keys did "
           "not produce a shared secret.")
errors.add("C003_AES_GCM_TAG_MISMATCH",   "EC003", 400,
           "AES-GCM authentication tag mismatch",
           "The AES-GCM tag did not verify. Either the ciphertext was "
           "tampered with in transit or the key derivation diverged "
           "between sender and receiver.")
errors.add("C004_BAD_SEAL_VERSION",       "EC004", 400,
           "Unknown sealed-envelope version",
           "The sealed envelope's version byte does not match any "
           "version this server understands.")
errors.add("C005_SEAL_TOO_SHORT",         "EC005", 400,
           "Sealed envelope is too short",
           "The sealed envelope is smaller than the minimum size for "
           "the declared version. Most likely a truncated upload.")
errors.add("C006_RATCHET_OOO",            "EC006", 400,
           "Ratchet message out of order",
           "A Double-Ratchet message arrived with a counter the receiver "
           "no longer has skipped keys for. Drop the message; the next "
           "ratchet rotation will resync.")
errors.add("C007_BAD_SIGNATURE",          "EC007", 400,
           "Signature verification failed",
           "An Ed25519 / ML-DSA-87 / SPHINCS+ signature did not verify "
           "against the pinned public key.")

# ── D: diagnostics ───────────────────────────────────────────────────
errors.add("D001_REPORT_REJECTED",        "ED001", 400,
           "Diagnostic report rejected",
           "The diagnostic report did not match the wire format or "
           "exceeded the size cap. Drop it client-side rather than "
           "retrying.")
errors.add("D002_NO_DIAG_KEY",            "ED002", 503,
           "Operator diagnostics key not provisioned",
           "The operator hasn't published a diagnostics public key yet. "
           "Anonymous error reports cannot be sealed.")

# ── F: federation / manifests ────────────────────────────────────────
errors.add("F001_FED_DISABLED",           "EF001", 503,
           "Federation disabled on this relay",
           "The relay was started without SHROUD_FEDERATION=1. Gossip "
           "and peer endpoints are unavailable.")
errors.add("F002_PEER_NOT_TRUSTED",       "EF002", 403,
           "Peer pubkey not pre-approved",
           "Each federation peer must be operator-vetted by inserting "
           "its Ed25519 pubkey into the federation_peers table. The "
           "incoming pubkey is not in the local roster.")
errors.add("F003_PEER_SIG_INVALID",       "EF003", 403,
           "Peer announcement signature invalid",
           "The Ed25519 signature on the peer announcement did not "
           "verify against the pre-approved pubkey.")
errors.add("F004_MANIFEST_MISSING",       "EF004", 404,
           "Operator manifest not provisioned",
           "No signed manifest has been dropped at "
           "SHROUD_MANIFEST_PATH. Clients fall back to the bootstrap "
           "relay URL.")
errors.add("F005_MANIFEST_BAD_JSON",      "EF005", 500,
           "Operator manifest is not valid JSON",
           "The signed manifest on disk failed JSON parsing. The "
           "operator should regenerate it via "
           "tools/build_operator_manifest.py.")
errors.add("F006_MANIFEST_BAD_SIG",       "EF006", 400,
           "Operator manifest signature invalid",
           "The Ed25519 signature on the manifest did not verify "
           "against the pinned manifest pubkey.")
errors.add("F007_MANIFEST_EXPIRED",       "EF007", 410,
           "Operator manifest has expired",
           "The manifest's expires_at is in the past. Clients reject "
           "expired manifests and fall back to the last-known-good copy.")

# ── M: messaging ─────────────────────────────────────────────────────
errors.add("M001_ROUTING_TAG_MISSING",    "EM001", 400,
           "X-Routing-Tag header missing",
           "The sealed-envelope POST didn't include a routing tag. The "
           "server cannot dispatch the message without one.")
errors.add("M002_BAD_PAD_BUCKET",         "EM002", 400,
           "Body is not a valid padded bucket size",
           "Anonymous-routing requests must be padded to one of the "
           "well-known bucket sizes (4096, 65536, 1048576, 16777216).")
errors.add("M003_TAG_OVERFLOW",           "EM003", 400,
           "Too many routing tags in fetch",
           "/messages/fetch-anon accepts at most 1024 tags per call. "
           "Paginate by sub-setting the tag list per request.")
errors.add("M004_TAG_BAD_LENGTH",         "EM004", 400,
           "Routing tag must be exactly 32 bytes hex",
           "Each tag in the fetch list must decode to exactly 32 bytes.")
errors.add("M005_DISK_QUOTA",             "EM005", 507,
           "Relay disk quota exceeded",
           "The relay is at its disk quota. Retain newer messages and "
           "drop older ones until the operator expands storage.")
errors.add("M006_RECIPIENT_UNKNOWN",      "EM006", 404,
           "Recipient device not found",
           "The recipient device_id does not exist on this relay.")

# ── N: network / transport ───────────────────────────────────────────
errors.add("N001_TLS_FLAG_MISSING",       "EN001", 0,
           "Client request was sent without WINHTTP_FLAG_SECURE",
           "The WinHTTP request was opened without the secure flag, so "
           "it negotiated plain HTTP against a TLS-only port. Response "
           "body comes back empty. Build issue, not a runtime error.")
errors.add("N002_RELAY_UNREACHABLE",      "EN002", 0,
           "Relay unreachable",
           "The client could not reach the configured relay URL. Check "
           "network, proxy settings, and that the relay's host:port is "
           "still serving SHROUD.")
errors.add("N003_TIMEOUT",                "EN003", 504,
           "Request timed out",
           "The relay accepted the connection but did not return a "
           "response within the timeout window.")
errors.add("N004_SOCKS_PROXY_BAD",        "EN004", 0,
           "SOCKS proxy unreachable",
           "The configured SOCKS5 proxy (usually a local Tor SOCKS "
           "listener at 127.0.0.1:9050) is not reachable. The client "
           "will fall back to direct connections.")
errors.add("N005_CERT_REJECTED",          "EN005", 0,
           "TLS certificate rejected",
           "WinHTTP refused the server's TLS certificate. Production "
           "relays use self-signed certs by design; ensure the client "
           "is built with the SECURITY_FLAG_IGNORE_* tolerances.")

# ── S: server-internal ───────────────────────────────────────────────
errors.add("S001_IDENTITY_UNAVAILABLE",   "ES001", 503,
           "Server long-term identity not loaded",
           "The relay's SERVER_IDENTITY did not load on startup. Most "
           "likely a missing or unreadable identity file. The relay "
           "will not accept any encrypted requests until this is "
           "fixed.")
errors.add("S002_DB_LOCKED",              "ES002", 503,
           "Database locked",
           "SQLite reported the database as locked. Usually a transient "
           "issue; retry in a few seconds.")
errors.add("S003_CONFIG_INVALID",         "ES003", 500,
           "Server configuration invalid",
           "A required environment variable or settings entry is "
           "missing or malformed.")

# ── T: Tor / SOCKS / onion ───────────────────────────────────────────
errors.add("T001_TOR_NOT_RUNNING",        "ET001", 0,
           "Local Tor daemon not reachable",
           "The client wanted to ride a .onion endpoint but the local "
           "Tor SOCKS5 listener is not running. Start Tor (Tor Browser "
           "or system tor) or disable prefer_tor in settings.")
errors.add("T002_ONION_UNREACHABLE",      "ET002", 0,
           "Onion endpoint unreachable through Tor",
           "The client could reach the local Tor SOCKS but the onion "
           "endpoint did not respond. The hidden service may be down.")

# ── U: user-facing client ────────────────────────────────────────────
errors.add("U001_VERSION_MISMATCH",       "EU001", 0,
           "Client version older than relay's minimum_supported",
           "Update the client to at least the version returned by "
           "/api/v1/version as minimum_supported.")
errors.add("U002_UPDATE_AVAILABLE",       "EU002", 0,
           "Client update available",
           "A newer release is available on the configured release URL.")
errors.add("U003_BAD_INSTALL_PATH",       "EU003", 0,
           "Installation path not writable",
           "The MSI installer could not write to the chosen install "
           "path. Run as administrator or choose a writable location.")
errors.add("U004_RELAY_BOOTSTRAP_MISSING", "EU004", 0,
           "Relay address not configured",
           "The client has no relay address. Set one via Settings or "
           "by accepting the bundled bootstrap address.")

# ── X: catch-all ─────────────────────────────────────────────────────
errors.add("X001_INTERNAL",               "EX001", 500,
           "Internal server error",
           "An uncaught exception leaked. The audit log has the full "
           "traceback; file an anonymous diagnostic report via "
           "/api/v1/diagnostics/report.")
errors.add("X999_UNKNOWN",                "EX999", 0,
           "Unknown error",
           "An error was raised but did not carry one of the catalogued "
           "codes. Treat as a bug in whatever component raised it.")


# ── Helpers ──────────────────────────────────────────────────────────


def raise_http(err: Err, extra: Dict[str, Any] | None = None) -> None:
    """Raise an HTTPException with this error's catalog entry as detail.

    Importing FastAPI is lazy so this module stays portable for client
    / CLI / language-port use."""
    from fastapi import HTTPException
    status = err.http or 500
    raise HTTPException(status_code=status, detail=err.as_dict(extra))


def _self_test() -> None:
    # Codes are unique and well-formed
    seen: set[str] = set()
    for e in errors.all():
        assert e.code not in seen, f"duplicate {e.code}"
        seen.add(e.code)
        assert e.code.startswith("E") and len(e.code) == 5 and e.code[2:].isdigit(), e.code
        assert e.title and "\n" not in e.title
        assert e.detail
    # Reverse lookup
    assert errors.by_code("EA001") is errors.A001_BAD_SESSION
    assert errors.by_code("ea001") is errors.A001_BAD_SESSION
    assert errors.by_code("XYZ") is None
    print(f"errors catalog: {len(errors.all())} entries OK")


if __name__ == "__main__":
    _self_test()
