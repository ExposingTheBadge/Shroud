"""
SHROUD At-Rest Field Encryption
==================================
Wraps a 32-byte master key (loaded from server/data.key or env var
SHROUD_DATA_KEY) around AES-256-GCM column-level encryption. Used for
columns whose contents leak metadata if the SQLite file is exfiltrated:

  - friend_requests.reason
  - group_invites.reason
  - devices.hwid
  - admin_sessions.ip
  - admin_sessions.user_agent

Format on disk:
  blob = magic 'AR1\\0' || nonce(12) || ct(N) || tag(16)
  Empty / NULL inputs round-trip as empty strings.

The master key never leaves the server. If the SQLite file is stolen but
the key isn't, none of these fields are recoverable.
"""
from __future__ import annotations
import os, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"AR1\x00"
DATA_KEY_LEN = 32


def load_or_create_data_key(path: str) -> bytes:
    """Load the master key from <path>, or create one if missing.
    Honors the SHROUD_DATA_KEY env var (hex string) when set."""
    env = os.environ.get("SHROUD_DATA_KEY", "")
    if env:
        try:
            k = bytes.fromhex(env)
            if len(k) == DATA_KEY_LEN: return k
        except Exception:
            pass
    if os.path.exists(path):
        with open(path, "rb") as f:
            k = f.read()
        if len(k) == DATA_KEY_LEN: return k
    k = os.urandom(DATA_KEY_LEN)
    with open(path, "wb") as f:
        f.write(k)
    try: os.chmod(path, 0o600)
    except Exception: pass
    return k


def encrypt(key: bytes, plaintext: str) -> bytes:
    if plaintext is None or plaintext == "": return b""
    pt = plaintext.encode("utf-8")
    nonce = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(nonce, pt, None)
    return MAGIC + nonce + ct_tag


def decrypt(key: bytes, blob) -> str:
    """Decrypt; returns plaintext str. If blob isn't our wrapped format
    (e.g. legacy plaintext), returns it as-is to keep migrations smooth."""
    if blob is None: return ""
    if isinstance(blob, str): return blob
    if len(blob) < 4 + 12 + 16 or blob[:4] != MAGIC:
        try: return blob.decode("utf-8", errors="replace")
        except Exception: return ""
    nonce = blob[4:16]
    ct = blob[16:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def self_test() -> bool:
    k = os.urandom(32)
    for s in ("hello", "", "with \U0001f389 emoji", "a" * 4096):
        if decrypt(k, encrypt(k, s)) != s: return False
    # Legacy str passes through
    if decrypt(k, "legacy") != "legacy": return False
    # Empty blob → empty string
    if decrypt(k, b"") != "": return False
    return True


if __name__ == "__main__":
    print("at_rest self-test:", "PASSED" if self_test() else "FAILED")
