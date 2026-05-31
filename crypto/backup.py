"""
SHROUD encrypted backup + restore.

What a backup is
----------------

A backup is a single self-contained file that lets a user:

  - Move their identity + history to a new device without going through
    a multi-device handshake (useful when the old device is dead or
    confiscated and no longer reachable).
  - Restore after a catastrophic local-storage failure.
  - Migrate from one operating system to another (Windows to Linux,
    Android to iOS) preserving conversations.

A backup contains the user's full plaintext message history + identity
keys + contact graph, encrypted under a password the user chooses.
Without the password, the backup is opaque.

File format
-----------

::

    +-------------------+---------+----------+--------+--------+--------+
    | magic   "SHRB"    | ver (1) | argon2id | salt   | nonce  | sealed |
    | 4 bytes           | 0x01    | params   | (32)   | (12)   | body   |
    +-------------------+---------+----------+--------+--------+--------+

  - argon2id params (8 bytes): time_cost (1) || mem_cost_log2 (1) ||
    parallelism (1) || reserved (5)
  - sealed body: AES-256-GCM(payload) with the derived key, 16-byte tag
    is appended (standard GCM output)

The plaintext ``payload`` is a JSON document::

    {
      "schema":         1,
      "exported_at":    1700000000,
      "identity_priv_x25519_hex": "<32 byte>",
      "identity_pub_x25519_hex":  "<32 byte>",
      "identity_priv_ed25519_hex":"<32 byte>",
      "identity_pub_ed25519_hex": "<32 byte>",
      "contacts": [
        {
          "username": "<contact>",
          "pubkey_x25519_hex": "<32 byte>",
          "pubkey_ed25519_hex":"<32 byte>",
          "shared_root_hex":   "<32 byte>",
          "verified":          true
        },
        ...
      ],
      "messages": [
        {"id":"...", "contact":"...", "direction":"in"|"out", "body":"...", "ts":...}
      ]
    }

Rule compliance
---------------
  - Rule 0: backups travel out-of-band of the relay, so a relay
    seizure does not destroy a user's history.
  - Rule 1+2: orthogonal — backups never touch the relay.
  - Rule 3: backup files inherit Rule 3 from the source data; nothing
    is added by the backup itself.

Production callers SHOULD prompt the user for a strong password (the
backup file is brute-forceable if the password is weak), and SHOULD
display the backup's KDF parameters so paranoid users can verify
Argon2id was tuned to current best practice.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


MAGIC = b"SHRB"
VERSION = 0x01
SALT_LEN = 32
NONCE_LEN = 12
GCM_TAG_LEN = 16
HEADER_LEN = 4 + 1 + 8 + SALT_LEN + NONCE_LEN


# ── Argon2id KDF backend ─────────────────────────────────────────────


def _argon2id(password: bytes, salt: bytes,
              time_cost: int, mem_cost_log2: int, parallelism: int) -> bytes:
    """Derive a 32-byte key from password + salt with Argon2id.

    Prefers the ``argon2-cffi`` library (a pure-Python binding to
    libargon2). Falls back to a clearly-weaker PBKDF2-HMAC-SHA512
    derivation when Argon2 is unavailable, and SHOUTS at the caller via
    a warning print. Production SHOULD install argon2-cffi.
    """
    mem_kib = 1 << mem_cost_log2
    try:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=mem_kib,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
        )
    except ImportError:
        import sys
        print(
            "WARNING: argon2-cffi not installed; falling back to PBKDF2-HMAC-SHA512.\n"
            "         Install with: pip install argon2-cffi",
            file=sys.stderr,
        )
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        # PBKDF2 with high iteration count as a less-good fallback
        return PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=600_000,
        ).derive(password)


# ── Default KDF parameters ───────────────────────────────────────────


# OWASP 2023 recommendation for interactive Argon2id:
#   - time_cost: 2
#   - memory:    19 MiB (log2 ~ 14 .. round to 15 -> 32 MiB)
#   - parallel:  1
# We pick a slightly larger memory cost for backup files since the
# user only does this rarely.
DEFAULT_TIME_COST = 3
DEFAULT_MEM_COST_LOG2 = 17  # 2^17 KiB = 128 MiB
DEFAULT_PARALLELISM = 1


# ── Pack / unpack ────────────────────────────────────────────────────


def pack(payload: Dict[str, Any], password: bytes,
         *, time_cost: int = DEFAULT_TIME_COST,
         mem_cost_log2: int = DEFAULT_MEM_COST_LOG2,
         parallelism: int = DEFAULT_PARALLELISM) -> bytes:
    """Serialize + encrypt a backup payload.

    Args:
        payload: the JSON-serializable history bundle to encrypt
        password: the user's chosen password as UTF-8 bytes
        time_cost / mem_cost_log2 / parallelism: Argon2id parameters

    Returns:
        Wire bytes ready to save to disk / hand off / store in cloud.
    """
    if not (1 <= time_cost <= 255):
        raise ValueError("time_cost must be 1..255")
    if not (10 <= mem_cost_log2 <= 31):
        raise ValueError("mem_cost_log2 must be 10..31")
    if not (1 <= parallelism <= 255):
        raise ValueError("parallelism must be 1..255")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _argon2id(password, salt, time_cost, mem_cost_log2, parallelism)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aead = AESGCM(key)
    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    # Bind the KDF parameters into the AAD so swapping them tamper-fails.
    aad = struct.pack(">BBBxxxxx", time_cost, mem_cost_log2, parallelism)
    ct_and_tag = aead.encrypt(nonce, plaintext, aad)

    params_blob = aad   # 8 bytes
    return (
        MAGIC
        + bytes([VERSION])
        + params_blob
        + salt
        + nonce
        + ct_and_tag
    )


def unpack(blob: bytes, password: bytes) -> Dict[str, Any]:
    """Reverse of ``pack``. Raises on tamper or bad password.

    Returns the decrypted JSON-loaded payload dict.
    """
    if len(blob) < HEADER_LEN + GCM_TAG_LEN:
        raise ValueError("backup blob too short")
    if blob[:4] != MAGIC:
        raise ValueError("bad backup magic")
    if blob[4] != VERSION:
        raise ValueError(f"unknown backup version {blob[4]}")

    params_blob = blob[5:13]
    time_cost = params_blob[0]
    mem_cost_log2 = params_blob[1]
    parallelism = params_blob[2]
    salt = blob[13:13 + SALT_LEN]
    nonce = blob[13 + SALT_LEN:13 + SALT_LEN + NONCE_LEN]
    ct_and_tag = blob[HEADER_LEN:]

    key = _argon2id(password, salt, time_cost, mem_cost_log2, parallelism)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    aead = AESGCM(key)
    try:
        plaintext = aead.decrypt(nonce, ct_and_tag, params_blob)
    except InvalidTag:
        raise ValueError(
            "could not decrypt backup — wrong password, tampered file, "
            "or KDF parameters changed"
        )
    return json.loads(plaintext.decode("utf-8"))


# ── Convenience helpers ──────────────────────────────────────────────


@dataclass
class BackupMeta:
    """Lightweight introspection of a backup file without decrypting."""
    version: int
    time_cost: int
    mem_cost_log2: int
    parallelism: int
    size_bytes: int

    @property
    def estimated_mem_mib(self) -> int:
        return (1 << self.mem_cost_log2) // 1024


def inspect(blob: bytes) -> BackupMeta:
    if len(blob) < HEADER_LEN:
        raise ValueError("backup too short to inspect")
    if blob[:4] != MAGIC:
        raise ValueError("bad backup magic")
    return BackupMeta(
        version=blob[4],
        time_cost=blob[5],
        mem_cost_log2=blob[6],
        parallelism=blob[7],
        size_bytes=len(blob),
    )


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    payload = {
        "schema": 1,
        "exported_at": int(time.time()),
        "identity_priv_x25519_hex": "aa" * 32,
        "contacts": [
            {"username": "bob", "pubkey_x25519_hex": "bb" * 32},
        ],
        "messages": [
            {"id": "msg-1", "contact": "bob", "direction": "out",
             "body": "hello bob", "ts": 1700000000},
        ],
    }
    password = b"correct horse battery staple"

    # Use lower KDF cost in tests so they finish quickly.
    blob = pack(payload, password, time_cost=1, mem_cost_log2=12, parallelism=1)
    assert blob[:4] == MAGIC
    meta = inspect(blob)
    assert meta.version == 1
    assert meta.time_cost == 1
    assert meta.mem_cost_log2 == 12

    recovered = unpack(blob, password)
    assert recovered == payload, "round trip mismatch"

    # Wrong password fails
    try:
        unpack(blob, b"wrong password")
        raise AssertionError("wrong password should not decrypt")
    except ValueError as e:
        assert "could not decrypt" in str(e)

    # Tampered KDF parameters fail (AAD bind)
    mangled = bytearray(blob)
    mangled[5] = 99  # twiddle time_cost
    try:
        unpack(bytes(mangled), password)
        raise AssertionError("tampered KDF params should fail")
    except ValueError:
        pass

    # Tampered ciphertext fails
    mangled = bytearray(blob)
    mangled[-1] ^= 0x01
    try:
        unpack(bytes(mangled), password)
        raise AssertionError("tampered ciphertext should fail")
    except ValueError:
        pass

    print("backup self-tests passed.")


if __name__ == "__main__":
    _self_test()
