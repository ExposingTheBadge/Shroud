"""
SHROUD Anonymous Send Credentials
====================================
Privacy-Pass-style blind RSA signatures. The server issues short-lived
tokens to authenticated users; the user spends a token per message. Because
the issuer signs a *blinded* message, the resulting token is unlinkable
across the issue and redeem steps — the server can rate-limit and reject
double-spends without learning which user sent which message.

Protocol:
  Server holds RSA-3072 keypair (n, e=65537, d). e and n are public.

  ISSUE
    1. Client authenticates (X-Device-ID).
    2. Client picks a random 32-byte nonce m and a blinding factor r∈[2,n-1].
    3. Client sends m_blind = (H(m) * r^e) mod n  to /credentials/issue.
    4. Server signs:  s_blind = (m_blind)^d mod n.  Replies with s_blind.
    5. Client unblinds: s = (s_blind * r^-1) mod n.  Verifies s^e == H(m).
    6. Token = (m, s).

  REDEEM
    Client sends (m, s) to /credentials/redeem (or attaches to a send).
    Server verifies s^e mod n == H(m). If valid and m has not been seen
    before (table redeemed_credentials), accept and record m.

H(m) uses RSA-FDH with full-domain SHA-256 expansion to fill 3072 bits
(simple iterated SHA-256 with domain-separated counters — adequate for
this anonymous-credential use; not a panacea for general signing).
"""
from __future__ import annotations
import os, struct, hashlib, secrets
from typing import Tuple

RSA_BITS = 3072
RSA_BYTES = RSA_BITS // 8

# ── Math helpers (Python 3.8+ has pow(a, -1, m) for modular inverse) ──
def _modinv(a: int, m: int) -> int:
    try:
        return pow(a, -1, m)
    except ValueError:
        raise ValueError("no inverse")


# ── Full-domain hash → integer mod n ──────────────────────────────
def fdh(msg: bytes, n: int) -> int:
    out = b""
    counter = 0
    while len(out) < RSA_BYTES:
        out += hashlib.sha256(b"SHROUD-FDH|" + counter.to_bytes(4, "big") + msg).digest()
        counter += 1
    val = int.from_bytes(out[:RSA_BYTES], "big")
    return val % n


# ── Server: keypair ───────────────────────────────────────────────
def server_keygen() -> Tuple[dict, dict]:
    """Returns (public_key, secret_key). Both are simple dicts with int
    fields so they can be JSON-stringified to disk."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    nums = priv.private_numbers()
    pub_nums = nums.public_numbers
    return ({"n": pub_nums.n, "e": pub_nums.e},
            {"n": pub_nums.n, "e": pub_nums.e, "d": nums.d})


def serialize_pub(pub: dict) -> str:
    return f"{pub['n']:x}.{pub['e']:x}"

def parse_pub(s: str) -> dict:
    n, e = s.split(".")
    return {"n": int(n, 16), "e": int(e, 16)}

def serialize_sk(sk: dict) -> bytes:
    return (sk["n"].to_bytes(RSA_BYTES, "big")
          + sk["e"].to_bytes(4, "big")
          + sk["d"].to_bytes(RSA_BYTES, "big"))

def parse_sk(blob: bytes) -> dict:
    if len(blob) < RSA_BYTES * 2 + 4: raise ValueError("bad sk blob")
    n = int.from_bytes(blob[:RSA_BYTES], "big")
    e = int.from_bytes(blob[RSA_BYTES:RSA_BYTES + 4], "big")
    d = int.from_bytes(blob[RSA_BYTES + 4:RSA_BYTES * 2 + 4], "big")
    return {"n": n, "e": e, "d": d}


# ── Client: blind / unblind ───────────────────────────────────────
def client_blind(pub: dict) -> Tuple[bytes, int, int]:
    """Pick a fresh message m and blind it. Returns (m, m_blind, r)."""
    m = secrets.token_bytes(32)
    n = pub["n"]; e = pub["e"]
    hm = fdh(m, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        try: _modinv(r, n)
        except ValueError: continue
        break
    m_blind = (hm * pow(r, e, n)) % n
    return m, m_blind, r


def client_unblind(s_blind: int, r: int, pub: dict) -> int:
    n = pub["n"]
    return (s_blind * _modinv(r, n)) % n


def client_token(m: bytes, s: int) -> str:
    return m.hex() + "." + format(s, "x")


def parse_token(token: str) -> Tuple[bytes, int]:
    m_hex, s_hex = token.split(".")
    return bytes.fromhex(m_hex), int(s_hex, 16)


# ── Server: sign blinded / verify token ───────────────────────────
def server_sign_blinded(m_blind: int, sk: dict) -> int:
    return pow(m_blind, sk["d"], sk["n"])


def verify_token(m: bytes, s: int, pub: dict) -> bool:
    n = pub["n"]; e = pub["e"]
    if s <= 0 or s >= n: return False
    return pow(s, e, n) == fdh(m, n)


# ── Self-test ─────────────────────────────────────────────────────
def self_test() -> bool:
    pub, sk = server_keygen()
    m, m_blind, r = client_blind(pub)
    s_blind = server_sign_blinded(m_blind, sk)
    s = client_unblind(s_blind, r, pub)
    if not verify_token(m, s, pub): return False
    # Tampered m must fail
    if verify_token(m + b"!", s, pub): return False
    # Wrong sig must fail
    if verify_token(m, s + 1, pub): return False
    # Round-trip the token string
    tok = client_token(m, s)
    m2, s2 = parse_token(tok)
    if m2 != m or s2 != s: return False
    return True


if __name__ == "__main__":
    print("anon_creds self-test:", "PASSED" if self_test() else "FAILED")
    pub, sk = server_keygen()
    print(f"  RSA-{RSA_BITS} keypair ready")
    print(f"  pub serialized:  {len(serialize_pub(pub))} chars")
    print(f"  sk blob:         {len(serialize_sk(sk))} bytes")
