"""
GHOSTLINK SRP-6a Augmented PAKE
===============================
Per RFC 5054, group 3072-bit (N_3072). The server never sees the user's
password — not even in transit, not even at decryption time. Only a
*verifier* is stored, derived from the password + a per-user salt. An
attacker who compromises the server cannot impersonate the user without
a brute-force grind against the verifier (much harder than a plain hash
because of the discrete-log structure).

Protocol (Alice = user, Bob = server, P = password, I = username):

  Registration (run once over an already-secure channel):
    1. Alice picks salt s; computes x = H(s || H(I || ':' || P))
    2. Verifier v = g^x mod N
    3. Alice sends (I, s, v) to Bob.  Bob stores (I, s, v).  P is never sent.

  Auth round:
    1. Alice → Bob:  I, A = g^a mod N            (a is random)
    2. Bob   → Alice: s, B = (kv + g^b) mod N    (b is random; k=H(N||g))
    3. Both compute:  u = H(A || B)
                      shared S_a = (B - k*g^x)^(a + u*x) mod N  (Alice)
                      shared S_b = (A * v^u)^b mod N             (Bob)
                      session key K = H(S)
                      M1 (proof from Alice) = H(A || B || K)
                      M2 (proof from Bob)   = H(A || M1 || K)
    3. Alice sends M1; Bob verifies; Bob sends M2; Alice verifies.

We use SHA-512 throughout (H).
"""
from __future__ import annotations
import hashlib, secrets
from typing import Tuple

# RFC 5054 3072-bit group
N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
N = int(N_HEX, 16)
g = 5


def _H(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def _i2osp(x: int, n: int = None) -> bytes:
    if n is None:
        n = (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big")


N_BYTES = (N.bit_length() + 7) // 8
G_BYTES = _i2osp(g, N_BYTES)


def _k() -> int:
    return int.from_bytes(_H(_i2osp(N, N_BYTES), G_BYTES), "big") % N


def _u(A: int, B: int) -> int:
    return int.from_bytes(_H(_i2osp(A, N_BYTES), _i2osp(B, N_BYTES)), "big") % N


def _x(salt: bytes, username: str, password: str) -> int:
    inner = _H(username.encode() + b":" + password.encode())
    return int.from_bytes(_H(salt + inner), "big") % N


# ── Registration ──────────────────────────────────────────────────
def make_verifier(username: str, password: str, salt: bytes = None) -> Tuple[bytes, int]:
    """Compute (salt, verifier). Run client-side once; server stores both."""
    if salt is None:
        salt = secrets.token_bytes(16)
    x = _x(salt, username, password)
    v = pow(g, x, N)
    return salt, v


# ── Client side ───────────────────────────────────────────────────
class ClientSession:
    def __init__(self, username: str, password: str):
        self.I = username
        self.P = password
        self.a = secrets.randbelow(N - 2) + 2
        self.A = pow(g, self.a, N)
        self.K = None
        self.M1 = None
        self.M2 = None

    def public(self) -> int:
        return self.A

    def derive_session(self, salt: bytes, B: int) -> Tuple[bytes, bytes]:
        if B % N == 0:
            raise ValueError("invalid server B")
        u = _u(self.A, B)
        if u == 0:
            raise ValueError("invalid u")
        x = _x(salt, self.I, self.P)
        k = _k()
        S = pow(B - (k * pow(g, x, N)) % N, self.a + u * x, N)
        self.K = _H(_i2osp(S, N_BYTES))
        self.M1 = _H(_i2osp(self.A, N_BYTES), _i2osp(B, N_BYTES), self.K)
        self.M2 = _H(_i2osp(self.A, N_BYTES), self.M1, self.K)
        return self.M1, self.K

    def verify_server_proof(self, server_m2: bytes) -> bool:
        return secrets.compare_digest(server_m2, self.M2 or b"")


# ── Server side ───────────────────────────────────────────────────
class ServerSession:
    def __init__(self, username: str, salt: bytes, verifier: int):
        self.I = username
        self.s = salt
        self.v = verifier
        self.b = secrets.randbelow(N - 2) + 2
        k = _k()
        self.B = (k * verifier + pow(g, self.b, N)) % N
        self.A = None
        self.K = None
        self.M1 = None
        self.M2 = None

    def challenge(self) -> Tuple[bytes, int]:
        return self.s, self.B

    def derive_and_verify(self, A: int, client_m1: bytes) -> bytes:
        if A % N == 0:
            raise ValueError("invalid client A")
        self.A = A
        u = _u(A, self.B)
        if u == 0:
            raise ValueError("invalid u")
        S = pow((A * pow(self.v, u, N)) % N, self.b, N)
        self.K = _H(_i2osp(S, N_BYTES))
        self.M1 = _H(_i2osp(A, N_BYTES), _i2osp(self.B, N_BYTES), self.K)
        if not secrets.compare_digest(client_m1, self.M1):
            raise ValueError("M1 mismatch — authentication failed")
        self.M2 = _H(_i2osp(A, N_BYTES), self.M1, self.K)
        return self.M2


# ── Self-test ─────────────────────────────────────────────────────
def self_test() -> bool:
    user = "alice@example.org"
    pw = "correct horse battery staple"
    salt, v = make_verifier(user, pw)

    client = ClientSession(user, pw)
    server = ServerSession(user, salt, v)

    s, B = server.challenge()
    if s != salt: return False
    A = client.public()
    M1, key_c = client.derive_session(s, B)
    try:
        M2 = server.derive_and_verify(A, M1)
    except ValueError:
        return False
    if not client.verify_server_proof(M2): return False
    if server.K != key_c: return False

    # Wrong password must fail
    bad = ClientSession(user, "wrong password")
    bad.derive_session(s, B)
    try:
        server2 = ServerSession(user, salt, v)
        s2, B2 = server2.challenge()
        bad2 = ClientSession(user, "wrong password")
        bad2.derive_session(s2, B2)
        server2.derive_and_verify(bad2.public(), bad2.M1)
        return False  # should have raised
    except ValueError:
        pass

    return True


if __name__ == "__main__":
    print("SRP-6a self-test:", "PASSED" if self_test() else "FAILED")
    print(f"  Group: RFC 5054 {N.bit_length()}-bit")
    print(f"  H: SHA-512")
