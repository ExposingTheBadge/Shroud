"""
SHROUD Double Ratchet
========================
Signal-style Double Ratchet for forward + future secrecy. Each conversation
maintains:

  RK   — 32-byte root key
  CKs  — sending chain key   (None until we send the first message after init)
  CKr  — receiving chain key (None until we receive the first message after init)
  DHs  — our current sending X25519 keypair
  DHr  — peer's current sending X25519 public key
  Ns   — number of messages sent in the current sending chain
  Nr   — number of messages received in the current receiving chain
  PN   — number of messages in the previous sending chain (for out-of-order)
  MKSKIPPED — cache of message keys for messages received out-of-order

A device compromise burns roughly one message worth of past traffic: every
send rotates the chain key, every receive after the peer's DH rotation
rotates the root. Old chain keys are forgotten.

Initialization is seeded by the SHROUD PQ-hybrid handshake (ECDH-P384 +
ML-KEM-1024 via HKDF-SHA512). That gives the root key. The per-message DH
ratchet uses X25519 — fast and well-studied. (Pure PQ ratcheting is on the
v1.7.0 roadmap; today's design closes Harvest-Now-Decrypt-Later at the
initial handshake and forward-secures from there.)

Wire format (single message envelope, sender to recipient):
    magic     (4B le) = 0x32325244 ('DR22')
    dh_pub    (32B X25519 public key — the sender's current DHs.pub)
    pn        (4B le)
    n         (4B le)
    nonce     (12B)
    ct        (var, AES-256-GCM)
"""
from __future__ import annotations
import os, struct, hmac, hashlib, json
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = 0x32325244
MAX_SKIP = 1000  # max messages we'll cache as "skipped"
INFO_RK = b"SHROUD-DR-RK"
INFO_CK = b"SHROUD-DR-CK"
INFO_MSG = b"SHROUD-DR-MSG"


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 64) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(ikm)


def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Advance the root key after a DH ratchet step. Returns (new_rk, new_chain_key)."""
    out = _hkdf(dh_out, rk, INFO_RK, 64)
    return out[:32], out[32:]


def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Advance a chain key and emit the message key. Returns (new_ck, mk)."""
    mk = hmac.new(ck, b"\x01", hashlib.sha512).digest()[:32]
    new_ck = hmac.new(ck, b"\x02", hashlib.sha512).digest()[:32]
    return new_ck, mk


def _x25519_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv.private_bytes_raw(), pub


def _x25519_dh(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)


@dataclass
class RatchetState:
    rk: bytes
    dhs_priv: bytes
    dhs_pub: bytes
    dhr_pub: bytes | None
    cks: bytes | None = None
    ckr: bytes | None = None
    ns: int = 0
    nr: int = 0
    pn: int = 0
    skipped: dict = field(default_factory=dict)  # (dhr_pub_hex, n) -> mk

    # ── State persistence ─────────────────────────────────────────
    def to_bytes(self) -> bytes:
        skipped = {f"{k[0]}|{k[1]}": v.hex() for k, v in self.skipped.items()}
        d = {
            "rk": self.rk.hex(),
            "dhs_priv": self.dhs_priv.hex(),
            "dhs_pub": self.dhs_pub.hex(),
            "dhr_pub": self.dhr_pub.hex() if self.dhr_pub else None,
            "cks": self.cks.hex() if self.cks else None,
            "ckr": self.ckr.hex() if self.ckr else None,
            "ns": self.ns, "nr": self.nr, "pn": self.pn,
            "skipped": skipped,
        }
        return json.dumps(d).encode()

    @classmethod
    def from_bytes(cls, b: bytes) -> "RatchetState":
        d = json.loads(b.decode())
        skipped = {}
        for k, v in d.get("skipped", {}).items():
            dhr_hex, n = k.split("|")
            skipped[(dhr_hex, int(n))] = bytes.fromhex(v)
        return cls(
            rk=bytes.fromhex(d["rk"]),
            dhs_priv=bytes.fromhex(d["dhs_priv"]),
            dhs_pub=bytes.fromhex(d["dhs_pub"]),
            dhr_pub=bytes.fromhex(d["dhr_pub"]) if d["dhr_pub"] else None,
            cks=bytes.fromhex(d["cks"]) if d["cks"] else None,
            ckr=bytes.fromhex(d["ckr"]) if d["ckr"] else None,
            ns=d["ns"], nr=d["nr"], pn=d["pn"], skipped=skipped,
        )


# ── Initialization ────────────────────────────────────────────────────
# The party that sends first ("Alice") and the party that receives first
# ("Bob") set up their state differently.  Both start from the same
# shared_secret produced by the PQ-hybrid handshake.

def init_alice(shared_secret: bytes, bob_dh_pub: bytes) -> RatchetState:
    """Alice — initiator. Pre-computes a sending chain so the first
    message goes out without waiting for Bob's reply."""
    dhs_priv, dhs_pub = _x25519_keypair()
    dh = _x25519_dh(dhs_priv, bob_dh_pub)
    rk, cks = _kdf_rk(shared_secret, dh)
    return RatchetState(rk=rk, dhs_priv=dhs_priv, dhs_pub=dhs_pub,
                        dhr_pub=bob_dh_pub, cks=cks, ckr=None)


def init_bob(shared_secret: bytes, bob_dh_priv: bytes, bob_dh_pub: bytes) -> RatchetState:
    """Bob — responder. Has no peer DH yet; will initialize on first
    incoming message."""
    return RatchetState(rk=shared_secret, dhs_priv=bob_dh_priv,
                        dhs_pub=bob_dh_pub, dhr_pub=None,
                        cks=None, ckr=None)


# ── Send / Receive ────────────────────────────────────────────────────

def encrypt(state: RatchetState, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt and advance our sending chain. Returns the wire envelope."""
    if state.cks is None:
        raise ValueError("No sending chain — cannot send until Bob's initial flow completes")
    state.cks, mk = _kdf_ck(state.cks)
    nonce = os.urandom(12)
    header = struct.pack("<I", MAGIC) + state.dhs_pub + struct.pack("<II", state.pn, state.ns)
    aad = header + associated_data
    ct = AESGCM(mk).encrypt(nonce, plaintext, aad)
    state.ns += 1
    return header + nonce + ct


def _skip_message_keys(state: RatchetState, until: int):
    if state.nr + MAX_SKIP < until:
        raise ValueError("Too many skipped messages")
    if state.ckr is None:
        return
    while state.nr < until:
        state.ckr, mk = _kdf_ck(state.ckr)
        state.skipped[(state.dhr_pub.hex(), state.nr)] = mk
        state.nr += 1


def _dh_ratchet_step(state: RatchetState, new_dhr_pub: bytes):
    state.pn = state.ns
    state.ns = 0
    state.nr = 0
    state.dhr_pub = new_dhr_pub
    dh1 = _x25519_dh(state.dhs_priv, state.dhr_pub)
    state.rk, state.ckr = _kdf_rk(state.rk, dh1)
    state.dhs_priv, state.dhs_pub = _x25519_keypair()
    dh2 = _x25519_dh(state.dhs_priv, state.dhr_pub)
    state.rk, state.cks = _kdf_rk(state.rk, dh2)


def decrypt(state: RatchetState, envelope: bytes, associated_data: bytes = b"") -> bytes:
    """Verify + decrypt + advance state. Returns plaintext."""
    if len(envelope) < 4 + 32 + 4 + 4 + 12 + 16:
        raise ValueError("Envelope too short")
    (magic,) = struct.unpack_from("<I", envelope, 0)
    if magic != MAGIC:
        raise ValueError(f"Bad magic 0x{magic:08x}")
    dhr_pub = envelope[4:36]
    pn, n = struct.unpack_from("<II", envelope, 36)
    nonce = envelope[44:56]
    ct = envelope[56:]
    header = envelope[:44]
    aad = header + associated_data

    # Was this skipped earlier?
    sk = state.skipped.pop((dhr_pub.hex(), n), None)
    if sk is not None:
        return AESGCM(sk).decrypt(nonce, ct, aad)

    if state.dhr_pub != dhr_pub:
        # Peer rotated their DH. Skip any remaining keys in the old chain,
        # then take a ratchet step.
        if state.ckr is not None:
            _skip_message_keys(state, pn)
        _dh_ratchet_step(state, dhr_pub)

    _skip_message_keys(state, n)
    state.ckr, mk = _kdf_ck(state.ckr)
    state.nr += 1
    return AESGCM(mk).decrypt(nonce, ct, aad)


# ── Self-test ─────────────────────────────────────────────────────────

def self_test() -> bool:
    shared = os.urandom(32)
    bob_priv, bob_pub = _x25519_keypair()
    a = init_alice(shared, bob_pub)
    b = init_bob(shared, bob_priv, bob_pub)

    # Round 1: Alice -> Bob
    e1 = encrypt(a, b"hello from Alice")
    p1 = decrypt(b, e1)
    if p1 != b"hello from Alice": return False

    # Round 2: Bob -> Alice (Bob's first send; he ratchets internally)
    # Need to give Bob a sending chain — first decrypt set up his DH state
    e2 = encrypt(b, b"hi Alice it's Bob")
    p2 = decrypt(a, e2)
    if p2 != b"hi Alice it's Bob": return False

    # Round 3: Alice sends 3 in a row
    msgs = [b"a", b"bb", b"ccc"]
    encs = [encrypt(a, m) for m in msgs]
    plain = [decrypt(b, e) for e in encs]
    if plain != msgs: return False

    # Round 4: out-of-order — Bob sends 2, Alice receives 2nd then 1st
    e4a = encrypt(b, b"first")
    e4b = encrypt(b, b"second")
    p4b = decrypt(a, e4b)
    p4a = decrypt(a, e4a)
    if (p4a, p4b) != (b"first", b"second"): return False

    # State serialization round-trip
    blob = a.to_bytes()
    a2 = RatchetState.from_bytes(blob)
    e5 = encrypt(a2, b"after restore")
    p5 = decrypt(b, e5)
    if p5 != b"after restore": return False

    return True


if __name__ == "__main__":
    ok = self_test()
    print(f"Double Ratchet self-test: {'PASSED' if ok else 'FAILED'}")
