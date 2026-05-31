"""
SHROUD Post-Quantum Hybrid Key Exchange
==========================================
ECDH P-384 (classical) + ML-KEM-1024 (lattice PQ) cascaded through HKDF-SHA512.
Closes the "Harvest Now, Decrypt Later" attack: an adversary recording today's
ciphertext must break BOTH primitives to recover the session key.

Wire format for the server pubkey blob:
    magic   (4B, little-endian) = 0x32474B50  ('PKG2' — Public-Key Generation v2)
    ec_len  (4B) = 96  (P-384 uncompressed: 48-byte X || 48-byte Y)
    ec_xy   (ec_len bytes)
    kem_len (4B) = 1568  (ML-KEM-1024 public key)
    kem_pk  (kem_len bytes)

Wire format for the client encapsulation reply:
    magic    (4B) = 0x32434B50 ('PKC2')
    ec_pub   (96B uncompressed)
    kem_ct   (1568B ML-KEM ciphertext)
"""
import os, struct, hashlib, hmac as _hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .ml_kem_1024 import ml_kem_keygen, ml_kem_encaps, ml_kem_decaps, PK_SIZE as KEM_PK, CT_SIZE as KEM_CT

MAGIC_SERVER_PUB = 0x32474B50
MAGIC_CLIENT_PUB = 0x32434B50
EC_XY_LEN = 96
CONTEXT = b"SHROUD-PQ-HYBRID-v1"


def gen_server_keypair():
    """Generate hybrid server keypair. Returns (state, server_pub_blob)."""
    ec_priv = ec.generate_private_key(ec.SECP384R1())
    ec_pub = ec_priv.public_key().public_numbers()
    ec_xy = ec_pub.x.to_bytes(48, "big") + ec_pub.y.to_bytes(48, "big")

    kem_pk, kem_sk = ml_kem_keygen()

    blob = struct.pack("<II", MAGIC_SERVER_PUB, EC_XY_LEN) + ec_xy
    blob += struct.pack("<I", KEM_PK) + kem_pk

    state = {"ec_priv": ec_priv, "kem_sk": kem_sk}
    return state, blob


def client_encapsulate(server_pub_blob: bytes) -> tuple[bytes, bytes]:
    """Client side: parse server blob, encapsulate, return (client_blob, shared_secret)."""
    magic, ec_len = struct.unpack_from("<II", server_pub_blob, 0)
    if magic != MAGIC_SERVER_PUB or ec_len != EC_XY_LEN:
        raise ValueError("Invalid server pubkey blob")
    off = 8
    ec_xy = server_pub_blob[off:off + EC_XY_LEN]; off += EC_XY_LEN
    (kem_len,) = struct.unpack_from("<I", server_pub_blob, off); off += 4
    if kem_len != KEM_PK:
        raise ValueError("Bad KEM pubkey length")
    kem_pk = server_pub_blob[off:off + kem_len]

    x = int.from_bytes(ec_xy[:48], "big"); y = int.from_bytes(ec_xy[48:], "big")
    server_ec_pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key()

    client_priv = ec.generate_private_key(ec.SECP384R1())
    client_pub = client_priv.public_key().public_numbers()
    client_xy = client_pub.x.to_bytes(48, "big") + client_pub.y.to_bytes(48, "big")
    ec_shared = client_priv.exchange(ec.ECDH(), server_ec_pub)

    kem_ct, kem_shared = ml_kem_encaps(kem_pk)

    shared = _hkdf_cascade(ec_shared, kem_shared)

    client_blob = struct.pack("<I", MAGIC_CLIENT_PUB) + client_xy + kem_ct
    return client_blob, shared


def server_decapsulate(state: dict, client_blob: bytes) -> bytes:
    """Server side: derive the shared secret from the client's reply."""
    (magic,) = struct.unpack_from("<I", client_blob, 0)
    if magic != MAGIC_CLIENT_PUB:
        raise ValueError("Invalid client pubkey blob")
    off = 4
    ec_xy = client_blob[off:off + EC_XY_LEN]; off += EC_XY_LEN
    kem_ct = client_blob[off:off + KEM_CT]; off += KEM_CT

    x = int.from_bytes(ec_xy[:48], "big"); y = int.from_bytes(ec_xy[48:], "big")
    client_ec_pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key()

    ec_shared = state["ec_priv"].exchange(ec.ECDH(), client_ec_pub)
    kem_shared = ml_kem_decaps(kem_ct, state["kem_sk"])

    return _hkdf_cascade(ec_shared, kem_shared)


def _hkdf_cascade(ec_secret: bytes, kem_secret: bytes) -> bytes:
    """HKDF-SHA512 over (ec || kem) — if either secret is unknown, output is unknown."""
    ikm = ec_secret + kem_secret
    return HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=b"\x00" * 64,
        info=CONTEXT,
    ).derive(ikm)


def self_test() -> bool:
    state, blob = gen_server_keypair()
    client_blob, ss1 = client_encapsulate(blob)
    ss2 = server_decapsulate(state, client_blob)
    return ss1 == ss2 and len(ss1) == 32


if __name__ == "__main__":
    ok = self_test()
    print(f"PQ hybrid self-test: {'PASSED' if ok else 'FAILED'}")
    if ok:
        state, blob = gen_server_keypair()
        print(f"  server pubkey blob: {len(blob)} bytes")
        cb, ss = client_encapsulate(blob)
        print(f"  client encap blob:  {len(cb)} bytes")
        print(f"  shared secret:      {len(ss)} bytes / {ss.hex()[:16]}...")
