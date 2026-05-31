"""
SHROUD Triple-Hybrid Signature
=================================
Ed25519 (classical) + ML-DSA-87 (lattice PQ, FIPS 204) + SPHINCS+-256s (hash-based PQ)
combined as concurrent independent signatures. To forge, an attacker must break
the discrete-log problem AND the lattice-LWE problem AND a generic hash function
preimage at the 256-bit security level — three uncorrelated assumptions.

Used to attest SHROUD's server identity. The server holds one identity
keypair forever; the public part is pinned by clients on first connect.

Wire format
-----------
Public-key blob (PK_BLOB):
    magic    (4B le) = 0x32424B53  ('SKB2' — Sig Key Bundle v2)
    ed_pk    (32 bytes)
    mldsa_pk (2592 bytes)
    sph_pk   (64 bytes)

Signature blob (SIG_BLOB):
    magic    (4B le) = 0x32424753  ('SGB2')
    ed_sig   (64 bytes)
    mldsa_sig (4627 bytes, ML-DSA-87)
    sph_sig  (29792 bytes, SPHINCS+-SHA2-256s-simple)

Total signature: ~34 KB. Verification: ~1-5 ms.
"""
import struct, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import oqs

MLDSA_NAME = "ML-DSA-87"
SPH_NAME   = "SPHINCS+-SHA2-256s-simple"

ED_PK_LEN   = 32
MLDSA_PK_LEN = 2592
SPH_PK_LEN  = 64
ED_SIG_LEN  = 64
MLDSA_SIG_LEN = 4627
SPH_SIG_LEN = 29792
PK_BLOB_LEN  = 4 + ED_PK_LEN + MLDSA_PK_LEN + SPH_PK_LEN
SIG_BLOB_LEN = 4 + ED_SIG_LEN + MLDSA_SIG_LEN + SPH_SIG_LEN

MAGIC_PK  = 0x32424B53
MAGIC_SIG = 0x32424753


def keygen() -> tuple[bytes, dict]:
    """Generate a triple identity keypair.
    Returns (pk_blob, secrets) where secrets is an opaque dict to pass to sign()."""
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pk_obj = ed_priv.public_key()
    ed_pk = ed_pk_obj.public_bytes_raw()

    mldsa_sigobj = oqs.Signature(MLDSA_NAME)
    mldsa_pk = mldsa_sigobj.generate_keypair()
    mldsa_sk = mldsa_sigobj.export_secret_key()

    sph_sigobj = oqs.Signature(SPH_NAME)
    sph_pk = sph_sigobj.generate_keypair()
    sph_sk = sph_sigobj.export_secret_key()

    assert len(ed_pk) == ED_PK_LEN
    assert len(mldsa_pk) == MLDSA_PK_LEN, f"unexpected ML-DSA pk len {len(mldsa_pk)}"
    assert len(sph_pk) == SPH_PK_LEN, f"unexpected SPHINCS+ pk len {len(sph_pk)}"

    pk_blob = struct.pack("<I", MAGIC_PK) + ed_pk + mldsa_pk + sph_pk
    secrets = {
        "ed_sk_bytes": ed_priv.private_bytes_raw(),
        "mldsa_sk": mldsa_sk,
        "sph_sk":   sph_sk,
    }
    return pk_blob, secrets


def sign(message: bytes, secrets: dict) -> bytes:
    """Triple-sign a message. Returns SIG_BLOB."""
    ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(secrets["ed_sk_bytes"])
    ed_sig = ed_priv.sign(message)

    mldsa_sigobj = oqs.Signature(MLDSA_NAME, secrets["mldsa_sk"])
    mldsa_sig = mldsa_sigobj.sign(message)

    sph_sigobj = oqs.Signature(SPH_NAME, secrets["sph_sk"])
    sph_sig = sph_sigobj.sign(message)

    assert len(ed_sig)   == ED_SIG_LEN
    assert len(mldsa_sig) == MLDSA_SIG_LEN, f"unexpected ML-DSA sig len {len(mldsa_sig)}"
    assert len(sph_sig)  == SPH_SIG_LEN,  f"unexpected SPHINCS+ sig len {len(sph_sig)}"

    return struct.pack("<I", MAGIC_SIG) + ed_sig + mldsa_sig + sph_sig


def verify(message: bytes, sig_blob: bytes, pk_blob: bytes) -> bool:
    """Verify a triple-sig. Returns True only if ALL THREE signatures verify."""
    if len(sig_blob) != SIG_BLOB_LEN or len(pk_blob) != PK_BLOB_LEN:
        return False
    (sm,) = struct.unpack_from("<I", sig_blob, 0)
    (pm,) = struct.unpack_from("<I", pk_blob, 0)
    if sm != MAGIC_SIG or pm != MAGIC_PK:
        return False

    off = 4
    ed_pk = pk_blob[off:off + ED_PK_LEN]; off += ED_PK_LEN
    mldsa_pk = pk_blob[off:off + MLDSA_PK_LEN]; off += MLDSA_PK_LEN
    sph_pk = pk_blob[off:off + SPH_PK_LEN]

    off = 4
    ed_sig = sig_blob[off:off + ED_SIG_LEN]; off += ED_SIG_LEN
    mldsa_sig = sig_blob[off:off + MLDSA_SIG_LEN]; off += MLDSA_SIG_LEN
    sph_sig = sig_blob[off:off + SPH_SIG_LEN]

    try:
        ed25519.Ed25519PublicKey.from_public_bytes(ed_pk).verify(ed_sig, message)
    except InvalidSignature:
        return False
    except Exception:
        return False

    if not oqs.Signature(MLDSA_NAME).verify(message, mldsa_sig, mldsa_pk):
        return False
    if not oqs.Signature(SPH_NAME).verify(message, sph_sig, sph_pk):
        return False
    return True


def fingerprint(pk_blob: bytes, digits: int = 32) -> str:
    """Stable human-readable fingerprint for a pubkey blob (hex of SHA-256 prefix)."""
    return hashlib.sha256(pk_blob).hexdigest()[:digits]


def self_test() -> bool:
    pk, sk = keygen()
    msg = b"SHROUD identity attestation self-test"
    s = sign(msg, sk)
    if not verify(msg, s, pk): return False
    # Tampered message must fail
    if verify(msg + b"!", s, pk): return False
    # Tampered sig must fail
    bad = bytearray(s); bad[-1] ^= 1
    if verify(msg, bytes(bad), pk): return False
    return True


if __name__ == "__main__":
    print(f"triple-sig self-test:", "PASSED" if self_test() else "FAILED")
    pk, sk = keygen()
    msg = b"x" * 256
    s = sign(msg, sk)
    print(f"  pk blob:  {len(pk)} bytes")
    print(f"  sig blob: {len(s)} bytes")
    print(f"  fingerprint: {fingerprint(pk)}")
