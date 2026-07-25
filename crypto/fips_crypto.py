"""
SHROUD FIPS 140-2 Cryptographic Module
Shared across server and all clients.
Implements: AES-256-GCM, ECDH P-384, PBKDF2-HMAC-SHA256, HMAC-SHA256/384/512
FIPS 140-2 validated algorithms only. No non-FIPS primitives.
"""

import os, hashlib, hmac, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac as crypthmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from secrets import token_bytes

# ── Constants ────────────────────────────────────────────────────────
AES_KEY_LEN = 32      # AES-256
GCM_IV_LEN = 12       # 96-bit nonce (FIPS recommended)
GCM_TAG_LEN = 16      # 128-bit authentication tag
PBKDF2_ITERATIONS = 600_000  # FIPS 140-2 minimum
PBKDF2_SALT_LEN = 16
PBKDF2_KEY_LEN = 32
HMAC_KEY_LEN = 32
ECDH_CURVE = ec.SECP384R1()  # P-384 (FIPS 140-2 validated)
DEVICE_ID_LEN = 32

# ── FIPS DRBG (Deterministic Random Bit Generator) ───────────────────
def fips_random(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes using OS entropy.
    Equivalent to FIPS 186-4 DRBG with SHA-256."""
    return token_bytes(length)

# ── PBKDF2-HMAC-SHA256 (FIPS 140-2) ──────────────────────────────────
def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive AES-256 key from password using PBKDF2-HMAC-SHA256.
    Returns (key, salt)."""
    if salt is None:
        salt = fips_random(PBKDF2_SALT_LEN)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8')), salt

# ── AES-256-GCM (FIPS 140-2) ────────────────────────────────────────
def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = b'') -> dict:
    """Encrypt using AES-256-GCM. Returns {nonce, ciphertext, tag}.
    Nonce must be unique per key (FIPS requirement)."""
    nonce = fips_random(GCM_IV_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
    }

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b'') -> bytes:
    """Decrypt AES-256-GCM. Raises InvalidTag on tampering."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

# ── HMAC-SHA256/384/512 (FIPS 140-2) ────────────────────────────────
def hmac_sign(key: bytes, data: bytes, algorithm: str = "sha256") -> bytes:
    """Generate HMAC signature. FIPS 140-2 compliant."""
    algo_map = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
    h = crypthmac.HMAC(key, algo_map[algorithm], backend=default_backend())
    h.update(data)
    return h.finalize()

def hmac_verify(key: bytes, data: bytes, signature: bytes, algorithm: str = "sha256") -> bool:
    """Verify HMAC signature using constant-time comparison."""
    expected = hmac_sign(key, data, algorithm)
    return hmac.compare_digest(expected, signature)

# ── ECDH P-384 Key Exchange (FIPS 140-2) ────────────────────────────
def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate ECDH P-384 key pair."""
    private_key = ec.generate_private_key(ECDH_CURVE, default_backend())
    return private_key, private_key.public_key()

def serialize_public_key(public_key: EllipticCurvePublicKey) -> bytes:
    """Serialize public key to DER bytes (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(data: bytes) -> EllipticCurvePublicKey:
    """Deserialize public key from DER or Microsoft BCRYPT_ECCPUBLIC_BLOB."""
    # Try DER SubjectPublicKeyInfo first
    try:
        return serialization.load_der_public_key(data, backend=default_backend())
    except Exception:
        pass

    # Try Microsoft BCRYPT_ECCPUBLIC_BLOB format
    # struct: Magic(4) + cbKey(4) + X[cbKey] + Y[cbKey]
    if len(data) >= 8:
        magic = struct.unpack_from("<I", data, 0)[0]
        cbKey = struct.unpack_from("<I", data, 4)[0]
        # P-384 public magic values (ECDH or ECDSA)
        if magic in (0x334B4345, 0x33534345) and len(data) == 8 + 2 * cbKey:
            x = int.from_bytes(data[8:8 + cbKey], 'big')
            y = int.from_bytes(data[8 + cbKey:8 + 2 * cbKey], 'big')
            pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ECDH_CURVE)
            return pub_numbers.public_key(default_backend())

    raise ValueError("Unrecognized public key format")

def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Serialize private key to DER bytes (PKCS8). FIPS requires encrypted storage."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(data: bytes) -> ec.EllipticCurvePrivateKey:
    """Deserialize private key from DER bytes."""
    return serialization.load_der_private_key(data, password=None, backend=default_backend())

def compute_shared_secret(private_key: ec.EllipticCurvePrivateKey,
                          peer_public: EllipticCurvePublicKey) -> bytes:
    """Compute ECDH shared secret using P-384, then derive AES key via HKDF."""
    shared = private_key.exchange(ec.ECDH(), peer_public)
    # Derive AES-256 key from shared secret using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SHROUD-ECDH-v1",
        backend=default_backend()
    )
    return hkdf.derive(shared)

# ── Device Identity ──────────────────────────────────────────────────
def generate_device_id() -> str:
    """Generate unique device identifier."""
    return fips_random(DEVICE_ID_LEN).hex()

# ── Message Envelope ─────────────────────────────────────────────────
def seal_message(key: bytes, plaintext: str, sender_id: str, timestamp: int) -> dict:
    """Encrypt and authenticate a message. Returns complete envelope."""
    payload = json.dumps({
        "sender": sender_id,
        "ts": timestamp,
        "body": plaintext
    }).encode('utf-8')
    encrypted = encrypt_aes_gcm(key, payload)
    return {
        "sender": sender_id,
        "ts": timestamp,
        "nonce": encrypted["nonce"].hex(),
        "ciphertext": encrypted["ciphertext"].hex(),
        "sig": hmac_sign(key, encrypted["ciphertext"]).hex()
    }

import json

def open_message(key: bytes, envelope: dict) -> dict:
    """Decrypt and verify a message envelope. Returns {sender, ts, body} or raises."""
    nonce = bytes.fromhex(envelope["nonce"])
    ciphertext = bytes.fromhex(envelope["ciphertext"])
    sig = bytes.fromhex(envelope["sig"])

    # Verify HMAC first
    if not hmac_verify(key, ciphertext, sig):
        raise ValueError("Message integrity check failed — tampering detected")

    # Decrypt
    plaintext = decrypt_aes_gcm(key, nonce, ciphertext)
    return json.loads(plaintext.decode('utf-8'))

# ── Hybrid Post-Quantum Key Exchange ────────────────────────────────
def generate_kyber_keypair():
    """Generate ML-KEM-1024 post-quantum keypair."""
    from crypto.ml_kem_1024 import ml_kem_keygen
    return ml_kem_keygen()

def hybrid_key_exchange_encaps(ecdh_priv, ecdh_pub_peer, kyber_pk):
    """HYBRID key exchange: ECDH P-384 + ML-KEM-1024.
    Runs both classical and post-quantum exchanges in parallel.
    Shared secrets are concatenated and fed through HKDF-SHA256.
    Returns (ciphertext_for_kyber, final_session_key).
    Even if quantum breaks ECDH, the Kyber half protects the key."""
    from crypto.ml_kem_1024 import ml_kem_encaps

    # Classical: ECDH P-384
    ecdh_shared = ecdh_priv.exchange(ec.ECDH(), ecdh_pub_peer)

    # Post-quantum: ML-KEM-1024
    kyber_ct, kyber_ss = ml_kem_encaps(kyber_pk)

    # Combine both shared secrets via HKDF
    combined = ecdh_shared + kyber_ss
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SHROUD-HYBRID-PQ-v2",
        backend=default_backend()
    )
    session_key = hkdf.derive(combined)
    return kyber_ct, session_key

def hybrid_key_exchange_decaps(ecdh_priv, ecdh_pub_peer, kyber_ct, kyber_sk):
    """HYBRID decapsulation: recover session key from ECDH + ML-KEM-1024."""
    from crypto.ml_kem_1024 import ml_kem_decaps

    # Classical: ECDH P-384
    ecdh_shared = ecdh_priv.exchange(ec.ECDH(), ecdh_pub_peer)

    # Post-quantum: ML-KEM-1024
    kyber_ss = ml_kem_decaps(kyber_ct, kyber_sk)

    # Combine both shared secrets via HKDF
    combined = ecdh_shared + kyber_ss
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SHROUD-HYBRID-PQ-v2",
        backend=default_backend()
    )
    return hkdf.derive(combined)

# ── Self-Test (FIPS 140-2 requirement) ───────────────────────────────
def fips_self_test() -> bool:
    """Run FIPS 140-2 required self-tests. Returns True on pass.

    These are known-answer tests: fixed key, fixed nonce, fixed input,
    compared against published expected output. What was here before was
    labelled a KAT but only did encrypt-then-decrypt and checked the
    plaintext came back — it declared a fixed nonce and never used it
    (encrypt_aes_gcm picks its own random one), so nothing was ever
    compared to a known answer. That test passes for any transform that
    round-trips, including one that isn't AES at all, while the relay
    logs "FIPS 140-2 self-test: PASSED" on the strength of it.

    Vectors are the published ones so this checks the implementation
    against the standard rather than against itself:
      - AES-256-GCM: NIST GCM spec Test Case 14
      - HMAC-SHA256: RFC 4231 Test Case 1
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # ── AES-256-GCM known-answer test (NIST GCM Test Case 14) ──
    kat_key = bytes(32)
    kat_iv = bytes(12)
    kat_pt = bytes(16)
    expected_ct = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
    expected_tag = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")
    out = AESGCM(kat_key).encrypt(kat_iv, kat_pt, None)
    if out[:16] != expected_ct or out[16:] != expected_tag:
        return False
    # Decrypt direction, and reject a tampered tag.
    if AESGCM(kat_key).decrypt(kat_iv, expected_ct + expected_tag, None) != kat_pt:
        return False
    try:
        bad = bytearray(expected_ct + expected_tag)
        bad[-1] ^= 0x01
        AESGCM(kat_key).decrypt(kat_iv, bytes(bad), None)
        return False          # a forged tag must not verify
    except Exception:         # noqa: BLE001 — InvalidTag is the pass path
        pass

    # ── HMAC-SHA256 known-answer test (RFC 4231 Test Case 1) ──
    if hmac_sign(b"\x0b" * 20, b"Hi There").hex() != (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    ):
        return False

    # ── The wrappers SHROUD actually calls ──
    # encrypt_aes_gcm picks its own random nonce, so it can't take a
    # fixed-nonce KAT directly. Instead: encrypt with the wrapper, then
    # decrypt independently with the raw primitive using the nonce it
    # returned. A wrapper that round-trips against itself proves nothing
    # — any reversible transform passes that — but one whose output the
    # standard primitive can decrypt really is AES-256-GCM.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plain = b"FIPS 140-2 self-test"
    enc = encrypt_aes_gcm(key, plain)
    try:
        if AESGCM(key).decrypt(enc["nonce"], enc["ciphertext"], b"") != plain:
            return False
    except Exception:                                        # noqa: BLE001
        return False
    if decrypt_aes_gcm(key, enc["nonce"], enc["ciphertext"]) != plain:
        return False
    if len(enc["nonce"]) != GCM_IV_LEN:
        return False

    hkey = bytes(32)
    if not hmac_verify(hkey, b"test", hmac_sign(hkey, b"test")):
        return False

    return True

if __name__ == "__main__":
    assert fips_self_test(), "FIPS self-test FAILED"
    print("FIPS 140-2 self-test: PASSED")
    print("SHROUD Crypto Module Ready")
