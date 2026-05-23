"""
ML-KEM-1024 (FIPS 203) — Post-Quantum Key Encapsulation Mechanism
NIST Security Level 5 (equivalent to AES-256)
Backed by liboqs — the NIST-validated reference implementation.
Lattice-based (MLWE problem). No known quantum algorithm can break lattices.
"""
import oqs

KEM_NAME = "ML-KEM-1024"
PK_SIZE = 1568
SK_SIZE = 3168
CT_SIZE = 1568
SS_SIZE = 32

def ml_kem_keygen():
    """Generate ML-KEM-1024 keypair.
    Returns (public_key: 1568 bytes, secret_key: 3168 bytes)"""
    kem = oqs.KeyEncapsulation(KEM_NAME)
    pk = kem.generate_keypair()
    sk = kem.export_secret_key()
    return pk, sk

def ml_kem_encaps(pk):
    """Encapsulate using public key.
    Returns (ciphertext: 1568 bytes, shared_secret: 32 bytes)"""
    kem = oqs.KeyEncapsulation(KEM_NAME)
    return kem.encap_secret(pk)

def ml_kem_decaps(ct, sk):
    """Decapsulate using secret key.
    Returns shared_secret: 32 bytes"""
    kem = oqs.KeyEncapsulation(KEM_NAME, sk)
    return kem.decap_secret(ct)

def ml_kem_self_test():
    """Verify ML-KEM-1024 correctness."""
    pk, sk = ml_kem_keygen()
    ct, ss1 = ml_kem_encaps(pk)
    ss2 = ml_kem_decaps(ct, sk)
    return ss1 == ss2

if __name__ == "__main__":
    assert ml_kem_self_test(), "ML-KEM-1024 self-test FAILED"
    print("ML-KEM-1024 Self-Test: PASSED")
    print(f"  PK={PK_SIZE}B, CT={CT_SIZE}B, SS={SS_SIZE}B")
    print("Post-quantum key exchange: READY")
