"""
SHROUD protocol micro-benchmarks.

Measures the per-operation cost of the hot-path protocol modules so
regressions are obvious. Not a replacement for proper profiling under
load; this is a "did my refactor make seal() 10x slower" smoke test.

Run::

    python -m tests.benchmark
"""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from crypto.anon_routing import (
    seal, unseal, routing_tag, pair_id, epoch_for,
)
from crypto.pq_double_ratchet import (
    init_alice, init_bob, encrypt as pq_encrypt, decrypt as pq_decrypt, KEM,
)


@contextmanager
def _timed(label: str, iters: int):
    t0 = time.perf_counter()
    yield
    t = (time.perf_counter() - t0) * 1000
    per_op = t / iters
    print(f"  {label:<40}  {iters:>6} ops  {t:>8.1f} ms  {per_op:>7.3f} ms/op")


def bench_anon_routing() -> None:
    print("\nanon_routing:")
    payload = b"x" * 256
    bob_priv = X25519PrivateKey.generate()
    bob_pub = bob_priv.public_key().public_bytes_raw()
    bob_sk = bob_priv.private_bytes_raw()

    iters = 500
    with _timed("seal (256 B payload)", iters):
        sealed_acc = None
        for _ in range(iters):
            sealed_acc = seal(payload, bob_pub)

    with _timed("unseal (256 B payload)", iters):
        for _ in range(iters):
            unseal(sealed_acc, bob_sk)

    root = os.urandom(32)
    pid = pair_id(os.urandom(32), os.urandom(32))
    e = epoch_for()
    iters = 5000
    with _timed("routing_tag", iters):
        for _ in range(iters):
            routing_tag(root, pid, e)


def bench_pq_double_ratchet() -> None:
    print("\npq_double_ratchet:")
    root = os.urandom(32)
    bob_dh_priv = os.urandom(32)
    # Use a real X25519 keypair so DH works.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    sk = X25519PrivateKey.generate()
    bob_dh_priv = sk.private_bytes_raw()
    bob_dh_pub = sk.public_key().public_bytes_raw()
    bob_kem_pk, bob_kem_sk = KEM.keygen()

    alice = init_alice(root, bob_dh_pub, bob_kem_pk)
    bob = init_bob(root, bob_dh_pub, bob_dh_priv, bob_kem_pk, bob_kem_sk)

    # First message warms the ratchet on both sides.
    m1 = pq_encrypt(alice, b"warmup")
    pq_decrypt(bob, m1)

    iters = 200
    payload = b"x" * 128
    with _timed("pq_double_ratchet encrypt (128 B)", iters):
        for _ in range(iters):
            pq_encrypt(alice, payload)

    iters = 50  # decrypt also drives chain; fewer to keep test fast
    msgs = [pq_encrypt(alice, payload) for _ in range(iters)]
    # The receiver only ratchets on the first message of a new chain;
    # subsequent messages just advance the symmetric chain. So decrypt
    # is roughly as fast as a chain advance.
    with _timed("pq_double_ratchet decrypt (128 B)", iters):
        for m in msgs:
            pq_decrypt(bob, m)


def main() -> int:
    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {sys.platform}")
    bench_anon_routing()
    bench_pq_double_ratchet()
    print("\nBenchmarks complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
