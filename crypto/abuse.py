"""
SHROUD server-side abuse mitigation.

The relay is a public endpoint accepting opaque ciphertext at high
volume. Without per-source limits a single malicious client (or a
botnet) can fill the queue with junk envelopes, run up bandwidth
costs, or saturate the storage.

This module ships rate-limit policy + a token-bucket implementation
that the FastAPI server uses on every incoming request that could be
abused.

Rate-limit dimensions
---------------------

We rate-limit on three orthogonal keys:

  - **IP address.** Coarse-grained, defeats single-machine floods.
    Defaults: 240 requests / minute per IP for /send-anon.
  - **routing_tag prefix.** Defaults: 60 messages / hour per
    routing_tag, so a single conversation can't be used to amplify
    a flood.
  - **anon_creds token.** When the relay requires
    /api/v1/credentials/redeem on a particular endpoint, each spent
    token is a one-shot — natural rate limit. anon_creds tokens are
    rationed at issue time per device_id.

Token-bucket algorithm
----------------------

Standard. Each (key, dimension) has a bucket of N tokens that refills
at R tokens/second. Each request consumes one token. If the bucket is
empty, the request is rejected with 429 Too Many Requests.

The state is kept in-memory; for a multi-instance deployment, swap
``LocalBucket`` for a Redis-backed implementation with the same API.

Rule compliance
---------------
  - Rule 1: we limit by routing_tag (not sender). The server already
    knows the routing tag — it's the routing primitive — so this
    doesn't leak new information.
  - Rule 2: same — the routing tag is what the server already sees.
  - Rule 3: orthogonal.
"""
from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class _Bucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    last_check: float


class LocalBucket:
    """In-memory thread-safe token bucket per key."""

    def __init__(self, capacity: float, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill = refill_per_sec
        self._lock = threading.Lock()
        self._buckets: Dict[str, _Bucket] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        t = now if now is not None else time.time()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(self.capacity, self.refill, self.capacity, t)
                self._buckets[key] = b
            # Refill.
            elapsed = max(0.0, t - b.last_check)
            b.tokens = min(b.capacity, b.tokens + elapsed * b.refill_per_sec)
            b.last_check = t
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True
            return False

    def stats(self, key: str) -> dict | None:
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                return None
            return {
                "capacity": b.capacity,
                "tokens": b.tokens,
                "refill_per_sec": b.refill_per_sec,
            }

    def purge_idle(self, older_than_seconds: float = 3600) -> int:
        cutoff = time.time() - older_than_seconds
        with self._lock:
            stale = [k for k, b in self._buckets.items()
                     if b.last_check < cutoff and b.tokens >= b.capacity]
            for k in stale:
                del self._buckets[k]
            return len(stale)


# ── Policy presets ───────────────────────────────────────────────────


@dataclass
class AbusePolicy:
    """Default thresholds. Tune per deployment."""
    per_ip_send_per_min: int = 240
    per_ip_fetch_per_min: int = 600
    per_tag_send_per_hour: int = 60
    per_ip_anon_credits_per_day: int = 2400

    def send_buckets(self) -> Dict[str, LocalBucket]:
        # Buckets refill continuously. Capacity = max burst.
        return {
            "ip_send":   LocalBucket(self.per_ip_send_per_min,   self.per_ip_send_per_min   / 60.0),
            "ip_fetch":  LocalBucket(self.per_ip_fetch_per_min,  self.per_ip_fetch_per_min  / 60.0),
            "tag_send":  LocalBucket(self.per_tag_send_per_hour, self.per_tag_send_per_hour / 3600.0),
            "ip_creds":  LocalBucket(self.per_ip_anon_credits_per_day, self.per_ip_anon_credits_per_day / 86400.0),
        }


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Token bucket basics: capacity 10, refill 1/sec
    b = LocalBucket(capacity=10, refill_per_sec=1.0)
    # First 10 allowed
    for i in range(10):
        assert b.allow("alice", now=100.0), f"call {i} should pass"
    # 11th rejected
    assert not b.allow("alice", now=100.0)
    # After 5 seconds of refill: 5 more pass
    for i in range(5):
        assert b.allow("alice", now=105.0)
    assert not b.allow("alice", now=105.0)
    # Different key has its own bucket
    assert b.allow("bob", now=105.0)

    # Stats
    s = b.stats("bob")
    assert s["capacity"] == 10
    assert s["tokens"] < 10

    # Purge idle
    purged = b.purge_idle(older_than_seconds=-1)  # purge anything not at full
    assert purged == 0  # bob just used a token, not "idle full"

    # AbusePolicy gives a coherent bucket map
    policy = AbusePolicy()
    buckets = policy.send_buckets()
    assert set(buckets) == {"ip_send", "ip_fetch", "tag_send", "ip_creds"}
    # ip_send default = 240/min capacity, refill = 4/sec
    assert buckets["ip_send"].capacity == 240
    assert abs(buckets["ip_send"].refill - 4.0) < 1e-9

    print("abuse self-tests passed.")


if __name__ == "__main__":
    _self_test()
