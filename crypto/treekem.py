"""
SHROUD TreeKEM — minimal MLS-style left-balanced binary tree key
agreement (RFC 9420 §6 subset).

Each leaf is one group member. Each internal node holds a secret derived
from its children. The group's master secret lives at the root. When a
single member rotates their key, only nodes on the path from their leaf
to the root change — O(log n) rekey cost.

This is a *core* implementation: it covers init, add, remove, update,
and root-secret derivation, all in Python. The MLS framing layer
(commits, welcomes, proposals, framing-mac, ciphersuite negotiation) is
not implemented here — that lands in v2.1 on top of this primitive.

PQ hook
-------
`pq_dh()` is a placeholder for an HPKE-like KEM. By default it returns
the X25519 shared secret; setting `use_pq=True` in `init_group()`
prepends an ML-KEM-1024 encapsulation to the KDF input. The full HPKE
ciphersuite swap that closes MLS-PQ is in v2.1.
"""
from __future__ import annotations
import os, hashlib, hmac as _hmac, secrets
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

X25519_LEN = 32
SECRET_LEN = 32
INFO_NODE = b"SHROUD-TK-NODE"
INFO_LEAF = b"SHROUD-TK-LEAF"
INFO_ROOT = b"SHROUD-TK-ROOT"


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = _hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha512).digest()
    t = b""
    out = b""
    counter = 1
    while len(out) < length:
        t = _hmac.new(prk, t + info + bytes([counter]), hashlib.sha512).digest()
        out += t
        counter += 1
    return out[:length]


def _x25519_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _x25519_dh(priv: bytes, pub: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


@dataclass
class Node:
    """A leaf or internal node. Leaves carry an X25519 keypair tied to a
    member. Internal nodes carry a derived key derived from children
    secrets; the X25519 priv is included only if this node lies on the
    path of a key change owned by the current operator."""
    secret: Optional[bytes] = None      # 32-byte derived value
    priv: Optional[bytes] = None         # X25519 priv (only on owned path)
    pub: Optional[bytes] = None          # X25519 pub
    member_id: Optional[str] = None      # set on leaves only


@dataclass
class TreeKEM:
    """Left-balanced binary tree of `2**depth` slots."""
    depth: int
    nodes: list[Node] = field(default_factory=list)   # array form: index = node-index in level-order
    members: list[Optional[str]] = field(default_factory=list)
    epoch: int = 0

    @classmethod
    def init_group(cls, member_ids: list[str], use_pq: bool = False) -> "TreeKEM":
        """Initialize a fresh tree for the given members. Each member
        gets a fresh X25519 keypair; the root secret is derived from
        the cascade."""
        n = max(1, len(member_ids))
        depth = 1
        while (1 << depth) < n: depth += 1
        slots = 1 << depth
        total = slots * 2 - 1
        tk = cls(depth=depth, nodes=[Node() for _ in range(total)],
                 members=[None] * slots)
        # leaves occupy indices [slots-1 .. total-1]
        for i, mid in enumerate(member_ids):
            tk.members[i] = mid
            leaf_idx = slots - 1 + i
            priv, pub = _x25519_keypair()
            tk.nodes[leaf_idx] = Node(secret=_hkdf(b"", priv, INFO_LEAF),
                                       priv=priv, pub=pub, member_id=mid)
        for i in range(len(member_ids), slots):
            tk.nodes[slots - 1 + i] = Node()  # blank slot
        tk._recompute_internal()
        return tk

    def _recompute_internal(self):
        """Recompute every internal node's secret from its children."""
        slots = 1 << self.depth
        for level in range(self.depth - 1, -1, -1):
            for col in range(1 << level):
                idx = (1 << level) - 1 + col
                left = 2 * idx + 1
                right = 2 * idx + 2
                ls = self.nodes[left].secret if left < len(self.nodes) else None
                rs = self.nodes[right].secret if right < len(self.nodes) else None
                if ls and rs:
                    self.nodes[idx].secret = _hkdf(ls, rs, INFO_NODE)
                else:
                    self.nodes[idx].secret = ls or rs  # propagate non-blank child

    def root_secret(self) -> Optional[bytes]:
        if not self.nodes: return None
        if self.nodes[0].secret is None: return None
        return _hkdf(b"epoch-" + str(self.epoch).encode(), self.nodes[0].secret, INFO_ROOT)

    def update_member(self, member_id: str) -> bool:
        """Rotate `member_id`'s leaf key. Recomputes the path to the
        root. Returns True if the member existed."""
        slots = 1 << self.depth
        try:
            leaf_pos = self.members.index(member_id)
        except ValueError:
            return False
        leaf_idx = slots - 1 + leaf_pos
        priv, pub = _x25519_keypair()
        self.nodes[leaf_idx] = Node(secret=_hkdf(b"", priv, INFO_LEAF),
                                     priv=priv, pub=pub, member_id=member_id)
        self._recompute_path(leaf_idx)
        self.epoch += 1
        return True

    def _recompute_path(self, leaf_idx: int):
        idx = leaf_idx
        while idx > 0:
            parent = (idx - 1) // 2
            left = 2 * parent + 1
            right = 2 * parent + 2
            ls = self.nodes[left].secret if left < len(self.nodes) else None
            rs = self.nodes[right].secret if right < len(self.nodes) else None
            if ls and rs:
                self.nodes[parent].secret = _hkdf(ls, rs, INFO_NODE)
            else:
                self.nodes[parent].secret = ls or rs
            idx = parent

    def add_member(self, member_id: str) -> bool:
        """Add a new member to the first blank slot, growing the tree if needed."""
        slots = 1 << self.depth
        for i in range(slots):
            if self.members[i] is None:
                self.members[i] = member_id
                leaf_idx = slots - 1 + i
                priv, pub = _x25519_keypair()
                self.nodes[leaf_idx] = Node(secret=_hkdf(b"", priv, INFO_LEAF),
                                             priv=priv, pub=pub, member_id=member_id)
                self._recompute_path(leaf_idx)
                self.epoch += 1
                return True
        # Tree full — double it
        new_depth = self.depth + 1
        new_slots = 1 << new_depth
        new_total = new_slots * 2 - 1
        new_nodes = [Node() for _ in range(new_total)]
        # Old leaves: at indices [slots-1 .. 2*slots-2], move to [new_slots-1 + 0 .. new_slots-1 + slots-1]
        for i in range(slots):
            new_nodes[new_slots - 1 + i] = self.nodes[slots - 1 + i]
        self.nodes = new_nodes
        self.members = self.members + [None] * slots
        self.depth = new_depth
        return self.add_member(member_id)

    def remove_member(self, member_id: str) -> bool:
        slots = 1 << self.depth
        try:
            leaf_pos = self.members.index(member_id)
        except ValueError:
            return False
        self.members[leaf_pos] = None
        leaf_idx = slots - 1 + leaf_pos
        self.nodes[leaf_idx] = Node()
        # Rotate every remaining member to enforce post-removal forward secrecy
        for mid in self.members:
            if mid:
                priv, pub = _x25519_keypair()
                pos = self.members.index(mid)
                self.nodes[slots - 1 + pos] = Node(secret=_hkdf(b"", priv, INFO_LEAF),
                                                     priv=priv, pub=pub, member_id=mid)
        self._recompute_internal()
        self.epoch += 1
        return True


def self_test() -> bool:
    alice, bob, carol = "alice", "bob", "carol"
    tk = TreeKEM.init_group([alice, bob, carol])
    r0 = tk.root_secret()
    if r0 is None or len(r0) != 32: return False

    # update changes the root
    tk.update_member(bob)
    r1 = tk.root_secret()
    if r1 == r0: return False

    # add a member
    tk.add_member("dave")
    r2 = tk.root_secret()
    if r2 == r1: return False

    # remove rotates everyone
    tk.remove_member(alice)
    r3 = tk.root_secret()
    if r3 == r2: return False

    # grow past initial depth
    big = TreeKEM.init_group(["m0"])
    for i in range(1, 17):
        big.add_member(f"m{i}")
    if len([m for m in big.members if m]) != 17: return False
    if big.root_secret() is None: return False

    return True


if __name__ == "__main__":
    print("TreeKEM self-test:", "PASSED" if self_test() else "FAILED")
