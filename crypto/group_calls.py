"""
SHROUD multi-party group calls (voice + video, up to ~16 participants).

Extends ``crypto.calls`` to N-party calls. The single 1-on-1 signaling
flow becomes a roster-based protocol where each participant signals
the others through their pairwise sealed-envelope channel.

Topology options
----------------

Three modes, selectable at call creation time:

  full-mesh
    Every pair of participants negotiates a direct WebRTC PeerConnection.
    With N participants you get N*(N-1)/2 connections, N*(N-1) media
    streams. Best privacy (no SFU server sees anything beyond opaque
    packets), highest bandwidth. Practical up to ~6 participants.

  sfu
    Each participant connects to a single Selective Forwarding Unit
    (SFU) — operated by a federation peer or a dedicated TURN/SFU
    server. The SFU forwards (does not decode) DTLS-SRTP packets
    between participants. Per-leg media is E2EE because DTLS-SRTP
    keys are derived in the signaling phase via the per-pair sealed
    channels, with TreeKEM ratcheting the group key whenever the
    roster changes. Supports up to ~16 participants.

  hybrid
    Audio is full-mesh (low bandwidth, latency-critical), video is
    SFU (high bandwidth, can tolerate one forwarding hop). Useful
    when call participants share rough geographic locality.

State machine
-------------

::

                                +--------------+
                                |  recruiting  |
    create-group-call -----+----> (offers sent |
                           |    | to invitees) |
                           |    +-------+------+
                           |            |
                           |   N-1 accepts gather
                           |            |
                           |            v
                           |    +--------------+
                           |    |   active     |
                           |    | (TreeKEM     |
                           |    |  ratcheting) |
                           |    +-------+------+
                           |            |
                           |    leave / join
                           |            |
                           |            v
                           |    +--------------+
                           +----+   ended       |
                                +--------------+

Wire format additions over crypto.calls
---------------------------------------

GroupCallInvite (initiator -> each invitee):

::

    {
      "type":          "shroud.group_call.invite",
      "group_call_id": "<random 16 hex>",
      "topology":      "full-mesh" | "sfu" | "hybrid",
      "sfu_endpoint":  "wss://sfu.example/relay/<sfu_session_id>",  // SFU/hybrid only
      "treekem_state":  <opaque hex blob from crypto.treekem>,
      "media":         ["audio"] or ["audio", "video"],
      "roster":        ["<x25519 pubkey hex>", ...],
      "ts":            <unix sec>
    }

GroupCallJoin (invitee -> all members through their pairwise channel):

::

    {
      "type":          "shroud.group_call.join",
      "group_call_id": "<hex>",
      "joining_pubkey":"<x25519 hex>",
      "ts":            <unix sec>
    }

GroupCallLeave (member -> all others):

::

    {
      "type":          "shroud.group_call.leave",
      "group_call_id": "<hex>",
      "leaving_pubkey":"<x25519 hex>",
      "reason":        "hangup" | "timeout" | "kicked",
      "ts":            <unix sec>
    }

GroupCallRekey (any member -> all others, after a join/leave):

::

    {
      "type":           "shroud.group_call.rekey",
      "group_call_id":  "<hex>",
      "epoch":          <int counter>,
      "treekem_commit": <opaque hex blob>,
      "ts":             <unix sec>
    }

Rule compliance
---------------
  - Rule 1: every signaling message rides a per-pair sealed envelope
    (crypto.anon_routing) — server sees only opaque bytes.
  - Rule 2: per-pair routing tags as usual; the group_call_id is NOT
    a routing field, it's just a correlation id inside the encrypted
    payload.
  - Rule 3: the only identifying field is each member's X25519 pubkey,
    which is already the long-term identity used everywhere else.
    SFU-relayed media is DTLS-SRTP between participants, which the
    SFU cannot decrypt.
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Set


SHROUD_GROUP_INVITE  = "shroud.group_call.invite"
SHROUD_GROUP_JOIN    = "shroud.group_call.join"
SHROUD_GROUP_LEAVE   = "shroud.group_call.leave"
SHROUD_GROUP_REKEY   = "shroud.group_call.rekey"


# ── Wire types ───────────────────────────────────────────────────────


@dataclass
class GroupCallInvite:
    group_call_id: str
    topology: str           # "full-mesh" | "sfu" | "hybrid"
    sfu_endpoint: Optional[str]
    treekem_state_hex: str   # opaque blob from crypto.treekem
    media: List[str]
    roster_hex: List[str]    # X25519 pubkey hex of each invited participant
    ts: int

    def to_dict(self) -> dict:
        return {
            "type": SHROUD_GROUP_INVITE,
            "group_call_id": self.group_call_id,
            "topology": self.topology,
            "sfu_endpoint": self.sfu_endpoint,
            "treekem_state": self.treekem_state_hex,
            "media": self.media,
            "roster": self.roster_hex,
            "ts": self.ts,
        }


@dataclass
class GroupCallJoin:
    group_call_id: str
    joining_pubkey_hex: str
    ts: int

    def to_dict(self) -> dict:
        return {
            "type": SHROUD_GROUP_JOIN,
            "group_call_id": self.group_call_id,
            "joining_pubkey": self.joining_pubkey_hex,
            "ts": self.ts,
        }


@dataclass
class GroupCallLeave:
    group_call_id: str
    leaving_pubkey_hex: str
    reason: str
    ts: int

    def to_dict(self) -> dict:
        return {
            "type": SHROUD_GROUP_LEAVE,
            "group_call_id": self.group_call_id,
            "leaving_pubkey": self.leaving_pubkey_hex,
            "reason": self.reason,
            "ts": self.ts,
        }


@dataclass
class GroupCallRekey:
    group_call_id: str
    epoch: int
    treekem_commit_hex: str
    ts: int

    def to_dict(self) -> dict:
        return {
            "type": SHROUD_GROUP_REKEY,
            "group_call_id": self.group_call_id,
            "epoch": self.epoch,
            "treekem_commit": self.treekem_commit_hex,
            "ts": self.ts,
        }


def new_group_call_id() -> str:
    return secrets.token_hex(8)


def parse_group_signaling(blob: bytes):
    try:
        d = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    t = d.get("type")
    try:
        if t == SHROUD_GROUP_INVITE:
            return GroupCallInvite(
                group_call_id=d["group_call_id"],
                topology=d.get("topology", "full-mesh"),
                sfu_endpoint=d.get("sfu_endpoint"),
                treekem_state_hex=d.get("treekem_state", ""),
                media=list(d.get("media", ["audio"])),
                roster_hex=list(d.get("roster", [])),
                ts=int(d.get("ts", 0)),
            )
        if t == SHROUD_GROUP_JOIN:
            return GroupCallJoin(
                group_call_id=d["group_call_id"],
                joining_pubkey_hex=d["joining_pubkey"],
                ts=int(d.get("ts", 0)),
            )
        if t == SHROUD_GROUP_LEAVE:
            return GroupCallLeave(
                group_call_id=d["group_call_id"],
                leaving_pubkey_hex=d["leaving_pubkey"],
                reason=d.get("reason", "hangup"),
                ts=int(d.get("ts", 0)),
            )
        if t == SHROUD_GROUP_REKEY:
            return GroupCallRekey(
                group_call_id=d["group_call_id"],
                epoch=int(d.get("epoch", 0)),
                treekem_commit_hex=d.get("treekem_commit", ""),
                ts=int(d.get("ts", 0)),
            )
    except (KeyError, TypeError, ValueError):
        return None
    return None


# ── Group call state ─────────────────────────────────────────────────


class GroupCallState:
    RECRUITING = "recruiting"
    ACTIVE     = "active"
    ENDED      = "ended"


@dataclass
class GroupCallSession:
    """Local view of one group call. Wraps WebRTC PCs + TreeKEM state
    on real clients."""
    group_call_id: str
    topology: str            # full-mesh | sfu | hybrid
    media: List[str]
    initiator_pubkey_hex: str
    my_pubkey_hex: str
    state: str = GroupCallState.RECRUITING
    roster: Set[str] = field(default_factory=set)         # currently-connected pubkeys
    pending: Set[str] = field(default_factory=set)        # invited but not yet joined
    treekem_epoch: int = 0
    sfu_endpoint: Optional[str] = None
    started_at: float = 0.0

    def begin(self) -> None:
        self.state = GroupCallState.RECRUITING
        self.started_at = time.time()

    def member_joined(self, pubkey_hex: str) -> None:
        if pubkey_hex in self.pending:
            self.pending.discard(pubkey_hex)
        self.roster.add(pubkey_hex)
        # Bump TreeKEM epoch — every membership change rotates group keys
        # so historical traffic stays unrecoverable to a newly-joined peer.
        self.treekem_epoch += 1
        # Promote to ACTIVE once at least the initiator + one invitee are in.
        if self.state == GroupCallState.RECRUITING and len(self.roster) >= 2:
            self.state = GroupCallState.ACTIVE

    def member_left(self, pubkey_hex: str) -> None:
        self.roster.discard(pubkey_hex)
        self.treekem_epoch += 1
        # If the initiator and we're alone, the call effectively ends.
        if len(self.roster) <= 1:
            self.state = GroupCallState.ENDED

    def end(self) -> None:
        self.state = GroupCallState.ENDED


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    gid = new_group_call_id()
    assert len(gid) == 16

    # Three-party group call
    alice = "aa" * 32
    bob   = "bb" * 32
    carol = "cc" * 32

    sess = GroupCallSession(
        group_call_id=gid,
        topology="full-mesh",
        media=["audio", "video"],
        initiator_pubkey_hex=alice,
        my_pubkey_hex=alice,
    )
    sess.pending = {bob, carol}
    sess.roster = {alice}
    sess.begin()
    assert sess.state == GroupCallState.RECRUITING

    sess.member_joined(bob)
    assert sess.state == GroupCallState.ACTIVE
    assert sess.treekem_epoch == 1

    sess.member_joined(carol)
    assert sess.state == GroupCallState.ACTIVE
    assert sess.treekem_epoch == 2
    assert sess.roster == {alice, bob, carol}

    sess.member_left(bob)
    assert sess.treekem_epoch == 3
    assert sess.roster == {alice, carol}
    # Still 2 members so still ACTIVE.
    assert sess.state == GroupCallState.ACTIVE

    sess.member_left(carol)
    # Now only Alice remains -> call ends.
    assert sess.state == GroupCallState.ENDED

    # Wire-format round trips
    inv = GroupCallInvite(
        group_call_id=gid, topology="hybrid",
        sfu_endpoint="wss://sfu.example/r/xyz", treekem_state_hex="00" * 64,
        media=["audio", "video"], roster_hex=[alice, bob, carol],
        ts=int(time.time()),
    )
    blob = json.dumps(inv.to_dict(), sort_keys=True).encode()
    parsed = parse_group_signaling(blob)
    assert isinstance(parsed, GroupCallInvite)
    assert parsed.group_call_id == gid
    assert parsed.topology == "hybrid"
    assert parsed.sfu_endpoint == "wss://sfu.example/r/xyz"
    assert set(parsed.roster_hex) == {alice, bob, carol}

    rk = GroupCallRekey(group_call_id=gid, epoch=3, treekem_commit_hex="dd" * 32, ts=int(time.time()))
    blob2 = json.dumps(rk.to_dict(), sort_keys=True).encode()
    parsed2 = parse_group_signaling(blob2)
    assert isinstance(parsed2, GroupCallRekey)
    assert parsed2.epoch == 3

    print("group_calls self-tests passed.")


if __name__ == "__main__":
    _self_test()
