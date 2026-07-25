"""
SHROUD Selective Forwarding Unit (SFU) — group call media relay.

A SFU receives DTLS-SRTP packets from each participant in a group
call and forwards them to the others, *without ever decoding the
media*. SHROUD's SFU is intentionally a dumb pipe: it inspects only
the session identifier (a 32-byte opaque token assigned by the call
initiator) and the participant's ephemeral routing token; it never
touches the SRTP payload.

This module is a runnable FastAPI app — small enough to deploy on
the same EC2 instance as the SHROUD relay, or to bring up separately
on a per-region basis.

Topology
--------

::

    Client A ----> SFU ----> Client B
                    \\----> Client C
                     \\---> Client D
    Client B ----> SFU ----> Client A, C, D
    ... etc.

Each client maintains exactly one WebSocket connection to the SFU
for the duration of the call. The SFU forwards all received packets
to every other participant in the same session.

Why not full-mesh
-----------------

Full-mesh works for ≤ 6 participants. Above that, the per-client
upload bandwidth becomes prohibitive (N-1 simultaneous encodes per
sender). A SFU lets each participant encode once and the SFU
fans out N-1 copies. The SFU cannot decode because the media is
DTLS-SRTP-encrypted between the participants, not between
participant↔SFU.

Wire format
-----------

  - Session creation: ``POST /sfu/sessions`` with
    ``{"session_id": "<32 byte hex>", "participants": ["<32 byte hex>", ...]}``.
    Returns a single-use websocket URL per participant.
  - Media: opaque WebSocket binary frames in either direction. The
    SFU broadcasts every frame to every other participant in the
    session.
  - Departure: closing the WebSocket signals the SFU to drop the
    participant from the session's broadcast set. When the last
    participant leaves, the session is destroyed.

Rule compliance
---------------
  - Rule 1: the SFU only knows participant ephemeral tokens, not
    identity. Tokens are issued via the existing /devices/link/* or
    anon-credentials flow, not SFU itself.
  - Rule 2: the SFU sees only the session_id and the ephemeral
    tokens of participants in that session. Sessions are short-lived
    (call duration only); no persistent log.
  - Rule 3: opaque media bytes. The SFU does not decode.
"""
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from typing import Dict, Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel


# ── Data ─────────────────────────────────────────────────────────────


@dataclass
class _Participant:
    token: str
    websocket: WebSocket | None = None


@dataclass
class _Session:
    session_id: str
    participants: Dict[str, _Participant] = field(default_factory=dict)

    def broadcast_targets(self, source_token: str) -> list[_Participant]:
        return [p for tok, p in self.participants.items()
                if tok != source_token and p.websocket is not None]


# Shared mutable state — single-process SFU only. For multi-process
# deployments, swap for a Redis-backed registry.
_SESSIONS: Dict[str, _Session] = {}
_SESSIONS_LOCK = asyncio.Lock()


# ── App ─────────────────────────────────────────────────────────────


app = FastAPI(title="SHROUD SFU")


class CreateSessionRequest(BaseModel):
    participants: int   # how many participants will join
    session_id: str | None = None    # optional, server picks if None


class CreateSessionResponse(BaseModel):
    session_id: str
    tokens: list[str]


@app.post("/sfu/sessions", response_model=CreateSessionResponse)
async def create_session(req: CreateSessionRequest) -> CreateSessionResponse:
    if not (2 <= req.participants <= 32):
        raise HTTPException(400, "participants must be 2..32")
    sid = req.session_id or secrets.token_hex(16)

    async with _SESSIONS_LOCK:
        if sid in _SESSIONS:
            raise HTTPException(409, "session id already exists")
        tokens = [secrets.token_hex(16) for _ in range(req.participants)]
        sess = _Session(session_id=sid)
        for tok in tokens:
            sess.participants[tok] = _Participant(token=tok)
        _SESSIONS[sid] = sess

    return CreateSessionResponse(session_id=sid, tokens=tokens)


@app.get("/sfu/sessions/{session_id}/active")
async def session_active(session_id: str) -> dict:
    sess = _SESSIONS.get(session_id)
    if sess is None:
        raise HTTPException(404, "no such session")
    return {
        "session_id": session_id,
        "active": sum(1 for p in sess.participants.values() if p.websocket is not None),
        "capacity": len(sess.participants),
    }


@app.websocket("/sfu/ws/{session_id}/{token}")
async def sfu_websocket(ws: WebSocket, session_id: str, token: str) -> None:
    await ws.accept()
    sess = _SESSIONS.get(session_id)
    if sess is None or token not in sess.participants:
        await ws.close(code=1008)  # policy violation
        return

    participant = sess.participants[token]
    if participant.websocket is not None:
        # Token already in use elsewhere — reject.
        await ws.close(code=1008)
        return

    participant.websocket = ws

    try:
        while True:
            msg = await ws.receive_bytes()
            # Forward opaque bytes to every other active participant.
            targets = sess.broadcast_targets(token)
            await asyncio.gather(
                *(p.websocket.send_bytes(msg) for p in targets),
                return_exceptions=True,
            )
    except WebSocketDisconnect:
        pass
    finally:
        participant.websocket = None
        # If everyone has left, drop the session.
        async with _SESSIONS_LOCK:
            still_active = any(
                p.websocket is not None
                for p in sess.participants.values()
            )
            if not still_active and sess.session_id in _SESSIONS:
                del _SESSIONS[sess.session_id]


# ── Standalone runner ────────────────────────────────────────────────


def main() -> None:
    """Run the SFU as a standalone service on port 58444.

    This said "HTTPS" and then called uvicorn with no ssl_keyfile or
    ssl_certfile, so it bound 0.0.0.0 in the clear. That matters more
    here than it looks: the media itself is DTLS-SRTP between
    participants, but the join tokens are not protected by it. They are
    returned in the /sfu/sessions response and then appear in the
    WebSocket path, and they are the *only* access control the SFU has —
    sfu_websocket admits anyone presenting a token in the session. On a
    plaintext channel an on-path observer can lift a token and join the
    call, and also read the session/participant graph the module docstring
    claims it does not expose.

    Takes the same TLS flags and environment variables as server.py so a
    systemd or Docker deployment configures both the same way, and says
    so loudly when TLS is absent instead of silently serving cleartext.
    """
    import argparse
    import os
    import sys
    import uvicorn

    ap = argparse.ArgumentParser(description="SHROUD SFU (group-call media relay)")
    ap.add_argument("--bind", default=os.environ.get("SHROUD_SFU_BIND", "0.0.0.0"),
                    help="Interface to listen on (default 0.0.0.0).")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("SHROUD_SFU_PORT", "58444")),
                    help="TCP port to listen on (default 58444).")
    ap.add_argument("--ssl-keyfile", default=os.environ.get("SHROUD_TLS_KEY", ""),
                    help="TLS private key. With --ssl-certfile, serves HTTPS/WSS.")
    ap.add_argument("--ssl-certfile", default=os.environ.get("SHROUD_TLS_CERT", ""),
                    help="TLS certificate chain.")
    args = ap.parse_args()

    kwargs = dict(host=args.bind, port=args.port, log_level="info")
    if args.ssl_keyfile and args.ssl_certfile:
        kwargs["ssl_keyfile"] = args.ssl_keyfile
        kwargs["ssl_certfile"] = args.ssl_certfile
        print(f"[SHROUD-SFU] Listening on https://{args.bind}:{args.port} (wss)")
    else:
        print(f"[SHROUD-SFU] Listening on http://{args.bind}:{args.port}", flush=True)
        print("[SHROUD-SFU] WARNING: no TLS configured. Join tokens are the only "
              "access control on a call and they travel in the session response "
              "and the WebSocket path — in cleartext anyone on-path can join. "
              "Pass --ssl-keyfile/--ssl-certfile (or SHROUD_TLS_KEY/SHROUD_TLS_CERT), "
              "or bind to 127.0.0.1 and terminate TLS in front.",
              file=sys.stderr, flush=True)
        if args.bind not in ("127.0.0.1", "localhost", "::1"):
            print(f"[SHROUD-SFU] WARNING: bound to {args.bind} without TLS — "
                  f"reachable off-host in the clear.", file=sys.stderr, flush=True)

    uvicorn.run("server.sfu:app", **kwargs)


if __name__ == "__main__":
    main()
