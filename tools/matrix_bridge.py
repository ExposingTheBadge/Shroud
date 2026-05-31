"""
SHROUD <-> Matrix bridge.

Forwards messages between a SHROUD identity and a Matrix room. Useful
for users who want to participate in a Matrix community without
exposing their primary chat client to the room's metadata.

Architecture::

    SHROUD relay  <-->  matrix_bridge.py  <-->  Matrix homeserver
                            (this process)

The bridge is a SHROUD client (via clients/python_sdk.ShroudClient) AND
a Matrix bot (via matrix-nio). Inbound Matrix messages get forwarded
to a pre-configured SHROUD contact; inbound SHROUD messages get posted
to a pre-configured Matrix room.

The bridge is fully sealed: messages between the bridge and the SHROUD
relay are sealed envelopes; messages between the bridge and Matrix are
encrypted under Matrix's own Megolm. The bridge itself sees plaintext —
that's the design tradeoff for a bridge. Users who don't trust the
bridge should not use it.

This is opt-in. The default SHROUD network does NOT include a bridge.

Rule compliance
---------------
  - Rule 1: SHROUD relay only sees the bridge's outbound sealed
    envelopes addressed to the user's routing tag.
  - Rule 2: same.
  - Rule 3: any media forwarded from Matrix gets stripped via
    crypto.strip_metadata before sealing. Matrix's own media is
    Megolm-encrypted to the room.
  - Rule 0: orthogonal — the bridge is a per-user opt-in.

Usage::

    pip install matrix-nio shroud-anon-routing
    python -m tools.matrix_bridge \\
        --shroud-identity ./bridge.id.json \\
        --shroud-contact ./alice.contact.json \\
        --matrix-homeserver https://matrix.org \\
        --matrix-user @mybridge:matrix.org \\
        --matrix-password env:MATRIX_PASSWORD \\
        --matrix-room "!roomid:matrix.org"
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _resolve_secret(spec: str) -> str:
    """Accept either 'env:NAME' or a literal value."""
    if spec.startswith("env:"):
        v = os.environ.get(spec[4:])
        if v is None:
            raise SystemExit(f"environment variable {spec[4:]} not set")
        return v
    return spec


async def run_bridge(args) -> None:
    try:
        from nio import AsyncClient, RoomMessageText
    except ImportError:
        print("ERROR: matrix-nio not installed. pip install matrix-nio",
              file=sys.stderr)
        return

    from clients.python_sdk import ShroudClient, Contact, ReceivedMessage

    # ── SHROUD side ──
    shroud = ShroudClient(
        relay_url=args.relay_url,
        identity_path=args.shroud_identity,
        verify_tls=args.verify_tls,
        poll_interval_seconds=3.0,
    )
    with open(args.shroud_contact, "r") as f:
        contact_dict = json.load(f)
    shroud.add_contact(Contact(**contact_dict))
    contact_name = contact_dict["name"]

    # ── Matrix side ──
    matrix = AsyncClient(args.matrix_homeserver, args.matrix_user)
    password = _resolve_secret(args.matrix_password)
    await matrix.login(password)
    await matrix.join(args.matrix_room)
    print(f"[bridge] connected to Matrix as {args.matrix_user}")
    print(f"[bridge] forwarding to SHROUD contact: {contact_name}")

    # Suppress messages the bridge itself just sent (avoid feedback loop)
    own_event_ids: set[str] = set()

    async def matrix_callback(room, event):
        if not isinstance(event, RoomMessageText):
            return
        if event.event_id in own_event_ids:
            return
        if event.sender == args.matrix_user:
            return
        body = event.body
        print(f"[bridge] matrix -> shroud: {body!r}")
        try:
            shroud.send(contact_name, f"[matrix:{event.sender}] {body}")
        except Exception as e:
            print(f"[bridge] shroud send failed: {e}")

    matrix.add_event_callback(matrix_callback, RoomMessageText)

    # Poll SHROUD in parallel and forward to Matrix.
    async def shroud_poll_loop():
        while True:
            try:
                for msg in shroud.poll_once():
                    body = f"[shroud:{msg.sender_label}] {msg.body}"
                    print(f"[bridge] shroud -> matrix: {body!r}")
                    resp = await matrix.room_send(
                        room_id=args.matrix_room,
                        message_type="m.room.message",
                        content={"msgtype": "m.text", "body": body},
                    )
                    own_event_ids.add(getattr(resp, "event_id", ""))
            except Exception as e:
                print(f"[bridge] shroud poll error: {e}")
            await asyncio.sleep(3.0)

    sync_task = asyncio.create_task(matrix.sync_forever(timeout=30000))
    shroud_task = asyncio.create_task(shroud_poll_loop())

    try:
        await asyncio.gather(sync_task, shroud_task)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await matrix.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD <-> Matrix bridge")
    ap.add_argument("--relay-url", default="https://44.202.225.57:58443")
    ap.add_argument("--shroud-identity", required=True)
    ap.add_argument("--shroud-contact", required=True,
                    help="JSON file with name, identity_pubkey_hex, shared_root_hex")
    ap.add_argument("--matrix-homeserver", required=True)
    ap.add_argument("--matrix-user", required=True,
                    help="@user:matrix.org")
    ap.add_argument("--matrix-password", required=True,
                    help="Literal password, or 'env:VARNAME' to read from env")
    ap.add_argument("--matrix-room", required=True,
                    help="!roomid:matrix.org")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    asyncio.run(run_bridge(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
