"""
SHROUD <-> Discord bridge.

Same pattern as ``matrix_bridge.py``. Forwards between a SHROUD
identity and a Discord channel.

Architecture::

    SHROUD relay  <-->  discord_bridge.py  <-->  Discord channel

The bridge is opt-in; users who don't trust the bridge process should
not use it. Discord servers see only the bridge's output messages,
not the user's SHROUD identity. SHROUD relay sees only the bridge's
sealed envelopes.

Usage::

    pip install "discord.py>=2.0"
    export DISCORD_TOKEN=...
    python -m tools.discord_bridge \\
        --shroud-identity ./bridge.id.json \\
        --shroud-contact ./alice.contact.json \\
        --discord-channel-id 1234567890
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


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD <-> Discord bridge")
    ap.add_argument("--relay-url", default="https://44.202.225.57:58443")
    ap.add_argument("--shroud-identity", required=True)
    ap.add_argument("--shroud-contact", required=True)
    ap.add_argument("--discord-channel-id", type=int, required=True)
    ap.add_argument("--token-env", default="DISCORD_TOKEN")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    token = os.environ.get(args.token_env)
    if not token:
        print(f"ERROR: ${args.token_env} not set", file=sys.stderr)
        return 1

    try:
        import discord
    except ImportError:
        print("ERROR: discord.py not installed. pip install discord.py",
              file=sys.stderr)
        return 1

    from clients.python_sdk import ShroudClient, Contact

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

    intents = discord.Intents.default()
    intents.message_content = True
    client = discord.Client(intents=intents)

    @client.event
    async def on_ready():
        print(f"[bridge] discord logged in as {client.user}")
        # Kick off SHROUD poll loop now that discord is ready.
        asyncio.create_task(shroud_poll_loop())

    @client.event
    async def on_message(message: discord.Message):
        if message.author.id == client.user.id:
            return
        if message.channel.id != args.discord_channel_id:
            return
        body = f"[discord:{message.author.display_name}] {message.content}"
        print(f"[bridge] discord -> shroud: {body!r}")
        try:
            shroud.send(contact_name, body)
        except Exception as e:
            print(f"[bridge] shroud send failed: {e}")

    async def shroud_poll_loop():
        channel = client.get_channel(args.discord_channel_id)
        if channel is None:
            print(f"[bridge] discord channel {args.discord_channel_id} not found",
                  file=sys.stderr)
            return
        while not client.is_closed():
            try:
                for msg in shroud.poll_once():
                    body = f"[shroud:{msg.sender_label}] {msg.body}"
                    print(f"[bridge] shroud -> discord: {body!r}")
                    await channel.send(body)
            except Exception as e:
                print(f"[bridge] shroud poll error: {e}")
            await asyncio.sleep(3.0)

    client.run(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
