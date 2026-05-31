"""
SHROUD echo bot — minimal demo built on the Python SDK.

Listens for messages from any contact in its address book and echoes
them back. Runs against the live AWS relay by default; override with
``--relay-url``.

Usage::

    python -m tools.echo_bot --identity ./echo.id.json
    # then in another shell, point another SHROUD client at this
    # bot's identity pubkey + a shared root, send "hello bot", and
    # watch it echo "bot: hello bot" back.

This file is also the shortest end-to-end demo of the whole protocol.
Reading it is the fastest way to understand what a working SHROUD
client looks like.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from clients.python_sdk import ShroudClient, Contact, ReceivedMessage


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD echo bot")
    ap.add_argument("--relay-url", default="https://44.202.225.57:58443")
    ap.add_argument("--identity", default="./echo_bot.id.json",
                    help="Where to persist the bot's identity")
    ap.add_argument("--verify-tls", action="store_true",
                    help="Strict TLS verification (default off for the dev relay)")
    ap.add_argument("--contacts", default="./echo_bot.contacts.json",
                    help="JSON list of {name,identity_pubkey_hex,shared_root_hex}")
    args = ap.parse_args()

    client = ShroudClient(
        relay_url=args.relay_url,
        identity_path=args.identity,
        verify_tls=args.verify_tls,
        poll_interval_seconds=3.0,
    )

    print(f"echo_bot identity pubkey: {client.identity.pub_x25519_hex}")
    print(f"echo_bot relay: {args.relay_url}")

    # Load contacts. Format: a JSON list of dicts with name + identity_pubkey_hex
    # + shared_root_hex.
    if os.path.exists(args.contacts):
        with open(args.contacts, "r") as f:
            for d in json.load(f):
                client.add_contact(Contact(**d))
        print(f"loaded {len(client.contacts())} contact(s) from {args.contacts}")
    else:
        print(f"no contacts file at {args.contacts}; will echo back to first sender")

    def on_message(msg: ReceivedMessage) -> None:
        print(f"<- '{msg.body}' from sender={msg.sender_label}")
        # Echo: find the contact (just use the first known one for the demo)
        contacts = client.contacts()
        if not contacts:
            print("   no contacts to echo to")
            return
        target = contacts[0]
        try:
            client.send(target.name, f"bot: {msg.body}")
            print(f"-> echoed to {target.name}")
        except Exception as e:
            print(f"   send failed: {e}")

    client.on_message = on_message
    print("polling — Ctrl+C to stop")
    client.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
