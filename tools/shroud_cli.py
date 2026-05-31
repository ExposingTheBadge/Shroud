"""
SHROUD CLI — interactive REPL on top of the Python SDK.

A bare-bones command-line client. Useful for:

  - quick testing against a live relay
  - SSH'ing into a server and reading/sending messages
  - scripted automation (pipe commands in)
  - learning the protocol surface

Commands::

    help
    me                              show my identity pubkey
    contacts                        list known contacts
    add <name> <pubkey> <root>      add a contact (hex pubkey, hex 32-byte root)
    send <name> <message...>        send a message to a contact
    poll                            poll once and print any inbox
    listen                          keep polling and printing until Ctrl+C
    quit / exit

Usage::

    python -m tools.shroud_cli --relay-url https://44.202.225.57:58443

State is persisted to:
  ~/.config/shroud-cli/identity.json
  ~/.config/shroud-cli/contacts.json
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from clients.python_sdk import ShroudClient, Contact, ReceivedMessage


def _help() -> None:
    print(__doc__.split("Commands::")[1].split("Usage::")[0].rstrip())


def _save_contacts(path: str, client: ShroudClient) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump([asdict(c) for c in client.contacts()], f, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD CLI")
    ap.add_argument("--relay-url", default="https://44.202.225.57:58443")
    ap.add_argument("--identity",
                    default="~/.config/shroud-cli/identity.json")
    ap.add_argument("--contacts",
                    default="~/.config/shroud-cli/contacts.json")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()
    args.identity = os.path.expanduser(args.identity)
    args.contacts = os.path.expanduser(args.contacts)

    client = ShroudClient(
        relay_url=args.relay_url,
        identity_path=args.identity,
        verify_tls=args.verify_tls,
        poll_interval_seconds=3.0,
    )

    if os.path.exists(args.contacts):
        with open(args.contacts, "r") as f:
            for d in json.load(f):
                client.add_contact(Contact(**d))

    print(f"SHROUD CLI — connected to {args.relay_url}")
    print(f"my pubkey: {client.identity.pub_x25519_hex}")
    print("type 'help' for commands")

    try:
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                print()
                break
            if not line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError as e:
                print(f"  parse error: {e}")
                continue
            cmd = parts[0]

            if cmd in ("help", "?"):
                _help()
            elif cmd == "me":
                print(f"  pubkey: {client.identity.pub_x25519_hex}")
            elif cmd == "contacts":
                for c in client.contacts():
                    print(f"  {c.name:<20} {c.identity_pubkey_hex[:16]}…")
                if not client.contacts():
                    print("  (none)")
            elif cmd == "add":
                if len(parts) != 4:
                    print("  usage: add <name> <pubkey_hex> <shared_root_hex>")
                    continue
                client.add_contact(Contact(
                    name=parts[1],
                    identity_pubkey_hex=parts[2],
                    shared_root_hex=parts[3],
                ))
                _save_contacts(args.contacts, client)
                print(f"  added {parts[1]}")
            elif cmd == "send":
                if len(parts) < 3:
                    print("  usage: send <name> <message...>")
                    continue
                name = parts[1]
                body = " ".join(parts[2:])
                try:
                    mid = client.send(name, body)
                    print(f"  sent message_id={mid}")
                except KeyError:
                    print(f"  unknown contact: {name}")
                except Exception as e:
                    print(f"  send failed: {e}")
            elif cmd == "poll":
                inbox = client.poll_once()
                for m in inbox:
                    print(f"  ← {m.sender_label}: {m.body}")
                if not inbox:
                    print("  (empty)")
            elif cmd == "listen":
                print("  listening (Ctrl-C to stop)...")
                try:
                    while True:
                        for m in client.poll_once():
                            print(f"  ← {m.sender_label}: {m.body}")
                        time.sleep(3.0)
                except KeyboardInterrupt:
                    print()
            elif cmd in ("quit", "exit"):
                break
            else:
                print(f"  unknown command: {cmd}")
    except KeyboardInterrupt:
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
