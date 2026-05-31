"""
SHROUD high-level client SDK.

This is the smallest possible end-to-end client that exercises the
full SHROUD protocol against a live relay. It:

  - Generates and persists an X25519 identity keypair
  - Tracks contacts with their identity pubkey + shared X3DH root
  - Sends messages via /api/v1/messages/send-anon (sealed envelope,
    routing tag, padding bucket)
  - Polls /api/v1/messages/fetch-anon for incoming messages, unseals,
    and dispatches to a callback
  - Periodically rotates routing tags as epochs advance

For prototyping, integration testing, or building a CLI / bot, you
import ``ShroudClient``, hand it your identity + a relay URL + an
on-message callback, and call ``client.run()``.

Example::

    from clients.python_sdk import ShroudClient, Contact

    client = ShroudClient(
        relay_url="https://44.202.225.57:58443",
        verify_tls=False,                # self-signed dev relay
        identity_path="./alice.id.json", # persisted between runs
    )

    # Add a contact (typically populated via X3DH out-of-band)
    client.add_contact(Contact(
        name="bob",
        identity_pubkey_hex="...",
        shared_root_hex="...",
    ))

    def on_message(msg):
        print(f"From {msg.sender_label}: {msg.body!r}")

    client.on_message = on_message
    client.run()                         # blocking poll loop, Ctrl-C to stop


Real Windows/Android/iOS clients should mirror this surface area.
The actual C++ / Kotlin / Swift code calls into the corresponding port
of ``crypto/anon_routing`` and assembles the same wire bytes.

Rule compliance
---------------
Inherited from the underlying modules. The SDK doesn't add any new
metadata or trust assumptions.
"""
from __future__ import annotations

import json
import os
import ssl
import threading
import time
import urllib.request
from dataclasses import dataclass, asdict, field
from typing import Callable, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto.anon_routing import (
    seal,
    unseal,
    routing_tag,
    pair_id,
    epoch_for,
    fetch_tags_for_window,
)


# ── Data types ───────────────────────────────────────────────────────


PAD_BUCKETS = (4096, 65536, 1048576, 16777216)


@dataclass
class Contact:
    """A peer we can exchange messages with."""
    name: str                       # local display name only
    identity_pubkey_hex: str        # their X25519 identity pubkey
    shared_root_hex: str            # 32-byte X3DH root we share with them


@dataclass
class ReceivedMessage:
    sender_label: str               # what the sender called themselves in the payload
    body: str                       # decrypted plaintext (may be bytes if not JSON)
    payload_raw: bytes              # original sealed-envelope plaintext
    routing_tag_hex: str
    server_ts: str


@dataclass
class _IdentityFile:
    priv_x25519_hex: str
    pub_x25519_hex: str

    @classmethod
    def generate(cls) -> "_IdentityFile":
        sk = X25519PrivateKey.generate()
        return cls(
            priv_x25519_hex=sk.private_bytes_raw().hex(),
            pub_x25519_hex=sk.public_key().public_bytes_raw().hex(),
        )


# ── Client ───────────────────────────────────────────────────────────


class ShroudClient:
    def __init__(
        self,
        relay_url: str,
        identity_path: Optional[str] = None,
        verify_tls: bool = True,
        poll_interval_seconds: float = 5.0,
    ) -> None:
        self.relay_url = relay_url.rstrip("/")
        self.verify_tls = verify_tls
        self.poll_interval = poll_interval_seconds
        self._identity_path = identity_path
        self._contacts: Dict[str, Contact] = {}
        self._stop = threading.Event()
        self.on_message: Optional[Callable[[ReceivedMessage], None]] = None

        # Identity (load or generate).
        self.identity = self._load_or_generate_identity()
        self.identity_pubkey = bytes.fromhex(self.identity.pub_x25519_hex)
        self._identity_priv = bytes.fromhex(self.identity.priv_x25519_hex)

        self._ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ── Identity persistence ─────────────────────────────────────────

    def _load_or_generate_identity(self) -> _IdentityFile:
        if self._identity_path and os.path.exists(self._identity_path):
            with open(self._identity_path, "r") as f:
                d = json.load(f)
            return _IdentityFile(**d)
        ident = _IdentityFile.generate()
        if self._identity_path:
            os.makedirs(
                os.path.dirname(os.path.abspath(self._identity_path)) or ".",
                exist_ok=True,
            )
            with open(self._identity_path, "w") as f:
                json.dump(asdict(ident), f)
        return ident

    # ── Contact management ──────────────────────────────────────────

    def add_contact(self, contact: Contact) -> None:
        self._contacts[contact.name] = contact

    def remove_contact(self, name: str) -> None:
        self._contacts.pop(name, None)

    def contacts(self) -> List[Contact]:
        return list(self._contacts.values())

    # ── Send ─────────────────────────────────────────────────────────

    def send(self, contact_name: str, body: str,
             expires_in_seconds: Optional[int] = None) -> str:
        """Send a plaintext message to the named contact. Returns the
        server's message_id on success."""
        contact = self._contacts.get(contact_name)
        if contact is None:
            raise KeyError(f"unknown contact: {contact_name}")

        their_pub = bytes.fromhex(contact.identity_pubkey_hex)
        root = bytes.fromhex(contact.shared_root_hex)

        # Routing tag for the current epoch (recipient polls a 3-epoch window).
        pid = pair_id(self.identity_pubkey, their_pub)
        tag = routing_tag(root, pid, epoch_for())

        # Inner payload: a JSON envelope so the recipient can route on type.
        payload = json.dumps({
            "sender": self.identity.pub_x25519_hex[:12],
            "ts": int(time.time()),
            "body": body,
        }, sort_keys=True).encode()

        sealed = seal(payload, their_pub)
        # Pad to the nearest server-accepted bucket.
        target = next(b for b in PAD_BUCKETS if b >= len(sealed))
        sealed = sealed + b"\x00" * (target - len(sealed))

        headers = {
            "X-Routing-Tag": tag.hex(),
            "X-Envelope-Version": "2",
            "Content-Type": "application/octet-stream",
        }
        if expires_in_seconds is not None:
            headers["X-Expires-In"] = str(int(expires_in_seconds))

        req = urllib.request.Request(
            f"{self.relay_url}/api/v1/messages/send-anon",
            data=sealed, method="POST", headers=headers,
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=15) as resp:
            d = json.loads(resp.read())
        return d.get("message_id", "")

    # ── Poll ─────────────────────────────────────────────────────────

    def poll_once(self) -> List[ReceivedMessage]:
        """Single poll of the relay across all contact routing tags.
        Returns the list of decrypted messages."""
        pairs = []
        for c in self._contacts.values():
            their_pub = bytes.fromhex(c.identity_pubkey_hex)
            root = bytes.fromhex(c.shared_root_hex)
            pid = pair_id(self.identity_pubkey, their_pub)
            pairs.append((pid, root))

        if not pairs:
            return []

        tags = fetch_tags_for_window(pairs)
        # Reverse map tag -> contact, so we know who sent what after fetch.
        tag_to_contact: Dict[str, Contact] = {}
        for c in self._contacts.values():
            their_pub = bytes.fromhex(c.identity_pubkey_hex)
            root = bytes.fromhex(c.shared_root_hex)
            pid = pair_id(self.identity_pubkey, their_pub)
            base = epoch_for()
            for e in (base - 1, base, base + 1):
                t = routing_tag(root, pid, e).hex()
                tag_to_contact[t] = c

        req = urllib.request.Request(
            f"{self.relay_url}/api/v1/messages/fetch-anon",
            data=json.dumps({"tags": [t.hex() for t in tags]}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=15) as resp:
            body = json.loads(resp.read())

        results: List[ReceivedMessage] = []
        for m in body.get("messages", []):
            sealed = bytes.fromhex(m["sealed"])
            try:
                plaintext = self._unseal_with_trim(sealed)
            except Exception:
                continue  # tampered / unknown sealed; drop silently
            try:
                inner = json.loads(plaintext.decode("utf-8"))
                body_str = inner.get("body", "")
                sender_label = inner.get("sender", "unknown")
            except (UnicodeDecodeError, json.JSONDecodeError):
                body_str = plaintext.decode("utf-8", errors="replace")
                sender_label = "unknown"
            results.append(ReceivedMessage(
                sender_label=sender_label,
                body=body_str,
                payload_raw=plaintext,
                routing_tag_hex="",
                server_ts=str(m.get("ts", "")),
            ))
        return results

    def _unseal_with_trim(self, sealed_padded: bytes) -> bytes:
        """The sealed envelope on the wire is padded to a bucket. We
        need to trim trailing zeros down to the actual ciphertext+tag
        length before AES-GCM can decrypt. Approach: binary search by
        attempting unseal at the maximum non-zero offset."""
        # Strip trailing zeros.
        i = len(sealed_padded)
        while i > 0 and sealed_padded[i - 1] == 0:
            i -= 1
        # The trim above might leave a zero that's actually part of the
        # ciphertext. Walk back forward up to 32 bytes to find the
        # exact tail position that successfully decrypts.
        for j in range(i, min(i + 32, len(sealed_padded)) + 1):
            try:
                return unseal(sealed_padded[:j], self._identity_priv)
            except Exception:
                continue
        raise ValueError("could not locate sealed envelope tail")

    # ── Run loop ─────────────────────────────────────────────────────

    def run(self) -> None:
        """Blocking poll loop. Calls self.on_message for each received
        message. Stops on Ctrl-C or self.stop()."""
        try:
            while not self._stop.is_set():
                try:
                    for msg in self.poll_once():
                        if self.on_message is not None:
                            self.on_message(msg)
                except Exception as e:
                    print(f"poll error: {e}")
                self._stop.wait(self.poll_interval)
        except KeyboardInterrupt:
            pass

    def stop(self) -> None:
        self._stop.set()
