"""
SHROUD Linux client — GTK4 + libadwaita UI shell.

Wraps ``clients/python_sdk/shroud_client.ShroudClient`` in a minimal
GTK4 + libadwaita window so Linux users can run a real SHROUD client.

What this ships
---------------

  - Login screen (relay URL + identity file path)
  - Contact list sidebar (loaded from a JSON file)
  - Single chat pane (selected contact)
  - Send box + Enter-to-send
  - Receive loop pumped on a background thread that posts to the GTK
    main loop via GLib.idle_add

This is the v0 UI. It does NOT yet have:

  - Voice / video calls (depends on a Linux WebRTC binding)
  - Sticker picker
  - Disappearing-message timer UI
  - Multi-device link QR scan
  - Settings dialog

Those come in subsequent iterations. The crypto layer is fully ready
via the Python re-export — every protocol module works through
``import crypto.*``.

Dependencies
------------

::

    # Debian / Ubuntu
    sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 python3-cryptography

    # Fedora
    sudo dnf install python3-gobject gtk4 libadwaita python3-cryptography

    # Arch
    sudo pacman -S python-gobject gtk4 libadwaita python-cryptography

Usage
-----

::

    python3 -m clients.linux.shroud_gtk \\
        --relay-url https://44.202.225.57:58443 \\
        --identity ~/.config/shroud/identity.json \\
        --contacts ~/.config/shroud/contacts.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# GTK4 + libadwaita are loaded lazily so this module can be imported
# (e.g. for the docs to scrape) without the deps installed.
try:
    import gi  # type: ignore
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk, GLib, Pango  # type: ignore
    _GTK_AVAILABLE = True
except (ImportError, ValueError):
    _GTK_AVAILABLE = False


from clients.python_sdk import ShroudClient, Contact, ReceivedMessage


# ── App ──────────────────────────────────────────────────────────────


class ShroudApp(Adw.Application if _GTK_AVAILABLE else object):  # type: ignore[misc]

    def __init__(self, relay_url: str, identity_path: str,
                 contacts_path: str, verify_tls: bool):
        if not _GTK_AVAILABLE:
            raise RuntimeError(
                "GTK4 + libadwaita not available. Install python3-gi + "
                "gir1.2-gtk-4.0 + gir1.2-adw-1 and try again."
            )
        super().__init__(application_id="org.shroud.linux")
        self.relay_url = relay_url
        self.identity_path = identity_path
        self.contacts_path = contacts_path
        self.verify_tls = verify_tls
        self.client: Optional[ShroudClient] = None
        self.selected_contact_name: Optional[str] = None
        self._chat_view: Optional[Gtk.TextView] = None
        self._sidebar_list: Optional[Gtk.ListBox] = None
        self._input_entry: Optional[Gtk.Entry] = None
        self._status_label: Optional[Gtk.Label] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.connect("activate", self._on_activate)

    def _on_activate(self, app: "ShroudApp") -> None:
        # Initialize SDK
        self.client = ShroudClient(
            relay_url=self.relay_url,
            identity_path=self.identity_path,
            verify_tls=self.verify_tls,
            poll_interval_seconds=5.0,
        )
        if os.path.exists(self.contacts_path):
            with open(self.contacts_path, "r") as f:
                for d in json.load(f):
                    self.client.add_contact(Contact(**d))

        # Build UI
        window = Adw.ApplicationWindow(application=self, title="SHROUD")
        window.set_default_size(900, 600)
        toast_overlay = Adw.ToastOverlay()
        window.set_content(toast_overlay)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        toast_overlay.set_child(outer)

        header = Adw.HeaderBar()
        title = Adw.WindowTitle(title="SHROUD", subtitle=self.relay_url)
        header.set_title_widget(title)
        outer.append(header)

        # Status bar
        self._status_label = Gtk.Label(
            label=f"identity {self.client.identity.pub_x25519_hex[:16]}…",
            halign=Gtk.Align.START,
            margin_start=12,
            margin_end=12,
            margin_top=4,
            margin_bottom=4,
        )
        outer.append(self._status_label)

        # Main paned: sidebar + chat
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_wide_handle(True)
        outer.append(paned)

        # Sidebar: contact list
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sidebar_scroll = Gtk.ScrolledWindow()
        sidebar_scroll.set_min_content_width(220)
        self._sidebar_list = Gtk.ListBox()
        self._sidebar_list.add_css_class("navigation-sidebar")
        self._sidebar_list.connect("row-activated", self._on_contact_selected)
        sidebar_scroll.set_child(self._sidebar_list)
        sidebar_box.append(sidebar_scroll)
        paned.set_start_child(sidebar_box)

        for c in self.client.contacts():
            row = Adw.ActionRow(title=c.name, subtitle=c.identity_pubkey_hex[:16] + "…")
            row.set_name(c.name)  # type: ignore[attr-defined]
            self._sidebar_list.append(row)

        # Chat pane
        chat_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        chat_scroll = Gtk.ScrolledWindow()
        chat_scroll.set_vexpand(True)
        self._chat_view = Gtk.TextView()
        self._chat_view.set_editable(False)
        self._chat_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self._chat_view.set_left_margin(12)
        self._chat_view.set_right_margin(12)
        self._chat_view.set_top_margin(12)
        chat_scroll.set_child(self._chat_view)
        chat_box.append(chat_scroll)

        # Input row
        input_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=6,
            margin_start=8, margin_end=8, margin_top=8, margin_bottom=8,
        )
        self._input_entry = Gtk.Entry()
        self._input_entry.set_placeholder_text("Type a message and press Enter")
        self._input_entry.set_hexpand(True)
        self._input_entry.connect("activate", self._on_send_clicked)
        input_row.append(self._input_entry)

        send_btn = Gtk.Button(label="Send")
        send_btn.add_css_class("suggested-action")
        send_btn.connect("clicked", self._on_send_clicked)
        input_row.append(send_btn)

        chat_box.append(input_row)
        paned.set_end_child(chat_box)
        paned.set_position(240)

        window.present()

        # Kick off polling thread
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

        # Stop polling cleanly when the window is closed.
        def on_close(_w: Gtk.Window) -> bool:
            self._stop_event.set()
            return False
        window.connect("close-request", on_close)

    def _on_contact_selected(self, _box: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        action = row.get_child()  # type: ignore[attr-defined]
        name = action.get_title()
        self.selected_contact_name = name
        if self._chat_view is not None:
            self._chat_view.get_buffer().set_text(f"--- chat with {name} ---\n")

    def _on_send_clicked(self, *_args) -> None:
        if self.client is None or self._input_entry is None:
            return
        text = self._input_entry.get_text().strip()
        if not text or not self.selected_contact_name:
            return
        try:
            self.client.send(self.selected_contact_name, text)
            self._append_chat(f"me: {text}\n")
            self._input_entry.set_text("")
        except Exception as e:
            self._append_chat(f"[send failed: {e}]\n")

    def _append_chat(self, line: str) -> None:
        if self._chat_view is None:
            return
        buf = self._chat_view.get_buffer()
        end_iter = buf.get_end_iter()
        buf.insert(end_iter, line)

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                for msg in self.client.poll_once():  # type: ignore[union-attr]
                    GLib.idle_add(self._handle_message, msg)
            except Exception as e:
                GLib.idle_add(self._handle_message, ReceivedMessage(
                    sender_label="(error)", body=str(e),
                    payload_raw=b"", routing_tag_hex="", server_ts="",
                ))
            self._stop_event.wait(5.0)

    def _handle_message(self, msg: ReceivedMessage) -> bool:
        self._append_chat(f"{msg.sender_label}: {msg.body}\n")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD GTK4 client")
    ap.add_argument("--relay-url", default="https://44.202.225.57:58443")
    ap.add_argument("--identity", default="~/.config/shroud/identity.json")
    ap.add_argument("--contacts", default="~/.config/shroud/contacts.json")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    args.identity = os.path.expanduser(args.identity)
    args.contacts = os.path.expanduser(args.contacts)
    os.makedirs(os.path.dirname(args.identity), exist_ok=True)

    if not _GTK_AVAILABLE:
        print(
            "Error: GTK4 + libadwaita not available.\n"
            "Install with:\n"
            "  Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1\n"
            "  Fedora:        sudo dnf install python3-gobject gtk4 libadwaita\n"
            "  Arch:          sudo pacman -S python-gobject gtk4 libadwaita",
            file=sys.stderr,
        )
        return 1

    app = ShroudApp(
        relay_url=args.relay_url,
        identity_path=args.identity,
        contacts_path=args.contacts,
        verify_tls=args.verify_tls,
    )
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
