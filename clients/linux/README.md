# SHROUD Linux client

Status: **roadmap** (see [`docs/linux-roadmap.md`](../../docs/linux-roadmap.md)).

The stale C/GTK3 source in this directory predates X3DH, the Double
Ratchet, the post-quantum hybrid, sealed sender, anonymous routing, and
everything else introduced in v1.6+. It is not built, not shipped, and
not maintained. The roadmap calls for a ground-up GTK4 + libadwaita
rewrite in Python with PyGObject; the current files in this directory
should be considered placeholders.

## What's in this directory today

| File | Purpose |
|------|---------|
| `main.c` | Stale GTK3 client (do not build) |
| `Makefile` | Builds the stale client (skip) |
| `shroud_anon_routing.py` | **Active.** Thin Python re-export of `crypto.anon_routing` so the upcoming GTK4 client can use it as a discrete module without reaching into `crypto/`. Already round-tripped against the live AWS relay. |
| `README.md` | This file |

## Building the GTK4 client (when it exists)

The intended dependency surface for the v2.x Linux client is small:

```bash
# Debian / Ubuntu
sudo apt install python3 python3-gi python3-cryptography \
                 gir1.2-gtk-4.0 gir1.2-adw-1 libsecret-tools

# Fedora
sudo dnf install python3 python3-gobject python3-cryptography \
                 gtk4 libadwaita libsecret

# Arch
sudo pacman -S python python-gobject python-cryptography \
               gtk4 libadwaita libsecret
```

Then:

```bash
cd clients/linux
python3 -m shroud_anon_routing   # smoke-test the wire-compatible crypto module
# (full GTK4 client invocation TBD when the rewrite ships)
```

## Why the rewrite is gated

The cryptography and protocol layers are now stable across server,
Windows, Android, and iOS. The Linux client rewrite has been waiting
on those landing before pulling in:

- The full feature matrix: sealed sender, rotating routing tags,
  privately-fetched link previews, content-addressed stickers,
  disappearing media, encrypted voice/video.
- Cover-traffic loop parity with the desktop client.
- Anonymous push via UnifiedPush (Linux desktops typically don't have
  APNs/FCM).
- Reproducible builds — the Linux client should build deterministically
  in a Wine-on-Linux container the same way the Windows client does in
  `BUILD-REPRODUCIBILITY.md`.

The protocol modules in `crypto/` (anon_routing, calls, link_preview,
stickers, disappearing, anon_push, federation, pq_double_ratchet) are
all installed-via-import-able and will be the Linux client's primary
backend once the UI shell exists.
