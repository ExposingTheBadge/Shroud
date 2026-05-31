"""
SHROUD anonymous routing — Linux client port.

The forthcoming GTK4/libadwaita Linux client (see docs/linux-roadmap.md)
will be built on top of Python + PyGObject for two reasons:

  1. We can directly reuse ``crypto/anon_routing.py`` from the project
     root, sharing one implementation between the server-side
     reference, Linux client, and ad-hoc testing.
  2. The Python implementation has already round-tripped against the
     deployed AWS relay end-to-end, so we have wire-format confidence
     before a single Linux line of UI code is written.

This module is a thin wrapper that exists primarily so the Linux
client's build system (Makefile) can include it as a discrete unit
without reaching into ``crypto/`` directly. The actual implementation
just re-exports the canonical module.

When the GTK4 rewrite lands, it will live in this directory alongside
this file. Until then, this is the only Linux-client artifact that's
guaranteed to compile and run on a stock Debian / Fedora / Arch box
with python3 + python3-cryptography installed.
"""
from __future__ import annotations

import os
import sys

# Make the project's crypto/ package importable when this file is run
# stand-alone (i.e., before the full Linux client packaging is in place).
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Re-export the canonical API so callers can write
#   from clients.linux import shroud_anon_routing as anon
# and stay platform-aligned with the GTK4 client when it lands.
from crypto.anon_routing import (  # noqa: F401, E402
    seal,
    unseal,
    routing_tag,
    pair_id,
    epoch_for,
    fetch_tags_for_window,
    EPOCH_SECONDS,
    TAG_BYTES,
    SEALED_VERSION,
    NONCE_BYTES,
    GCM_TAG_BYTES,
)


if __name__ == "__main__":
    # When run directly, exercise the same self-tests as the canonical
    # module. Lets a Linux packager verify the integration in CI before
    # the rest of the client is built.
    from crypto.anon_routing import _self_test
    _self_test()
