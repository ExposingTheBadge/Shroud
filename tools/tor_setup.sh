#!/bin/bash
# SHROUD Tor hidden-service setup.
#
# Installs Tor, configures a v3 onion service in front of the SHROUD
# relay's port 58443, prints the .onion address for clients to use.
#
# Tested on:
#   - Debian / Ubuntu (apt)
#   - Fedora (dnf)
#   - Amazon Linux 2023 (dnf)
#
# Usage:
#   sudo tools/tor_setup.sh
#
# After:
#   - Tor service auto-starts on boot
#   - .onion address printed to stdout AND saved to /var/log/shroud-onion-address.txt
#   - Optionally toggle SHROUD relay to onion_only mode via admin UI

set -euo pipefail

SHROUD_RELAY_PORT="${SHROUD_RELAY_PORT:-58443}"
TOR_HIDDEN_SERVICE_PORT="${TOR_HIDDEN_SERVICE_PORT:-58443}"
TOR_HS_DIR="/var/lib/tor/shroud_hidden_service"
TORRC="/etc/tor/torrc"
ADDRESS_LOG="/var/log/shroud-onion-address.txt"


# ── Detect distro + install Tor ──────────────────────────────────────

if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y tor curl
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y tor curl
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm tor curl
else
    echo "FATAL: unsupported distro — install tor manually then re-run" >&2
    exit 1
fi


# ── Configure torrc ──────────────────────────────────────────────────

# Back up the existing torrc once.
if [[ -f "$TORRC" ]] && [[ ! -f "${TORRC}.shroud-bak" ]]; then
    cp "$TORRC" "${TORRC}.shroud-bak"
fi

# Append (or replace) the SHROUD hidden-service stanza.
TMP=$(mktemp)
{
    # Pull through everything that isn't a SHROUD-managed line
    if [[ -f "$TORRC" ]]; then
        awk '
            /^# >>> SHROUD HIDDEN SERVICE START/ { skip=1 }
            !skip { print }
            /^# <<< SHROUD HIDDEN SERVICE END/ { skip=0 }
        ' "$TORRC"
    fi

    cat <<EOF

# >>> SHROUD HIDDEN SERVICE START (managed by tor_setup.sh — do not edit by hand)
HiddenServiceDir $TOR_HS_DIR
HiddenServiceVersion 3
HiddenServicePort $TOR_HIDDEN_SERVICE_PORT 127.0.0.1:$SHROUD_RELAY_PORT
# <<< SHROUD HIDDEN SERVICE END
EOF
} > "$TMP"
mv "$TMP" "$TORRC"

# Ensure the hidden-service dir exists with the right perms.
mkdir -p "$TOR_HS_DIR"
chown debian-tor:debian-tor "$TOR_HS_DIR" 2>/dev/null \
    || chown tor:tor "$TOR_HS_DIR" 2>/dev/null \
    || true
chmod 700 "$TOR_HS_DIR"


# ── Enable + restart Tor ─────────────────────────────────────────────

systemctl enable tor 2>/dev/null || systemctl enable tor.service 2>/dev/null || true
systemctl restart tor 2>/dev/null || systemctl restart tor.service


# ── Wait for the hostname file to appear ─────────────────────────────

ADDRESS=""
for i in {1..30}; do
    sleep 1
    if [[ -f "$TOR_HS_DIR/hostname" ]]; then
        ADDRESS=$(cat "$TOR_HS_DIR/hostname")
        break
    fi
done

if [[ -z "$ADDRESS" ]]; then
    echo "FATAL: Tor did not generate a hidden service hostname in time" >&2
    echo "  Check: journalctl -u tor -n 50" >&2
    exit 1
fi


# ── Persist + print ──────────────────────────────────────────────────

echo "$ADDRESS" > "$ADDRESS_LOG"

cat <<EOF

╔════════════════════════════════════════════════════════════════════╗
║  SHROUD Tor hidden service is up.                                 ║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║    .onion address:                                                 ║
║    $ADDRESS
║                                                                    ║
║    Clients connect to:                                             ║
║    http://$(echo "$ADDRESS" | cut -d. -f1).onion:$TOR_HIDDEN_SERVICE_PORT
║                                                                    ║
║    Saved to: $ADDRESS_LOG                                          ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

Next steps:

  1. Publish this address via your release manifest so clients
     can discover it. Sign the manifest with the multisig roster
     (release/multisig.py) so the address can't be substituted.

  2. (Optional) Enable onion_only mode on the relay via the admin
     UI to reject any clearnet connections.

  3. Test from a Tor-equipped client:
       torify curl -k http://$(echo "$ADDRESS" | cut -d. -f1).onion:$TOR_HIDDEN_SERVICE_PORT/health

EOF
