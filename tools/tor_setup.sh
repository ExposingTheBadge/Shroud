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

install_tor_from_torproject_repo() {
    # The Tor Project distributes el9-compatible RPMs. AL2023 is RHEL 9
    # based so they install cleanly. Used as a fallback when EPEL isn't
    # available or doesn't ship tor.
    cat >/etc/yum.repos.d/tor.repo <<'EOF'
[tor]
name=Tor packages from torproject.org (CentOS 9 / EL9 / AL2023)
baseurl=https://rpm.torproject.org/centos/9/$basearch
enabled=1
gpgcheck=1
gpgkey=https://rpm.torproject.org/centos/public_gpg.key
cost=100
EOF
    rpm --import https://rpm.torproject.org/centos/public_gpg.key 2>/dev/null || true

    # The Tor Project repo declares `torsocks` as a hard dep, but
    # torsocks lives in EPEL and is unavailable on AL2023. torsocks is
    # only a SOCKS-wrapper utility — `tor` itself doesn't need it to
    # run the daemon or a hidden service. We download the tor RPM via
    # `dnf download` and install it with `rpm -i --nodeps`.
    arch=$(uname -m)
    tmpdir=$(mktemp -d)
    pushd "$tmpdir" >/dev/null
    if dnf download --resolve --downloadonly --downloaddir="$tmpdir" tor 2>/dev/null; then
        :
    else
        dnf download tor --downloaddir="$tmpdir" 2>/dev/null || true
    fi
    # If dnf download didn't work, fall back to direct curl from the repo
    if ! ls "$tmpdir"/tor-*.rpm >/dev/null 2>&1; then
        # Find the latest available tor RPM from the repo
        latest=$(curl -s "https://rpm.torproject.org/centos/9/$arch/" \
                 | grep -oE 'tor-[0-9.]+-[0-9]+\.el9\.[a-z0-9_]+\.rpm' \
                 | sort -V | tail -1)
        if [[ -n "$latest" ]]; then
            curl -sLO "https://rpm.torproject.org/centos/9/$arch/$latest"
        fi
    fi
    if ls "$tmpdir"/tor-*.rpm >/dev/null 2>&1; then
        rpm -i --nodeps "$tmpdir"/tor-*.rpm
    else
        echo "FATAL: could not obtain a tor RPM from rpm.torproject.org" >&2
        popd >/dev/null
        rm -rf "$tmpdir"
        return 1
    fi
    popd >/dev/null
    rm -rf "$tmpdir"
}

if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y tor curl
elif command -v dnf >/dev/null 2>&1; then
    # Try the distro repo first; fall back to EPEL, then the Tor Project
    # repo for distros (like Amazon Linux 2023) that don't ship tor.
    # AL2023 ships curl-minimal preinstalled and conflicts with the
    # full curl package. Don't try to install curl — every AL2023 / EL9
    # system already has a curl binary that satisfies our needs.
    if dnf install -y tor 2>/dev/null; then
        :
    elif grep -q "Amazon Linux 2023" /etc/os-release 2>/dev/null; then
        echo "Detected Amazon Linux 2023 — installing tor from rpm.torproject.org"
        install_tor_from_torproject_repo
    else
        echo "Trying EPEL 9 for tor..."
        dnf install -y \
            https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm 2>/dev/null \
            || true
        dnf install -y tor || install_tor_from_torproject_repo
    fi
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
# Different distros / RPM sources use different user accounts for Tor:
#   - Debian/Ubuntu: debian-tor
#   - EPEL: tor
#   - Tor Project RPM (AL2023, EL9): toranon
mkdir -p "$TOR_HS_DIR"
chown debian-tor:debian-tor "$TOR_HS_DIR" 2>/dev/null \
    || chown tor:tor "$TOR_HS_DIR" 2>/dev/null \
    || chown toranon:toranon "$TOR_HS_DIR" 2>/dev/null \
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
