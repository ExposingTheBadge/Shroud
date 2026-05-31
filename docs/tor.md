# Running SHROUD over Tor

SHROUD ships with end-to-end encrypted message contents from v1, but the
network layer (TLS over a clearnet IP) still leaks two pieces of metadata to
anyone watching the wire:

  - **Who is talking to SHROUD at all** — the destination IP + port is
    visible to every router between the client and the server.
  - **Server location** — the operator's hosting provider, ASN, and rough
    geographic location can be derived from the IP.

A Tor v3 hidden service (`.onion`) closes both gaps. The client speaks to
`<56-char>.onion:58443`, Tor wraps the traffic in three onion-encryption
layers, and neither the network nor the server learns the other's location.

Tier 6 of the SHROUD roadmap has shipped two pieces toward this:

  - **v1.5** — admin-toggleable `onion_only` mode that rejects any request
    whose Host header is not a `.onion` address.
  - **v2.3** — server `--bind` flag and Windows client SOCKS5 routing toggle
    so operators and users can actually deploy the hidden service end-to-end.

This document is the deployment guide for both halves.

## Threat model

Tor protects:

  - **Server-IP confidentiality.** Even if the client's host or local network
    is compromised, an attacker cannot reach the SHROUD server directly —
    they can only reach the Tor entry guard.
  - **Client-IP confidentiality.** The server only ever sees connections
    arriving from `127.0.0.1` (the local Tor daemon on the server box). It
    has no way to log the client's real IP.
  - **Censorship resistance.** Networks that block SHROUD's public IP
    cannot block the onion address without blocking all of Tor.

Tor does **not** protect against:

  - **A compromised server.** All of SHROUD's existing server-trust
    assumptions still apply — the operator can still see whatever they could
    see before (envelope metadata, message timing, sender/recipient device
    IDs). Tor is a network-layer fix, not a server-trust fix.
  - **Traffic-confirmation attacks** against a global passive adversary. If
    someone watches both the client's guard and the server's host, timing
    correlation can still de-anonymize the conversation. SHROUD's
    fixed-bucket padding (v1.7) makes this measurably harder but not
    impossible.
  - **Malware on the endpoint.** Tor doesn't help if either device is owned.

## Server deployment

### 1. Install Tor on the server host

Debian/Ubuntu:

```
sudo apt-get install tor
```

### 2. Configure the hidden service

Append to `/etc/tor/torrc` (or drop into `/etc/tor/torrc.d/shroud.conf`):

```
HiddenServiceDir /var/lib/tor/shroud/
HiddenServicePort 58443 127.0.0.1:58443
HiddenServiceVersion 3
```

Restart Tor and read out the new onion address:

```
sudo systemctl restart tor
sudo cat /var/lib/tor/shroud/hostname
```

Treat the file `hostname` as low-sensitivity (it's publicly advertised) and
the file `hs_ed25519_secret_key` as **maximum sensitivity** — anyone with
that key can impersonate your hidden service. Owner-only permissions are
applied automatically by the Tor daemon; do not back it up to anywhere less
trusted than the host itself.

### 3. Bind the SHROUD server to localhost

```
python -m server.server --bind 127.0.0.1
```

Or via the environment:

```
SHROUD_BIND=127.0.0.1 python -m server.server
```

Binding to `127.0.0.1` means only the local Tor daemon can connect — there
is no path from the public internet that bypasses Tor.

### 4. Enable onion-only enforcement

Open the admin dashboard, click the **Onion** toggle (it's next to the
registration and maintenance toggles). The server will now return HTTP 403
to any request whose Host header is not a `.onion` address. Admin paths
(`/admin/*`) are deliberately exempt so you can recover via the loopback
HTTP path if something goes wrong.

You can also flip this from the API once authenticated:

```
curl -X POST https://<onion>/api/v1/admin/control/onion-only \
     -H "Content-Type: application/json" \
     --data '{"enabled":true}'
```

### 5. Systemd hardening (optional but recommended)

Drop-in at `/etc/systemd/system/shroud.service.d/hardening.conf`:

```
[Service]
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX AF_INET
SystemCallArchitectures=native
ReadWritePaths=/opt/shroud/server /opt/shroud/server/files
CapabilityBoundingSet=
```

Reload and restart:

```
sudo systemctl daemon-reload
sudo systemctl restart shroud
```

## Client deployment (Windows)

The Windows client gained a **Settings → Route through Tor (SOCKS5)** toggle
in v2.3. Enable it and supply the SOCKS5 host/port (defaults to
`127.0.0.1:9050`, which matches a stock Tor Browser or `tor-expert-bundle`
install on the same machine).

When the toggle is on:

  - All HTTPS requests issued by the client go through the local Tor SOCKS
    proxy.
  - The server hostname is whatever you set under Settings → Server URL —
    pointing it at the operator's `.onion:58443` URL is the whole point.
  - Connections fail closed if Tor isn't running. The client will not
    silently fall back to clearnet.

Until a bundled tor-client lands, the user needs Tor running locally. The
two normal options:

  - **Tor Browser** — start it once. It binds SOCKS to `127.0.0.1:9150`,
    not the default 9050. Change the client's SOCKS port to 9150.
  - **tor-expert-bundle** — unzip and run `tor.exe`. Binds 9050 by default
    on Windows.

## Client deployment (Android)

Android Tor routing rides on Orbot's SOCKS5 endpoint
(`127.0.0.1:9050` once Orbot is in VPN mode). Wiring a toggle into the
Android client is tracked separately — the v2.3 release ships the docs and
the wire-format hooks but not the toggle UI yet.

## Verifying the deployment

From a fresh machine:

  1. Install Tor Browser.
  2. Visit `https://<your-onion>:58443/health` — should return
     `{"status":"healthy"}`.
  3. Visit `https://<your-clearnet-ip>:58443/health` — should return
     `{"detail":"Server is in onion-only mode"}` once the toggle is on.
  4. Open the admin dashboard via the `.onion` and confirm the "Onion ON"
     pill is green.

If step 3 still works, something is bypassing the middleware — almost
always either the `onion_only` toggle is off or you forgot to bind to
`127.0.0.1` and the connection arrived on a public IP.

## Recovery

If you lock yourself out of the admin dashboard with the onion-only toggle
on:

  1. SSH to the box.
  2. `sqlite3 server/shroud.db "UPDATE server_settings SET value='0' WHERE key='onion_only';"`
  3. Restart the server.

That's why admin paths are exempt from the middleware — local-loopback
recovery still works even when onion-only is on.

## Future work

  - **Bundled tor-client** so the Windows client can ship a turnkey
    onion-only build with no separate Tor install.
  - **Android Orbot integration** — tracked under v2.4.
