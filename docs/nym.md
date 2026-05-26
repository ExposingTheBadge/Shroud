# Nym mixnet — Windows client guide

GHOSTLINK v2.3.1 ships an opt-in **Nym mixnet** transport for the Windows
client. This document covers what it gives you, what it doesn't, and how
to wire it up.

> **Status check.** The client-side plumbing is shipped and ready. The
> server-side **Service Provider (SP)** that the mixnet needs in order
> to translate Sphinx packets back into HTTP is **not yet operated by the
> GHOSTLINK project itself** — that's tracked for v2.5 (see
> `docs/nym-roadmap.md`). Until then, the toggle is functional only if
> you run your own SP. The Tor onion transport remains the recommended
> default in v2.3.x.

## Why Nym

Tor onion services (shipped in v2.3.0, see `docs/tor.md`) defeat the
ISP-level observer and partial network-level adversaries. They do **not**
defend against a **global passive adversary** that can correlate flows at
both ends by timing and volume.

Nym is built specifically for that threat. Every packet is wrapped in
fixed-size **Sphinx** encryption, padded so all traffic on the wire looks
identical, shuffled through mix nodes with **Poisson-distributed delays**,
and accompanied by constant **cover traffic** so even your idle state is
indistinguishable from active use.

The trade-off is real and on by design:

| Property | Tor onion (v2.3) | Nym (v2.3.1) |
|---|---|---|
| ISP-level observer | defeated | defeated |
| Global passive adversary | partial | **defeated** |
| Active timing / fingerprinting | vulnerable | **defeated** |
| Round-trip latency | ~hundreds of ms | **~1–3 seconds**, occasionally spikes |
| Bandwidth | normal | cover traffic burns ~constant uplink |

If your threat model is "passive ISP collection or law enforcement
subpoena," Tor is enough. If your threat model is "an adversary that
already has wire access to large chunks of the internet and is trying
to deanonymize by traffic analysis," that's what Nym is for.

## How GHOSTLINK uses Nym

The Windows client doesn't speak Nym natively. It speaks SOCKS5 to a
local **`nym-socks5-client`** daemon you run alongside it. That daemon
Sphinx-wraps every outgoing packet and forwards it through the Nym
mixnet to a **Service Provider** configured by Nym address. The SP runs
next to the GHOSTLINK server, unwraps the packet, and forwards the
plaintext HTTP request to the API.

```
ghostlink.exe
    │  WinHTTP, SOCKS5 to 127.0.0.1:1080
    ▼
nym-socks5-client (on your machine)
    │  Sphinx-wrapped, fixed-size, Poisson-delayed
    ▼
mixnet (3 hops, randomised per packet)
    │
    ▼
Service Provider (next to ghostlink server)
    │  unwrap → plain HTTP
    ▼
GHOSTLINK server
```

This is the same shape as the Tor flow — SOCKS5 in front of WinHTTP —
just with `nym-socks5-client` swapped in for `tor.exe` and one extra
piece of configuration (the SP address).

## Setup on the client side

1. **Install `nym-socks5-client`.** Either build from source or grab a
   binary release from <https://nymtech.net/download>.

2. **Initialise it for the GHOSTLINK SP.** The SP address is a triplet of
   Base58 strings in the form
   `<encryption_key>.<identity_key>@<gateway_identity>`. You'll get this
   from whoever runs the SP you want to use (project, third party, or
   yourself — see "Running your own SP" below).

   ```
   nym-socks5-client init \
       --id ghostlink \
       --provider <encryption_key>.<identity_key>@<gateway_identity>
   ```

3. **Run it.** This binds SOCKS5 to `127.0.0.1:1080` by default.

   ```
   nym-socks5-client run --id ghostlink
   ```

4. **Tell GHOSTLINK to use it.** In the Windows client:
   - Settings → **Network** tab.
   - Select **Nym mixnet** under Transport.
   - Confirm the SOCKS5 endpoint is `127.0.0.1:1080` (default).
   - Paste the same SP address into "Service Provider address" so it's
     stored alongside the rest of your config.
   - Close Settings.

5. **Verify.** Help → About should show `Active transport: Nym mixnet
   (SOCKS5)`. Send a message; expect a 1–3 second delay before it lands.

## Setup on the server side (SP)

The server doesn't run anything Nym-specific itself. The Service Provider
is a **separate process** that lives next to the GHOSTLINK server and
talks to it over loopback. It can be either:

- **`nym-network-requester`** (reference SP implementation), configured
  with an allowlist of GHOSTLINK API endpoints, OR
- A **custom SP** built with the `nym-sdk` Rust crate that knows about
  GHOSTLINK's specific endpoints — this is what we plan to ship as the
  reference in v2.5.

```
                                     ┌─────────────────────────────┐
mixnet ──Sphinx──> SP ──HTTP/loopback> ghostlink server (--bind 127.0.0.1)
                                     └─────────────────────────────┘
```

The SP and the server should run on the **same host**, with the server
bound to localhost (`--bind 127.0.0.1`), so the unwrapped HTTP traffic
never touches the public network.

Until the GHOSTLINK project's reference SP ships (v2.5), anyone who wants
to use this transport in production needs to run their own SP. The
mechanics are documented at
<https://nymtech.net/docs/integrations/socks-proxy.html>.

## Threat-model edge cases

- **SP is a trust point.** The SP sees the unwrapped HTTP — that's how
  it forwards to the server. It does **not** see who sent the request
  (that's what the mixnet is for), but it sees what the request is. If
  the SP is compromised, it can read GHOSTLINK API traffic the same way
  the GHOSTLINK server can. End-to-end content encryption (Double
  Ratchet) is unaffected; only metadata it can already infer from the
  HTTP request would leak.

- **No content-level downgrade.** Even with Nym off, the message
  payloads themselves are encrypted by the Double Ratchet — clearnet
  vs Tor vs Nym only changes who knows you talked to the server, not
  what you said.

- **Stacking with Tor is not supported.** The transport selector is
  mutually exclusive. Running Nym → Tor → onion adds 1–3s per hop
  twice and protects against nothing extra; both layers are designed
  against the same active adversary in different ways. Pick one.

- **Cover traffic is uplink-only by default.** The current Loopix-based
  Nym design pushes cover from the client side; the server doesn't yet
  emit matching cover toward you. A passive observer of *just your
  downlink* may still see when the server actually has something to
  send you. Closing this gap is on Nym's roadmap; GHOSTLINK will pick
  it up automatically once Nym ships it.

## Running your own Service Provider

Until the project SP exists, this is the only way to use the toggle for
real. Two paths:

### Easy: reference SP

```
nym-network-requester init --id ghostlink-sp
# Edit ~/.nym/service-providers/network-requester/ghostlink-sp/data/allowed.list
# Add only the GHOSTLINK endpoints you want to expose, e.g.
#   ghostlink.example.org
nym-network-requester run --id ghostlink-sp
```

The SP's Nym address is printed at startup; that's the value you paste
into the client.

### Harder: custom SP

If you want strict input validation (e.g. only accept POSTs to specific
GHOSTLINK paths) you can build a small Rust SP with `nym-sdk`. Outline,
not full code:

```rust
use nym_sdk::mixnet::{MixnetClient, ReconstructedMessage};

#[tokio::main]
async fn main() {
    let mut client = MixnetClient::connect_new().await.unwrap();
    while let Some(msg) = client.wait_for_messages().await {
        for m in msg {
            // m.message is the inbound HTTP request the client sent.
            // Validate path, forward to localhost:58443, reply via
            // client.send_str_to(m.sender_tag, response).await
        }
    }
}
```

This is roughly the structure of the M2 binary in the v2.5 plan.

## See also

- `docs/tor.md` — Tor onion deployment (default network-anonymity mode)
- `docs/nym-roadmap.md` — what's still missing and when it's scheduled
- Nym SOCKS5 client docs: <https://nymtech.net/docs/integrations/socks-proxy.html>
- Loopix paper: <https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska>
