# Nym Mixnet Integration — Roadmap (deferred to v2.5)

## Why this isn't shipping in v2.3

Tor hidden services (v2.3) defeat passive metadata collection on the
content side but still leak **traffic patterns**: a global passive
adversary watching both ends of a Tor circuit can correlate flows by
timing and volume. Nym's mixnet adds a packet-level mix (Loopix-style:
Poisson-shuffled, padded, cover-traffic) on top of, or alongside, Tor.

We considered shipping Nym in v2.3 alongside Tor; we are explicitly
**deferring it** for the following reasons.

### 1. No first-class mixnet client for our platforms

Today's options are:

| Path                         | Status                                    |
|------------------------------|-------------------------------------------|
| `nym-client` daemon (Rust)   | Works on Linux/macOS, awkward on Windows  |
| `nym-sdk` (Rust crate)       | Best path — needs FFI bindings per client |
| Native browser/WASM client   | Not viable on desktop/Android             |

Embedding `nym-sdk` requires a Rust toolchain in every client build:
- Windows client: would need cbindgen + a Rust crate linked into Qt6.
- Android client: would need JNI bindings and an `arm64-v8a/armv7/x86_64`
  triple-build of the SDK.
- Server side: an out-of-process daemon is fine but introduces a new
  long-running supervised process and a new on-disk identity to manage.

This is doable but it's a multi-week piece of work that should NOT block
the v2.3 features (multi-device linking, multi-sig, persistent stats).

### 2. Service-Provider model needs server changes

Nym apps don't talk peer-to-peer — they go through a **service provider**
that lives on the mixnet boundary and translates Sphinx packets to/from
the actual transport. For GHOSTLINK that means:
- Run a `nym-network-requester` (or custom Rust SP) next to the FastAPI
  server.
- Allowlist the GHOSTLINK API endpoints in the SP allowlist.
- Make the SP's Nym address discoverable to clients (probably committed
  in a `.well-known/ghostlink-nym.json` and signed alongside the release
  manifest).

That's a new operational surface. We want the Tor onion deployment to
soak first before stacking another transport.

### 3. UX cost is non-trivial

Nym latency is currently 1–3 seconds per round-trip in steady state and
can spike when the mixnet reshuffles. Our message-send and HTTP-poll
flows assume sub-second latency. We need to:
- Make the long-poll endpoint mix-tolerant (server already supports
  cancellation; clients should back off rather than spam retries).
- Surface a clear UI mode ("Mixnet — slower, harder to trace") so users
  understand the trade-off vs Tor or clearnet.
- Decide what happens when the mixnet SP is unreachable — fall back to
  Tor? Refuse to send? This is a policy decision the user should own.

## Threat model — Tor vs Nym

| Adversary                              | Tor hidden service | Nym mixnet |
|----------------------------------------|--------------------|------------|
| Passive ISP observer                   | defeated           | defeated   |
| Global passive (correlate both ends)   | partially mitigated| defeated   |
| Active traffic-pattern fingerprint     | vulnerable         | defeated   |
| Server compromise leaking metadata     | not addressed      | not addressed |
| Endpoint compromise (cold-boot, etc.)  | not addressed      | not addressed |

Bottom line: Nym protects against a *much* stronger adversary at a real
latency cost. Tor is the right default; Nym is the right opt-in.

## Plan for v2.5

Phased rollout, each milestone independently shippable:

### M1 — Server-side service provider (target: v2.5)
- Stand up `nym-network-requester` next to the server.
- Document the SP's Nym address in the published release manifest.
- Add `--enable-nym` flag to `server.py` for symmetry with `--bind`.

### M2 — Reference Rust client (target: v2.5)
- Tiny Rust binary that wraps `nym-sdk`, exposes a localhost HTTP proxy
  identical to what Tor's SOCKS port looks like (`127.0.0.1:1789`).
- Ships per-platform: `ghostlink-nym-bridge.exe`, ARM64 Android `.so`,
  Linux/macOS binaries.
- Pinned to a fixed `nym-sdk` version; signed with the same multi-sig
  bundle as the rest of the release.

### M3 — Client integration (target: v2.6)
- Windows: same Settings → Network tab now exposes a third radio,
  "Mixnet (Nym)", below the Tor SOCKS field. Sets WinHTTP proxy to the
  bridge's localhost port.
- Android: re-use the Network settings dialog from v2.3 Tor support;
  point at the bundled bridge service.
- Add UX affordance: a small chip on the chat list shows the active
  transport (Direct / Tor / Nym) so users always know how their messages
  are reaching the server.

### M4 — Cover traffic + padding (target: v2.7)
- Even with Nym, real-time messaging can leak via the cover-traffic
  distribution. Once M1–M3 ship and stabilise, replace our current cover
  traffic loop (server-only) with a client-side equivalent so client
  uplink also looks like noise to the SP.

## Open questions

1. **Service provider trust.** A self-hosted SP that the GHOSTLINK
   project runs becomes a juicy target. Long-term we should publish the
   SP source and config so others can run their own and we publish a
   *list* of SPs rather than a single endpoint.
2. **Reproducible Rust builds.** The bridge binary needs to be in our
   reproducible-builds story (`BUILD-REPRODUCIBILITY.md`) before it can
   be shipped. Cargo + a pinned toolchain is the obvious path.
3. **Co-existence with Tor.** Clients should be able to choose Tor or
   Nym per session. Stacking them (Nym → Tor → onion) is overkill and
   adds latency for no extra security against the threat models we care
   about; we'll explicitly not support it.

## References

- Nym whitepaper: <https://nymtech.net/nym-whitepaper.pdf>
- `nym-sdk` Rust docs: <https://nymtech.net/docs/sdk/rust>
- Loopix design (Piotrowska et al.): <https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-piotrowska.pdf>

## When this doc gets deleted

When `docs/nym.md` exists with concrete deployment instructions and
clients ship a working bridge, delete this roadmap. Until then, it's the
canonical answer to "why is Nym not in GHOSTLINK yet?".
