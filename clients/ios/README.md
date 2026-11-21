# SHROUD for iOS and macOS

One SwiftUI codebase for iPhone, iPad and Mac. It speaks the same protocol
as the Android and Windows clients:

- **Encrypted sign-in.** The password travels only inside an AES-GCM payload
  keyed by ECDH (P-384) with a one-time relay key. It is never stored on the
  device; later calls authenticate with the device id.
- **Double Ratchet with X3DH** (`Ratchet.swift`, `RatchetSession.swift`),
  byte-for-byte the `DR22` / `X3D1` wire format of `crypto/double_ratchet.py`,
  `clients/windows/ratchet.c` and the Android `Ratchet.kt`.
- **Anonymous routing** (`AnonRouting.swift`, `NetworkClientAnon.swift`):
  sealed-sender envelopes padded to fixed buckets and posted to rotating
  per-pair routing tags, so the relay can't see who writes to whom.
- **TLS trust-on-first-use** (`Relay.swift`): the relay's self-signed
  certificate is pinned on first contact; a different one later is refused.
- **Sender verification:** a message is filed under a contact only when the
  sending device really belongs to that account on the relay.
- Contacts and requests, safety numbers, disappearing-message timer,
  per-conversation history stored with complete file protection, a
  configurable relay address for self-hosters, and anonymous crash reports.

Not yet on iOS: sending and viewing images, groups, calls, device linking.
Incoming images show a short notice instead.

## Build

The Xcode project is generated from `project.yml` with
[XcodeGen](https://github.com/yonaskolb/XcodeGen):

```sh
brew install xcodegen
cd clients/ios
xcodegen generate
open Shroud.xcodeproj
```

Pick the **Shroud** scheme, choose an iPhone simulator or *My Mac*, set your
signing team under *Signing & Capabilities*, and run. iOS 16+ / macOS 13+.

The generated `Shroud.xcodeproj`, `Info.plist` and `Shroud.entitlements` are
git-ignored; edit `project.yml` instead.

## Testing against a local relay

Run the relay (`python server/server.py`), then in the app's sign-in screen
set the relay address to `https://<your-mac-ip>:58443`. The first connection
pins that relay's certificate. The relay contract the app relies on is
checked in CI by `python -m tests.mobile_client_contract`.
