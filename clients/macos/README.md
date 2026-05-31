# SHROUD macOS client

The macOS desktop client. Shares the Swift `AnonRouting` port with
the iOS client (CryptoKit is identical on both platforms), wraps it
in an AppKit-based UI.

## Status

Shipping as a v0 reference. The UI is intentionally minimal:

  - Login + relay URL
  - Contact list sidebar
  - Chat view per contact
  - Send box (Enter to send)

Voice/video calling, sticker picker, multi-device link QR scan,
and settings dialog all come in subsequent iterations. The crypto
layer is fully ready via `../ios/AnonRouting.swift`.

## Files

- `ShroudMacApp.swift` — AppKit application entry point
- `Sources/MainWindow.swift` — primary window controller
- `Sources/NetworkClient.swift` — REST client around the relay API

These import `../ios/AnonRouting.swift` directly. If you're building
a Mac app target in Xcode, add both directories to the target.

## Dependencies

- macOS 12.0+ (CryptoKit is in the SDK)
- Xcode 14+
- No third-party crypto

## Build

The `clients/macos/` tree ships source-only. There is no Xcode
project file checked in yet (one will be added after the AppKit
shell stabilizes). For now:

```bash
cd clients/macos
swift build           # if you have Package.swift (todo)
# or just open Xcode and add the sources to a new macOS App target.
```
