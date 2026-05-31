# SHROUD web / Node port

Pure-JavaScript port of `crypto/anon_routing.py` using the
platform-native WebCrypto API. Works in:

- **Modern browsers** — Chrome 99+, Firefox 119+, Safari 17+
  (X25519 in WebCrypto landed in those versions)
- **Node.js 16+** — `globalThis.crypto.subtle` is built in
- **Deno 1.40+** — same

For older browsers, drop in `@noble/curves`'s X25519 as a tiny pure-JS
fallback; the rest of the module is unchanged.

## Usage

```html
<script type="module">
import { seal, unseal, routingTag, pairId, epochFor }
    from './anon_routing.js';

// Tiny example: pre-shared root + recipient pubkey, send a message
const root = new Uint8Array(32);  // from your X3DH handshake
const recipientPub = new Uint8Array(32);
const tag = await routingTag(root, await pairId(myId, recipientPub), epochFor());

const sealed = await seal(new TextEncoder().encode('hi bob'), recipientPub);
// POST sealed bytes to /api/v1/messages/send-anon with X-Routing-Tag=tag
</script>
```

The web port is wire-compatible with the Python/C/Kotlin/Swift ports.
A self-test is included as the exported `_selfTest()` function; run
it in your dev console after loading the script.

## What this enables

- **Browser-based chat client** — embed in a web page.
- **Browser extension** — sign messages from a Chrome / Firefox
  extension.
- **Node bot** — automated SHROUD agents on a server.
- **Electron clients** — share crypto code across desktop + web.

Voice/video calling in the browser would use the page's
`RTCPeerConnection` directly; the signaling envelopes ride sealed
envelopes the same as native clients.
