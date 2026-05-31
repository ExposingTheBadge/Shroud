# SHROUD browser extension

Tiny Chrome / Firefox / Safari extension that adds a "Send selected
text to SHROUD" right-click action to any web page. Useful for
quickly sharing a quote, a URL, a screenshot caption.

## Status

v0 scaffold — works as a sender. Receive UI is intentionally not
included because doing it well needs a persistent background tab,
which extensions strongly discourage. Receive on a desktop / mobile
client instead.

## Install (developer mode)

### Chrome / Edge / Brave

1. Build the extension:
   ```bash
   cd clients/browser_extension
   # the extension is plain JS modules; no build step needed
   ```
2. Open `chrome://extensions/`
3. Toggle **Developer mode** (top right)
4. Click **Load unpacked** and pick the
   `clients/browser_extension/` directory

### Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on…**
3. Pick `clients/browser_extension/manifest.json`

(Firefox v0 limitation: temporary add-ons reset on restart. For
permanent install, sign the .zip via Mozilla's add-on portal.)

### Safari

Safari requires Xcode-built extensions. Convert the manifest+JS via:
```bash
xcrun safari-web-extension-converter clients/browser_extension/
```
then load the resulting Xcode project.

## Configure

After install, right-click the extension icon → **Options** to
configure:

  - Relay URL (defaults to `https://44.202.225.57:58443`)
  - Your SHROUD identity (paste an X25519 keypair or generate)
  - Contacts (per-contact name + pubkey + shared root)

State lives in `chrome.storage.local`, which is on-disk inside the
browser's profile. Never leaves your machine.

## Files

- `manifest.json` — Manifest V3 declaration
- `background.js` — service worker; uses
  `../web/anon_routing.js` for the actual sealing
- `popup.html` + `popup.js` — toolbar popup
- `options.html` (todo) — settings page for identity + contacts
- `icons/` — placeholder icons (provide your own before publishing)

## Limitations

- No receive UI (see Status above)
- No multi-device sync — extension storage is per-browser-profile
- Icons are placeholders; replace with the SHROUD lattice icon
  before publishing
- Not yet submitted to the Chrome Web Store / Mozilla Add-ons; the
  current scaffold is for sideload only

## Future

- Options page with QR code scan to import contacts from a phone
- "Send screenshot to SHROUD" via the OS clipboard
- Receive notifications (with an opt-in to keep a tab open)
