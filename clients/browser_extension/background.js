/*
 * SHROUD browser extension — service worker.
 *
 * Registers a context menu item "Send to SHROUD…" that turns the
 * selected text into a sealed envelope addressed to the user's
 * pre-configured contact list and posts it to the configured relay.
 *
 * The user's identity + contacts live in chrome.storage.local,
 * encrypted at rest via the browser's built-in storage. They are
 * NEVER sent to a remote server — only the message ciphertext is.
 */

import { seal, routingTag, pairId, epochFor, Hex } from '../web/anon_routing.js';

const RELAY_URL_KEY = 'shroud_relay_url';
const IDENTITY_KEY = 'shroud_identity';
const CONTACTS_KEY = 'shroud_contacts';
const DEFAULT_RELAY = 'https://44.202.225.57:58443';
const PAD_BUCKETS = [4096, 65536, 1048576, 16777216];


// ── Storage helpers ──────────────────────────────────────────────────

async function getRelayUrl() {
    const { [RELAY_URL_KEY]: url } = await chrome.storage.local.get(RELAY_URL_KEY);
    return url || DEFAULT_RELAY;
}

async function getIdentity() {
    const { [IDENTITY_KEY]: ident } = await chrome.storage.local.get(IDENTITY_KEY);
    return ident || null;
}

async function getContacts() {
    const { [CONTACTS_KEY]: contacts } = await chrome.storage.local.get(CONTACTS_KEY);
    return contacts || [];
}


// ── Context menu ────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'shroud-send-selection',
        title: 'Send selected text to SHROUD contact…',
        contexts: ['selection'],
    });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId !== 'shroud-send-selection') return;
    const text = info.selectionText || '';
    if (!text) return;
    // Open the popup with the text pre-filled (popup reads via
    // session storage so it survives the popup open).
    await chrome.storage.session.set({ shroud_pending_send: text });
    chrome.action.openPopup();
});


// ── Public message API for popup.js to call ──────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'shroud_send_to_contact') {
        sendToContact(msg.contactName, msg.body)
            .then(result => sendResponse({ ok: true, ...result }))
            .catch(err => sendResponse({ ok: false, error: String(err) }));
        return true;  // async response
    }
});


async function sendToContact(contactName, body) {
    const relayUrl = await getRelayUrl();
    const identity = await getIdentity();
    const contacts = await getContacts();
    if (!identity) throw new Error('no SHROUD identity configured — set one in Options');

    const c = contacts.find(c => c.name === contactName);
    if (!c) throw new Error(`unknown contact: ${contactName}`);

    const myPubBytes = Hex.decode(identity.pub_x25519_hex);
    const theirPubBytes = Hex.decode(c.identity_pubkey_hex);
    const rootBytes = Hex.decode(c.shared_root_hex);

    const pair = await pairId(myPubBytes, theirPubBytes);
    const tag = await routingTag(rootBytes, pair, epochFor());

    const payload = new TextEncoder().encode(JSON.stringify({
        sender: identity.pub_x25519_hex.slice(0, 12),
        ts: Math.floor(Date.now() / 1000),
        body,
    }));

    const sealed = await seal(payload, theirPubBytes);
    const target = PAD_BUCKETS.find(b => b >= sealed.length);
    const padded = new Uint8Array(target);
    padded.set(sealed, 0);

    const resp = await fetch(`${relayUrl.replace(/\/$/, '')}/api/v1/messages/send-anon`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/octet-stream',
            'X-Routing-Tag': Hex.encode(tag),
            'X-Envelope-Version': '2',
        },
        body: padded,
    });
    if (!resp.ok) throw new Error(`relay returned HTTP ${resp.status}`);
    const data = await resp.json();
    return { message_id: data.message_id };
}
