/*
 * SHROUD Share — options page.
 *
 * Lets the user configure relay URL, generate / paste an X25519
 * identity, and edit the contact list. All state lives in
 * chrome.storage.local and never leaves the browser profile.
 */

import { Hex } from './lib/anon_routing.js';

const RELAY_URL_KEY = 'shroud_relay_url';
const IDENTITY_KEY = 'shroud_identity';
const CONTACTS_KEY = 'shroud_contacts';
const DEFAULT_RELAY = 'https://173.245.244.180:58443';

const relayInput   = document.getElementById('relay');
const pubkeyDiv    = document.getElementById('pubkey');
const genButton    = document.getElementById('gen');
const clearButton  = document.getElementById('clear');
const contactsText = document.getElementById('contacts');
const saveButton   = document.getElementById('save');
const statusDiv    = document.getElementById('status');


async function load() {
    const got = await chrome.storage.local.get([RELAY_URL_KEY, IDENTITY_KEY, CONTACTS_KEY]);
    relayInput.value = got[RELAY_URL_KEY] || DEFAULT_RELAY;
    pubkeyDiv.textContent = got[IDENTITY_KEY]?.pub_x25519_hex || '(none — generate one below)';
    contactsText.value = JSON.stringify(got[CONTACTS_KEY] || [], null, 2);
}


genButton.addEventListener('click', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const privPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    // Strip the 16-byte PKCS8 prefix to get raw private bytes.
    const privRaw = privPkcs8.subarray(16);
    const identity = {
        priv_x25519_hex: Hex.encode(privRaw),
        pub_x25519_hex:  Hex.encode(pubRaw),
    };
    await chrome.storage.local.set({ [IDENTITY_KEY]: identity });
    pubkeyDiv.textContent = identity.pub_x25519_hex;
    setStatus('new identity generated', 'ok');
});


clearButton.addEventListener('click', async () => {
    if (!confirm('Erase your SHROUD identity? You will need to re-share your new public key with contacts.')) {
        return;
    }
    await chrome.storage.local.remove(IDENTITY_KEY);
    pubkeyDiv.textContent = '(none)';
    setStatus('identity erased', 'ok');
});


saveButton.addEventListener('click', async () => {
    const relay = relayInput.value.trim() || DEFAULT_RELAY;
    let contacts;
    try {
        const raw = contactsText.value.trim();
        contacts = raw ? JSON.parse(raw) : [];
        if (!Array.isArray(contacts)) throw new Error('expected a JSON array');
        for (const c of contacts) {
            if (typeof c.name !== 'string' || typeof c.identity_pubkey_hex !== 'string'
                || typeof c.shared_root_hex !== 'string') {
                throw new Error('each contact needs name + identity_pubkey_hex + shared_root_hex');
            }
        }
    } catch (e) {
        setStatus(`bad contacts JSON: ${e.message}`, 'err');
        return;
    }
    let origin;
    try {
        const u = new URL(relay);
        if (u.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(u.hostname)) {
            throw new Error('use https://');
        }
        origin = `${u.protocol}//${u.host}/*`;
    } catch (e) {
        setStatus(`bad relay URL: ${e.message}`, 'err');
        return;
    }
    // Only the default relay is granted at install; ask for any other.
    const granted = await chrome.permissions.contains({ origins: [origin] })
        || await chrome.permissions.request({ origins: [origin] });
    if (!granted) {
        setStatus('the browser did not allow reaching that relay', 'err');
        return;
    }
    await chrome.storage.local.set({
        [RELAY_URL_KEY]: relay,
        [CONTACTS_KEY]: contacts,
    });
    setStatus(`saved (${contacts.length} contact(s))`, 'ok');
});


function setStatus(text, kind) {
    statusDiv.textContent = text;
    statusDiv.className = `status ${kind || ''}`;
}


load();
