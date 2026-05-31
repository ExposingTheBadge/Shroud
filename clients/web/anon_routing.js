/*
 * SHROUD anonymous routing — Browser + Node.js port.
 *
 * Pure-JS port of crypto/anon_routing.py, matching the wire format
 * byte-for-byte against the Python/C/Kotlin/Swift implementations.
 *
 * Uses the platform-native WebCrypto API:
 *   - browsers: window.crypto.subtle  (Chrome 60+, Firefox 57+, Safari 11+)
 *   - Node:     globalThis.crypto.subtle  (Node 16+ has it natively)
 *
 * X25519 in WebCrypto is gated on slightly newer browsers:
 *   - Chrome 99+ (2022)
 *   - Firefox 119+ (2023)
 *   - Safari 17+ (2023)
 * If you need to ship to older browsers, drop in @noble/curves as a
 * tiny pure-JS X25519 fallback — the rest of the module is unchanged.
 *
 * Exports both ESM and CommonJS shapes so a build can consume this
 * from a web page, a node script, or a browser extension.
 */
'use strict';

const _subtle =
    (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) ||
    (typeof window !== 'undefined' && window.crypto && window.crypto.subtle);
if (!_subtle) {
    throw new Error('WebCrypto subtle API not available');
}

// ── Wire constants ───────────────────────────────────────────────────

export const ROUTING_TAG_LEN     = 32;
export const SEAL_VERSION        = 0x01;
export const SEAL_VERSION_LEN    = 1;
export const SEAL_EPHEMERAL_LEN  = 32;
export const SEAL_NONCE_LEN      = 12;
export const SEAL_GCM_TAG_LEN    = 16;
export const SEAL_FIXED_OVERHEAD =
    SEAL_VERSION_LEN + SEAL_EPHEMERAL_LEN + SEAL_NONCE_LEN + SEAL_GCM_TAG_LEN;
export const EPOCH_SECONDS       = 3600;

const TAG_SALT      = new TextEncoder().encode('shroud-tag-v1');
const SEAL_SALT     = new TextEncoder().encode('shroud-seal-v1');
const SEAL_KEY_INFO = new TextEncoder().encode('key');


// ── Small byte helpers ───────────────────────────────────────────────

function _concat(...arrays) {
    let len = 0;
    for (const a of arrays) len += a.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrays) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}

function _hex(buf) {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function _fromHex(s) {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.substr(i * 2, 2), 16);
    }
    return out;
}


// ── HKDF-SHA256 ──────────────────────────────────────────────────────

async function _hkdfExtract(salt, ikm) {
    const key = await _subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
    const bits = await _subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array(0) },
        key, 256
    );
    return new Uint8Array(bits);
}

async function _hkdfExpand(prk, info, length) {
    const key = await _subtle.importKey('raw', prk, { name: 'HKDF' }, false, ['deriveBits']);
    const bits = await _subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
        key, length * 8
    );
    return new Uint8Array(bits);
}

// HKDF as a single call. Web crypto's HKDF API does the extract+expand
// in one go when you pass both `salt` and `info`. For wire-format
// parity with the Python ref we explicitly do extract-then-expand so
// the intermediate PRK matches across implementations.
async function _hkdf(salt, ikm, info, length) {
    const prk = await _hkdfExtract(salt, ikm);
    return _hkdfExpand(prk, info, length);
}


// ── Routing tag (Rule 2) ─────────────────────────────────────────────

export function epochFor(unixTs = Math.floor(Date.now() / 1000)) {
    return Math.floor(unixTs / EPOCH_SECONDS);
}

async function _sha256(data) {
    return new Uint8Array(await _subtle.digest('SHA-256', data));
}

export async function pairId(myId, theirId) {
    if (myId.length !== 32 || theirId.length !== 32) {
        throw new Error('ids must be 32 bytes');
    }
    let lo = myId, hi = theirId;
    // Lexicographic order
    for (let i = 0; i < 32; i++) {
        if (myId[i] !== theirId[i]) {
            if (myId[i] > theirId[i]) { lo = theirId; hi = myId; }
            break;
        }
    }
    const input = _concat(lo, new TextEncoder().encode('||'), hi);
    const digest = await _sha256(input);
    // First 8 bytes big-endian -> 64-bit BigInt
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(digest[i]);
    return v;
}

async function _hkdfRoutingTag(sharedRoot, pair, epoch) {
    const info = new Uint8Array(16);
    const view = new DataView(info.buffer);
    view.setBigUint64(0, pair, false);
    view.setBigUint64(8, BigInt(epoch), false);
    return _hkdf(TAG_SALT, sharedRoot, info, ROUTING_TAG_LEN);
}

export async function routingTag(sharedRoot, pair, epoch) {
    if (sharedRoot.length !== 32) throw new Error('shared_root must be 32 bytes');
    return _hkdfRoutingTag(sharedRoot, pair, epoch);
}

export async function fetchTagsForWindow(pairs, around = null, window = 1) {
    const anchor = epochFor(around ?? Math.floor(Date.now() / 1000));
    const seen = new Set();
    const out = [];
    for (const [pid, root] of pairs) {
        for (let e = anchor - window; e <= anchor + window; e++) {
            const t = await routingTag(root, pid, e);
            const k = _hex(t);
            if (!seen.has(k)) {
                seen.add(k);
                out.push(t);
            }
        }
    }
    return out;
}


// ── Sealed envelope (Rule 1) ─────────────────────────────────────────

async function _x25519Generate() {
    const kp = await _subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pubRaw = new Uint8Array(await _subtle.exportKey('raw', kp.publicKey));
    return { priv: kp.privateKey, pub: pubRaw };
}

async function _x25519DhRaw(privKey, peerPubBytes) {
    const peer = await _subtle.importKey(
        'raw', peerPubBytes, { name: 'X25519' }, false, []
    );
    const bits = await _subtle.deriveBits({ name: 'X25519', public: peer }, privKey, 256);
    return new Uint8Array(bits);
}

async function _importPriv(rawPriv) {
    // WebCrypto X25519 only accepts PKCS8 — wrap manually.
    const pkcs8 = _concat(
        new Uint8Array([
            0x30, 0x2e, 0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x04, 0x22, 0x04, 0x20,
        ]),
        rawPriv
    );
    return _subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
}

async function _deriveSealKey(ecdhShared, ephPub, recipientPub) {
    const ikm = _concat(ecdhShared, ephPub, recipientPub);
    const prk = await _hkdfExtract(SEAL_SALT, ikm);
    return _hkdfExpand(prk, SEAL_KEY_INFO, 32);
}

export async function seal(payload, recipientPub) {
    if (recipientPub.length !== 32) throw new Error('recipient pubkey must be 32 bytes');
    const eph = await _x25519Generate();
    const shared = await _x25519DhRaw(eph.priv, recipientPub);
    const keyBytes = await _deriveSealKey(shared, eph.pub, recipientPub);
    const key = await _subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);

    const nonce = new Uint8Array(SEAL_NONCE_LEN);
    (globalThis.crypto || window.crypto).getRandomValues(nonce);

    const ctAndTag = new Uint8Array(await _subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: SEAL_GCM_TAG_LEN * 8 },
        key, payload
    ));

    return _concat(new Uint8Array([SEAL_VERSION]), eph.pub, nonce, ctAndTag);
}

export async function unseal(sealedBytes, myPrivRaw, myPub) {
    if (sealedBytes.length < SEAL_FIXED_OVERHEAD) throw new Error('sealed too short');
    if (sealedBytes[0] !== SEAL_VERSION) throw new Error('unknown seal version ' + sealedBytes[0]);

    const ephPub  = sealedBytes.subarray(1, 1 + 32);
    const nonce   = sealedBytes.subarray(1 + 32, 1 + 32 + SEAL_NONCE_LEN);
    const ctAndT  = sealedBytes.subarray(1 + 32 + SEAL_NONCE_LEN);

    const myPriv = await _importPriv(myPrivRaw);
    const shared = await _x25519DhRaw(myPriv, ephPub);
    const keyBytes = await _deriveSealKey(shared, ephPub, myPub);
    const key = await _subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);

    const plain = await _subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: SEAL_GCM_TAG_LEN * 8 },
        key, ctAndT
    );
    return new Uint8Array(plain);
}


// ── Convenience for callers that only have hex strings ───────────────

export const Hex = {
    encode: _hex,
    decode: _fromHex,
};


// ── Self-test ────────────────────────────────────────────────────────

export async function _selfTest() {
    const root = new Uint8Array(32); (globalThis.crypto || window.crypto).getRandomValues(root);
    const aliceId = new Uint8Array(32); (globalThis.crypto || window.crypto).getRandomValues(aliceId);
    const bobId = new Uint8Array(32); (globalThis.crypto || window.crypto).getRandomValues(bobId);

    const pa = await pairId(aliceId, bobId);
    const pb = await pairId(bobId, aliceId);
    if (pa !== pb) throw new Error('pair_id must be order-independent');

    const e = epochFor();
    const ta = await routingTag(root, pa, e);
    const tb = await routingTag(root, pb, e);
    if (_hex(ta) !== _hex(tb)) throw new Error('tags must agree across parties');
    if (ta.length !== 32) throw new Error('tag length wrong');

    // Seal roundtrip
    const bob = await _x25519Generate();
    // WebCrypto generated key, raw export needs the pkcs8 wrap on import.
    // For simplicity, we test via export & re-import with the raw helper.
    const bobPrivRaw = new Uint8Array(await _subtle.exportKey('pkcs8', bob.priv));
    // Strip the 16-byte PKCS8 prefix to get raw private bytes.
    const rawPriv = bobPrivRaw.subarray(16);
    const payload = new TextEncoder().encode('hello bob from anon JS');
    const sealed = await seal(payload, bob.pub);
    const recovered = await unseal(sealed, rawPriv, bob.pub);
    const recoveredStr = new TextDecoder().decode(recovered);
    if (recoveredStr !== 'hello bob from anon JS') {
        throw new Error('seal roundtrip failed: ' + recoveredStr);
    }

    // Tamper detection
    sealed[sealed.length - 1] ^= 1;
    let tampered = false;
    try {
        await unseal(sealed, rawPriv, bob.pub);
    } catch (e) {
        tampered = true;
    }
    if (!tampered) throw new Error('tamper detection failed');

    return true;
}
