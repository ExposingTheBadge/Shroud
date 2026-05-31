//! SHROUD anonymous routing — Rust port.
//!
//! Bit-compatible with `crypto/anon_routing.py`, `clients/windows/anon_routing.c`,
//! `clients/android/.../AnonRouting.kt`, `clients/ios/AnonRouting.swift`, and
//! `clients/web/anon_routing.js`. Wire format spec in
//! `docs/anon-routing-protocol.md`.
//!
//! Use this when you want a SHROUD client (or relay-side component) in
//! a memory-safe systems language. Common targets:
//!   - embedded devices (e.g., a SHROUD-aware router)
//!   - CLI tools that need to be fast / single-binary
//!   - server-side workers in mixed environments
//!   - browser via wasm-bindgen (subset; see README)

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub const ROUTING_TAG_LEN: usize = 32;
pub const SEAL_VERSION: u8 = 0x01;
pub const SEAL_VERSION_LEN: usize = 1;
pub const SEAL_EPHEMERAL_LEN: usize = 32;
pub const SEAL_NONCE_LEN: usize = 12;
pub const SEAL_GCM_TAG_LEN: usize = 16;
pub const SEAL_FIXED_OVERHEAD: usize =
    SEAL_VERSION_LEN + SEAL_EPHEMERAL_LEN + SEAL_NONCE_LEN + SEAL_GCM_TAG_LEN;
pub const EPOCH_SECONDS: u64 = 3600;

const TAG_SALT: &[u8] = b"shroud-tag-v1";
const SEAL_SALT: &[u8] = b"shroud-seal-v1";
const SEAL_KEY_INFO: &[u8] = b"key";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key (must be 32 bytes)")]
    InvalidPublicKey,
    #[error("invalid private key (must be 32 bytes)")]
    InvalidPrivateKey,
    #[error("sealed envelope too short")]
    SealedTooShort,
    #[error("unknown sealed version {0:#x}")]
    UnknownSealVersion(u8),
    #[error("decryption failed")]
    DecryptionFailed,
}

pub fn epoch_for(unix_ts: u64) -> u64 {
    unix_ts / EPOCH_SECONDS
}

pub fn epoch_now() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_for(now)
}

/// Order-independent 64-bit pair fingerprint from two X25519 identity
/// public keys. Both parties compute the same value regardless of which
/// side is "mine" and which is "theirs".
pub fn pair_id(a: &[u8; 32], b: &[u8; 32]) -> u64 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(lo);
    hasher.update(b"||");
    hasher.update(hi);
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().unwrap())
}

/// Derive a 32-byte routing tag for a given epoch.
pub fn routing_tag(
    shared_root: &[u8; 32],
    pair: u64,
    epoch: u64,
) -> [u8; ROUTING_TAG_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(TAG_SALT), shared_root);
    let mut info = [0u8; 16];
    info[..8].copy_from_slice(&pair.to_be_bytes());
    info[8..].copy_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; ROUTING_TAG_LEN];
    hk.expand(&info, &mut out)
        .expect("HKDF expand never fails for 32 bytes");
    out
}

/// Enumerate routing tags across (prev, current, next) epochs for each
/// contact pair. Recipients submit this list to /messages/fetch-anon.
pub fn fetch_tags_for_window(
    pairs: &[(u64, [u8; 32])],
    anchor_epoch: u64,
    window: u64,
) -> Vec<[u8; ROUTING_TAG_LEN]> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (pid, root) in pairs {
        let lo = anchor_epoch.saturating_sub(window);
        let hi = anchor_epoch.saturating_add(window);
        for e in lo..=hi {
            let t = routing_tag(root, *pid, e);
            if seen.insert(t) {
                out.push(t);
            }
        }
    }
    out
}

fn derive_seal_key(
    ecdh_shared: &[u8; 32],
    eph_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> [u8; 32] {
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(ecdh_shared);
    ikm[32..64].copy_from_slice(eph_pub);
    ikm[64..].copy_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(SEAL_SALT), &ikm);
    let mut key = [0u8; 32];
    hk.expand(SEAL_KEY_INFO, &mut key)
        .expect("HKDF expand never fails");
    key
}

/// Seal a payload so only the holder of the X25519 private key paired
/// with `recipient_pub` can decrypt it.
pub fn seal(payload: &[u8], recipient_pub: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let recipient = PublicKey::from(*recipient_pub);
    let eph_priv = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_pub = PublicKey::from(&eph_priv);
    let shared = eph_priv.diffie_hellman(&recipient);

    let key = derive_seal_key(shared.as_bytes(), eph_pub.as_bytes(), recipient_pub);

    let mut nonce_bytes = [0u8; SEAL_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::InvalidPrivateKey)?;
    // No AAD: KDF input already commits eph_pub + recipient_pub.
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: payload, aad: &[] })
        .map_err(|_| Error::DecryptionFailed)?;

    let mut out = Vec::with_capacity(SEAL_FIXED_OVERHEAD + payload.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Recover the plaintext payload from a sealed envelope.
pub fn unseal(
    sealed: &[u8],
    my_priv: &[u8; 32],
    my_pub: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if sealed.len() < SEAL_FIXED_OVERHEAD {
        return Err(Error::SealedTooShort);
    }
    if sealed[0] != SEAL_VERSION {
        return Err(Error::UnknownSealVersion(sealed[0]));
    }
    let eph_pub_bytes: [u8; 32] = sealed[1..1 + 32].try_into().unwrap();
    let nonce_bytes: [u8; SEAL_NONCE_LEN] =
        sealed[1 + 32..1 + 32 + SEAL_NONCE_LEN].try_into().unwrap();
    let ct_and_tag = &sealed[1 + 32 + SEAL_NONCE_LEN..];

    let priv_key = StaticSecret::from(*my_priv);
    let eph_pub_pk = PublicKey::from(eph_pub_bytes);
    let shared = priv_key.diffie_hellman(&eph_pub_pk);

    let key = derive_seal_key(shared.as_bytes(), &eph_pub_bytes, my_pub);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::InvalidPrivateKey)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct_and_tag, aad: &[] })
        .map_err(|_| Error::DecryptionFailed)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_id_is_order_independent() {
        let a: [u8; 32] = [0x11; 32];
        let b: [u8; 32] = [0x22; 32];
        assert_eq!(pair_id(&a, &b), pair_id(&b, &a));
    }

    #[test]
    fn tags_agree_across_parties() {
        let root: [u8; 32] = [0xAB; 32];
        let alice: [u8; 32] = [0x11; 32];
        let bob: [u8; 32] = [0x22; 32];
        let pid = pair_id(&alice, &bob);
        let t_alice = routing_tag(&root, pid, 100);
        let t_bob = routing_tag(&root, pair_id(&bob, &alice), 100);
        assert_eq!(t_alice, t_bob);
    }

    #[test]
    fn tags_rotate_per_epoch() {
        let root: [u8; 32] = [0xCD; 32];
        let t1 = routing_tag(&root, 1, 100);
        let t2 = routing_tag(&root, 1, 101);
        assert_ne!(t1, t2);
    }

    #[test]
    fn seal_roundtrip() {
        let priv_bytes: [u8; 32] = rand::random();
        let priv_key = StaticSecret::from(priv_bytes);
        let pub_key = PublicKey::from(&priv_key);
        let pub_bytes: [u8; 32] = pub_key.to_bytes();

        let payload = b"hello bob from rust";
        let sealed = seal(payload, &pub_bytes).unwrap();
        assert_eq!(sealed[0], SEAL_VERSION);
        let recovered = unseal(&sealed, &priv_bytes, &pub_bytes).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn tamper_is_detected() {
        let priv_bytes: [u8; 32] = rand::random();
        let priv_key = StaticSecret::from(priv_bytes);
        let pub_key = PublicKey::from(&priv_key);
        let pub_bytes = pub_key.to_bytes();

        let payload = b"sensitive";
        let mut sealed = seal(payload, &pub_bytes).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(unseal(&sealed, &priv_bytes, &pub_bytes).is_err());
    }

    #[test]
    fn fetch_tags_window_returns_2w_plus_1_per_pair() {
        let root: [u8; 32] = [0; 32];
        let pairs = vec![(1u64, root), (2u64, root)];
        let tags = fetch_tags_for_window(&pairs, 100, 1);
        // 2 pairs * 3 epochs = 6 tags (no overlap expected since pair differs)
        assert_eq!(tags.len(), 6);
    }
}
