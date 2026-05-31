/*
 * SHROUD Double Ratchet — Windows C port
 *
 * Mirrors crypto/double_ratchet.py. Provides forward + future secrecy for
 * each peer-to-peer conversation. On-disk state is written per conversation
 * via storage_save_ratchet() and reloaded the next session.
 *
 * Wire format (matches the Python reference, magic = 'DR22'):
 *     magic     4B  le  0x32325244
 *     dh_pub   32B      sender's current X25519 public key
 *     pn        4B  le  previous-chain length (for OOO)
 *     n         4B  le  message number in current chain
 *     nonce    12B      AES-256-GCM nonce
 *     ct       var      AES-256-GCM ciphertext + tag
 */
#ifndef SHROUD_RATCHET_H
#define SHROUD_RATCHET_H

#include "client.h"

#define RATCHET_X25519_LEN  32
#define RATCHET_KEY_LEN     32
#define RATCHET_NONCE_LEN   12
#define RATCHET_GCM_TAG_LEN 16
#define RATCHET_HEADER_LEN  (4 + RATCHET_X25519_LEN + 4 + 4)  /* 44 */
#define RATCHET_MAGIC       0x32325244UL  /* 'DR22' LE */
#define RATCHET_MAX_SKIP    256           /* max OOO messages cached per chain */

typedef struct {
    BYTE  dhr_pub[RATCHET_X25519_LEN];
    DWORD n;
    BYTE  mk[RATCHET_KEY_LEN];
} RatchetSkippedKey;

typedef struct {
    BYTE   rk[RATCHET_KEY_LEN];
    BYTE   cks[RATCHET_KEY_LEN];     BOOL has_cks;
    BYTE   ckr[RATCHET_KEY_LEN];     BOOL has_ckr;
    BYTE   dhs_priv[RATCHET_X25519_LEN];
    BYTE   dhs_pub[RATCHET_X25519_LEN];
    BYTE   dhr_pub[RATCHET_X25519_LEN]; BOOL has_dhr;
    DWORD  ns;
    DWORD  nr;
    DWORD  pn;
    RatchetSkippedKey skipped[RATCHET_MAX_SKIP];
    DWORD  skipped_count;
} RatchetState;

/* X25519 / KDF primitives (Windows BCrypt-backed) */
BOOL ratchet_init_crypto(void);
BOOL ratchet_x25519_keygen(BYTE priv[RATCHET_X25519_LEN], BYTE pub[RATCHET_X25519_LEN]);
BOOL ratchet_x25519_dh(const BYTE priv[RATCHET_X25519_LEN],
                       const BYTE pub[RATCHET_X25519_LEN],
                       BYTE shared[RATCHET_X25519_LEN]);
/* HMAC-SHA512 / HKDF-SHA512 are reused by the v2 PQ hybrid handshake */
BOOL ratchet_hmac_sha512(const BYTE *key, DWORD key_len, const BYTE *data, DWORD data_len, BYTE out[64]);
BOOL ratchet_hkdf_sha512(const BYTE *salt, DWORD salt_len,
                         const BYTE *ikm,  DWORD ikm_len,
                         const BYTE *info, DWORD info_len,
                         BYTE *out, DWORD out_len);

/* Initialize a session.
 *  Alice (initiator) needs Bob's bundle x25519 pub.
 *  Bob (responder) initializes with his own x25519 keypair (matching what he
 *  published in his bundle) and waits for Alice's first message. */
BOOL ratchet_init_alice(RatchetState *st,
                        const BYTE shared_secret[RATCHET_KEY_LEN],
                        const BYTE bob_pub[RATCHET_X25519_LEN]);
BOOL ratchet_init_bob(RatchetState *st,
                      const BYTE shared_secret[RATCHET_KEY_LEN],
                      const BYTE my_priv[RATCHET_X25519_LEN],
                      const BYTE my_pub[RATCHET_X25519_LEN]);

/* Encrypt/decrypt one message.
 *  envelope buffer must have room for RATCHET_HEADER_LEN + RATCHET_NONCE_LEN
 *    + plaintext_len + RATCHET_GCM_TAG_LEN bytes.
 *  envelope_len_io is in/out: caller passes capacity, returns written. */
BOOL ratchet_encrypt(RatchetState *st,
                     const BYTE *plain, DWORD plain_len,
                     const BYTE *aad,   DWORD aad_len,
                     BYTE *envelope, DWORD *envelope_len_io);
BOOL ratchet_decrypt(RatchetState *st,
                     const BYTE *envelope, DWORD envelope_len,
                     const BYTE *aad,      DWORD aad_len,
                     BYTE *plain, DWORD *plain_len_io);

/* State (de)serialization for on-disk persistence. */
BOOL ratchet_state_save(const RatchetState *st, const char *path);
BOOL ratchet_state_load(RatchetState *st, const char *path);

/* Bootstrap shared root key for a session between two devices.
 * shared = HKDF-SHA512(salt=0, ikm=X25519(my_priv, peer_pub), info=...)
 * Both sides compute the same 32 bytes (ECDH symmetry).
 *
 * NOTE: kept for v1.6-era clients only. New code should use the X3DH
 * variants below — static-static-DH alone leaks the entire session if
 * either side's long-term identity is ever compromised. */
BOOL ratchet_compute_bootstrap(const BYTE my_priv[RATCHET_X25519_LEN],
                               const BYTE peer_pub[RATCHET_X25519_LEN],
                               BYTE shared_out[RATCHET_KEY_LEN]);

/* ── X3DH (Extended Triple Diffie-Hellman) ───────────────────────────
 *
 * Asynchronous handshake from Signal's X3DH spec, simplified for
 * SHROUD's IK + OTP schema (no signed prekey — Ed25519 ownership
 * proof on the IK already binds the bundle).
 *
 * Alice's input: her long-term identity priv (IK_A), a fresh ephemeral
 * keypair (EK_A), peer's identity pub (IK_B), and OPTIONALLY peer's
 * one-time prekey pub (OPK_B). Pass NULL for opk_pub to degrade to a
 * 2-DH handshake when the peer's OTP pool is exhausted; the resulting
 * SK still has forward secrecy on Bob's side via EK_A.
 *
 * Bob's input: his identity priv (IK_B), the OTP priv (OPK_B) Alice
 * consumed (or NULL if Alice signalled no-OTP), peer's identity pub
 * (IK_A), and peer's ephemeral pub (EK_A) lifted from the wire preamble.
 *
 * SK = HKDF-SHA512(salt=0,
 *                  ikm = 0xFF*32 || DH1 || DH2 || [DH3 || DH4],
 *                  info = "SHROUD-X3DH-v1",
 *                  L = 32)
 *
 *   DH1 = X25519(IK_A_priv, IK_B_pub)     [Alice]
 *       = X25519(IK_B_priv, IK_A_pub)     [Bob]   — authentication
 *   DH2 = X25519(EK_A_priv, IK_B_pub)     [Alice]
 *       = X25519(IK_B_priv, EK_A_pub)     [Bob]   — forward secrecy
 *   DH3 = X25519(EK_A_priv, OPK_B_pub)    [Alice] — extra forward+future
 *       = X25519(OPK_B_priv, EK_A_pub)    [Bob]     secrecy via OTP
 *   DH4 = X25519(IK_A_priv, OPK_B_pub)    [Alice] — binds Alice's
 *       = X25519(OPK_B_priv, IK_A_pub)    [Bob]     identity to the OTP
 *
 * The resulting SK is then fed to ratchet_init_alice/ratchet_init_bob
 * as the shared_secret root key. After successful decrypt Bob MUST
 * delete OPK_B_priv from local storage to lock in forward secrecy. */
BOOL ratchet_x3dh_alice(const BYTE my_ik_priv[RATCHET_X25519_LEN],
                        const BYTE my_ek_priv[RATCHET_X25519_LEN],
                        const BYTE peer_ik_pub[RATCHET_X25519_LEN],
                        const BYTE peer_opk_pub[RATCHET_X25519_LEN],  /* nullable */
                        BYTE sk_out[RATCHET_KEY_LEN]);

BOOL ratchet_x3dh_bob(const BYTE my_ik_priv[RATCHET_X25519_LEN],
                      const BYTE my_opk_priv[RATCHET_X25519_LEN],     /* nullable */
                      const BYTE peer_ik_pub[RATCHET_X25519_LEN],
                      const BYTE peer_ek_pub[RATCHET_X25519_LEN],
                      BYTE sk_out[RATCHET_KEY_LEN]);

#endif /* SHROUD_RATCHET_H */
