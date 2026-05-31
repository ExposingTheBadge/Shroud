/*
 * SHROUD anonymous routing — Windows client port.
 *
 * C counterpart of crypto/anon_routing.py. Implements:
 *   - 64-bit pair_id from two X25519 identity pubkeys (order-independent)
 *   - 32-byte routing tag = HKDF(shared_root || pair_id || epoch_hour)
 *   - Sealed envelope: ephemeral X25519 + ECDH + AES-256-GCM
 *
 * Rule 1 + Rule 2 compliant: the server learns only the routing tag and
 * an opaque ciphertext. Sender identity lives inside the ciphertext.
 *
 * Wire-format compatibility is guaranteed against the server's
 * /api/v1/messages/send-anon and /fetch-anon endpoints. The Python
 * server uses HKDF-SHA256; this header uses the same.
 */
#ifndef SHROUD_ANON_ROUTING_H
#define SHROUD_ANON_ROUTING_H

#include "client.h"
#include <stdint.h>

#define SHROUD_ROUTING_TAG_LEN     32
#define SHROUD_SEAL_VERSION        0x01
#define SHROUD_SEAL_VERSION_LEN    1
#define SHROUD_SEAL_EPHEMERAL_LEN  32
#define SHROUD_SEAL_NONCE_LEN      12
#define SHROUD_SEAL_GCM_TAG_LEN    16
#define SHROUD_SEAL_FIXED_OVERHEAD (SHROUD_SEAL_VERSION_LEN + \
                                    SHROUD_SEAL_EPHEMERAL_LEN + \
                                    SHROUD_SEAL_NONCE_LEN + \
                                    SHROUD_SEAL_GCM_TAG_LEN)
#define SHROUD_EPOCH_SECONDS       3600ULL

#ifdef __cplusplus
extern "C" {
#endif

/* Order-independent 64-bit pair fingerprint. Sender and receiver
 * derive the same value regardless of argument order. */
uint64_t anon_pair_id(const BYTE my_id[32], const BYTE their_id[32]);

/* unix_ts // 3600 */
uint64_t anon_epoch_for(uint64_t unix_ts);

/* Derive the routing tag the sender writes to / recipient polls.
 * shared_root: 32-byte X3DH root shared by both parties.
 * pair: anon_pair_id(...) of the two identity pubkeys.
 * epoch: anon_epoch_for(current_unix_time).
 * tag_out: 32 bytes, filled on success. */
BOOL anon_routing_tag(const BYTE shared_root[32],
                      uint64_t pair,
                      uint64_t epoch,
                      BYTE tag_out[SHROUD_ROUTING_TAG_LEN]);

/* Compute the up-to-(2*window+1) tags the recipient should poll across
 * a clock-skew window. Caller provides storage; returns count written.
 * window=1 -> {prev, current, next} = 3 tags. */
DWORD anon_routing_tags_window(const BYTE shared_root[32],
                               uint64_t pair,
                               uint64_t anchor_epoch,
                               DWORD window,
                               BYTE tags_out[][SHROUD_ROUTING_TAG_LEN],
                               DWORD tags_cap);

/* Seal a payload for a recipient. sealed_out must be at least
 * payload_len + SHROUD_SEAL_FIXED_OVERHEAD bytes. */
BOOL anon_seal(const BYTE *payload,
               DWORD payload_len,
               const BYTE recipient_pub[32],
               BYTE *sealed_out,
               DWORD *sealed_len_out);

/* Unseal a sealed envelope using the recipient's private key.
 * Caller provides both my_priv and my_pub (caller has them on hand from
 * key generation; this avoids needing a pub-from-priv helper).
 * payload_out must be at least sealed_len - SHROUD_SEAL_FIXED_OVERHEAD. */
BOOL anon_unseal(const BYTE *sealed,
                 DWORD sealed_len,
                 const BYTE my_priv[32],
                 const BYTE my_pub[32],
                 BYTE *payload_out,
                 DWORD *payload_len_out);

#ifdef __cplusplus
}
#endif

#endif /* SHROUD_ANON_ROUTING_H */
