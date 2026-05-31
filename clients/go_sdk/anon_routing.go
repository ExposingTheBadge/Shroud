// Package shroud implements SHROUD's anonymous routing protocol in Go.
//
// Bit-compatible with the Python reference (crypto/anon_routing.py) and
// the C / Kotlin / Swift / JavaScript / Rust ports. Wire format spec in
// docs/anon-routing-protocol.md.
package shroud

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Wire format constants.
const (
	RoutingTagLen      = 32
	SealVersion        = 0x01
	SealVersionLen     = 1
	SealEphemeralLen   = 32
	SealNonceLen       = 12
	SealGCMTagLen      = 16
	SealFixedOverhead  = SealVersionLen + SealEphemeralLen + SealNonceLen + SealGCMTagLen
	EpochSeconds       = 3600
)

var (
	tagSalt     = []byte("shroud-tag-v1")
	sealSalt    = []byte("shroud-seal-v1")
	sealKeyInfo = []byte("key")
)

var (
	ErrInvalidPubKey       = errors.New("shroud: invalid public key (must be 32 bytes)")
	ErrInvalidPrivKey      = errors.New("shroud: invalid private key (must be 32 bytes)")
	ErrSealedTooShort      = errors.New("shroud: sealed envelope too short")
	ErrUnknownSealVersion  = errors.New("shroud: unknown sealed envelope version")
	ErrDecryptionFailed    = errors.New("shroud: decryption failed")
)


// EpochFor returns the epoch index for a given unix timestamp.
func EpochFor(unixTs int64) uint64 {
	if unixTs < 0 {
		return 0
	}
	return uint64(unixTs) / EpochSeconds
}

// EpochNow returns the current epoch index.
func EpochNow() uint64 {
	return EpochFor(time.Now().Unix())
}

// PairID returns the order-independent 64-bit pair fingerprint for two
// X25519 identity public keys.
func PairID(a, b [32]byte) uint64 {
	lo, hi := a, b
	if greater(a, b) {
		lo, hi = b, a
	}
	h := sha256.New()
	h.Write(lo[:])
	h.Write([]byte("||"))
	h.Write(hi[:])
	d := h.Sum(nil)
	return binary.BigEndian.Uint64(d[:8])
}

func greater(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// RoutingTag derives a 32-byte routing tag for a (shared_root, pair, epoch) triple.
func RoutingTag(sharedRoot [32]byte, pair uint64, epoch uint64) [RoutingTagLen]byte {
	info := make([]byte, 16)
	binary.BigEndian.PutUint64(info[0:8], pair)
	binary.BigEndian.PutUint64(info[8:16], epoch)

	reader := hkdf.New(sha256.New, sharedRoot[:], tagSalt, info)
	var out [RoutingTagLen]byte
	_, err := reader.Read(out[:])
	if err != nil {
		// HKDF-Expand of 32 bytes cannot fail for SHA-256.
		panic(err)
	}
	return out
}

// FetchTagsForWindow enumerates routing tags across an epoch window per pair.
// Recipients post these to /messages/fetch-anon.
func FetchTagsForWindow(
	pairs []PairKeyPair, anchorEpoch uint64, window int,
) [][RoutingTagLen]byte {
	seen := map[[RoutingTagLen]byte]struct{}{}
	out := make([][RoutingTagLen]byte, 0, len(pairs)*(2*window+1))
	for _, p := range pairs {
		lo := int64(anchorEpoch) - int64(window)
		hi := int64(anchorEpoch) + int64(window)
		for e := lo; e <= hi; e++ {
			ee := uint64(e)
			if e < 0 {
				ee = 0
			}
			t := RoutingTag(p.SharedRoot, p.PairID, ee)
			if _, dup := seen[t]; !dup {
				seen[t] = struct{}{}
				out = append(out, t)
			}
		}
	}
	return out
}

// PairKeyPair is the (pair_id, shared_root) tuple FetchTagsForWindow consumes.
type PairKeyPair struct {
	PairID     uint64
	SharedRoot [32]byte
}


// Seal encrypts payload so only the holder of the X25519 private key
// matching recipientPub can decrypt it.
func Seal(payload []byte, recipientPub [32]byte) ([]byte, error) {
	// Ephemeral X25519 keypair
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return nil, err
	}
	// Curve25519 private-key clamping
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	var ephPub [32]byte
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)

	shared, err := curve25519.X25519(ephPriv[:], recipientPub[:])
	if err != nil {
		return nil, err
	}

	key := deriveSealKey(shared, ephPub[:], recipientPub[:])

	var nonce [SealNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// No AAD: KDF input already commits eph_pub + recipient_pub.
	ciphertext := aead.Seal(nil, nonce[:], payload, nil)

	out := make([]byte, 0, SealFixedOverhead+len(payload))
	out = append(out, SealVersion)
	out = append(out, ephPub[:]...)
	out = append(out, nonce[:]...)
	out = append(out, ciphertext...)
	return out, nil
}

// Unseal recovers the plaintext payload from a sealed envelope.
func Unseal(sealed []byte, myPriv [32]byte, myPub [32]byte) ([]byte, error) {
	if len(sealed) < SealFixedOverhead {
		return nil, ErrSealedTooShort
	}
	if sealed[0] != SealVersion {
		return nil, ErrUnknownSealVersion
	}
	var ephPub [32]byte
	copy(ephPub[:], sealed[1:1+32])
	nonce := sealed[1+32 : 1+32+SealNonceLen]
	ctAndTag := sealed[1+32+SealNonceLen:]

	shared, err := curve25519.X25519(myPriv[:], ephPub[:])
	if err != nil {
		return nil, err
	}

	key := deriveSealKey(shared, ephPub[:], myPub[:])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ctAndTag, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plain, nil
}

func deriveSealKey(ecdhShared, ephPub, recipientPub []byte) []byte {
	ikm := make([]byte, 0, 96)
	ikm = append(ikm, ecdhShared...)
	ikm = append(ikm, ephPub...)
	ikm = append(ikm, recipientPub...)

	reader := hkdf.New(sha256.New, ikm, sealSalt, sealKeyInfo)
	key := make([]byte, 32)
	_, err := reader.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

// SortTagsLexicographic returns tags sorted lex-ascending. Useful when
// you want a canonical wire order for a fetch request.
func SortTagsLexicographic(tags [][RoutingTagLen]byte) {
	sort.Slice(tags, func(i, j int) bool {
		for k := 0; k < RoutingTagLen; k++ {
			if tags[i][k] != tags[j][k] {
				return tags[i][k] < tags[j][k]
			}
		}
		return false
	})
}
