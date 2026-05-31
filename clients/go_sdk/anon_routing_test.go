package shroud

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestPairIDIsOrderIndependent(t *testing.T) {
	var a, b [32]byte
	for i := 0; i < 32; i++ {
		a[i] = 0x11
		b[i] = 0x22
	}
	if PairID(a, b) != PairID(b, a) {
		t.Fatal("pair_id must be order-independent")
	}
}

func TestTagsAgreeAcrossParties(t *testing.T) {
	var root, alice, bob [32]byte
	for i := 0; i < 32; i++ {
		root[i] = 0xAB
		alice[i] = 0x11
		bob[i] = 0x22
	}
	pid := PairID(alice, bob)
	tA := RoutingTag(root, pid, 100)
	tB := RoutingTag(root, PairID(bob, alice), 100)
	if tA != tB {
		t.Fatal("tags must agree across parties")
	}
}

func TestTagsRotatePerEpoch(t *testing.T) {
	var root [32]byte
	for i := range root {
		root[i] = 0xCD
	}
	t1 := RoutingTag(root, 1, 100)
	t2 := RoutingTag(root, 1, 101)
	if t1 == t2 {
		t.Fatal("tags must rotate per epoch")
	}
}

func TestSealRoundtrip(t *testing.T) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	payload := []byte("hello bob from go")
	sealed, err := Seal(payload, pub)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != SealVersion {
		t.Fatalf("expected version %d, got %d", SealVersion, sealed[0])
	}
	recovered, err := Unseal(sealed, priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("roundtrip mismatch: got %q want %q", recovered, payload)
	}
}

func TestTamperIsDetected(t *testing.T) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	payload := []byte("sensitive")
	sealed, err := Seal(payload, pub)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Unseal(sealed, priv, pub); err == nil {
		t.Fatal("expected tamper to be detected")
	}
}

func TestFetchTagsForWindow(t *testing.T) {
	var r [32]byte
	pairs := []PairKeyPair{
		{PairID: 1, SharedRoot: r},
		{PairID: 2, SharedRoot: r},
	}
	tags := FetchTagsForWindow(pairs, 100, 1)
	// 2 pairs * 3 epochs = 6 tags
	if len(tags) != 6 {
		t.Fatalf("expected 6 tags, got %d", len(tags))
	}
}
