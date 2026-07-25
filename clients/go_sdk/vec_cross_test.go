package shroud

import (
	"encoding/hex"
	"testing"
)

func TestCrossLangVectors(t *testing.T) {
	var a, b, root [32]byte
	for i := 0; i < 32; i++ {
		a[i] = byte(i)
		b[i] = byte(100 + i)
		root[i] = 0xAB
	}
	pair := PairID(a, b)
	if pair != 14238346497009308455 {
		t.Fatalf("pair_id: got %d want 14238346497009308455", pair)
	}
	want := map[uint64]string{
		0:      "0878c6e14dea3a235c954bb9277e6570f6be47b45ac427c5bf83440e88304216",
		1:      "c1ee572ddd805462bc00f0307996b9747dc9cc97f9fce3bb85a7f9ce3cbe3e6d",
		472000: "d9ccbe248ee1e6401eb76751638d06debb9262181fe936c3ff744a842f2a4057",
	}
	for e, w := range want {
		got := RoutingTag(root, pair, e)
		if h := hex.EncodeToString(got[:]); h != w {
			t.Errorf("epoch %d: got %s want %s", e, h, w)
		}
	}
}
