//! Pins this crate against the reference vectors in
//! crypto/anon_routing.py. A silent drift here means messages land on a
//! routing tag nobody polls — see tests/cross_client_vectors.py.
use shroud_anon_routing::{pair_id, routing_tag};

#[test]
fn matches_python_reference() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let root = [0xABu8; 32];
    for i in 0..32 {
        a[i] = i as u8;
        b[i] = (100 + i) as u8;
    }

    let pair = pair_id(&a, &b);
    assert_eq!(pair, 14238346497009308455, "pair_id drifted");

    let want: [(u64, &str); 3] = [
        (0,      "0878c6e14dea3a235c954bb9277e6570f6be47b45ac427c5bf83440e88304216"),
        (1,      "c1ee572ddd805462bc00f0307996b9747dc9cc97f9fce3bb85a7f9ce3cbe3e6d"),
        (472000, "d9ccbe248ee1e6401eb76751638d06debb9262181fe936c3ff744a842f2a4057"),
    ];
    for (epoch, expected) in want {
        let tag = routing_tag(&root, pair, epoch);
        assert_eq!(hex::encode(tag), expected, "tag mismatch at epoch {epoch}");
    }
}
