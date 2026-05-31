# SHROUD Rust SDK — anon_routing port

Byte-compatible port of `crypto/anon_routing.py`. Same wire format as
the Python / C / Kotlin / Swift / JavaScript implementations. See
[`docs/anon-routing-protocol.md`](../../docs/anon-routing-protocol.md)
for the canonical spec.

## Why a Rust port

  - Memory-safe systems language for embedded SHROUD relays
  - Single-binary CLI tools
  - WebAssembly target via `wasm-bindgen` (X25519 + AES-GCM compile to
    a ~80 KB .wasm)
  - Server-side workers in heterogeneous environments

## Use

```toml
[dependencies]
shroud-anon-routing = "0.1"
```

```rust
use shroud_anon_routing::{seal, unseal, routing_tag, pair_id, epoch_now};
use x25519_dalek::{StaticSecret, PublicKey};

let priv_key = StaticSecret::random();
let pub_key = PublicKey::from(&priv_key);
let payload = b"hi bob";
let sealed = seal(payload, &pub_key.to_bytes()).unwrap();
let recovered = unseal(&sealed, &priv_key.to_bytes(), &pub_key.to_bytes()).unwrap();
assert_eq!(recovered, payload);

let tag = routing_tag(&[0u8; 32], pair_id(&[1u8;32], &[2u8;32]), epoch_now());
```

## Build

```bash
cd clients/rust_sdk
cargo test    # run all tests
cargo build --release
```

## Dependencies

- `x25519-dalek` for X25519
- `aes-gcm` for AES-256-GCM
- `hkdf` + `sha2` for HKDF-SHA256
- `rand` for the RNG

Locked versions in `Cargo.toml` for reproducibility. Bump together after audit.
