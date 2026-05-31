# SHROUD Go SDK — anon_routing port

Byte-compatible Go port of `crypto/anon_routing.py`. Wire spec in
[`docs/anon-routing-protocol.md`](../../docs/anon-routing-protocol.md).

## Why

  - Bots and integrations written in Go
  - Server-side workers
  - CLI tools that need a single static binary
  - Containers that want a small base image (Go's net/http is in the
    stdlib so a SHROUD-aware micro-relay can be ~10 MB after `upx`)

## Use

```go
import shroud "github.com/ExposingTheBadge/Shroud/clients/go_sdk"

// X25519 identity pubkey
var recipientPub [32]byte

payload := []byte("hi bob")
sealed, err := shroud.Seal(payload, recipientPub)
if err != nil { panic(err) }

// Recipient side:
var priv, pub [32]byte
// derive priv/pub from your X3DH state...
recovered, err := shroud.Unseal(sealed, priv, pub)
```

## Build

```bash
cd clients/go_sdk
go test ./...
go build ./...
```

## Dependencies

- `golang.org/x/crypto` for `curve25519`, `hkdf`
- Standard library for `aes/gcm`, `sha256`, `rand`

Both pinned at known-good versions in `go.mod`.

## Coverage

This package covers `anon_routing` only. The richer protocol modules
(`crypto/calls`, `crypto/file_transfer`, etc.) are not yet ported to
Go — open a PR if you need them. The protocol layer is small,
self-contained, and the test vectors in the other ports are easy to
mirror.
