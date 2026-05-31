#!/bin/sh
# SHROUD relay enclave entrypoint.
#
# The enclave has NO direct network. Everything reaches the outside world
# via vsock to the parent EC2 instance, which is responsible for proxying
# TCP traffic (signed and load-balanced upstream) into the enclave.
#
# Steps:
#   1. Wait for the parent's vsock-proxy to become available.
#   2. Fetch the encrypted config bundle from the parent over vsock.
#   3. Call KMS:Decrypt with a Nitro attestation document. KMS releases
#      plaintext only when the enclave's PCR matches the published value.
#   4. Materialize identity keys, anon_creds key, and SRP secrets in
#      memory only (no disk writes).
#   5. Start uvicorn on a vsock listener.

set -e

# Vsock CIDs are fixed by Nitro convention:
#   3  = parent EC2 instance
#   16 = this enclave (configured at `nitro-cli run-enclave --enclave-cid 16`)
PARENT_CID=3
ENCLAVE_CID=16
CONFIG_PORT=5006
RELAY_PORT=5005

echo "[shroud-enclave] booting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── 1. Fetch the KMS-encrypted config blob from the parent ──────────
#
# The parent listens on vsock CID 3 port 5006 and serves the encrypted
# config bundle from S3 (uploaded once during deploy).
echo "[shroud-enclave] fetching encrypted config from parent CID=$PARENT_CID port=$CONFIG_PORT"
python3 /shroud/vsock-server.py fetch-config \
    --parent-cid $PARENT_CID \
    --port $CONFIG_PORT \
    --output /tmp/encrypted-config.bin

# ── 2. Generate Nitro attestation document and ask KMS to decrypt ──
#
# nsm-cli generates an attestation document signed by the Nitro
# hypervisor's private key. The KMS policy's
# `kms:RecipientAttestation:ImageSha384` condition checks the embedded
# PCR0 measurement and only decrypts if it matches.
#
# Key never appears in plaintext outside the enclave.
echo "[shroud-enclave] requesting KMS Decrypt with attestation"
python3 /shroud/vsock-server.py kms-decrypt \
    --parent-cid $PARENT_CID \
    --ciphertext /tmp/encrypted-config.bin \
    --output /run/shroud-config.json

# Tmpfs only — no disk persistence. /run is tmpfs in alpine.
chmod 600 /run/shroud-config.json
trap 'shred -u /run/shroud-config.json 2>/dev/null || rm -f /run/shroud-config.json' EXIT

# ── 3. Export config to env so server.py can pick it up ─────────────
export SHROUD_CONFIG_PATH=/run/shroud-config.json
export SHROUD_VSOCK_LISTEN_CID=$ENCLAVE_CID
export SHROUD_VSOCK_LISTEN_PORT=$RELAY_PORT
export SHROUD_NSM_DEVICE=/dev/nsm

# ── 4. Boot uvicorn on vsock ─────────────────────────────────────────
#
# vsock-server.py wraps uvicorn so it binds AF_VSOCK instead of AF_INET.
echo "[shroud-enclave] launching uvicorn on vsock://$ENCLAVE_CID:$RELAY_PORT"
exec python3 /shroud/vsock-server.py serve \
    --app server.server:app \
    --cid $ENCLAVE_CID \
    --port $RELAY_PORT \
    --log-level info
