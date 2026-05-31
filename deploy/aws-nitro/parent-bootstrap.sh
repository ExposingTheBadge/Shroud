#!/bin/bash
# Runs on the parent EC2 instance at boot.
#
# Responsibilities:
#   1. Install nitro-cli (idempotent — packages may already be in the AMI)
#   2. Configure the allocator (CPU/RAM for enclaves)
#   3. Pull the EIF (the enclave image file) from S3
#   4. Verify the EIF measurements match the published values
#   5. Launch the enclave
#   6. Start vsock-proxy services that bridge:
#        - tcp/58443 (the public relay port)            -> enclave vsock 5005
#        - vsock 3:5006 (config fetch from enclave)     -> S3 GetObject
#        - vsock 3:5007 (KMS Decrypt with attestation)  -> KMS endpoint
#
# Should be uploaded to the instance via cloud-init user-data and re-run
# from systemd if it ever needs to restart.

set -euxo pipefail

REGION=${SHROUD_REGION:-us-east-1}
S3_BUCKET=${SHROUD_S3_BUCKET:?must be set}
EIF_KEY=${SHROUD_EIF_KEY:-shroud-enclave.eif}
EXPECTED_PCR0=${SHROUD_EXPECTED_PCR0:?must be set}
ENCLAVE_CPUS=${SHROUD_ENCLAVE_CPUS:-2}
ENCLAVE_MEMORY=${SHROUD_ENCLAVE_MEMORY:-4096}
ENCLAVE_CID=${SHROUD_ENCLAVE_CID:-16}
RELAY_PORT=${SHROUD_RELAY_PORT:-58443}

LOG_DIR=/var/log/shroud
mkdir -p $LOG_DIR

# ── 1. Install nitro-cli + dependencies ─────────────────────────────
if ! command -v nitro-cli >/dev/null 2>&1; then
    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel jq
    systemctl enable --now nitro-enclaves-allocator.service
fi

# ── 2. Configure the allocator ──────────────────────────────────────
cat > /etc/nitro_enclaves/allocator.yaml <<EOF
memory_mib: $ENCLAVE_MEMORY
cpu_count: $ENCLAVE_CPUS
EOF
systemctl restart nitro-enclaves-allocator.service

# Wait for the allocator to come back up
for i in {1..30}; do
    if nitro-cli describe-enclaves >/dev/null 2>&1; then break; fi
    sleep 1
done

# ── 3. Pull EIF from S3 ──────────────────────────────────────────────
mkdir -p /opt/shroud
aws s3 cp "s3://$S3_BUCKET/$EIF_KEY" /opt/shroud/shroud-enclave.eif --region $REGION

# ── 4. Verify EIF measurement matches published PCR0 ────────────────
ACTUAL_PCR0=$(nitro-cli describe-eif --eif-path /opt/shroud/shroud-enclave.eif \
              | jq -r '.Measurements.PCR0')
if [[ "$ACTUAL_PCR0" != "$EXPECTED_PCR0" ]]; then
    echo "FATAL: EIF PCR0 mismatch" >&2
    echo "  expected: $EXPECTED_PCR0" >&2
    echo "  got:      $ACTUAL_PCR0" >&2
    exit 1
fi

# ── 5. Launch enclave (or restart if already running) ───────────────
EXISTING=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
if [[ -n "$EXISTING" ]]; then
    echo "[parent] terminating existing enclave $EXISTING"
    nitro-cli terminate-enclave --enclave-id "$EXISTING" || true
    sleep 2
fi

nitro-cli run-enclave \
    --eif-path /opt/shroud/shroud-enclave.eif \
    --cpu-count $ENCLAVE_CPUS \
    --memory $ENCLAVE_MEMORY \
    --enclave-cid $ENCLAVE_CID \
    --debug-mode false \
    > $LOG_DIR/run-enclave.json

# ── 6. Start vsock-proxy services ───────────────────────────────────
# Forward inbound TCP to the enclave's relay port.
cat > /etc/systemd/system/shroud-vsock-relay.service <<EOF
[Unit]
Description=SHROUD vsock-proxy: tcp/$RELAY_PORT -> enclave vsock $ENCLAVE_CID:5005
After=nitro-enclaves-allocator.service

[Service]
ExecStart=/usr/bin/vsock-proxy $RELAY_PORT $ENCLAVE_CID 5005
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# Config server that the enclave talks to for its KMS-encrypted config.
cat > /etc/systemd/system/shroud-config-server.service <<EOF
[Unit]
Description=SHROUD config server: serve KMS-encrypted bundle to enclave over vsock
After=nitro-enclaves-allocator.service

[Service]
Environment=SHROUD_S3_BUCKET=$S3_BUCKET
Environment=SHROUD_REGION=$REGION
ExecStart=/usr/bin/python3 /opt/shroud/parent-config-server.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# KMS proxy. The enclave does NOT call KMS directly (no IP networking).
# It hands us a signed attestation + ciphertext over vsock; we forward to
# kms.<region>.amazonaws.com using the parent's IAM role.
cat > /etc/systemd/system/shroud-kms-proxy.service <<EOF
[Unit]
Description=SHROUD KMS proxy: forward attestation-bound KMS:Decrypt for enclave
After=nitro-enclaves-allocator.service

[Service]
Environment=SHROUD_REGION=$REGION
ExecStart=/usr/bin/python3 /opt/shroud/parent-kms-proxy.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now shroud-vsock-relay.service
systemctl enable --now shroud-config-server.service
systemctl enable --now shroud-kms-proxy.service

echo "[parent] SHROUD relay enclave is running"
nitro-cli describe-enclaves
