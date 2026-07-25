#!/bin/bash
# SHROUD relay — bootstrap script for plain (non-enclave) t3.micro EC2.
# Runs at first boot from cloud-init. Idempotent so subsequent reboots
# re-converge state instead of duplicating it.
set -euxo pipefail

LOG=/var/log/shroud-bootstrap.log
exec > >(tee -a $LOG) 2>&1

# ── 1. System packages ────────────────────────────────────────────────
# AL2023's default python3 is 3.9, but SHROUD's server.py uses PEP 604
# union syntax ("str | None") which requires 3.10+. Install python3.11.
dnf update -y
dnf install -y python3.11 python3.11-pip python3.11-devel gcc git sqlite openssl

# ── 2. Clone SHROUD ───────────────────────────────────────────────────
if [ ! -d /opt/shroud/src ]; then
    mkdir -p /opt/shroud
    git clone https://github.com/ExposingTheBadge/Shroud.git /opt/shroud/src
else
    cd /opt/shroud/src && git pull origin master
fi

# ── 3. Python deps in a venv (keeps system python clean) ─────────────
if [ ! -d /opt/shroud/venv ]; then
    python3.11 -m venv /opt/shroud/venv
fi
source /opt/shroud/venv/bin/activate
pip install --upgrade pip
pip install fastapi 'uvicorn[standard]' pydantic cryptography boto3

# ── 3b. liboqs — post-quantum primitives ─────────────────────────────
# Without this the relay boots fine but logs "PQ hybrid unavailable" and
# silently runs classical-only: no ML-KEM-1024 hybrid, no triple-hybrid
# signature. Every relay in the fleet sat that way until 2026-07-25.
#
# Build only the mechanisms SHROUD asks for. The full algorithm set is
# ~1600 compile targets and takes ~30 min on a t3.micro; this is ~250 and
# takes about a minute. 2 GB of swap keeps a parallel compile from
# OOM-killing the relay on a 1 GiB box.
if ! /opt/shroud/venv/bin/python -c "import oqs" >/dev/null 2>&1; then
    if ! swapon --show | grep -q swapfile; then
        dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
        chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
    fi
    dnf install -y -q cmake gcc gcc-c++ ninja-build openssl-devel python3.11-devel
    rm -rf /tmp/liboqs-build
    git clone -q --depth 1 --branch 0.16.0 \
        https://github.com/open-quantum-safe/liboqs /tmp/liboqs-build
    cmake -S /tmp/liboqs-build -B /tmp/liboqs-build/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_1024;SIG_ml_dsa_87;SIG_slh_dsa_pure_sha2_256s" \
        -DCMAKE_INSTALL_PREFIX=/usr/local
    ninja -C /tmp/liboqs-build/build -j"$(nproc)"
    ninja -C /tmp/liboqs-build/build install
    ldconfig
    pip install liboqs-python
fi

# ── 4. Self-signed TLS cert (clients pin server identity separately) ──
# IMDSv2: get a token first, then ask for metadata. AL2023 enforces this.
IMDS_TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)
PUB_IP=$(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
    -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")

CERT_DIR=/opt/shroud/tls
mkdir -p $CERT_DIR
if [ ! -f $CERT_DIR/server.crt ]; then
    if [ -n "$PUB_IP" ]; then
        SAN="subjectAltName=DNS:shroud-relay,IP:$PUB_IP"
    else
        SAN="subjectAltName=DNS:shroud-relay"
    fi
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout $CERT_DIR/server.key \
        -out $CERT_DIR/server.crt \
        -subj "/CN=shroud-relay" \
        -addext "$SAN"
    chmod 600 $CERT_DIR/server.key
fi

# ── 5. Runtime data dirs ──────────────────────────────────────────────
mkdir -p /opt/shroud/data/files
chown -R ec2-user:ec2-user /opt/shroud
# Server expects to run from its src dir so relative paths resolve
ln -sfn /opt/shroud/data/files /opt/shroud/src/server/files

# ── 6. systemd unit ───────────────────────────────────────────────────
cat > /etc/systemd/system/shroud-relay.service <<'EOF'
[Unit]
Description=SHROUD blind-relay server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/shroud/src
Environment=PYTHONUNBUFFERED=1
Environment=SHROUD_DATA_DIR=/opt/shroud/data
# liboqs-python searches OQS_INSTALL_PATH first. Without it the binding
# falls back to $HOME/_oqs and COMPILES liboqs from source at import
# time, pinning every vCPU for ~30 minutes while the relay is starting.
Environment=OQS_INSTALL_PATH=/usr/local
# Pin the hash-based signature mechanism. Auto-selection is per-host, and
# SLH-DSA and SPHINCS+ signatures do not cross-verify, so a fleet on
# mixed liboqs versions would silently split. See crypto/hybrid_sig.py.
Environment=SHROUD_SPH_MECH=SLH_DSA_PURE_SHA2_256S
ExecStart=/opt/shroud/venv/bin/uvicorn server.server:app \
    --host 0.0.0.0 \
    --port 58443 \
    --ssl-keyfile /opt/shroud/tls/server.key \
    --ssl-certfile /opt/shroud/tls/server.crt \
    --log-level info
Restart=always
RestartSec=5
StandardOutput=append:/var/log/shroud-relay.log
StandardError=append:/var/log/shroud-relay.log

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/shroud/data /opt/shroud/src/server /var/log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now shroud-relay.service

# ── 7. Status ─────────────────────────────────────────────────────────
sleep 5
systemctl status shroud-relay.service --no-pager || true
echo "SHROUD relay bootstrap complete"
echo "Public IP: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo "Endpoint:  https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):58443"
