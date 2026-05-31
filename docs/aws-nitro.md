# Running a SHROUD relay on AWS Nitro Enclaves

This runbook deploys a SHROUD relay inside an AWS Nitro Enclave — a
hardware-isolated VM whose code can be cryptographically attested by
Amazon and verified by clients. Even AWS administrators cannot read into
the enclave's memory or disk; the enclave's secrets are encrypted to a
KMS key whose policy refuses to decrypt for any code other than the
specific image whose PCR0 measurement is published in the release manifest.

The result: AWS hosts SHROUD's compute, AWS cannot read or modify SHROUD's
data, AWS cannot compel SHROUD's maintainers to introduce a backdoor
without changing PCR0 (which immediately fails every client's verifier).

## Architecture

```
                Internet
                    │
                    ▼
            ┌─────────────────┐
            │  Network LB     │
            │  (TLS opt.)     │
            └────────┬────────┘
                     │ tcp/58443
                     ▼
            ┌─────────────────────────────────┐
            │  Parent EC2 (c6i.xlarge)        │
            │  ┌───────────────────────────┐  │
            │  │  vsock-proxy 58443->16:5005 │
            │  │  config-server (vsock 5006) │
            │  │  kms-proxy     (vsock 5007) │
            │  └───────────────────────────┘  │
            │                                  │
            │  ┌───────────────────────────┐  │
            │  │   Nitro Enclave (CID 16)  │  │
            │  │   - Sees only ciphertext  │  │
            │  │   - No disk, no IP        │  │
            │  │   - PCR0 attested by AWS  │  │
            │  └───────────────────────────┘  │
            └─────────────────────────────────┘
                     │
                     ▼ S3 / KMS via parent's IAM role
              ┌──────────────┐
              │ S3 artifacts │  (EIF, encrypted config bundle)
              │  KMS key     │  (config decrypt requires attestation)
              └──────────────┘
```

## Prereqs

1. AWS account, CLI installed and authenticated (`aws sts get-caller-identity`)
2. Terraform ≥ 1.5 (`winget install Hashicorp.Terraform`)
3. Docker (for building the enclave image locally before pushing)
4. An EC2 key pair (Console → EC2 → Key Pairs → Create key pair, RSA 2048,
   .pem format if SSHing from WSL/Linux, .ppk if PuTTY)

## End-to-end deploy

### Phase 1 — Build the EIF locally and capture PCR0

You need PCR0 *before* Terraform can apply, because the KMS policy
references it.

```bash
# Build the enclave image. Run this on a Linux host with nitro-cli
# installed (an Amazon Linux 2023 EC2 instance is the easiest path).
cd ~/Shroud
docker build -t shroud-enclave:latest -f deploy/aws-nitro/Dockerfile.enclave .
nitro-cli build-enclave \
    --docker-uri shroud-enclave:latest \
    --output-file shroud-enclave.eif

# Capture PCR0
PCR0=$(nitro-cli describe-eif --eif-path shroud-enclave.eif \
        | jq -r '.Measurements.PCR0')
echo "PCR0=$PCR0"
```

Save `$PCR0` — you'll pass it to Terraform and to clients (via the
multisig-signed release manifest).

### Phase 2 — Apply the Terraform module

```bash
cd deploy/aws-nitro/terraform

terraform init
terraform apply \
    -var="region=us-east-1" \
    -var="subnet_ids=[\"subnet-aaa\",\"subnet-bbb\"]" \
    -var="ssh_key_name=my-ec2-keypair" \
    -var="ssh_cidr=$(curl -s ifconfig.me)/32" \
    -var="expected_pcr0=$PCR0"
```

Outputs:
- `relay_dns_name` — the Network Load Balancer DNS; clients connect here
- `s3_bucket` — upload the EIF + encrypted config here
- `kms_key_arn` — encrypt the config bundle to this key

### Phase 3 — Upload artifacts to S3

```bash
S3_BUCKET=$(terraform output -raw s3_bucket)
KMS_KEY_ARN=$(terraform output -raw kms_key_arn)

# Upload the EIF
aws s3 cp shroud-enclave.eif s3://$S3_BUCKET/shroud-enclave.eif

# Upload parent-side scripts (the launch template's user-data fetches these)
aws s3 cp deploy/aws-nitro/parent-bootstrap.sh    s3://$S3_BUCKET/parent-scripts/
aws s3 cp deploy/aws-nitro/parent-config-server.py s3://$S3_BUCKET/parent-scripts/
aws s3 cp deploy/aws-nitro/parent-kms-proxy.py    s3://$S3_BUCKET/parent-scripts/

# Encrypt and upload the runtime config (server identity keys, anon_creds
# RSA keypair, SRP params, etc.). Generate the config locally first; it
# never lives on disk on the parent — the parent only sees the ciphertext.
python deploy/aws-nitro/generate-config.py > /tmp/shroud-config.json
aws kms encrypt \
    --key-id $KMS_KEY_ARN \
    --plaintext fileb:///tmp/shroud-config.json \
    --output text \
    --query CiphertextBlob \
    | base64 -d \
    > /tmp/shroud-config.encrypted
aws s3 cp /tmp/shroud-config.encrypted s3://$S3_BUCKET/shroud-config.encrypted

# IMPORTANT — wipe the plaintext config from your local disk.
shred -u /tmp/shroud-config.json
```

### Phase 4 — Trigger ASG instance refresh

```bash
ASG_NAME=$(aws autoscaling describe-auto-scaling-groups \
    --query 'AutoScalingGroups[?starts_with(AutoScalingGroupName, `shroud-relay`)].AutoScalingGroupName' \
    --output text)
aws autoscaling start-instance-refresh --auto-scaling-group-name $ASG_NAME
```

The instance comes up, runs user-data, which runs `parent-bootstrap.sh`,
which downloads the EIF, verifies PCR0, launches the enclave, and starts
the three vsock-proxy services. Within ~90 seconds the relay is live.

### Phase 5 — Sign and publish PCR0 to the release manifest

```bash
# Include PCR0 in the next signed release manifest.
python release/sign_manifest.py \
    --version $(cat VERSION) \
    --windows-zip ... \
    --android-apk ... \
    --extra-field aws_nitro_pcr0=$PCR0 \
    --output RELEASES-$(cat VERSION).txt

# Multisig the manifest.
python release/multisig.py attest ... --extra-field aws_nitro_pcr0=$PCR0
```

Clients fetch the signed manifest, extract PCR0, and use it to verify the
relay attestation (see `deploy/aws-nitro/attestation_verifier.py`).

## Verifying the deploy from a client

```bash
python deploy/aws-nitro/attestation_verifier.py \
    https://relay.shroud.example \
    $PCR0_FROM_SIGNED_MANIFEST
# {
#   "ok": true,
#   "pcr0": "0a1b2c...",
#   "reason": null
# }
```

If `ok: false`, the client refuses to connect. Common reasons:

| Reason | Meaning |
|---|---|
| `cert chain does not link to pinned Nitro root` | Someone replaced the relay with a non-Nitro VM, or you forgot to update the root CA pin after AWS rotated it |
| `PCR0 mismatch` | Either the deployed EIF is not the one the manifest signed, or the manifest is stale |
| `nonce mismatch` | Relay replayed an old attestation document (active attack) |
| `COSE_Sign1 signature invalid` | Either the leaf cert is wrong or the document was modified in flight |

## Multi-region federation

Repeat Phase 2–4 in additional regions:

```bash
terraform workspace new eu-west-1
terraform apply -var="region=eu-west-1" -var="subnet_ids=[...]" ...

terraform workspace new ap-southeast-2
terraform apply -var="region=ap-southeast-2" -var="subnet_ids=[...]" ...
```

Each region has its own NLB, S3 bucket, KMS key, and ASG. Each region
must be added to the public relay roster (clients query a static
manifest on CloudFront that lists all current relay endpoints + their
expected PCR0).

## Rule-0 compliance — the non-AWS mirror requirement

Per the SHROUD warrant policy, the project never shuts down. AWS can
terminate any account at any time, so **at least one relay must live
outside AWS** (Hetzner, OVH, bare metal at a co-lo, or on-prem).

The non-AWS mirror doesn't get Nitro attestation — its trust model is
weaker — but it gives the network a hostile-takeover-resistant fallback.
Clients prefer attested AWS relays when reachable and fall back to the
mirror with a downgraded UI warning.

## Costs

| Component | Approx. monthly |
|---|---|
| 1 × c6i.xlarge | $123 |
| Network LB | $16 + bandwidth |
| S3 storage + requests | $1 |
| KMS key + 1000 ops/day | $1.10 |
| Per relay total | ~$150 |
| × 3 regions | ~$450 |
| × non-AWS mirror | + $10 (Hetzner CX22) |
| **Network grand total** | **~$460/mo** |

Cut by half by using `c6i.large` if voice/video signaling isn't enabled.

## Operational

### Update the relay code

1. Rebuild the EIF
2. Capture new PCR0
3. `terraform apply -var="expected_pcr0=$NEW_PCR0"` (KMS policy updates,
   clients still trusted via the *old* PCR until you publish the new
   manifest)
4. Upload new EIF and new encrypted config to S3
5. Trigger ASG refresh
6. Publish new manifest with the new PCR0
7. Clients pick up the new manifest and accept the new PCR0

### Rotate the KMS key

```bash
terraform taint aws_kms_key.config
terraform apply -var="expected_pcr0=$PCR0"
```

KMS rotates the key automatically every year by default; manual rotation
is only needed if you suspect compromise.

### Compromise response

If you suspect PCR0 has been forged (extremely unlikely — would require
breaking AWS's hardware root of trust) or your IAM credentials are
compromised:

1. Disable the IAM user's access keys immediately
2. `terraform destroy` — kills the ASG, the EIF, the encrypted config, and
   the KMS key
3. Publish an emergency manifest revoking the current PCR0 from the
   acceptance list
4. Stand up a new relay in a different region with new keys
