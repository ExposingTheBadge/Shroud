# Live federation deployment

This document describes the running 4-region production federation, the
operational procedures for managing it, and the gotchas worth remembering.

It's the operator runbook. The protocol spec lives in
[`anon-routing-protocol.md`](anon-routing-protocol.md).

---

## Roster (production)

| Region | Public IP | Operator | Endpoint |
|---|---|---|---|
| us-east-1 (Virginia) | `44.202.225.57` | Brent Gordon | `https://44.202.225.57:58443` |
| us-east-2 (Ohio) | `3.142.185.104` | Brent Gordon | `https://3.142.185.104:58443` |
| us-west-2 (Oregon) | `54.214.75.14` | Brent Gordon | `https://54.214.75.14:58443` |
| eu-west-1 (Ireland) | `54.171.165.223` | Brent Gordon | `https://54.171.165.223:58443` |

All four:

- Run identical SHROUD master from `/opt/shroud/src`
- t3.micro (1 vCPU, 1 GiB RAM) — free tier eligible for first 12 months
- Self-signed TLS at port 58443
- `SHROUD_FEDERATION=1` enabled via systemd drop-in
- Have **all other relays' operator pubkeys** in their local `federation_peers`
  table (operator-vetted; not auto-trusted)

Operator Ed25519 pubkeys and instance metadata are checked into `SESSION_NOTES.md`
(operator-only; they're public information by design — vetting is the operator's
private decision, not the pubkey's secrecy).

## Gossip behavior

When a relay accepts a sealed envelope on `/api/v1/messages/send-anon`:

1. The envelope is persisted locally with its routing tag
2. The envelope is enqueued in `FEDERATION_OUTBOX` for broadcast to all
   active peers
3. The background `_federation_loop` drains the outbox, POSTing each item
   to `/api/v1/federation/broadcast` on every peer
4. Peers dedupe via `federation_seen_ids` (envelope ID is content-derived)
   and insert if novel

When a relay delivers a message (drops it from `anon_messages` on
`fetch-anon`), the same loop POSTs `/api/v1/federation/delete` to all
peers so they too clear the row. This preserves Rule 2 (delete on delivery)
across the entire federation, not just the home relay.

**Measured propagation:** ~3 seconds round-trip, all 4 regions, verified by
`tests/federation_live.py`. Geographic latency dominates; the gossip loop
itself runs every second.

## Verifying federation health

### From any operator workstation

```pwsh
python -m tests.federation_live
```

This:

1. Health-checks all 4 relays
2. Posts a sealed envelope to us-east-1
3. Polls the same routing tag at the other 3 relays for up to 30s
4. PASSes iff all three peers serve back the envelope and successfully unseal

Expected: `PASS  gossip reached all 3 peers` with each peer under ~5s.

### Per-relay diagnostics

```pwsh
# Show this relay's view of the federation roster
curl -k https://<relay-ip>:58443/api/v1/federation/peers

# Should return ~3 entries, all with active=true and recent ts
```

## Operator-vetted peer onboarding

Peers are not auto-trusted. Adding a new operator's relay to the federation
is a two-step manual ceremony:

1. **Operator generates an Ed25519 long-term keypair** on their new relay:
   ```bash
   sudo /opt/shroud/venv/bin/python -m crypto.operator_manifest --keygen \
       --out /opt/shroud/data/operator_ed25519.json
   sudo chmod 600 /opt/shroud/data/operator_ed25519.json
   ```
2. **Existing operators each individually approve the new pubkey** by
   inserting into their `federation_peers` table:
   ```bash
   sudo sqlite3 /opt/shroud/data/shroud.db <<EOF
   INSERT INTO federation_peers
     (pubkey_hex, operator, endpoint, ttl_seconds, ts, active)
   VALUES
     ('<new-operator-pubkey-hex>',
      '<operator-label>',
      'https://<new-relay-ip>:58443',
      86400,
      strftime('%s', 'now'),
      1);
   EOF
   sudo systemctl restart shroud-relay.service
   ```
3. **Exchange signed PeerAnnouncements** by running:
   ```pwsh
   python -m tools.federation_join `
       --my-endpoint https://<new-relay>:58443 `
       --existing-relay-url https://44.202.225.57:58443 `
       --keyfile ~/.config/shroud/operator.ed25519.json
   ```

Until step 2 is complete on the existing relays, the new peer's
`POST /federation/announce` returns 403. This is **intentional** — it
prevents a hostile new operator from quietly attaching to the federation
without each existing operator's individual sign-off.

## Pubkey rotation

Operator Ed25519 keys are long-term and rotation should be rare. If an
operator must rotate:

1. Generate a new keypair (`--keygen`), keep the old keypair available
2. Sign a fresh PeerAnnouncement with the **new** key
3. Each peer operator manually replaces the row for that operator in their
   `federation_peers` table (UPDATE, not INSERT — keep the row's other
   metadata)
4. After all peers have updated, securely delete the old private key
5. Run `python -m tests.federation_live` to confirm gossip still flows

There is no automated rotation — by design, rotation is a coordinated
operator action.

## Gotchas worth remembering

### us-east-2 default subnet missing IGW route

When spinning up a new t3.micro in us-east-2 (Ohio) using the default VPC,
the subnet's custom route table may be missing the `0.0.0.0/0 → IGW` route.
Symptom: instance accepts SSH key on creation but every connection times
out; cloud-init hangs.

**Fix:**
```pwsh
aws ec2 create-route --region us-east-2 `
    --route-table-id rtb-0369c2dbabadba03b `
    --destination-cidr-block 0.0.0.0/0 `
    --gateway-id igw-09a8298a9fbc7e535
```

Adjust `--route-table-id` and `--gateway-id` for the actual VPC. List
them with:
```pwsh
aws ec2 describe-route-tables --region us-east-2 --filters Name=vpc-id,Values=<vpc-id>
aws ec2 describe-internet-gateways --region us-east-2 --filters Name=attachment.vpc-id,Values=<vpc-id>
```

### Multi-instance testing collides on shroud.db

If you boot multiple SHROUD relays on the same host (or share a database
file), they'll fight over `anon_messages`. `tests/federation_e2e.py` works
around this by setting `SHROUD_DB_PATH=<workdir>/shroud.db` per instance.
The same env var works in production; default is `/opt/shroud/src/server/shroud.db`.

### `operator_ed25519.json` permissions

The operator key must be `chmod 600`. If you `sudo systemctl restart`
the relay but the key file is owned by `root:root`, the relay
(`User=ec2-user` in the service unit) can't read it and federation
broadcasts will silently no-op.

**Check:**
```bash
sudo -u ec2-user /opt/shroud/venv/bin/python -c "import json; print(json.load(open('/opt/shroud/data/operator_ed25519.json'))['pub_hex'][:16] + '...')"
```

If this fails with PermissionError, fix:
```bash
sudo chown ec2-user:ec2-user /opt/shroud/data/operator_ed25519.json
sudo chmod 600 /opt/shroud/data/operator_ed25519.json
```

## Tearing down a relay

```pwsh
# Identify the instance, then:
aws ec2 terminate-instances --region <region> --instance-ids <i-...>
```

Other relays will continue to gossip among themselves. Their
`federation_peers` rows for the terminated relay will eventually be
purged when the TTL expires (default 24h) — or operators can remove
the row manually:

```bash
sudo sqlite3 /opt/shroud/data/shroud.db \
    "DELETE FROM federation_peers WHERE pubkey_hex='<terminated-relay-pub>';"
sudo systemctl restart shroud-relay.service
```

## See also

- [`anon-routing-protocol.md`](anon-routing-protocol.md) — wire format
- [`security-faq.md`](security-faq.md) — threat model
- [`aws-nitro.md`](aws-nitro.md) — Nitro enclave deployment (alternative)
- [`SESSION_NOTES.md`](../SESSION_NOTES.md) — current operator-only state
- [`tests/federation_live.py`](../tests/federation_live.py) — health smoke test
- [`tools/federation_join.py`](../tools/federation_join.py) — peer onboarding helper
