# Running a federation

SHROUD's public relay is a single machine (`173.245.244.180:58443`), and
federation is off by default (`SHROUD_FEDERATION` unset). Everything below
applies only if you choose to link several independently-operated relays.
The four-region AWS federation this document used to describe has been
retired.

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

**Propagation:** a few seconds between relays; the gossip loop runs every
second and `tests/federation_e2e.py` checks it with two local relays.

## Verifying federation health

### Per-relay diagnostics

```pwsh
# Show this relay's view of the federation roster
curl -k https://<relay-ip>:58443/api/v1/federation/peers

# One entry per peer, each with a recent ts
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
       --existing-relay-url https://100.30.51.8:58443 `
       --keyfile ~/.config/shroud/operator.ed25519.json
   ```

Every relay-to-relay request (`broadcast`, `delete`, `state-event`,
`state-events/since`) is signed with the sending relay's operator key
(`operator_ed25519.json` next to the DB, or in `SHROUD_DATA_DIR`) and is
refused with 401 unless that key is pinned in the receiver's
`federation_peers`. A relay without its operator key cannot gossip.
The signed headers are `X-Shroud-Fed-Key`, `X-Shroud-Fed-Ts` and
`X-Shroud-Fed-Sig`: Ed25519 over method, path+query, timestamp and the
SHA-256 of the body, accepted within ±300 s. `state-events/since`
responses are signed the same way and discarded by the puller if they
are not signed by the peer's pinned key. Relays running older code send
unsigned requests, so upgrade the whole federation together; the hourly
state pull catches up anything dropped during the rollout.

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
5. Check `/api/v1/federation/peers` on each relay to confirm the new key is listed

There is no automated rotation — by design, rotation is a coordinated
operator action.

## Gotchas worth remembering

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

## See also

- [`anon-routing-protocol.md`](anon-routing-protocol.md) — wire format
- [`security-faq.md`](security-faq.md) — threat model
- [`aws-nitro.md`](aws-nitro.md) — Nitro enclave deployment (alternative)
- [`SESSION_NOTES.md`](../SESSION_NOTES.md) — current operator-only state
- [`tools/federation_join.py`](../tools/federation_join.py) — peer onboarding helper
