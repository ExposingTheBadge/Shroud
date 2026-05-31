# SHROUD security policy

## Supported versions

The latest tagged release on `master` is the only version that
receives security fixes. Older releases are not supported.

See [Releases](https://github.com/ExposingTheBadge/Shroud/releases)
for the current version.

## Reporting a vulnerability

**Do not open a public GitHub issue.** Email
`security@fuseobd.com` with:

- A description of the issue
- Reproduction steps or proof-of-concept
- Your assessment of the impact severity
- Affected component (server, Windows client, Android client, etc.)
  and version

### What to expect

| Phase | Timeline |
|---|---|
| Acknowledgment | 72 hours |
| Initial triage | 7 days |
| Fix shipped (high-severity) | 14 days |
| Fix shipped (medium-severity) | 30 days |
| Public disclosure | After fix ships + 7 day grace period |

We will credit reporters in the release notes unless asked otherwise.

We do not currently run a paid bug bounty. If your finding ships
a fix, we will name you in the release notes and in our hall of
acknowledged-researchers in this file.

## Threat model

The exhaustive answer is in [`docs/security-faq.md`](docs/security-faq.md).
The TL;DR:

- We assume the relay is untrusted. The relay sees only sealed
  envelopes addressed to opaque routing tags.
- We assume the network is untrusted. All traffic is TLS, signed by
  the relay's pinned identity key.
- We assume passive global adversaries exist. We mitigate via
  padding buckets, cover traffic, optional Tor routing, and adaptive
  poll cadence.
- We do **not** assume the endpoint is trustworthy. Endpoint
  compromise is explicitly out of scope; users should run SHROUD on
  a device with full-disk encryption and pristine OS install for
  high-stakes use.
- We do **not** assume any single CA, key signer, or operator is
  honest. Multi-signer release attestation + federation are the
  structural defenses.

## Out-of-scope reports

The following reports will be closed without action:

- Self-XSS / requires user to paste attacker-supplied text into
  their own dev console
- Phishing / social engineering against SHROUD users that doesn't
  exploit a protocol or implementation bug
- Reports against the deployed AWS relay at `44.202.225.57:58443`
  that are essentially "the TLS cert is self-signed" or "the HTTP
  response headers don't have X-Frame-Options". This is a relay,
  not a website — those headers don't matter.
- Reports that depend on the attacker having the user's master
  password / vault key. That's the line above which encryption
  doesn't help, by design.

## Acknowledged researchers

(none yet — be the first)
