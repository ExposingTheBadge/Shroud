# Multi-party release signing

GHOSTLINK ships with `release/sign_manifest.py`, which produces a single
hybrid signature (Ed25519 + ML-DSA-87 + SPHINCS+-256s) over each release.
That binds a release to one server identity key.

The threat model gap that solves: forgery without source access. The gap it
*doesn't* solve: compromise of that one key. If the box holding the
identity is owned, the attacker can sign anything.

`release/multisig.py` closes the second gap. Each release additionally
requires **M-of-N independent signers** to attest the artefact hashes
before the public is asked to trust them. Compromise of any subset smaller
than M cannot forge.

We deliberately use *separate-key threshold* (count valid sigs against a
roster) instead of *cryptographic threshold* (FROST, MuSig2). The
operational story is much simpler — every signer is a regular Ed25519
keypair, signing is offline, no DKG ceremony — at the cost of slightly
larger bundles (a few hundred bytes per signer).

## Files

```
release/multisig.py            # signer + roster operations
release/multisig_verify.py     # public verifier (no secrets needed)
release/signers/<name>.pub     # public keys, checked in
release/signers/<name>.key     # private keys, NEVER checked in
release/roster.json            # active {threshold, signers[]}
```

`release/signers/*.key` MUST be in `.gitignore` and held only on each
signer's own machine. `release/signers/*.pub` is checked in; that's how
the public learns the roster.

## Day-1 setup

  1. Each signer runs, on their own machine:
     ```
     python release/multisig.py keygen --name alice
     ```
     This writes `release/signers/alice.key` (private, chmod 600) and
     `release/signers/alice.pub` (public). Commit only the `.pub`.

  2. The release captain emits the active roster:
     ```
     python release/multisig.py roster --threshold 2
     ```
     `--threshold` is M. With N=3 signers, M=2 is the canonical choice
     ("any two of us can ship; any one of us being kidnapped doesn't lose
     the project"). With N=5, M=3.

  3. Commit `release/signers/*.pub` and `release/roster.json` to git. The
     first commit of `roster.json` is the genesis — there's no previous
     roster signing it, so it's trust-on-first-use. Subsequent roster
     changes MUST be attested by the previous roster (see "Rotating
     signers" below).

## Per-release flow

  1. Release captain builds artefacts as usual (e.g.
     `releases/v2.3.0/GHOSTLINK-v2.3.0-win64.zip`).

  2. Each signer, on their own machine, runs:
     ```
     python release/multisig.py attest \
         --signer alice \
         --version 2.3.0 \
         --git-commit $(git rev-parse HEAD) \
         --windows-zip releases/v2.3.0/GHOSTLINK-v2.3.0-win64.zip \
         --output /tmp/attest-alice.json
     ```
     Each `attest-*.json` is independent — signers don't need to coordinate
     online. Pass the file back to the captain over any channel (email,
     signal, paste into a PR).

  3. Captain combines them:
     ```
     python release/multisig.py gather \
         --attestations attest-alice.json attest-bob.json \
         --output releases/v2.3.0/RELEASES-2.3.0.multisig.json
     ```
     `gather` refuses to combine attestations over different manifests, so
     a signer accidentally signing the wrong version won't slip through.

  4. Ship `RELEASES-2.3.0.multisig.json` alongside the artefacts. Verifiers
     don't need anything else.

## Verifying

```
python release/multisig_verify.py \
    --bundle RELEASES-2.3.0.multisig.json \
    --windows-zip GHOSTLINK-v2.3.0-win64.zip
```

The verifier exits 0 only when:

  - every signature is over the *same* canonicalised manifest,
  - every signing pubkey is in the bundled roster,
  - the number of valid signatures meets or exceeds `roster.threshold`,
  - (if `--windows-zip` / `--android-apk` / `--windows-exe` were provided)
    the SHA-256 in the manifest matches the local file.

## Rotating signers

Adding, removing, or re-keying a signer changes `roster.json`. The new
roster file MUST be checked in *and* attested by the previous roster's
threshold. The mechanism is identical to a release attestation, but the
"manifest" is just `{"product":"GHOSTLINK","roster":<new-roster-json>}`.
That gives a cryptographic chain from genesis: forging the roster requires
forging M sigs at *every* historical roster transition, not just the
current one.

## Trust model summary

| Threat                                       | Single-sig | Multi-sig (M of N) |
|----------------------------------------------|------------|--------------------|
| Source-only attacker (no key)                | safe       | safe               |
| Server identity key stolen                   | broken     | safe (need ≥ M)    |
| One signer's machine owned                   | broken     | safe (need ≥ M)    |
| (M-1) signers compromised at once            | broken     | safe               |
| M signers compromised at once                | broken     | broken             |
| Loss of (N-M) signer keys (key destroyed)    | broken     | safe (still ≥ M)   |
| Lose the box holding sign_manifest's key     | broken     | safe (still ≥ M)   |

The single-sig (`sign_manifest.py`) path stays useful — it covers the
"this is the GHOSTLINK server identity" claim — and the multi-sig
(`multisig.py`) path covers the "humans agree this is a real release"
claim. Both ride along in the v2.3.0+ release directory.
