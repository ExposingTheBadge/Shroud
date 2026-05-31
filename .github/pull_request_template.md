## Summary

What does this PR change, and why?

## Rule check

The four inviolable rules ([CONTRIBUTING.md](../CONTRIBUTING.md)):

- [ ] Rule 0: doesn't introduce a single point of compulsion
- [ ] Rule 1: doesn't add any sender-identifying field visible to the relay
- [ ] Rule 2: doesn't add any receiver-identifying field visible to the relay
- [ ] Rule 3: doesn't add identifying metadata to transmitted content

If any box can't be checked, this PR will be closed.

## Tests

- [ ] `python -m tests.run_all` passes locally
- [ ] `python -m tests.e2e_anon_protocol` passes against the live relay
- [ ] Per-platform self-tests pass (if I touched a client port)

## Touched modules

List the `crypto/`, `server/`, `clients/*` modules this PR modifies,
plus a one-line summary of the change in each.

## Wire-format compatibility

- [ ] No wire-format change
- [ ] Wire-format change documented in `docs/anon-routing-protocol.md`
- [ ] Wire-format change has matching updates in Python / C / Kotlin / Swift / JS ports

## Reviewer's checklist

For crypto-touching PRs, the reviewer should verify:

- The threat model + math behind any change
- That the change interoperates byte-for-byte across all language ports
- That tamper-detection still works in the modified path
- That the change cannot be downgraded into a Rule-violating form via
  a compromised client
