---
name: Feature request
about: Suggest a new feature
title: '[feature] '
labels: enhancement
assignees: ''
---

### What problem does this solve?
Describe the user-facing problem this would solve.

### Proposed solution
What would you build, and how would it interact with the existing
protocol modules in [`docs/protocol-modules.md`](../../docs/protocol-modules.md)?

### Rule check
Confirm the proposed feature complies with each rule:

- [ ] Rule 0: doesn't introduce a single point of compulsion that
      could force a shutdown
- [ ] Rule 1: doesn't add any sender-identifying field visible to
      the relay
- [ ] Rule 2: doesn't add any receiver-identifying field visible to
      the relay
- [ ] Rule 3: doesn't add identifying metadata to transmitted content

If any box can't be checked, redesign the feature before opening this
issue.

### Alternatives considered
What did you reject and why?

### Additional context
