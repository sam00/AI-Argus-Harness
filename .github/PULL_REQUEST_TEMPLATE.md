<!-- Thanks for contributing to AI-Argus-Harness! -->

## Summary

<!-- What does this PR do and why? Link related issues: Closes #123 -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] New / updated scanner
- [ ] Docs / examples
- [ ] CI / tooling

## How was this tested?

<!-- Commands you ran. Prefer deterministic offline runs. -->

```bash
python -m pytest -q
argus scan ./examples/demo-target --offline --no-auth-scan \
  --path ./examples/demo-target --inventory examples/inventory.json
```

## Checklist

- [ ] Tests added/updated and `python -m pytest` passes locally.
- [ ] `CHANGELOG.md` updated under **Unreleased**.
- [ ] Determinism preserved (same inputs → same IDs/scores/severities).
- [ ] No new **required** dependency or network call; core stays offline-capable.
- [ ] Read-only / safe-by-default behavior preserved (active checks gated).
- [ ] **No secrets, credentials, or customer data** in code, tests, or fixtures.
- [ ] No references to external/private design documents in code or docs.
- [ ] Commits are signed off (`git commit -s`, DCO).

## Authorized-use attestation

- [ ] Any sample data/findings included come only from systems I own or am
      authorized to test, or from synthetic fixtures.
