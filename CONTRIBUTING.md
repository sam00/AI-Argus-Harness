# Contributing to AI-Argus-Harness

Thanks for your interest in improving AI-Argus-Harness! This project is an
evidence-first security assessment harness, and contributions that keep it
**deterministic, safe, and zero-dependency** are especially welcome.

## Ground rules

- **Authorized use only.** Never include data, findings, or evidence obtained
  from systems you do not own or are not authorized to test.
- **No secrets in commits.** The repo runs secret scanning; never commit real
  credentials, tokens, or customer data. Use references (env-var names / file
  paths), not values.
- **Stay offline-by-default.** The core harness must run with **no hard
  third-party dependencies** and **no network calls** unless the user explicitly
  requests a scan or configures a remote LLM provider.
- **Determinism matters.** Same inputs → same `finding_id`/`chain_id`, scores,
  and severities. Don't introduce nondeterminism (wall-clock, unordered sets in
  IDs, etc.) into scoring or IDs.

## Development setup

```bash
git clone git@github.com:sam00/AI-Argus-Harness.git
cd AI-Argus-Harness

# editable install with dev + optional extras
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[yaml,dev]"
```

## Running tests

```bash
python -m pytest            # full suite
python -m pytest -q         # quiet
```

Run a smoke check of the CLI:

```bash
argus doctor
argus scan ./examples/demo-target --offline --no-auth-scan \
    --path ./examples/demo-target --inventory examples/inventory.json
```

## Coding standards

- Python **3.9+**, standard library first. New runtime dependencies require
  discussion and must be optional extras where possible.
- Type hints on public functions; keep modules focused.
- Match the existing docstring style. **Do not** reference external/private
  design documents — describe behavior in-place.
- Keep changes minimal and well-scoped; prefer the smallest correct fix.

## Adding a scanner

Scanners are plugins. See [`docs/scanner-plugin-spec.md`](docs/scanner-plugin-spec.md).
A scanner must:

1. Produce **source-bound evidence** for every claim (no evidence → no finding).
2. Emit complete findings (`asset + evidence + identity_path + impact +
   confidence + remediation + owner`) — the completeness gate enforces this.
3. Be **read-only** unless gated behind `--safe`/`--auth`.
4. Use the shared `Category` enum and the deterministic ID helpers.

External scanners can ship as separate packages exposing the
`ai_argus.scanners` entry-point group.

## Pull request process

1. Fork and create a feature branch (`feat/...`, `fix/...`, `docs/...`).
2. Add or update tests; keep the suite green (`python -m pytest`).
3. Update `CHANGELOG.md` under "Unreleased".
4. Open a PR using the template; link any related issue.
5. CI (tests, CodeQL, OpenSSF Scorecard) must pass before review.

### Sign-off (DCO)

Sign your commits to certify you wrote the code and can submit it under the
project license:

```bash
git commit -s -m "fix: ..."
```

This adds a `Signed-off-by:` line ([Developer Certificate of Origin](https://developercertificate.org/)).

## Reporting bugs / requesting features

Use the issue templates under **Issues → New issue**. For **security**
vulnerabilities, do **not** open a public issue — follow
[`SECURITY.md`](SECURITY.md).

## Code of Conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
