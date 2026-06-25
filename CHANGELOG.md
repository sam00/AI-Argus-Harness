# Changelog

All notable changes to AI-Argus-Harness are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub publishing package: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, CI, CodeQL, OpenSSF Scorecard, and
  Dependabot workflows.
- Demo assets: `examples/demo-target/`, `examples/sample-report.sarif`,
  `examples/sample-finding.json`, `examples/redteam-plan.md`, and an
  architecture diagram under `docs/`.

## [0.1.0] - 2026-06-25

First public release.

### Added
- **Evidence-first pipeline** (stages S1–S10): discovery, identity, threat
  analysis, evidence/verification, reliability review, risk intelligence, and
  reporting. AI is an evidence *interpreter*, never a *creator*.
- **Authenticated vs non-authenticated scanning** with an **S0 credential
  preflight**: discovers credentials for the planned services (operator
  override → inventory census → environment variables → standard files), prompts
  for missing keys or falls back to non-authenticated. Records only references
  (env-var name / file path), never secret values. New flags: `--auth-scan`,
  `--no-auth-scan`, `--auth-key SERVICE=REF`, `--all-targets`, plus multi-target
  scans.
- **11 deterministic scanners**: `domain`, `network`, `secrets`,
  `supply_chain`, `aws`, `gcp`, `kubernetes`, `saas`, `cicd`, `data_exposure`,
  `application`.
- **Identity-as-a-graph**: first-class principals and access edges with
  privileged/blind-spot path detection.
- **Content-addressed IDs**: `finding_id` / `chain_id` derived from stable
  content, enabling diffs, suppressions, and idempotent ticket export.
- **Thread-safe, content-addressed, de-duplicating evidence store** and
  lock-guarded asset/identity graphs.
- **Deterministic additive risk scoring** with severity derived from score plus
  qualitative signals; category-intrinsic exploitability.
- **Reliability layer**: claim verifier, adversarial reviewer with N-sample
  voting + grounding (rejects invented CVEs/IPs/ARNs), single-pass validator,
  and a completeness gate.
- **Secrets false-positive reduction**: Shannon-entropy gating, anchored
  placeholder/template denylist, path/extension pruning, per-secret dedup.
- **Incremental `--diff`** baseline cache (new/fixed/unchanged) and an auditable
  **suppression store**.
- **Reporting**: JSON, SARIF 2.1.0, Markdown, executive summary, and ticket
  export.
- **Model-agnostic LLM layer** with an **offline default** (zero external
  calls), per-stage routing, and cost tracking/budgets.
- **Cost modes** (`--minimal`/`--balanced`/`--research`/`--deep-research`/
  `--offline`) and **stealth modes** (`--passive`/`--safe`/`--auth`/`--stealth`).

### Security
- Read-only by default; no destructive actions (no credential dumping,
  persistence, lateral movement, or exfiltration).
- Secret redaction in the evidence store.
- No telemetry; the core harness runs fully offline/air-gapped.

[Unreleased]: https://github.com/sam00/ai-argus-harness/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sam00/ai-argus-harness/releases/tag/v0.1.0
