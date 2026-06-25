# Architecture

AI-Argus-Harness is organized as an evidence-first pipeline. Deterministic
scanners emit structured evidence; the reliability layer validates and gates it;
scoring and chaining add risk intelligence; reporting makes it actionable.

```
AI-Argus-Harness
├── Discovery        (attack surface, cloud, network, endpoint, k8s, app, saas, supply chain)
├── Identity         (users, roles, service accounts, oauth apps, ci identities, externals)
├── Verification     (evidence collection, claim verification, controlled offensive, review)
├── Risk Intelligence(deduplication, chain construction, detection coverage, scoring)
└── Reporting        (SARIF, JSON, Markdown, executive, evidence appendix, ticket export)
```

## Components

| Component | Module | Responsibility |
| --- | --- | --- |
| Stage Orchestrator | `core/orchestrator.py` | Runs S1..S10 over a target, coordinates everything |
| Plugin Loader | `core/plugin_loader.py` | Registers built-in + entry-point scanners |
| Run Context | `core/context.py` | Shared state: graphs, evidence, findings, LLM |
| Asset Graph | `graph/asset_graph.py` | Directed graph of assets + relationships |
| Identity Graph | `graph/identity_graph.py` | First-class principals + access edges, path search |
| Evidence Store | `evidence/store.py` | Append-only, redacted, replayable evidence |
| Reliability Layer | `reliability/*` | Claim verifier, adversarial reviewer, validator, gate |
| Scoring | `scoring/risk_scoring.py` | Deterministic additive risk model + severity rules |
| Deduplication | `scoring/dedup.py` | Collapse by asset/root-cause/identity/owner |
| Chaining | `chaining/chain_constructor.py` | Link findings into attack paths |
| Reporting | `reporting/*` | JSON, SARIF, Markdown, executive, tickets |
| LLM Providers | `llm/provider.py` | Model-agnostic, offline default, cost tracking |

## Data flow

1. Orchestrator selects scanners (by profile or explicit subset) and stages.
2. Scanners run (parallelized by `--workers`), populating the asset/identity
   graphs and the evidence store, and emitting **candidate** findings.
3. Evidence is normalized; claims are verified (source-bound).
4. Adversarial review challenges findings; the single-pass validator checks shape.
5. Findings are scored deterministically and deduplicated.
6. Attack-path chains are constructed; findings are re-scored to reflect chainability.
7. The completeness gate promotes complete findings and routes the rest to human review.
8. Reports are emitted in all configured formats.

## Determinism

Given the same inputs and `--offline`/`--minimal` cost mode, a run produces the
same findings, scores, and severities. This is what makes results replayable and
audit-ready.
