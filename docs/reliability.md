# Reliability Layer (hallucination & false-positive reduction)

The reliability layer is what makes AI-Argus-Harness trustworthy. AI never
creates findings; it only reasons over evidence produced by deterministic
scanners.

## Pipeline

```
verify_claims → adversarial_review → single_pass_validate → completeness_gate
```

| Step | Module | Rule enforced |
| --- | --- | --- |
| Claim Verifier | `reliability/claim_verifier.py` | No source-bound evidence → no finding |
| Adversarial Reviewer | `reliability/adversarial_reviewer.py` | Challenge weak/unsupported claims; track disagreement |
| Single-Pass Validator | `reliability/validator.py` | Structural/shape validation |
| Completeness Gate | `reliability/completeness_gate.py` | Promotion decision |

## Reliability rules

- No evidence, no finding.
- No asset, no finding.
- No identity path, no high severity.
- No impact, no severity.
- No owner, no enterprise-report promotion.
- No remediation, no ticket.
- Confidence below threshold (in `--strict`) → human review or drop.

## Outcomes

Each finding ends in one of three states:

- **passed** — complete and promoted to enterprise reporting.
- **needs-human-review** — incomplete; routed to the human review queue.
- **dropped** — unsupported (no evidence) or strict-mode low-confidence + incomplete.

The `argus replay <id>` command re-runs verification against current evidence to
determine whether a finding still holds.
