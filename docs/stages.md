# Stage Model

The harness runs an explicit, ordered stage pipeline. Stages can be limited with
`--stage S1,S2,S4` or `--until S6`.

| Code | Stage | What it does |
| --- | --- | --- |
| S1 | Attack-Surface Mapper | Discover assets, build the asset graph |
| S1.5 | Identity & Access Graph Builder | Build the first-class identity graph |
| S2 | Threat Modeler | Identify likely threats per asset |
| S3 | Vulnerability Research Strategist | Plan research lenses |
| S4 | Research Lenses | Run scanners to collect evidence |
| S5 | Evidence Collector | Normalize evidence from all sources |
| S5.5 | Controlled Offensive Verification | Passive/safe, non-destructive validation |
| S6 | Adversarial Reviewer | Challenge findings; multi-agent disagreement |
| S6.5 | Single-Pass Validator | Structural validation |
| S7 | Deduplication | Collapse related findings |
| S8 | Chain Construction | Build attack-path chains |
| S8.5 | Detection & Control Coverage Review | Assess detection blind spots |
| S9 | Report Generator | Score, prioritize, emit reports |
| S10 | Human Review / Exception Workflow | Route uncertain findings to humans |

## Execution flow

The orchestrator collects evidence (S1–S5) in parallel across scanners, then runs
the verification and risk-intelligence stages sequentially because each depends on
the previous stage's output (e.g. chains depend on scored, deduplicated findings).
