# Red Team Engagement Plan (template)

> Sample, **authorized-use** engagement plan showing how AI-Argus-Harness fits a
> red team / purple team exercise. Replace the bracketed fields. This is a
> planning template — it is not an authorization by itself.

## 1. Authorization (must be signed before any activity)

| Field | Value |
| --- | --- |
| Engagement name | `[ACME Q3 External + Identity Assessment]` |
| Authorizing party | `[CISO / system owner name + title]` |
| Authorization ref | `[ticket / contract #]` |
| Window (start–end) | `[2026-07-01 09:00 → 2026-07-05 18:00 TZ]` |
| In-scope assets | `[domains, CIDRs, cloud accounts, repos, clusters]` |
| Out-of-scope | `[prod payment processing, third-party SaaS, employee devices]` |
| Emergency contact | `[name / phone]` |

> ⚠️ Do not proceed without written authorization. Only targets explicitly listed
> as in-scope may be assessed.

## 2. Objectives

- Map the externally reachable attack surface and identity attack paths.
- Identify privilege-escalation and lateral-movement chains to sensitive data.
- Validate detection coverage (which steps would alert).
- Produce evidence-backed, reproducible findings with owners and remediation.

## 3. Rules of engagement

- **Posture:** start `--passive` (read-only). Escalate to `--safe` only with
  explicit per-target approval. No `--stealth` paced active testing without
  sign-off.
- **No destructive actions:** the harness does not perform credential dumping,
  persistence, lateral movement, or exfiltration; neither will the operators.
- **Data handling:** findings reference secrets/credentials by location only;
  no secret values are copied. Reports stored in `[secure location]`.

## 4. Phase plan (mapped to AI-Argus-Harness stages)

| Phase | ATT&CK tactic | Argus stage(s) | Command |
| --- | --- | --- | --- |
| Recon / attack surface | Reconnaissance (TA0043) | S1 | `argus quick acme.example` |
| Identity mapping | Discovery (TA0007) | S1.5 | `argus scan --inventory inv.json --stage S1.5` |
| Exposure & policy | Discovery / Collection | S2–S3 | `argus scan --inventory inv.json --offline` |
| Verification | — | S4 | `argus replay <finding-id>` |
| Attack-path chaining | Lateral Movement / PrivEsc (TA0008/TA0004) | S6 | (automatic; see `chains` in report) |
| Reporting & handoff | — | S7+ | `report.sarif`, `executive.md`, `tickets.json` |

## 5. Example: discover attack paths (authorized, offline inventory)

```bash
argus scan acme.example \
  --profile enterprise --safe \
  --inventory examples/inventory.json \
  --auth-scan --auth-key aws=AWS_PROFILE_REDTEAM
# Review chains (privilege escalation paths) and critical findings:
argus graph
argus explain FINDING-XXXXXXXX
```

## 6. Deliverables

- `report.sarif` — import into code-scanning / DefectDojo.
- `executive.md` — leadership summary (risk, not jargon).
- `tickets.json` — owner-routed remediation items.
- Attack-path narrative(s) from the `chains` section.

## 7. Sign-off

| Role | Name | Date |
| --- | --- | --- |
| Red team lead | | |
| System owner | | |
| Reviewer (blue team) | | |
