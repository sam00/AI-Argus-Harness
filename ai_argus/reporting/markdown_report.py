"""Markdown report generator (engineer-facing detail)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..models import Finding, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_BADGE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
          "low": "LOW", "info": "INFO"}


def _finding_block(f: Finding) -> str:
    lines = [
        f"### [{f.severity.value.upper()}] {f.title}",
        "",
        f"- **Finding ID:** `{f.finding_id}`",
        f"- **Asset:** `{f.asset.name}` ({f.asset.type.value}, {f.asset.environment.value})",
        f"- **Category:** {f.category}  |  **Scanner:** {f.scanner}  |  **Stage:** {f.stage}",
        f"- **Risk score:** {f.risk_score}  |  **Confidence:** {f.confidence.value}",
        f"- **Owner:** {f.owner.team or 'unassigned'} ({f.owner.service})",
        f"- **Review status:** {f.review_status}",
        "",
        "**Evidence**",
    ]
    for e in f.evidence:
        lines.append(f"- _{e.source}_ ({e.confidence.value}): {e.detail}")
    if f.identity_path:
        lines += ["", "**Identity path**", ""]
        path = " -> ".join(f"{h.principal} =={h.relationship.value}==> {h.target}"
                           for h in f.identity_path)
        lines.append(f"`{path}`")
    lines += [
        "",
        "**Impact**",
        f"- Business: {f.impact.business or 'n/a'}",
        f"- Technical: {f.impact.technical or 'n/a'}",
        f"- Blast radius: {f.impact.blast_radius or 'n/a'}",
        "",
        "**Remediation**",
        f"- {f.remediation.summary}",
    ]
    for s in f.remediation.steps:
        lines.append(f"  - {s}")
    if f.chain_ids:
        lines += ["", f"**Attack chains:** {', '.join(f.chain_ids)}"]
    lines.append("")
    return "\n".join(lines)


def build_markdown(result) -> str:
    s = result.summary()
    out: List[str] = [
        "# AI-Argus-Harness Report",
        "",
        f"- **Run ID:** `{result.run_id}`",
        f"- **Target:** `{result.target}`",
        f"- **Profile:** {result.profile}  |  **Cost mode:** {result.cost_mode}  "
        f"|  **Stealth:** {result.stealth_mode}",
        f"- **Started:** {result.started}  |  **Finished:** {result.finished}",
        "",
        "## Summary",
        "",
        f"- Total findings: **{s['total_findings']}**",
        f"- Review queue: **{s['review_queue']}**",
        f"- Attack chains: **{s['chains']}**",
        f"- Assets discovered: **{s['assets']}**  |  Identities: **{s['identities']}**",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in _SEV_ORDER:
        out.append(f"| {sev.value} | {s['by_severity'].get(sev.value, 0)} |")
    out.append("")

    if result.chains:
        out += ["## Attack Path Chains", ""]
        for c in result.chains[:10]:
            out += [f"### {c.title} [{c.severity.value}] (score {c.score})",
                    "", f"- Narrative: {c.narrative}",
                    f"- Findings: {', '.join(c.finding_ids)}", ""]

    out += ["## Findings", ""]
    findings = sorted(result.findings,
                      key=lambda f: (-f.severity.rank, -f.risk_score))
    for f in findings:
        out.append(_finding_block(f))

    if result.review_queue:
        out += ["## Human Review Queue", ""]
        for f in result.review_queue:
            out.append(f"- `{f.finding_id}` {f.title} — {', '.join(f.notes[-1:])}")
        out.append("")

    return "\n".join(out)


def write_markdown(result, path: Path) -> Path:
    path = Path(path)
    path.write_text(build_markdown(result))
    return path
