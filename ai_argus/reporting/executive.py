"""Executive summary + owner-based ticket export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..models import Finding, Severity


def build_executive(result) -> str:
    s = result.summary()
    crit = s["by_severity"].get("critical", 0)
    high = s["by_severity"].get("high", 0)
    top = sorted(result.findings, key=lambda f: -f.risk_score)[:5]

    lines = [
        "# Executive Security Summary — AI-Argus-Harness",
        "",
        f"**Target:** {result.target}    **Date:** {result.finished}",
        "",
        "## Risk Posture",
        "",
        f"- **{crit}** critical and **{high}** high-severity issues require attention.",
        f"- **{s['chains']}** multi-step attack paths were identified.",
        f"- **{s['review_queue']}** findings were routed to human review for verification.",
        "",
        "## Top Risks",
        "",
    ]
    for f in top:
        lines.append(f"1. **{f.title}** ({f.severity.value}, score {f.risk_score}) — "
                     f"{f.impact.business or f.impact.technical}")
    lines += [
        "",
        "## Recommended Focus",
        "",
        "- Remediate internet-exposed, privileged, and sensitive-data findings first.",
        "- Close detection blind spots on critical assets.",
        "- Enforce least privilege across identities and service accounts.",
        "",
        "_All findings are evidence-backed; see the full report and evidence appendix._",
    ]
    return "\n".join(lines)


def write_executive(result, path: Path) -> Path:
    path = Path(path)
    path.write_text(build_executive(result))
    return path


def build_tickets(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Owner-based ticket export (Jira / ServiceNow friendly)."""
    tickets: List[Dict[str, Any]] = []
    for f in findings:
        if f.severity.rank < Severity.MEDIUM.rank:
            continue
        tickets.append({
            "summary": f"[{f.severity.value.upper()}] {f.title}",
            "assignee_team": f.owner.team or "Security",
            "service": f.owner.service,
            "priority": f.remediation.priority.value,
            "finding_id": f.finding_id,
            "description": (f.impact.business or f.impact.technical),
            "remediation": f.remediation.summary,
            "steps": f.remediation.steps,
            "evidence_refs": [e.raw_ref for e in f.evidence if e.raw_ref],
            "labels": ["ai-argus", f.category, f.severity.value],
        })
    return tickets


def write_tickets(findings: List[Finding], path: Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(build_tickets(findings), indent=2))
    return path
