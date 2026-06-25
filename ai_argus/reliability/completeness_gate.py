"""Finding completeness gate.

Enforces the core enterprise rule:

    asset + evidence + identity_path + impact + confidence + remediation + owner

plus severity-specific reliability rules. A finding that fails the
gate is NOT promoted to enterprise reporting — instead it is routed to human
review (or dropped in strict mode if below the confidence threshold).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..models import Category, Confidence, Finding, Severity


@dataclass
class GateResult:
    passed: List[Finding] = field(default_factory=list)
    review: List[Finding] = field(default_factory=list)
    dropped: List[Finding] = field(default_factory=list)
    reasons: dict = field(default_factory=dict)


_CONF_ORDER = {"low": 0, "medium": 1, "high": 2}

# An identity path is the *evidence* for privilege/access findings, so it is
# required at high+ severity for those categories. Pure exposure/credential
# findings (secrets, supply-chain, exposed datastore/port, etc.) have an
# implicit principal (anonymous internet / credential holder) and are exempt,
# preventing legitimate high findings from being needlessly routed to review.
_IDENTITY_PATH_REQUIRED = {
    Category.IDENTITY.value, Category.KUBERNETES_RBAC.value,
    Category.KUBERNETES.value, Category.SAAS.value,
}


def _missing_required(f: Finding) -> List[str]:
    missing: List[str] = []
    if not f.asset or not f.asset.id:
        missing.append("asset")
    if not f.evidence:
        missing.append("evidence")
    if not (f.impact.business or f.impact.technical):
        missing.append("impact")
    if not (f.remediation.summary or f.remediation.steps):
        missing.append("remediation")
    if not (f.owner.team or f.owner.service or f.owner.contact):
        missing.append("owner")
    # severity-specific rule: privilege findings must show the access path.
    if (f.severity.rank >= Severity.HIGH.rank and not f.identity_path
            and f.category in _IDENTITY_PATH_REQUIRED):
        missing.append("identity_path (required for high+ privilege findings)")
    return missing


def completeness_gate(findings: List[Finding], *, strict: bool,
                      confidence_threshold: str = "medium") -> GateResult:
    result = GateResult()
    threshold = _CONF_ORDER.get(confidence_threshold, 1)

    for f in findings:
        missing = _missing_required(f)
        below_conf = _CONF_ORDER.get(f.confidence.value, 0) < threshold

        if not missing and not (strict and below_conf):
            result.passed.append(f)
            continue

        reasons = list(missing)
        if strict and below_conf:
            reasons.append(f"confidence<{confidence_threshold}")

        result.reasons[f.finding_id] = reasons

        # In strict mode, critical incompleteness with low confidence is dropped.
        if strict and below_conf and missing:
            f.review_status = "dropped"
            result.dropped.append(f)
        else:
            f.review_status = "needs-human-review"
            f.notes.append("Gate: missing " + ", ".join(reasons))
            result.review.append(f)

    return result
