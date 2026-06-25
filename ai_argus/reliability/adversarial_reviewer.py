"""Adversarial reviewer + multi-agent disagreement tracking.

A deterministic challenger that probes each finding for weaknesses and adjusts
confidence. When an LLM provider is available it can add a second independent
opinion; disagreement between the deterministic reviewer and the model is
recorded (agent_disagreement) for the reliability dashboard.
"""

from __future__ import annotations

from typing import List, Optional

from ..llm import LLMProvider
from ..models import Category, Confidence, Finding
from .voting import vote

# High severity must show an access path only for privilege/access findings;
# pure exposure/credential findings have an implicit principal (mirrors the
# completeness gate so the reviewer does not emit noisy challenges).
_PATH_EXPECTED = {
    Category.IDENTITY.value, Category.KUBERNETES_RBAC.value,
    Category.KUBERNETES.value, Category.SAAS.value,
}
# Disagreement above this routes the finding to human review.
DISAGREEMENT_THRESHOLD = 0.34


def _downgrade(conf: Confidence) -> Confidence:
    return {Confidence.HIGH: Confidence.MEDIUM,
            Confidence.MEDIUM: Confidence.LOW,
            Confidence.LOW: Confidence.LOW}[conf]


def adversarial_review(findings: List[Finding],
                       llm: Optional[LLMProvider] = None,
                       samples: int = 3) -> List[Finding]:
    for f in findings:
        challenges: List[str] = []

        # Challenge 1: single weak evidence item.
        if len(f.evidence) == 1 and f.evidence[0].confidence == Confidence.LOW:
            challenges.append("single low-confidence evidence item")
            f.confidence = _downgrade(f.confidence)

        # Challenge 2: high-severity privilege finding without an identity path.
        if (f.severity.rank >= 3 and not f.identity_path
                and f.category in _PATH_EXPECTED):
            challenges.append("high severity lacks identity path")

        # Challenge 3: no blast radius described.
        if not f.impact.blast_radius:
            challenges.append("impact missing blast radius")

        # Independent, evidence-bound, multi-sample model opinion (when enabled).
        if llm is not None:
            verdict = vote(llm, f, n=samples)
            f.score_breakdown["agent_disagreement"] = round(verdict.disagreement, 3)
            f.notes.append(f"reviewer-vote: {verdict.verdict} "
                           f"(disagreement={verdict.disagreement:.2f}, "
                           f"grounded={verdict.grounded}, n={verdict.samples})")
            if verdict.verdict == "refuted":
                challenges.append("model review refuted the finding")
                f.confidence = _downgrade(f.confidence)
            if verdict.disagreement > DISAGREEMENT_THRESHOLD:
                challenges.append(f"high reviewer disagreement ({verdict.disagreement:.2f})")
                f.confidence = _downgrade(f.confidence)
            if not verdict.grounded:
                challenges.append("model rationale not grounded in evidence")

        if challenges:
            f.notes.append("Adversarial: " + "; ".join(challenges))
            f.score_breakdown["adversarial_challenges"] = float(len(challenges))
    return findings
