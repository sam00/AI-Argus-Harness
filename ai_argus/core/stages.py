"""Enterprise stage model (S1 .. S10).

Defines the canonical pipeline stages. The orchestrator executes
them in order; each stage maps to a phase of the evidence-first flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Stage:
    code: str
    name: str
    description: str


STAGES: List[Stage] = [
    Stage("S1", "Attack-Surface Mapper", "Discover assets and build the asset graph."),
    Stage("S1.5", "Identity & Access Graph Builder", "Build first-class identity graph."),
    Stage("S2", "Threat Modeler", "Identify likely threats against discovered assets."),
    Stage("S3", "Vulnerability Research Strategist", "Plan research lenses per asset."),
    Stage("S4", "Research Lenses", "Run scanner stages to collect evidence."),
    Stage("S5", "Evidence Collector", "Normalize evidence from all sources."),
    Stage("S5.5", "Controlled Offensive Verification", "Safe, non-destructive validation."),
    Stage("S6", "Adversarial Reviewer", "Challenge findings; multi-agent disagreement."),
    Stage("S6.5", "Single-Pass Validator", "Structural validation of findings."),
    Stage("S7", "Deduplication", "Collapse related findings."),
    Stage("S8", "Chain Construction", "Build attack-path chains."),
    Stage("S8.5", "Detection & Control Coverage Review", "Assess detection blind spots."),
    Stage("S9", "Report Generator", "Score, prioritize, and emit reports."),
    Stage("S10", "Human Review / Exception Workflow", "Route uncertain findings to humans."),
]

STAGE_CODES = [s.code for s in STAGES]


def stages_until(code: str) -> List[Stage]:
    out: List[Stage] = []
    for s in STAGES:
        out.append(s)
        if s.code == code:
            break
    return out


def stages_subset(codes: List[str]) -> List[Stage]:
    wanted = set(codes)
    return [s for s in STAGES if s.code in wanted]
