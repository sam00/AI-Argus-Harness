"""Single-pass validator — schema-style structural validation.

Validates each finding against the required structure without external libs.
Returns the findings annotated with any structural problems. This is distinct
from the completeness gate: the validator checks *shape/typing*, the gate makes
the *promotion decision*.
"""

from __future__ import annotations

from typing import List

from ..models import Confidence, Finding, Severity


def single_pass_validate(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        problems: List[str] = []
        if not isinstance(f.severity, Severity):
            problems.append("severity not enum")
        if not isinstance(f.confidence, Confidence):
            problems.append("confidence not enum")
        if not f.title.strip():
            problems.append("empty title")
        for hop in f.identity_path:
            if not (hop.principal and hop.target):
                problems.append("identity hop missing principal/target")
                break
        if problems:
            f.notes.append("Validator: " + "; ".join(problems))
    return findings
