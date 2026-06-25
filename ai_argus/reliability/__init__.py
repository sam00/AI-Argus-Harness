"""LLM reliability layer — hallucination & false-positive reduction.

Pipeline order:
    claim_verifier -> adversarial_reviewer -> single_pass_validator
    -> completeness_gate (final promotion decision)
"""

from .completeness_gate import completeness_gate, GateResult
from .claim_verifier import verify_claims
from .adversarial_reviewer import adversarial_review
from .validator import single_pass_validate

__all__ = [
    "completeness_gate", "GateResult", "verify_claims",
    "adversarial_review", "single_pass_validate",
]
