"""Claim verifier — source-bound reasoning.

Ensures every finding is backed by at least one concrete evidence record whose
detail is non-empty and source-attributed. Drops "claims" that have no source
(implements: *No evidence, no finding* / *No source, no finding*).
"""

from __future__ import annotations

from typing import List, Tuple

from ..models import Finding

VALID_SOURCES = {"scanner", "log", "config", "code", "cloud-api", "endpoint-agent"}


def verify_claims(findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
    """Return (verified, rejected)."""
    verified: List[Finding] = []
    rejected: List[Finding] = []
    for f in findings:
        good = [e for e in f.evidence
                if e.detail.strip() and e.source in VALID_SOURCES]
        if good:
            f.evidence = good
            verified.append(f)
        else:
            f.notes.append("ClaimVerifier: no source-bound evidence")
            f.review_status = "dropped"
            rejected.append(f)
    return verified, rejected
