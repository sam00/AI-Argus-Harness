"""Deterministic risk scoring + deduplication."""

from .risk_scoring import score_finding, assign_severity
from .dedup import deduplicate

__all__ = ["score_finding", "assign_severity", "deduplicate"]
