"""Evidence normalizer.

Collapses duplicate/near-duplicate evidence entries on a finding and orders them
by confidence so the strongest support appears first. Deterministic — no AI.
"""

from __future__ import annotations

from typing import List

from ..models import Evidence


def normalize_evidence(evidence: List[Evidence]) -> List[Evidence]:
    seen = set()
    unique: List[Evidence] = []
    for ev in evidence:
        key = (ev.source, ev.detail.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(ev)
    unique.sort(key=lambda e: e.confidence.weight, reverse=True)
    return unique
