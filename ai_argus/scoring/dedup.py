"""Deduplication.

Collapses findings that share a dedup key composed of:
asset id + root cause(category) + identity path + remediation owner. Keeps the
highest-scoring representative and records merged finding ids.
"""

from __future__ import annotations

import hashlib
from typing import List

from ..models import Finding


def _dedup_key(f: Finding) -> str:
    path = "|".join(f"{h.principal}->{h.target}" for h in f.identity_path)
    parts = [f.asset.id, f.category, path, f.owner.team or f.owner.service]
    # When there is no identity path to disambiguate (e.g. secrets, supply-chain,
    # application findings), the title is part of the root cause so distinct
    # issue types on the same asset are not over-merged.
    if not path:
        parts.append(f.title)
    basis = "::".join(parts)
    return hashlib.sha1(basis.encode()).hexdigest()[:16]


def deduplicate(findings: List[Finding]) -> List[Finding]:
    groups: dict = {}
    for f in findings:
        f.dedup_key = _dedup_key(f)
        groups.setdefault(f.dedup_key, []).append(f)

    result: List[Finding] = []
    for key, group in groups.items():
        group.sort(key=lambda x: x.risk_score, reverse=True)
        primary = group[0]
        if len(group) > 1:
            merged = [g.finding_id for g in group[1:]]
            primary.notes.append(f"Deduplicated {len(merged)} related finding(s): "
                                 + ", ".join(merged))
        result.append(primary)
    return result
