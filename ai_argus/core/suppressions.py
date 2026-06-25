"""Suppression / risk-acceptance store.

Lets teams accept a known risk (with a reason and optional expiry) so it stops
appearing in promoted results until it expires or the underlying issue changes.
Suppressions match on the content-addressed ``finding_id`` (stable across runs),
the ``dedup_key``, or a case-insensitive substring of the title.

Stored at ``$AI_ARGUS_HOME/suppressions.json``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from ..config import config_home
from ..models import Finding


def _path():
    return config_home() / "suppressions.json"


@dataclass
class Suppression:
    match: str
    reason: str = ""
    expires: str = ""          # "YYYY-MM-DD" or "" for no expiry
    created: str = field(default_factory=lambda: time.strftime("%Y-%m-%d", time.gmtime()))

    def active(self, today: Optional[str] = None) -> bool:
        if not self.expires:
            return True
        today = today or time.strftime("%Y-%m-%d", time.gmtime())
        return today <= self.expires

    def to_dict(self) -> dict:
        return {"match": self.match, "reason": self.reason,
                "expires": self.expires, "created": self.created}


def load() -> List[Suppression]:
    p = _path()
    if not p.exists():
        return []
    try:
        return [Suppression(**d) for d in json.loads(p.read_text())]
    except Exception:
        return []


def save(rules: List[Suppression]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([r.to_dict() for r in rules], indent=2))


def add(match: str, reason: str, until: str = "") -> Suppression:
    rules = load()
    rule = Suppression(match=match, reason=reason, expires=until)
    rules = [r for r in rules if r.match != match] + [rule]
    save(rules)
    return rule


def matches(rule: Suppression, f: Finding) -> bool:
    m = rule.match
    if m == f.finding_id or m == f.dedup_key:
        return True
    return m.lower() in f.title.lower()


def apply(findings: List[Finding],
          rules: Optional[List[Suppression]] = None) -> Tuple[List[Finding], List[Finding]]:
    """Return (kept, suppressed)."""
    rules = [r for r in (rules if rules is not None else load()) if r.active()]
    if not rules:
        return list(findings), []
    kept: List[Finding] = []
    suppressed: List[Finding] = []
    for f in findings:
        hit = next((r for r in rules if matches(r, f)), None)
        if hit:
            f.review_status = "suppressed"
            f.notes.append(f"Suppressed: {hit.reason or 'accepted risk'}"
                           + (f" (expires {hit.expires})" if hit.expires else ""))
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed
