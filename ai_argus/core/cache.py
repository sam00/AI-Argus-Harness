"""Baseline cache + incremental diff.

Persists the set of content-addressed finding ids from the last run of a given
target so a later ``--diff`` run can report what is NEW, FIXED, or UNCHANGED.
Because finding ids are content-addressed (stable across runs), the diff is
meaningful without re-running unchanged work.

Baselines live under ``$AI_ARGUS_HOME/baselines/<target-signature>.json``.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from ..config import config_home


def _baseline_dir() -> Path:
    d = config_home() / "baselines"
    d.mkdir(parents=True, exist_ok=True)
    return d


def target_signature(raw_target: str, profile: str = "") -> str:
    return hashlib.sha1(f"{raw_target}|{profile}".encode()).hexdigest()[:16]


def _baseline_path(sig: str) -> Path:
    return _baseline_dir() / f"{sig}.json"


@dataclass
class Diff:
    added: List[str] = field(default_factory=list)
    fixed: List[str] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)
    had_baseline: bool = False

    def to_dict(self) -> Dict:
        return {
            "had_baseline": self.had_baseline,
            "added": self.added,
            "fixed": self.fixed,
            "unchanged": self.unchanged,
            "counts": {"added": len(self.added), "fixed": len(self.fixed),
                       "unchanged": len(self.unchanged)},
        }


def load_baseline(sig: str) -> List[str]:
    p = _baseline_path(sig)
    if not p.exists():
        return []
    try:
        return list(json.loads(p.read_text()).get("finding_ids", []))
    except Exception:
        return []


def save_baseline(sig: str, finding_ids: List[str], summary: Dict) -> None:
    _baseline_path(sig).write_text(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finding_ids": sorted(set(finding_ids)),
        "summary": summary,
    }, indent=2))


def compute_diff(current_ids: List[str], baseline_ids: List[str]) -> Diff:
    cur, base = set(current_ids), set(baseline_ids)
    return Diff(
        added=sorted(cur - base),
        fixed=sorted(base - cur),
        unchanged=sorted(cur & base),
        had_baseline=bool(baseline_ids),
    )
