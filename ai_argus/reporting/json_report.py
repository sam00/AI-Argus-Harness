"""Structured JSON report (full machine-readable run output)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from ..core.orchestrator import RunResult


def build_json(result: "RunResult") -> Dict[str, Any]:
    return {
        "tool": "AI-Argus-Harness",
        "version": result.version,
        "run_id": result.run_id,
        "started": result.started,
        "finished": result.finished,
        "target": result.target,
        "profile": result.profile,
        "cost_mode": result.cost_mode,
        "stealth_mode": result.stealth_mode,
        "summary": result.summary(),
        "auth": result.auth,
        "findings": [f.to_dict() for f in result.findings],
        "review_queue": [f.to_dict() for f in result.review_queue],
        "suppressed": [f.to_dict() for f in result.suppressed],
        "diff": result.diff,
        "chains": [c.to_dict() for c in result.chains],
        "asset_graph": result.asset_graph.to_dict(),
        "identity_graph": result.identity_graph.to_dict(),
        "evidence": result.evidence.to_dict(),
        "stage_log": result.stage_log,
        "cost": result.cost_summary,
    }


def write_json(result: "RunResult", path: Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(build_json(result), indent=2, default=str))
    return path
