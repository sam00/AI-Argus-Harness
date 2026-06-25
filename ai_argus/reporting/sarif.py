"""SARIF 2.1.0 exporter (subset) for enterprise tooling integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..models import Finding, Severity

_SARIF_LEVEL = {
    Severity.INFO: "none",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _rules(findings: List[Finding]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rid = f.category
        if rid not in seen:
            seen[rid] = {
                "id": rid,
                "name": rid.replace("-", " ").title(),
                "shortDescription": {"text": f"AI-Argus {rid} finding"},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            }
    return list(seen.values())


def _result(f: Finding) -> Dict[str, Any]:
    return {
        "ruleId": f.category,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title} — {f.impact.technical or f.impact.business}"},
        "properties": {
            "finding_id": f.finding_id,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "risk_score": f.risk_score,
            "asset": f.asset.name,
            "owner": f.owner.team,
            "review_status": f.review_status,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.asset.name}
            }
        }],
    }


def to_sarif(findings: List[Finding], version: str = "0.1.0") -> Dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AI-Argus-Harness",
                    "version": version,
                    "informationUri": "https://github.com/sam00/AI-Argus-Harness",
                    "rules": _rules(findings),
                }
            },
            "results": [_result(f) for f in findings],
        }],
    }


def write_sarif(findings: List[Finding], path: Path, version: str = "0.1.0") -> Path:
    path = Path(path)
    path.write_text(json.dumps(to_sarif(findings, version), indent=2))
    return path
