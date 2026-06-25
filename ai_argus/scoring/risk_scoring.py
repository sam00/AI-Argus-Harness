"""Deterministic risk scoring engine.

Additive, deterministic risk model:

    Risk = Exposure + Privilege + Exploitability + IdentityPathStrength
         + DataSensitivity + BusinessCriticality + Chainability + DetectionGap
         + ControlWeakness + Confidence - CompensatingControls

Scoring is deterministic (same inputs -> same score) for reproducibility.
Severity is then derived from the score plus qualitative signals.
"""

from __future__ import annotations

from typing import Dict

from ..models import (
    AssetType, Category, Confidence, Environment, Finding, Relationship, Severity,
)

PRIV_RELATIONS = {Relationship.CAN_ADMIN, Relationship.CAN_ASSUME,
                  Relationship.CAN_DEPLOY, Relationship.CAN_WRITE}

# Intrinsic exploitability by category (decoupled from severity to avoid the
# previous severity<->score feedback loop). Reflects how directly the issue
# yields attacker value, independent of the final severity.
EXPLOITABILITY: Dict[str, float] = {
    Category.SECRETS.value: 3.0,            # a working credential is directly usable
    Category.DATA_EXPOSURE.value: 2.5,
    Category.NETWORK_EXPOSURE.value: 2.5,
    Category.IDENTITY.value: 2.5,
    Category.KUBERNETES_RBAC.value: 2.5,
    Category.KUBERNETES.value: 2.0,
    Category.SAAS.value: 2.0,
    Category.APPLICATION.value: 2.0,
    Category.ENDPOINT.value: 2.0,            # a compromised endpoint is directly usable
    Category.SUPPLY_CHAIN.value: 1.5,
    Category.CICD.value: 1.5,
    Category.ATTACK_SURFACE.value: 1.0,
    Category.TLS.value: 0.5,
}

# Categories that represent a weak/over-broad control (escalation surface).
WEAK_CONTROL_CATEGORIES = {
    Category.IDENTITY.value, Category.KUBERNETES_RBAC.value,
    Category.KUBERNETES.value, Category.SAAS.value,
    Category.CICD.value, Category.NETWORK_EXPOSURE.value,
}
# Categories that inherently touch sensitive data.
DATA_SENSITIVE_CATEGORIES = {Category.DATA_EXPOSURE.value, Category.SECRETS.value}


def _exposure(f: Finding) -> float:
    txt = (f.title + " " + f.impact.technical).lower()
    attrs = f.asset.attributes or {}
    score = 0.0
    if attrs.get("public") is True or any(
            k in txt for k in ("public", "internet", "external", "anonymous", "exposed")):
        score += 3.0
    if f.category == Category.SECRETS.value:   # credential committed to source is exposed
        score += 2.0
    if f.asset.environment == Environment.PROD:
        score += 1.0
    return score


def _privilege(f: Finding) -> float:
    return 3.0 if any(h.relationship in PRIV_RELATIONS for h in f.identity_path) else 0.0


def _exploitability(f: Finding) -> float:
    return EXPLOITABILITY.get(f.category, 1.5)


def _identity_path_strength(f: Finding) -> float:
    if not f.identity_path:
        return 0.0
    priv = sum(1 for h in f.identity_path if h.relationship in PRIV_RELATIONS)
    return min(3.0, 1.0 + priv)


def _data_sensitivity(f: Finding) -> float:
    classes = f.asset.attributes.get("classes", []) if f.asset.attributes else []
    if any(c in ("pii", "phi", "pci") for c in classes):
        return 3.0
    if f.category in DATA_SENSITIVE_CATEGORIES:
        return 2.0
    return 0.0


def _business_criticality(f: Finding) -> float:
    return 2.0 if f.asset.environment == Environment.PROD else 0.5


def _chainability(f: Finding) -> float:
    return min(3.0, float(len(f.chain_ids)))


def _detection_gap(f: Finding) -> float:
    return 2.0 if f.detection_gap else 0.0


def _control_weakness(f: Finding) -> float:
    return 1.5 if f.category in WEAK_CONTROL_CATEGORIES else 0.0


def _confidence(f: Finding) -> float:
    return {Confidence.LOW: 0.3, Confidence.MEDIUM: 1.0, Confidence.HIGH: 2.0}[f.confidence]


def _compensating(f: Finding) -> float:
    return 1.0 if f.asset.environment in (Environment.DEV, Environment.STAGING) else 0.0


def score_finding(f: Finding) -> Finding:
    breakdown: Dict[str, float] = {
        "exposure": _exposure(f),
        "privilege": _privilege(f),
        "exploitability": _exploitability(f),
        "identity_path_strength": _identity_path_strength(f),
        "data_sensitivity": _data_sensitivity(f),
        "business_criticality": _business_criticality(f),
        "chainability": _chainability(f),
        "detection_gap": _detection_gap(f),
        "control_weakness": _control_weakness(f),
        "confidence": _confidence(f),
        "compensating_controls": -_compensating(f),
    }
    f.risk_score = round(sum(breakdown.values()), 2)
    f.score_breakdown.update({k: round(v, 2) for k, v in breakdown.items()})
    f.severity = assign_severity(f)
    return f


def assign_severity(f: Finding) -> Severity:
    """Severity derived from the score plus qualitative signals."""
    internet = any(k in (f.title + f.impact.technical).lower()
                   for k in ("public", "internet", "external", "anonymous"))
    privileged = any(h.relationship in PRIV_RELATIONS for h in f.identity_path)
    sensitive = _data_sensitivity(f) >= 2.0
    weak_detection = f.detection_gap

    if internet and privileged and sensitive and weak_detection:
        return Severity.CRITICAL
    if f.risk_score >= 14:
        return Severity.CRITICAL
    if f.risk_score >= 9:
        return Severity.HIGH
    if f.risk_score >= 5:
        return Severity.MEDIUM
    if f.risk_score >= 2:
        return Severity.LOW
    return Severity.INFO
