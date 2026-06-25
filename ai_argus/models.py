"""Core data models for AI-Argus-Harness.

These dataclasses are the canonical in-memory representation of every object
that flows through the harness. They mirror the JSON schemas in
``ai_argus/schemas`` and enforce the evidence-first design principle:

    asset + evidence + identity_path + impact + confidence + remediation + owner

No finding is promoted to enterprise reporting unless all required fields exist
(see :mod:`ai_argus.reliability.completeness_gate`).
"""

from __future__ import annotations

import enum
import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weight(self) -> float:
        return {"low": 0.3, "medium": 0.6, "high": 1.0}[self.value]


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    CLOUD = "cloud"
    ENDPOINT = "endpoint"
    K8S = "k8s"
    APP = "app"
    SERVICE = "service"
    DEPENDENCY = "dependency"
    SAAS = "saas"
    NETWORK = "network"


class Environment(str, enum.Enum):
    PROD = "prod"
    STAGING = "staging"
    DEV = "dev"
    UNKNOWN = "unknown"


class Relationship(str, enum.Enum):
    CAN_READ = "can-read"
    CAN_WRITE = "can-write"
    CAN_ADMIN = "can-admin"
    CAN_ASSUME = "can-assume"
    CAN_DEPLOY = "can-deploy"


class Category(str, enum.Enum):
    """Canonical finding-category taxonomy.

    Single source of truth shared by scanners, scoring and reporting so the
    taxonomy cannot silently drift (string values are stable for wire/report
    compatibility).
    """

    ATTACK_SURFACE = "attack-surface"
    TLS = "tls"
    NETWORK_EXPOSURE = "network-exposure"
    DATA_EXPOSURE = "data-exposure"
    SECRETS = "secrets"
    SUPPLY_CHAIN = "supply-chain"
    CICD = "cicd"
    IDENTITY = "identity"
    KUBERNETES = "kubernetes"
    KUBERNETES_RBAC = "kubernetes-rbac"
    SAAS = "saas"
    APPLICATION = "application"
    ENDPOINT = "endpoint"
    GENERAL = "general"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _short_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def content_id(prefix: str, *parts: str) -> str:
    """Deterministic, content-addressed identifier.

    Stable across runs for identical content, which enables incremental diffs,
    suppressions, idempotent ticket export and cross-run replay.
    """
    basis = "::".join(p for p in parts if p)
    return f"{prefix}-{hashlib.sha1(basis.encode()).hexdigest()[:10]}"


# --------------------------------------------------------------------------- #
# Graph primitives
# --------------------------------------------------------------------------- #
@dataclass
class Asset:
    """A discovered enterprise asset (node in the asset graph)."""

    id: str
    type: AssetType
    name: str
    environment: Environment = Environment.UNKNOWN
    owner: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    @staticmethod
    def make(type: AssetType, name: str, **kw: Any) -> "Asset":
        aid = "asset-" + hashlib.sha1(f"{type.value}:{name}".encode()).hexdigest()[:12]
        return Asset(id=aid, type=type, name=name, **kw)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["environment"] = self.environment.value
        return d


@dataclass
class Identity:
    """A principal in the identity graph (human, role, service account, etc.)."""

    id: str
    kind: str  # user | group | role | service-account | oauth-app | ci-identity | external
    name: str
    provider: str = ""  # aws | gcp | k8s | okta | github | ...
    privileged: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def make(kind: str, name: str, provider: str = "", **kw: Any) -> "Identity":
        iid = "id-" + hashlib.sha1(f"{provider}:{kind}:{name}".encode()).hexdigest()[:12]
        return Identity(id=iid, kind=kind, name=name, provider=provider, **kw)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IdentityHop:
    """A single edge in an identity/access path."""

    principal: str
    permission: str
    target: str
    relationship: Relationship = Relationship.CAN_READ

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["relationship"] = self.relationship.value
        return d


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """A single, source-attributed observation.

    AI never creates evidence — deterministic scanners do. The reliability layer
    only allows AI to *reason over* evidence, never invent it.
    """

    source: str  # scanner | log | config | code | cloud-api | endpoint-agent
    detail: str
    confidence: Confidence = Confidence.MEDIUM
    timestamp: str = field(default_factory=_now)
    raw_ref: Optional[str] = None  # pointer to raw artifact in the evidence store

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Impact:
    business: str = ""
    technical: str = ""
    blast_radius: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Remediation:
    summary: str = ""
    steps: List[str] = field(default_factory=list)
    priority: Severity = Severity.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["priority"] = self.priority.value
        return d


@dataclass
class Owner:
    team: str = ""
    service: str = ""
    contact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """The central enterprise object. Must be complete to be reported."""

    title: str
    asset: Asset
    finding_id: str = field(default_factory=lambda: _short_id("FINDING"))
    evidence: List[Evidence] = field(default_factory=list)
    identity_path: List[IdentityHop] = field(default_factory=list)
    impact: Impact = field(default_factory=Impact)
    confidence: Confidence = Confidence.MEDIUM
    remediation: Remediation = field(default_factory=Remediation)
    owner: Owner = field(default_factory=Owner)
    severity: Severity = Severity.INFO
    category: str = "general"
    scanner: str = ""
    stage: str = ""
    risk_score: float = 0.0
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    dedup_key: str = ""
    chain_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    detection_gap: bool = False
    review_status: str = "auto"  # auto | needs-human-review | accepted
    notes: List[str] = field(default_factory=list)

    def add_evidence(self, ev: Evidence) -> "Finding":
        self.evidence.append(ev)
        return self

    def compute_id(self) -> str:
        """Assign a deterministic, content-addressed finding id.

        Derived from the stable identity of the issue (asset + category +
        title + identity path + owning service + primary evidence) so the same
        underlying problem keeps the same id across runs.
        """
        hops = "|".join(f"{h.principal}>{h.relationship.value}>{h.target}"
                        for h in self.identity_path)
        ev = self.evidence[0].detail if self.evidence else ""
        self.finding_id = content_id("FINDING", self.asset.id, self.category,
                                     self.title, hops, self.owner.service, ev)
        return self.finding_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "scanner": self.scanner,
            "stage": self.stage,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "risk_score": round(self.risk_score, 2),
            "score_breakdown": self.score_breakdown,
            "asset": self.asset.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "identity_path": [h.to_dict() for h in self.identity_path],
            "impact": self.impact.to_dict(),
            "remediation": self.remediation.to_dict(),
            "owner": self.owner.to_dict(),
            "detection_gap": self.detection_gap,
            "chain_ids": self.chain_ids,
            "references": self.references,
            "dedup_key": self.dedup_key,
            "review_status": self.review_status,
            "notes": self.notes,
        }


@dataclass
class Chain:
    """An attack-path chain linking assets and identities across findings."""

    chain_id: str = field(default_factory=lambda: _short_id("CHAIN"))
    title: str = ""
    finding_ids: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    identities: List[str] = field(default_factory=list)
    narrative: str = ""
    severity: Severity = Severity.HIGH
    score: float = 0.0

    def compute_id(self) -> str:
        """Content-addressed chain id derived from its member findings."""
        self.chain_id = content_id("CHAIN", *sorted(self.finding_ids))
        return self.chain_id

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
