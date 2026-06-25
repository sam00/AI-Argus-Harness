"""Shared run context passed to scanners and stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Config
from ..evidence import EvidenceStore
from ..graph import AssetGraph, IdentityGraph
from ..llm import CostTracker, LLMProvider, get_provider
from ..models import Chain, Finding
from .auth import AuthResolution


@dataclass
class ScanTarget:
    """What we are scanning. ``raw`` is the user-supplied target string."""

    raw: str
    kind: str = "auto"  # domain | cidr | repo | cloud-account | file | auto
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    config: Config
    target: ScanTarget
    asset_graph: AssetGraph = field(default_factory=AssetGraph)
    identity_graph: IdentityGraph = field(default_factory=IdentityGraph)
    evidence_store: EvidenceStore = field(default_factory=EvidenceStore)
    findings: List[Finding] = field(default_factory=list)
    chains: List[Chain] = field(default_factory=list)
    tracker: CostTracker = field(default_factory=CostTracker)
    run_dir: Optional[Path] = None
    auth: Optional[AuthResolution] = None  # credential preflight (S1..S5.5)
    logs: List[str] = field(default_factory=list)
    _llm: Optional[LLMProvider] = None

    @property
    def llm(self) -> LLMProvider:
        if self._llm is None:
            self._llm = get_provider(self.config, self.tracker)
        return self._llm

    def log(self, msg: str) -> None:
        self.logs.append(msg)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
