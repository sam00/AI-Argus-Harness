"""Scanner plugin base class + registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Type

from ..core.context import ScanContext
from ..models import Finding


@dataclass
class ScannerResult:
    scanner: str
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class Scanner:
    """Base class for all scanners.

    Subclasses set ``name``/``category`` and implement :meth:`run`. They must:
      * be read-only by default (no destructive actions),
      * respect stealth/passive modes,
      * attach at least one :class:`Evidence` to every candidate finding.
    """

    name: str = "base"
    category: str = "general"
    description: str = ""
    requires_network: bool = False

    #: stealth modes this scanner is allowed to run in
    allowed_stealth: tuple = ("passive", "safe", "auth", "stealth")

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def run(self, ctx: ScanContext) -> ScannerResult:  # pragma: no cover - abstract
        raise NotImplementedError


REGISTRY: Dict[str, Type[Scanner]] = {}


def register(cls: Type[Scanner]) -> Type[Scanner]:
    REGISTRY[cls.name] = cls
    return cls


def get_scanner(name: str) -> Scanner:
    if name not in REGISTRY:
        raise KeyError(f"unknown scanner: {name}")
    return REGISTRY[name]()


def all_scanners() -> List[str]:
    return sorted(REGISTRY.keys())
