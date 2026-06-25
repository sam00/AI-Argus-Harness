"""Supply-chain scanner — manifest/lockfile parsing + SBOM + risk heuristics.

Offline. Parses common dependency manifests, builds a lightweight SBOM, and
flags heuristic risks (pinned-to-latest, suspicious/typosquat names). It does
NOT claim a CVE without package + version + source (design reliability rule).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Evidence, Finding,
    Impact, Owner, Remediation, Severity,
)

POPULAR = {"react", "lodash", "requests", "numpy", "express", "flask", "django",
           "axios", "urllib3", "pyyaml"}
# Legitimate packages that happen to be edit-distance 1 from a popular name.
# Suppresses known typosquat false positives.
TYPOSQUAT_ALLOWLIST = {"request", "requests", "reacts", "expressjs", "djangos",
                       "numpyro", "flasks", "axion", "reactor"}


@register
class SupplyChainScanner(Scanner):
    name = "supply_chain"
    category = "supply-chain"
    description = "Dependency manifest/lockfile parsing, SBOM, typosquat heuristics."

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def _root(self, ctx: ScanContext) -> Path:
        raw = ctx.target.attributes.get("path") or ctx.target.raw
        p = Path(raw)
        return p if p.exists() and p.is_dir() else Path.cwd()

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        root = self._root(ctx)
        sbom: List[Dict[str, str]] = []

        for parser, fname in ((self._parse_requirements, "requirements.txt"),
                              (self._parse_package_json, "package.json")):
            for path in root.rglob(fname):
                if "node_modules" in path.parts:
                    continue
                deps = parser(path)
                sbom.extend(deps)
                for name, version in [(d["name"], d["version"]) for d in deps]:
                    self._evaluate_dep(ctx, root, name, version, path, res)

        ctx.evidence_store.put("scanner",
                               f"SBOM generated with {len(sbom)} components")
        res.notes.append(f"sbom components: {len(sbom)}")
        if ctx.run_dir:
            try:
                (ctx.run_dir / "sbom.json").write_text(json.dumps(sbom, indent=2))
            except Exception:
                pass
        return res

    # ------------------------------------------------------------------ #
    def _parse_requirements(self, path: Path) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        try:
            for line in path.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~]=?)?\s*([0-9A-Za-z.\-]*)", line)
                if m:
                    out.append({"name": m.group(1), "version": m.group(3) or "*",
                                "ecosystem": "pypi"})
        except Exception:
            pass
        return out

    def _parse_package_json(self, path: Path) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        try:
            data = json.loads(path.read_text(errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                for name, ver in (data.get(section) or {}).items():
                    out.append({"name": name, "version": str(ver), "ecosystem": "npm"})
        except Exception:
            pass
        return out

    def _evaluate_dep(self, ctx: ScanContext, root: Path, name: str, version: str,
                      path: Path, res: ScannerResult) -> None:
        asset = Asset.make(AssetType.DEPENDENCY, name,
                           attributes={"version": version, "manifest": str(path)})
        ctx.asset_graph.add(asset)

        if version in ("*", "latest", ""):
            ev = ctx.evidence_store.put(
                "config", f"Dependency {name} is unpinned ({version or 'none'}) in {path.name}")
            res.findings.append(Finding(
                title=f"Unpinned dependency: {name}",
                asset=asset, scanner=self.name, category=Category.SUPPLY_CHAIN.value,
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                evidence=[Evidence("config",
                                   f"{name} has no pinned version in {path.name}.",
                                   Confidence.HIGH, raw_ref=ev)],
                impact=Impact(
                    business="Unpinned dependencies enable supply-chain drift and confusion.",
                    technical=f"{name} resolves to a floating version.",
                    blast_radius="build + deployed artifacts"),
                remediation=Remediation(
                    summary="Pin dependency to an exact, reviewed version with a lockfile.",
                    steps=[f"Pin {name} to an exact version", "Commit a lockfile",
                           "Enable dependency review in CI"],
                    priority=Severity.MEDIUM),
                owner=Owner(team="Application Security", service=str(path))))

        squat = self._typosquat(name)
        if squat:
            ev = ctx.evidence_store.put(
                "config", f"Dependency {name} resembles popular package '{squat}' (typosquat heuristic)")
            res.findings.append(Finding(
                title=f"Possible typosquat dependency: {name}",
                asset=asset, scanner=self.name, category=Category.SUPPLY_CHAIN.value,
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                evidence=[Evidence("config",
                                   f"{name} is edit-distance 1 from popular '{squat}'.",
                                   Confidence.MEDIUM, raw_ref=ev)],
                impact=Impact(
                    business="Typosquatted packages can deliver malicious code.",
                    technical=f"{name} may impersonate '{squat}'.",
                    blast_radius="build + runtime"),
                remediation=Remediation(
                    summary="Verify package authenticity; replace with the legitimate package.",
                    steps=[f"Confirm intended package vs '{squat}'",
                           "Pin and verify provenance/signature"],
                    priority=Severity.HIGH),
                owner=Owner(team="Application Security", service=str(path))))

    def _typosquat(self, name: str) -> str:
        n = name.lower()
        if n in TYPOSQUAT_ALLOWLIST or n in POPULAR:
            return ""
        for pop in POPULAR:
            if n != pop and _edit_distance_le1(n, pop):
                return pop
        return ""


def _edit_distance_le1(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if a == b:
        return False
    # check edit distance == 1
    if len(a) == len(b):
        return sum(c1 != c2 for c1, c2 in zip(a, b)) == 1
    # insertion/deletion
    short, lng = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    diff = 0
    while i < len(short) and j < len(lng):
        if short[i] != lng[j]:
            diff += 1
            if diff > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True
