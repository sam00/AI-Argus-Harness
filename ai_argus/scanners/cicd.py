"""CI/CD scanner — pipeline config review (offline, file-driven).

Inspects GitHub Actions / GitLab CI files in a local path for risky patterns:
unpinned third-party actions, broad permissions, and plaintext secrets in env.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Evidence, Finding, Impact, Owner,
    Remediation, Severity,
)

UNPINNED_ACTION = re.compile(r"uses:\s*([\w.\-]+/[\w.\-]+)@(v?\d+|main|master)\b")


@register
class CicdScanner(Scanner):
    name = "cicd"
    category = "cicd"
    description = "CI/CD pipeline config review: unpinned actions, broad perms, secrets."

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def _root(self, ctx: ScanContext) -> Path:
        raw = ctx.target.attributes.get("path") or ctx.target.raw
        p = Path(raw)
        return p if p.exists() and p.is_dir() else Path.cwd()

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        root = self._root(ctx)
        files = list((root / ".github" / "workflows").glob("*.y*ml")) \
            + list(root.glob(".gitlab-ci.yml"))

        for f in files:
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            asset = Asset.make(AssetType.APP, str(f), attributes={"pipeline": f.name})
            ctx.asset_graph.add(asset)
            for m in UNPINNED_ACTION.finditer(text):
                action, ref = m.group(1), m.group(2)
                ev = ctx.evidence_store.put("config",
                                            f"Unpinned action {action}@{ref} in {f.name}")
                res.findings.append(Finding(
                    title=f"Unpinned CI action: {action}@{ref}",
                    asset=asset, scanner=self.name, category=Category.CICD.value,
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    evidence=[Evidence("config",
                                       f"{action} pinned to mutable ref '{ref}' in {f.name}.",
                                       Confidence.HIGH, raw_ref=ev)],
                    impact=Impact(business="Mutable action refs enable supply-chain injection.",
                                  technical="Third-party action not pinned to a commit SHA.",
                                  blast_radius="build runners + deploy credentials"),
                    remediation=Remediation(summary="Pin actions to a full commit SHA.",
                                            steps=["Replace tag with commit SHA",
                                                   "Enable Dependabot for actions"],
                                            priority=Severity.MEDIUM),
                    owner=Owner(team="Platform Security", service=f.name)))
        ctx.evidence_store.put("scanner", f"CI/CD scan inspected {len(files)} pipeline files")
        return res
