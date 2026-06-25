"""Data exposure scanner — public datastores & sensitive data indicators (inventory-driven)."""

from __future__ import annotations

from ._inventory import load_inventory
from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Environment, Evidence, Finding, IdentityHop,
    Impact, Owner, Relationship, Remediation, Severity,
)


@register
class DataExposureScanner(Scanner):
    name = "data_exposure"
    category = "data-exposure"
    description = "Public databases/backups + PII/PHI/PCI sensitivity indicators."

    def applicable(self, ctx: ScanContext) -> bool:
        return load_inventory(ctx, "data_stores") is not None

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        stores = load_inventory(ctx, "data_stores") or []

        for ds in stores:
            if not ds.get("public"):
                continue
            name = ds.get("name", "datastore")
            classes = ds.get("data_classes", [])
            sensitive = any(c in ("pii", "phi", "pci") for c in classes)
            sev = Severity.CRITICAL if sensitive else Severity.HIGH
            asset = Asset.make(AssetType.SERVICE, name, environment=Environment.PROD,
                               attributes={"engine": ds.get("engine", ""), "classes": classes})
            ctx.asset_graph.add(asset)
            ev = ctx.evidence_store.put("cloud-api",
                                        f"Datastore {name} publicly reachable; data classes={classes}")
            res.findings.append(Finding(
                title=f"Publicly exposed datastore: {name}",
                asset=asset, scanner=self.name, category=Category.DATA_EXPOSURE.value,
                severity=sev, confidence=Confidence.HIGH,
                evidence=[Evidence("cloud-api",
                                   f"{name} accepts public connections; sensitivity={classes}.",
                                   Confidence.HIGH, raw_ref=ev)],
                identity_path=[IdentityHop("anonymous-internet", "connect",
                                           name, Relationship.CAN_READ)],
                impact=Impact(business="Direct exposure of regulated/sensitive data."
                                       if sensitive else "Exposure of internal datastore.",
                              technical=f"{ds.get('engine','datastore')} reachable from internet.",
                              blast_radius="entire dataset"),
                remediation=Remediation(summary="Remove public access; enforce network controls.",
                                        steps=["Restrict to private network",
                                               "Require auth + TLS", "Enable audit logging"],
                                        priority=sev),
                owner=Owner(team="Data Security", service=name),
                detection_gap=not ds.get("logging", False)))
        ctx.evidence_store.put("scanner", f"Data exposure scan reviewed {len(stores)} datastores")
        return res
