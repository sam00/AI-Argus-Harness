"""Application / API scanner — exposed debug routes & auth surface (inventory-driven)."""

from __future__ import annotations

from ._inventory import load_inventory
from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Environment, Evidence, Finding, IdentityHop,
    Impact, Owner, Relationship, Remediation, Severity,
)

DEBUG_HINTS = ("/debug", "/actuator", "/__debug__", "/swagger", "/.env", "/admin")


@register
class ApplicationScanner(Scanner):
    name = "application"
    category = "application"
    description = "API inventory, exposed debug/admin routes, missing authentication."

    def applicable(self, ctx: ScanContext) -> bool:
        return load_inventory(ctx, "endpoints") is not None

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        endpoints = load_inventory(ctx, "endpoints") or []

        for ep in endpoints:
            route = ep.get("route", "/")
            host = ep.get("host", "app")
            unauth = not ep.get("auth", True)
            is_debug = any(h in route.lower() for h in DEBUG_HINTS)
            if not (unauth or is_debug):
                continue
            asset = Asset.make(AssetType.APP, f"{host}{route}", environment=Environment.PROD,
                               attributes={"host": host, "route": route})
            ctx.asset_graph.add(asset)
            sev = Severity.HIGH if (unauth and is_debug) else Severity.MEDIUM
            reason = []
            if is_debug:
                reason.append("debug/admin route")
            if unauth:
                reason.append("no authentication")
            ev = ctx.evidence_store.put("scanner",
                                        f"Endpoint {host}{route} exposed ({', '.join(reason)})")
            res.findings.append(Finding(
                title=f"Exposed endpoint: {route}",
                asset=asset, scanner=self.name, category=Category.APPLICATION.value,
                severity=sev, confidence=Confidence.MEDIUM,
                evidence=[Evidence("scanner",
                                   f"{host}{route} is {', '.join(reason)}.",
                                   Confidence.MEDIUM, raw_ref=ev)],
                identity_path=[IdentityHop("external-user", "http-request",
                                           f"{host}{route}", Relationship.CAN_READ)],
                impact=Impact(business="Unauthenticated/administrative surface reachable externally.",
                              technical="Sensitive route lacks access control.",
                              blast_radius="application + backing data"),
                remediation=Remediation(summary="Require authentication; disable debug routes in prod.",
                                        steps=["Enforce authN/authZ on the route",
                                               "Disable debug/actuator endpoints in production",
                                               "Add WAF rule"],
                                        priority=sev),
                owner=Owner(team="Application Security", service=host)))
        ctx.evidence_store.put("scanner", f"Application scan reviewed {len(endpoints)} endpoints")
        return res
