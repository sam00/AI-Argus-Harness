"""SaaS / third-party scanner — OAuth grants, external users, privileged integrations."""

from __future__ import annotations

from ._inventory import load_inventory
from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Evidence, Finding, Identity, IdentityHop,
    Impact, Owner, Relationship, Remediation, Severity,
)


@register
class SaasScanner(Scanner):
    name = "saas"
    category = "saas"
    description = "OAuth app grants, external users, privileged third-party integrations."

    def applicable(self, ctx: ScanContext) -> bool:
        return load_inventory(ctx, "saas") is not None

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        saas = load_inventory(ctx, "saas") or {}
        tenant = saas.get("tenant", "unknown")

        for app in saas.get("oauth_apps", []):
            if app.get("broad_scope") or "admin" in (app.get("scopes") or []):
                asset = Asset.make(AssetType.SAAS, app["name"],
                                   attributes={"tenant": tenant, "provider": app.get("provider", "")})
                ctx.asset_graph.add(asset)
                ident = Identity.make("oauth-app", app["name"], app.get("provider", "saas"),
                                      privileged=True, attributes={"broad_scope": True})
                ctx.identity_graph.grant(ident, tenant, "oauth-grant", Relationship.CAN_WRITE)
                ev = ctx.evidence_store.put("config",
                                            f"OAuth app {app['name']} has broad scopes on tenant {tenant}")
                res.findings.append(Finding(
                    title=f"Over-scoped OAuth integration: {app['name']}",
                    asset=asset, scanner=self.name, category=Category.SAAS.value,
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    evidence=[Evidence("config",
                                       f"{app['name']} granted broad/admin OAuth scopes.",
                                       Confidence.HIGH, raw_ref=ev)],
                    identity_path=[IdentityHop(app["name"], "oauth-grant",
                                               tenant, Relationship.CAN_WRITE)],
                    impact=Impact(business="Third-party compromise exposes tenant data.",
                                  technical="OAuth app holds excessive scopes.",
                                  blast_radius="tenant-wide data"),
                    remediation=Remediation(summary="Reduce OAuth scopes; review/revoke unused apps.",
                                            steps=["Audit OAuth grants",
                                                   "Apply least-privilege scopes",
                                                   "Revoke unused integrations"],
                                            priority=Severity.HIGH),
                    owner=Owner(team="Identity Security", service=app["name"])))
        ctx.evidence_store.put("scanner", f"SaaS scan complete for tenant {tenant}")
        return res
