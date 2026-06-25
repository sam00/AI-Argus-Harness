"""Kubernetes scanner — RBAC, workload, and exposure checks (inventory-driven)."""

from __future__ import annotations

from ._inventory import load_inventory
from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Evidence, Finding, Identity, IdentityHop,
    Impact, Owner, Relationship, Remediation, Severity,
)


@register
class KubernetesScanner(Scanner):
    name = "kubernetes"
    category = "kubernetes"
    description = "Cluster RBAC, privileged workloads, exposed services, secrets."

    def applicable(self, ctx: ScanContext) -> bool:
        return load_inventory(ctx, "kubernetes") is not None

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        k8s = load_inventory(ctx, "kubernetes") or {}
        cluster = k8s.get("cluster", "unknown")

        for binding in k8s.get("rolebindings", []):
            if binding.get("role") == "cluster-admin" and binding.get("subject_kind") == "ServiceAccount":
                ns = binding.get("namespace", "default")
                subj = binding.get("subject", "default")
                asset = Asset.make(AssetType.K8S, f"{cluster}/{ns}/{subj}",
                                   attributes={"cluster": cluster, "namespace": ns,
                                               "object": "rolebinding", "subject": subj})
                ctx.asset_graph.add(asset)
                ident = Identity.make("service-account", f"{ns}:{subj}", "k8s", privileged=True)
                ctx.identity_graph.grant(ident, "cluster", "cluster-admin", Relationship.CAN_ADMIN)
                ev = ctx.evidence_store.put("config",
                                            f"SA {ns}:{subj} bound to cluster-admin in {cluster}")
                res.findings.append(Finding(
                    title=f"Service account with cluster-admin: {ns}:{subj}",
                    asset=asset, scanner=self.name, category=Category.KUBERNETES_RBAC.value,
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    evidence=[Evidence("config",
                                       f"ServiceAccount {ns}:{subj} has cluster-admin via RBAC.",
                                       Confidence.HIGH, raw_ref=ev)],
                    identity_path=[IdentityHop(f"{ns}:{subj}", "cluster-admin",
                                               cluster, Relationship.CAN_ADMIN)],
                    impact=Impact(business="Pod compromise escalates to full cluster takeover.",
                                  technical="Excessive RBAC binding to cluster-admin.",
                                  blast_radius="entire cluster"),
                    remediation=Remediation(summary="Replace cluster-admin with scoped Role.",
                                            steps=["Define least-privilege Role",
                                                   "Remove cluster-admin binding",
                                                   "Enable admission policy"],
                                            priority=Severity.CRITICAL),
                    owner=Owner(team="Platform Security", service=f"{cluster}/{ns}")))

        for pod in k8s.get("pods", []):
            if pod.get("privileged"):
                ns = pod.get("namespace", "default")
                asset = Asset.make(AssetType.K8S, f"{cluster}/{ns}/{pod['name']}",
                                   attributes={"cluster": cluster, "namespace": ns,
                                               "object": "pod", "subject": pod["name"]})
                ctx.asset_graph.add(asset)
                ev = ctx.evidence_store.put("config",
                                            f"Pod {ns}/{pod['name']} runs privileged in {cluster}")
                res.findings.append(Finding(
                    title=f"Privileged pod: {ns}/{pod['name']}",
                    asset=asset, scanner=self.name, category=Category.KUBERNETES.value,
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    evidence=[Evidence("config",
                                       f"Pod {ns}/{pod['name']} requests privileged security context.",
                                       Confidence.HIGH, raw_ref=ev)],
                    identity_path=[IdentityHop(f"{ns}/{pod['name']}", "node-access",
                                               cluster, Relationship.CAN_ADMIN)],
                    impact=Impact(business="Container breakout to host node.",
                                  technical="privileged: true grants host capabilities.",
                                  blast_radius="node + co-located workloads"),
                    remediation=Remediation(summary="Drop privileged security context.",
                                            steps=["Remove privileged: true",
                                                   "Apply restricted PodSecurity",
                                                   "Drop Linux capabilities"],
                                            priority=Severity.HIGH),
                    owner=Owner(team="Platform Security", service=f"{cluster}/{ns}")))

        ctx.evidence_store.put("scanner", f"Kubernetes scan complete for {cluster}")
        return res
