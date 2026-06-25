"""AWS + GCP scanners (read-only, inventory-driven, identity-aware)."""

from __future__ import annotations

from typing import Any, Dict, List

from ._inventory import load_inventory
from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Environment, Evidence, Finding, Identity,
    IdentityHop, Impact, Owner, Relationship, Remediation, Severity,
)


def _public_bucket_finding(asset: Asset, name: str, ev: str, scanner: str,
                           hops: List[IdentityHop]) -> Finding:
    return Finding(
        title=f"Publicly accessible storage bucket: {name}",
        asset=asset, scanner=scanner, category=Category.DATA_EXPOSURE.value,
        severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        evidence=[Evidence("cloud-api", f"Bucket {name} grants public access.",
                           Confidence.HIGH, raw_ref=ev)],
        identity_path=hops,
        impact=Impact(business="Potential sensitive data exposure from production storage.",
                      technical="Object storage readable by anonymous principals.",
                      blast_radius="all objects in bucket"),
        remediation=Remediation(summary="Remove public access and enforce least privilege.",
                                 steps=["Block public access", "Audit bucket policy/ACLs",
                                        "Enable access logging"],
                                 priority=Severity.CRITICAL),
        owner=Owner(team="Cloud Security", service=name),
        detection_gap=True)


@register
class AwsScanner(Scanner):
    name = "aws"
    category = "cloud"
    description = "AWS IAM, S3 exposure, security groups, trust relationships."

    def applicable(self, ctx: ScanContext) -> bool:
        return load_inventory(ctx, "aws") is not None

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        aws = load_inventory(ctx, "aws") or {}
        account = aws.get("account_id", "unknown")

        for b in aws.get("s3_buckets", []):
            asset = Asset.make(AssetType.CLOUD, b["name"],
                               environment=Environment.PROD,
                               attributes={"account": account, "service": "s3"})
            ctx.asset_graph.add(asset)
            if b.get("public"):
                ext = Identity.make("external", "anonymous-internet", "aws")
                sa = Identity.make("role", b.get("reader_role", "s3-reader"), "aws", privileged=False)
                ctx.identity_graph.grant(ext, asset.id, "s3:GetObject", Relationship.CAN_READ)
                hops = [IdentityHop("anonymous-internet", "s3:GetObject",
                                    b["name"], Relationship.CAN_READ)]
                ev = ctx.evidence_store.put("cloud-api",
                                            f"S3 bucket {b['name']} is public in account {account}")
                res.findings.append(_public_bucket_finding(asset, b["name"], ev, self.name, hops))

        for role in aws.get("iam_roles", []):
            if role.get("admin") and role.get("assumable_by_external"):
                asset = Asset.make(AssetType.CLOUD, role["name"],
                                   attributes={"account": account, "service": "iam"})
                ctx.asset_graph.add(asset)
                ident = Identity.make("role", role["name"], "aws", privileged=True)
                ext = Identity.make("external", "external-account", "aws")
                ctx.identity_graph.grant(ext, ident.id, "sts:AssumeRole", Relationship.CAN_ASSUME)
                ev = ctx.evidence_store.put("cloud-api",
                                            f"IAM role {role['name']} admin + externally assumable")
                res.findings.append(Finding(
                    title=f"Externally assumable admin role: {role['name']}",
                    asset=asset, scanner=self.name, category=Category.IDENTITY.value,
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    evidence=[Evidence("cloud-api",
                                       f"Role {role['name']} is admin and trusts external accounts.",
                                       Confidence.HIGH, raw_ref=ev)],
                    identity_path=[IdentityHop("external-account", "sts:AssumeRole",
                                               role["name"], Relationship.CAN_ASSUME),
                                   IdentityHop(role["name"], "*", "account", Relationship.CAN_ADMIN)],
                    impact=Impact(business="Full account compromise via cross-account trust.",
                                  technical="Privileged role assumable from outside the org.",
                                  blast_radius="entire AWS account"),
                    remediation=Remediation(summary="Restrict trust policy to known principals.",
                                            steps=["Scope AssumeRole trust", "Add external-id / MFA",
                                                   "Reduce role permissions"],
                                            priority=Severity.CRITICAL),
                    owner=Owner(team="Cloud Security", service=role["name"]),
                    detection_gap=not aws.get("cloudtrail_enabled", False)))

        mode = ctx.auth.label("aws") if ctx.auth else "unauthenticated"
        ctx.evidence_store.put(
            "scanner", f"AWS scan complete for account {account} ({mode})")
        return res


@register
class GcpScanner(Scanner):
    name = "gcp"
    category = "cloud"
    description = "GCP IAM bindings, service accounts, storage exposure."

    def applicable(self, ctx: ScanContext) -> bool:
        return load_inventory(ctx, "gcp") is not None

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        gcp = load_inventory(ctx, "gcp") or {}
        project = gcp.get("project_id", "unknown")

        for b in gcp.get("buckets", []):
            asset = Asset.make(AssetType.CLOUD, b["name"], environment=Environment.PROD,
                               attributes={"project": project, "service": "gcs"})
            ctx.asset_graph.add(asset)
            if b.get("public"):
                hops = [IdentityHop("allUsers", "storage.objects.get",
                                    b["name"], Relationship.CAN_READ)]
                ev = ctx.evidence_store.put("cloud-api",
                                            f"GCS bucket {b['name']} grants allUsers in {project}")
                res.findings.append(_public_bucket_finding(asset, b["name"], ev, self.name, hops))

        for sa in gcp.get("service_accounts", []):
            if sa.get("owner_role"):
                asset = Asset.make(AssetType.CLOUD, sa["email"],
                                   attributes={"project": project, "service": "iam"})
                ctx.asset_graph.add(asset)
                ident = Identity.make("service-account", sa["email"], "gcp", privileged=True)
                ctx.identity_graph.add(ident)
                ev = ctx.evidence_store.put("cloud-api",
                                            f"Service account {sa['email']} has roles/owner in {project}")
                res.findings.append(Finding(
                    title=f"Over-privileged service account: {sa['email']}",
                    asset=asset, scanner=self.name, category=Category.IDENTITY.value,
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    evidence=[Evidence("cloud-api",
                                       f"{sa['email']} holds roles/owner on project {project}.",
                                       Confidence.HIGH, raw_ref=ev)],
                    identity_path=[IdentityHop(sa["email"], "roles/owner",
                                               project, Relationship.CAN_ADMIN)],
                    impact=Impact(business="Service-account compromise yields full project control.",
                                  technical="roles/owner violates least privilege.",
                                  blast_radius="entire GCP project"),
                    remediation=Remediation(summary="Replace roles/owner with scoped roles.",
                                            steps=["Grant least-privilege roles",
                                                   "Rotate keys", "Enable org policy constraints"],
                                            priority=Severity.HIGH),
                    owner=Owner(team="Cloud Security", service=sa["email"])))

        mode = ctx.auth.label("gcp") if ctx.auth else "unauthenticated"
        ctx.evidence_store.put(
            "scanner", f"GCP scan complete for project {project} ({mode})")
        return res
