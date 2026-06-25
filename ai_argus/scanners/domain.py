"""Domain scanner — attack-surface mapping for a root domain.

Offline-capable: uses only the Python standard library (socket / ssl). When the
network is unavailable every check degrades gracefully to an informational
inventory entry instead of failing the run.
"""

from __future__ import annotations

import socket
import ssl
from typing import List

from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Environment, Evidence, Finding,
    Impact, Owner, Remediation, Severity,
)

COMMON_SUBDOMAINS = ["www", "api", "admin", "dev", "staging", "vpn", "mail",
                     "portal", "test", "internal"]


@register
class DomainScanner(Scanner):
    name = "domain"
    category = "attack-surface"
    description = "Root domain mapping, DNS, TLS, subdomain discovery, takeover risk."
    requires_network = True

    def applicable(self, ctx: ScanContext) -> bool:
        return ctx.target.kind in ("domain", "auto") and "." in ctx.target.raw

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        domain = ctx.target.raw.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

        root = Asset.make(AssetType.DOMAIN, domain, environment=Environment.PROD)
        ctx.asset_graph.add(root)

        # --- DNS resolution -------------------------------------------------
        ips: List[str] = []
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None)})
            ref = ctx.evidence_store.put("scanner", f"{domain} resolves to {', '.join(ips)}")
            res.notes.append(f"resolved {domain} -> {ips}")
        except Exception as exc:
            ctx.evidence_store.put("scanner", f"DNS resolution failed for {domain}: {exc}")
            res.notes.append(f"offline/no-DNS for {domain}")
            ref = None

        # --- TLS inspection -------------------------------------------------
        if self._stealth_allows(ctx, active=True):
            self._check_tls(ctx, domain, root, res)

        # --- Subdomain discovery (passive resolution only) ------------------
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                socket.getaddrinfo(fqdn, None)
            except Exception:
                continue
            child = Asset.make(AssetType.DOMAIN, fqdn, environment=Environment.PROD)
            ctx.asset_graph.link(root, child, "subdomain")
            ev = ctx.evidence_store.put("scanner", f"Discovered live subdomain {fqdn}")
            if sub in ("admin", "internal", "dev", "staging", "test"):
                res.findings.append(self._sensitive_subdomain(child, fqdn, ev))

        return res

    # ------------------------------------------------------------------ #
    def _stealth_allows(self, ctx: ScanContext, active: bool) -> bool:
        if not active:
            return True
        return ctx.config.stealth_mode in ("safe", "auth", "stealth")

    def _check_tls(self, ctx: ScanContext, domain: str, root: Asset,
                   res: ScannerResult) -> None:
        try:
            sctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with sctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            not_after = cert.get("notAfter", "unknown")
            ctx.evidence_store.put("scanner", f"TLS certificate for {domain} expires {not_after}")
            res.notes.append(f"TLS ok for {domain} (expires {not_after})")
        except Exception as exc:
            ev = ctx.evidence_store.put("scanner", f"TLS check for {domain} failed: {exc}")
            res.findings.append(Finding(
                title=f"TLS endpoint not verifiable on {domain}",
                asset=root, scanner=self.name, category=Category.TLS.value,
                severity=Severity.LOW, confidence=Confidence.LOW,
                evidence=[Evidence("scanner", f"TLS handshake failed: {exc}",
                                   Confidence.LOW, raw_ref=ev)],
                impact=Impact(technical="Endpoint may not enforce TLS or is unreachable.",
                              blast_radius="single endpoint"),
                remediation=Remediation(
                    summary="Verify TLS configuration and certificate validity.",
                    steps=["Confirm 443 is intended to be open",
                           "Renew/replace certificate if expired"],
                    priority=Severity.LOW),
                owner=Owner(team="Platform Security", service=domain),
            ))

    def _sensitive_subdomain(self, asset: Asset, fqdn: str, ev_ref: str) -> Finding:
        return Finding(
            title=f"Sensitive subdomain exposed: {fqdn}",
            asset=asset, scanner=self.name, category=Category.ATTACK_SURFACE.value,
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            evidence=[Evidence("scanner",
                               f"{fqdn} resolves publicly and matches a sensitive naming pattern.",
                               Confidence.HIGH, raw_ref=ev_ref)],
            impact=Impact(
                business="Internal/administrative surface reachable from the internet.",
                technical="Publicly resolvable administrative or non-production host.",
                blast_radius="subdomain + backing services"),
            remediation=Remediation(
                summary="Restrict exposure of administrative/non-production subdomains.",
                steps=["Place behind VPN or zero-trust proxy",
                       "Enforce authentication and IP allow-listing",
                       "Remove DNS record if decommissioned"],
                priority=Severity.MEDIUM),
            owner=Owner(team="Platform Security", service=fqdn, contact="platform-sec@example.com"),
        )
