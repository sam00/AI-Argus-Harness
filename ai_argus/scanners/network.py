"""Network scanner — host discovery + open-port fingerprinting.

Read-only TCP connect checks against a curated set of common ports. Honors
stealth pacing and only performs active probing in safe/auth/stealth modes.
Passive mode records inventory only.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Environment, Evidence, Finding,
    Impact, Owner, Remediation, Severity,
)

# port -> (service, severity-if-exposed)
COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 6379: "redis", 9200: "elasticsearch",
    27017: "mongodb",
}
RISKY_IF_PUBLIC = {23: "telnet", 3389: "rdp", 445: "smb", 3306: "mysql",
                   5432: "postgres", 6379: "redis", 9200: "elasticsearch",
                   27017: "mongodb"}


@register
class NetworkScanner(Scanner):
    name = "network"
    category = "network"
    description = "Host discovery, open-port discovery, service fingerprinting."
    requires_network = True
    allowed_stealth = ("safe", "auth", "stealth")

    def applicable(self, ctx: ScanContext) -> bool:
        return ctx.target.kind in ("domain", "cidr", "auto")

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        host = ctx.target.raw.strip().replace("https://", "").replace("http://", "").split("/")[0]

        if ctx.config.stealth_mode == "passive":
            ctx.evidence_store.put("scanner", f"Passive mode: skipping active port probe of {host}")
            res.notes.append("passive mode — no active probing")
            return res

        asset = Asset.make(AssetType.NETWORK, host, environment=Environment.PROD)
        ctx.asset_graph.add(asset)

        # Probe all ports concurrently (was sequential: up to ~22s/host).
        open_ports: List[int] = []
        with ThreadPoolExecutor(max_workers=min(16, len(COMMON_PORTS))) as ex:
            futures = {ex.submit(self._connect, host, port): port
                       for port in COMMON_PORTS}
            for fut, port in futures.items():
                try:
                    if fut.result():
                        open_ports.append(port)
                except Exception:
                    pass

        # Emit evidence/findings deterministically (sorted), independent of
        # probe-completion order.
        for port in sorted(open_ports):
            service = COMMON_PORTS[port]
            ev = ctx.evidence_store.put("scanner", f"TCP {port} ({service}) open on {host}")
            if port in RISKY_IF_PUBLIC:
                res.findings.append(self._risky_port(asset, host, port, service, ev))

        ctx.evidence_store.put("scanner",
                               f"{host} open ports: {sorted(open_ports) or 'none detected'}")
        res.notes.append(f"open ports on {host}: {sorted(open_ports)}")
        return res

    def _connect(self, host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def _risky_port(self, asset: Asset, host: str, port: int, service: str,
                    ev_ref: str) -> Finding:
        return Finding(
            title=f"Sensitive service exposed: {service} on {host}:{port}",
            asset=asset, scanner=self.name, category=Category.NETWORK_EXPOSURE.value,
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            evidence=[Evidence("scanner",
                               f"{service} ({port}) accepts TCP connections on {host}.",
                               Confidence.HIGH, raw_ref=ev_ref)],
            impact=Impact(
                business="Direct internet exposure of a sensitive backend service.",
                technical=f"{service} should not be publicly reachable.",
                blast_radius="host + connected data stores"),
            remediation=Remediation(
                summary=f"Remove public exposure of {service}.",
                steps=["Restrict via security group / firewall",
                       "Place behind VPN / bastion",
                       "Enforce authentication and encryption in transit"],
                priority=Severity.HIGH),
            owner=Owner(team="Network Security", service=host),
            detection_gap=True,
        )
