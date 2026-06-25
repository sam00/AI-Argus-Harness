"""Endpoint scanner — host posture for macOS / Linux / Windows (agent-driven).

Deterministic, read-only policy checks over an endpoint-agent *device inventory*
snapshot (the same shape an EDR/MDM collector would export), so the harness can
assess endpoints without shipping a live agent. Provide device records under the
``devices`` key of ``--inventory inventory.json``:

    {"devices": [
       {"host": "laptop-eng-014", "os": "macos", "os_version": "13.2",
        "owner": "engineering", "environment": "prod",
        "edr": {"installed": true, "healthy": false, "product": "..."},
        "disk_encryption": false, "patch_age_days": 210,
        "listening_ports": [22, 3389], "local_admins": ["alice", "contractor-tmp"],
        "suspicious_libraries": ["/tmp/.x/libinject.dylib"],
        "software": [{"name": "openssl", "version": "1.0.1", "vulnerable": true}]}
    ]}

Evidence is attributed to the ``endpoint-agent`` source. Findings are exposure /
posture issues (no identity path required by the completeness gate).
"""

from __future__ import annotations

from typing import List

from ._inventory import load_inventory
from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Environment, Evidence, Finding,
    Impact, Owner, Remediation, Severity,
)

# Services that should rarely listen on an endpoint/workstation.
RISKY_ENDPOINT_PORTS = {
    22: "ssh", 23: "telnet", 445: "smb", 3389: "rdp", 5900: "vnc", 5985: "winrm",
}
_SUPPORTED_OS = {"macos", "linux", "windows"}
_STALE_PATCH_DAYS = 90
_TEMP_ADMIN_HINTS = ("tmp", "temp", "contractor", "test", "guest")


def _env(value: str) -> Environment:
    try:
        return Environment(value)
    except ValueError:
        return Environment.UNKNOWN


@register
class EndpointScanner(Scanner):
    name = "endpoint"
    category = "endpoint"
    description = ("Endpoint posture for macOS/Linux/Windows: EDR, disk "
                   "encryption, patch level, listening services, local admins, "
                   "suspicious libraries, vulnerable software.")

    def applicable(self, ctx: ScanContext) -> bool:
        return load_inventory(ctx, "devices") is not None

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        devices = load_inventory(ctx, "devices") or []

        for dev in devices:
            host = dev.get("host", "unknown-host")
            os_name = str(dev.get("os", "unknown")).lower()
            env = _env(str(dev.get("environment", "unknown")))
            owner_team = dev.get("owner") or "Endpoint Security"
            asset = Asset.make(
                AssetType.ENDPOINT, host, environment=env, owner=owner_team,
                attributes={"os": os_name, "os_version": dev.get("os_version", ""),
                            "managed": dev.get("edr", {}).get("installed", False)})
            ctx.asset_graph.add(asset)
            owner = Owner(team="Endpoint Security", service=host)

            def emit(title: str, detail: str, impact: Impact, rem: Remediation,
                     sev: Severity = Severity.MEDIUM, gap: bool = False) -> None:
                ev_ref = ctx.evidence_store.put("endpoint-agent", f"{host}: {detail}")
                res.findings.append(Finding(
                    title=title, asset=asset, scanner=self.name,
                    category=Category.ENDPOINT.value, severity=sev,
                    confidence=Confidence.HIGH,
                    evidence=[Evidence("endpoint-agent", detail, Confidence.HIGH,
                                       raw_ref=ev_ref)],
                    impact=impact, remediation=rem, owner=owner, detection_gap=gap))

            # --- EDR presence / health (detection gap) ---
            edr = dev.get("edr") or {}
            if not edr.get("installed"):
                emit(f"No EDR agent on endpoint: {host}",
                     f"device has no endpoint detection & response agent installed ({os_name}).",
                     Impact(business="Compromise of this device would go undetected.",
                            technical="No EDR/telemetry on host.", blast_radius="host + user data"),
                     Remediation(summary="Deploy and enforce the managed EDR agent.",
                                 steps=["Install approved EDR", "Enforce via MDM policy",
                                        "Alert on agent removal"], priority=Severity.HIGH),
                     sev=Severity.HIGH, gap=True)
            elif edr.get("healthy") is False:
                emit(f"Unhealthy EDR agent on endpoint: {host}",
                     f"EDR agent present but unhealthy/not reporting ({edr.get('product', 'edr')}).",
                     Impact(business="Detection coverage is silently degraded.",
                            technical="EDR agent unhealthy / not reporting.", blast_radius="host"),
                     Remediation(summary="Repair or reinstall the EDR agent.",
                                 steps=["Investigate agent health", "Reinstall agent",
                                        "Monitor heartbeat"], priority=Severity.HIGH),
                     sev=Severity.HIGH, gap=True)

            # --- Disk encryption (data at rest) ---
            if dev.get("disk_encryption") is False:
                emit(f"Disk encryption disabled: {host}",
                     "full-disk encryption (FileVault/BitLocker/LUKS) is disabled.",
                     Impact(business="Data readable if the device is lost or stolen.",
                            technical="No full-disk encryption.", blast_radius="all data at rest"),
                     Remediation(summary="Enforce full-disk encryption via MDM.",
                                 steps=["Enable FileVault/BitLocker/LUKS", "Escrow recovery keys",
                                        "Enforce via policy"], priority=Severity.HIGH),
                     sev=Severity.HIGH)

            # --- Patch posture ---
            patch_age = dev.get("patch_age_days")
            if isinstance(patch_age, (int, float)) and patch_age > _STALE_PATCH_DAYS:
                sev = Severity.HIGH if patch_age > 2 * _STALE_PATCH_DAYS else Severity.MEDIUM
                emit(f"Stale patch level: {host}",
                     f"OS/software unpatched for {int(patch_age)} days (> {_STALE_PATCH_DAYS}).",
                     Impact(business="Exposed to known, patchable vulnerabilities.",
                            technical=f"patch_age_days={int(patch_age)}.", blast_radius="host"),
                     Remediation(summary="Bring the device to current patch baseline.",
                                 steps=["Apply pending OS updates", "Enforce patch SLA via MDM"],
                                 priority=sev), sev=sev)

            # --- Risky listening services ---
            for port in dev.get("listening_ports", []) or []:
                if port in RISKY_ENDPOINT_PORTS:
                    svc = RISKY_ENDPOINT_PORTS[port]
                    emit(f"Risky service listening on endpoint: {svc} ({host})",
                         f"endpoint is listening on {svc} (port {port}).",
                         Impact(business="Lateral-movement / remote-access surface on a user device.",
                                technical=f"{svc} listening on {port}.",
                                blast_radius="host + reachable peers"),
                         Remediation(summary=f"Disable or firewall {svc} on endpoints.",
                                     steps=[f"Disable {svc} if unused",
                                            "Restrict via host firewall", "Require VPN/MDM gating"],
                                     priority=Severity.MEDIUM), sev=Severity.MEDIUM)

            # --- Excess / temporary local admins ---
            admins = dev.get("local_admins", []) or []
            temp_admins = [a for a in admins
                           if any(h in str(a).lower() for h in _TEMP_ADMIN_HINTS)]
            if temp_admins or len(admins) > 2:
                if temp_admins:
                    detail = "temporary/contractor admin accounts: " + ", ".join(temp_admins)
                else:
                    detail = f"{len(admins)} local admin accounts on device."
                emit(f"Excessive local admin rights: {host}", detail,
                     Impact(business="Larger blast radius if the device is compromised.",
                            technical="Excessive/temporary local administrators.",
                            blast_radius="host"),
                     Remediation(summary="Reduce local admins to least privilege.",
                                 steps=["Remove temporary/contractor admins",
                                        "Use just-in-time elevation", "Audit local admin group"],
                                 priority=Severity.MEDIUM), sev=Severity.MEDIUM)

            # --- Suspicious libraries / startup items (possible compromise) ---
            suspicious: List[str] = list(dev.get("suspicious_libraries", []) or []) \
                + list(dev.get("startup_items_flagged", []) or [])
            for item in suspicious:
                emit(f"Suspicious library/startup item: {host}",
                     f"flagged artifact present: {item}.",
                     Impact(business="Possible malware persistence on a corporate device.",
                            technical=f"Suspicious artifact: {item}.", blast_radius="host"),
                     Remediation(summary="Isolate and investigate the device.",
                                 steps=["Isolate host", "Triage artifact in EDR",
                                        "Reimage if confirmed malicious"], priority=Severity.HIGH),
                     sev=Severity.HIGH, gap=True)

            # --- Vulnerable installed software ---
            for sw in dev.get("software", []) or []:
                if sw.get("vulnerable"):
                    name = sw.get("name", "package")
                    ver = sw.get("version", "")
                    emit(f"Vulnerable software on endpoint: {name} {ver} ({host})",
                         f"installed {name} {ver} is flagged vulnerable.",
                         Impact(business="Known-vulnerable software increases compromise risk.",
                                technical=f"{name} {ver} flagged vulnerable.", blast_radius="host"),
                         Remediation(summary=f"Update or remove {name}.",
                                     steps=[f"Upgrade {name} to a fixed version",
                                            "Remove if unused"], priority=Severity.MEDIUM),
                         sev=Severity.MEDIUM)

            if os_name not in _SUPPORTED_OS:
                res.notes.append(f"{host}: unrecognized OS '{os_name}' (expected macos/linux/windows)")

        ctx.evidence_store.put("scanner", f"Endpoint scan complete for {len(devices)} device(s)")
        return res
