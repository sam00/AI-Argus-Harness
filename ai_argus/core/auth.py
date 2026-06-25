"""Authenticated vs non-authenticated scan support (credential preflight).

When the operator chooses an *authenticated* scan, the harness performs a
credential-resolution preflight: it discovers which credentials are available
for the services it is about to scan, so the credentialed stages (S1 .. S5.5)
can run *with access* instead of from the outside only. A *non-authenticated*
scan requires no key and behaves exactly as before.

Safe interpretation of "scan the network for an authentication key"
-------------------------------------------------------------------
This module performs **local, read-only credential discovery** scoped to the
target services. It inspects, in priority order:

  1. explicit operator overrides         (service -> env-var NAME or @file path)
  2. the inventory snapshot's ``auth`` map (the network/account credential census)
  3. standard environment variables        (per-service conventions)
  4. standard credential files              (~/.aws/credentials, ~/.kube/config, ...)

It never reads, prints, transmits or stores secret *values* — only the
*reference* (env-var name / file path) and a presence boolean, mirroring the
rest of the harness (``api_key_env`` style: by name, never by value). It does
not probe third-party hosts to harvest keys.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuthMode(str, enum.Enum):
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"


#: Stages that operate against the target and therefore consume credentials.
AUTH_STAGES: List[str] = ["S1", "S1.5", "S2", "S3", "S4", "S5", "S5.5"]


@dataclass(frozen=True)
class CredentialSpec:
    """How to recognise a credential for a service / target type."""

    service: str
    #: each inner list is ANDed (all vars required); the outer list is ORed.
    env_any: List[List[str]] = field(default_factory=list)
    #: standard credential file locations (``~`` is expanded).
    files_any: List[str] = field(default_factory=list)
    description: str = ""


# Credentialed services: an authenticated scan materially changes what they see.
CREDENTIALED_SERVICES = {"aws", "gcp", "kubernetes", "saas", "cicd"}

CREDENTIAL_SPECS: Dict[str, CredentialSpec] = {
    "aws": CredentialSpec(
        "aws",
        env_any=[["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], ["AWS_PROFILE"],
                 ["AWS_SESSION_TOKEN"], ["AWS_WEB_IDENTITY_TOKEN_FILE"]],
        files_any=["~/.aws/credentials", "~/.aws/config"],
        description="AWS API access (IAM / S3 / STS)."),
    "gcp": CredentialSpec(
        "gcp",
        env_any=[["GOOGLE_APPLICATION_CREDENTIALS"], ["CLOUDSDK_AUTH_ACCESS_TOKEN"]],
        files_any=["~/.config/gcloud/application_default_credentials.json"],
        description="GCP API access (IAM / Storage)."),
    "kubernetes": CredentialSpec(
        "kubernetes",
        env_any=[["KUBECONFIG"]],
        files_any=["~/.kube/config",
                   "/var/run/secrets/kubernetes.io/serviceaccount/token"],
        description="Kubernetes API access (kubeconfig / in-cluster SA)."),
    "saas": CredentialSpec(
        "saas",
        env_any=[["OKTA_API_TOKEN"], ["SLACK_TOKEN"], ["GITHUB_TOKEN"],
                 ["SAAS_API_TOKEN"]],
        description="SaaS / OAuth admin API token."),
    "cicd": CredentialSpec(
        "cicd",
        env_any=[["GITHUB_TOKEN"], ["GITLAB_TOKEN"], ["CI_JOB_TOKEN"]],
        description="CI/CD platform token."),
    # External scanners may OPTIONALLY use HTTP auth but never require it.
    "domain": CredentialSpec(
        "domain", env_any=[["ARGUS_HTTP_BEARER"]],
        description="Optional HTTP bearer for authenticated probes."),
    "application": CredentialSpec(
        "application", env_any=[["ARGUS_HTTP_BEARER"]],
        description="Optional HTTP bearer for authenticated probes."),
}


@dataclass
class CredentialStatus:
    service: str
    present: bool
    source: str = ""        # override:env | override:file | inventory | env | file
    ref: str = ""           # env var NAME / file path — never a secret value
    required: bool = True   # credentialed service vs external-optional
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service, "present": self.present,
            "source": self.source, "ref": self.ref,
            "required": self.required, "detail": self.detail,
        }


@dataclass
class AuthResolution:
    """Outcome of the credential preflight for one run."""

    mode: AuthMode = AuthMode.UNAUTHENTICATED
    statuses: Dict[str, CredentialStatus] = field(default_factory=dict)

    @property
    def required_services(self) -> List[str]:
        return [s for s, st in self.statuses.items() if st.required]

    @property
    def authenticated_services(self) -> List[str]:
        return [s for s, st in self.statuses.items() if st.present]

    @property
    def missing_services(self) -> List[str]:
        return [s for s, st in self.statuses.items() if st.required and not st.present]

    @property
    def satisfied(self) -> bool:
        """True when authenticated mode has a credential for every required service."""
        return self.mode is AuthMode.AUTHENTICATED and not self.missing_services

    def label(self, service: str) -> str:
        """Per-service mode a scanner should report (authenticated / unauthenticated)."""
        if self.mode is not AuthMode.AUTHENTICATED:
            return AuthMode.UNAUTHENTICATED.value
        st = self.statuses.get(service)
        return AuthMode.AUTHENTICATED.value if (st and st.present) \
            else AuthMode.UNAUTHENTICATED.value

    def for_service(self, service: str) -> Optional[CredentialStatus]:
        return self.statuses.get(service)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "applies_to_stages": list(AUTH_STAGES),
            "satisfied": self.satisfied,
            "authenticated_services": self.authenticated_services,
            "missing_services": self.missing_services,
            "services": {s: st.to_dict() for s, st in self.statuses.items()},
        }


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def _expand(p: str) -> Path:
    return Path(os.path.expanduser(p))


def services_for_scanners(scanners: List[str]) -> List[str]:
    """Map planned scanner names to credential service keys (order-preserving)."""
    out: List[str] = []
    for s in scanners:
        if s in CREDENTIAL_SPECS and s not in out:
            out.append(s)
    return out


def _inventory_auth(inventory: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(inventory, dict):
        return None
    census = inventory.get("auth") or inventory.get("credentials")
    return census if isinstance(census, dict) else None


def _discover_one(spec: CredentialSpec, override: Optional[str],
                  inv_auth: Optional[Dict[str, Any]]) -> CredentialStatus:
    required = spec.service in CREDENTIALED_SERVICES

    # 1) explicit operator override: env var NAME, or @path to a key file.
    if override:
        if override.startswith("@"):
            path = override[1:]
            present = _expand(path).exists()
            return CredentialStatus(
                spec.service, present, source="override:file", ref=path,
                required=required,
                detail="operator-supplied key file"
                       if present else "supplied key file not found")
        present = bool(os.environ.get(override))
        return CredentialStatus(
            spec.service, present, source="override:env", ref=override,
            required=required,
            detail=f"operator-supplied env var {override}"
                   + ("" if present else " is not set"))

    # 2) inventory credential census (the "network" snapshot of available keys).
    if inv_auth and spec.service in inv_auth:
        entry = inv_auth[spec.service]
        if isinstance(entry, dict):
            present = bool(entry.get("present", True))
            ref = str(entry.get("ref", entry.get("source", "inventory")))
        else:
            present, ref = bool(entry), "inventory"
        return CredentialStatus(spec.service, present, source="inventory", ref=ref,
                                required=required,
                                detail="declared in inventory credential census")

    # 3) standard environment variables.
    for combo in spec.env_any:
        if combo and all(os.environ.get(v) for v in combo):
            return CredentialStatus(spec.service, True, source="env",
                                    ref="+".join(combo), required=required,
                                    detail="discovered in environment")

    # 4) standard credential files.
    for f in spec.files_any:
        if _expand(f).exists():
            return CredentialStatus(spec.service, True, source="file", ref=f,
                                    required=required,
                                    detail="discovered standard credential file")

    return CredentialStatus(spec.service, False, required=required,
                            detail="no credential discovered")


def discover_credentials(services: List[str],
                         inventory: Optional[Dict[str, Any]] = None,
                         overrides: Optional[Dict[str, str]] = None
                         ) -> Dict[str, CredentialStatus]:
    overrides = overrides or {}
    inv_auth = _inventory_auth(inventory)
    out: Dict[str, CredentialStatus] = {}
    for svc in services:
        spec = CREDENTIAL_SPECS.get(svc)
        if spec is not None:
            out[svc] = _discover_one(spec, overrides.get(svc), inv_auth)
    return out


def unauthenticated(services: Optional[List[str]] = None) -> AuthResolution:
    statuses: Dict[str, CredentialStatus] = {}
    for svc in (services or []):
        if svc in CREDENTIAL_SPECS:
            statuses[svc] = CredentialStatus(
                svc, present=False, required=svc in CREDENTIALED_SERVICES,
                detail="non-authenticated scan")
    return AuthResolution(AuthMode.UNAUTHENTICATED, statuses)


def resolve(mode: AuthMode, services: List[str],
            inventory: Optional[Dict[str, Any]] = None,
            overrides: Optional[Dict[str, str]] = None) -> AuthResolution:
    if mode is AuthMode.UNAUTHENTICATED:
        return unauthenticated(services)
    return AuthResolution(AuthMode.AUTHENTICATED,
                          discover_credentials(services, inventory, overrides))


def parse_overrides(pairs: Optional[List[str]]) -> Dict[str, str]:
    """Parse ``SERVICE=REF`` CLI pairs into an overrides map.

    REF is an env-var NAME or ``@/path`` to a key file — never a secret value.
    """
    out: Dict[str, str] = {}
    for p in pairs or []:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k, v = k.strip(), v.strip()
        if k and v:
            out[k] = v
    return out
