# Coverage layers

This document maps AI-Argus-Harness against the **12 enterprise coverage layers**
and their sub-capabilities, with an **honest implementation status** for each item.

The harness is **evidence-first and deterministic**: cloud / identity / SaaS /
Kubernetes / endpoint layers are driven by a normalized **inventory snapshot**
(the same shape a credentialed collector or EDR/MDM agent would export), so checks
are replayable and safe. Live SDK calls, agents, CVE feeds, and managed-service
integrations (GuardDuty, Security Command Center, SBOM CVE matching, etc.) are
intentionally modeled as snapshot inputs and/or tracked on the roadmap rather than
claimed as live capabilities.

## Legend

| Mark | Meaning |
| --- | --- |
| ✅ | **Implemented** — a deterministic check exists and is tested |
| ◑ | **Partial** — a related/narrower check exists; full depth is planned |
| 🔜 | **Planned** — on the roadmap; not yet implemented |

> "Implemented" means the harness produces an evidence-backed finding for that
> capability from supported input (live for `domain`/`network`; inventory snapshot
> for cloud/identity/endpoint; local path for code-based scanners).

## Summary

| # | Layer | Scanner | Status | Input |
| --- | --- | --- | --- | --- |
| 6.1 | Domain | `domain` | ◑ core implemented | live (stdlib) |
| 6.2 | AWS | `aws` | ◑ core implemented | inventory `aws` |
| 6.3 | GCP | `gcp` | ◑ core implemented | inventory `gcp` |
| 6.4 | Network | `network` | ◑ core implemented | live (stdlib) |
| 6.5 | Endpoint | `endpoint` | ✅ implemented | inventory `devices` |
| 6.6 | Kubernetes | `kubernetes` | ◑ core implemented | inventory `kubernetes` |
| 6.7 | Application | `application` | ◑ core implemented | inventory `endpoints` |
| 6.8 | SaaS / Third-Party | `saas` | ◑ core implemented | inventory `saas` |
| 6.9 | Supply Chain | `supply_chain` | ◑ core implemented | local path |
| 6.10 | CI/CD | `cicd` | ◑ core implemented | local path |
| 6.11 | Secrets | `secrets` | ◑ core implemented | local path |
| 6.12 | Data Exposure | `data_exposure` | ◑ core implemented | inventory `data_stores` |

All 12 layers have a working scanner. Within each layer, the highest-signal
checks are implemented; broader enumeration depth is tracked below.

---

## 6.1 Domain Scanner — `domain`

| Sub-capability | Status |
| --- | --- |
| Root domain mapping | ✅ |
| DNS records | ◑ (A/AAAA resolution) |
| Subdomain discovery | ◑ (common-name passive resolution) |
| Certificate transparency | 🔜 |
| MX / SPF / DKIM / DMARC | 🔜 |
| Web service fingerprinting | ◑ (TLS certificate inspection) |
| Takeover risk detection | 🔜 |
| Domain-to-asset linking | ✅ |

## 6.2 AWS Scanner — `aws`

| Sub-capability | Status |
| --- | --- |
| Account inventory | ✅ |
| IAM users / roles / policies | ◑ (privileged + externally-assumable roles) |
| Cross-account trust | ✅ |
| EC2 / ELB / ECS / EKS | 🔜 |
| S3 exposure | ✅ |
| Security groups | 🔜 |
| Lambda | 🔜 |
| Secrets Manager | 🔜 |
| CloudTrail | ◑ (used as a detection-gap signal) |
| GuardDuty | 🔜 |
| Public exposure graph | ✅ (asset + identity graph) |

## 6.3 GCP Scanner — `gcp`

| Sub-capability | Status |
| --- | --- |
| Project inventory | ✅ |
| IAM bindings | ◑ |
| Service accounts | ✅ (owner-role / over-privileged) |
| Workload identity | 🔜 |
| Compute Engine | 🔜 |
| GKE | 🔜 (see `kubernetes`) |
| Cloud Storage | ✅ (public bucket exposure) |
| Cloud Run / Functions | 🔜 |
| Firewall rules | 🔜 |
| Secret Manager | 🔜 |
| Audit logs | 🔜 |
| Security Command Center | 🔜 |

## 6.4 Network Scanner — `network`

| Sub-capability | Status |
| --- | --- |
| CIDR mapping | ◑ |
| Host discovery | ✅ |
| Open port discovery | ✅ |
| Service fingerprinting | ✅ (SSH, RDP, SMB, FTP, Telnet, SMTP, IMAP, POP3, HTTP/S, MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB) |
| TLS review | ◑ (via `domain`) |
| Routing map | 🔜 |
| Segmentation map | 🔜 |
| Firewall exposure | ◑ (risky-if-public services) |
| Network-to-cloud correlation | 🔜 |

## 6.5 Endpoint Scanner — `endpoint`

Driven by an endpoint-agent / EDR / MDM **device inventory snapshot** (`devices`).

| Sub-capability | Status |
| --- | --- |
| macOS agent | ✅ (snapshot ingest) |
| Linux agent | ✅ (snapshot ingest) |
| Windows agent | ✅ (snapshot ingest) |
| Installed software | ✅ (vulnerable-software flag) |
| Running services | ◑ (listening ports) |
| Listening ports | ✅ (risky services: RDP/SMB/SSH/Telnet/VNC/WinRM) |
| Local users / groups | ✅ (excess / temporary local admins) |
| Patch posture | ✅ (patch-age threshold) |
| EDR status | ✅ (missing / unhealthy → detection gap) |
| Disk encryption | ✅ (FileVault / BitLocker / LUKS) |
| Startup items | ✅ (flagged startup items) |
| Suspicious libraries | ✅ |

## 6.6 Kubernetes Scanner — `kubernetes`

| Sub-capability | Status |
| --- | --- |
| Cluster inventory | ✅ |
| Namespace mapping | ◑ |
| Workloads | ◑ (pods) |
| RBAC | ✅ (`cluster-admin` bindings) |
| Service accounts | ✅ |
| Network policies | 🔜 |
| Ingress | 🔜 |
| Secrets | 🔜 |
| Images | 🔜 |
| Admission controllers | 🔜 |
| Pod security | ✅ (privileged pods) |
| Runtime exposure | 🔜 |

## 6.7 Application Scanner — `application`

| Sub-capability | Status |
| --- | --- |
| API inventory | ✅ |
| AuthN / AuthZ review | ◑ (missing authentication detected; AuthZ planned) |
| Session handling | 🔜 |
| Business logic paths | 🔜 |
| Input validation | 🔜 |
| Admin surfaces | ✅ (`/admin`, `/actuator`, etc.) |
| Exposed debug routes | ✅ |
| Dependency usage | 🔜 (see `supply_chain`) |
| Data access paths | 🔜 |

## 6.8 SaaS / Third-Party Scanner — `saas`

Provider-agnostic over an inventory `saas` snapshot (Okta shown in the demo).

| Sub-capability | Status |
| --- | --- |
| Google Workspace / Microsoft 365 | 🔜 |
| Okta / Entra / OneLogin | ◑ (provider-agnostic OAuth analysis) |
| Slack / Teams | 🔜 |
| GitHub / GitLab | 🔜 |
| Jira / Confluence | 🔜 |
| Salesforce | 🔜 |
| Datadog / Sentry | 🔜 |
| OAuth app grants | ✅ |
| External users | 🔜 |
| Privileged integrations | ✅ (over-scoped / admin-scope apps) |

## 6.9 Supply Chain Scanner — `supply_chain`

| Sub-capability | Status |
| --- | --- |
| Package manifests | ✅ |
| Lockfiles | ◑ |
| SBOM generation | ◑ (lightweight in-memory SBOM) |
| Known vulnerability matching | 🔜 (no CVE claimed without package+version+source) |
| Malicious package heuristics | ◑ |
| Typosquat detection | ✅ |
| Dependency confusion risk | ◑ |
| Maintainer risk signals | 🔜 |
| Build scripts | 🔜 |
| Artifact provenance | 🔜 |

## 6.10 CI/CD Scanner — `cicd`

| Sub-capability | Status |
| --- | --- |
| GitHub Actions | ✅ (unpinned actions, broad permissions) |
| GitLab CI | ◑ |
| Jenkins | 🔜 |
| Build secrets | ✅ (plaintext secrets in env) |
| Runner exposure | 🔜 |
| Deployment permissions | ◑ (broad `permissions:`) |
| Branch protection | 🔜 |
| CODEOWNERS | 🔜 |
| Artifact signing | 🔜 |
| Release provenance | 🔜 |

## 6.11 Secrets Scanner — `secrets`

| Sub-capability | Status |
| --- | --- |
| Git history | 🔜 |
| CI/CD variables | ◑ (YAML/workflow files in path) |
| Container images | 🔜 |
| Kubernetes secrets | 🔜 |
| Cloud secret stores | 🔜 |
| Endpoint files | 🔜 |
| Logs | 🔜 |
| Environment variables | ◑ (`.env` files) |
| Hardcoded credentials | ✅ (entropy + placeholder filtered) |

## 6.12 Data Exposure Scanner — `data_exposure`

| Sub-capability | Status |
| --- | --- |
| Public buckets | ✅ (via `aws`/`gcp`) |
| Databases | ✅ (public datastores) |
| Backups | 🔜 |
| Logs | ◑ (logging-disabled signal) |
| Object storage | ✅ |
| SaaS exports | 🔜 |
| PII indicators | ✅ |
| PHI indicators | ◑ (supported data class) |
| PCI indicators | ✅ |
| Sensitive internal datasets | 🔜 |

---

## Roadmap themes

The 🔜 items cluster into a few tracks (see also the README **Roadmap**):

- **Live provider depth** (opt-in SDKs): broader AWS/GCP service enumeration,
  GuardDuty / Security Command Center, managed secret stores.
- **Supply-chain depth**: SBOM export + CVE matching, provenance, maintainer risk.
- **Secrets breadth**: git history, container images, K8s/cloud secret stores.
- **SaaS breadth**: first-class connectors per provider.
- **Endpoint/EDR**: ingest from real EDR/MDM connectors (the `endpoint-agent`
  evidence source) in addition to inventory snapshots.

Contributions that deepen any layer are welcome — see
[`CONTRIBUTING.md`](../CONTRIBUTING.md) and
[`docs/scanner-plugin-spec.md`](scanner-plugin-spec.md).
