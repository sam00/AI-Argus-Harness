# Security Policy

AI-Argus-Harness is a defensive/offensive **security assessment** tool. We take
the security of the tool itself — and of the people who run it — seriously.

## Supported versions

The project is pre-1.0. Security fixes are applied to the latest released
version and the `main` branch.

| Version | Supported |
| ------- | --------- |
| `0.1.x` | ✅ |
| `< 0.1` | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use **GitHub Private Vulnerability Reporting** instead:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Provide a clear description, affected version/commit, reproduction steps,
   and impact.

This opens a private advisory visible only to maintainers. If private reporting
is unavailable, contact the maintainer through the address listed on the GitHub
profile of the repository owner.

### What to expect

| Stage | Target |
| ----- | ------ |
| Acknowledgement | within **3 business days** |
| Triage + severity assessment | within **7 business days** |
| Fix or mitigation plan | within **30 days** for High/Critical |
| Coordinated public disclosure | after a fix is available (or 90 days, whichever is sooner) |

We will credit reporters in the advisory and `CHANGELOG.md` unless you prefer to
remain anonymous.

## Scope

In scope:

- Code execution, path traversal, or injection in the harness, CLI, or
  reporting/exporter code.
- Leakage of secrets/credentials by the tool (e.g. secrets written to reports,
  logs, or evidence in plaintext).
- Bypasses of the safety controls described below.

Out of scope:

- Findings produced **about your target** (those are the tool's normal output).
- Issues requiring a malicious local environment you fully control.
- Vulnerabilities in optional third-party providers/SDKs you choose to enable.

## Safe harbor

We support good-faith security research. If you make a good-faith effort to
comply with this policy, we will not pursue or support legal action against you,
and will work with you to understand and resolve the issue quickly.

## Tool safety model (by design)

AI-Argus-Harness is built to be safe to run:

- **Read-only by default.** Active checks require explicit `--safe` / `--auth`
  modes and human approval.
- **No destructive actions.** The harness never performs credential dumping,
  persistence, lateral movement, or data exfiltration.
- **Secret redaction.** The evidence store redacts secrets; only **references**
  (env-var names / file paths) are recorded for credentials — never secret
  values.
- **No telemetry.** The tool makes **no outbound network calls** except (a) the
  scans you explicitly request against targets you specify, and (b) optional
  LLM provider calls you explicitly configure. There is no analytics, no
  phone-home, and no usage collection. The default `offline` provider makes
  **zero** external calls.

## Responsible / authorized use

Only run AI-Argus-Harness against systems you **own** or are **explicitly
authorized** to assess. See the "Safe / authorized-use policy" section of the
[README](README.md). Unauthorized scanning may be illegal.
