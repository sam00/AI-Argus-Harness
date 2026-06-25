# Enterprise Deployment

## Configuration layers

1. **Global config** — `~/.config/ai-argus/config.json` (provider, model,
   API-key env var name, budget). Created by `argus init`.
2. **Project config** — `argus.yaml` / `argus.json` in the project root.

Example `argus.yaml`:

```yaml
project:
  name: production
  profile: enterprise
  model: auto
  stealth: true
  budget: balanced
  workers: auto
  cache: enabled
  identity_graph: enabled
  sarif: true
  reports:
    - markdown
    - json
    - sarif
```

> API keys are never stored in config. Set `api_key_env` to the **name** of the
> environment variable that holds the key.

## Security posture

- Read-only scanning by default; active checks require `--safe`/`--auth`.
- Secret redaction in the evidence store.
- Least-privilege, audit-ready evidence trail; replayable runs.
- No credential dumping, persistence, lateral movement, or exfiltration.

## Cost governance

- Cost modes: `minimal`, `balanced`, `research`, `deep-research`, `offline`.
- `argus cost` shows daily/monthly spend, tokens, per-model usage, and estimates.
- Budgets (`daily`, `monthly`, `max_scan`) drive automatic fallback to cheaper
  models / offline reasoning.

## Integration

- **SARIF** output integrates with code-scanning dashboards.
- **tickets.json** is an owner-based export for Jira / ServiceNow.
- **executive.md** is a leadership-ready summary.
- External scanners install via the `ai_argus.scanners` entry-point group.

## Scaling

- Plugin-based scanners with parallel execution (`--workers`, `--auto-workers`).
- Incremental scans (`--diff`) target only changed assets.
- Inventory-snapshot model lets credentialed cloud/identity checks run from a
  central collector, supporting multi-account / multi-tenant environments.
