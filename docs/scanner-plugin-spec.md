# Scanner Plugin Specification

Scanners are the only components allowed to produce evidence. They must be
read-only by default, deterministic, and must never call an LLM.

## Contract

```python
from ai_argus.scanners.base import Scanner, ScannerResult, register
from ai_argus.core.context import ScanContext
from ai_argus.models import Asset, AssetType, Confidence, Evidence, Finding

@register
class MyScanner(Scanner):
    name = "myscanner"          # unique registry key
    category = "custom"
    description = "What it checks."
    requires_network = False
    allowed_stealth = ("passive", "safe", "auth", "stealth")

    def applicable(self, ctx: ScanContext) -> bool:
        return True             # decide if this scanner runs for the target

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        asset = Asset.make(AssetType.APP, "thing")
        ctx.asset_graph.add(asset)
        ref = ctx.evidence_store.put("scanner", "observed X")
        res.findings.append(Finding(
            title="X is misconfigured",
            asset=asset, scanner=self.name, category=self.category,
            evidence=[Evidence("scanner", "observed X", Confidence.HIGH, raw_ref=ref)],
            # ... impact / remediation / owner / identity_path as available
        ))
        return res
```

## Rules

- Attach at least one `Evidence` (with a valid `source`) to every candidate finding.
- Use `ctx.asset_graph` / `ctx.identity_graph` to register nodes and edges so
  chaining and blast-radius analysis work.
- Respect `ctx.config.stealth_mode`; only probe actively in `safe`/`auth`/`stealth`.
- Never perform destructive actions. Read-only only.
- Let the reliability layer and completeness gate decide promotion — do not
  fabricate fields you do not have evidence for.

## Distribution

Ship external scanners as a Python package that exposes the entry-point group:

```toml
[project.entry-points."ai_argus.scanners"]
myscanner = "my_pkg.scanner:MyScanner"
```

`argus plugins` lists everything registered, including loaded entry-point plugins.
