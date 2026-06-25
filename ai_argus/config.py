"""Configuration model for AI-Argus-Harness.

Supports a layered configuration:

  * Global config:   ~/.config/ai-argus/config.json   (provider, api keys ref, budget)
  * Project config:  ./argus.yaml or ./argus.json      (profile, model, stealth, ...)

YAML is optional. If PyYAML is not installed we transparently fall back to JSON
so the core harness has zero hard dependencies (offline / air-gapped friendly).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Cost / AI modes
# --------------------------------------------------------------------------- #
COST_MODES = ["minimal", "balanced", "research", "deep-research", "offline"]
STEALTH_MODES = ["passive", "safe", "auth", "stealth"]
PROFILES = [
    "quick", "enterprise", "cloud", "identity", "kubernetes",
    "api", "endpoint", "supply-chain", "stealth", "executive", "deep-research",
]

# Which scanners run for each scan profile.
PROFILE_SCANNERS: Dict[str, List[str]] = {
    "quick": ["domain", "network"],
    "enterprise": ["domain", "network", "secrets", "supply_chain", "aws", "gcp",
                   "kubernetes", "saas", "cicd", "data_exposure", "endpoint"],
    "cloud": ["aws", "gcp", "data_exposure"],
    "identity": ["aws", "gcp", "saas", "kubernetes"],
    "kubernetes": ["kubernetes"],
    "api": ["domain", "application"],
    "endpoint": ["endpoint", "network"],
    "supply-chain": ["supply_chain", "secrets", "cicd"],
    "stealth": ["domain", "network"],
    "executive": ["domain", "network", "secrets", "supply_chain", "aws"],
    "deep-research": ["domain", "network", "secrets", "supply_chain", "aws", "gcp",
                      "kubernetes", "saas", "cicd", "data_exposure", "application",
                      "endpoint"],
}


def config_home() -> Path:
    base = os.environ.get("AI_ARGUS_HOME")
    if base:
        return Path(base)
    return Path(os.path.expanduser("~")) / ".config" / "ai-argus"


@dataclass
class Budget:
    daily_usd: float = 5.0
    monthly_usd: float = 100.0
    max_scan_usd: float = 2.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModelRouting:
    """Per-stage model routing (multi-model, no vendor lock-in)."""

    reasoning: str = "offline"
    code: str = "offline"
    summaries: str = "offline"
    validation: str = "offline"
    reports: str = "offline"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Config:
    # provider / model
    provider: str = "offline"          # openai|anthropic|google|azure|ollama|...|offline
    model: str = "auto"
    api_key_env: str = ""              # name of env var holding the key (never the key itself)
    base_url: str = ""                 # for custom OpenAI-compatible / local endpoints
    routing: ModelRouting = field(default_factory=ModelRouting)

    # run behavior
    profile: str = "enterprise"
    cost_mode: str = "balanced"
    stealth_mode: str = "passive"
    strict: bool = False               # --strict hallucination mode
    diff: bool = False                 # --diff incremental mode (vs baseline)
    auth_scan: bool = False            # authenticated scan: resolve & use credentials
    workers: int = 8
    auto_workers: bool = False
    confidence_threshold: str = "medium"
    budget: Budget = field(default_factory=Budget)

    # outputs
    reports: List[str] = field(default_factory=lambda: ["json", "markdown", "sarif"])
    identity_graph: bool = True
    cache: bool = True
    notify_slack: bool = False         # post a run summary to a Slack webhook on completion
                                       # (URL from $ARGUS_SLACK_WEBHOOK / --slack-webhook)

    # project metadata
    project_name: str = "default"

    # ------------------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Config":
        d = dict(d or {})
        budget = d.pop("budget", None)
        routing = d.pop("routing", None)
        cfg = Config()
        for k, v in d.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        if isinstance(budget, dict):
            cfg.budget = Budget(**{k: v for k, v in budget.items() if k in Budget().__dict__})
        if isinstance(routing, dict):
            cfg.routing = ModelRouting(**{k: v for k, v in routing.items()
                                          if k in ModelRouting().__dict__})
        return cfg

    # ------------------------------------------------------------------ #
    def save_global(self) -> Path:
        home = config_home()
        home.mkdir(parents=True, exist_ok=True)
        path = home / "config.json"
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    @staticmethod
    def load() -> "Config":
        """Load global config, then overlay project config if present."""
        cfg = Config()
        gpath = config_home() / "config.json"
        if gpath.exists():
            try:
                cfg = Config.from_dict(json.loads(gpath.read_text()))
            except Exception:
                pass
        # overlay project config from CWD
        proj = _load_project_config(Path.cwd())
        if proj:
            merged = cfg.to_dict()
            merged.update(proj)
            cfg = Config.from_dict(merged)
        return cfg


def _load_project_config(cwd: Path) -> Optional[Dict[str, Any]]:
    for name in ("argus.yaml", "argus.yml", "argus.json"):
        p = cwd / name
        if not p.exists():
            continue
        text = p.read_text()
        if name.endswith(".json"):
            try:
                return _flatten_project(json.loads(text))
            except Exception:
                return None
        # YAML
        try:
            import yaml  # type: ignore
            return _flatten_project(yaml.safe_load(text) or {})
        except Exception:
            return None
    return None


def _flatten_project(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Map the `project:` document onto Config fields."""
    proj = doc.get("project", doc) or {}
    out: Dict[str, Any] = {}
    mapping = {
        "name": "project_name",
        "profile": "profile",
        "model": "model",
        "stealth": "stealth_mode",
        "budget": "cost_mode",
        "workers": "workers",
        "cache": "cache",
        "identity_graph": "identity_graph",
        "provider": "provider",
        "notify_slack": "notify_slack",
    }
    for k, v in proj.items():
        if k == "reports" and isinstance(v, list):
            out["reports"] = v
        elif k == "stealth" and isinstance(v, bool):
            out["stealth_mode"] = "stealth" if v else "passive"
        elif k == "workers" and v == "auto":
            out["auto_workers"] = True
        elif k == "cache" and isinstance(v, str):
            out["cache"] = v.lower() == "enabled"
        elif k in mapping:
            out[mapping[k]] = v
    return out
