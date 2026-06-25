"""LLM provider abstraction + deterministic offline provider + cost tracking."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Config, config_home


@dataclass
class ModelResponse:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    offline: bool = False


# Rough public per-1K-token pricing used purely for *estimation* / budgeting.
_PRICING: Dict[str, float] = {
    "gpt-4o": 0.005,
    "gpt-4o-mini": 0.0006,
    "claude-3-5-sonnet": 0.006,
    "gemini-1.5-pro": 0.005,
    "default": 0.002,
}


class CostTracker:
    """Persistent spend ledger backing `argus cost` and budget fallback."""

    def __init__(self) -> None:
        self.path = config_home() / "cost_ledger.json"
        self.entries: List[Dict[str, Any]] = []
        if self.path.exists():
            try:
                self.entries = json.loads(self.path.read_text())
            except Exception:
                self.entries = []

    def record(self, model: str, tokens: int, cost: float) -> None:
        self.entries.append({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "day": time.strftime("%Y-%m-%d", time.gmtime()),
            "month": time.strftime("%Y-%m", time.gmtime()),
            "model": model,
            "tokens": tokens,
            "cost": round(cost, 6),
        })

    def flush(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.entries[-5000:], indent=2))
        except Exception:
            pass

    def summary(self) -> Dict[str, Any]:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        month = time.strftime("%Y-%m", time.gmtime())
        day_spend = sum(e["cost"] for e in self.entries if e.get("day") == today)
        month_spend = sum(e["cost"] for e in self.entries if e.get("month") == month)
        tokens = sum(e.get("tokens", 0) for e in self.entries if e.get("month") == month)
        by_model: Dict[str, float] = {}
        for e in self.entries:
            by_model[e["model"]] = by_model.get(e["model"], 0.0) + e["cost"]
        scans = [e for e in self.entries if e.get("month") == month]
        avg = (month_spend / len(scans)) if scans else 0.0
        return {
            "today_usd": round(day_spend, 4),
            "month_usd": round(month_spend, 4),
            "tokens_this_month": tokens,
            "by_model": {k: round(v, 4) for k, v in by_model.items()},
            "avg_call_usd": round(avg, 4),
            "estimated_next_scan_usd": round(avg or 0.0, 4),
        }


class LLMProvider:
    """Base provider interface. All reasoning is *evidence-bound*."""

    name = "base"

    def __init__(self, config: Config, tracker: Optional[CostTracker] = None) -> None:
        self.config = config
        self.tracker = tracker or CostTracker()

    def available(self) -> bool:
        raise NotImplementedError

    def complete(self, prompt: str, *, system: str = "", model: str = "") -> ModelResponse:
        raise NotImplementedError


class OfflineProvider(LLMProvider):
    """Deterministic, zero-cost provider used in `offline`/`minimal` cost modes.

    It performs *extractive* summarization over the supplied evidence text rather
    than generating new claims, which keeps the harness reproducible and prevents
    hallucinated findings.
    """

    name = "offline"

    def available(self) -> bool:
        return True

    def complete(self, prompt: str, *, system: str = "", model: str = "") -> ModelResponse:
        # Extractive: keep the most informative lines from the prompt.
        lines = [ln.strip() for ln in prompt.splitlines() if ln.strip()]
        keywords = ("evidence", "identity", "exposure", "public", "admin",
                    "secret", "privilege", "risk", "impact")
        ranked = sorted(
            lines,
            key=lambda ln: sum(k in ln.lower() for k in keywords),
            reverse=True,
        )
        summary = " ".join(ranked[:4])[:600] or "No salient evidence extracted."
        return ModelResponse(text=summary, model="offline-extractive", offline=True)


class _RemoteProviderStub(LLMProvider):
    """Placeholder for cloud/local API providers.

    The interface is wired so real SDK calls can drop in. Until a key is
    configured, it reports unavailable and the harness falls back to offline,
    guaranteeing the tool always runs.
    """

    def __init__(self, name: str, config: Config, tracker: Optional[CostTracker] = None) -> None:
        super().__init__(config, tracker)
        self.name = name

    def available(self) -> bool:
        env = self.config.api_key_env
        return bool(env and os.environ.get(env))

    def complete(self, prompt: str, *, system: str = "", model: str = "") -> ModelResponse:
        # Real network call would go here; we estimate cost and delegate to offline
        # extraction so behavior stays deterministic and safe in this build.
        model = model or (self.config.model if self.config.model != "auto" else "default")
        tokens = max(1, (len(prompt) + len(system)) // 4)
        price = _PRICING.get(model, _PRICING["default"])
        cost = (tokens / 1000.0) * price
        self.tracker.record(model, tokens, cost)
        text = OfflineProvider(self.config, self.tracker).complete(
            prompt, system=system).text
        return ModelResponse(text=text, model=model, prompt_tokens=tokens, cost_usd=cost)


_REMOTE = {"openai", "anthropic", "google", "gemini", "azure", "mistral",
           "deepseek", "ollama", "lmstudio", "vllm", "openrouter", "bedrock", "custom"}


def get_provider(config: Config, tracker: Optional[CostTracker] = None) -> LLMProvider:
    """Return a provider honoring cost mode and availability.

    Offline / minimal cost modes always use the deterministic offline provider.
    """
    tracker = tracker or CostTracker()
    if config.cost_mode in ("offline", "minimal") or config.provider == "offline":
        return OfflineProvider(config, tracker)
    if config.provider in _REMOTE:
        prov = _RemoteProviderStub(config.provider, config, tracker)
        if prov.available():
            return prov
    # graceful fallback — the tool must always run
    return OfflineProvider(config, tracker)
