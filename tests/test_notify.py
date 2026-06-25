"""Tests for the Slack completion-notification reporter."""

import json
import urllib.error

from ai_argus.core.orchestrator import RunResult
from ai_argus.models import Asset, AssetType, Finding, Severity
from ai_argus.reporting import build_slack_payload, notify_slack, resolve_webhook
from ai_argus.reporting import notify as notify_mod


def _finding(title, sev, score):
    return Finding(title=title, asset=Asset.make(AssetType.CLOUD, "bucket-x"),
                   severity=sev, risk_score=score)


def _result():
    return RunResult(
        run_id="RUN-abc123", version="0.1.0", target="example.com",
        profile="enterprise", cost_mode="balanced", stealth_mode="passive",
        started="2025-01-01T00:00:00Z", finished="2025-01-01T00:05:00Z",
        findings=[_finding("Public S3 bucket", Severity.CRITICAL, 9.1),
                  _finding("Weak TLS", Severity.MEDIUM, 4.2)],
    )


def test_resolve_webhook_prefers_explicit_then_env(monkeypatch):
    monkeypatch.setenv(notify_mod.WEBHOOK_ENV, "https://env.example/hook")
    assert resolve_webhook("https://explicit.example/hook") == "https://explicit.example/hook"
    assert resolve_webhook() == "https://env.example/hook"
    monkeypatch.delenv(notify_mod.WEBHOOK_ENV, raising=False)
    assert resolve_webhook() is None
    assert resolve_webhook("   ") is None


def test_build_slack_payload_shape():
    payload = build_slack_payload(_result(), report_dir="argus-runs/RUN-abc123")
    assert "example.com" in payload["text"]
    assert "1 critical" in payload["text"]

    block_types = [b["type"] for b in payload["blocks"]]
    assert block_types[0] == "header"
    assert "section" in block_types
    assert block_types[-1] == "context"

    # Must be JSON-serializable — the webhook transport requires it.
    json.dumps(payload)

    # Top findings are ordered by risk score (critical before medium).
    top = next(b for b in payload["blocks"]
               if b.get("text", {}).get("text", "").startswith("*Top findings:*"))
    body = top["text"]["text"]
    assert body.index("Public S3 bucket") < body.index("Weak TLS")


class _FakeResp:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getcode(self):
        return self.status


def test_notify_slack_posts_json_payload(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["content_type"] = req.headers.get("Content-type")
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResp(200)

    monkeypatch.setattr(notify_mod.urllib.request, "urlopen", fake_urlopen)
    assert notify_slack(_result(), "https://hooks.slack.test/abc") is True
    assert captured["url"] == "https://hooks.slack.test/abc"
    assert captured["method"] == "POST"
    assert captured["content_type"] == "application/json"
    assert "blocks" in captured["body"] and "text" in captured["body"]


def test_notify_slack_failure_is_non_fatal(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(notify_mod.urllib.request, "urlopen", boom)
    assert notify_slack(_result(), "https://hooks.slack.test/abc") is False
    # An empty webhook short-circuits without attempting a request.
    assert notify_slack(_result(), "") is False
