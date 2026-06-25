"""Slack notification on scan completion.

Posts a concise run summary to a Slack Incoming Webhook when a scan finishes,
so teams get notified the moment a task is complete. Uses only the standard
library (``urllib``), keeping the core harness zero-dependency and
offline/air-gapped friendly.

The webhook URL is a secret and is therefore *never* written to config files or
reports. Resolve it from the ``ARGUS_SLACK_WEBHOOK`` environment variable
(preferred) or an explicit ``--slack-webhook`` argument.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

WEBHOOK_ENV = "ARGUS_SLACK_WEBHOOK"

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def resolve_webhook(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the Slack webhook URL from an explicit value or the environment."""
    url = (explicit or os.environ.get(WEBHOOK_ENV, "") or "").strip()
    return url or None


def _severity_line(by_severity: Dict[str, int]) -> str:
    parts = [f"{sev}: {by_severity[sev]}" for sev in _SEV_ORDER if by_severity.get(sev)]
    return "  |  ".join(parts) if parts else "none"


def build_slack_payload(result, *, report_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Build a Slack Incoming-Webhook payload (Block Kit + plain-text fallback)."""
    s = result.summary()
    by_sev = s.get("by_severity", {})
    crit = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)

    headline = "AI-Argus-Harness — scan complete"
    fallback = (
        f"{headline}: {result.target} — {s['total_findings']} findings "
        f"({crit} critical, {high} high), {s['chains']} attack paths, "
        f"{s['review_queue']} in review."
    )

    fields = [
        {"type": "mrkdwn", "text": f"*Target:*\n{result.target}"},
        {"type": "mrkdwn", "text": f"*Run:*\n`{result.run_id}`"},
        {"type": "mrkdwn",
         "text": (f"*Profile:*\n{result.profile} "
                  f"(cost={result.cost_mode}, stealth={result.stealth_mode})")},
        {"type": "mrkdwn",
         "text": (f"*Findings:*\n{s['total_findings']} "
                  f"(review {s['review_queue']}, suppressed {s['suppressed']}, "
                  f"chains {s['chains']})")},
    ]

    blocks: List[Dict[str, Any]] = [
        {"type": "header",
         "text": {"type": "plain_text", "text": headline, "emoji": False}},
        {"type": "section", "fields": fields},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": f"*Severity:*  {_severity_line(by_sev)}"}},
    ]

    top = sorted(result.findings, key=lambda f: -f.risk_score)[:5]
    if top:
        lines = [
            f"- *{f.title}* ({f.severity.value}, score {round(f.risk_score, 2)})"
            for f in top
        ]
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Top findings:*\n" + "\n".join(lines)},
        })

    context_bits = [f"finished {result.finished or 'now'}"]
    if report_dir is not None:
        context_bits.append(f"reports: {report_dir}")
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "  •  ".join(context_bits)}],
    })

    return {"text": fallback, "blocks": blocks}


def notify_slack(result, webhook_url: str, *, report_dir: Optional[Path] = None,
                 timeout: float = 10.0) -> bool:
    """POST a run summary to a Slack Incoming Webhook.

    Returns ``True`` on a 2xx response. Never raises: a failed notification must
    not break an otherwise-successful scan.
    """
    if not webhook_url:
        return False
    payload = build_slack_payload(result, report_dir=report_dir)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            return 200 <= int(code) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False
