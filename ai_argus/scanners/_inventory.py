"""Shared helper: load an enterprise inventory snapshot.

Cloud / Kubernetes / SaaS scanners are credentialed and read-only. Rather than
embedding live SDK calls (which require credentials and network), this build
reads a normalized JSON *inventory snapshot* — the same shape a collector would
produce — so the deterministic policy checks are fully testable and replayable.

Provide one via:  argus scan ... --inventory inventory.json
The relevant top-level key (e.g. "aws", "gcp", "kubernetes") is passed to the
scanner.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from ..core.context import ScanContext


def load_inventory(ctx: ScanContext, section: str) -> Optional[Dict[str, Any]]:
    inv = ctx.target.attributes.get("inventory")
    if inv is None:
        path = ctx.target.attributes.get("inventory_path")
        if path and Path(path).exists():
            try:
                inv = json.loads(Path(path).read_text())
                ctx.target.attributes["inventory"] = inv
            except Exception:
                inv = None
    if not isinstance(inv, dict):
        return None
    return inv.get(section)
