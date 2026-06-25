"""Append-only evidence store.

Preserves raw artifacts for replayable, audit-ready runs. Secrets are redacted
before persistence (enterprise readiness requirement: secret redaction).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_REDACTION_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def redact(text: str) -> str:
    out = text
    for pat in _REDACTION_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


class EvidenceStore:
    """Thread-safe, content-addressed evidence store.

    Evidence refs are derived purely from ``source`` + redacted ``detail`` so
    they are deterministic and independent of insertion order. Identical
    observations collapse to a single record, which removes the previous
    ``len(records)`` race and makes runs reproducible under parallel scanners.
    """

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else None
        self.records: List[Dict[str, Any]] = []
        self._index: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        if self.base_dir:
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def put(self, source: str, detail: str, raw: Any = None) -> str:
        detail = redact(detail)
        ref = "ev-" + hashlib.sha1(f"{source}:{detail}".encode()).hexdigest()[:12]
        rec = {
            "ref": ref,
            "source": source,
            "detail": detail,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if raw is not None:
            rec["raw"] = redact(json.dumps(raw, default=str))
        with self._lock:
            if ref in self._index:               # identical evidence already stored
                return ref
            self._index[ref] = rec
            self.records.append(rec)
            write_target = self.base_dir
        if write_target:
            try:
                (write_target / f"{ref}.json").write_text(json.dumps(rec, indent=2))
            except Exception:
                pass
        return ref

    def all(self) -> List[Dict[str, Any]]:
        # Sorted by ref for stable, order-independent output.
        return sorted(self.records, key=lambda r: r["ref"])

    def to_dict(self) -> Dict[str, Any]:
        recs = self.all()
        return {"count": len(recs), "records": recs}
