"""Evidence grounding — programmatic anti-hallucination guard.

When an LLM contributes reasoning, this module verifies that the text does not
introduce *specific factual entities* (CVEs, ARNs, hostnames, IPs, emails,
versions, quoted identifiers) that are absent from the supplied evidence.

This turns the prompt-level instruction "never invent facts" into an enforced
check: any ungrounded entity is reported so the caller can reject or sanitize
the output. AI may only reason over evidence it was given.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from ..models import Evidence

# Patterns for "specific" entities a model must not invent.
_ENTITY_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{3,7}", re.I),
    re.compile(r"arn:aws:[^\s'\"]+", re.I),
    re.compile(r"\bhttps?://[^\s'\"]+", re.I),
    re.compile(r"\b[\w.\-]+@[\w.\-]+\.[A-Za-z]{2,}\b"),          # email
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),                  # IPv4
    re.compile(r"\b\d+\.\d+(?:\.\d+)*\b"),                       # version
    re.compile(r"'([^']{3,})'|\"([^\"]{3,})\""),                # quoted literal
]


def _corpus(evidence: Iterable[Evidence]) -> str:
    parts: List[str] = []
    for e in evidence:
        parts.append(e.detail or "")
        if getattr(e, "raw_ref", None):
            parts.append(e.raw_ref)
    return "\n".join(parts).lower()


def extract_entities(text: str) -> List[str]:
    found: List[str] = []
    for pat in _ENTITY_PATTERNS:
        for m in pat.finditer(text):
            token = next((g for g in m.groups() if g), None) if m.groups() else m.group(0)
            token = (token or m.group(0)).strip()
            if token and token.lower() not in (t.lower() for t in found):
                found.append(token)
    return found


def grounded(text: str, evidence: Iterable[Evidence]) -> Tuple[bool, List[str]]:
    """Return (is_grounded, ungrounded_entities).

    A text is grounded if every specific entity it mentions also appears in the
    evidence corpus.
    """
    corpus = _corpus(evidence)
    ungrounded = [ent for ent in extract_entities(text)
                  if ent.lower() not in corpus]
    return (not ungrounded), ungrounded


def sanitize(text: str, evidence: Iterable[Evidence]) -> str:
    """Drop sentences that contain ungrounded entities (defense in depth)."""
    ok, ungrounded = grounded(text, evidence)
    if ok:
        return text
    low_bad = [u.lower() for u in ungrounded]
    kept = []
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if not any(b in sentence.lower() for b in low_bad):
            kept.append(sentence)
    return " ".join(kept).strip()
