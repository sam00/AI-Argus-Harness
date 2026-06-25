"""Multi-sample (multi-agent) voting over an evidence-bound verdict.

Implements a "multi-agent disagreement" guard. The model is asked,
N times, to judge whether the evidence supports a finding and to reply with a
strict JSON verdict. We then:

  * parse each verdict defensively (JSON, with a keyword fallback),
  * verify each rationale is *grounded* in the evidence (see grounding.py),
  * take a majority vote and quantify disagreement.

High disagreement, an unsupported majority, or ungrounded rationales cause the
caller to lower confidence and route the finding to human review. With the
deterministic offline provider this collapses to a trivially-supported,
zero-disagreement verdict (evidence-bound by construction), while remaining
fully functional when a real model provider is configured.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional

from ..llm import LLMProvider
from ..models import Finding
from .grounding import grounded

VERDICTS = ("supported", "refuted", "uncertain")

SYSTEM = (
    "You are an adversarial security reviewer. Reason ONLY over the provided "
    "evidence. Never invent facts, CVEs, names, hosts, IPs or numbers. If the "
    "evidence is insufficient, answer 'uncertain'."
)


@dataclass
class Verdict:
    verdict: str = "uncertain"
    confidence: str = "low"
    disagreement: float = 0.0
    samples: int = 0
    grounded: bool = True
    rationale: str = ""
    cited_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "disagreement": round(self.disagreement, 3),
            "samples": self.samples,
            "grounded": self.grounded,
            "rationale": self.rationale[:240],
            "cited_refs": self.cited_refs,
        }


def _build_prompt(f: Finding) -> str:
    ev = "\n".join(f"[{e.raw_ref or 'ev'}] {e.detail}" for e in f.evidence)
    return (
        f"Finding: {f.title}\n"
        f"Category: {f.category}\n"
        f"Evidence:\n{ev}\n\n"
        "Does the evidence support the finding? Reply ONLY as compact JSON:\n"
        '{"verdict":"supported|refuted|uncertain","confidence":"low|medium|high",'
        '"rationale":"<=200 chars citing evidence","cited_refs":["ev-..."]}'
    )


def _parse(text: str) -> dict:
    """Defensively parse a verdict from model text (JSON, else keywords)."""
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        obj = json.loads(text[start:end])
        v = str(obj.get("verdict", "")).lower()
        if v in VERDICTS:
            return {
                "verdict": v,
                "confidence": str(obj.get("confidence", "low")).lower(),
                "rationale": str(obj.get("rationale", "")),
                "cited_refs": [str(r) for r in obj.get("cited_refs", []) if r],
            }
    except Exception:
        pass
    low = text.lower()
    if "refut" in low or "not support" in low or "unsupported" in low:
        v = "refuted"
    elif "support" in low:
        v = "supported"
    else:
        v = "uncertain"
    return {"verdict": v, "confidence": "low", "rationale": text[:200], "cited_refs": []}


def vote(llm: LLMProvider, finding: Finding, n: int = 3) -> Verdict:
    n = max(1, n)
    prompt = _build_prompt(finding)
    parsed: List[dict] = []
    for _ in range(n):
        resp = llm.complete(prompt, system=SYSTEM)
        # The deterministic offline provider is extractive (it echoes the prompt)
        # and is evidence-bound by construction, so it is not a meaningful
        # "reviewer". Short-circuit to a trivially-supported, zero-disagreement
        # verdict rather than parsing/grounding its echoed template text.
        if getattr(resp, "offline", False) or str(resp.model).startswith("offline"):
            return Verdict(verdict="supported", confidence="medium",
                           disagreement=0.0, samples=n, grounded=True,
                           rationale="offline evidence-bound reasoning")
        parsed.append(_parse(resp.text))

    counts = {v: sum(1 for p in parsed if p["verdict"] == v) for v in VERDICTS}
    majority = max(counts, key=counts.get)
    disagreement = 1.0 - counts[majority] / n
    rep = next((p for p in parsed if p["verdict"] == majority), parsed[0])
    is_grounded, _ung = grounded(rep["rationale"], finding.evidence)
    if not is_grounded and majority == "supported":
        majority = "uncertain"      # ungrounded rationale cannot support a finding
    return Verdict(
        verdict=majority,
        confidence=rep.get("confidence", "low"),
        disagreement=disagreement,
        samples=n,
        grounded=is_grounded,
        rationale=rep.get("rationale", ""),
        cited_refs=rep.get("cited_refs", []),
    )
