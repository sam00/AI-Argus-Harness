"""Stage orchestrator — the harness core execution engine.

Runs the enterprise stage pipeline over a target, coordinating scanners,
graphs, the reliability layer, scoring, deduplication, and chain construction.
Produces a :class:`RunResult` that the reporting layer serializes.
"""

from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import __version__
from ..config import Config, PROFILE_SCANNERS
from ..evidence import normalize_evidence
from ..graph import AssetGraph, IdentityGraph
from ..llm import CostTracker
from ..models import Chain, Finding
from ..reliability import (
    adversarial_review, completeness_gate, single_pass_validate, verify_claims,
)
from ..scoring import deduplicate, score_finding
from ..chaining import construct_chains
from . import auth as _auth
from . import suppressions as _suppressions
from .auth import AuthMode, AuthResolution, AUTH_STAGES
from .cache import compute_diff, load_baseline, save_baseline, target_signature
from .context import ScanContext, ScanTarget
from .stages import STAGES, Stage


@dataclass
class RunResult:
    run_id: str
    version: str
    target: str
    profile: str
    cost_mode: str
    stealth_mode: str
    started: str
    finished: str = ""
    findings: List[Finding] = field(default_factory=list)
    review_queue: List[Finding] = field(default_factory=list)
    dropped: List[Finding] = field(default_factory=list)
    suppressed: List[Finding] = field(default_factory=list)
    chains: List[Chain] = field(default_factory=list)
    diff: Dict[str, Any] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=dict)
    asset_graph: AssetGraph = field(default_factory=AssetGraph)
    identity_graph: IdentityGraph = field(default_factory=IdentityGraph)
    evidence: Any = None
    stage_log: List[Dict[str, Any]] = field(default_factory=list)
    cost_summary: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        out = {
            "total_findings": len(self.findings),
            "review_queue": len(self.review_queue),
            "dropped": len(self.dropped),
            "suppressed": len(self.suppressed),
            "chains": len(self.chains),
            "assets": len(self.asset_graph.nodes),
            "identities": len(self.identity_graph.nodes),
            "by_severity": by_sev,
        }
        if self.diff:
            out["diff"] = self.diff.get("counts", {})
        return out


class Orchestrator:
    def __init__(self, config: Config, run_dir: Optional[Path] = None) -> None:
        self.config = config
        self.run_dir = run_dir
        self.tracker = CostTracker()

    # ------------------------------------------------------------------ #
    def resolve_scanners(self, explicit: Optional[List[str]] = None) -> List[str]:
        from ..scanners import all_scanners
        available = set(all_scanners())
        if explicit:
            return [s for s in explicit if s in available]
        wanted = PROFILE_SCANNERS.get(self.config.profile, PROFILE_SCANNERS["enterprise"])
        return [s for s in wanted if s in available]

    def _workers(self) -> int:
        if self.config.auto_workers:
            import os
            return max(2, min(32, (os.cpu_count() or 4) * 2))
        return max(1, int(self.config.workers))

    # ------------------------------------------------------------------ #
    def run(self, target: ScanTarget, scanners: Optional[List[str]] = None,
            stages: Optional[List[Stage]] = None,
            auth: Optional[AuthResolution] = None) -> RunResult:
        from ..scanners import get_scanner
        stages = stages or STAGES
        stage_codes = {s.code for s in stages}
        names = self.resolve_scanners(scanners)

        ctx = ScanContext(config=self.config, target=target,
                          tracker=self.tracker, run_dir=self.run_dir)

        result = RunResult(
            run_id="run-" + uuid.uuid4().hex[:10],
            version=__version__,
            target=target.raw,
            profile=self.config.profile,
            cost_mode=self.config.cost_mode,
            stealth_mode=self.config.stealth_mode,
            started=_now(),
        )

        def log(stage: Stage, status: str, **extra: Any) -> None:
            result.stage_log.append({"stage": stage.code, "name": stage.name,
                                     "status": status, **extra})

        # --- S0 credential preflight (authenticated vs non-authenticated) - #
        # Resolve credentials for the services we are about to scan; this auth
        # context applies to stages S1, S1.5, S2, S3, S4, S5 and S5.5.
        services = _auth.services_for_scanners(names)
        inventory = _inventory_for(target)
        if auth is not None:
            auth_res = auth
        elif getattr(self.config, "auth_scan", False):
            overrides = target.attributes.get("auth_keys") or {}
            auth_res = _auth.resolve(AuthMode.AUTHENTICATED, services,
                                     inventory=inventory, overrides=overrides)
        else:
            auth_res = _auth.unauthenticated(services)
        ctx.auth = auth_res
        result.auth = auth_res.to_dict()
        for svc, st in auth_res.statuses.items():
            if st.present:
                ctx.evidence_store.put(
                    "auth", f"{svc}: authenticated via {st.source}:{st.ref}")
            elif st.required:
                ctx.evidence_store.put(
                    "auth", f"{svc}: unauthenticated (no credential discovered)")
        result.stage_log.append({
            "stage": "S0", "name": "Credential Preflight", "status": "done",
            "mode": auth_res.mode.value, "applies_to": list(AUTH_STAGES),
            "authenticated_services": auth_res.authenticated_services,
            "missing_services": auth_res.missing_services,
            "satisfied": auth_res.satisfied,
        })

        # --- S1 / S1.5 / S4 / S5: discovery + evidence collection -------- #
        collected: List[Finding] = []
        active_scanners = []
        for n in names:
            sc = get_scanner(n)
            if self.config.stealth_mode not in sc.allowed_stealth:
                ctx.log(f"skip {n}: not allowed in stealth={self.config.stealth_mode}")
                continue
            if not sc.applicable(ctx):
                ctx.log(f"skip {n}: not applicable to target")
                continue
            active_scanners.append(sc)

        s1 = next(s for s in STAGES if s.code == "S1")
        log(s1, "running", scanners=[s.name for s in active_scanners])

        workers = self._workers()
        if workers > 1 and len(active_scanners) > 1:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(self._safe_run, sc, ctx): sc for sc in active_scanners}
                for fut in as_completed(futures):
                    collected.extend(fut.result())
        else:
            for sc in active_scanners:
                collected.extend(self._safe_run(sc, ctx))

        result.asset_graph = ctx.asset_graph
        result.identity_graph = ctx.identity_graph
        result.evidence = ctx.evidence_store
        for f in collected:
            f.stage = f.stage or "S4"
            f.evidence = normalize_evidence(f.evidence)
            f.compute_id()          # deterministic, content-addressed id
        log(s1, "done", assets=len(ctx.asset_graph.nodes),
            identities=len(ctx.identity_graph.nodes), candidates=len(collected),
            auth=auth_res.mode.value)

        # --- S5.5 controlled offensive verification (passive/safe) ------- #
        s55 = next(s for s in STAGES if s.code == "S5.5")
        verified, rejected = verify_claims(collected)
        result.dropped.extend(rejected)
        log(s55, "done", mode=self.config.stealth_mode,
            verified=len(verified), rejected=len(rejected),
            auth=auth_res.mode.value)

        # --- S6 adversarial review --------------------------------------- #
        s6 = next(s for s in STAGES if s.code == "S6")
        llm = ctx.llm if self.config.cost_mode in ("research", "deep-research") else None
        adversarial_review(verified, llm=llm)
        log(s6, "done")

        # --- S6.5 single-pass validation --------------------------------- #
        s65 = next(s for s in STAGES if s.code == "S6.5")
        single_pass_validate(verified)
        log(s65, "done")

        # --- score (first pass) ------------------------------------------ #
        for f in verified:
            score_finding(f)

        # --- S7 dedup ----------------------------------------------------- #
        s7 = next(s for s in STAGES if s.code == "S7")
        deduped = deduplicate(verified)
        log(s7, "done", before=len(verified), after=len(deduped))

        # --- S8 chain construction --------------------------------------- #
        s8 = next(s for s in STAGES if s.code == "S8")
        result.chains = construct_chains(deduped, ctx.asset_graph)
        # re-score to incorporate chainability, then finalize severity
        for f in deduped:
            score_finding(f)
        log(s8, "done", chains=len(result.chains))

        # --- S8.5 detection & control coverage review -------------------- #
        s85 = next(s for s in STAGES if s.code == "S8.5")
        gaps = sum(1 for f in deduped if f.detection_gap)
        log(s85, "done", detection_gaps=gaps)

        # --- S9/S10 completeness gate + human review routing ------------- #
        gate = completeness_gate(deduped, strict=self.config.strict,
                                 confidence_threshold=self.config.confidence_threshold)
        promoted = sorted(gate.passed,
                          key=lambda f: (-f.severity.rank, -f.risk_score))
        # Apply accepted-risk suppressions (stable id / dedup-key / title match).
        promoted, suppressed = _suppressions.apply(promoted)
        result.findings = promoted
        result.suppressed = suppressed
        result.review_queue = gate.review
        result.dropped.extend(gate.dropped)
        s10 = next(s for s in STAGES if s.code == "S10")
        log(s10, "done", promoted=len(result.findings),
            review=len(result.review_queue), dropped=len(result.dropped),
            suppressed=len(result.suppressed))

        # --- incremental diff vs the target's baseline (--diff) ----------- #
        if getattr(self.config, "diff", False):
            sig = target_signature(target.raw, self.config.profile)
            baseline = load_baseline(sig)
            d = compute_diff([f.finding_id for f in result.findings], baseline)
            result.diff = d.to_dict()
            save_baseline(sig, [f.finding_id for f in result.findings], result.summary())
            log(s10, "diff", **d.to_dict().get("counts", {}))

        result.finished = _now()
        self.tracker.flush()
        result.cost_summary = self.tracker.summary()
        return result

    def _safe_run(self, scanner, ctx: ScanContext) -> List[Finding]:
        try:
            res = scanner.run(ctx)
            for f in res.findings:
                f.scanner = f.scanner or scanner.name
            return res.findings
        except Exception as exc:  # a scanner failure must not abort the run
            ctx.log(f"scanner {scanner.name} failed: {exc}")
            return []


def _inventory_for(target: ScanTarget) -> Optional[Dict[str, Any]]:
    """Best-effort load of the inventory snapshot (for the credential census)."""
    inv = target.attributes.get("inventory")
    if inv is None:
        p = target.attributes.get("inventory_path")
        if p and Path(p).exists():
            try:
                inv = json.loads(Path(p).read_text())
                target.attributes["inventory"] = inv  # cache for scanners
            except Exception:
                inv = None
    return inv if isinstance(inv, dict) else None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
