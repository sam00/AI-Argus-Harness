"""Chain constructor.

Links findings into attack-path chains by shared assets/identities. A chain
represents how an attacker could move from initial exposure to high-impact
access. Chains require linked assets and identities (design rule: *No chain
without linked assets and identities*).
"""

from __future__ import annotations

from typing import Dict, List

from ..graph import AssetGraph
from ..models import Chain, Finding, Severity


def construct_chains(findings: List[Finding], asset_graph: AssetGraph) -> List[Chain]:
    chains: List[Chain] = []

    # Index findings by the identity targets they touch.
    by_target: Dict[str, List[Finding]] = {}
    for f in findings:
        for hop in f.identity_path:
            by_target.setdefault(hop.target, []).append(f)
        by_target.setdefault(f.asset.id, []).append(f)

    used = set()
    for target, group in by_target.items():
        # Need at least an exposure step + a privilege/impact step.
        if len(group) < 2:
            continue
        group_sorted = sorted(group, key=lambda x: x.risk_score, reverse=True)
        key = tuple(sorted(g.finding_id for g in group_sorted))
        if key in used:
            continue
        used.add(key)

        assets = sorted({g.asset.id for g in group_sorted})
        identities = sorted({h.principal for g in group_sorted for h in g.identity_path})
        if not assets or not identities:
            continue

        narrative = " -> ".join(
            [f"{g.title} [{g.severity.value}]" for g in group_sorted[:4]])
        top = group_sorted[0].severity
        chain = Chain(
            title=f"Attack path converging on {target}",
            finding_ids=[g.finding_id for g in group_sorted],
            assets=assets,
            identities=identities,
            narrative=narrative,
            severity=top if top.rank >= Severity.HIGH.rank else Severity.MEDIUM,
            score=round(sum(g.risk_score for g in group_sorted), 2),
        )
        chain.compute_id()                      # content-addressed, stable across runs
        chains.append(chain)
        for g in group_sorted:
            g.chain_ids.append(chain.chain_id)

    chains.sort(key=lambda c: c.score, reverse=True)
    return chains
