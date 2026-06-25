"""Identity & access graph engine.

Identity is a first-class graph. Nodes are principals (users, roles, service
accounts, OAuth apps, CI identities, external users). Edges are permissions to
targets (assets or other identities). The graph powers identity-path analysis,
blind-spot checks, and privilege-escalation chain construction.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Set, Tuple

from ..models import Identity, IdentityHop, Relationship


# Relationships considered "privilege-bearing" for path strength.
PRIV_RELATIONS = {Relationship.CAN_ADMIN, Relationship.CAN_ASSUME,
                  Relationship.CAN_WRITE, Relationship.CAN_DEPLOY}


class IdentityGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Identity] = {}
        # src_id -> list of (target, permission, relationship)
        self.edges: Dict[str, List[Tuple[str, str, Relationship]]] = {}
        self._lock = threading.Lock()

    def add(self, identity: Identity) -> Identity:
        with self._lock:
            if identity.id not in self.nodes:
                self.nodes[identity.id] = identity
                self.edges.setdefault(identity.id, [])
            return self.nodes[identity.id]

    def grant(self, src: Identity, target: str, permission: str,
              relationship: Relationship = Relationship.CAN_READ) -> None:
        self.add(src)
        with self._lock:
            self.edges[src.id].append((target, permission, relationship))

    def paths_to(self, target: str, max_depth: int = 6) -> List[List[IdentityHop]]:
        """Return identity paths (as hop lists) that terminate at ``target``."""
        results: List[List[IdentityHop]] = []

        def dfs(node_id: str, path: List[IdentityHop], visited: Set[str]) -> None:
            if len(path) > max_depth:
                return
            for tgt, perm, rel in self.edges.get(node_id, []):
                hop = IdentityHop(principal=self.nodes[node_id].name,
                                  permission=perm, target=tgt, relationship=rel)
                new_path = path + [hop]
                if tgt == target:
                    results.append(new_path)
                elif tgt in self.nodes and tgt not in visited:
                    dfs(tgt, new_path, visited | {tgt})

        for nid in list(self.nodes.keys()):
            dfs(nid, [], {nid})
        return results

    def shortest_path_to(self, target: str) -> Optional[List[IdentityHop]]:
        paths = self.paths_to(target)
        if not paths:
            return None
        return min(paths, key=len)

    def privileged_identities(self) -> List[Identity]:
        return [i for i in self.nodes.values() if i.privileged]

    def blind_spots(self) -> List[Dict[str, str]]:
        """Detect classic identity blind spots."""
        issues: List[Dict[str, str]] = []
        for i in self.nodes.values():
            attrs = i.attributes or {}
            if i.privileged and attrs.get("dormant"):
                issues.append({"identity": i.name, "issue": "dormant privileged user"})
            if i.kind == "service-account" and attrs.get("orphaned"):
                issues.append({"identity": i.name, "issue": "orphaned service account"})
            if attrs.get("mfa") is False and i.kind == "user":
                issues.append({"identity": i.name, "issue": "missing MFA"})
            if attrs.get("key_age_days", 0) and attrs["key_age_days"] > 365:
                issues.append({"identity": i.name, "issue": "long-lived key"})
            if i.kind == "oauth-app" and attrs.get("broad_scope"):
                issues.append({"identity": i.name, "issue": "OAuth consent risk"})
        return issues

    def stats(self) -> Dict[str, int]:
        s = {"identities": len(self.nodes),
             "grants": sum(len(v) for v in self.edges.values()),
             "privileged": len(self.privileged_identities())}
        return s

    def to_dict(self) -> Dict[str, object]:
        return {
            "nodes": [i.to_dict() for i in self.nodes.values()],
            "edges": [
                {"src": src, "target": tgt, "permission": perm,
                 "relationship": rel.value}
                for src, grants in self.edges.items()
                for tgt, perm, rel in grants
            ],
        }
