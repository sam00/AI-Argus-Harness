"""Enterprise asset graph engine.

A lightweight, dependency-free directed graph of assets and their relationships
(domain -> service -> cloud-resource, network -> host, etc.). Findings link to
asset IDs so blast-radius and chaining can traverse the graph.
"""

from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Set, Tuple

from ..models import Asset


class AssetGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Asset] = {}
        self.edges: Dict[str, Set[Tuple[str, str]]] = {}  # src -> {(dst, relation)}
        self._lock = threading.Lock()

    def add(self, asset: Asset) -> Asset:
        with self._lock:
            if asset.id not in self.nodes:
                self.nodes[asset.id] = asset
                self.edges.setdefault(asset.id, set())
            return self.nodes[asset.id]

    def link(self, src: Asset, dst: Asset, relation: str = "connected-to") -> None:
        self.add(src)
        self.add(dst)
        with self._lock:
            self.edges[src.id].add((dst.id, relation))

    def neighbors(self, asset_id: str) -> List[Tuple[str, str]]:
        return sorted(self.edges.get(asset_id, set()))

    def reachable(self, asset_id: str) -> Set[str]:
        seen: Set[str] = set()
        stack = [asset_id]
        while stack:
            cur = stack.pop()
            for dst, _rel in self.edges.get(cur, set()):
                if dst not in seen:
                    seen.add(dst)
                    stack.append(dst)
        return seen

    def by_type(self, type_value: str) -> List[Asset]:
        return [a for a in self.nodes.values() if a.type.value == type_value]

    def stats(self) -> Dict[str, int]:
        s: Dict[str, int] = {"assets": len(self.nodes),
                             "edges": sum(len(v) for v in self.edges.values())}
        for a in self.nodes.values():
            s[a.type.value] = s.get(a.type.value, 0) + 1
        return s

    def to_dict(self) -> Dict[str, object]:
        return {
            "nodes": [a.to_dict() for a in self.nodes.values()],
            "edges": [
                {"src": src, "dst": dst, "relation": rel}
                for src, dsts in self.edges.items()
                for dst, rel in dsts
            ],
        }
