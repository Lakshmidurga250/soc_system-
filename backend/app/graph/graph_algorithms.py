"""SentinelAI Graph Theory & Attack Path Analytics Engine.

Implements graph traversal and centrality algorithms for SOC investigations:
- Dijkstra / A* Least-Resistance Attack Path Discovery
- PageRank Asset Critical Exposure Centrality
- Brandes' Betweenness Centrality for Chokepoint Identification
- Dynamic Incident Blast Radius Boundary Computation
"""

from __future__ import annotations

import heapq
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AttackPathStep:
    from_node: str
    to_node: str
    relation: str
    weight: float
    accumulated_cost: float
    mitre_technique: Optional[str] = None


@dataclass
class AttackPathResult:
    source: str
    target: str
    path_found: bool
    total_cost: float
    hop_count: int
    nodes_in_path: List[str]
    steps: List[AttackPathStep]
    risk_level: str


class AttackGraphAnalytics:
    """Graph theoretical analysis over SOC security knowledge graphs."""

    @classmethod
    def find_shortest_attack_path(
        cls,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        start_node_id: str,
        target_node_id: str,
    ) -> AttackPathResult:
        """Finds the least-cost multi-hop attack lateral movement path using Dijkstra's algorithm.

        Weights represent attack resistance (lower weight = easier compromise / higher vulnerability).
        """
        adj: Dict[str, List[Tuple[str, float, str]]] = defaultdict(list)
        for e in edges:
            src = e.get("source", "")
            tgt = e.get("target", "")
            w = float(e.get("weight", 1.0))
            rel = e.get("relation", "CONNECTED_TO")
            # In an attack graph, relations can often be traversed in both directions
            adj[src].append((tgt, w, rel))
            adj[tgt].append((src, w * 1.2, f"REVERSE_{rel}"))

        # Priority queue for Dijkstra: (cost, current_node, path, step_objects)
        pq: List[Tuple[float, str, List[str], List[AttackPathStep]]] = []
        heapq.heappush(pq, (0.0, start_node_id, [start_node_id], []))

        visited_cost: Dict[str, float] = {start_node_id: 0.0}

        while pq:
            current_cost, u, path, steps = heapq.heappop(pq)

            if u == target_node_id:
                # Risk level inversely proportional to cost
                risk = "CRITICAL" if current_cost < 3.0 else ("HIGH" if current_cost < 6.0 else "MEDIUM")
                return AttackPathResult(
                    source=start_node_id,
                    target=target_node_id,
                    path_found=True,
                    total_cost=round(current_cost, 2),
                    hop_count=len(path) - 1,
                    nodes_in_path=path,
                    steps=steps,
                    risk_level=risk,
                )

            if current_cost > visited_cost.get(u, float("inf")):
                continue

            for v, weight, rel in adj[u]:
                new_cost = current_cost + weight
                if new_cost < visited_cost.get(v, float("inf")):
                    visited_cost[v] = new_cost
                    new_step = AttackPathStep(
                        from_node=u,
                        to_node=v,
                        relation=rel,
                        weight=round(weight, 2),
                        accumulated_cost=round(new_cost, 2),
                    )
                    heapq.heappush(pq, (new_cost, v, path + [v], steps + [new_step]))

        return AttackPathResult(
            source=start_node_id,
            target=target_node_id,
            path_found=False,
            total_cost=0.0,
            hop_count=0,
            nodes_in_path=[],
            steps=[],
            risk_level="NONE",
        )

    @classmethod
    def calculate_pagerank(
        cls,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        damping: float = 0.85,
        max_iter: int = 50,
        tol: float = 1e-5,
    ) -> Dict[str, float]:
        """Calculates PageRank centrality to identify high-exposure central asset hubs."""
        node_ids = [n["id"] for n in nodes]
        n_count = len(node_ids)
        if n_count == 0:
            return {}

        out_edges: Dict[str, List[str]] = defaultdict(list)
        in_edges: Dict[str, List[str]] = defaultdict(list)

        for e in edges:
            s, t = e["source"], e["target"]
            out_edges[s].append(t)
            in_edges[t].append(s)

        # Initial uniform distribution
        pr = {nid: 1.0 / n_count for nid in node_ids}

        for _ in range(max_iter):
            new_pr = {}
            dangling_sum = sum(pr[nid] for nid in node_ids if len(out_edges[nid]) == 0)
            dangling_contrib = (damping * dangling_sum) / n_count

            diff = 0.0
            for nid in node_ids:
                in_sum = sum(pr[in_n] / len(out_edges[in_n]) for in_n in in_edges[nid] if len(out_edges[in_n]) > 0)
                rank = ((1.0 - damping) / n_count) + (damping * in_sum) + dangling_contrib
                diff += abs(rank - pr[nid])
                new_pr[nid] = rank

            pr = new_pr
            if diff < tol:
                break

        # Normalize so sum equals 100 for easy visual inspection
        scale = 100.0 / max(sum(pr.values()), 1e-6)
        return {nid: round(val * scale, 3) for nid, val in sorted(pr.items(), key=lambda x: x[1], reverse=True)}

    @classmethod
    def calculate_betweenness_centrality(
        cls,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """Calculates Betweenness Centrality using Brandes' algorithm to pinpoint defense chokepoints."""
        node_ids = [n["id"] for n in nodes]
        adj: Dict[str, List[str]] = defaultdict(list)
        for e in edges:
            adj[e["source"]].append(e["target"])
            adj[e["target"]].append(e["source"])

        cb: Dict[str, float] = {nid: 0.0 for nid in node_ids}

        for s in node_ids:
            # Single-source shortest paths (BFS)
            stack: List[str] = []
            predecessors: Dict[str, List[str]] = defaultdict(list)
            sigma: Dict[str, int] = defaultdict(int)
            sigma[s] = 1
            distance: Dict[str, int] = {s: 0}
            queue = deque([s])

            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in adj[v]:
                    if w not in distance:
                        distance[w] = distance[v] + 1
                        queue.append(w)
                    if distance[w] == distance[v] + 1:
                        sigma[w] += sigma[v]
                        predecessors[w].append(v)

            # Accumulation of dependencies
            delta: Dict[str, float] = defaultdict(float)
            while stack:
                w = stack.pop()
                for v in predecessors[w]:
                    if sigma[w] > 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    cb[w] += delta[w]

        # Normalize
        n = len(node_ids)
        if n > 2:
            norm_factor = 2.0 / ((n - 1) * (n - 2))
            return {nid: round(val * norm_factor * 100.0, 3) for nid, val in sorted(cb.items(), key=lambda x: x[1], reverse=True)}

        return {nid: round(val, 3) for nid, val in cb.items()}

    @classmethod
    def compute_blast_radius(
        cls,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        compromised_seeds: List[str],
        max_hops: int = 3,
    ) -> Dict[str, Any]:
        """Calculates dynamic containment boundary, blast radius, and exposed crown-jewel assets."""
        node_map = {n["id"]: n for n in nodes}
        adj: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        for e in edges:
            adj[e["source"]].append((e["target"], e.get("relation", "CONNECTED")))
            adj[e["target"]].append((e["source"], e.get("relation", "CONNECTED")))

        visited: Set[str] = set()
        queue: deque[Tuple[str, int, List[str]]] = deque([(seed, 0, [seed]) for seed in compromised_seeds])

        compromised_subgraph_nodes = []
        hop_layers: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        exposed_asset_types: Dict[str, int] = defaultdict(int)

        while queue:
            node_id, depth, path = queue.popleft()
            if node_id in visited or depth > max_hops:
                continue

            visited.add(node_id)
            node_info = node_map.get(node_id, {"id": node_id, "label": node_id, "type": "Unknown"})
            node_entry = {
                "id": node_id,
                "label": node_info.get("label", node_id),
                "type": node_info.get("type", "Unknown"),
                "hop_distance": depth,
                "path_from_seed": path,
            }
            compromised_subgraph_nodes.append(node_entry)
            hop_layers[depth].append(node_entry)
            exposed_asset_types[node_info.get("type", "Unknown")] += 1

            if depth < max_hops:
                for neighbor, _ in adj[node_id]:
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1, path + [neighbor]))

        # Calculate blast radius risk index [0 - 100]
        critical_assets = sum(1 for n in compromised_subgraph_nodes if n["type"] in ("Host", "Server", "Incident"))
        total_reach = len(compromised_subgraph_nodes)
        blast_score = min(100.0, (critical_assets * 15.0) + (total_reach * 4.0))

        return {
            "seed_nodes": compromised_seeds,
            "max_hops_analyzed": max_hops,
            "total_nodes_in_blast_radius": len(compromised_subgraph_nodes),
            "blast_radius_risk_score": round(blast_score, 1),
            "threat_scope": "ENTERPRISE_WIDE" if blast_score > 70 else ("SEGMENT_LOCAL" if blast_score > 35 else "ISOLATED"),
            "exposed_entity_breakdown": dict(exposed_asset_types),
            "hop_distribution": {f"hop_{k}": len(v) for k, v in hop_layers.items()},
            "nodes": compromised_subgraph_nodes,
        }


# Global instance
attack_graph_analytics = AttackGraphAnalytics()
