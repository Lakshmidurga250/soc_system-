"""
SentinelAI - Enterprise Attack Path Graph Reasoning & Blast Radius Engine
Computes multi-hop lateral movement vectors, critical asset exposure, and graph centralities.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional, Tuple, Any
import math
import collections
import datetime

class NodeType(Enum):
    IDENTITY = "IDENTITY"
    HOST = "HOST"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    DATABASE = "DATABASE"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    NETWORK_SEGMENT = "NETWORK_SEGMENT"

class EdgeType(Enum):
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    ADMIN_OF = "ADMIN_OF"
    NETWORK_REACHABLE = "NETWORK_REACHABLE"
    TRUSTS_DOMAIN = "TRUSTS_DOMAIN"
    CONTAINS_DATA = "CONTAINS_DATA"
    EXECUTES_CODE_ON = "EXECUTES_CODE_ON"

@dataclass
class GraphNode:
    node_id: str
    node_type: NodeType
    name: str
    criticality: float = 1.0  # 1.0 to 10.0
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    compromised: bool = False
    compromise_time: Optional[datetime.datetime] = None

@dataclass
class GraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    bidirectional: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)

class AttackPathGraph:
    """
    In-memory directed attack graph representation supporting multi-hop shortest paths,
    blast radius computation, and Dijkstra/PageRank risk propagation.
    """
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.adjacency: Dict[str, List[GraphEdge]] = collections.defaultdict(list)
        self.reverse_adjacency: Dict[str, List[GraphEdge]] = collections.defaultdict(list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.adjacency[edge.source_id].append(edge)
        self.reverse_adjacency[edge.target_id].append(edge)
        if edge.bidirectional:
            rev_edge = GraphEdge(
                edge_id=f"{edge.edge_id}_rev",
                source_id=edge.target_id,
                target_id=edge.source_id,
                edge_type=edge.edge_type,
                weight=edge.weight,
                bidirectional=True,
                attributes=edge.attributes
            )
            self.adjacency[edge.target_id].append(rev_edge)
            self.reverse_adjacency[edge.source_id].append(rev_edge)

    def find_shortest_attack_path(self, start_node: str, target_node: str) -> Optional[List[str]]:
        """Dijkstra pathfinding for highest-probability attack traversal."""
        if start_node not in self.nodes or target_node not in self.nodes:
            return None
        
        distances: Dict[str, float] = {start_node: 0.0}
        previous: Dict[str, Optional[str]] = {start_node: None}
        unvisited = set(self.nodes.keys())
        
        while unvisited:
            current = min(unvisited, key=lambda n: distances.get(n, float('inf')))
            if distances.get(current, float('inf')) == float('inf'):
                break
            if current == target_node:
                break
            unvisited.remove(current)
            
            for edge in self.adjacency[current]:
                if edge.target_id in unvisited:
                    new_dist = distances[current] + edge.weight
                    if new_dist < distances.get(edge.target_id, float('inf')):
                        distances[edge.target_id] = new_dist
                        previous[edge.target_id] = current
                        
        if target_node not in previous and start_node != target_node:
            return None
            
        path = []
        curr = target_node
        while curr is not None:
            path.append(curr)
            curr = previous.get(curr)
        path.reverse()
        return path if path and path[0] == start_node else None

    def calculate_blast_radius(self, root_compromised_id: str, max_hops: int = 4) -> Dict[str, Any]:
        """Calculates cascading compromise potential across N hops."""
        if root_compromised_id not in self.nodes:
            return {"error": "Root node not found", "nodes_reached": 0}
            
        reached_nodes: Dict[str, int] = {root_compromised_id: 0}
        queue = collections.deque([(root_compromised_id, 0)])
        total_criticality_exposure = 0.0
        compromised_types: Dict[str, int] = collections.defaultdict(int)
        
        while queue:
            node_id, hops = queue.popleft()
            node = self.nodes[node_id]
            total_criticality_exposure += node.criticality * (1.0 / (1.0 + hops * 0.5))
            compromised_types[node.node_type.value] += 1
            
            if hops < max_hops:
                for edge in self.adjacency[node_id]:
                    if edge.target_id not in reached_nodes:
                        reached_nodes[edge.target_id] = hops + 1
                        queue.append((edge.target_id, hops + 1))
                        
        return {
            "root_node": root_compromised_id,
            "max_hops": max_hops,
            "total_nodes_exposed": len(reached_nodes),
            "aggregate_exposure_score": round(total_criticality_exposure, 2),
            "exposed_by_type": dict(compromised_types),
            "reachability_matrix": reached_nodes
        }

    def compute_pagerank_centrality(self, iterations: int = 25, damping: float = 0.85) -> Dict[str, float]:
        """Calculates asset centrality score to identify crown jewels."""
        n = len(self.nodes)
        if n == 0:
            return {}
        scores = {node_id: 1.0 / n for node_id in self.nodes}
        
        for _ in range(iterations):
            new_scores = {node_id: (1.0 - damping) / n for node_id in self.nodes}
            for node_id, score in scores.items():
                out_edges = self.adjacency[node_id]
                if out_edges:
                    share = (damping * score) / len(out_edges)
                    for edge in out_edges:
                        new_scores[edge.target_id] += share
                else:
                    for target_id in self.nodes:
                        new_scores[target_id] += (damping * score) / n
            scores = new_scores
        return {k: round(v, 6) for k, v in scores.items()}

# Pre-instantiate enterprise SOC graph
enterprise_graph = AttackPathGraph()
