"""Security Knowledge Graph Builder & Query Subsystem for SentinelAI SOC."""
from typing import Dict, List, Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import SecurityEvent, Alert, Incident

class SecurityKnowledgeGraph:
    def build_graph(self, db: Session, limit_events: int = 500) -> Dict[str, Any]:
        """Constructs an in-memory graph representation of security entities and interactions."""
        events = db.scalars(select(SecurityEvent).limit(limit_events)).all()
        alerts = db.scalars(select(Alert).limit(100)).all()
        incidents = db.scalars(select(Incident).limit(50)).all()

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        def add_node(node_id: str, label: str, node_type: str, metadata: dict | None = None):
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "degree": 0,
                    "metadata": metadata or {},
                }
            nodes[node_id]["degree"] += 1

        def add_edge(source: str, target: str, relation: str, weight: float = 1.0):
            edges.append({
                "source": source,
                "target": target,
                "relation": relation,
                "weight": weight,
            })

        # Process Incidents
        for inc in incidents:
            inc_node_id = f"incident:{inc.id}"
            add_node(inc_node_id, inc.title[:30], "Incident", {"severity": inc.severity, "risk": inc.risk_score})
            for alt_id in (inc.alert_ids or []):
                add_edge(inc_node_id, f"alert:{alt_id}", "ASSOCIATED_WITH")

        # Process Alerts
        for alt in alerts:
            alt_node_id = f"alert:{alt.id}"
            add_node(alt_node_id, alt.title[:30], "Alert", {"severity": alt.severity, "risk": alt.risk_score})
            if alt.entities:
                if alt.entities.get("source_ip"):
                    ip_id = f"ip:{alt.entities['source_ip']}"
                    add_node(ip_id, alt.entities['source_ip'], "IP")
                    add_edge(alt_node_id, ip_id, "OBSERVED_ON")
                if alt.entities.get("username"):
                    u_id = f"user:{alt.entities['username']}"
                    add_node(u_id, alt.entities['username'], "User")
                    add_edge(alt_node_id, u_id, "TRIGGERED")
                if alt.entities.get("hostname"):
                    h_id = f"host:{alt.entities['hostname']}"
                    add_node(h_id, alt.entities['hostname'], "Host")
                    add_edge(alt_node_id, h_id, "OBSERVED_ON")

        # Process Events
        for evt in events:
            if evt.source_ip and evt.username:
                ip_id = f"ip:{evt.source_ip}"
                u_id = f"user:{evt.username}"
                add_node(ip_id, evt.source_ip, "IP")
                add_node(u_id, evt.username, "User")
                add_edge(u_id, ip_id, "LOGIN_FROM")

            if evt.username and evt.hostname:
                u_id = f"user:{evt.username}"
                h_id = f"host:{evt.hostname}"
                add_node(u_id, evt.username, "User")
                add_node(h_id, evt.hostname, "Host")
                add_edge(u_id, h_id, "ACCESSED")

        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": list(nodes.values()),
            "edges": edges,
        }

    def query_subgraph_for_entity(self, db: Session, entity_value: str) -> Dict[str, Any]:
        """Extracts the 1-hop and 2-hop neighborhood surrounding a specific entity."""
        full = self.build_graph(db)
        matched_node_ids = {n["id"] for n in full["nodes"] if entity_value.lower() in n["label"].lower()}
        
        neighbor_ids = set(matched_node_ids)
        sub_edges = []
        for e in full["edges"]:
            if e["source"] in matched_node_ids or e["target"] in matched_node_ids:
                neighbor_ids.add(e["source"])
                neighbor_ids.add(e["target"])
                sub_edges.append(e)

        sub_nodes = [n for n in full["nodes"] if n["id"] in neighbor_ids]
        return {
            "entity": entity_value,
            "node_count": len(sub_nodes),
            "edge_count": len(sub_edges),
            "nodes": sub_nodes,
            "edges": sub_edges,
        }

knowledge_graph = SecurityKnowledgeGraph()
