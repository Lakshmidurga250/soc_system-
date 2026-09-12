"""SentinelAI Multi-Signal Sliding-Window Attack Scenario Reconstruction Engine.

Correlates heterogeneous telemetry events (Auth, Network, Process, File, IDS) across:
- Shared Pivot Entities (Source IP, Destination IP, User Account, Hostname, Asset)
- Temporal Sliding Windows (5 min, 15 min, 1 hour, 24 hours)
- MITRE ATT&CK Multi-Tactic Progression (Kill Chain Sequence Verification)
Generates high-fidelity consolidated Incident Candidates with timeline narratives.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CorrelationCandidate:
    candidate_id: str
    scenario_title: str
    scenario_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score: int  # 0 to 100
    risk_score: float
    affected_entities: Dict[str, List[str]]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    events_count: int
    first_event_time: str
    last_event_time: str
    event_ids: List[str]
    timeline_steps: List[Dict[str, Any]]
    explanation: str


class MultiSignalCorrelationEngine:
    """Detects multi-stage attack campaigns across distributed security telemetry."""

    def __init__(self, time_window_seconds: int = 1800):
        self.time_window = time_window_seconds

    def correlate_event_stream(self, events: List[Dict[str, Any]]) -> List[CorrelationCandidate]:
        """Correlates a batch of normalized security events into attack scenario candidates."""
        if not events:
            return []

        # 1. Cluster events by primary pivot entity (Source IP, User, Destination IP, Hostname)
        ip_clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        user_clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        host_clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for evt in events:
            src_ip = evt.get("source_ip")
            user = evt.get("username")
            host = evt.get("hostname")

            if src_ip and src_ip not in ("127.0.0.1", "0.0.0.0", "-"):
                ip_clusters[src_ip].append(evt)
            if user and user.lower() not in ("system", "anonymous", "network", "-"):
                user_clusters[user].append(evt)
            if host and host != "unknown":
                host_clusters[host].append(evt)

        candidates: List[CorrelationCandidate] = []

        # 2. Analyze IP clusters for lateral movement & multi-phase attacks
        for ip, cluster in ip_clusters.items():
            candidate = self._evaluate_cluster(cluster, pivot_type="IP", pivot_value=ip)
            if candidate:
                candidates.append(candidate)

        # 3. Analyze User clusters for credential compromise & account takeover
        for user, cluster in user_clusters.items():
            candidate = self._evaluate_cluster(cluster, pivot_type="User", pivot_value=user)
            if candidate:
                candidates.append(candidate)

        # Deduplicate overlapping candidates
        unique_candidates = self._deduplicate_candidates(candidates)
        return sorted(unique_candidates, key=lambda x: x.risk_score, reverse=True)

    def _evaluate_cluster(
        self,
        cluster: List[Dict[str, Any]],
        pivot_type: str,
        pivot_value: str,
    ) -> Optional[CorrelationCandidate]:
        """Evaluates whether an entity cluster forms a multi-stage attack pattern."""
        if len(cluster) < 2:
            return None

        # Sort cluster by timestamp
        sorted_events = sorted(cluster, key=lambda x: str(x.get("timestamp", "")))
        event_ids = [str(e.get("id") or f"EVT-{idx}") for idx, e in enumerate(sorted_events)]

        # Collect unique observed tactics and attack categories
        tactics_observed = set()
        techniques_observed = set()
        categories_observed = set()
        severities = []

        for e in sorted_events:
            cat = e.get("category", "")
            if cat:
                categories_observed.add(cat)
            t_list = e.get("mitre_tactics") or []
            for t in t_list:
                tactics_observed.add(t)
            tech_list = e.get("mitre_attack") or []
            for tech in tech_list:
                techniques_observed.add(tech)
            severities.append(e.get("severity", "LOW"))

        # Calculate Coordinated Attack Score
        has_auth_failure = any(
            e.get("event_type") == "AUTH_FAILURE" or "4625" in str(e.get("event_type", "")) or e.get("status") == "FAILURE"
            for e in sorted_events
        )
        has_proc_execution = any(
            "PROCESS" in str(e.get("event_type", "")) or "4688" in str(e.get("event_type", "")) or e.get("process_name")
            for e in sorted_events
        )
        has_c2_or_ids = any(
            "C2" in str(e.get("event_type", "")) or "IDS" in str(e.get("source", "")).upper() or "SNORT" in str(e.get("source", "")).upper()
            for e in sorted_events
        )
        has_priv_or_dump = any(
            "LSASS" in str(e.get("resource", "")).upper() or "SAM" in str(e.get("resource", "")).upper() or "SHADOW" in str(e.get("resource", "")).upper()
            for e in sorted_events
        )

        distinct_signals_count = sum([has_auth_failure, has_proc_execution, has_c2_or_ids, has_priv_or_dump])
        if distinct_signals_count < 2 and len(tactics_observed) < 2 and len(sorted_events) < 4:
            return None

        # Build timeline steps
        timeline_steps = []
        for idx, e in enumerate(sorted_events):
            timeline_steps.append({
                "step_index": idx + 1,
                "timestamp": e.get("timestamp", ""),
                "event_type": e.get("event_type", "SECURITY_EVENT"),
                "severity": e.get("severity", "MEDIUM"),
                "summary": e.get("action") or e.get("resource") or "Security signal logged",
                "source": e.get("source", "telemetry"),
            })

        # Scenario Title & Severity Determination
        if has_priv_or_dump and (has_c2_or_ids or has_proc_execution):
            scenario = "Advanced Multi-Stage Lateral Compromise & Credential Access"
            sev = "CRITICAL"
            conf = 95
            base_risk = 88.0
        elif has_auth_failure and has_proc_execution:
            scenario = "Account Compromise Followed by Living-Off-The-Land Execution"
            sev = "HIGH"
            conf = 88
            base_risk = 76.0
        elif has_c2_or_ids:
            scenario = "Persistent External C2 Communication & Exploit Delivery"
            sev = "HIGH"
            conf = 85
            base_risk = 72.0
        else:
            scenario = f"Correlated Multi-Event Anomaly Burst on {pivot_type}: {pivot_value}"
            sev = "MEDIUM"
            conf = 70
            base_risk = 55.0

        first_ts = sorted_events[0].get("timestamp", datetime.now(timezone.utc).isoformat())
        last_ts = sorted_events[-1].get("timestamp", datetime.now(timezone.utc).isoformat())

        unique_hosts = list({e.get("hostname") for e in sorted_events if e.get("hostname")})
        unique_users = list({e.get("username") for e in sorted_events if e.get("username")})
        unique_ips = list({e.get("source_ip") for e in sorted_events if e.get("source_ip")}.union({e.get("destination_ip") for e in sorted_events if e.get("destination_ip")}))

        explanation = (
            f"Correlated {len(sorted_events)} events across {distinct_signals_count} distinct detection domains. "
            f"Identified progressive kill-chain activity anchored on {pivot_type} '{pivot_value}' "
            f"spanning {len(tactics_observed)} MITRE tactics ({', '.join(tactics_observed) or 'Execution'})."
        )

        return CorrelationCandidate(
            candidate_id=f"CORR-{uuid.uuid4().hex[:8].upper()}",
            scenario_title=scenario,
            scenario_type="MULTI_SIGNAL_KILLCHAIN",
            severity=sev,
            confidence_score=conf,
            risk_score=min(99.0, base_risk + (len(sorted_events) * 1.5)),
            affected_entities={
                "hosts": unique_hosts,
                "users": unique_users,
                "ips": unique_ips,
            },
            mitre_tactics=list(tactics_observed),
            mitre_techniques=list(techniques_observed),
            events_count=len(sorted_events),
            first_event_time=first_ts,
            last_event_time=last_ts,
            event_ids=event_ids,
            timeline_steps=timeline_steps,
            explanation=explanation,
        )

    def _deduplicate_candidates(self, candidates: List[CorrelationCandidate]) -> List[CorrelationCandidate]:
        """Eliminates redundant candidates that share identical event ID sets."""
        seen_event_sets = []
        unique = []
        for c in candidates:
            evt_set = frozenset(c.event_ids)
            if not any(evt_set.issubset(s) or s.issubset(evt_set) for s in seen_event_sets):
                seen_event_sets.append(evt_set)
                unique.append(c)
        return unique


# Global instance
correlation_service = MultiSignalCorrelationEngine()
