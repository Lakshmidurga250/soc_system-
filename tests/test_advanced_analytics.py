"""Automated Test Suite for Advanced Mathematical SOC Analytics & Graph Algorithms."""

import pytest
from backend.app.ml.markov_detector import markov_detector, MarkovProcessChainDetector
from backend.app.ml.bayesian_risk import (
    bayesian_engine,
    BayesianRiskInference,
    EvidenceObservation,
    EvidenceType,
)
from backend.app.ml.timeseries_forecaster import timeseries_forecaster, HoltWintersForecaster
from backend.app.graph.graph_algorithms import attack_graph_analytics
from backend.app.services.soar_playbooks import soar_engine
from backend.app.services.forensic_analyzer import forensic_analyzer


def test_markov_sequence_anomaly_scoring():
    # Normal enterprise sequence
    normal_seq = ["explorer.exe", "chrome.exe", "chrome.exe"]
    res_normal = markov_detector.score_sequence(normal_seq)
    assert not res_normal["is_anomalous"]
    assert res_normal["perplexity"] < 20.0

    # Anomalous malicious LOLBin / weaponization chain
    malicious_seq = ["winword.exe", "powershell.exe", "whoami.exe", "mimikatz.exe"]
    res_malicious = markov_detector.score_sequence(malicious_seq)
    assert res_malicious["is_anomalous"]
    assert res_malicious["anomaly_score"] >= 0.50
    assert res_malicious["rare_transitions_count"] >= 1


def test_bayesian_risk_belief_updating():
    engine = BayesianRiskInference(prior_probability=0.05)

    # 1. Host with no suspicious evidence
    clean_obs = [
        EvidenceObservation(evidence_type=EvidenceType.FAILED_LOGINS, observed=False),
        EvidenceObservation(evidence_type=EvidenceType.ML_ANOMALY, observed=False),
    ]
    res_clean = engine.infer_compromise_probability(clean_obs)
    assert res_clean["posterior_probability"] <= 0.05

    # 2. Host with high-fidelity IoCs, C2 beaconing, and Sigma matches
    threat_obs = [
        EvidenceObservation(evidence_type=EvidenceType.C2_BEACONING, observed=True, confidence=1.0),
        EvidenceObservation(evidence_type=EvidenceType.SIGMA_RULE_MATCH, observed=True, confidence=1.0),
        EvidenceObservation(evidence_type=EvidenceType.PROCESS_INJECTION, observed=True, confidence=0.9),
    ]
    res_threat = engine.infer_compromise_probability(threat_obs)
    assert res_threat["posterior_probability"] >= 0.90
    assert res_threat["threat_level"] == "CRITICAL_COMPROMISE"
    assert res_threat["recommended_urgency"] == "IMMEDIATE_CONTAINMENT"


def test_holt_winters_timeseries_forecaster():
    forecaster = HoltWintersForecaster(season_length=12, confidence_z=2.5)

    # Generate synthetic 48-hour periodic traffic baseline with an injection spike at t=40
    series = []
    for t in range(48):
        baseline = 100.0 + 30.0 * (t % 12)  # Daily periodic wave
        if t == 40:
            baseline += 500.0  # Massive data exfiltration / burst
        series.append(baseline)

    result = forecaster.fit_and_detect(series)
    assert result["total_samples"] == 48
    assert result["anomaly_count"] >= 1
    # Check that anomaly was detected at index 40
    anom_indices = [a["index"] for a in result["anomalies"]]
    assert 40 in anom_indices


def test_attack_graph_shortest_path_and_centrality():
    nodes = [
        {"id": "host:workstation-01", "label": "Workstation-01", "type": "Host"},
        {"id": "user:jsmith", "label": "jsmith", "type": "User"},
        {"id": "host:jumpbox-01", "label": "Jumpbox-01", "type": "Host"},
        {"id": "user:adm_backup", "label": "adm_backup", "type": "User"},
        {"id": "host:domain-controller", "label": "DC-01", "type": "CrownJewel"},
    ]

    edges = [
        {"source": "host:workstation-01", "target": "user:jsmith", "weight": 1.0, "relation": "LOGGED_IN"},
        {"source": "user:jsmith", "target": "host:jumpbox-01", "weight": 2.0, "relation": "SSH_ACCESS"},
        {"source": "host:jumpbox-01", "target": "user:adm_backup", "weight": 1.5, "relation": "STOLEN_CRED"},
        {"source": "user:adm_backup", "target": "host:domain-controller", "weight": 1.0, "relation": "RDP_ADMIN"},
    ]

    # Dijkstra shortest attack path
    path_res = attack_graph_analytics.find_shortest_attack_path(
        nodes=nodes,
        edges=edges,
        start_node_id="host:workstation-01",
        target_node_id="host:domain-controller",
    )
    assert path_res.path_found
    assert path_res.hop_count == 4
    assert path_res.nodes_in_path[0] == "host:workstation-01"
    assert path_res.nodes_in_path[-1] == "host:domain-controller"

    # PageRank
    pr = attack_graph_analytics.calculate_pagerank(nodes, edges)
    assert len(pr) == len(nodes)
    assert sum(pr.values()) > 95.0  # Sum normalized near 100

    # Betweenness Centrality
    bc = attack_graph_analytics.calculate_betweenness_centrality(nodes, edges)
    assert len(bc) == len(nodes)

    # Blast Radius
    blast = attack_graph_analytics.compute_blast_radius(nodes, edges, ["host:jumpbox-01"], max_hops=2)
    assert blast["total_nodes_in_blast_radius"] >= 3


def test_soar_playbook_catalog_and_execution():
    playbooks = soar_engine.list_playbooks()
    assert len(playbooks) >= 4
    pb_ids = [p["id"] for p in playbooks]
    assert "PB-RANSOMWARE-01" in pb_ids
    assert "PB-C2-COBALTSTRIKE-02" in pb_ids

    # Dry-run execution
    exec_res = soar_engine.execute_playbook(
        playbook_id="PB-RANSOMWARE-01",
        incident_id="INC-2026-TEST",
        target_entity="host:fin-srv-01",
        analyst_user="analyst_lead",
        dry_run=True,
    )
    assert exec_res["status"] == "DRY_RUN_COMPLETED"
    assert exec_res["steps_executed"] == 4
    assert exec_res["step_results"][0]["action"] == "NETWORK_ISOLATE_HOST"


def test_host_forensics_mft_timestomping():
    # Synthetic MFT records: normal vs timestomped
    records = [
        {
            "file_path": "C:\\Windows\\System32\\calc.exe",
            "si_created_time": "2024-01-01T10:00:00Z",
            "fn_created_time": "2024-01-01T10:00:02Z",
        },
        {
            "file_path": "C:\\Windows\\Temp\\malware.exe",
            "si_created_time": "2020-01-01T00:00:00Z",  # Backdated 4 years earlier
            "fn_created_time": "2024-01-01T10:00:00Z",
        },
    ]
    findings = forensic_analyzer.detect_mft_timestomping(records)
    assert len(findings) == 2
    assert not findings[0]["is_timestomped"]
    assert findings[1]["is_timestomped"]
    assert findings[1]["mitre_technique"] == "T1070.006"
