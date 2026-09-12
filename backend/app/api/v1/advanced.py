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
