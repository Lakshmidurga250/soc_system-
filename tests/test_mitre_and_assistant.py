"""Unit Tests for MITRE ATT&CK Mapping & Local Investigation Assistant."""
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.core.database import Base
from backend.app.models import Incident, Alert, SecurityEvent
from backend.app.intelligence.mitre_mapper import mitre_mapper
from backend.app.engines.assistant_engine import assistant_engine
from backend.app.optimization.investigation_optimizer import investigation_optimizer

def get_test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

def test_mitre_mapper_coverage():
    res_brute = mitre_mapper.map_category("Brute Force")
    assert res_brute["technique_id"] == "T1110"
    assert res_brute["tactic"] == "Credential Access"

    res_dos = mitre_mapper.map_category("DoS")
    assert res_dos["technique_id"] == "T1499"

    res_exfil = mitre_mapper.map_category("Data Exfiltration")
    assert res_exfil["technique_id"] == "T1048"

    matrix = mitre_mapper.get_full_matrix()
    assert len(matrix) >= 10

def test_local_investigation_assistant():
    db = get_test_db()
    
    # Create test incident
    inc = Incident(
        title="Active Credential Stuffing Campaign",
        description="Automated incident detection case for testing",
        severity="CRITICAL",
        risk_score=88.5,
        confidence=0.92,
        status="OPEN",
        root_cause="Repeated failed authentications exceeding velocity threshold",
        alert_ids=[]
    )
    db.add(inc)
    db.commit()

    # Query 1: Summary / What happened
    res1 = assistant_engine.query_incident_investigation(db, inc.id, "What happened in this incident?")
    assert "Incident 'Active Credential Stuffing Campaign'" in res1["answer"]
    assert "T1110" in res1["mitre_technique"]

    # Query 2: Risk score explanation
    res2 = assistant_engine.query_incident_investigation(db, inc.id, "Why is the risk score high?")
    assert "88.5/100" in res2["answer"]

    # Query 3: Next steps
    res3 = assistant_engine.query_incident_investigation(db, inc.id, "What should the analyst investigate next?")
    assert len(res3["suggested_next_steps"]) > 0

def test_investigation_optimization_scheduling():
    opt_crit = investigation_optimizer.schedule_adaptive_pipeline(severity="CRITICAL", risk_score=95.0)
    assert opt_crit["executed_stages_count"] >= 7
    assert opt_crit["confidence_retained_percentage"] >= 98.0

    opt_low = investigation_optimizer.schedule_adaptive_pipeline(severity="LOW", risk_score=15.0)
    assert opt_low["compute_savings_percentage"] > 50.0
    assert len(opt_low["skipped_stages"]) >= 4
