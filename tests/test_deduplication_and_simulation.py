"""Unit Tests for Alert Deduplication & Safe Response Simulator."""
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.core.database import Base
from backend.app.models import SecurityEvent, Alert, ResponseAction
from backend.app.engines.deduplication_engine import deduplication_engine
from backend.app.services.response_simulator import response_simulator

def get_test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

def test_alert_deduplication_engine():
    db = get_test_db()
    
    # Event 1
    ev1 = SecurityEvent(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        event_type="login",
        status="FAILURE",
        severity="HIGH",
        resource="/ssh",
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    db.add(ev1)
    db.commit()

    alert1, is_new1 = deduplication_engine.find_or_create_deduplicated_alert(
        db=db,
        event=ev1,
        rule_name="Brute Force Login",
        severity="HIGH",
        risk_score=75.0,
        confidence_score=0.85,
        explanation={"reason": "Initial failure"}
    )
    assert is_new1 is True
    assert alert1.status == "NEW"

    # Event 2 (same entity in window)
    ev2 = SecurityEvent(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        event_type="login",
        status="FAILURE",
        severity="HIGH",
        resource="/ssh",
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    db.add(ev2)
    db.commit()

    alert2, is_new2 = deduplication_engine.find_or_create_deduplicated_alert(
        db=db,
        event=ev2,
        rule_name="Brute Force Login",
        severity="HIGH",
        risk_score=75.0,
        confidence_score=0.85,
        explanation={"reason": "Subsequent failure"}
    )
    assert is_new2 is False
    assert alert2.id == alert1.id
    assert len(alert2.event_ids) == 2

def test_safe_response_simulator():
    db = get_test_db()
    res = response_simulator.execute_simulated_action(
        db=db,
        action_type="ISOLATE_HOST",
        target="192.168.1.100",
        analyst_id="analyst-001",
        reason="Test containment"
    )
    assert res["status"] == "SIMULATED_SUCCESS"
    assert "SIMULATION ONLY" in res["simulation_badge"]
    assert "192.168.1.100" in res["command_executed"]
    assert res["action_type"] == "ISOLATE_HOST"
