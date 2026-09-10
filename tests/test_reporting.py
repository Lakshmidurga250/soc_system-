from datetime import datetime, timezone
from backend.app.models import Incident, Alert, Investigation
from backend.app.services.reporting import generate_incident_pdf, generate_soc_executive_pdf

def test_incident_pdf_generation():
    inc = Incident(
        id="inc-test-01",
        title="Brute Force Detection",
        description="Multiple failed login attempts observed.",
        severity="HIGH",
        risk_score=88.0,
        confidence=0.92,
        status="OPEN",
        created_at=datetime.now(timezone.utc),
    )
    alert = Alert(
        id="alt-01",
        title="Multiple Failed Logins",
        severity="HIGH",
        risk_score=88.0,
        source="rule_engine",
        created_at=datetime.now(timezone.utc),
    )
    inv = Investigation(
        id="inv-01",
        incident_id=inc.id,
        summary="Investigated 50 events.",
        timeline=[{"at": "2026-09-10T20:00:00", "event_id": "evt-01", "description": "Failed login attempt"}],
    )
    pdf_bytes = generate_incident_pdf(inc, [alert], inv)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")

def test_soc_executive_pdf_generation():
    kpis = {
        "total_events": 1200,
        "active_alerts": 14,
        "open_incidents": 3,
        "critical_incidents": 1,
        "anomalies_detected": 5,
        "investigations_running": 0,
    }
    by_sev = {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 7, "LOW": 10}
    pdf_bytes = generate_soc_executive_pdf(kpis, by_sev)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")
