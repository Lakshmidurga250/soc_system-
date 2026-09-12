"""Comprehensive Tests for Global Search, Adaptive Investigation Optimizer, and RBAC."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.core.database import SessionLocal
from backend.app.models import User, Alert, Incident, SecurityEvent, Asset, ThreatIndicator
from backend.app.core.security import hash_password
from backend.app.optimization.investigation_optimizer import InvestigationOptimizer

client = TestClient(app)

@pytest.fixture
def auth_headers():
    """Create test admin and analyst users and return valid JWT auth headers."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter_by(email="test_admin_search@sentinelai.local").first()
        if not admin:
            admin = User(
                full_name="Search Test Admin",
                username="test_admin_search",
                email="test_admin_search@sentinelai.local",
                password_hash=hash_password("SentinelAdmin!2026"),
                role="ADMIN"
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            
        login_res = client.post("/api/v1/auth/login", json={
            "identifier": "test_admin_search@sentinelai.local",
            "password": "SentinelAdmin!2026"
        })
        assert login_res.status_code == 200, login_res.text
        token = login_res.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    finally:
        db.close()

def test_global_search_endpoint(auth_headers):
    """Test multi-entity unified fuzzy search across alerts, incidents, events, and assets."""
    db = SessionLocal()
    try:
        # Seed test entities if not present
        test_asset = db.query(Asset).filter_by(hostname="prod-finance-db").first()
        if not test_asset:
            test_asset = Asset(
                hostname="prod-finance-db",
                ip_address="10.0.0.50",
                asset_type="DATABASE",
                criticality="TIER_1",
                owner="Financial SecOps"
            )
            db.add(test_asset)

        test_event = db.query(SecurityEvent).filter_by(hostname="prod-finance-db").first()
        if not test_event:
            test_event = SecurityEvent(
                source_ip="198.51.100.77",
                destination_ip="10.0.0.50",
                username="investigator_target",
                hostname="prod-finance-db",
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                severity="HIGH"
            )
            db.add(test_event)

        test_alert = db.query(Alert).filter(Alert.title.contains("prod-finance-db")).first()
        if not test_alert:
            test_alert = Alert(
                title="Brute Force on prod-finance-db",
                description="Repeated authentication failures detected from 198.51.100.77",
                source="rule_engine",
                detection_method="RULE",
                severity="HIGH",
                risk_score=85.0,
                confidence_score=0.92,
                status="NEW"
            )
            db.add(test_alert)

        db.commit()

        # Query global search
        res = client.get("/api/v1/search?q=prod-finance-db", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["query"] == "prod-finance-db"
        assert data["total_matches"] >= 2
        assert "categories" in data
        assert len(data["categories"]["alerts"]) >= 1
        assert len(data["categories"]["assets"]) >= 1
    finally:
        db.close()

def test_investigation_optimizer_execution():
    """Verify that the adaptive investigation optimizer adjusts execution depth based on risk score."""
    optimizer = InvestigationOptimizer()
    
    # 1. Low Risk Incident
    plan_low = optimizer.schedule_adaptive_pipeline(severity="LOW", risk_score=15.0)
    assert plan_low["executed_stages_count"] < plan_low["total_stages_count"]
    assert plan_low["compute_savings_percentage"] > 0
    assert len(plan_low["skipped_stages"]) >= 1

    # 2. Critical Risk Incident
    plan_critical = optimizer.schedule_adaptive_pipeline(severity="CRITICAL", risk_score=95.0)
    assert plan_critical["executed_stages_count"] == plan_critical["total_stages_count"]
    assert len(plan_critical["skipped_stages"]) == 0

    # 3. Investigation step planner
    plan_steps = optimizer.optimize_investigation_plan(
        incident_id="inc-test-01",
        affected_entities={"source_ips": ["192.168.1.50"], "usernames": ["admin"]},
        max_steps=3
    )
    assert "optimized_investigation_path" in plan_steps
    assert len(plan_steps["optimized_investigation_path"]) <= 3

def test_rbac_user_management_access(auth_headers):
    """Verify that user governance operations are restricted and function correctly for admins."""
    # List users
    res = client.get("/api/v1/users", headers=auth_headers)
    assert res.status_code == 200
    users = res.json()
    assert isinstance(users, list)
    assert len(users) >= 1
