import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal, init_db
from backend.app.models import User
from backend.app.core.security import hash_password
from backend.app.services.detection import seed_rules

@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()
    db = SessionLocal()
    try:
        seed_rules(db)
        admin = db.query(User).filter_by(email="admin@sentinelai.local").first()
        if not admin:
            db.add(User(
                full_name="SentinelAI Administrator",
                username="admin",
                email="admin@sentinelai.local",
                password_hash=hash_password("SentinelDemo!2026"),
                role="ADMIN"
            ))
        else:
            if not admin.username:
                admin.username = "admin"
        db.commit()
    finally:
        db.close()

def test_auth_and_dashboard_flow():
    with TestClient(app) as client:
        # Login as admin demo
        resp = client.post("/api/v1/auth/login", json={"email": "admin@sentinelai.local", "password": "SentinelDemo!2026"})
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Verify /auth/me
        me_resp = client.get("/api/v1/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == "admin@sentinelai.local"

        # Verify /dashboard
        dash_resp = client.get("/api/v1/dashboard", headers=headers)
        assert dash_resp.status_code == 200
        assert "kpis" in dash_resp.json()

        # Ingest synthetic events
        sim_resp = client.post("/api/v1/simulation/run", json={"scenario": "brute_force", "count": 10, "seed": 42}, headers=headers)
        assert sim_resp.status_code == 200
        assert sim_resp.json()["generated"] == 10

        # List events
        events_resp = client.get("/api/v1/events", headers=headers)
        assert events_resp.status_code == 200
        assert len(events_resp.json()["items"]) >= 10

        # Query ML status
        ml_resp = client.get("/api/v1/ml/status", headers=headers)
        assert ml_resp.status_code == 200
        assert ml_resp.json()["anomaly_detector"]["is_trained"] is True

        # Test PDF executive summary
        pdf_resp = client.get("/api/v1/reports/executive-summary/pdf", headers=headers)
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"
