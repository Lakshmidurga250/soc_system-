import pytest
from backend.app.ml.anomaly_detector import AnomalyDetector
from backend.app.ml.playbook_generator import generate_incident_playbook
from backend.app.models import Incident, Alert, SecurityEvent

def test_anomaly_detector_training_and_scoring():
    detector = AnomalyDetector()
    train_res = detector.train_baseline()
    assert train_res["status"] == "TRAINED"
    assert detector.is_trained is True

    # Normal feature vector
    normal_vector = {
        "failed_login_count": 0,
        "successful_login_count": 5,
        "event_frequency": 5,
        "requests_per_minute": 1.0,
        "unique_ip_count": 1,
        "unique_user_count": 1,
        "time_of_day_deviation": 0.0,
        "weekend_deviation": 0.0,
        "resource_sensitivity": 0.0,
        "authentication_failure_ratio": 0.0,
        "repeated_event_score": 0.1,
        "source_reputation_score": 0.0,
        "behavioral_deviation": 0.05,
        "correlation_score": 0.1,
    }
    score_normal = detector.score_event_features(normal_vector)
    assert "risk_score" in score_normal
    assert score_normal["risk_score"] < 65.0

    # Anomalous feature vector (Brute force + unusual hour)
    anomaly_vector = {
        "failed_login_count": 50,
        "successful_login_count": 0,
        "event_frequency": 120,
        "requests_per_minute": 60.0,
        "unique_ip_count": 10,
        "unique_user_count": 5,
        "time_of_day_deviation": 1.0,
        "weekend_deviation": 1.0,
        "resource_sensitivity": 1.0,
        "authentication_failure_ratio": 0.95,
        "repeated_event_score": 0.8,
        "source_reputation_score": 1.0,
        "behavioral_deviation": 0.9,
        "correlation_score": 0.85,
    }
    score_anomaly = detector.score_event_features(anomaly_vector)
    assert score_anomaly["risk_score"] >= 60.0
    assert len(score_anomaly["top_contributing_factors"]) > 0

def test_incident_playbook_generation():
    incident = Incident(
        id="inc-test-01",
        title="Incident: Brute Force Authentication",
        description="Multiple failed logins",
        severity="HIGH",
        risk_score=85.0,
        confidence=0.9,
    )
    alert = Alert(
        id="alt-01",
        title="Multiple Failed Logins",
        severity="HIGH",
        risk_score=85.0,
        confidence_score=0.9,
        entities={"source_ip": "198.51.100.44", "username": "admin"},
        event_ids=["evt-01"],
    )
    event = SecurityEvent(
        id="evt-01",
        event_type="auth_failure",
        source_ip="198.51.100.44",
        username="admin",
        hostname="auth-srv-01",
    )
    playbook = generate_incident_playbook(incident, [alert], [event])
    assert playbook["threat_category"] == "CREDENTIAL_ATTACK"
    assert "198.51.100.44" in playbook["affected_entities"]["source_ips"]
    assert len(playbook["response_playbook"]) >= 3
    assert len(playbook["suggested_actions"]) > 0
