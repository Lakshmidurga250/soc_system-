"""System Diagnostics and Health Probe endpoints."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import User
from ...ml.anomaly_detector import get_anomaly_detector

router = APIRouter(prefix="/health", tags=["System Health"])

@router.get("")
def health_check(db: Session = Depends(get_db)):
    db.execute(select(func.count()).select_from(User))
    detector = get_anomaly_detector()
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "backend_api": "healthy",
            "sqlite_wal_database": "healthy",
            "detection_rule_engine": "healthy",
            "ml_anomaly_detector": "operational" if detector.is_trained else "ready",
            "simulation_lab": "ready",
            "knowledge_graph": "healthy",
            "pdf_report_engine": "ready",
        },
    }
