"""Master API Router mounting all modular V1 controllers."""
from fastapi import APIRouter
from .v1 import (
    auth, users, dashboard, events, logs, alerts, incidents,
    graph, intelligence, detection, ml, behavior,
    risk, response, approvals, reports, audit, simulation, health,
    assistant, assets, analytics
)

router = APIRouter(prefix="/api/v1")

# Mount all domain routers
router.include_router(auth.router)
router.include_router(users.router)
router.include_router(dashboard.router)
router.include_router(events.router)
router.include_router(logs.router)
router.include_router(alerts.router)
router.include_router(incidents.router)
router.include_router(graph.router)
router.include_router(intelligence.router)
router.include_router(detection.router)
router.include_router(ml.router)
router.include_router(behavior.router)
router.include_router(risk.router)
router.include_router(response.router)
router.include_router(approvals.router)
router.include_router(reports.router)
router.include_router(audit.router)
router.include_router(simulation.router)
router.include_router(health.router)
router.include_router(assistant.router)
router.include_router(assets.router)
router.include_router(analytics.router)
