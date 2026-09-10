"""Simulation Lab Attack Scenario Injection endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...schemas.domain import SimulationRequest
from ...engines.simulation_engine import simulation_engine
from ...services.audit import audit
from ..deps import require_roles

router = APIRouter(prefix="/simulation", tags=["Simulation Lab"])

@router.post("/run")
def run_simulation_scenario(payload: SimulationRequest, db: Session = Depends(get_db), user = Depends(require_roles("ADMIN", "SOC_ANALYST"))):
    run = simulation_engine.run_scenario(
        db,
        scenario=payload.scenario,
        count=payload.count,
        seed=payload.seed,
    )
    audit(db, "SIMULATION_SCENARIO_EXECUTED", f"simulation:{run.id}", user.id, scenario=payload.scenario, generated_count=run.generated_count)
    db.commit()
    return {
        "id": run.id,
        "scenario": run.scenario,
        "generated": run.generated_count,
        "synthetic": True,
        "status": "COMPLETED",
    }
