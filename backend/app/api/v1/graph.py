"""Security Knowledge Graph endpoints."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...graph.knowledge_graph import knowledge_graph
from ..deps import current_user

router = APIRouter(prefix="/graph", tags=["Knowledge Graph"])

@router.get("/topology")
def get_graph_topology(limit: int = Query(default=300, le=1000), db: Session = Depends(get_db), user = Depends(current_user)):
    return knowledge_graph.build_graph(db, limit_events=limit)

@router.get("/neighborhood")
def get_entity_neighborhood(entity: str = Query(...), db: Session = Depends(get_db), user = Depends(current_user)):
    return knowledge_graph.query_subgraph_for_entity(db, entity_value=entity)
