"""
SentinelAI - Real-Time Behavioral Entity Risk Multi-Dimensional Aggregator
"""

from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class AggregatedRiskProfile:
    entity_id: str
    entity_type: str
    ml_anomaly_score: float
    threat_intel_score: float
    cve_exposure_score: float
    final_risk_score: float
    risk_tier: str

class BehavioralRiskAggregator:
    def compute_risk(self, ml: float, ti: float, cve: float) -> AggregatedRiskProfile:
        score = (ml * 0.4) + (ti * 0.35) + (cve * 0.25)
        tier = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW"
        return AggregatedRiskProfile("entity_01", "HOST", ml, ti, cve, round(score, 2), tier)

risk_aggregator = BehavioralRiskAggregator()
