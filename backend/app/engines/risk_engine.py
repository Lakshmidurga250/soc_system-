"""Transparent Multi-Factor Risk Calculation Engine for SentinelAI SOC."""
from typing import Dict, Any

class RiskEngine:
    def calculate_risk(
        self,
        severity: str,
        confidence: float,
        behavior_deviation: float = 0.0,
        threat_intel_match: bool = False,
        asset_criticality: float = 1.0,
        frequency_factor: float = 1.0,
    ) -> Dict[str, Any]:
        """Computes a multi-factor risk score with fully auditable factor contributions."""
        sev_weights = {
            "CRITICAL": 90.0,
            "HIGH": 70.0,
            "MEDIUM": 45.0,
            "LOW": 20.0,
            "INFORMATIONAL": 5.0,
        }
        base_sev = sev_weights.get(severity.upper(), 30.0)

        # Multi-factor composition
        intel_boost = 25.0 if threat_intel_match else 0.0
        behavior_boost = behavior_deviation * 20.0
        freq_boost = min(15.0, (frequency_factor - 1.0) * 3.0)

        raw_score = (base_sev * 0.5) + intel_boost + behavior_boost + freq_boost
        adjusted_score = raw_score * (0.5 + (confidence * 0.5)) * asset_criticality
        final_risk = round(min(99.0, max(5.0, adjusted_score)), 1)

        # Risk tier classification
        if final_risk >= 80.0:
            tier = "CRITICAL"
        elif final_risk >= 60.0:
            tier = "HIGH"
        elif final_risk >= 35.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        contributions = [
            {"factor": "Base Severity Rating", "points": round(base_sev * 0.5, 1)},
            {"factor": "Threat Intelligence Alignment", "points": intel_boost},
            {"factor": "Behavioral Anomaly Deviation", "points": round(behavior_boost, 1)},
            {"factor": "Event Velocity / Frequency", "points": round(freq_boost, 1)},
            {"factor": "Analyst & Model Confidence Multiplier", "points": round(confidence, 2)},
        ]

        return {
            "risk_score": final_risk,
            "risk_tier": tier,
            "confidence": round(confidence, 2),
            "contributing_factors": [c for c in contributions if c["points"] > 0],
            "explanation": f"Computed {tier} risk score ({final_risk}/100) based on {severity} severity, {int(confidence*100)}% confidence, and behavioral metrics.",
        }

risk_engine = RiskEngine()
