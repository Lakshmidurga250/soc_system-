SEVERITY = {"LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90}

def score(*, severity: str, count: int = 1, behavior: float = 0, indicator: bool = False, confidence: float = 0.65) -> dict:
    factors = [{"name": "event severity", "value": severity, "points": SEVERITY.get(severity.upper(), 20)}]
    value = SEVERITY.get(severity.upper(), 20)
    if count > 1:
        bonus = min(20, count * 2); value += bonus; factors.append({"name": "related event frequency", "value": count, "points": bonus})
    if behavior:
        bonus = min(15, round(behavior * 15)); value += bonus; factors.append({"name": "behavioral deviation", "value": behavior, "points": bonus})
    if indicator:
        value += 15; factors.append({"name": "local threat indicator match", "value": True, "points": 15})
    value = min(100, value)
    return {"risk_score": value, "confidence_score": round(min(.99, confidence + count / 100), 2), "risk_factors": factors, "severity": "CRITICAL" if value >= 85 else "HIGH" if value >= 65 else "MEDIUM" if value >= 35 else "LOW"}
