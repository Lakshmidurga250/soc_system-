from backend.app.services.risk import score

def test_risk_score_is_explainable_and_bounded():
    result=score(severity="HIGH",count=8,indicator=True)
    assert 0 <= result["risk_score"] <= 100
    assert result["severity"] in {"HIGH","CRITICAL"}
    assert any(item["name"] == "local threat indicator match" for item in result["risk_factors"])
