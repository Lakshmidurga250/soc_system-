"""Unit & Evaluation Tests for Multi-Model ML Threat Classifiers."""
import numpy as np
import pandas as pd
from backend.app.ml.preprocessor import preprocessor, FEATURE_COLUMNS, ATTACK_CLASSES
from backend.app.ml.threat_classifier import threat_classifier
from backend.app.ml.evaluator import model_evaluator

def test_preprocessor_fit_transform():
    data = []
    for i in range(100):
        row = {col: float(i % 10) for col in FEATURE_COLUMNS}
        row["category"] = "Brute Force" if i % 2 == 0 else "Normal"
        data.append(row)
    df = pd.DataFrame(data)

    X_trans, y_trans = preprocessor.fit_transform(df, df["category"])
    assert X_trans.shape == (100, 14)
    assert len(y_trans) == 100
    assert isinstance(X_trans, np.ndarray)

def test_multi_model_training_and_benchmarks():
    data = []
    for i in range(200):
        row = {col: float(np.random.rand() * 5) for col in FEATURE_COLUMNS}
        if i < 50:
            row["category"] = "Brute Force"
            row["failed_login_count"] = 12.0
        elif i < 100:
            row["category"] = "DoS"
            row["requests_per_minute"] = 800.0
        elif i < 150:
            row["category"] = "Port Scan"
            row["unique_ip_count"] = 50.0
        else:
            row["category"] = "Normal"
        data.append(row)
    df = pd.DataFrame(data)

    benchmarks = threat_classifier.train_and_benchmark_all(df, target_column="category")
    
    for model_name in ["random_forest", "decision_tree", "logistic_regression", "gradient_boosting"]:
        assert model_name in benchmarks
        res = benchmarks[model_name]
        assert "accuracy" in res
        assert "f1_weighted" in res
        assert "precision_weighted" in res
        assert "recall_weighted" in res
        assert res["accuracy"] >= 0.70

def test_threat_classifier_predict_single():
    sample_feature = {
        "failed_login_count": 15.0,
        "successful_login_count": 0.0,
        "event_frequency": 25.0,
        "requests_per_minute": 60.0,
        "unique_ip_count": 1.0,
        "unique_user_count": 1.0,
        "time_of_day_deviation": 1.0,
        "weekend_deviation": 0.0,
        "resource_sensitivity": 1.0,
        "authentication_failure_ratio": 1.0,
        "repeated_event_score": 0.9,
        "source_reputation_score": 1.0,
        "behavioral_deviation": 0.8,
        "correlation_score": 0.7,
    }
    pred = threat_classifier.predict(sample_feature)
    assert "predicted_category" in pred
    assert "confidence" in pred
    assert pred["confidence"] > 0.5
