"""Local Machine Learning Anomaly Detection Engine for SentinelAI SOC.

Utilizes scikit-learn IsolationForest combined with behavioral feature scoring
and SHAP-proxy feature attribution for explainable AI threat detection.
"""
from __future__ import annotations
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "failed_login_count",
    "successful_login_count",
    "event_frequency",
    "requests_per_minute",
    "unique_ip_count",
    "unique_user_count",
    "time_of_day_deviation",
    "weekend_deviation",
    "resource_sensitivity",
    "authentication_failure_ratio",
    "repeated_event_score",
    "source_reputation_score",
    "behavioral_deviation",
    "correlation_score",
]

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "anomaly_detector.joblib"


class AnomalyDetector:
    def __init__(self):
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self.is_trained: bool = False
        self.feature_names = FEATURE_COLUMNS
        self.last_trained_at: str | None = None
        self.training_sample_count: int = 0
        self._load_or_initialize()

    def _load_or_initialize(self) -> None:
        if MODEL_PATH.exists():
            try:
                bundle = joblib.load(MODEL_PATH)
                self.model = bundle.get("model")
                self.scaler = bundle.get("scaler")
                self.is_trained = bundle.get("is_trained", False)
                self.last_trained_at = bundle.get("last_trained_at")
                self.training_sample_count = bundle.get("training_sample_count", 0)
            except Exception:
                self.train_baseline()
        else:
            self.train_baseline()

    def _generate_synthetic_training_data(self, n_normal: int = 2000, n_anomaly: int = 200) -> pd.DataFrame:
        """Generates realistic synthetic behavioral baseline data for training."""
        rng = np.random.default_rng(42)

        normal_data = {
            "failed_login_count": rng.poisson(lam=0.2, size=n_normal),
            "successful_login_count": rng.poisson(lam=5.0, size=n_normal) + 1,
            "event_frequency": rng.poisson(lam=8.0, size=n_normal) + 1,
            "requests_per_minute": rng.uniform(0.1, 5.0, size=n_normal),
            "unique_ip_count": rng.choice([1, 2], p=[0.9, 0.1], size=n_normal),
            "unique_user_count": rng.choice([1, 2], p=[0.95, 0.05], size=n_normal),
            "time_of_day_deviation": rng.choice([0.0, 1.0], p=[0.85, 0.15], size=n_normal),
            "weekend_deviation": rng.choice([0.0, 1.0], p=[0.8, 0.2], size=n_normal),
            "resource_sensitivity": rng.choice([0.0, 1.0], p=[0.9, 0.1], size=n_normal),
            "authentication_failure_ratio": rng.beta(a=0.5, b=10.0, size=n_normal),
            "repeated_event_score": rng.uniform(0.0, 0.3, size=n_normal),
            "source_reputation_score": rng.choice([0.0, 1.0], p=[0.98, 0.02], size=n_normal),
            "behavioral_deviation": rng.uniform(0.0, 0.25, size=n_normal),
            "correlation_score": rng.uniform(0.0, 0.3, size=n_normal),
        }

        anomaly_data = {
            "failed_login_count": rng.poisson(lam=25.0, size=n_anomaly) + 5,
            "successful_login_count": rng.poisson(lam=1.0, size=n_anomaly),
            "event_frequency": rng.poisson(lam=60.0, size=n_anomaly) + 10,
            "requests_per_minute": rng.uniform(15.0, 120.0, size=n_anomaly),
            "unique_ip_count": rng.poisson(lam=6.0, size=n_anomaly) + 1,
            "unique_user_count": rng.poisson(lam=8.0, size=n_anomaly) + 1,
            "time_of_day_deviation": rng.choice([0.0, 1.0], p=[0.2, 0.8], size=n_anomaly),
            "weekend_deviation": rng.choice([0.0, 1.0], p=[0.3, 0.7], size=n_anomaly),
            "resource_sensitivity": rng.choice([0.0, 1.0], p=[0.2, 0.8], size=n_anomaly),
            "authentication_failure_ratio": rng.beta(a=8.0, b=1.5, size=n_anomaly),
            "repeated_event_score": rng.uniform(0.6, 1.0, size=n_anomaly),
            "source_reputation_score": rng.choice([0.0, 1.0], p=[0.4, 0.6], size=n_anomaly),
            "behavioral_deviation": rng.uniform(0.6, 1.0, size=n_anomaly),
            "correlation_score": rng.uniform(0.6, 1.0, size=n_anomaly),
        }

        df_normal = pd.DataFrame(normal_data)
        df_anomaly = pd.DataFrame(anomaly_data)
        return pd.concat([df_normal, df_anomaly], ignore_index=True)

    def train_baseline(self, custom_df: pd.DataFrame | None = None) -> Dict[str, Any]:
        """Trains or retrains the IsolationForest anomaly detector on telemetry."""
        if custom_df is not None and not custom_df.empty:
            df = custom_df[self.feature_names].copy().fillna(0)
        else:
            df = self._generate_synthetic_training_data()

        X = df[self.feature_names].values
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=42,
            max_samples="auto",
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        self.is_trained = True
        self.last_trained_at = datetime.now(timezone.utc).isoformat()
        self.training_sample_count = len(df)

        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "is_trained": True,
                "last_trained_at": self.last_trained_at,
                "training_sample_count": self.training_sample_count,
            },
            MODEL_PATH,
        )

        return {
            "status": "TRAINED",
            "samples_trained": self.training_sample_count,
            "trained_at": self.last_trained_at,
            "features": self.feature_names,
        }

    def score_event_features(self, feature_data: Dict[str, Any] | Any) -> Dict[str, Any]:
        """Evaluates an event's feature vector and calculates anomaly probability & SHAP explanations."""
        if not self.is_trained or self.model is None or self.scaler is None:
            self.train_baseline()

        if hasattr(feature_data, "__dict__"):
            raw_dict = {
                k: float(getattr(feature_data, k, 0.0) or 0.0)
                for k in self.feature_names
            }
        else:
            raw_dict = {
                k: float(feature_data.get(k, 0.0) or 0.0)
                for k in self.feature_names
            }

        vec = np.array([[raw_dict.get(k, 0.0) for k in self.feature_names]])
        vec_scaled = self.scaler.transform(vec)

        # Raw anomaly decision score (negative = anomaly)
        raw_score = float(self.model.decision_function(vec_scaled)[0])
        
        # Rule-based heuristic boost
        heuristic_score = (
            min(1.0, raw_dict.get("failed_login_count", 0) / 10.0) * 35.0
            + raw_dict.get("authentication_failure_ratio", 0) * 25.0
            + raw_dict.get("source_reputation_score", 0) * 20.0
            + raw_dict.get("behavioral_deviation", 0) * 15.0
            + raw_dict.get("resource_sensitivity", 0) * 10.0
        )
        
        # Sigmoid conversion of IsolationForest score
        ml_score = float(np.clip(1.0 / (1.0 + np.exp(raw_score * 8.0)), 0.0, 1.0)) * 100.0
        
        # Combined hybrid risk score
        risk_score = round(min(99.0, max(5.0, 0.4 * ml_score + 0.6 * heuristic_score)), 1)
        is_anomaly = bool(risk_score >= 60.0)

        # Feature attributions
        feature_contributions = {}
        for idx, col in enumerate(self.feature_names):
            scaled_val = abs(float(vec_scaled[0][idx]))
            feature_contributions[col] = round(scaled_val, 3)

        top_factors = sorted(
            feature_contributions.items(), key=lambda x: x[1], reverse=True
        )[:4]

        explanation_factors = [
            {
                "feature": k.replace("_", " ").title(),
                "weight": v,
                "description": self._describe_factor(k, raw_dict.get(k, 0)),
            }
            for k, v in top_factors if v > 0.4
        ]

        confidence = round(min(0.98, max(0.55, 0.5 + abs(risk_score - 50) / 100.0)), 2)

        return {
            "risk_score": risk_score,
            "is_anomaly": is_anomaly,
            "confidence_score": confidence,
            "raw_decision_score": round(raw_score, 4),
            "top_contributing_factors": explanation_factors,
            "feature_vector": raw_dict,
        }

    def _describe_factor(self, feature_name: str, value: float) -> str:
        descriptions = {
            "failed_login_count": f"Elevated failed authentication attempts ({int(value)} failures)",
            "successful_login_count": f"Multiple concurrent successful authentications ({int(value)})",
            "event_frequency": f"Abnormal burst in event frequency ({int(value)} events)",
            "requests_per_minute": f"High request velocity ({value:.1f} req/min)",
            "unique_ip_count": f"Distributed origin from {int(value)} unique IPs",
            "unique_user_count": f"Targeting {int(value)} unique user accounts",
            "time_of_day_deviation": "Activity observed outside standard operational hours",
            "weekend_deviation": "Activity logged during non-business weekend period",
            "resource_sensitivity": "Access attempt against critical/sensitive resource",
            "authentication_failure_ratio": f"Extremely high failure ratio ({value*100:.1f}%)",
            "repeated_event_score": "High repetition of identical event payloads",
            "source_reputation_score": "Source entity matches known active Threat Intelligence indicator",
            "behavioral_deviation": "Significant divergence from baseline entity profile",
            "correlation_score": "Strong multi-event entity correlation pattern",
        }
        return descriptions.get(feature_name, f"Anomalous metric for {feature_name}: {value}")


_detector_instance: AnomalyDetector | None = None

def get_anomaly_detector() -> AnomalyDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
    return _detector_instance
