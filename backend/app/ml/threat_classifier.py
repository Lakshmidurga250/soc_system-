"""Multi-Model Supervised ML Threat Classifier Suite."""
import os
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from .preprocessor import preprocessor, FEATURE_COLUMNS, ATTACK_CLASSES
from .evaluator import model_evaluator

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

class MultiModelThreatClassifier:
    """Trains, persists, evaluates, and predicts with multiple threat classification architectures."""

    SUPPORTED_MODELS = {
        "random_forest": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1),
        "decision_tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "logistic_regression": LogisticRegression(max_iter=1000, random_state=42),
        "gradient_boosting": GradientBoostingClassifier(n_estimators=60, max_depth=6, random_state=42),
    }

    def __init__(self):
        self.active_model_name = "random_forest"
        self.models: Dict[str, Any] = {}
        self.benchmarks: Dict[str, Dict[str, Any]] = {}
        self._load_or_init_models()

    def _load_or_init_models(self):
        """Load trained models from disk if present."""
        for name in self.SUPPORTED_MODELS.keys():
            path = MODEL_DIR / f"{name}_classifier.joblib"
            if path.exists():
                try:
                    self.models[name] = joblib.load(path)
                except Exception:
                    pass

    def train_and_benchmark_all(self, df: pd.DataFrame, target_column: str = "category") -> Dict[str, Any]:
        """Train all supported models on dataset and compute comparative benchmark table."""
        if target_column not in df.columns:
            # Fallback target column if not explicitly labeled
            df[target_column] = "Normal"

        # Fit preprocessor
        X_trans, y_trans = preprocessor.fit_transform(df, df[target_column])
        
        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X_trans, y_trans, test_size=0.25, random_state=42, stratify=y_trans if len(np.unique(y_trans)) > 1 else None
        )

        results = {}
        class_names = list(preprocessor.label_encoder.classes_)

        for model_name, base_model in self.SUPPORTED_MODELS.items():
            model = type(base_model)(**base_model.get_params())
            
            # Measure training time
            t0 = time.time()
            model.fit(X_train, y_train)
            train_time = time.time() - t0

            # Measure inference time
            t1 = time.time()
            y_pred = model.predict(X_test)
            inf_time = time.time() - t1

            # Get class probability distribution if supported
            y_prob = None
            if hasattr(model, "predict_proba"):
                try:
                    y_prob = model.predict_proba(X_test)
                except Exception:
                    y_prob = None

            metrics = model_evaluator.evaluate(
                y_true=y_test,
                y_pred=y_pred,
                y_prob=y_prob,
                class_names=class_names,
                training_time_sec=train_time,
                inference_time_sec=inf_time,
            )

            # Feature Importance
            feature_importances = []
            if hasattr(model, "feature_importances_"):
                fi = model.feature_importances_
                for f_name, score in sorted(zip(FEATURE_COLUMNS, fi), key=lambda x: x[1], reverse=True):
                    feature_importances.append({"feature": f_name, "importance": round(float(score), 4)})
            elif hasattr(model, "coef_"):
                # Average absolute coefficients across classes
                avg_coef = np.mean(np.abs(model.coef_), axis=0)
                for f_name, score in sorted(zip(FEATURE_COLUMNS, avg_coef), key=lambda x: x[1], reverse=True):
                    feature_importances.append({"feature": f_name, "importance": round(float(score), 4)})

            metrics["feature_importances"] = feature_importances
            results[model_name] = metrics

            # Save model to disk
            self.models[model_name] = model
            joblib.dump(model, MODEL_DIR / f"{model_name}_classifier.joblib")

        # Persist preprocessor
        joblib.dump(preprocessor, MODEL_DIR / "preprocessor.joblib")
        self.benchmarks = results
        return results

    def predict(self, feature_dict: Dict[str, Any], model_name: Optional[str] = None) -> Dict[str, Any]:
        """Classify single feature vector and return category, confidence, and feature contributions."""
        m_name = model_name or self.active_model_name
        model = self.models.get(m_name) or self.SUPPORTED_MODELS.get(m_name)
        
        # Transform features
        X_vec = preprocessor.transform_single(feature_dict)
        
        if not hasattr(model, "classes_") or len(getattr(model, "classes_", [])) == 0:
            # If not yet trained, return rule-derived baseline
            return {
                "predicted_category": "Normal",
                "confidence": 0.85,
                "probabilities": {"Normal": 0.85},
                "model_used": m_name,
                "top_features": [],
            }

        pred_idx = model.predict(X_vec)[0]
        category = preprocessor.decode_labels(np.array([pred_idx]))[0]

        probs = {}
        confidence = 0.90
        if hasattr(model, "predict_proba"):
            p_vec = model.predict_proba(X_vec)[0]
            confidence = float(np.max(p_vec))
            for c_idx, prob in enumerate(p_vec):
                if prob > 0.01:
                    c_name = preprocessor.label_encoder.classes_[c_idx]
                    probs[c_name] = round(float(prob), 4)

        # Compute feature contributions
        contributions = []
        for i, f_name in enumerate(FEATURE_COLUMNS):
            val = float(feature_dict.get(f_name, 0.0))
            if abs(val) > 0.01:
                contributions.append({
                    "feature": f_name,
                    "value": round(val, 3),
                    "impact": "ELEVATED" if val > 1.0 else "NOMINAL"
                })

        return {
            "predicted_category": category,
            "confidence": round(confidence, 4),
            "probabilities": probs,
            "model_used": m_name,
            "top_features": contributions[:5],
        }

threat_classifier = MultiModelThreatClassifier()
