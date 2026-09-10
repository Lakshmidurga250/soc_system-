"""Multi-Class Model Performance Evaluation & Benchmark Module."""
import time
import numpy as np
from typing import Dict, List, Any, Optional
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)

class ModelEvaluator:
    """Computes comprehensive multi-class classification and performance metrics."""

    @staticmethod
    def evaluate(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: Optional[np.ndarray] = None,
        class_names: Optional[List[str]] = None,
        training_time_sec: float = 0.0,
        inference_time_sec: float = 0.0,
    ) -> Dict[str, Any]:
        """Generate full metrics dictionary including macro/weighted scores and confusion matrix."""
        # Calculate primary classification metrics
        acc = float(accuracy_score(y_true, y_pred))
        prec_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
        rec_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
        f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
        
        prec_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
        rec_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
        f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

        # Multi-class ROC-AUC if probability distribution is provided
        roc_auc = None
        if y_prob is not None:
            try:
                # One-vs-rest multi-class ROC AUC
                roc_auc = float(roc_auc_score(y_true, y_prob, multi_class="ovr", average="weighted"))
            except Exception:
                roc_auc = None

        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # Per-class breakdown
        unique_labels = np.unique(np.concatenate([y_true, y_pred]))
        per_class_metrics = []
        for label_idx in unique_labels:
            name = class_names[label_idx] if class_names and label_idx < len(class_names) else f"Class_{label_idx}"
            bin_true = (y_true == label_idx).astype(int)
            bin_pred = (y_pred == label_idx).astype(int)
            
            per_class_metrics.append({
                "class_index": int(label_idx),
                "class_name": name,
                "precision": round(float(precision_score(bin_true, bin_pred, zero_division=0)), 4),
                "recall": round(float(recall_score(bin_true, bin_pred, zero_division=0)), 4),
                "f1_score": round(float(f1_score(bin_true, bin_pred, zero_division=0)), 4),
                "support": int(np.sum(bin_true)),
            })

        return {
            "accuracy": round(acc, 4),
            "precision_weighted": round(prec_weighted, 4),
            "recall_weighted": round(rec_weighted, 4),
            "f1_weighted": round(f1_weighted, 4),
            "precision_macro": round(prec_macro, 4),
            "recall_macro": round(rec_macro, 4),
            "f1_macro": round(f1_macro, 4),
            "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
            "training_time_sec": round(training_time_sec, 4),
            "inference_time_sec": round(inference_time_sec, 4),
            "samples_evaluated": len(y_true),
            "confusion_matrix": cm.tolist(),
            "class_names": class_names or [f"Class_{i}" for i in unique_labels],
            "per_class_metrics": per_class_metrics,
        }

model_evaluator = ModelEvaluator()
