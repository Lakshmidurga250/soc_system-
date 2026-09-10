"""False Positive Analysis & Detection Feedback Tuning Service."""
from typing import Dict, Any, List
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..models import Alert, DetectionRule

class FeedbackService:
    """Aggregates analyst feedback on alerts (True Positive vs False Positive) and tunes detection rule weights."""

    @staticmethod
    def get_false_positive_metrics(db: Session) -> Dict[str, Any]:
        """Compute system-wide true positive vs false positive statistics."""
        total_alerts = db.query(Alert).count()
        fp_count = db.query(Alert).filter(Alert.status == "FALSE_POSITIVE").count()
        tp_count = db.query(Alert).filter(Alert.status.in_(["CONFIRMED", "RESOLVED", "CLOSED"])).count()
        unresolved_count = db.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).count()

        fp_rate = round((fp_count / max(1, (fp_count + tp_count))) * 100.0, 2)
        precision_rate = round((tp_count / max(1, (fp_count + tp_count))) * 100.0, 2)

        # Rule-specific FP rates
        rules = db.scalars(select(DetectionRule)).all()
        rule_breakdown = []
        for r in rules:
            r_alerts = db.query(Alert).filter(Alert.title == r.name).all()
            r_fp = sum(1 for a in r_alerts if a.status == "FALSE_POSITIVE")
            r_tp = sum(1 for a in r_alerts if a.status in ["CONFIRMED", "RESOLVED", "CLOSED"])
            r_total = len(r_alerts)
            
            rule_breakdown.append({
                "rule_id": r.id,
                "rule_name": r.name,
                "severity": r.severity,
                "total_alerts": r_total,
                "true_positives": r_tp,
                "false_positives": r_fp,
                "fp_rate_percentage": round((r_fp / max(1, r_total)) * 100.0, 1) if r_total else 0.0,
                "recommended_tuning": "Increase threshold count" if r_fp > 3 else "Optimal"
            })

        return {
            "total_evaluated_alerts": total_alerts,
            "confirmed_true_positives": tp_count,
            "confirmed_false_positives": fp_count,
            "unresolved_alerts": unresolved_count,
            "overall_false_positive_rate": fp_rate,
            "overall_precision_rate": precision_rate,
            "rule_breakdown": rule_breakdown,
        }

feedback_service = FeedbackService()
