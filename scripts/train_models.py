"""Local ML Model Baseline Training Script."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.ml.anomaly_detector import get_anomaly_detector

def main():
    print("[INFO] Initializing local scikit-learn IsolationForest anomaly detector...")
    detector = get_anomaly_detector()
    res = detector.train_baseline()
    print(f"[SUCCESS] Model trained successfully on {res['samples_trained']} vectors.")
    print(f"[INFO] Features evaluated: {', '.join(res['features'])}")

if __name__ == "__main__":
    main()
