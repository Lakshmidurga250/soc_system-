"""Data Preprocessing & Feature Transformation Pipeline for ML Models."""
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from sklearn.preprocessing import StandardScaler, RobustScaler, LabelEncoder

# 14 Canonical Feature Columns
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

# Standard 14 Attack Classification Categories
ATTACK_CLASSES = [
    "Normal",
    "DoS",
    "DDoS",
    "Brute Force",
    "Port Scan",
    "Network Scan",
    "Bot Activity",
    "Web Attack",
    "Credential Attack",
    "Privilege Escalation",
    "Suspicious Authentication",
    "Data Exfiltration",
    "Malware",
    "Anomalous Activity"
]

class SecurityDataPreprocessor:
    """Preprocesses raw feature dictionaries and DataFrames for machine learning models."""

    def __init__(self, scaler_type: str = "standard"):
        self.scaler = StandardScaler() if scaler_type == "standard" else RobustScaler()
        self.label_encoder = LabelEncoder()
        self.is_fitted = False

    def fit(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> "SecurityDataPreprocessor":
        """Fit scaler on numerical feature matrix and encoder on target classes."""
        X_clean = self._clean_dataframe(X)
        self.scaler.fit(X_clean[FEATURE_COLUMNS])
        
        if y is not None:
            # Ensure all canonical classes are represented in label encoder
            all_classes = np.unique(np.concatenate([ATTACK_CLASSES, y.dropna().unique()]))
            self.label_encoder.fit(all_classes)
        
        self.is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transform numerical feature matrix using fitted scaler."""
        X_clean = self._clean_dataframe(X)
        return self.scaler.transform(X_clean[FEATURE_COLUMNS])

    def fit_transform(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fit and transform feature matrix and targets."""
        self.fit(X, y)
        X_trans = self.transform(X)
        y_trans = self.encode_labels(y) if y is not None else None
        return X_trans, y_trans

    def encode_labels(self, y: pd.Series) -> np.ndarray:
        """Encode categorical attack class labels to integer indices."""
        y_clean = y.fillna("Normal").astype(str)
        # Fallback unknown classes to Anomalous Activity
        known_classes = set(self.label_encoder.classes_)
        y_clean = y_clean.apply(lambda val: val if val in known_classes else "Anomalous Activity")
        return self.label_encoder.transform(y_clean)

    def decode_labels(self, y_indices: np.ndarray) -> List[str]:
        """Decode integer class predictions back to category strings."""
        return list(self.label_encoder.inverse_transform(y_indices))

    def _clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing columns, NaNs, and infinite values."""
        df_clean = df.copy()
        for col in FEATURE_COLUMNS:
            if col not in df_clean.columns:
                df_clean[col] = 0.0
            else:
                df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0.0)
                # Cap extreme outliers / infs
                df_clean[col] = df_clean[col].replace([np.inf, -np.inf], 0.0)
        return df_clean

    def transform_single(self, feature_dict: Dict[str, Any]) -> np.ndarray:
        """Transform a single feature dictionary into 2D scaled feature array."""
        row_df = pd.DataFrame([feature_dict])
        return self.transform(row_df)

preprocessor = SecurityDataPreprocessor()
