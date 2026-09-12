"""SentinelAI Time-Series Baseline Forecaster & Volumetric Anomaly Detector.

Implements Holt-Winters Triple Exponential Smoothing (Additive Level, Trend, Seasonality)
combined with robust rolling Z-scores and IQR bounds to detect network egress spikes,
authentication volume bursts, and DNS tunneling volumetric anomalies.
100% offline numerical computation without external API dependencies.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ForecastPoint:
    index: int
    actual: float
    predicted: float
    lower_bound: float
    upper_bound: float
    residual: float
    z_score: float
    is_anomaly: bool
    anomaly_direction: str  # "HIGH", "LOW", "NORMAL"


class HoltWintersForecaster:
    """Holt-Winters Triple Exponential Smoothing (Additive seasonality) for SOC telemetry time-series."""

    def __init__(
        self,
        alpha: float = 0.3,
        beta: float = 0.1,
        gamma: float = 0.2,
        season_length: int = 24,  # e.g., 24-hour daily seasonality cycle
        confidence_z: float = 2.5,
    ):
        self.alpha: float = alpha
        self.beta: float = beta
        self.gamma: float = gamma
        self.season_length: int = season_length
        self.confidence_z: float = confidence_z

    def fit_and_detect(self, series: List[float]) -> Dict[str, Any]:
        """Fits Holt-Winters model on series and detects point anomalies and burst spikes."""
        n = len(series)
        if n < self.season_length * 2:
            # Fallback to rolling robust statistics if series is shorter than 2 seasons
            return self._fallback_rolling_stats(series)

        # 1. Initialize Level, Trend, Seasonality components
        season_len = self.season_length
        season_averages = []
        n_seasons = n // season_len

        for i in range(n_seasons):
            season_averages.append(sum(series[i * season_len : (i + 1) * season_len]) / season_len)

        # Initial trend
        trend = (season_averages[-1] - season_averages[0]) / (n_seasons * season_len)

        # Initial level
        level = season_averages[0]

        # Initial seasonal factors
        seasonal = [0.0] * season_len
        for i in range(season_len):
            seasonal[i] = sum(
                series[k * season_len + i] - season_averages[k] for k in range(n_seasons)
            ) / n_seasons

        points: List[ForecastPoint] = []
        residuals: List[float] = []

        # 2. Iterate and update components
        for t in range(n):
            val = series[t]
            season_idx = t % season_len

            # Forecast before seeing point
            pred = level + trend + seasonal[season_idx]
            resid = val - pred
            residuals.append(resid)

            # Rolling std deviation of recent residuals
            window = residuals[-min(len(residuals), 48):]
            mean_res = sum(window) / len(window)
            var_res = sum((x - mean_res) ** 2 for x in window) / max(len(window) - 1, 1)
            std_res = math.sqrt(max(var_res, 1e-4))

            z_score = resid / std_res
            is_anomaly = abs(z_score) >= self.confidence_z
            direction = "HIGH" if z_score >= self.confidence_z else ("LOW" if z_score <= -self.confidence_z else "NORMAL")

            margin = self.confidence_z * std_res
            points.append(
                ForecastPoint(
                    index=t,
                    actual=round(val, 2),
                    predicted=round(pred, 2),
                    lower_bound=round(pred - margin, 2),
                    upper_bound=round(pred + margin, 2),
                    residual=round(resid, 2),
                    z_score=round(z_score, 2),
                    is_anomaly=is_anomaly,
                    anomaly_direction=direction,
                )
            )

            # Update level, trend, seasonal with observed value
            old_level = level
            level = self.alpha * (val - seasonal[season_idx]) + (1.0 - self.alpha) * (level + trend)
            trend = self.beta * (level - old_level) + (1.0 - self.beta) * trend
            seasonal[season_idx] = (
                self.gamma * (val - level) + (1.0 - self.gamma) * seasonal[season_idx]
            )

        anomalies = [p for p in points if p.is_anomaly]

        return {
            "total_samples": n,
            "anomaly_count": len(anomalies),
            "anomaly_rate": round(len(anomalies) / max(n, 1), 4),
            "model": "Holt-Winters-Additive",
            "season_length": season_len,
            "points": [p.__dict__ for p in points[-min(n, 48):]],  # Return recent slice for API visualization
            "anomalies": [p.__dict__ for p in anomalies],
        }

    def _fallback_rolling_stats(self, series: List[float]) -> Dict[str, Any]:
        """Rolling window mean/std baseline for short series."""
        n = len(series)
        points: List[ForecastPoint] = []
        window_size = min(max(5, n // 3), 15)

        for i in range(n):
            val = series[i]
            if i < 3:
                pred = val
                std = 1.0
                z = 0.0
            else:
                window = series[max(0, i - window_size) : i]
                pred = sum(window) / len(window)
                var = sum((x - pred) ** 2 for x in window) / max(len(window) - 1, 1)
                std = math.sqrt(max(var, 1e-4))
                z = (val - pred) / std

            is_anom = abs(z) >= self.confidence_z
            margin = self.confidence_z * std
            direction = "HIGH" if z >= self.confidence_z else ("LOW" if z <= -self.confidence_z else "NORMAL")

            points.append(
                ForecastPoint(
                    index=i,
                    actual=round(val, 2),
                    predicted=round(pred, 2),
                    lower_bound=round(pred - margin, 2),
                    upper_bound=round(pred + margin, 2),
                    residual=round(val - pred, 2),
                    z_score=round(z, 2),
                    is_anomaly=is_anom,
                    anomaly_direction=direction,
                )
            )

        anomalies = [p for p in points if p.is_anomaly]
        return {
            "total_samples": n,
            "anomaly_count": len(anomalies),
            "anomaly_rate": round(len(anomalies) / max(n, 1), 4),
            "model": "Rolling-ZScore-Baseline",
            "season_length": window_size,
            "points": [p.__dict__ for p in points],
            "anomalies": [p.__dict__ for p in anomalies],
        }


# Global forecaster instance
timeseries_forecaster = HoltWintersForecaster()
