"""Anomaly detection over network KPI series (M4) and event correlation (M5)."""

from app.analytics.config import DEFAULT_RULES, DetectionConfig, MetricRule
from app.analytics.engine import MetricAnomaly, MetricSeries, detect_anomalies, detect_series
from app.analytics.sources import series_from_simulation

__all__ = [
    "DEFAULT_RULES", "DetectionConfig", "MetricAnomaly", "MetricRule", "MetricSeries",
    "detect_anomalies", "detect_series", "series_from_simulation",
]
