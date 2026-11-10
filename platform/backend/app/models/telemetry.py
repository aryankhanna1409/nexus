"""Pipeline runs, network telemetry, call analysis and operational events."""

from __future__ import annotations

from typing import Any

from sqlalchemy import BigInteger, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scenario: Mapped[str] = mapped_column(String(64))
    seed: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    started_epoch: Mapped[int] = mapped_column(BigInteger)
    finished_epoch: Mapped[int | None] = mapped_column(BigInteger)
    data_start_epoch: Mapped[int] = mapped_column(BigInteger)
    data_end_epoch: Mapped[int] = mapped_column(BigInteger)
    fingerprint: Mapped[str] = mapped_column(String(64))
    params: Mapped[dict[str, Any]]


class NetworkMetric(Base):
    __tablename__ = "network_metrics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="CASCADE"))
    epoch: Mapped[int] = mapped_column(BigInteger)
    cell_id: Mapped[str] = mapped_column(String(32))
    node_id: Mapped[str] = mapped_column(String(32))
    metric: Mapped[str] = mapped_column(String(48))
    value: Mapped[float] = mapped_column(Float)
    __table_args__ = (Index("ix_network_metrics_lookup", "run_id", "metric", "cell_id", "epoch"),)


class Anomaly(Base):
    __tablename__ = "anomalies"
    anomaly_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="CASCADE"), index=True)
    metric: Mapped[str] = mapped_column(String(48))
    cell_id: Mapped[str] = mapped_column(String(32), index=True)
    node_id: Mapped[str] = mapped_column(String(32))
    start_epoch: Mapped[int] = mapped_column(BigInteger, index=True)
    end_epoch: Mapped[int] = mapped_column(BigInteger)
    value: Mapped[float] = mapped_column(Float)
    baseline: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16))
    anomaly_score: Mapped[float] = mapped_column(Float)
    points: Mapped[int] = mapped_column(Integer)
    detectors: Mapped[list[Any]]
    related_metrics: Mapped[list[Any]]


class CallAnalysisRun(Base):
    __tablename__ = "call_analysis_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(Text)
    library_version: Mapped[str] = mapped_column(String(16))
    total_calls: Mapped[int] = mapped_column(Integer)
    successful_calls: Mapped[int] = mapped_column(Integer)
    failed_setup_calls: Mapped[int] = mapped_column(Integer)
    dropped_calls: Mapped[int] = mapped_column(Integer)
    success_rate: Mapped[float] = mapped_column(Float)
    drop_rate: Mapped[float] = mapped_column(Float)
    setup_failure_rate: Mapped[float] = mapped_column(Float)
    average_duration: Mapped[float] = mapped_column(Float)
    average_signal: Mapped[float] = mapped_column(Float)
    average_packet_loss: Mapped[float] = mapped_column(Float)
    first_epoch: Mapped[int | None] = mapped_column(BigInteger)
    last_epoch: Mapped[int | None] = mapped_column(BigInteger)
    failure_codes: Mapped[list[Any]]
    time_windows: Mapped[list[Any]]
    suspicious_time_windows: Mapped[list[Any]]
    parse_report: Mapped[dict[str, Any]]


class CallCellStatistics(Base):
    __tablename__ = "call_cell_statistics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("call_analysis_runs.id", ondelete="CASCADE"),
                                             index=True)
    cell_id: Mapped[str] = mapped_column(String(32))
    total_calls: Mapped[int] = mapped_column(Integer)
    successful_calls: Mapped[int] = mapped_column(Integer)
    failed_setup_calls: Mapped[int] = mapped_column(Integer)
    dropped_calls: Mapped[int] = mapped_column(Integer)
    drop_rate: Mapped[float] = mapped_column(Float)
    setup_failure_rate: Mapped[float] = mapped_column(Float)
    average_signal: Mapped[float] = mapped_column(Float)
    average_packet_loss: Mapped[float] = mapped_column(Float)


class CallAnomalyRecord(Base):
    __tablename__ = "call_anomalies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("call_analysis_runs.id", ondelete="CASCADE"),
                                             index=True)
    type: Mapped[str] = mapped_column(String(48))
    category: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    subject: Mapped[str] = mapped_column(String(32))
    window_start_epoch: Mapped[int] = mapped_column(BigInteger)
    window_end_epoch: Mapped[int] = mapped_column(BigInteger)
    value: Mapped[float] = mapped_column(Float)
    baseline: Mapped[float] = mapped_column(Float)
    z_score: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float] = mapped_column(Float)
    sample_size: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text)


class OperationalEventRecord(Base):
    __tablename__ = "operational_events"
    event_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="CASCADE"), index=True)
    epoch: Mapped[int] = mapped_column(BigInteger, index=True)
    type: Mapped[str] = mapped_column(String(24), index=True)
    source: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16))
    message: Mapped[str] = mapped_column(Text)
    node_id: Mapped[str | None] = mapped_column(String(32))
    cell_id: Mapped[str | None] = mapped_column(String(32))
    attributes: Mapped[dict[str, Any]]


class Deployment(Base):
    __tablename__ = "deployments"
    deployment_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="CASCADE"), index=True)
    service: Mapped[str] = mapped_column(String(48))
    node_id: Mapped[str] = mapped_column(String(32))
    from_version: Mapped[str] = mapped_column(String(32))
    to_version: Mapped[str] = mapped_column(String(32))
    deployed_epoch: Mapped[int] = mapped_column(BigInteger)
    change_summary: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))  # active | rolled_back
    rolled_back_epoch: Mapped[int | None] = mapped_column(BigInteger)
