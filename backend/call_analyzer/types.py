"""Typed shapes of the dictionaries returned by :func:`analyze_call_log`.

Timestamps are given both as epoch seconds (``*_epoch``) and as ISO-8601 UTC
strings. Rates are fractions in [0, 1]; packet loss is in percent.
"""

from __future__ import annotations

from typing import TypedDict


class ParseReportDict(TypedDict):
    lines_read: int
    records_parsed: int
    records_rejected: int
    header_present: bool
    first_error_line: int | None
    first_error_code: int | None
    first_error: str | None
    first_error_message: str | None


class CellStatisticsDict(TypedDict):
    cell_id: str
    total_calls: int
    successful_calls: int
    failed_setup_calls: int
    dropped_calls: int
    success_rate: float
    drop_rate: float
    setup_failure_rate: float
    average_duration: float
    average_signal: float
    average_packet_loss: float
    weak_signal_calls: int
    first_epoch: int
    last_epoch: int
    first_timestamp: str
    last_timestamp: str


class FailureCodeDict(TypedDict):
    status_code: int
    outcome: str
    count: int
    share: float


class TimeWindowDict(TypedDict):
    window_start_epoch: int
    window_end_epoch: int
    window_start: str
    window_end: str
    total_calls: int
    successful_calls: int
    failed_setup_calls: int
    dropped_calls: int
    drop_rate: float
    setup_failure_rate: float
    average_signal: float
    average_packet_loss: float


class CallerStatisticsDict(TypedDict):
    caller: str
    calls_made: int
    distinct_callees: int
    successful_calls: int
    failed_setup_calls: int
    dropped_calls: int
    short_calls: int
    average_duration: float
    total_duration: int
    first_epoch: int
    last_epoch: int


class AnomalyDict(TypedDict):
    type: str
    category: str
    severity: str
    subject: str
    window_start_epoch: int
    window_end_epoch: int
    window_start: str
    window_end: str
    value: float
    baseline: float
    z_score: float
    anomaly_score: float
    sample_size: int
    record_index: int | None
    description: str


class SuspiciousWindowDict(TypedDict):
    window_start_epoch: int
    window_end_epoch: int
    window_start: str
    window_end: str
    reasons: list[str]
    severity: str
    anomaly_score: float
    total_calls: int
    drop_rate: float


class CallAnalysisResult(TypedDict):
    source: str
    library_version: str
    window_seconds: int
    total_calls: int
    successful_calls: int
    failed_setup_calls: int
    dropped_calls: int
    unknown_calls: int
    success_rate: float
    drop_rate: float
    setup_failure_rate: float
    average_duration: float
    duration_stddev: float
    min_duration: int
    max_duration: int
    average_signal: float
    average_packet_loss: float
    weak_signal_calls: int
    unique_cells: int
    unique_callers: int
    first_epoch: int | None
    last_epoch: int | None
    first_timestamp: str | None
    last_timestamp: str | None
    cells: list[CellStatisticsDict]
    failure_codes: list[FailureCodeDict]
    time_windows: list[TimeWindowDict]
    callers: list[CallerStatisticsDict]
    anomalies: list[AnomalyDict]
    suspicious_time_windows: list[SuspiciousWindowDict]
    parse_report: ParseReportDict
