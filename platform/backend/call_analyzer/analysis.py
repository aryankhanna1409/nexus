"""High-level entry point: run every libcallanalyzer analysis over one call log.

All computation happens in C. This module only marshals arguments, converts
native structs into plain Python values, and releases each native allocation
with its matching ``free_*`` function before returning.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, TypeVar

from call_analyzer import _native as n
from call_analyzer.errors import CA_OK, STATUS_NAMES, CallAnalyzerError, error_from_status
from call_analyzer.types import (
    AnomalyDict,
    CallAnalysisResult,
    CallerStatisticsDict,
    CellStatisticsDict,
    FailureCodeDict,
    ParseReportDict,
    SuspiciousWindowDict,
    TimeWindowDict,
)

DEFAULT_WINDOW_SECONDS = 300

_StructT = TypeVar("_StructT", bound=ctypes.Structure)
_ItemT = TypeVar("_ItemT")

_SIZE_T_MAX = 2 ** (8 * ctypes.sizeof(ctypes.c_size_t)) - 1
_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _encode_path(path: str | os.PathLike[str]) -> bytes:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f"path must be str or os.PathLike, got {type(path).__name__}")
    encoded = os.fsencode(path)
    if not encoded:
        raise ValueError("path must not be empty")
    if b"\x00" in encoded:
        raise ValueError("path must not contain NUL bytes")
    return encoded


# ---- Struct conversion -------------------------------------------------------


def _convert_report(report: n.ParseReport) -> ParseReportDict:
    has_error = report.first_error_line != 0
    return {
        "lines_read": report.lines_read,
        "records_parsed": report.records_parsed,
        "records_rejected": report.records_rejected,
        "header_present": bool(report.header_present),
        "first_error_line": report.first_error_line if has_error else None,
        "first_error_code": report.first_error if has_error else None,
        "first_error": STATUS_NAMES.get(report.first_error, "UNKNOWN") if has_error else None,
        "first_error_message": _text(report.first_error_message) if has_error else None,
    }


def _convert_cell(c: n.CellStatistics) -> CellStatisticsDict:
    return {
        "cell_id": _text(c.cell_id),
        "total_calls": c.total_calls,
        "successful_calls": c.successful_calls,
        "failed_setup_calls": c.failed_setup_calls,
        "dropped_calls": c.dropped_calls,
        "success_rate": c.success_rate,
        "drop_rate": c.drop_rate,
        "setup_failure_rate": c.setup_failure_rate,
        "average_duration": c.average_duration,
        "average_signal": c.average_signal,
        "average_packet_loss": c.average_packet_loss,
        "weak_signal_calls": c.weak_signal_calls,
        "first_epoch": c.first_epoch,
        "last_epoch": c.last_epoch,
        "first_timestamp": _iso(c.first_epoch),
        "last_timestamp": _iso(c.last_epoch),
    }


def _convert_window(w: n.TimeWindowStatistics) -> TimeWindowDict:
    return {
        "window_start_epoch": w.window_start,
        "window_end_epoch": w.window_end,
        "window_start": _iso(w.window_start),
        "window_end": _iso(w.window_end),
        "total_calls": w.total_calls,
        "successful_calls": w.successful_calls,
        "failed_setup_calls": w.failed_setup_calls,
        "dropped_calls": w.dropped_calls,
        "drop_rate": w.drop_rate,
        "setup_failure_rate": w.setup_failure_rate,
        "average_signal": w.average_signal,
        "average_packet_loss": w.average_packet_loss,
    }


def _convert_caller(c: n.CallerStatistics) -> CallerStatisticsDict:
    return {
        "caller": _text(c.caller),
        "calls_made": c.calls_made,
        "distinct_callees": c.distinct_callees,
        "successful_calls": c.successful_calls,
        "failed_setup_calls": c.failed_setup_calls,
        "dropped_calls": c.dropped_calls,
        "short_calls": c.short_calls,
        "average_duration": c.average_duration,
        "total_duration": c.total_duration,
        "first_epoch": c.first_epoch,
        "last_epoch": c.last_epoch,
    }


# ---- Native call helpers -------------------------------------------------------


def _raise_for_status(lib: n.NativeLibrary, rc: int, operation: str) -> None:
    if rc != CA_OK:
        raise error_from_status(rc, operation=operation, c_message=lib.strerror(rc))


def _collect_array(
    lib: n.NativeLibrary,
    compute: Callable[..., int],
    free: Callable[[Any], None],
    struct_type: type[_StructT],
    convert: Callable[[_StructT], _ItemT],
    operation: str,
    *args: object,
) -> list[_ItemT]:
    """Calls ``compute(*args, &out, &count)``, converts the array, then frees it.

    The array is freed in every case, including conversion errors; the C
    contract guarantees ``out`` is NULL on failure, and free(NULL) is a no-op.
    """
    out = ctypes.POINTER(struct_type)()
    count = ctypes.c_size_t(0)
    try:
        rc = compute(*args, ctypes.byref(out), ctypes.byref(count))
        _raise_for_status(lib, rc, operation)
        return [convert(out[i]) for i in range(count.value)]
    finally:
        free(out)


def _build_anomaly_config(
    lib: n.NativeLibrary, window_seconds: int, overrides: Mapping[str, float | int] | None
) -> n.AnomalyConfig:
    config = n.AnomalyConfig()
    lib.cdll.anomaly_config_default(ctypes.byref(config))  # defaults come from C
    config.window_seconds = window_seconds
    if not overrides:
        return config
    field_types = {spec[0]: spec[1] for spec in n.AnomalyConfig._fields_}
    for key, value in overrides.items():
        if key == "window_seconds":
            raise ValueError("set window_seconds via the window_seconds argument")
        if key not in field_types:
            raise ValueError(f"unknown anomaly_config key {key!r}")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"anomaly_config[{key!r}] must be a number")
        if field_types[key] is ctypes.c_size_t:
            if not isinstance(value, int) or not 0 <= value <= _SIZE_T_MAX:
                raise ValueError(f"anomaly_config[{key!r}] must be a non-negative int")
        try:
            setattr(config, key, value)
        except OverflowError as exc:  # e.g. an int too large for a C double
            raise ValueError(f"anomaly_config[{key!r}] is out of range") from exc
    return config


def _convert_anomaly(lib: n.NativeLibrary, a: n.CallAnomaly) -> AnomalyDict:
    type_name = lib.name_of("call_anomaly_type_name", a.type)
    return {
        "type": type_name,
        "category": type_name.split("_", 1)[0],
        "severity": lib.name_of("call_severity_name", a.severity),
        "subject": _text(a.subject),
        "window_start_epoch": a.window_start,
        "window_end_epoch": a.window_end,
        "window_start": _iso(a.window_start),
        "window_end": _iso(a.window_end),
        "value": a.value,
        "baseline": a.baseline,
        "z_score": a.z_score,
        "anomaly_score": a.score,
        "sample_size": a.sample_size,
        "record_index": a.record_index if a.record_index >= 0 else None,
        "description": _text(a.description),
    }


def _suspicious_windows(
    anomalies: list[AnomalyDict], windows: list[TimeWindowDict]
) -> list[SuspiciousWindowDict]:
    """Groups window-level anomalies by window and joins the window's statistics."""
    by_start = {w["window_start_epoch"]: w for w in windows}
    grouped: dict[int, SuspiciousWindowDict] = {}
    for anomaly in anomalies:  # already sorted by descending score
        if anomaly["category"] != "window":
            continue
        start = anomaly["window_start_epoch"]
        entry = grouped.get(start)
        if entry is None:
            stats = by_start.get(start)
            if stats is None:  # C reported a window it has no statistics for
                raise CallAnalyzerError(
                    f"window anomaly at {anomaly['window_start']} has no matching time window"
                )
            grouped[start] = {
                "window_start_epoch": start,
                "window_end_epoch": anomaly["window_end_epoch"],
                "window_start": anomaly["window_start"],
                "window_end": anomaly["window_end"],
                "reasons": [anomaly["type"]],
                "severity": anomaly["severity"],
                "anomaly_score": anomaly["anomaly_score"],
                "total_calls": stats["total_calls"],
                "drop_rate": stats["drop_rate"],
            }
        elif anomaly["type"] not in entry["reasons"]:
            entry["reasons"].append(anomaly["type"])
    return [grouped[start] for start in sorted(grouped)]


# ---- Public API ----------------------------------------------------------------


def analyze_call_log(
    path: str | os.PathLike[str],
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    strict: bool = False,
    max_records: int | None = None,
    anomaly_config: Mapping[str, float | int] | None = None,
) -> CallAnalysisResult:
    """Parses and analyses a CSV call log with libcallanalyzer.

    Args:
        path: CSV file in the format documented in ARCHITECTURE.md §3.1.
        window_seconds: time-window size (1..86400) for window statistics and
            window anomaly detection.
        strict: fail on the first invalid row instead of skipping it.
        max_records: cap on parsed rows (library default when None).
        anomaly_config: overrides for AnomalyConfig fields (defaults come from C).

    Raises:
        CallAnalyzerError subclasses carrying the original C status code;
        LibraryLoadError if the shared library is unavailable; TypeError /
        ValueError for arguments that cannot be passed to C at all.
    """
    encoded_path = _encode_path(path)
    window_seconds = _require_int("window_seconds", window_seconds)
    if not _INT64_MIN <= window_seconds <= _INT64_MAX:
        # ctypes would silently wrap it; values in int64 range are checked by C.
        raise ValueError("window_seconds does not fit in int64_t")
    if max_records is not None:
        max_records = _require_int("max_records", max_records)
        if not 1 <= max_records <= _SIZE_T_MAX:
            raise ValueError("max_records must be a positive int")

    lib = n.get_library()
    cdll = lib.cdll
    display_path = os.fsdecode(encoded_path)

    options = n.ParseOptions()
    cdll.parse_options_default(ctypes.byref(options))
    options.strict = 1 if strict else 0
    if max_records is not None:
        options.max_records = max_records
    anomaly_cfg = _build_anomaly_config(lib, window_seconds, anomaly_config)

    records = ctypes.POINTER(n.CallRecord)()
    count = ctypes.c_size_t(0)
    report = n.ParseReport()
    try:
        rc = cdll.parse_call_log_ex(
            encoded_path,
            ctypes.byref(options),
            ctypes.byref(records),
            ctypes.byref(count),
            ctypes.byref(report),
        )
        report_dict = _convert_report(report)
        if rc != CA_OK:
            raise error_from_status(
                rc,
                operation=f"parsing {display_path}",
                c_message=lib.strerror(rc),
                detail=report_dict["first_error_message"],
                parse_report=report_dict,
            )

        stats = n.CallStatistics()
        _raise_for_status(
            lib,
            cdll.calculate_statistics(records, count, ctypes.byref(stats)),
            "calculate_statistics",
        )
        cells = _collect_array(
            lib, cdll.calculate_cell_statistics, cdll.free_cell_statistics,
            n.CellStatistics, _convert_cell, "calculate_cell_statistics", records, count,
        )
        codes = _collect_array(
            lib, cdll.calculate_failure_code_statistics, cdll.free_failure_code_statistics,
            n.FailureCodeStatistics,
            lambda c: FailureCodeDict(
                status_code=c.status_code,
                outcome=lib.name_of("call_outcome_name", c.outcome),
                count=c.count,
                share=c.share,
            ),
            "calculate_failure_code_statistics", records, count,
        )
        windows = _collect_array(
            lib, cdll.calculate_time_window_statistics, cdll.free_time_window_statistics,
            n.TimeWindowStatistics, _convert_window, "calculate_time_window_statistics",
            records, count, ctypes.c_int64(window_seconds),
        )
        callers = _collect_array(
            lib, cdll.calculate_caller_statistics, cdll.free_caller_statistics,
            n.CallerStatistics, _convert_caller, "calculate_caller_statistics", records, count,
        )
        anomalies = _collect_array(
            lib, cdll.detect_call_anomalies, cdll.free_call_anomalies, n.CallAnomaly,
            lambda a: _convert_anomaly(lib, a), "detect_call_anomalies",
            records, count, ctypes.byref(anomaly_cfg),
        )
    finally:
        cdll.free_call_records(records)

    has_calls = stats.total_calls > 0
    return {
        "source": display_path,
        "library_version": lib.version,
        "window_seconds": window_seconds,
        "total_calls": stats.total_calls,
        "successful_calls": stats.successful_calls,
        "failed_setup_calls": stats.failed_setup_calls,
        "dropped_calls": stats.dropped_calls,
        "unknown_calls": stats.unknown_calls,
        "success_rate": stats.success_rate,
        "drop_rate": stats.drop_rate,
        "setup_failure_rate": stats.setup_failure_rate,
        "average_duration": stats.average_duration,
        "duration_stddev": stats.duration_stddev,
        "min_duration": stats.min_duration,
        "max_duration": stats.max_duration,
        "average_signal": stats.average_signal,
        "average_packet_loss": stats.average_packet_loss,
        "weak_signal_calls": stats.weak_signal_calls,
        "unique_cells": stats.unique_cells,
        "unique_callers": stats.unique_callers,
        "first_epoch": stats.first_epoch if has_calls else None,
        "last_epoch": stats.last_epoch if has_calls else None,
        "first_timestamp": _iso(stats.first_epoch) if has_calls else None,
        "last_timestamp": _iso(stats.last_epoch) if has_calls else None,
        "cells": cells,
        "failure_codes": codes,
        "time_windows": windows,
        "callers": callers,
        "anomalies": anomalies,
        "suspicious_time_windows": _suspicious_windows(anomalies, windows),
        "parse_report": report_dict,
    }
