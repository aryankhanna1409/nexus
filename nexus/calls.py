"""Python access to the C library (c-library/) through ctypes.

All the computation happens in C; this file only describes the C structs
to Python, calls the functions, copies the results into dicts and frees
the C memory.
"""
from __future__ import annotations

import ctypes as C
import os
from pathlib import Path

ID = C.c_char * 32
REPO = Path(__file__).resolve().parent.parent
DEFAULT_LIB = REPO / "c-library" / "build" / "libcallanalyzer.so"


class Record(C.Structure):
    _fields_ = [("cell_id", ID), ("epoch", C.c_int64), ("duration", C.c_int),
                ("status_code", C.c_int), ("signal_dbm", C.c_int), ("packet_loss", C.c_int)]


class ParseReport(C.Structure):
    _fields_ = [("lines", C.c_size_t), ("parsed", C.c_size_t), ("rejected", C.c_size_t),
                ("first_error_line", C.c_size_t), ("first_error", C.c_char * 96)]


class Stats(C.Structure):
    _fields_ = [("total", C.c_size_t), ("completed", C.c_size_t), ("setup_failed", C.c_size_t),
                ("dropped", C.c_size_t), ("unknown", C.c_size_t),
                ("success_rate", C.c_double), ("drop_rate", C.c_double),
                ("setup_failure_rate", C.c_double), ("avg_duration", C.c_double),
                ("avg_signal_dbm", C.c_double), ("avg_packet_loss", C.c_double),
                ("unique_cells", C.c_size_t), ("first_epoch", C.c_int64), ("last_epoch", C.c_int64)]


class CellStats(C.Structure):
    _fields_ = [("cell_id", ID), ("stats", Stats)]


class Anomaly(C.Structure):
    _fields_ = [("cell_id", ID), ("metric", C.c_char * 24), ("value", C.c_double),
                ("baseline", C.c_double), ("z_score", C.c_double), ("severity", C.c_int),
                ("calls", C.c_size_t)]


class CallAnalyzerError(RuntimeError):
    pass


_lib = None


def load() -> C.CDLL:
    global _lib
    if _lib is not None:
        return _lib
    path = Path(os.environ.get("NEXUS_CALLANALYZER_LIB") or DEFAULT_LIB)
    if not path.is_file():
        raise CallAnalyzerError(f"{path} not found. Build the C library first: make c")
    lib = C.CDLL(str(path))
    lib.ca_version.restype = C.c_char_p
    lib.ca_strerror.restype = C.c_char_p
    lib.ca_strerror.argtypes = [C.c_int]
    lib.ca_severity_name.restype = C.c_char_p
    lib.ca_severity_name.argtypes = [C.c_int]
    lib.ca_free.argtypes = [C.c_void_p]
    lib.ca_free.restype = None
    lib.ca_parse_file.argtypes = [C.c_char_p, C.POINTER(C.POINTER(Record)), C.POINTER(C.c_size_t),
                                  C.POINTER(ParseReport)]
    lib.ca_stats.argtypes = [C.POINTER(Record), C.c_size_t, C.POINTER(Stats)]
    lib.ca_cell_stats.argtypes = [C.POINTER(Record), C.c_size_t, C.POINTER(C.POINTER(CellStats)),
                                  C.POINTER(C.c_size_t)]
    lib.ca_detect_anomalies.argtypes = [C.POINTER(CellStats), C.c_size_t, C.c_double, C.c_size_t,
                                        C.POINTER(C.POINTER(Anomaly)), C.POINTER(C.c_size_t)]
    for fn in ("ca_parse_file", "ca_stats", "ca_cell_stats", "ca_detect_anomalies"):
        getattr(lib, fn).restype = C.c_int
    _lib = lib
    return lib


def _check(lib: C.CDLL, rc: int, what: str) -> None:
    if rc != 0:
        raise CallAnalyzerError(f"{what}: {lib.ca_strerror(rc).decode()}")


def _stats_dict(s: Stats) -> dict:
    return {name: (round(v, 5) if isinstance(v, float) else v)
            for name, _ in Stats._fields_ for v in [getattr(s, name)]}


def analyze(path: str | Path, z_threshold: float = 3.5, min_calls: int = 50) -> dict:
    """Parse a call-log CSV and return overall stats, per-cell stats and anomalies."""
    lib = load()
    recs, n, report = C.POINTER(Record)(), C.c_size_t(), ParseReport()
    cells, nc = C.POINTER(CellStats)(), C.c_size_t()
    anoms, na = C.POINTER(Anomaly)(), C.c_size_t()
    overall = Stats()
    try:
        _check(lib, lib.ca_parse_file(str(path).encode(), C.byref(recs), C.byref(n), C.byref(report)), "parse")
        _check(lib, lib.ca_stats(recs, n, C.byref(overall)), "stats")
        _check(lib, lib.ca_cell_stats(recs, n, C.byref(cells), C.byref(nc)), "cell stats")
        _check(lib, lib.ca_detect_anomalies(cells, nc, z_threshold, min_calls, C.byref(anoms), C.byref(na)),
               "anomalies")
        return {
            "library_version": lib.ca_version().decode(),
            "parse": {"parsed": report.parsed, "rejected": report.rejected,
                      "first_error_line": report.first_error_line,
                      "first_error": report.first_error.decode()},
            "overall": _stats_dict(overall),
            "cells": [{"cell_id": cells[i].cell_id.decode(), **_stats_dict(cells[i].stats)}
                      for i in range(nc.value)],
            "anomalies": [{"cell_id": a.cell_id.decode(), "metric": a.metric.decode(),
                           "value": round(a.value, 4), "baseline": round(a.baseline, 4),
                           "z_score": round(a.z_score, 1), "calls": a.calls,
                           "severity": lib.ca_severity_name(a.severity).decode()}
                          for a in (anoms[i] for i in range(na.value))],
        }
    finally:
        lib.ca_free(recs)
        lib.ca_free(cells)
        lib.ca_free(anoms)
