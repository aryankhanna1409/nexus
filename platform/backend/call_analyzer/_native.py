"""ctypes mirror of c-library/include/call_analyzer.h and library loading.

The header is authoritative. Struct layouts are verified against the loaded
library with ``call_analyzer_struct_sizes`` before any analysis call is made.
"""

from __future__ import annotations

import ctypes
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from call_analyzer.errors import LibraryLoadError

ENV_VAR: Final = "CALL_ANALYZER_LIB"
REPO_ROOT: Final = Path(__file__).resolve().parents[2]
LOCAL_BUILD_PATH: Final = REPO_ROOT / "c-library" / "build" / "libcallanalyzer.so"
DOCKER_INSTALL_PATH: Final = Path("/usr/local/lib/libcallanalyzer.so")
DEFAULT_CANDIDATES: Final[tuple[Path, ...]] = (LOCAL_BUILD_PATH, DOCKER_INSTALL_PATH)
SUPPORTED_MAJOR_VERSION: Final = 1

# Header constants that size fixed arrays.
CA_FIELD_LEN: Final = 32
CA_DESCRIPTION_LEN: Final = 160
CA_ERROR_MESSAGE_LEN: Final = 128

c_size_t = ctypes.c_size_t
c_int64 = ctypes.c_int64
c_uint64 = ctypes.c_uint64
c_int = ctypes.c_int
c_double = ctypes.c_double
c_enum = ctypes.c_int  # C enums (CallOutcome, CallAnomalyType, CallSeverity) are int-sized


class CallRecord(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_char * CA_FIELD_LEN),
        ("caller", ctypes.c_char * CA_FIELD_LEN),
        ("callee", ctypes.c_char * CA_FIELD_LEN),
        ("cell_id", ctypes.c_char * CA_FIELD_LEN),
        ("duration", c_int),
        ("status_code", c_int),
        ("signal_strength", c_int),
        ("packet_loss", c_int),
        ("epoch_seconds", c_int64),
    ]


class ParseOptions(ctypes.Structure):
    _fields_ = [("strict", c_int), ("max_records", c_size_t)]


class ParseReport(ctypes.Structure):
    _fields_ = [
        ("lines_read", c_size_t),
        ("records_parsed", c_size_t),
        ("records_rejected", c_size_t),
        ("header_present", c_int),
        ("first_error_line", c_size_t),
        ("first_error", c_int),
        ("first_error_message", ctypes.c_char * CA_ERROR_MESSAGE_LEN),
    ]


class CallStatistics(ctypes.Structure):
    _fields_ = [
        ("total_calls", c_size_t),
        ("successful_calls", c_size_t),
        ("failed_setup_calls", c_size_t),
        ("dropped_calls", c_size_t),
        ("unknown_calls", c_size_t),
        ("success_rate", c_double),
        ("drop_rate", c_double),
        ("setup_failure_rate", c_double),
        ("average_duration", c_double),
        ("duration_stddev", c_double),
        ("min_duration", c_int),
        ("max_duration", c_int),
        ("average_signal", c_double),
        ("average_packet_loss", c_double),
        ("weak_signal_calls", c_size_t),
        ("unique_cells", c_size_t),
        ("unique_callers", c_size_t),
        ("first_epoch", c_int64),
        ("last_epoch", c_int64),
    ]


class CellStatistics(ctypes.Structure):
    _fields_ = [
        ("cell_id", ctypes.c_char * CA_FIELD_LEN),
        ("total_calls", c_size_t),
        ("successful_calls", c_size_t),
        ("failed_setup_calls", c_size_t),
        ("dropped_calls", c_size_t),
        ("success_rate", c_double),
        ("drop_rate", c_double),
        ("setup_failure_rate", c_double),
        ("average_duration", c_double),
        ("average_signal", c_double),
        ("average_packet_loss", c_double),
        ("weak_signal_calls", c_size_t),
        ("first_epoch", c_int64),
        ("last_epoch", c_int64),
    ]


class FailureCodeStatistics(ctypes.Structure):
    _fields_ = [
        ("status_code", c_int),
        ("outcome", c_enum),
        ("count", c_size_t),
        ("share", c_double),
    ]


class TimeWindowStatistics(ctypes.Structure):
    _fields_ = [
        ("window_start", c_int64),
        ("window_end", c_int64),
        ("total_calls", c_size_t),
        ("successful_calls", c_size_t),
        ("failed_setup_calls", c_size_t),
        ("dropped_calls", c_size_t),
        ("drop_rate", c_double),
        ("setup_failure_rate", c_double),
        ("average_signal", c_double),
        ("average_packet_loss", c_double),
    ]


class CallerStatistics(ctypes.Structure):
    _fields_ = [
        ("caller", ctypes.c_char * CA_FIELD_LEN),
        ("calls_made", c_size_t),
        ("distinct_callees", c_size_t),
        ("successful_calls", c_size_t),
        ("failed_setup_calls", c_size_t),
        ("dropped_calls", c_size_t),
        ("short_calls", c_size_t),
        ("average_duration", c_double),
        ("total_duration", c_uint64),
        ("first_epoch", c_int64),
        ("last_epoch", c_int64),
    ]


class CallAnomaly(ctypes.Structure):
    _fields_ = [
        ("type", c_enum),
        ("severity", c_enum),
        ("subject", ctypes.c_char * CA_FIELD_LEN),
        ("window_start", c_int64),
        ("window_end", c_int64),
        ("value", c_double),
        ("baseline", c_double),
        ("z_score", c_double),
        ("score", c_double),
        ("sample_size", c_size_t),
        ("record_index", c_int64),
        ("description", ctypes.c_char * CA_DESCRIPTION_LEN),
    ]


class AnomalyConfig(ctypes.Structure):
    _fields_ = [
        ("z_threshold", c_double),
        ("duration_z_threshold", c_double),
        ("min_peer_groups", c_size_t),
        ("min_calls_per_cell", c_size_t),
        ("min_calls_per_window", c_size_t),
        ("min_calls_per_caller", c_size_t),
        ("min_established_for_duration", c_size_t),
        ("window_seconds", c_int64),
        ("min_rate_delta", c_double),
        ("min_signal_delta_dbm", c_double),
        ("min_packet_loss_delta", c_double),
        ("min_volume_ratio", c_double),
        ("min_short_call_ratio", c_double),
        ("max_anomalies", c_size_t),
    ]


class CaStructSizes(ctypes.Structure):
    _fields_ = [
        ("call_record", c_size_t),
        ("call_statistics", c_size_t),
        ("cell_statistics", c_size_t),
        ("failure_code_statistics", c_size_t),
        ("time_window_statistics", c_size_t),
        ("caller_statistics", c_size_t),
        ("call_anomaly", c_size_t),
        ("anomaly_config", c_size_t),
        ("parse_options", c_size_t),
        ("parse_report", c_size_t),
    ]


# Maps CaStructSizes fields to the Python mirror that must match.
_STRUCT_MIRRORS: Final[dict[str, type[ctypes.Structure]]] = {
    "call_record": CallRecord,
    "call_statistics": CallStatistics,
    "cell_statistics": CellStatistics,
    "failure_code_statistics": FailureCodeStatistics,
    "time_window_statistics": TimeWindowStatistics,
    "caller_statistics": CallerStatistics,
    "call_anomaly": CallAnomaly,
    "anomaly_config": AnomalyConfig,
    "parse_options": ParseOptions,
    "parse_report": ParseReport,
}

_P = ctypes.POINTER

# name: (restype, argtypes) for every function the binding uses.
_PROTOTYPES: Final[dict[str, tuple[object, list[object]]]] = {
    "call_analyzer_version": (ctypes.c_char_p, []),
    "call_analyzer_strerror": (ctypes.c_char_p, [c_int]),
    "call_analyzer_struct_sizes": (None, [_P(CaStructSizes)]),
    "call_outcome_name": (ctypes.c_char_p, [c_enum]),
    "call_anomaly_type_name": (ctypes.c_char_p, [c_enum]),
    "call_severity_name": (ctypes.c_char_p, [c_enum]),
    "parse_options_default": (None, [_P(ParseOptions)]),
    "parse_call_log_ex": (
        c_int,
        [ctypes.c_char_p, _P(ParseOptions), _P(_P(CallRecord)), _P(c_size_t), _P(ParseReport)],
    ),
    "free_call_records": (None, [_P(CallRecord)]),
    "calculate_statistics": (c_int, [_P(CallRecord), c_size_t, _P(CallStatistics)]),
    "calculate_cell_statistics": (
        c_int,
        [_P(CallRecord), c_size_t, _P(_P(CellStatistics)), _P(c_size_t)],
    ),
    "free_cell_statistics": (None, [_P(CellStatistics)]),
    "calculate_failure_code_statistics": (
        c_int,
        [_P(CallRecord), c_size_t, _P(_P(FailureCodeStatistics)), _P(c_size_t)],
    ),
    "free_failure_code_statistics": (None, [_P(FailureCodeStatistics)]),
    "calculate_time_window_statistics": (
        c_int,
        [_P(CallRecord), c_size_t, c_int64, _P(_P(TimeWindowStatistics)), _P(c_size_t)],
    ),
    "free_time_window_statistics": (None, [_P(TimeWindowStatistics)]),
    "calculate_caller_statistics": (
        c_int,
        [_P(CallRecord), c_size_t, _P(_P(CallerStatistics)), _P(c_size_t)],
    ),
    "free_caller_statistics": (None, [_P(CallerStatistics)]),
    "anomaly_config_default": (None, [_P(AnomalyConfig)]),
    "detect_call_anomalies": (
        c_int,
        [_P(CallRecord), c_size_t, _P(AnomalyConfig), _P(_P(CallAnomaly)), _P(c_size_t)],
    ),
    "free_call_anomalies": (None, [_P(CallAnomaly)]),
}

_BUILD_HINT: Final = (
    "Build it with `make c-build` from the repository root (produces "
    f"{LOCAL_BUILD_PATH}), or set {ENV_VAR} to the absolute path of libcallanalyzer.so."
)


def resolve_library_path(
    env: Mapping[str, str] | None = None,
    candidates: Sequence[Path] = DEFAULT_CANDIDATES,
) -> Path:
    """Returns the library path to load.

    ``CALL_ANALYZER_LIB`` wins when set and is never silently ignored: if it
    points at a missing file, loading fails rather than falling back.
    """
    environ = os.environ if env is None else env
    override = environ.get(ENV_VAR, "").strip()
    if override:
        path = Path(override).expanduser().resolve()
        if not path.is_file():
            raise LibraryLoadError(f"{ENV_VAR}={override!r} does not point to a file. {_BUILD_HINT}")
        return path
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    searched = ", ".join(str(c) for c in candidates)
    raise LibraryLoadError(f"libcallanalyzer.so not found (searched: {searched}). {_BUILD_HINT}")


@dataclass(frozen=True)
class NativeLibrary:
    """A loaded, ABI-checked libcallanalyzer."""

    path: Path
    cdll: ctypes.CDLL
    version: str

    def strerror(self, code: int) -> str:
        message: bytes | None = self.cdll.call_analyzer_strerror(code)
        return message.decode("ascii", "replace") if message else "unknown error"

    def name_of(self, function: str, value: int) -> str:
        name: bytes | None = getattr(self.cdll, function)(value)
        return name.decode("ascii", "replace") if name else "invalid"


def _configure_prototypes(cdll: ctypes.CDLL, path: Path) -> None:
    for name, (restype, argtypes) in _PROTOTYPES.items():
        try:
            func = getattr(cdll, name)
        except AttributeError as exc:
            raise LibraryLoadError(f"{path} does not export {name}; library is incompatible") from exc
        func.restype = restype
        func.argtypes = argtypes


def _verify_abi(cdll: ctypes.CDLL, path: Path) -> str:
    raw_version: bytes | None = cdll.call_analyzer_version()
    version = raw_version.decode("ascii", "replace") if raw_version else ""
    major = version.split(".", 1)[0]
    if major != str(SUPPORTED_MAJOR_VERSION):
        raise LibraryLoadError(
            f"{path} reports version {version!r}; binding supports major version "
            f"{SUPPORTED_MAJOR_VERSION}"
        )
    sizes = CaStructSizes()
    cdll.call_analyzer_struct_sizes(ctypes.byref(sizes))
    mismatches = [
        f"{field}: C={getattr(sizes, field)} Python={ctypes.sizeof(mirror)}"
        for field, mirror in _STRUCT_MIRRORS.items()
        if getattr(sizes, field) != ctypes.sizeof(mirror)
    ]
    if mismatches:
        raise LibraryLoadError(
            f"struct layout mismatch between {path} and the Python binding: "
            + "; ".join(mismatches)
        )
    return version


def load_library(path: Path) -> NativeLibrary:
    """Loads and ABI-checks the library at an explicit path (no search)."""
    try:
        cdll = ctypes.CDLL(str(path))
    except OSError as exc:
        raise LibraryLoadError(f"failed to load {path}: {exc}. {_BUILD_HINT}") from exc
    _configure_prototypes(cdll, path)
    version = _verify_abi(cdll, path)
    return NativeLibrary(path=path, cdll=cdll, version=version)


_lock = threading.Lock()
_library: NativeLibrary | None = None


def get_library() -> NativeLibrary:
    """Process-wide library instance, loaded on first use."""
    global _library
    with _lock:
        if _library is None:
            _library = load_library(resolve_library_path())
        return _library
