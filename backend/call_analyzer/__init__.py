"""Python binding for libcallanalyzer (Aegis-Net call-log analysis in C).

    from call_analyzer import analyze_call_log
    result = analyze_call_log("data/call_logs/call_logs.csv")
"""

from call_analyzer._native import ENV_VAR, get_library, resolve_library_path
from call_analyzer.analysis import DEFAULT_WINDOW_SECONDS, analyze_call_log
from call_analyzer.errors import (
    CallAnalyzerError,
    CallAnalyzerOverflowError,
    CallLogIOError,
    CallLogParseError,
    InvalidArgumentError,
    LibraryLoadError,
    LimitExceededError,
    NullArgumentError,
    OutOfMemoryError,
)
from call_analyzer.types import CallAnalysisResult


def library_path() -> str:
    """Absolute path of the shared library in use (loads it if needed)."""
    return str(get_library().path)


def library_version() -> str:
    return get_library().version


__all__ = [
    "DEFAULT_WINDOW_SECONDS",
    "ENV_VAR",
    "CallAnalysisResult",
    "CallAnalyzerError",
    "CallAnalyzerOverflowError",
    "CallLogIOError",
    "CallLogParseError",
    "InvalidArgumentError",
    "LibraryLoadError",
    "LimitExceededError",
    "NullArgumentError",
    "OutOfMemoryError",
    "analyze_call_log",
    "library_path",
    "library_version",
    "resolve_library_path",
]
