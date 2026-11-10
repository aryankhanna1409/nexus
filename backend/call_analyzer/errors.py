"""Exception hierarchy for the call_analyzer binding.

Every error originating from the C library carries the original ``CaStatus``
code (``code``), its symbolic name (``code_name``) and the library's own
message (``c_message``) so nothing is lost in translation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from call_analyzer.types import ParseReportDict

# Mirrors the CaStatus enum in c-library/include/call_analyzer.h.
CA_OK: Final = 0
CA_ERR_NULL_ARG: Final = -1
CA_ERR_INVALID_ARG: Final = -2
CA_ERR_IO: Final = -3
CA_ERR_NOMEM: Final = -4
CA_ERR_PARSE: Final = -5
CA_ERR_OVERFLOW: Final = -6
CA_ERR_LIMIT: Final = -7

STATUS_NAMES: Final[dict[int, str]] = {
    CA_OK: "CA_OK",
    CA_ERR_NULL_ARG: "CA_ERR_NULL_ARG",
    CA_ERR_INVALID_ARG: "CA_ERR_INVALID_ARG",
    CA_ERR_IO: "CA_ERR_IO",
    CA_ERR_NOMEM: "CA_ERR_NOMEM",
    CA_ERR_PARSE: "CA_ERR_PARSE",
    CA_ERR_OVERFLOW: "CA_ERR_OVERFLOW",
    CA_ERR_LIMIT: "CA_ERR_LIMIT",
}


class CallAnalyzerError(Exception):
    """Base class for every error raised by the binding."""

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        c_message: str | None = None,
        parse_report: ParseReportDict | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.code_name = STATUS_NAMES.get(code, "UNKNOWN") if code is not None else None
        self.c_message = c_message
        self.parse_report = parse_report


class LibraryLoadError(CallAnalyzerError):
    """The shared library could not be found, loaded, or failed its ABI check."""


class NullArgumentError(CallAnalyzerError):
    """CA_ERR_NULL_ARG: the binding passed a NULL where one is not allowed (a binding bug)."""


class InvalidArgumentError(CallAnalyzerError):
    """CA_ERR_INVALID_ARG: an argument or field value is out of range."""


class CallLogIOError(CallAnalyzerError):
    """CA_ERR_IO: the call log could not be opened or read."""


class OutOfMemoryError(CallAnalyzerError):
    """CA_ERR_NOMEM: the native library could not allocate memory."""


class CallLogParseError(CallAnalyzerError):
    """CA_ERR_PARSE: malformed input (bad header, or a bad row in strict mode)."""


class CallAnalyzerOverflowError(CallAnalyzerError):
    """CA_ERR_OVERFLOW: a value or size overflowed (e.g. over-long field in strict mode)."""


class LimitExceededError(CallAnalyzerError):
    """CA_ERR_LIMIT: a configured limit was exceeded (e.g. max_records)."""


_EXCEPTION_FOR_STATUS: Final[dict[int, type[CallAnalyzerError]]] = {
    CA_ERR_NULL_ARG: NullArgumentError,
    CA_ERR_INVALID_ARG: InvalidArgumentError,
    CA_ERR_IO: CallLogIOError,
    CA_ERR_NOMEM: OutOfMemoryError,
    CA_ERR_PARSE: CallLogParseError,
    CA_ERR_OVERFLOW: CallAnalyzerOverflowError,
    CA_ERR_LIMIT: LimitExceededError,
}


def exception_class_for_status(code: int) -> type[CallAnalyzerError]:
    """Exception class used for a non-zero C status code."""
    return _EXCEPTION_FOR_STATUS.get(code, CallAnalyzerError)


def error_from_status(
    code: int,
    *,
    operation: str,
    c_message: str,
    detail: str | None = None,
    parse_report: ParseReportDict | None = None,
) -> CallAnalyzerError:
    """Builds the typed exception for a failed C call."""
    name = STATUS_NAMES.get(code, "UNKNOWN")
    message = f"{operation} failed: {c_message} ({name}, code {code})"
    if detail:
        message = f"{message}: {detail}"
    return exception_class_for_status(code)(
        message, code=code, c_message=c_message, parse_report=parse_report
    )
