"""Tests for the ctypes binding against the real compiled libcallanalyzer."""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import math
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import call_analyzer
from call_analyzer import _native, errors
from call_analyzer import analyze_call_log

from . import reference

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _assert_matches(actual: dict[str, Any], expected: dict[str, Any], context: str) -> None:
    for key, value in expected.items():
        got = actual[key]
        if isinstance(value, float):
            assert math.isclose(got, value, rel_tol=1e-9, abs_tol=1e-9), f"{context}.{key}: {got} != {value}"
        else:
            assert got == value, f"{context}.{key}: {got!r} != {value!r}"


def _assert_matches_reference(result: dict[str, Any], path: Path, window_seconds: int) -> None:
    rows = reference.read_rows(path)
    _assert_matches(result, reference.overall(rows), "overall")
    expected_cells = reference.cells(rows)
    assert [c["cell_id"] for c in result["cells"]] == [c["cell_id"] for c in expected_cells]
    for got, want in zip(result["cells"], expected_cells, strict=True):
        _assert_matches(got, want, f"cell {want['cell_id']}")
    expected_codes = reference.failure_codes(rows)
    assert len(result["failure_codes"]) == len(expected_codes)
    for got, want in zip(result["failure_codes"], expected_codes, strict=True):
        _assert_matches(got, want, f"code {want['status_code']}")
    expected_windows = reference.time_windows(rows, window_seconds)
    assert len(result["time_windows"]) == len(expected_windows)
    for got, want in zip(result["time_windows"], expected_windows, strict=True):
        _assert_matches(got, want, f"window {want['window_start_epoch']}")
    expected_callers = reference.callers(rows)
    assert len(result["callers"]) == len(expected_callers)
    for got, want in zip(result["callers"], expected_callers, strict=True):
        _assert_matches(got, want, f"caller {want['caller']}")


# ---- Library loading -----------------------------------------------------------


def _mapped_callanalyzer_files() -> set[str]:
    maps = Path("/proc/self/maps").read_text()
    return {line.split()[-1] for line in maps.splitlines() if "libcallanalyzer" in line}


def test_library_loaded_from_documented_path() -> None:
    """The binding loads exactly the library it resolved, not one found by accident."""
    override = os.environ.get(_native.ENV_VAR)
    if override:
        expected = Path(override).resolve()
    else:
        expected = next(p for p in _native.DEFAULT_CANDIDATES if p.is_file()).resolve()
    assert Path(call_analyzer.library_path()) == expected
    if sys.platform.startswith("linux"):
        assert _mapped_callanalyzer_files() == {str(expected)}


def test_library_version_and_abi() -> None:
    lib = _native.get_library()
    assert call_analyzer.library_version() == "1.0.0"
    sizes = _native.CaStructSizes()
    lib.cdll.call_analyzer_struct_sizes(ctypes.byref(sizes))
    assert sizes.call_record == ctypes.sizeof(_native.CallRecord)
    assert sizes.call_anomaly == ctypes.sizeof(_native.CallAnomaly)


def test_every_prototype_is_declared() -> None:
    lib = _native.get_library()
    for name, (restype, argtypes) in _native._PROTOTYPES.items():
        func = getattr(lib.cdll, name)
        assert func.restype is restype, name
        assert tuple(func.argtypes) == tuple(argtypes), name


def test_resolve_prefers_env_and_never_falls_back(tmp_path: Path) -> None:
    lib = tmp_path / "libcustom.so"
    lib.write_bytes(b"")
    fallback = tmp_path / "fallback.so"
    fallback.write_bytes(b"")
    assert _native.resolve_library_path({_native.ENV_VAR: str(lib)}, [fallback]) == lib.resolve()
    with pytest.raises(call_analyzer.LibraryLoadError, match="does not point to a file"):
        _native.resolve_library_path({_native.ENV_VAR: str(tmp_path / "missing.so")}, [fallback])


def test_resolve_uses_candidates_in_order(tmp_path: Path) -> None:
    first, second = tmp_path / "a.so", tmp_path / "b.so"
    second.write_bytes(b"")
    assert _native.resolve_library_path({}, [first, second]) == second.resolve()
    first.write_bytes(b"")
    assert _native.resolve_library_path({}, [first, second]) == first.resolve()


def test_resolve_reports_how_to_build_when_nothing_found(tmp_path: Path) -> None:
    with pytest.raises(call_analyzer.LibraryLoadError) as info:
        _native.resolve_library_path({}, [tmp_path / "nope.so"])
    message = str(info.value)
    assert "make c-build" in message and _native.ENV_VAR in message and "nope.so" in message
    assert info.value.code is None


def test_default_candidates_are_documented_paths() -> None:
    assert _native.DEFAULT_CANDIDATES == (
        _native.REPO_ROOT / "c-library" / "build" / "libcallanalyzer.so",
        Path("/usr/local/lib/libcallanalyzer.so"),
    )


def test_load_rejects_non_library_file(tmp_path: Path) -> None:
    bogus = tmp_path / "libcallanalyzer.so"
    bogus.write_text("not an ELF file")
    with pytest.raises(call_analyzer.LibraryLoadError, match="failed to load"):
        _native.load_library(bogus)


@pytest.mark.skipif(ctypes.util.find_library("m") is None, reason="libm not locatable")
def test_load_rejects_wrong_library() -> None:
    libm = ctypes.util.find_library("m")
    assert libm is not None
    with pytest.raises(call_analyzer.LibraryLoadError, match="does not export"):
        _native.load_library(Path(libm))


def test_missing_library_error_in_fresh_process(tmp_path: Path) -> None:
    env = {**os.environ, _native.ENV_VAR: str(tmp_path / "absent" / "libcallanalyzer.so")}
    code = (
        "import call_analyzer\n"
        "try:\n"
        "    call_analyzer.analyze_call_log('x.csv')\n"
        "except call_analyzer.LibraryLoadError as exc:\n"
        "    print('LibraryLoadError:', exc)\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=BACKEND_DIR, env=env,
                          capture_output=True, text=True, timeout=60, check=True)
    assert "LibraryLoadError:" in proc.stdout
    assert "make c-build" in proc.stdout


# ---- Result conversion and reference agreement -----------------------------------


def test_small_fixture_values(c_fixtures: Path) -> None:
    result = analyze_call_log(c_fixtures / "valid_small.csv")
    assert result["total_calls"] == 10
    assert result["successful_calls"] == 5
    assert result["failed_setup_calls"] == 2
    assert result["dropped_calls"] == 2
    assert result["success_rate"] == pytest.approx(0.5)
    assert result["drop_rate"] == pytest.approx(2 / 7)
    assert result["average_duration"] == pytest.approx(843 / 7)
    assert result["average_signal"] == pytest.approx(-88.1)
    assert result["average_packet_loss"] == pytest.approx(2.4)
    assert result["first_timestamp"] == "2026-03-01T14:00:00Z"
    assert result["last_timestamp"] == "2026-03-01T14:12:00Z"
    assert result["failure_codes"][0] == {"status_code": 200, "outcome": "completed",
                                          "count": 5, "share": 0.5}
    assert {c["outcome"] for c in result["failure_codes"]} == {
        "completed", "unknown", "setup_failed", "dropped"}
    assert result["cells"][1]["cell_id"] == "CELL-B"
    assert result["time_windows"][0]["window_start"] == "2026-03-01T14:00:00Z"
    assert result["callers"][0]["caller"] == "+15550001"
    assert result["anomalies"] == []
    assert result["suspicious_time_windows"] == []
    assert result["parse_report"] == {
        "lines_read": 11, "records_parsed": 10, "records_rejected": 0, "header_present": True,
        "first_error_line": None, "first_error_code": None, "first_error": None,
        "first_error_message": None,
    }
    assert result["library_version"] == "1.0.0"


@pytest.mark.parametrize("window_seconds", [60, 300, 3600])
def test_small_fixture_matches_reference(c_fixtures: Path, window_seconds: int) -> None:
    path = c_fixtures / "valid_small.csv"
    _assert_matches_reference(analyze_call_log(path, window_seconds=window_seconds), path,
                              window_seconds)


def test_generated_log_matches_reference(generated_log: Path) -> None:
    result = analyze_call_log(generated_log, window_seconds=300)
    assert result["total_calls"] > 4000
    _assert_matches_reference(result, generated_log, 300)


def test_result_shape_is_json_serialisable(generated_log: Path) -> None:
    result = analyze_call_log(generated_log)
    decoded = json.loads(json.dumps(result))
    assert decoded == result
    expected_keys = set(call_analyzer.CallAnalysisResult.__annotations__)
    assert set(result) == expected_keys
    anomaly = result["anomalies"][0]
    assert set(anomaly) == set(call_analyzer.types.AnomalyDict.__annotations__)
    assert anomaly["severity"] in {"low", "medium", "high", "critical"}
    assert 0.0 <= anomaly["anomaly_score"] <= 1.0


def test_anomalies_sorted_and_categorised(generated_log: Path) -> None:
    anomalies = analyze_call_log(generated_log)["anomalies"]
    scores = [a["anomaly_score"] for a in anomalies]
    assert scores == sorted(scores, reverse=True)
    for a in anomalies:
        assert a["category"] in {"cell", "window", "caller", "call"}
        assert a["type"].startswith(a["category"] + "_")
        assert (a["record_index"] is None) == (a["category"] != "call")


def test_suspicious_windows_group_window_anomalies(c_fixtures: Path, tmp_path: Path) -> None:
    """A synthetic burst in one window becomes one suspicious window with both reasons."""
    lines = (c_fixtures / "valid_small.csv").read_text().splitlines()[:1]
    for minute in range(60):  # 12 quiet 5-minute windows, 20 calls each, ~1 drop
        for i in range(4):
            status = 901 if (minute * 4 + i) % 23 == 0 else 200
            lines.append(f"2026-03-01T10:{minute:02d}:{i * 10:02d}Z,+1555{i},+1666{minute},"
                         f"CELL-1,60,{status},-80,1")
    for i in range(120):  # burst at 10:30 with heavy drops
        status = 901 if i % 2 else 200
        lines.append(f"2026-03-01T10:31:{i % 60:02d}Z,+1777{i},+16660001,CELL-1,30,{status},-80,1")
    path = tmp_path / "burst.csv"
    path.write_text("\n".join(lines) + "\n")

    result = analyze_call_log(path, window_seconds=300)
    windows = result["suspicious_time_windows"]
    assert len(windows) == 1
    w = windows[0]
    assert w["window_start"] == "2026-03-01T10:30:00Z"
    assert sorted(w["reasons"]) == ["window_drop_rate", "window_volume_spike"]
    assert w["total_calls"] == 140
    burst_stats = next(t for t in result["time_windows"] if t["window_start"] == w["window_start"])
    assert w["drop_rate"] == burst_stats["drop_rate"]
    assert w["anomaly_score"] == max(a["anomaly_score"] for a in result["anomalies"]
                                     if a["window_start"] == w["window_start"])


def test_empty_log(c_fixtures: Path) -> None:
    result = analyze_call_log(c_fixtures / "empty.csv")
    assert result["total_calls"] == 0
    assert result["first_timestamp"] is None
    assert result["cells"] == result["failure_codes"] == result["time_windows"] == []
    assert result["callers"] == result["anomalies"] == []
    assert result["parse_report"]["lines_read"] == 0


def test_lenient_parse_report(c_fixtures: Path) -> None:
    result = analyze_call_log(c_fixtures / "mixed_valid_invalid.csv")
    report = result["parse_report"]
    assert result["total_calls"] == 2
    assert report["records_rejected"] == 2
    assert report["first_error_line"] == 3
    assert report["first_error"] == "CA_ERR_PARSE"
    assert report["first_error_code"] == errors.CA_ERR_PARSE
    assert report["first_error_message"].startswith("line 3:")


def test_anomaly_config_overrides(generated_log: Path) -> None:
    default = analyze_call_log(generated_log)
    capped = analyze_call_log(generated_log, anomaly_config={"max_anomalies": 1})
    assert len(capped["anomalies"]) == 1
    assert capped["anomalies"][0] == default["anomalies"][0]
    strict = analyze_call_log(generated_log, anomaly_config={"z_threshold": 1000.0})
    assert not any(a["category"] == "cell" for a in strict["anomalies"])


@pytest.mark.parametrize(
    ("overrides", "exc"),
    [
        ({"no_such_field": 1}, ValueError),
        ({"window_seconds": 60}, ValueError),
        ({"min_calls_per_cell": -1}, ValueError),
        ({"min_calls_per_cell": 2.5}, ValueError),
        ({"z_threshold": "3"}, TypeError),
        ({"z_threshold": True}, TypeError),
    ],
)
def test_anomaly_config_rejects_bad_overrides(
    generated_log: Path, overrides: dict[str, Any], exc: type[Exception]
) -> None:
    with pytest.raises(exc):
        analyze_call_log(generated_log, anomaly_config=overrides)


# ---- Error mapping ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "exc_type"),
    [
        (errors.CA_ERR_NULL_ARG, call_analyzer.NullArgumentError),
        (errors.CA_ERR_INVALID_ARG, call_analyzer.InvalidArgumentError),
        (errors.CA_ERR_IO, call_analyzer.CallLogIOError),
        (errors.CA_ERR_NOMEM, call_analyzer.OutOfMemoryError),
        (errors.CA_ERR_PARSE, call_analyzer.CallLogParseError),
        (errors.CA_ERR_OVERFLOW, call_analyzer.CallAnalyzerOverflowError),
        (errors.CA_ERR_LIMIT, call_analyzer.LimitExceededError),
        (-42, call_analyzer.CallAnalyzerError),
    ],
)
def test_status_code_mapping(code: int, exc_type: type[call_analyzer.CallAnalyzerError]) -> None:
    lib = _native.get_library()
    c_message = lib.strerror(code)
    err = errors.error_from_status(code, operation="op", c_message=c_message, detail="ctx")
    assert type(err) is exc_type
    assert isinstance(err, call_analyzer.CallAnalyzerError)
    assert err.code == code
    assert err.c_message == c_message
    assert c_message in str(err) and "ctx" in str(err) and f"code {code}" in str(err)
    assert err.code_name == errors.STATUS_NAMES.get(code, "UNKNOWN")


def test_status_names_match_c_messages() -> None:
    """Every mirrored status code has a real (not 'unknown error') message in C."""
    lib = _native.get_library()
    for code in errors.STATUS_NAMES:
        assert lib.strerror(code) != "unknown error", code
    assert lib.strerror(-42) == "unknown error"


def test_missing_file_raises_io_error(tmp_path: Path) -> None:
    with pytest.raises(call_analyzer.CallLogIOError) as info:
        analyze_call_log(tmp_path / "missing.csv")
    assert info.value.code == errors.CA_ERR_IO
    assert info.value.code_name == "CA_ERR_IO"
    assert "missing.csv" in str(info.value)


def test_directory_raises_io_error(tmp_path: Path) -> None:
    with pytest.raises(call_analyzer.CallLogIOError):
        analyze_call_log(tmp_path)


def test_wrong_header_raises_parse_error_with_report(c_fixtures: Path) -> None:
    with pytest.raises(call_analyzer.CallLogParseError) as info:
        analyze_call_log(c_fixtures / "wrong_column_order.csv")
    assert info.value.code == errors.CA_ERR_PARSE
    assert info.value.parse_report is not None
    assert info.value.parse_report["first_error_line"] == 1
    assert "header column" in str(info.value)


def test_strict_mode_raises_on_bad_row(c_fixtures: Path) -> None:
    with pytest.raises(call_analyzer.CallLogParseError) as info:
        analyze_call_log(c_fixtures / "mixed_valid_invalid.csv", strict=True)
    assert info.value.parse_report is not None
    assert info.value.parse_report["first_error_line"] == 3


def test_strict_mode_overflow_error(tmp_path: Path) -> None:
    path = tmp_path / "long_caller.csv"
    path.write_text("2026-03-01T14:00:00Z," + "1" * 40 + ",+2,CELL-A,10,200,-80,1\n")
    with pytest.raises(call_analyzer.CallAnalyzerOverflowError):
        analyze_call_log(path, strict=True)


def test_max_records_limit(c_fixtures: Path) -> None:
    with pytest.raises(call_analyzer.LimitExceededError) as info:
        analyze_call_log(c_fixtures / "valid_small.csv", max_records=5)
    assert info.value.code == errors.CA_ERR_LIMIT
    assert analyze_call_log(c_fixtures / "valid_small.csv", max_records=10)["total_calls"] == 10


@pytest.mark.parametrize("window_seconds", [0, -5, 86401])
def test_window_range_validated_by_c(c_fixtures: Path, window_seconds: int) -> None:
    with pytest.raises(call_analyzer.InvalidArgumentError) as info:
        analyze_call_log(c_fixtures / "valid_small.csv", window_seconds=window_seconds)
    assert info.value.code == errors.CA_ERR_INVALID_ARG


@pytest.mark.parametrize(
    ("kwargs", "exc"),
    [
        ({"path": "a\x00b.csv"}, ValueError),
        ({"path": ""}, ValueError),
        ({"path": 123}, TypeError),
        ({"path": "x.csv", "window_seconds": True}, TypeError),
        ({"path": "x.csv", "window_seconds": 300.0}, TypeError),
        ({"path": "x.csv", "max_records": 0}, ValueError),
        ({"path": "x.csv", "max_records": -1}, ValueError),
    ],
)
def test_python_side_argument_validation(kwargs: dict[str, Any], exc: type[Exception]) -> None:
    path = kwargs.pop("path")
    with pytest.raises(exc):
        analyze_call_log(path, **kwargs)


# ---- Memory ownership --------------------------------------------------------------


def _asan_loaded() -> bool:
    maps = Path("/proc/self/maps")
    return maps.exists() and "libasan" in maps.read_text()


def _glibc_heap_in_use() -> int | None:
    """Bytes allocated from the glibc heap (mallinfo2), or None if unavailable.

    Unavailable under AddressSanitizer, whose allocator bypasses glibc's heap.
    """
    if platform.libc_ver()[0] != "glibc" or _asan_loaded():
        return None

    class MallInfo2(ctypes.Structure):
        _fields_ = [(name, ctypes.c_size_t) for name in (
            "arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks",
            "uordblks", "fordblks", "keepcost")]

    libc = ctypes.CDLL(None)
    if not hasattr(libc, "mallinfo2"):
        return None
    libc.mallinfo2.restype = MallInfo2
    libc.mallinfo2.argtypes = []
    info = libc.mallinfo2()
    return int(info.uordblks + info.hblkhd)


HEAP_ITERATIONS = 100
# Measured noise for 100 calls on the seed-42 log: <= 5,056 bytes. The smallest
# per-array leak (failure codes) adds ~25,800 bytes, so 16 KiB separates both.
HEAP_GROWTH_LIMIT = 16 * 1024


def _heap_growth(path: Path, iterations: int = HEAP_ITERATIONS) -> int:
    for _ in range(5):  # warm up caches and lazily allocated interpreter state
        analyze_call_log(path)
    before = _glibc_heap_in_use()
    assert before is not None
    for _ in range(iterations):
        analyze_call_log(path)
    after = _glibc_heap_in_use()
    assert after is not None
    return after - before


needs_glibc_heap = pytest.mark.skipif(
    _glibc_heap_in_use() is None, reason="needs glibc mallinfo2 (unavailable on non-glibc or under ASan)")


@needs_glibc_heap
def test_repeated_calls_do_not_leak_native_memory(generated_log: Path) -> None:
    growth = _heap_growth(generated_log)
    assert growth < HEAP_GROWTH_LIMIT, f"native heap grew by {growth} bytes over {HEAP_ITERATIONS} calls"


@needs_glibc_heap
@pytest.mark.parametrize("free_name", [
    "free_call_records", "free_cell_statistics", "free_failure_code_statistics",
    "free_time_window_statistics", "free_caller_statistics", "free_call_anomalies",
])
def test_leak_check_detects_each_missing_free(
    generated_log: Path, monkeypatch: pytest.MonkeyPatch, free_name: str
) -> None:
    """Sanity check of the leak test itself: skipping any one free exceeds the limit."""
    monkeypatch.setattr(_native.get_library().cdll, free_name, lambda pointer: None)
    growth = _heap_growth(generated_log)
    assert growth > HEAP_GROWTH_LIMIT, f"{free_name} leak not detected (growth {growth})"


def test_repeated_calls_are_stable(generated_log: Path) -> None:
    first = analyze_call_log(generated_log)
    for _ in range(3):
        assert analyze_call_log(generated_log) == first


def test_errors_do_not_leak_or_corrupt_state(c_fixtures: Path, tmp_path: Path) -> None:
    for _ in range(50):
        with pytest.raises(call_analyzer.CallLogParseError):
            analyze_call_log(c_fixtures / "mixed_valid_invalid.csv", strict=True)
        with pytest.raises(call_analyzer.CallLogIOError):
            analyze_call_log(tmp_path / "missing.csv")
    assert analyze_call_log(c_fixtures / "valid_small.csv")["total_calls"] == 10
