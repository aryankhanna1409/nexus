"""Audit tests: per-field ABI agreement, native memory ownership, anomaly values.

These close gaps left by the load-time size check (``call_analyzer_struct_sizes``),
which cannot detect same-size field reorderings or type confusions.
"""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import call_analyzer
from call_analyzer import _native, analysis, analyze_call_log

from . import reference
from .conftest import REPO_ROOT

HEADER = REPO_ROOT / "c-library" / "include" / "call_analyzer.h"
BACKEND_DIR = Path(__file__).resolve().parents[1]

# Every ctypes mirror; class names equal the C typedef names.
MIRRORS: tuple[type[ctypes.Structure], ...] = (
    _native.CallRecord, _native.ParseOptions, _native.ParseReport, _native.CallStatistics,
    _native.CellStatistics, _native.FailureCodeStatistics, _native.TimeWindowStatistics,
    _native.CallerStatistics, _native.CallAnomaly, _native.AnomalyConfig, _native.CaStructSizes,
)
# C enums: gcc makes enums without negative values unsigned; values are small either way.
ENUM_FIELDS = {("FailureCodeStatistics", "outcome"), ("CallAnomaly", "type"),
               ("CallAnomaly", "severity")}


# ---- ABI: field names, order, offsets, sizes and type classes ------------------------


def _header_fields() -> dict[str, list[str]]:
    """Field names per typedef'd struct, in declaration order, parsed from the header."""
    text = re.sub(r"/\*.*?\*/", "", HEADER.read_text(), flags=re.S)
    structs: dict[str, list[str]] = {}
    for body, name in re.findall(r"typedef struct \{(.*?)\}\s*(\w+);", text, flags=re.S):
        structs[name] = re.findall(r"(\w+)\s*(?:\[[^\]]*\])?\s*;", body)
    return structs


def test_mirrors_declare_every_header_field_in_order() -> None:
    header = _header_fields()
    assert set(header) == {m.__name__ for m in MIRRORS}
    for mirror in MIRRORS:
        assert [f[0] for f in mirror._fields_] == header[mirror.__name__], mirror.__name__


def _python_kind(ctype: Any) -> str:
    if isinstance(ctype, type) and issubclass(ctype, ctypes.Array):
        return "s"
    if ctype is ctypes.c_double:
        return "f"
    if ctype in (ctypes.c_size_t, ctypes.c_uint64):
        return "u"
    if ctype in (ctypes.c_int, ctypes.c_int64):
        return "i"
    raise AssertionError(f"unexpected ctypes field type {ctype!r}")


def _probe_source() -> str:
    lines = [
        "#include <stddef.h>",
        "#include <stdio.h>",
        '#include "call_analyzer.h"',
        "#define KIND(x) _Generic((x), double: \"f\", int: \"i\", long: \"i\", long long: \"i\", \\",
        "    unsigned int: \"u\", unsigned long: \"u\", unsigned long long: \"u\", \\",
        "    char *: \"s\", default: \"?\")",
        "int main(void) {",
    ]
    for mirror in MIRRORS:
        name = mirror.__name__
        lines.append(f'    printf("{name} . %zu\\n", sizeof({name}));')
        for field, _ in mirror._fields_:
            member = f"((({name} *)0)->{field})"
            lines.append(
                f'    printf("{name} {field} %zu %zu %s\\n", offsetof({name}, {field}), '
                f"sizeof {member}, KIND({member}));"
            )
    lines += ["    return 0;", "}"]
    return "\n".join(lines) + "\n"


def test_struct_layouts_match_header_per_field(tmp_path: Path) -> None:
    """Compiles an offsetof/sizeof/_Generic probe against the authoritative header."""
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler available to build the ABI probe")
    source = tmp_path / "abi_probe.c"
    source.write_text(_probe_source())
    exe = tmp_path / "abi_probe"
    subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", f"-I{HEADER.parent}",
                    str(source), "-o", str(exe)], check=True, capture_output=True, text=True)
    output = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout

    c_layout: dict[tuple[str, str], tuple[int, int, str]] = {}
    c_sizes: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if parts[1] == ".":
            c_sizes[parts[0]] = int(parts[2])
        else:
            c_layout[(parts[0], parts[1])] = (int(parts[2]), int(parts[3]), parts[4])

    for mirror in MIRRORS:
        name = mirror.__name__
        assert ctypes.sizeof(mirror) == c_sizes[name], name
        for field, ctype in mirror._fields_:
            offset, size, kind = c_layout[(name, field)]
            descriptor = getattr(mirror, field)
            assert descriptor.offset == offset, f"{name}.{field} offset"
            assert descriptor.size == size, f"{name}.{field} size"
            expected = _python_kind(ctype)
            if (name, field) in ENUM_FIELDS:
                assert kind in ("i", "u"), f"{name}.{field} kind {kind}"
            else:
                assert kind == expected, f"{name}.{field}: C kind {kind}, Python {expected}"


def test_c_defaults_read_through_mirrors() -> None:
    """C writes defaults; reading them back field by field validates read/write offsets."""
    cdll = _native.get_library().cdll
    options = _native.ParseOptions()
    cdll.parse_options_default(ctypes.byref(options))
    assert (options.strict, options.max_records) == (0, 10_000_000)
    config = _native.AnomalyConfig()
    cdll.anomaly_config_default(ctypes.byref(config))
    assert {f: getattr(config, f) for f, _ in config._fields_} == reference.DEFAULT_ANOMALY_CONFIG


# ---- Memory ownership ------------------------------------------------------------------

# compute function -> (matching free function, index of the out-pointer argument)
_ALLOCATORS: dict[str, tuple[str, int]] = {
    "parse_call_log_ex": ("free_call_records", 2),
    "calculate_cell_statistics": ("free_cell_statistics", -2),
    "calculate_failure_code_statistics": ("free_failure_code_statistics", -2),
    "calculate_time_window_statistics": ("free_time_window_statistics", -2),
    "calculate_caller_statistics": ("free_caller_statistics", -2),
    "detect_call_anomalies": ("free_call_anomalies", -2),
}


def _address(pointer: Any) -> int | None:
    value: int | None = ctypes.cast(pointer, ctypes.c_void_p).value
    return value


class NativeSpy:
    """Wraps allocating C calls and free functions to record pointer ownership."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cdll = _native.get_library().cdll
        self.allocated: dict[str, list[int]] = defaultdict(list)
        self.freed: dict[str, list[int | None]] = defaultdict(list)
        self.calls: list[str] = []
        for compute_name, (free_name, out_index) in _ALLOCATORS.items():
            original = getattr(cdll, compute_name)

            def compute(*args: Any, _orig: Any = original, _free: str = free_name,
                        _idx: int = out_index, _name: str = compute_name) -> int:
                self.calls.append(_name)
                rc: int = _orig(*args)
                address = _address(args[_idx]._obj)
                if address is not None:
                    self.allocated[_free].append(address)
                return rc

            monkeypatch.setattr(cdll, compute_name, compute)
            original_free = getattr(cdll, free_name)

            def free(pointer: Any, _orig: Any = original_free, _name: str = free_name) -> None:
                self.freed[_name].append(_address(pointer))
                _orig(pointer)

            monkeypatch.setattr(cdll, free_name, free)

    def assert_balanced(self) -> None:
        for free_name, _ in _ALLOCATORS.values():
            released = [a for a in self.freed[free_name] if a is not None]
            assert len(set(released)) == len(released), f"double free via {free_name}"
            assert sorted(released) == sorted(self.allocated[free_name]), (
                f"{free_name}: allocated {self.allocated[free_name]} freed {released}")


def test_success_frees_every_allocation_exactly_once(
    generated_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = NativeSpy(monkeypatch)
    result = analyze_call_log(generated_log)
    assert result["anomalies"]
    spy.assert_balanced()
    for free_name, _ in _ALLOCATORS.values():
        assert len(spy.allocated[free_name]) == 1, free_name  # every array was non-empty
        assert len(spy.freed[free_name]) == 1, free_name


def test_c_failure_midway_frees_what_was_allocated(
    generated_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = NativeSpy(monkeypatch)
    with pytest.raises(call_analyzer.InvalidArgumentError):
        analyze_call_log(generated_log, window_seconds=0)  # rejected by the windows step
    spy.assert_balanced()
    assert spy.calls == ["parse_call_log_ex", "calculate_cell_statistics",
                         "calculate_failure_code_statistics", "calculate_time_window_statistics"]
    assert spy.freed["free_time_window_statistics"] == [None]
    assert len(spy.freed["free_call_records"]) == 1
    assert spy.freed["free_caller_statistics"] == spy.freed["free_call_anomalies"] == []


@pytest.mark.parametrize("converter", ["_convert_cell", "_convert_window", "_convert_caller",
                                       "_convert_anomaly"])
def test_python_exception_during_conversion_frees_arrays(
    generated_log: Path, monkeypatch: pytest.MonkeyPatch, converter: str
) -> None:
    spy = NativeSpy(monkeypatch)

    def explode(*_: object) -> None:
        raise RuntimeError("conversion failed")

    monkeypatch.setattr(analysis, converter, explode)
    with pytest.raises(RuntimeError, match="conversion failed"):
        analyze_call_log(generated_log)
    spy.assert_balanced()
    assert len(spy.freed["free_call_records"]) == 1


def test_parse_failure_allocates_nothing(c_fixtures: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spy = NativeSpy(monkeypatch)
    with pytest.raises(call_analyzer.CallLogParseError):
        analyze_call_log(c_fixtures / "mixed_valid_invalid.csv", strict=True)
    spy.assert_balanced()
    assert spy.calls == ["parse_call_log_ex"]
    assert all(not addresses for addresses in spy.allocated.values())


def test_spy_detects_missing_and_double_free(
    generated_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sanity check of the spy: tampered records fail the balance assertion."""
    spy = NativeSpy(monkeypatch)
    analyze_call_log(generated_log)
    spy.freed["free_cell_statistics"].clear()  # as if the free never happened
    with pytest.raises(AssertionError, match="free_cell_statistics"):
        spy.assert_balanced()
    spy.freed["free_cell_statistics"] = list(spy.allocated["free_cell_statistics"]) * 2
    with pytest.raises(AssertionError, match="double free"):
        spy.assert_balanced()


def _assert_plain_data(value: object, path: str = "result") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            assert type(key) is str, path
            _assert_plain_data(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_plain_data(item, f"{path}[{index}]")
    else:
        assert value is None or type(value) in (str, int, float, bool), f"{path}: {type(value)}"


def test_result_retains_no_native_objects(generated_log: Path) -> None:
    _assert_plain_data(analyze_call_log(generated_log))


# ---- Anomaly values against an independent reference ------------------------------------


def _all_anomaly_types_log(generator: ModuleType, path: Path) -> Path:
    """Seed-42 faulty cell plus additions that trigger every anomaly type."""
    lines = generator.render_csv(
        generator.generate_rows(generator.GeneratorConfig(seed=42))).splitlines()
    for i in range(360):  # burst on a new cell: volume spike (> 2x median), window drops, setup failures
        status = (200, 901, 503)[i % 3]
        lines.append(f"2026-03-01T14:20:{i % 60:02d}Z,+15569{i:06d},+15550000001,CELL-901,"
                     f"40,{status},-85,1")
    for i in range(60):  # robocaller: many short calls
        lines.append(f"2026-03-01T15:{i:02d}:30Z,+15560000000,+1555{i:07d},CELL-102,2,200,-85,1")
    lines.append("2026-03-01T14:10:00Z,+15550004242,+15550004243,CELL-103,20000,200,-85,1")
    lines[1:] = sorted(lines[1:])
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def _assert_anomalies_match(actual: list[dict[str, Any]], expected: list[dict[str, Any]]) -> None:
    assert [(a["type"], a["subject"]) for a in actual] == [(e["type"], e["subject"]) for e in expected]
    for got, want in zip(actual, expected, strict=True):
        for key, value in want.items():
            if isinstance(value, float):
                assert got[key] == pytest.approx(value, rel=1e-9, abs=1e-12), (want["type"], key)
            else:
                assert got[key] == value, (want["type"], want["subject"], key)


def test_every_anomaly_type_matches_reference(generator: ModuleType, tmp_path: Path) -> None:
    path = _all_anomaly_types_log(generator, tmp_path / "all_types.csv")
    actual = analyze_call_log(path)["anomalies"]
    assert {a["type"] for a in actual} == set(reference.ANOMALY_TYPE_ORDER)
    _assert_anomalies_match(actual, reference.anomalies(reference.read_rows(path)))


def test_anomalies_match_reference_with_overrides(generator: ModuleType, tmp_path: Path) -> None:
    path = _all_anomaly_types_log(generator, tmp_path / "all_types.csv")
    overrides: dict[str, float | int] = {"z_threshold": 5.0, "min_rate_delta": 0.1,
                                         "duration_z_threshold": 50.0, "max_anomalies": 4}
    cfg = {**reference.DEFAULT_ANOMALY_CONFIG, **overrides, "window_seconds": 600}
    actual = analyze_call_log(path, window_seconds=600, anomaly_config=overrides)["anomalies"]
    _assert_anomalies_match(actual, reference.anomalies(reference.read_rows(path), cfg))


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_generated_anomalies_match_reference(generator: ModuleType, tmp_path: Path, seed: int) -> None:
    path = tmp_path / "g.csv"
    path.write_text(generator.render_csv(generator.generate_rows(
        generator.GeneratorConfig(seed=seed))), encoding="ascii")
    _assert_anomalies_match(analyze_call_log(path)["anomalies"],
                            reference.anomalies(reference.read_rows(path)))


def test_suspicious_windows_are_exactly_grouped_c_window_anomalies(
    generator: ModuleType, tmp_path: Path
) -> None:
    """Python adds only grouping + a join: every field traces to a C-returned value."""
    result = analyze_call_log(_all_anomaly_types_log(generator, tmp_path / "all.csv"))
    window_anomalies = [a for a in result["anomalies"] if a["category"] == "window"]
    windows = {w["window_start_epoch"]: w for w in result["time_windows"]}
    assert result["suspicious_time_windows"]
    for entry in result["suspicious_time_windows"]:
        mine = [a for a in window_anomalies if a["window_start_epoch"] == entry["window_start_epoch"]]
        top = mine[0]  # anomalies are sorted by descending score
        assert entry["reasons"] == list(dict.fromkeys(a["type"] for a in mine))
        assert (entry["severity"], entry["anomaly_score"]) == (top["severity"], top["anomaly_score"])
        assert entry["window_end_epoch"] == top["window_end_epoch"]
        stats = windows[entry["window_start_epoch"]]
        assert (entry["total_calls"], entry["drop_rate"]) == (stats["total_calls"], stats["drop_rate"])
    assert {e["window_start_epoch"] for e in result["suspicious_time_windows"]} == {
        a["window_start_epoch"] for a in window_anomalies}


def test_suspicious_window_without_statistics_is_an_error() -> None:
    anomaly = {"category": "window", "window_start_epoch": 0, "window_start": "1970-01-01T00:00:00Z"}
    with pytest.raises(call_analyzer.CallAnalyzerError, match="no matching time window"):
        analysis._suspicious_windows([anomaly], [])  # type: ignore[list-item]


# ---- Argument range checks that ctypes would otherwise wrap silently -------------------


@pytest.mark.parametrize("window_seconds", [2**63, 2**64 + 300, -(2**63) - 1, -(2**64) + 300])
def test_window_seconds_outside_int64_is_rejected(c_fixtures: Path, window_seconds: int) -> None:
    with pytest.raises(ValueError, match="int64"):
        analyze_call_log(c_fixtures / "valid_small.csv", window_seconds=window_seconds)


def test_window_seconds_int64_extremes_reach_c(c_fixtures: Path) -> None:
    for value in (2**63 - 1, -(2**63)):
        with pytest.raises(call_analyzer.InvalidArgumentError):
            analyze_call_log(c_fixtures / "valid_small.csv", window_seconds=value)


def test_anomaly_config_float_overflow_is_value_error(c_fixtures: Path) -> None:
    with pytest.raises(ValueError, match="out of range"):
        analyze_call_log(c_fixtures / "valid_small.csv", anomaly_config={"z_threshold": 10**400})


def test_anomaly_config_size_t_max_accepted(c_fixtures: Path) -> None:
    result = analyze_call_log(c_fixtures / "valid_small.csv",
                              anomaly_config={"max_anomalies": 2**64 - 1})
    assert result["anomalies"] == []
    with pytest.raises(ValueError):
        analyze_call_log(c_fixtures / "valid_small.csv", anomaly_config={"max_anomalies": 2**64})


# ---- Library discovery edge cases -------------------------------------------------------


def test_empty_env_value_means_unset(tmp_path: Path) -> None:
    candidate = tmp_path / "lib.so"
    candidate.write_bytes(b"")
    for value in ("", "   "):
        assert _native.resolve_library_path({_native.ENV_VAR: value}, [candidate]) == candidate


def test_env_pointing_at_invalid_file_fails_in_fresh_process(tmp_path: Path) -> None:
    bogus = tmp_path / "libcallanalyzer.so"
    bogus.write_text("not a shared library")
    env = {**os.environ, _native.ENV_VAR: str(bogus)}
    code = (
        "import call_analyzer\n"
        "try:\n"
        "    call_analyzer.analyze_call_log('x.csv')\n"
        "except call_analyzer.LibraryLoadError as exc:\n"
        "    print('LibraryLoadError:', exc)\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=BACKEND_DIR, env=env,
                          capture_output=True, text=True, timeout=60, check=True)
    assert "LibraryLoadError: failed to load" in proc.stdout
    assert str(bogus) in proc.stdout
