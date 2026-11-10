# libcallanalyzer

C11 library for parsing, validating, aggregating and screening call-detail
records (CDRs) for Aegis-Net. The Python backend loads it as a shared library
(`libcallanalyzer.so`) via ctypes; all CDR number-crunching happens here.

## Build and test

```bash
make c-build        # from the repo root: RelWithDebInfo, warnings are errors
make c-test         # ctest: shared-library tests + fault-injection tests
make c-test-asan    # same tests under AddressSanitizer + UBSan + LeakSanitizer
```

Or directly:

```bash
cmake -S c-library -B c-library/build && cmake --build c-library/build
ctest --test-dir c-library/build --output-on-failure
```

CMake options: `CA_ENABLE_SANITIZERS` (OFF), `CA_WARNINGS_AS_ERRORS` (ON),
`CA_BUILD_TESTS` (ON). Warnings enabled: `-Wall -Wextra -Wpedantic -Wshadow
-Wconversion -Wsign-conversion -Wdouble-promotion -Wformat=2
-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wcast-qual
-Wnull-dereference -Wvla -Wundef -Wswitch-enum`.

The shared library is built with hidden visibility; only functions declared in
`include/call_analyzer.h` are exported.

## Input format

```
timestamp,caller,callee,cell_id,duration,status_code,signal_strength,packet_loss
2026-03-01T14:05:00Z,+15550001,+15550002,CELL-102,184,200,-82,1
```

- Header optional; if the first row starts with `timestamp` it must match the
  column list exactly (case-insensitive), otherwise parsing fails.
- UTF-8 BOM, CRLF line endings, blank lines and RFC 4180 quoted fields are accepted.
- Lines longer than 1024 bytes, fields longer than 63 bytes, embedded NUL bytes,
  and out-of-range values are rejected per row.
- Lenient mode (default) skips invalid rows and reports them in `ParseReport`;
  strict mode fails the whole parse on the first invalid row.

Field ranges and the status-code classification (2xx completed, 9xx dropped,
3xx–8xx setup failure, 1xx unknown) are documented in the header and in
`ARCHITECTURE.md` §3.1.

## API overview

| Function | Purpose |
|---|---|
| `parse_call_log`, `parse_call_log_ex`, `parse_call_log_buffer` | Parse a file or memory buffer into `CallRecord[]` |
| `calculate_statistics` | Totals, success/drop/setup-failure rates, duration mean/stddev/min/max, signal, packet loss, unique cells/callers, time span |
| `calculate_cell_statistics` | Per-cell aggregates |
| `calculate_failure_code_statistics` | Histogram of status codes with outcome class and share |
| `calculate_time_window_statistics` | Fixed-size time buckets (1 s – 24 h) |
| `calculate_caller_statistics` | Per-caller volume, distinct callees, short calls, outcomes |
| `detect_call_anomalies` | Robust outlier detection (see below) |
| `free_*` | Release library-allocated arrays (all accept NULL) |
| `call_analyzer_strerror`, `call_analyzer_version`, `call_analyzer_struct_sizes` | Diagnostics; struct sizes let bindings verify layout |

Example:

```c
CallRecord *records = NULL;
size_t count = 0;
CallStatistics stats;
CallAnomaly *anomalies = NULL;
size_t anomaly_count = 0;

int rc = parse_call_log("call_logs.csv", &records, &count);
if (rc != CA_OK) { fprintf(stderr, "%s\n", call_analyzer_strerror(rc)); return 1; }
calculate_statistics(records, count, &stats);
detect_call_anomalies(records, count, NULL, &anomalies, &anomaly_count);
for (size_t i = 0; i < anomaly_count; i++) puts(anomalies[i].description);
free_call_anomalies(anomalies);
free_call_records(records);
```

## Anomaly detection

Groups (cells, time windows, callers) and individual calls are compared with
peers using a robust z-score `z = (x − median) / max(1.4826·MAD, floor)`.
A finding needs both `z ≥ threshold` and a minimum absolute deviation, plus a
minimum sample size per group and at least `min_peer_groups` groups.

| Type | Signal | Defaults |
|---|---|---|
| `cell_drop_rate` | drop rate above peers | z ≥ 3.5, +5 pp, ≥ 20 established calls |
| `cell_setup_failure_rate` | setup failure rate above peers | z ≥ 3.5, +5 pp, ≥ 20 calls |
| `cell_low_signal` | mean signal below peers | z ≥ 3.5, −6 dB |
| `cell_packet_loss` | mean packet loss above peers | z ≥ 3.5, +3 pp |
| `window_drop_rate` | 5-minute window drop rate above other windows | z ≥ 3.5, +5 pp, ≥ 10 established calls |
| `window_volume_spike` | window call count above other windows | z ≥ 3.5, ≥ 2× median |
| `caller_high_volume` | caller volume above peers, mostly short/unanswered | z ≥ 3.5, ≥ 20 calls, ≥ 60 % short or failed |
| `call_duration` | individual established call far longer than typical | z ≥ 10 |

`score = 1 − 2^(−z/threshold)` (0.5 at the threshold), so severity bands are
low < 0.6 ≤ medium < 0.75 ≤ high < 0.9 ≤ critical. Results are sorted by score
and capped at `max_anomalies` (default 1000).

Limitations: baselines are computed from peers within the same input file, so a
fault affecting most cells at once shows up as window anomalies rather than
cell anomalies; time windows with zero calls are not reported, so volume drops
to zero are not detected here (the Python analytics layer handles that).

## Memory and safety

- Every output array is a single allocation released by its `free_*` function.
- On any error, outputs are NULL/0 and nothing is leaked; this is verified for
  every allocation site by the fault-injection test build (`CA_FAULT_INJECTION`),
  which forces each allocation to fail in turn.
- Size arithmetic is overflow-checked; running sums use 64-bit integers with
  overflow checks.
- Caller-supplied `CallRecord` arrays are checked for NUL-terminated strings
  before use.
- No global mutable state in the production library; functions are re-entrant.

## Tests

`tests/test_call_analyzer.c` (28 cases in the fault-injection build, 27 in
the shared build) covers parsing, malformed input (21 bad-row cases in lenient
and strict modes), NULL/invalid arguments, statistics checked against
hand-computed values, all aggregations, each anomaly type, a clean baseline
with no false positives, and out-of-memory handling. Fixtures are in `tests/data/`.
