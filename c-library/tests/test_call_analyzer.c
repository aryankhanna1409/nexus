/*
 * test_call_analyzer.c - unit tests for libcallanalyzer.
 *
 * Built twice: against the shared library, and against a static build with
 * CA_FAULT_INJECTION so out-of-memory paths can be exercised. Run the suite
 * under ASan/UBSan (make c-test-asan) to check memory safety and leaks.
 */
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_analyzer.h"

#ifdef CA_FAULT_INJECTION
void ca_fault_inject_set(long remaining);
long ca_fault_inject_triggered(void);
#endif

#ifndef CA_TEST_DATA_DIR
#error "CA_TEST_DATA_DIR must be defined"
#endif

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        g_checks++;                                                                    \
        if (!(cond)) {                                                                 \
            g_failures++;                                                              \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
        }                                                                              \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                                 \
    do {                                                                               \
        const long long a_ = (long long)(actual);                                      \
        const long long e_ = (long long)(expected);                                    \
        g_checks++;                                                                    \
        if (a_ != e_) {                                                                \
            g_failures++;                                                              \
            fprintf(stderr, "  FAIL %s:%d: %s == %lld, expected %lld\n", __FILE__,     \
                    __LINE__, #actual, a_, e_);                                        \
        }                                                                              \
    } while (0)

#define CHECK_NEAR(actual, expected, tol)                                              \
    do {                                                                               \
        const double a_ = (actual);                                                    \
        const double e_ = (expected);                                                  \
        g_checks++;                                                                    \
        if (fabs(a_ - e_) > (tol)) {                                                   \
            g_failures++;                                                              \
            fprintf(stderr, "  FAIL %s:%d: %s == %.9g, expected %.9g\n", __FILE__,     \
                    __LINE__, #actual, a_, e_);                                        \
        }                                                                              \
    } while (0)

#define CHECK_STR(actual, expected)                                                    \
    do {                                                                               \
        g_checks++;                                                                    \
        if (strcmp((actual), (expected)) != 0) {                                       \
            g_failures++;                                                              \
            fprintf(stderr, "  FAIL %s:%d: %s == \"%s\", expected \"%s\"\n", __FILE__, \
                    __LINE__, #actual, (actual), (expected));                          \
        }                                                                              \
    } while (0)

#define DATA(name) CA_TEST_DATA_DIR "/" name
#define EPOCH_2026_03_01 1772323200LL

/* ---- Helpers --------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} TextBuf;

static void buf_append(TextBuf *b, const char *fmt, ...)
{
    va_list ap;
    int needed;

    va_start(ap, fmt);
    needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0) {
        abort();
    }
    while (b->len + (size_t)needed + 1 > b->cap) {
        size_t new_cap = b->cap == 0 ? 4096 : b->cap * 2;
        char *grown = realloc(b->data, new_cap);
        if (grown == NULL) {
            abort();
        }
        b->data = grown;
        b->cap = new_cap;
    }
    va_start(ap, fmt);
    vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    b->len += (size_t)needed;
}

/* Appends one CSV row; `seconds` is the offset from 2026-03-01T00:00:00Z (< 1 day). */
static void add_row(TextBuf *b, long seconds, const char *caller, const char *callee,
                    const char *cell, int duration, int status, int signal, int loss)
{
    buf_append(b, "2026-03-01T%02ld:%02ld:%02ldZ,%s,%s,%s,%d,%d,%d,%d\n", seconds / 3600,
               (seconds % 3600) / 60, seconds % 60, caller, callee, cell, duration, status,
               signal, loss);
}

/* Deterministic LCG so generated datasets are identical on every run. */
static unsigned long g_rng = 12345UL;
static unsigned rng_next(void)
{
    g_rng = (g_rng * 1103515245UL + 12345UL) & 0x7fffffffUL;
    return (unsigned)(g_rng >> 8);
}

typedef struct {
    int drop_cell;          /* cell index with elevated drops, -1 for none */
    int weak_signal_cell;   /* cell index with degraded signal, -1 for none */
    int volume_spike;       /* add a burst of calls in one window */
    int robocaller;         /* add one caller with many short calls */
    int long_call;          /* add one extremely long call */
} DatasetSpec;

/* 10 cells x 100 calls over 3000 s, ~2% drops, plus the requested faults. */
static void build_dataset(TextBuf *b, const DatasetSpec *spec)
{
    g_rng = 12345UL;
    for (int i = 0; i < 1000; i++) {
        const int cell = i % 10;
        char cell_id[16], caller[16], callee[16];
        unsigned r = rng_next() % 1000;
        int status = 200;
        int signal = -80 - (int)(rng_next() % 10);
        int duration = 30 + (int)(rng_next() % 271);

        snprintf(cell_id, sizeof cell_id, "CELL-%03d", 100 + cell);
        snprintf(caller, sizeof caller, "+1555%04u", rng_next() % 200);
        snprintf(callee, sizeof callee, "+1666%04u", rng_next() % 500);
        if (cell == spec->drop_cell) {
            status = r < 300 ? 901 : 200;
        } else if (r < 20) {
            status = 901;
        } else if (r < 30) {
            status = 486;
        }
        if (cell == spec->weak_signal_cell) {
            signal = -112 - (int)(rng_next() % 5);
        }
        add_row(b, 36000 + i * 3, caller, callee, cell_id, duration, status, signal,
                (int)(rng_next() % 3));
    }
    if (spec->volume_spike) {
        for (int i = 0; i < 400; i++) {
            char caller[16];
            snprintf(caller, sizeof caller, "+1777%04d", i);
            add_row(b, 36000 + 1500 + (i % 290), caller, "+16660001", "CELL-105", 60, 200, -85,
                    1);
        }
    }
    if (spec->robocaller) {
        for (int i = 0; i < 60; i++) {
            char callee[16];
            snprintf(callee, sizeof callee, "+1888%04d", i);
            add_row(b, 36000 + i * 45, "+19990000", callee, "CELL-103", 2, 200, -85, 1);
        }
    }
    if (spec->long_call) {
        add_row(b, 36100, "+15550042", "+16660042", "CELL-102", 20000, 200, -85, 1);
    }
}

static int parse_text(const TextBuf *b, CallRecord **records, size_t *count)
{
    return parse_call_log_buffer(b->data, b->len, NULL, records, count, NULL);
}

static size_t count_type(const CallAnomaly *a, size_t n, CallAnomalyType type, const char *subject)
{
    size_t found = 0;
    for (size_t i = 0; i < n; i++) {
        if (a[i].type == type && (subject == NULL || strcmp(a[i].subject, subject) == 0)) {
            found++;
        }
    }
    return found;
}

/* ---- Parser tests ---------------------------------------------------------- */

static void test_parser_valid_file(void)
{
    CallRecord *records = NULL;
    size_t count = 0;
    ParseReport report;

    CHECK_EQ_INT(parse_call_log_ex(DATA("valid_small.csv"), NULL, &records, &count, &report), CA_OK);
    CHECK_EQ_INT(count, 10);
    CHECK_EQ_INT(report.records_parsed, 10);
    CHECK_EQ_INT(report.records_rejected, 0);
    CHECK_EQ_INT(report.lines_read, 11);
    CHECK_EQ_INT(report.header_present, 1);
    CHECK_EQ_INT(report.first_error_line, 0);
    if (count == 10) {
        CHECK_STR(records[0].timestamp, "2026-03-01T14:00:00Z");
        CHECK_STR(records[0].caller, "+15550001");
        CHECK_STR(records[0].callee, "+15550002");
        CHECK_STR(records[0].cell_id, "CELL-A");
        CHECK_EQ_INT(records[0].duration, 120);
        CHECK_EQ_INT(records[0].status_code, 200);
        CHECK_EQ_INT(records[0].signal_strength, -80);
        CHECK_EQ_INT(records[0].packet_loss, 1);
        CHECK_EQ_INT(records[0].epoch_seconds, EPOCH_2026_03_01 + 14 * 3600);
        CHECK_EQ_INT(records[9].status_code, 180);
    }
    free_call_records(records);
}

static void test_parser_simple_api(void)
{
    CallRecord *records = NULL;
    size_t count = 0;
    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, &count), CA_OK);
    CHECK_EQ_INT(count, 10);
    free_call_records(records);
}

static void test_parser_no_header_crlf_bom(void)
{
    const char text[] = "\xEF\xBB\xBF"
                        "2026-03-01T14:00:00Z,+1,+2,CELL-A,10,200,-80,1\r\n"
                        "\r\n"
                        "   \n"
                        "2026-03-01 14:00:05,+1,+3,CELL-B,20,901,-90,2\r\n";
    CallRecord *records = NULL;
    size_t count = 0;
    ParseReport report;

    CHECK_EQ_INT(parse_call_log_buffer(text, sizeof text - 1, NULL, &records, &count, &report),
                 CA_OK);
    CHECK_EQ_INT(count, 2);
    CHECK_EQ_INT(report.header_present, 0);
    CHECK_EQ_INT(report.lines_read, 4);
    if (count == 2) {
        CHECK_STR(records[0].timestamp, "2026-03-01T14:00:00Z");
        CHECK_STR(records[1].timestamp, "2026-03-01T14:00:05Z");
        CHECK_STR(records[1].cell_id, "CELL-B");
        CHECK_EQ_INT(records[1].packet_loss, 2);
    }
    free_call_records(records);
}

static void test_parser_quoted_fields(void)
{
    const char text[] = "timestamp,caller,callee,cell_id,duration,status_code,signal_strength,"
                        "packet_loss\n"
                        "\"2026-03-01T14:00:00Z\", \"+1\" ,\"+2\",\"CELL-A\",\"10\",200,-80,1\n";
    CallRecord *records = NULL;
    size_t count = 0;

    CHECK_EQ_INT(parse_call_log_buffer(text, sizeof text - 1, NULL, &records, &count, NULL), CA_OK);
    CHECK_EQ_INT(count, 1);
    if (count == 1) {
        CHECK_STR(records[0].caller, "+1");
        CHECK_EQ_INT(records[0].duration, 10);
    }
    free_call_records(records);
}

static void test_parser_empty_inputs(void)
{
    CallRecord *records = (CallRecord *)&records; /* must be reset to NULL */
    size_t count = 99;
    ParseReport report;

    CHECK_EQ_INT(parse_call_log_ex(DATA("empty.csv"), NULL, &records, &count, &report), CA_OK);
    CHECK(records == NULL);
    CHECK_EQ_INT(count, 0);
    CHECK_EQ_INT(report.lines_read, 0);

    CHECK_EQ_INT(parse_call_log_buffer(NULL, 0, NULL, &records, &count, NULL), CA_OK);
    CHECK(records == NULL);
    CHECK_EQ_INT(count, 0);

    const char header_only[] = "timestamp,caller,callee,cell_id,duration,status_code,"
                               "signal_strength,packet_loss\n";
    CHECK_EQ_INT(parse_call_log_buffer(header_only, sizeof header_only - 1, NULL, &records,
                                       &count, &report),
                 CA_OK);
    CHECK_EQ_INT(count, 0);
    CHECK_EQ_INT(report.header_present, 1);
}

static void test_parser_missing_file(void)
{
    CallRecord *records = NULL;
    size_t count = 0;
    CHECK_EQ_INT(parse_call_log(DATA("does_not_exist.csv"), &records, &count), CA_ERR_IO);
    CHECK(records == NULL);
    CHECK_EQ_INT(parse_call_log(CA_TEST_DATA_DIR, &records, &count), CA_ERR_IO); /* directory */
    CHECK(records == NULL);
}

static void test_parser_timestamps(void)
{
    struct {
        const char *ts;
        int expected_rc;
        long long epoch;
    } cases[] = {
        {"2026-03-01T14:05:00Z", CA_OK, EPOCH_2026_03_01 + 14 * 3600 + 5 * 60},
        {"1970-01-01T00:00:00Z", CA_OK, 0},
        {"2024-02-29T00:00:00", CA_OK, 1709164800LL},
        {"2026-02-29T00:00:00Z", CA_ERR_INVALID_ARG, 0},
        {"2026-13-01T00:00:00Z", CA_ERR_INVALID_ARG, 0},
        {"2026-03-01T24:00:00Z", CA_ERR_INVALID_ARG, 0},
        {"1969-12-31T23:59:59Z", CA_ERR_INVALID_ARG, 0},
        {"2026-3-01T14:05:00Z", CA_ERR_PARSE, 0},
        {"2026-03-01T14:05:00+01:00", CA_ERR_PARSE, 0},
        {"2026/03/01T14:05:00Z", CA_ERR_PARSE, 0},
        {"", CA_ERR_PARSE, 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char line[256];
        CallRecord *records = NULL;
        size_t count = 0;
        ParseReport report;
        const ParseOptions strict = {1, 0};
        snprintf(line, sizeof line, "%s,+1,+2,CELL-A,10,200,-80,1\n", cases[i].ts);
        const int rc = parse_call_log_buffer(line, strlen(line), &strict, &records, &count, &report);
        CHECK_EQ_INT(rc, cases[i].expected_rc);
        if (cases[i].expected_rc == CA_OK && count == 1) {
            CHECK_EQ_INT(records[0].epoch_seconds, cases[i].epoch);
        } else if (cases[i].expected_rc != CA_OK) {
            CHECK(records == NULL);
            CHECK_EQ_INT(report.first_error_line, 1);
        }
        free_call_records(records);
    }
}

/* ---- Malformed-input tests ------------------------------------------------- */

typedef struct {
    const char *name;
    const char *row;
    int expected_rc;
} BadRow;

static void test_malformed_rows(void)
{
    static const BadRow rows[] = {
        {"too few fields", "2026-03-01T14:00:00Z,+1,+2,CELL-A,10,200,-80", CA_ERR_PARSE},
        {"too many fields", "2026-03-01T14:00:00Z,+1,+2,CELL-A,10,200,-80,1,9", CA_ERR_PARSE},
        {"non-numeric duration", "2026-03-01T14:00:00Z,+1,+2,CELL-A,ten,200,-80,1", CA_ERR_PARSE},
        {"trailing garbage", "2026-03-01T14:00:00Z,+1,+2,CELL-A,10x,200,-80,1", CA_ERR_PARSE},
        {"empty duration", "2026-03-01T14:00:00Z,+1,+2,CELL-A,,200,-80,1", CA_ERR_PARSE},
        {"negative duration", "2026-03-01T14:00:00Z,+1,+2,CELL-A,-5,200,-80,1", CA_ERR_INVALID_ARG},
        {"duration too large", "2026-03-01T14:00:00Z,+1,+2,CELL-A,86401,200,-80,1",
         CA_ERR_INVALID_ARG},
        {"status out of range", "2026-03-01T14:00:00Z,+1,+2,CELL-A,10,42,-80,1", CA_ERR_INVALID_ARG},
        {"positive signal", "2026-03-01T14:00:00Z,+1,+2,CELL-A,10,200,5,1", CA_ERR_INVALID_ARG},
        {"packet loss > 100", "2026-03-01T14:00:00Z,+1,+2,CELL-A,10,200,-80,101", CA_ERR_INVALID_ARG},
        {"integer overflow", "2026-03-01T14:00:00Z,+1,+2,CELL-A,99999999999999999999999,200,-80,1",
         CA_ERR_OVERFLOW},
        {"int-range overflow", "2026-03-01T14:00:00Z,+1,+2,CELL-A,4294967296,200,-80,1",
         CA_ERR_OVERFLOW},
        {"empty caller", "2026-03-01T14:00:00Z,,+2,CELL-A,10,200,-80,1", CA_ERR_PARSE},
        {"bad caller chars", "2026-03-01T14:00:00Z,+1;rm,+2,CELL-A,10,200,-80,1", CA_ERR_PARSE},
        {"bad cell chars", "2026-03-01T14:00:00Z,+1,+2,CELL A/1,10,200,-80,1", CA_ERR_PARSE},
        {"caller 32 chars", "2026-03-01T14:00:00Z,12345678901234567890123456789012,+2,CELL-A,10,"
                            "200,-80,1",
         CA_ERR_OVERFLOW},
        {"field over 63 bytes",
         "2026-03-01T14:00:00Z,+1,+2,CELL-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
         ",10,200,-80,1",
         CA_ERR_OVERFLOW},
        {"unterminated quote", "2026-03-01T14:00:00Z,\"+1,+2,CELL-A,10,200,-80,1", CA_ERR_PARSE},
        {"stray quote", "2026-03-01T14:00:00Z,+1\"x,+2,CELL-A,10,200,-80,1", CA_ERR_PARSE},
        {"text after quote", "2026-03-01T14:00:00Z,\"+1\"x,+2,CELL-A,10,200,-80,1", CA_ERR_PARSE},
        {"bad timestamp", "yesterday,+1,+2,CELL-A,10,200,-80,1", CA_ERR_PARSE},
    };

    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        TextBuf b = {NULL, 0, 0};
        CallRecord *records = NULL;
        size_t count = 0;
        ParseReport report;
        const ParseOptions strict = {1, 0};
        int rc;

        /* Lenient: the bad row is skipped, the valid row survives. */
        buf_append(&b, "%s\n2026-03-01T14:00:01Z,+1,+2,CELL-A,10,200,-80,1\n", rows[i].row);
        rc = parse_call_log_buffer(b.data, b.len, NULL, &records, &count, &report);
        if (rc != CA_OK || count != 1 || report.records_rejected != 1 ||
            report.first_error != rows[i].expected_rc || report.first_error_line != 1) {
            fprintf(stderr, "  case '%s': rc=%d count=%zu rejected=%zu first_error=%d (%s)\n",
                    rows[i].name, rc, count, report.records_rejected, report.first_error,
                    report.first_error_message);
        }
        CHECK_EQ_INT(rc, CA_OK);
        CHECK_EQ_INT(count, 1);
        CHECK_EQ_INT(report.records_rejected, 1);
        CHECK_EQ_INT(report.first_error, rows[i].expected_rc);
        CHECK(strncmp(report.first_error_message, "line 1:", 7) == 0);
        free_call_records(records);

        /* Strict: the whole parse fails and nothing is returned. */
        records = NULL;
        rc = parse_call_log_buffer(b.data, b.len, &strict, &records, &count, &report);
        CHECK_EQ_INT(rc, rows[i].expected_rc);
        CHECK(records == NULL);
        CHECK_EQ_INT(count, 0);
        free(b.data);
    }
}

static void test_malformed_mixed_file(void)
{
    CallRecord *records = NULL;
    size_t count = 0;
    ParseReport report;
    ParseOptions strict;

    CHECK_EQ_INT(parse_call_log_ex(DATA("mixed_valid_invalid.csv"), NULL, &records, &count, &report),
                 CA_OK);
    CHECK_EQ_INT(count, 2);
    CHECK_EQ_INT(report.records_rejected, 2);
    CHECK_EQ_INT(report.first_error_line, 3);
    free_call_records(records);

    parse_options_default(&strict);
    strict.strict = 1;
    records = NULL;
    CHECK_EQ_INT(parse_call_log_ex(DATA("mixed_valid_invalid.csv"), &strict, &records, &count,
                                   &report),
                 CA_ERR_PARSE);
    CHECK(records == NULL);
    CHECK_EQ_INT(count, 0);
}

static void test_malformed_header(void)
{
    CallRecord *records = NULL;
    size_t count = 0;
    ParseReport report;
    /* A header with the wrong column order is fatal even in lenient mode. */
    CHECK_EQ_INT(parse_call_log_ex(DATA("wrong_column_order.csv"), NULL, &records, &count, &report),
                 CA_ERR_PARSE);
    CHECK(records == NULL);
    CHECK_EQ_INT(report.first_error_line, 1);
}

static void test_malformed_long_line_and_nul(void)
{
    TextBuf b = {NULL, 0, 0};
    CallRecord *records = NULL;
    size_t count = 0;
    ParseReport report;
    char *with_nul;
    const char tail[] = "2026-03-01T14:00:01Z,+1,+2,CELL-A,10,200,-80,1\n";

    for (int i = 0; i < 3000; i++) {
        buf_append(&b, "x");
    }
    buf_append(&b, "\n%s", tail);
    CHECK_EQ_INT(parse_call_log_buffer(b.data, b.len, NULL, &records, &count, &report), CA_OK);
    CHECK_EQ_INT(count, 1);
    CHECK_EQ_INT(report.records_rejected, 1);
    CHECK_EQ_INT(report.first_error, CA_ERR_LIMIT);
    free_call_records(records);
    free(b.data);

    /* Embedded NUL byte inside a row. */
    with_nul = malloc(sizeof tail * 2);
    CHECK(with_nul != NULL);
    if (with_nul != NULL) {
        memcpy(with_nul, tail, sizeof tail - 1);
        memcpy(with_nul + sizeof tail - 1, tail, sizeof tail - 1);
        with_nul[5] = '\0';
        records = NULL;
        CHECK_EQ_INT(parse_call_log_buffer(with_nul, 2 * (sizeof tail - 1), NULL, &records, &count,
                                           &report),
                     CA_OK);
        CHECK_EQ_INT(count, 1);
        CHECK_EQ_INT(report.first_error, CA_ERR_PARSE);
        free_call_records(records);
        free(with_nul);
    }

    /* A final line without a trailing newline is still parsed. */
    records = NULL;
    CHECK_EQ_INT(parse_call_log_buffer(tail, sizeof tail - 2, NULL, &records, &count, NULL), CA_OK);
    CHECK_EQ_INT(count, 1);
    free_call_records(records);
}

static void test_parser_record_limit(void)
{
    TextBuf b = {NULL, 0, 0};
    CallRecord *records = NULL;
    size_t count = 0;
    ParseOptions opts;

    for (int i = 0; i < 300; i++) {
        add_row(&b, i, "+1", "+2", "CELL-A", 10, 200, -80, 1);
    }
    parse_options_default(&opts);
    opts.max_records = 299;
    CHECK_EQ_INT(parse_call_log_buffer(b.data, b.len, &opts, &records, &count, NULL), CA_ERR_LIMIT);
    CHECK(records == NULL);
    opts.max_records = 300; /* exactly at the limit, crossing the initial capacity */
    CHECK_EQ_INT(parse_call_log_buffer(b.data, b.len, &opts, &records, &count, NULL), CA_OK);
    CHECK_EQ_INT(count, 300);
    free_call_records(records);
    free(b.data);
}

/* ---- NULL / argument handling --------------------------------------------- */

static void test_null_arguments(void)
{
    CallRecord *records = NULL;
    size_t count = 0;
    CallStatistics stats;
    CellStatistics *cells = NULL;
    FailureCodeStatistics *codes = NULL;
    TimeWindowStatistics *windows = NULL;
    CallerStatistics *callers = NULL;
    CallAnomaly *anomalies = NULL;
    CallRecord one;

    CHECK_EQ_INT(parse_call_log(NULL, &records, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), NULL, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, NULL), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(parse_call_log_buffer(NULL, 5, NULL, &records, &count, NULL), CA_ERR_NULL_ARG);

    CHECK_EQ_INT(calculate_statistics(NULL, 0, NULL), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_statistics(NULL, 3, &stats), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_cell_statistics(NULL, 3, &cells, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_cell_statistics(NULL, 0, NULL, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_failure_code_statistics(NULL, 3, &codes, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_failure_code_statistics(NULL, 0, &codes, NULL), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_time_window_statistics(NULL, 3, 60, &windows, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_time_window_statistics(NULL, 0, 60, NULL, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_caller_statistics(NULL, 3, &callers, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(calculate_caller_statistics(NULL, 0, &callers, NULL), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(detect_call_anomalies(NULL, 3, NULL, &anomalies, &count), CA_ERR_NULL_ARG);
    CHECK_EQ_INT(detect_call_anomalies(NULL, 0, NULL, NULL, &count), CA_ERR_NULL_ARG);

    /* Free functions accept NULL. */
    free_call_records(NULL);
    free_cell_statistics(NULL);
    free_failure_code_statistics(NULL);
    free_time_window_statistics(NULL);
    free_caller_statistics(NULL);
    free_call_anomalies(NULL);
    parse_options_default(NULL);
    anomaly_config_default(NULL);
    call_analyzer_struct_sizes(NULL);

    /* Caller-built records with unterminated strings are rejected, not read past. */
    memset(&one, 'A', sizeof one);
    one.status_code = 200;
    CHECK_EQ_INT(calculate_statistics(&one, 1, &stats), CA_ERR_INVALID_ARG);
    CHECK_EQ_INT(calculate_cell_statistics(&one, 1, &cells, &count), CA_ERR_INVALID_ARG);
    CHECK(cells == NULL);
    CHECK_EQ_INT(detect_call_anomalies(&one, 1, NULL, &anomalies, &count), CA_ERR_INVALID_ARG);

    /* Invalid window size and anomaly configuration. */
    CHECK_EQ_INT(calculate_time_window_statistics(NULL, 0, 0, &windows, &count), CA_ERR_INVALID_ARG);
    CHECK_EQ_INT(calculate_time_window_statistics(NULL, 0, 86401, &windows, &count),
                 CA_ERR_INVALID_ARG);
    {
        AnomalyConfig cfg;
        anomaly_config_default(&cfg);
        cfg.z_threshold = 0.0;
        CHECK_EQ_INT(detect_call_anomalies(NULL, 0, &cfg, &anomalies, &count), CA_ERR_INVALID_ARG);
        anomaly_config_default(&cfg);
        cfg.min_short_call_ratio = 1.5;
        CHECK_EQ_INT(detect_call_anomalies(NULL, 0, &cfg, &anomalies, &count), CA_ERR_INVALID_ARG);
        anomaly_config_default(&cfg);
        cfg.z_threshold = NAN;
        CHECK_EQ_INT(detect_call_anomalies(NULL, 0, &cfg, &anomalies, &count), CA_ERR_INVALID_ARG);
    }
}

static void test_library_info(void)
{
    CaStructSizes sizes;
    CHECK_STR(call_analyzer_version(), "1.0.0");
    CHECK_STR(call_analyzer_strerror(CA_ERR_NOMEM), "out of memory");
    CHECK_STR(call_analyzer_strerror(-999), "unknown error");
    CHECK_EQ_INT(call_outcome_for_status(200), CALL_COMPLETED);
    CHECK_EQ_INT(call_outcome_for_status(299), CALL_COMPLETED);
    CHECK_EQ_INT(call_outcome_for_status(486), CALL_SETUP_FAILED);
    CHECK_EQ_INT(call_outcome_for_status(901), CALL_DROPPED);
    CHECK_EQ_INT(call_outcome_for_status(180), CALL_UNKNOWN);
    CHECK_EQ_INT(call_outcome_for_status(-1), CALL_UNKNOWN);
    CHECK_STR(call_outcome_name(CALL_DROPPED), "dropped");
    CHECK_STR(call_anomaly_type_name(CA_ANOMALY_CELL_DROP_RATE), "cell_drop_rate");
    CHECK_STR(call_anomaly_type_name(CA_ANOMALY_TYPE_COUNT), "invalid");
    CHECK_STR(call_severity_name(CA_SEVERITY_CRITICAL), "critical");
    call_analyzer_struct_sizes(&sizes);
    CHECK_EQ_INT(sizes.call_record, sizeof(CallRecord));
    CHECK_EQ_INT(sizes.call_anomaly, sizeof(CallAnomaly));
}

/* ---- Statistics tests ------------------------------------------------------ */

static void test_statistics_small(void)
{
    CallRecord *records = NULL;
    size_t count = 0;
    CallStatistics s;
    const double durations[] = {120, 60, 30, 240, 90, 3, 300};
    double mean = 0.0, m2 = 0.0;

    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, &count), CA_OK);
    CHECK_EQ_INT(calculate_statistics(records, count, &s), CA_OK);
    CHECK_EQ_INT(s.total_calls, 10);
    CHECK_EQ_INT(s.successful_calls, 5);
    CHECK_EQ_INT(s.dropped_calls, 2);
    CHECK_EQ_INT(s.failed_setup_calls, 2);
    CHECK_EQ_INT(s.unknown_calls, 1);
    CHECK_NEAR(s.success_rate, 0.5, 1e-12);
    CHECK_NEAR(s.drop_rate, 2.0 / 7.0, 1e-12);
    CHECK_NEAR(s.setup_failure_rate, 0.2, 1e-12);
    CHECK_NEAR(s.average_duration, 843.0 / 7.0, 1e-9);
    for (size_t i = 0; i < 7; i++) {
        mean += durations[i];
    }
    mean /= 7.0;
    for (size_t i = 0; i < 7; i++) {
        m2 += (durations[i] - mean) * (durations[i] - mean);
    }
    CHECK_NEAR(s.duration_stddev, sqrt(m2 / 7.0), 1e-9);
    CHECK_EQ_INT(s.min_duration, 3);
    CHECK_EQ_INT(s.max_duration, 300);
    CHECK_NEAR(s.average_signal, -88.1, 1e-9);
    CHECK_NEAR(s.average_packet_loss, 2.4, 1e-9);
    CHECK_EQ_INT(s.weak_signal_calls, 2);
    CHECK_EQ_INT(s.unique_cells, 3);
    CHECK_EQ_INT(s.unique_callers, 5);
    CHECK_EQ_INT(s.first_epoch, EPOCH_2026_03_01 + 14 * 3600);
    CHECK_EQ_INT(s.last_epoch, EPOCH_2026_03_01 + 14 * 3600 + 12 * 60);
    free_call_records(records);
}

static void test_statistics_empty(void)
{
    CallStatistics s;
    CHECK_EQ_INT(calculate_statistics(NULL, 0, &s), CA_OK);
    CHECK_EQ_INT(s.total_calls, 0);
    CHECK_NEAR(s.drop_rate, 0.0, 0.0);
    CHECK_NEAR(s.average_duration, 0.0, 0.0);
    CHECK_EQ_INT(s.first_epoch, 0);
}

static void test_cell_statistics(void)
{
    CallRecord *records = NULL;
    size_t count = 0, n = 0;
    CellStatistics *cells = NULL;

    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, &count), CA_OK);
    CHECK_EQ_INT(calculate_cell_statistics(records, count, &cells, &n), CA_OK);
    CHECK_EQ_INT(n, 3);
    if (n == 3) {
        CHECK_STR(cells[0].cell_id, "CELL-A");
        CHECK_EQ_INT(cells[0].total_calls, 4);
        CHECK_EQ_INT(cells[0].successful_calls, 3);
        CHECK_EQ_INT(cells[0].dropped_calls, 1);
        CHECK_NEAR(cells[0].drop_rate, 0.25, 1e-12);
        CHECK_NEAR(cells[0].average_duration, 127.5, 1e-9);
        CHECK_NEAR(cells[0].average_signal, -89.25, 1e-9);
        CHECK_EQ_INT(cells[0].weak_signal_calls, 1);
        CHECK_EQ_INT(cells[0].first_epoch, EPOCH_2026_03_01 + 14 * 3600);
        CHECK_EQ_INT(cells[0].last_epoch, EPOCH_2026_03_01 + 14 * 3600 + 11 * 60);

        CHECK_STR(cells[1].cell_id, "CELL-B");
        CHECK_EQ_INT(cells[1].total_calls, 3);
        CHECK_EQ_INT(cells[1].failed_setup_calls, 1);
        CHECK_NEAR(cells[1].drop_rate, 0.5, 1e-12);
        CHECK_NEAR(cells[1].setup_failure_rate, 1.0 / 3.0, 1e-12);
        CHECK_NEAR(cells[1].average_duration, 165.0, 1e-9);

        CHECK_STR(cells[2].cell_id, "CELL-C");
        CHECK_NEAR(cells[2].drop_rate, 0.0, 0.0);
        CHECK_NEAR(cells[2].average_duration, 3.0, 1e-9);
    }
    free_cell_statistics(cells);

    CHECK_EQ_INT(calculate_cell_statistics(records, 0, &cells, &n), CA_OK);
    CHECK(cells == NULL);
    CHECK_EQ_INT(n, 0);
    free_call_records(records);
}

static void test_failure_code_statistics(void)
{
    CallRecord *records = NULL;
    size_t count = 0, n = 0;
    FailureCodeStatistics *codes = NULL;
    const int expected_order[] = {200, 180, 486, 503, 901, 902};

    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, &count), CA_OK);
    CHECK_EQ_INT(calculate_failure_code_statistics(records, count, &codes, &n), CA_OK);
    CHECK_EQ_INT(n, 6);
    if (n == 6) {
        for (size_t i = 0; i < 6; i++) {
            CHECK_EQ_INT(codes[i].status_code, expected_order[i]);
        }
        CHECK_EQ_INT(codes[0].count, 5);
        CHECK_NEAR(codes[0].share, 0.5, 1e-12);
        CHECK_EQ_INT(codes[0].outcome, CALL_COMPLETED);
        CHECK_EQ_INT(codes[4].outcome, CALL_DROPPED);
        CHECK_EQ_INT(codes[2].outcome, CALL_SETUP_FAILED);
        CHECK_EQ_INT(codes[1].outcome, CALL_UNKNOWN);
    }
    free_failure_code_statistics(codes);

    /* Out-of-range codes in caller-built records are rejected. */
    records[0].status_code = 5000;
    CHECK_EQ_INT(calculate_failure_code_statistics(records, count, &codes, &n), CA_ERR_INVALID_ARG);
    CHECK(codes == NULL);
    free_call_records(records);
}

static void test_time_window_statistics(void)
{
    CallRecord *records = NULL;
    size_t count = 0, n = 0;
    TimeWindowStatistics *w = NULL;
    const long long base = EPOCH_2026_03_01 + 14 * 3600;

    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, &count), CA_OK);
    CHECK_EQ_INT(calculate_time_window_statistics(records, count, 300, &w, &n), CA_OK);
    CHECK_EQ_INT(n, 3);
    if (n == 3) {
        CHECK_EQ_INT(w[0].window_start, base);
        CHECK_EQ_INT(w[0].window_end, base + 300);
        CHECK_EQ_INT(w[0].total_calls, 5);
        CHECK_EQ_INT(w[0].dropped_calls, 1);
        CHECK_NEAR(w[0].drop_rate, 0.25, 1e-12);
        CHECK_EQ_INT(w[1].window_start, base + 300);
        CHECK_EQ_INT(w[1].total_calls, 3);
        CHECK_EQ_INT(w[2].window_start, base + 600);
        CHECK_EQ_INT(w[2].total_calls, 2);
    }
    free_time_window_statistics(w);

    /* One-hour windows collapse everything into one bucket. */
    CHECK_EQ_INT(calculate_time_window_statistics(records, count, 3600, &w, &n), CA_OK);
    CHECK_EQ_INT(n, 1);
    if (n == 1) {
        CHECK_EQ_INT(w[0].total_calls, 10);
    }
    free_time_window_statistics(w);
    free_call_records(records);
}

static void test_caller_statistics(void)
{
    CallRecord *records = NULL;
    size_t count = 0, n = 0;
    CallerStatistics *c = NULL;

    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, &count), CA_OK);
    CHECK_EQ_INT(calculate_caller_statistics(records, count, &c, &n), CA_OK);
    CHECK_EQ_INT(n, 5);
    if (n == 5) {
        CHECK_STR(c[0].caller, "+15550001");
        CHECK_EQ_INT(c[0].calls_made, 4);
        CHECK_EQ_INT(c[0].distinct_callees, 3);
        CHECK_EQ_INT(c[0].successful_calls, 2);
        CHECK_EQ_INT(c[0].dropped_calls, 1);
        CHECK_EQ_INT(c[0].total_duration, 270);
        CHECK_NEAR(c[0].average_duration, 90.0, 1e-9);
        CHECK_STR(c[4].caller, "+15550005");
        CHECK_EQ_INT(c[4].calls_made, 2);
        CHECK_EQ_INT(c[4].short_calls, 1);
        CHECK_EQ_INT(c[4].failed_setup_calls, 1);
    }
    free_caller_statistics(c);
    free_call_records(records);
}

/* ---- Anomaly tests --------------------------------------------------------- */

static void run_detection(const DatasetSpec *spec, CallAnomaly **anomalies, size_t *n,
                          CallRecord **records_out, size_t *count_out)
{
    TextBuf b = {NULL, 0, 0};
    CallRecord *records = NULL;
    size_t count = 0;

    build_dataset(&b, spec);
    CHECK_EQ_INT(parse_text(&b, &records, &count), CA_OK);
    CHECK_EQ_INT(detect_call_anomalies(records, count, NULL, anomalies, n), CA_OK);
    free(b.data);
    if (records_out != NULL) {
        *records_out = records;
        *count_out = count;
    } else {
        free_call_records(records);
    }
}

static void test_anomaly_clean_baseline(void)
{
    const DatasetSpec spec = {-1, -1, 0, 0, 0};
    CallAnomaly *a = NULL;
    size_t n = 0;

    run_detection(&spec, &a, &n, NULL, NULL);
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, "  unexpected anomaly: %s\n", a[i].description);
    }
    CHECK_EQ_INT(n, 0);
    free_call_anomalies(a);
}

static void test_anomaly_cell_drop_rate(void)
{
    const DatasetSpec spec = {7, -1, 0, 0, 0};
    CallAnomaly *a = NULL;
    size_t n = 0;

    run_detection(&spec, &a, &n, NULL, NULL);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_CELL_DROP_RATE, "CELL-107"), 1);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_CELL_DROP_RATE, NULL), 1);
    for (size_t i = 0; i < n; i++) {
        if (a[i].type == CA_ANOMALY_CELL_DROP_RATE) {
            CHECK(a[i].value > 0.2);
            CHECK(a[i].baseline < 0.05);
            CHECK(a[i].z_score >= 3.5);
            CHECK(a[i].score >= 0.5 && a[i].score <= 1.0);
            CHECK(a[i].severity >= CA_SEVERITY_HIGH);
            CHECK_EQ_INT(a[i].sample_size, 100);
            CHECK_EQ_INT(a[i].record_index, -1);
            CHECK(strstr(a[i].description, "CELL-107") != NULL);
        }
    }
    /* Sorted by descending score. */
    for (size_t i = 1; i < n; i++) {
        CHECK(a[i - 1].score >= a[i].score);
    }
    free_call_anomalies(a);
}

static void test_anomaly_cell_low_signal(void)
{
    const DatasetSpec spec = {-1, 3, 0, 0, 0};
    CallAnomaly *a = NULL;
    size_t n = 0;

    run_detection(&spec, &a, &n, NULL, NULL);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_CELL_LOW_SIGNAL, "CELL-103"), 1);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_CELL_LOW_SIGNAL, NULL), 1);
    free_call_anomalies(a);
}

static void test_anomaly_volume_spike(void)
{
    const DatasetSpec spec = {-1, -1, 1, 0, 0};
    CallAnomaly *a = NULL;
    size_t n = 0;

    run_detection(&spec, &a, &n, NULL, NULL);
    /* Burst lands in [10:25:00, 10:30:00). */
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_WINDOW_VOLUME_SPIKE, "2026-03-01T10:25:00Z"), 1);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_WINDOW_VOLUME_SPIKE, NULL), 1);
    free_call_anomalies(a);
}

static void test_anomaly_robocaller(void)
{
    const DatasetSpec spec = {-1, -1, 0, 1, 0};
    CallAnomaly *a = NULL;
    size_t n = 0;

    run_detection(&spec, &a, &n, NULL, NULL);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_CALLER_HIGH_VOLUME, "+19990000"), 1);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_CALLER_HIGH_VOLUME, NULL), 1);
    free_call_anomalies(a);
}

static void test_anomaly_long_call(void)
{
    const DatasetSpec spec = {-1, -1, 0, 0, 1};
    CallAnomaly *a = NULL;
    size_t n = 0, count = 0;
    CallRecord *records = NULL;

    run_detection(&spec, &a, &n, &records, &count);
    CHECK_EQ_INT(count_type(a, n, CA_ANOMALY_CALL_DURATION, NULL), 1);
    for (size_t i = 0; i < n; i++) {
        if (a[i].type == CA_ANOMALY_CALL_DURATION) {
            CHECK(a[i].record_index >= 0 && (size_t)a[i].record_index < count);
            if (a[i].record_index >= 0 && (size_t)a[i].record_index < count) {
                CHECK_EQ_INT(records[a[i].record_index].duration, 20000);
            }
        }
    }
    free_call_anomalies(a);
    free_call_records(records);
}

static void test_anomaly_small_inputs(void)
{
    CallRecord *records = NULL;
    size_t count = 0, n = 0;
    CallAnomaly *a = NULL;
    AnomalyConfig cfg;

    /* Too few calls per group for any baseline: no anomalies, no error. */
    CHECK_EQ_INT(parse_call_log(DATA("valid_small.csv"), &records, &count), CA_OK);
    CHECK_EQ_INT(detect_call_anomalies(records, count, NULL, &a, &n), CA_OK);
    CHECK_EQ_INT(n, 0);
    CHECK(a == NULL);
    CHECK_EQ_INT(detect_call_anomalies(records, 0, NULL, &a, &n), CA_OK);
    CHECK_EQ_INT(n, 0);
    free_call_records(records);

    /* max_anomalies keeps only the highest-scoring results. */
    {
        const DatasetSpec spec = {7, 3, 1, 1, 1};
        TextBuf b = {NULL, 0, 0};
        size_t all = 0;
        build_dataset(&b, &spec);
        CHECK_EQ_INT(parse_text(&b, &records, &count), CA_OK);
        CHECK_EQ_INT(detect_call_anomalies(records, count, NULL, &a, &all), CA_OK);
        CHECK(all >= 5);
        anomaly_config_default(&cfg);
        cfg.max_anomalies = 2;
        {
            CallAnomaly *top = NULL;
            CHECK_EQ_INT(detect_call_anomalies(records, count, &cfg, &top, &n), CA_OK);
            CHECK_EQ_INT(n, 2);
            if (n == 2 && all >= 2) {
                CHECK_NEAR(top[0].score, a[0].score, 0.0);
                CHECK_NEAR(top[1].score, a[1].score, 0.0);
            }
            free_call_anomalies(top);
        }
        free_call_anomalies(a);
        free_call_records(records);
        free(b.data);
    }
}

/* ---- Out-of-memory tests --------------------------------------------------- */

#ifdef CA_FAULT_INJECTION
typedef int (*Operation)(const CallRecord *, size_t, const TextBuf *, void **, size_t *);

static int op_parse(const CallRecord *r, size_t n, const TextBuf *t, void **out, size_t *cnt)
{
    (void)r;
    (void)n;
    return parse_call_log_buffer(t->data, t->len, NULL, (CallRecord **)out, cnt, NULL);
}

static int op_statistics(const CallRecord *r, size_t n, const TextBuf *t, void **out, size_t *cnt)
{
    CallStatistics s;
    (void)t;
    *out = NULL;
    *cnt = 0;
    return calculate_statistics(r, n, &s);
}

static int op_cells(const CallRecord *r, size_t n, const TextBuf *t, void **out, size_t *cnt)
{
    (void)t;
    return calculate_cell_statistics(r, n, (CellStatistics **)out, cnt);
}

static int op_codes(const CallRecord *r, size_t n, const TextBuf *t, void **out, size_t *cnt)
{
    (void)t;
    return calculate_failure_code_statistics(r, n, (FailureCodeStatistics **)out, cnt);
}

static int op_windows(const CallRecord *r, size_t n, const TextBuf *t, void **out, size_t *cnt)
{
    (void)t;
    return calculate_time_window_statistics(r, n, 300, (TimeWindowStatistics **)out, cnt);
}

static int op_callers(const CallRecord *r, size_t n, const TextBuf *t, void **out, size_t *cnt)
{
    (void)t;
    return calculate_caller_statistics(r, n, (CallerStatistics **)out, cnt);
}

static int op_anomalies(const CallRecord *r, size_t n, const TextBuf *t, void **out, size_t *cnt)
{
    (void)t;
    return detect_call_anomalies(r, n, NULL, (CallAnomaly **)out, cnt);
}

static void test_oom_all_operations(void)
{
    static const struct {
        const char *name;
        Operation op;
    } ops[] = {
        {"parse", op_parse},         {"statistics", op_statistics}, {"cells", op_cells},
        {"codes", op_codes},         {"windows", op_windows},       {"callers", op_callers},
        {"anomalies", op_anomalies},
    };
    const DatasetSpec spec = {7, 3, 1, 1, 1};
    TextBuf text = {NULL, 0, 0};
    CallRecord *records = NULL;
    size_t count = 0;

    build_dataset(&text, &spec);
    CHECK_EQ_INT(parse_text(&text, &records, &count), CA_OK);

    for (size_t o = 0; o < sizeof ops / sizeof ops[0]; o++) {
        long k;
        int completed = 0;
        for (k = 0; k < 100000; k++) {
            void *out = (void *)&out;
            size_t n = 99;
            int rc;
            ca_fault_inject_set(k);
            rc = ops[o].op(records, count, &text, &out, &n);
            const long triggered = ca_fault_inject_triggered();
            ca_fault_inject_set(-1);
            if (triggered == 0) {
                CHECK_EQ_INT(rc, CA_OK);
                free(out); /* every result array is a single allocation */
                completed = 1;
                break;
            }
            if (rc != CA_ERR_NOMEM || out != NULL || n != 0) {
                fprintf(stderr, "  %s: failure at allocation %ld returned %d\n", ops[o].name, k, rc);
            }
            CHECK_EQ_INT(rc, CA_ERR_NOMEM);
            CHECK(out == NULL);
            CHECK_EQ_INT(n, 0);
            if (out != NULL && out != (void *)&out) {
                free(out);
            }
        }
        CHECK(completed);
        fprintf(stderr, "  %s: %ld allocation failure points verified\n", ops[o].name, k);
    }
    free_call_records(records);
    free(text.data);
}
#endif

/* ---- Runner ---------------------------------------------------------------- */

typedef struct {
    const char *name;
    void (*fn)(void);
} TestCase;

int main(void)
{
    static const TestCase tests[] = {
        {"parser_valid_file", test_parser_valid_file},
        {"parser_simple_api", test_parser_simple_api},
        {"parser_no_header_crlf_bom", test_parser_no_header_crlf_bom},
        {"parser_quoted_fields", test_parser_quoted_fields},
        {"parser_empty_inputs", test_parser_empty_inputs},
        {"parser_missing_file", test_parser_missing_file},
        {"parser_timestamps", test_parser_timestamps},
        {"parser_record_limit", test_parser_record_limit},
        {"malformed_rows", test_malformed_rows},
        {"malformed_mixed_file", test_malformed_mixed_file},
        {"malformed_header", test_malformed_header},
        {"malformed_long_line_and_nul", test_malformed_long_line_and_nul},
        {"null_arguments", test_null_arguments},
        {"library_info", test_library_info},
        {"statistics_small", test_statistics_small},
        {"statistics_empty", test_statistics_empty},
        {"cell_statistics", test_cell_statistics},
        {"failure_code_statistics", test_failure_code_statistics},
        {"time_window_statistics", test_time_window_statistics},
        {"caller_statistics", test_caller_statistics},
        {"anomaly_clean_baseline", test_anomaly_clean_baseline},
        {"anomaly_cell_drop_rate", test_anomaly_cell_drop_rate},
        {"anomaly_cell_low_signal", test_anomaly_cell_low_signal},
        {"anomaly_volume_spike", test_anomaly_volume_spike},
        {"anomaly_robocaller", test_anomaly_robocaller},
        {"anomaly_long_call", test_anomaly_long_call},
        {"anomaly_small_inputs", test_anomaly_small_inputs},
#ifdef CA_FAULT_INJECTION
        {"oom_all_operations", test_oom_all_operations},
#endif
    };
    int failed_tests = 0;

    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        const int before = g_failures;
        tests[i].fn();
        const int ok = g_failures == before;
        failed_tests += !ok;
        printf("[%s] %s\n", ok ? " OK " : "FAIL", tests[i].name);
    }
    printf("\n%zu tests, %d failed, %d checks, %d check failures\n",
           sizeof tests / sizeof tests[0], failed_tests, g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
