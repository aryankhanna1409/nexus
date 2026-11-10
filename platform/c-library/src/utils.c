/*
 * utils.c - error strings, allocation wrappers, checked arithmetic, field
 * parsing/validation and robust-statistics helpers.
 */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ca_internal.h"

#define CA_STR2(x) #x
#define CA_STR(x) CA_STR2(x)

const char *call_analyzer_version(void)
{
    return CA_STR(CA_VERSION_MAJOR) "." CA_STR(CA_VERSION_MINOR) "." CA_STR(CA_VERSION_PATCH);
}

const char *call_analyzer_strerror(int status)
{
    switch (status) {
    case CA_OK: return "success";
    case CA_ERR_NULL_ARG: return "required argument is NULL";
    case CA_ERR_INVALID_ARG: return "argument or field value out of range";
    case CA_ERR_IO: return "I/O error";
    case CA_ERR_NOMEM: return "out of memory";
    case CA_ERR_PARSE: return "malformed input";
    case CA_ERR_OVERFLOW: return "value or size overflow";
    case CA_ERR_LIMIT: return "configured limit exceeded";
    default: return "unknown error";
    }
}

void call_analyzer_struct_sizes(CaStructSizes *sizes)
{
    if (sizes == NULL) {
        return;
    }
    sizes->call_record = sizeof(CallRecord);
    sizes->call_statistics = sizeof(CallStatistics);
    sizes->cell_statistics = sizeof(CellStatistics);
    sizes->failure_code_statistics = sizeof(FailureCodeStatistics);
    sizes->time_window_statistics = sizeof(TimeWindowStatistics);
    sizes->caller_statistics = sizeof(CallerStatistics);
    sizes->call_anomaly = sizeof(CallAnomaly);
    sizes->anomaly_config = sizeof(AnomalyConfig);
    sizes->parse_options = sizeof(ParseOptions);
    sizes->parse_report = sizeof(ParseReport);
}

CallOutcome call_outcome_for_status(int status_code)
{
    if (status_code >= 200 && status_code <= 299) {
        return CALL_COMPLETED;
    }
    if (status_code >= 900 && status_code <= 999) {
        return CALL_DROPPED;
    }
    if (status_code >= 300 && status_code <= 899) {
        return CALL_SETUP_FAILED;
    }
    return CALL_UNKNOWN;
}

const char *call_outcome_name(CallOutcome outcome)
{
    switch (outcome) {
    case CALL_COMPLETED: return "completed";
    case CALL_SETUP_FAILED: return "setup_failed";
    case CALL_DROPPED: return "dropped";
    case CALL_UNKNOWN: return "unknown";
    default: return "invalid";
    }
}

const char *call_anomaly_type_name(CallAnomalyType type)
{
    switch (type) {
    case CA_ANOMALY_CELL_DROP_RATE: return "cell_drop_rate";
    case CA_ANOMALY_CELL_SETUP_FAILURE_RATE: return "cell_setup_failure_rate";
    case CA_ANOMALY_CELL_LOW_SIGNAL: return "cell_low_signal";
    case CA_ANOMALY_CELL_PACKET_LOSS: return "cell_packet_loss";
    case CA_ANOMALY_WINDOW_DROP_RATE: return "window_drop_rate";
    case CA_ANOMALY_WINDOW_VOLUME_SPIKE: return "window_volume_spike";
    case CA_ANOMALY_CALLER_HIGH_VOLUME: return "caller_high_volume";
    case CA_ANOMALY_CALL_DURATION: return "call_duration";
    case CA_ANOMALY_TYPE_COUNT:
    default: return "invalid";
    }
}

const char *call_severity_name(CallSeverity severity)
{
    switch (severity) {
    case CA_SEVERITY_LOW: return "low";
    case CA_SEVERITY_MEDIUM: return "medium";
    case CA_SEVERITY_HIGH: return "high";
    case CA_SEVERITY_CRITICAL: return "critical";
    default: return "invalid";
    }
}

/* ---- Allocation ------------------------------------------------------------ */

#ifdef CA_FAULT_INJECTION
/* Test-only global state; never compiled into the production library. */
static long g_fault_remaining = -1;
static long g_fault_triggered = 0;

void ca_fault_inject_set(long remaining)
{
    g_fault_remaining = remaining;
    g_fault_triggered = 0;
}

long ca_fault_inject_triggered(void)
{
    return g_fault_triggered;
}

static int ca_fault_should_fail(void)
{
    if (g_fault_remaining < 0) {
        return 0;
    }
    if (g_fault_remaining == 0) {
        g_fault_triggered++;
        return 1;
    }
    g_fault_remaining--;
    return 0;
}
#else
static int ca_fault_should_fail(void)
{
    return 0;
}
#endif

void *ca_malloc(size_t size)
{
    if (size == 0 || ca_fault_should_fail()) {
        return NULL;
    }
    return malloc(size);
}

void *ca_calloc(size_t nmemb, size_t size)
{
    size_t total;
    if (ca_mul_size(nmemb, size, &total) != CA_OK || total == 0 || ca_fault_should_fail()) {
        return NULL;
    }
    return calloc(nmemb, size);
}

void *ca_realloc_array(void *ptr, size_t nmemb, size_t size)
{
    size_t total;
    if (ca_mul_size(nmemb, size, &total) != CA_OK || total == 0 || ca_fault_should_fail()) {
        return NULL;
    }
    return realloc(ptr, total);
}

void ca_free(void *ptr)
{
    free(ptr);
}

/* ---- Checked arithmetic ---------------------------------------------------- */

int ca_mul_size(size_t a, size_t b, size_t *out)
{
    if (a != 0 && b > SIZE_MAX / a) {
        return CA_ERR_OVERFLOW;
    }
    *out = a * b;
    return CA_OK;
}

int ca_add_i64(int64_t a, int64_t b, int64_t *out)
{
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b)) {
        return CA_ERR_OVERFLOW;
    }
    *out = a + b;
    return CA_OK;
}

/* ---- Dates ----------------------------------------------------------------- */

/* Howard Hinnant's days_from_civil / civil_from_days (proleptic Gregorian). */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d)
{
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = (unsigned)(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = (int64_t)yoe + era * 400 + (*m <= 2);
}

static int is_leap(int64_t y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static unsigned days_in_month(int64_t y, unsigned m)
{
    static const unsigned days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return (m == 2 && is_leap(y)) ? 29u : days[m - 1];
}

/* Reads exactly `n` decimal digits. */
static int read_digits(const char *text, size_t n, unsigned *out)
{
    unsigned value = 0;
    for (size_t i = 0; i < n; i++) {
        if (text[i] < '0' || text[i] > '9') {
            return 0;
        }
        value = value * 10u + (unsigned)(text[i] - '0');
    }
    *out = value;
    return 1;
}

int ca_parse_timestamp(const char *text, int64_t *epoch)
{
    unsigned year, month, day, hour, minute, second;
    size_t len;

    if (text == NULL || epoch == NULL) {
        return CA_ERR_NULL_ARG;
    }
    len = strlen(text);
    if (len != 19 && !(len == 20 && text[19] == 'Z')) {
        return CA_ERR_PARSE;
    }
    if (text[4] != '-' || text[7] != '-' || (text[10] != 'T' && text[10] != ' ') ||
        text[13] != ':' || text[16] != ':') {
        return CA_ERR_PARSE;
    }
    if (!read_digits(text, 4, &year) || !read_digits(text + 5, 2, &month) ||
        !read_digits(text + 8, 2, &day) || !read_digits(text + 11, 2, &hour) ||
        !read_digits(text + 14, 2, &minute) || !read_digits(text + 17, 2, &second)) {
        return CA_ERR_PARSE;
    }
    if (year < 1970 || month < 1 || month > 12 || day < 1 ||
        day > days_in_month((int64_t)year, month) || hour > 23 || minute > 59 || second > 59) {
        return CA_ERR_INVALID_ARG;
    }
    *epoch = days_from_civil((int64_t)year, month, day) * 86400 +
             (int64_t)hour * 3600 + (int64_t)minute * 60 + (int64_t)second;
    return CA_OK;
}

void ca_format_epoch(int64_t epoch, char *buf, size_t buf_size)
{
    int64_t days = epoch / 86400;
    int64_t secs = epoch % 86400;
    int64_t y;
    unsigned m, d;

    if (secs < 0) {
        secs += 86400;
        days -= 1;
    }
    civil_from_days(days, &y, &m, &d);
    snprintf(buf, buf_size, "%04" PRId64 "-%02u-%02uT%02u:%02u:%02uZ", y, m, d,
             (unsigned)(secs / 3600), (unsigned)((secs % 3600) / 60), (unsigned)(secs % 60));
}

/* ---- Field validation ------------------------------------------------------ */

int ca_parse_int(const char *text, long min, long max, int *out)
{
    char *end = NULL;
    long value;

    if (text == NULL || out == NULL) {
        return CA_ERR_NULL_ARG;
    }
    if (text[0] == '\0') {
        return CA_ERR_PARSE;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (end == text || *end != '\0') {
        return CA_ERR_PARSE;
    }
    if (errno == ERANGE || value < INT_MIN || value > INT_MAX) {
        return CA_ERR_OVERFLOW;
    }
    if (value < min || value > max) {
        return CA_ERR_INVALID_ARG;
    }
    *out = (int)value;
    return CA_OK;
}

static int valid_chars(const char *text, const char *extra)
{
    size_t len;

    if (text == NULL) {
        return 0;
    }
    len = strlen(text);
    if (len == 0 || len >= CA_FIELD_LEN) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        const char c = text[i];
        const int alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!alnum && strchr(extra, c) == NULL) {
            return 0;
        }
    }
    return 1;
}

int ca_valid_party(const char *text)
{
    return valid_chars(text, "+*#._-");
}

int ca_valid_cell_id(const char *text)
{
    return valid_chars(text, "._-");
}

int ca_copy_string(char *dst, size_t dst_size, const char *src)
{
    const size_t len = strlen(src);
    if (len >= dst_size) {
        return CA_ERR_OVERFLOW;
    }
    memcpy(dst, src, len + 1);
    return CA_OK;
}

/* ---- Robust statistics ----------------------------------------------------- */

static int compare_double(const void *a, const void *b)
{
    const double x = *(const double *)a;
    const double y = *(const double *)b;
    return (x > y) - (x < y);
}

double ca_median_inplace(double *values, size_t n)
{
    qsort(values, n, sizeof *values, compare_double);
    if (n % 2 == 1) {
        return values[n / 2];
    }
    return (values[n / 2 - 1] + values[n / 2]) / 2.0;
}

double ca_mad(const double *values, size_t n, double median, double *scratch)
{
    for (size_t i = 0; i < n; i++) {
        scratch[i] = fabs(values[i] - median);
    }
    return ca_median_inplace(scratch, n);
}

double ca_robust_z(double x, double median, double mad, double floor)
{
    double scale = 1.4826 * mad;
    if (scale < floor) {
        scale = floor;
    }
    return (x - median) / scale;
}

double ca_anomaly_score(double z, double threshold)
{
    if (z <= 0.0 || threshold <= 0.0) {
        return 0.0;
    }
    return 1.0 - pow(2.0, -z / threshold);
}

CallSeverity ca_severity_for_score(double score)
{
    if (score >= 0.9) {
        return CA_SEVERITY_CRITICAL;
    }
    if (score >= 0.75) {
        return CA_SEVERITY_HIGH;
    }
    if (score >= 0.6) {
        return CA_SEVERITY_MEDIUM;
    }
    return CA_SEVERITY_LOW;
}

double ca_safe_ratio(size_t numerator, size_t denominator)
{
    return denominator == 0 ? 0.0 : (double)numerator / (double)denominator;
}

/* ---- Accumulator ----------------------------------------------------------- */

void ca_accumulator_init(CaAccumulator *acc)
{
    memset(acc, 0, sizeof *acc);
    acc->first_epoch = INT64_MAX;
    acc->last_epoch = INT64_MIN;
}

int ca_accumulator_add(CaAccumulator *acc, const CallRecord *record)
{
    const CallOutcome outcome = call_outcome_for_status(record->status_code);
    int64_t signal_sum, loss_sum;

    if (ca_add_i64(acc->signal_sum, record->signal_strength, &signal_sum) != CA_OK ||
        ca_add_i64(acc->packet_loss_sum, record->packet_loss, &loss_sum) != CA_OK) {
        return CA_ERR_OVERFLOW;
    }
    if (outcome == CALL_COMPLETED || outcome == CALL_DROPPED) {
        const uint64_t duration = (uint64_t)(record->duration < 0 ? 0 : record->duration);
        if (acc->duration_sum > UINT64_MAX - duration) {
            return CA_ERR_OVERFLOW;
        }
        acc->duration_sum += duration;
    }

    acc->signal_sum = signal_sum;
    acc->packet_loss_sum = loss_sum;
    acc->total++;
    switch (outcome) {
    case CALL_COMPLETED: acc->completed++; break;
    case CALL_SETUP_FAILED: acc->setup_failed++; break;
    case CALL_DROPPED: acc->dropped++; break;
    case CALL_UNKNOWN:
    default: acc->unknown++; break;
    }
    if (record->signal_strength <= CA_WEAK_SIGNAL_DBM) {
        acc->weak_signal++;
    }
    if (outcome == CALL_COMPLETED || outcome == CALL_DROPPED) {
        const size_t n = acc->completed + acc->dropped;
        const double x = (double)record->duration;
        const double delta = x - acc->duration_mean;
        acc->duration_mean += delta / (double)n;
        acc->duration_m2 += delta * (x - acc->duration_mean);
        if (n == 1 || record->duration < acc->min_duration) {
            acc->min_duration = record->duration;
        }
        if (n == 1 || record->duration > acc->max_duration) {
            acc->max_duration = record->duration;
        }
        if (record->duration < CA_SHORT_CALL_SECONDS) {
            acc->short_calls++;
        }
    }
    if (record->epoch_seconds < acc->first_epoch) {
        acc->first_epoch = record->epoch_seconds;
    }
    if (record->epoch_seconds > acc->last_epoch) {
        acc->last_epoch = record->epoch_seconds;
    }
    return CA_OK;
}

size_t ca_accumulator_established(const CaAccumulator *acc)
{
    return acc->completed + acc->dropped;
}

double ca_accumulator_drop_rate(const CaAccumulator *acc)
{
    return ca_safe_ratio(acc->dropped, ca_accumulator_established(acc));
}

double ca_accumulator_avg_duration(const CaAccumulator *acc)
{
    const size_t n = ca_accumulator_established(acc);
    return n == 0 ? 0.0 : (double)acc->duration_sum / (double)n;
}

double ca_accumulator_avg_signal(const CaAccumulator *acc)
{
    return acc->total == 0 ? 0.0 : (double)acc->signal_sum / (double)acc->total;
}

double ca_accumulator_avg_packet_loss(const CaAccumulator *acc)
{
    return acc->total == 0 ? 0.0 : (double)acc->packet_loss_sum / (double)acc->total;
}

int ca_check_records(const CallRecord *records, size_t count)
{
    if (records == NULL && count > 0) {
        return CA_ERR_NULL_ARG;
    }
    /* Records may be built by callers (e.g. via FFI), so string fields are
     * checked for termination before any strcmp/strlen touches them. */
    for (size_t i = 0; i < count; i++) {
        const CallRecord *r = &records[i];
        if (memchr(r->timestamp, '\0', sizeof r->timestamp) == NULL ||
            memchr(r->caller, '\0', sizeof r->caller) == NULL ||
            memchr(r->callee, '\0', sizeof r->callee) == NULL ||
            memchr(r->cell_id, '\0', sizeof r->cell_id) == NULL) {
            return CA_ERR_INVALID_ARG;
        }
    }
    return CA_OK;
}
