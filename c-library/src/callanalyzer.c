/*
 * callanalyzer.c - parsing, statistics and anomaly detection for call logs.
 *
 * Reading guide:
 *   1. parsing    - ca_parse_buffer() validates each CSV row strictly
 *   2. statistics - accumulate() + finish() turn records into rates
 *   3. anomalies  - ca_detect_anomalies() compares each cell with its peers
 */
#include "callanalyzer.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIELD_COUNT 8

const char *ca_version(void) { return CA_VERSION; }

const char *ca_strerror(int status)
{
    switch (status) {
    case CA_OK: return "ok";
    case CA_ERR_NULL_ARG: return "a required argument was NULL";
    case CA_ERR_IO: return "could not read the file";
    case CA_ERR_NOMEM: return "out of memory";
    case CA_ERR_PARSE: return "invalid input";
    default: return "unknown error";
    }
}

const char *ca_severity_name(CaSeverity severity)
{
    static const char *names[] = {"low", "medium", "high", "critical"};
    return (severity >= CA_SEV_LOW && severity <= CA_SEV_CRITICAL) ? names[severity] : "unknown";
}

CaOutcome ca_outcome(int status_code)
{
    if (status_code >= 200 && status_code <= 299) return CA_CALL_COMPLETED;
    if (status_code >= 900 && status_code <= 999) return CA_CALL_DROPPED;
    if (status_code >= 300 && status_code <= 899) return CA_CALL_SETUP_FAILED;
    return CA_CALL_UNKNOWN;
}

void ca_free(void *ptr) { free(ptr); }

/* ------------------------------------------------------------------ */
/* 1. Parsing                                                          */
/* ------------------------------------------------------------------ */

static int parse_int(const char *s, long lo, long hi, int *out)
{
    char *end = NULL;
    long v;
    if (*s == '\0' || isspace((unsigned char)*s)) return 0;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < lo || v > hi) return 0;
    *out = (int)v;
    return 1;
}

static int valid_id(const char *s, const char *extra)
{
    size_t n = strlen(s);
    if (n == 0 || n >= CA_ID_LEN) return 0;
    for (; *s; s++) {
        if (!isalnum((unsigned char)*s) && strchr(extra, *s) == NULL) return 0;
    }
    return 1;
}

static int digits(const char *s, int n, int *out)
{
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (!isdigit((unsigned char)s[i])) return 0;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return 1;
}

/* Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant). */
static int64_t days_from_civil(int y, int m, int d)
{
    int64_t yy = (int64_t)y - (m <= 2);
    int64_t era = (yy >= 0 ? yy : yy - 399) / 400;
    int64_t yoe = yy - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* Accepts "YYYY-MM-DDTHH:MM:SS" with an optional trailing "Z". */
static int parse_timestamp(const char *s, int64_t *epoch)
{
    static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int y, mo, d, h, mi, se, dim;
    size_t n = strlen(s);
    if (n != 19 && !(n == 20 && s[19] == 'Z')) return 0;
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':') return 0;
    if (!digits(s, 4, &y) || !digits(s + 5, 2, &mo) || !digits(s + 8, 2, &d) ||
        !digits(s + 11, 2, &h) || !digits(s + 14, 2, &mi) || !digits(s + 17, 2, &se))
        return 0;
    if (y < 1970 || mo < 1 || mo > 12 || h > 23 || mi > 59 || se > 59) return 0;
    dim = mdays[mo - 1];
    if (mo == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) dim = 29;
    if (d < 1 || d > dim) return 0;
    *epoch = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    return 1;
}

/* Parses one NUL-terminated line in place. Returns NULL or an error text. */
static const char *parse_line(char *line, CaRecord *rec)
{
    char *field[FIELD_COUNT];
    int n = 0;
    char *p = line;

    field[n++] = p;
    for (; *p; p++) {
        if (*p == ',') {
            if (n == FIELD_COUNT) return "too many columns";
            *p = '\0';
            field[n++] = p + 1;
        }
    }
    if (n != FIELD_COUNT) return "expected 8 columns";

    memset(rec, 0, sizeof(*rec));
    if (!parse_timestamp(field[0], &rec->epoch)) return "bad timestamp";
    if (!valid_id(field[1], "+*#._-")) return "bad caller";
    if (!valid_id(field[2], "+*#._-")) return "bad callee";
    if (!valid_id(field[3], "._-")) return "bad cell_id";
    memcpy(rec->cell_id, field[3], strlen(field[3]) + 1);
    if (!parse_int(field[4], 0, 86400, &rec->duration)) return "bad duration";
    if (!parse_int(field[5], 100, 999, &rec->status_code)) return "bad status_code";
    if (!parse_int(field[6], -150, 0, &rec->signal_dbm)) return "bad signal_strength";
    if (!parse_int(field[7], 0, 100, &rec->packet_loss)) return "bad packet_loss";
    return NULL;
}

static int push(CaRecord **arr, size_t *len, size_t *cap, const CaRecord *rec)
{
    if (*len == *cap) {
        size_t ncap = *cap ? *cap * 2 : 1024;
        CaRecord *grown;
        if (ncap > SIZE_MAX / sizeof(CaRecord)) return 0;
        grown = realloc(*arr, ncap * sizeof(CaRecord));
        if (!grown) return 0;
        *arr = grown;
        *cap = ncap;
    }
    (*arr)[(*len)++] = *rec;
    return 1;
}

int ca_parse_buffer(const char *data, size_t len, CaRecord **records,
                    size_t *count, CaParseReport *report)
{
    CaParseReport local;
    CaRecord *arr = NULL;
    size_t n = 0, cap = 0, pos = 0;
    int seen_content = 0;

    if (!records || !count || (!data && len > 0)) return CA_ERR_NULL_ARG;
    *records = NULL;
    *count = 0;
    if (!report) report = &local;
    memset(report, 0, sizeof(*report));

    while (pos < len) {
        const char *start = data + pos;
        const char *nl = memchr(start, '\n', len - pos);
        size_t linelen = nl ? (size_t)(nl - start) : len - pos;
        char line[CA_MAX_LINE];
        const char *err = NULL;
        CaRecord rec;

        pos += linelen + (nl ? 1 : 0);
        report->lines++;
        if (linelen > 0 && start[linelen - 1] == '\r') linelen--;
        if (linelen == 0) continue;

        if (linelen >= CA_MAX_LINE) {
            err = "line too long";
        } else {
            memcpy(line, start, linelen);
            line[linelen] = '\0';
            if (memchr(line, '\0', linelen) != NULL) {
                err = "NUL byte in line";
            } else if (!seen_content && strncmp(line, "timestamp,", 10) == 0) {
                seen_content = 1;
                continue; /* header */
            } else {
                err = parse_line(line, &rec);
            }
        }
        seen_content = 1;

        if (err) {
            report->rejected++;
            if (!report->first_error_line) {
                report->first_error_line = report->lines;
                snprintf(report->first_error, sizeof(report->first_error), "%s", err);
            }
            continue;
        }
        if (!push(&arr, &n, &cap, &rec)) {
            free(arr);
            return CA_ERR_NOMEM;
        }
        report->parsed++;
    }

    *records = arr;
    *count = n;
    return CA_OK;
}

int ca_parse_file(const char *path, CaRecord **records, size_t *count,
                  CaParseReport *report)
{
    FILE *f;
    char *buf = NULL;
    size_t len = 0, cap = 0;
    int rc;

    if (!path || !records || !count) return CA_ERR_NULL_ARG;
    *records = NULL;
    *count = 0;
    f = fopen(path, "rb");
    if (!f) return CA_ERR_IO;

    for (;;) {
        size_t got;
        if (cap - len < 65536) {
            size_t ncap = cap ? cap * 2 : 1 << 20;
            char *grown = realloc(buf, ncap);
            if (!grown) {
                free(buf);
                fclose(f);
                return CA_ERR_NOMEM;
            }
            buf = grown;
            cap = ncap;
        }
        got = fread(buf + len, 1, cap - len, f);
        len += got;
        if (got == 0) break;
    }
    rc = ferror(f) ? CA_ERR_IO : CA_OK;
    fclose(f);
    if (rc == CA_OK) rc = ca_parse_buffer(buf, len, records, count, report);
    free(buf);
    return rc;
}

/* ------------------------------------------------------------------ */
/* 2. Statistics                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    CaStats s;
    double sum_duration, sum_signal, sum_loss;
} Acc;

static void accumulate(Acc *a, const CaRecord *r)
{
    CaStats *s = &a->s;
    if (s->total == 0 || r->epoch < s->first_epoch) s->first_epoch = r->epoch;
    if (s->total == 0 || r->epoch > s->last_epoch) s->last_epoch = r->epoch;
    s->total++;
    switch (ca_outcome(r->status_code)) {
    case CA_CALL_COMPLETED: s->completed++; a->sum_duration += r->duration; break;
    case CA_CALL_DROPPED: s->dropped++; a->sum_duration += r->duration; break;
    case CA_CALL_SETUP_FAILED: s->setup_failed++; break;
    default: s->unknown++; break;
    }
    a->sum_signal += r->signal_dbm;
    a->sum_loss += r->packet_loss;
}

static double ratio(double num, double den) { return den > 0 ? num / den : 0.0; }

static void finish(Acc *a)
{
    CaStats *s = &a->s;
    size_t established = s->completed + s->dropped;
    s->success_rate = ratio((double)s->completed, (double)s->total);
    s->drop_rate = ratio((double)s->dropped, (double)established);
    s->setup_failure_rate = ratio((double)s->setup_failed, (double)s->total);
    s->avg_duration = ratio(a->sum_duration, (double)established);
    s->avg_signal_dbm = ratio(a->sum_signal, (double)s->total);
    s->avg_packet_loss = ratio(a->sum_loss, (double)s->total);
}

static int by_cell(const void *x, const void *y)
{
    const CaRecord *a = *(const CaRecord *const *)x;
    const CaRecord *b = *(const CaRecord *const *)y;
    return strcmp(a->cell_id, b->cell_id);
}

/* Pointers to records sorted by cell id, so equal cells sit together. */
static const CaRecord **sorted_by_cell(const CaRecord *records, size_t count)
{
    const CaRecord **idx;
    if (count > SIZE_MAX / sizeof(*idx)) return NULL;
    idx = malloc(count * sizeof(*idx));
    if (!idx) return NULL;
    for (size_t i = 0; i < count; i++) idx[i] = &records[i];
    qsort(idx, count, sizeof(*idx), by_cell);
    return idx;
}

int ca_stats(const CaRecord *records, size_t count, CaStats *out)
{
    Acc a;
    const CaRecord **idx;

    if (!out || (!records && count > 0)) return CA_ERR_NULL_ARG;
    memset(&a, 0, sizeof(a));
    if (count == 0) {
        *out = a.s;
        return CA_OK;
    }
    idx = sorted_by_cell(records, count);
    if (!idx) return CA_ERR_NOMEM;
    for (size_t i = 0; i < count; i++) {
        accumulate(&a, idx[i]);
        if (i == 0 || strcmp(idx[i]->cell_id, idx[i - 1]->cell_id) != 0) a.s.unique_cells++;
    }
    free(idx);
    finish(&a);
    *out = a.s;
    return CA_OK;
}

int ca_cell_stats(const CaRecord *records, size_t count,
                  CaCellStats **cells, size_t *cell_count)
{
    const CaRecord **idx;
    CaCellStats *out;
    size_t n = 0;

    if (!cells || !cell_count || (!records && count > 0)) return CA_ERR_NULL_ARG;
    *cells = NULL;
    *cell_count = 0;
    if (count == 0) return CA_OK;

    idx = sorted_by_cell(records, count);
    if (!idx) return CA_ERR_NOMEM;
    out = calloc(count, sizeof(*out)); /* upper bound: one cell per record */
    if (!out) {
        free(idx);
        return CA_ERR_NOMEM;
    }

    for (size_t i = 0; i < count;) {
        Acc a;
        size_t j = i;
        memset(&a, 0, sizeof(a));
        while (j < count && strcmp(idx[j]->cell_id, idx[i]->cell_id) == 0) accumulate(&a, idx[j++]);
        finish(&a);
        a.s.unique_cells = 1;
        memcpy(out[n].cell_id, idx[i]->cell_id, CA_ID_LEN);
        out[n++].stats = a.s;
        i = j;
    }
    free(idx);

    {
        CaCellStats *shrunk = realloc(out, n * sizeof(*out));
        *cells = shrunk ? shrunk : out; /* if shrinking fails the larger block is still valid */
    }
    *cell_count = n;
    return CA_OK;
}

/* ------------------------------------------------------------------ */
/* 3. Anomaly detection                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    double direction;   /* +1: higher is worse, -1: lower is worse */
    double spread_floor; /* smallest spread we trust, avoids dividing by ~0 */
    double min_delta;    /* smallest difference from the median that matters */
} Metric;

static const Metric METRICS[] = {
    {"drop_rate", +1.0, 0.005, 0.02},
    {"setup_failure_rate", +1.0, 0.005, 0.02},
    {"avg_signal_dbm", -1.0, 1.0, 5.0},
    {"avg_packet_loss", +1.0, 0.25, 1.0},
};
#define METRIC_COUNT (sizeof(METRICS) / sizeof(METRICS[0]))

static double metric_value(const CaStats *s, size_t m)
{
    switch (m) {
    case 0: return s->drop_rate;
    case 1: return s->setup_failure_rate;
    case 2: return s->avg_signal_dbm;
    default: return s->avg_packet_loss;
    }
}

static int cmp_double(const void *x, const void *y)
{
    double a = *(const double *)x, b = *(const double *)y;
    return (a > b) - (a < b);
}

/* Sorts v in place. */
static double median(double *v, size_t n)
{
    qsort(v, n, sizeof(*v), cmp_double);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

static int by_z_desc(const void *x, const void *y)
{
    const CaAnomaly *a = x, *b = y;
    if (a->z_score != b->z_score) return a->z_score < b->z_score ? 1 : -1;
    return strcmp(a->cell_id, b->cell_id);
}

int ca_detect_anomalies(const CaCellStats *cells, size_t cell_count,
                        double z_threshold, size_t min_calls,
                        CaAnomaly **anomalies, size_t *anomaly_count)
{
    double *vals = NULL, *dev = NULL;
    const CaCellStats **eligible = NULL;
    CaAnomaly *out = NULL;
    size_t n = 0, k = 0;
    int rc = CA_OK;

    if (!anomalies || !anomaly_count || (!cells && cell_count > 0)) return CA_ERR_NULL_ARG;
    *anomalies = NULL;
    *anomaly_count = 0;
    if (!(z_threshold > 0)) return CA_ERR_PARSE;

    eligible = malloc((cell_count ? cell_count : 1) * sizeof(*eligible));
    vals = malloc((cell_count ? cell_count : 1) * sizeof(*vals));
    dev = malloc((cell_count ? cell_count : 1) * sizeof(*dev));
    out = malloc((cell_count ? cell_count : 1) * METRIC_COUNT * sizeof(*out));
    if (!eligible || !vals || !dev || !out) {
        rc = CA_ERR_NOMEM;
        goto done;
    }

    for (size_t i = 0; i < cell_count; i++)
        if (cells[i].stats.total >= min_calls) eligible[k++] = &cells[i];
    if (k < 5) goto done; /* too few peers for a meaningful baseline */

    for (size_t m = 0; m < METRIC_COUNT; m++) {
        double med, mad, spread;
        for (size_t i = 0; i < k; i++) vals[i] = metric_value(&eligible[i]->stats, m);
        med = median(vals, k);
        for (size_t i = 0; i < k; i++) dev[i] = fabs(metric_value(&eligible[i]->stats, m) - med);
        mad = median(dev, k);
        spread = fmax(1.4826 * mad, METRICS[m].spread_floor);

        for (size_t i = 0; i < k; i++) {
            double x = metric_value(&eligible[i]->stats, m);
            double worse_by = METRICS[m].direction * (x - med);
            double z = worse_by / spread;
            CaAnomaly *a;
            if (z < z_threshold || worse_by < METRICS[m].min_delta) continue;
            a = &out[n++];
            memset(a, 0, sizeof(*a));
            memcpy(a->cell_id, eligible[i]->cell_id, CA_ID_LEN);
            snprintf(a->metric, sizeof(a->metric), "%s", METRICS[m].name);
            a->value = x;
            a->baseline = med;
            a->z_score = z;
            a->severity = z >= 4 * z_threshold ? CA_SEV_CRITICAL
                        : z >= 2 * z_threshold ? CA_SEV_HIGH : CA_SEV_MEDIUM;
            a->calls = eligible[i]->stats.total;
        }
    }

done:
    free(eligible);
    free(vals);
    free(dev);
    if (rc != CA_OK || n == 0) {
        free(out);
        return rc;
    }
    qsort(out, n, sizeof(*out), by_z_desc);
    *anomalies = out;
    *anomaly_count = n;
    return CA_OK;
}
