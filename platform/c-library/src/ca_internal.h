/*
 * ca_internal.h - helpers shared between translation units. Not installed.
 */
#ifndef CA_INTERNAL_H
#define CA_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "call_analyzer.h"

/* ---- Allocation (wrapped so tests can inject failures) ------------------ */
void *ca_malloc(size_t size);
void *ca_calloc(size_t nmemb, size_t size);
/* realloc for an array; fails with NULL on multiplication overflow. */
void *ca_realloc_array(void *ptr, size_t nmemb, size_t size);
void ca_free(void *ptr);

#ifdef CA_FAULT_INJECTION
/* Fail the allocation after `remaining` more successful ones; -1 disables. */
void ca_fault_inject_set(long remaining);
/* Number of allocations that were forced to fail since the last set. */
long ca_fault_inject_triggered(void);
#endif

/* ---- Checked arithmetic -------------------------------------------------- */
int ca_mul_size(size_t a, size_t b, size_t *out);
int ca_add_i64(int64_t a, int64_t b, int64_t *out);

/* ---- Parsing helpers ------------------------------------------------------ */
/* Parses "YYYY-MM-DDTHH:MM:SS" with optional trailing 'Z'; 'T' may be ' '. */
int ca_parse_timestamp(const char *text, int64_t *epoch);
/* Formats as "YYYY-MM-DDTHH:MM:SSZ"; buf must hold at least 21 bytes. */
void ca_format_epoch(int64_t epoch, char *buf, size_t buf_size);
/* Whole-string base-10 integer within [min, max]. */
int ca_parse_int(const char *text, long min, long max, int *out);
/* Non-empty, shorter than CA_FIELD_LEN, every char in the allowed set. */
int ca_valid_party(const char *text);
int ca_valid_cell_id(const char *text);
/* Copies src (length < dst_size) or returns CA_ERR_OVERFLOW. */
int ca_copy_string(char *dst, size_t dst_size, const char *src);

/* ---- Statistics helpers --------------------------------------------------- */
/* Sorts `values` in place and returns the median. n must be > 0. */
double ca_median_inplace(double *values, size_t n);
/* Median absolute deviation around `median`; uses `scratch` (n doubles). */
double ca_mad(const double *values, size_t n, double median, double *scratch);
/* Robust z-score: (x - median) / max(1.4826 * mad, floor). */
double ca_robust_z(double x, double median, double mad, double floor);
/* 1 - 2^(-z/threshold) for z > 0, else 0. */
double ca_anomaly_score(double z, double threshold);
CallSeverity ca_severity_for_score(double score);
double ca_safe_ratio(size_t numerator, size_t denominator);

/* Running totals for one group of calls. */
typedef struct {
    size_t total;
    size_t completed;
    size_t setup_failed;
    size_t dropped;
    size_t unknown;
    size_t weak_signal;
    size_t short_calls;
    uint64_t duration_sum;   /* established calls */
    int64_t signal_sum;
    int64_t packet_loss_sum;
    double duration_mean;    /* Welford, established calls */
    double duration_m2;
    int min_duration;
    int max_duration;
    int64_t first_epoch;
    int64_t last_epoch;
} CaAccumulator;

void ca_accumulator_init(CaAccumulator *acc);
/* Returns CA_ERR_OVERFLOW if a running sum would overflow. */
int ca_accumulator_add(CaAccumulator *acc, const CallRecord *record);
size_t ca_accumulator_established(const CaAccumulator *acc);
double ca_accumulator_drop_rate(const CaAccumulator *acc);
double ca_accumulator_avg_duration(const CaAccumulator *acc);
double ca_accumulator_avg_signal(const CaAccumulator *acc);
double ca_accumulator_avg_packet_loss(const CaAccumulator *acc);

/* Validates (records, count) pairs at API entry. */
int ca_check_records(const CallRecord *records, size_t count);

#endif /* CA_INTERNAL_H */
