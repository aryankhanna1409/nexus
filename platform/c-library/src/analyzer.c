/*
 * analyzer.c - grouped aggregations: per cell, per failure code, per time
 * window and per caller.
 *
 * Grouping sorts an array of record pointers (the input is never modified),
 * then walks runs of equal keys. Cost is O(n log n) time and O(n) memory.
 */
#include <stdlib.h>
#include <string.h>

#include "ca_internal.h"

#define CA_MAX_WINDOW_SECONDS 86400

static int compare_by_cell(const void *a, const void *b)
{
    const CallRecord *x = *(const CallRecord *const *)a;
    const CallRecord *y = *(const CallRecord *const *)b;
    return strcmp(x->cell_id, y->cell_id);
}

static int compare_by_epoch(const void *a, const void *b)
{
    const CallRecord *x = *(const CallRecord *const *)a;
    const CallRecord *y = *(const CallRecord *const *)b;
    return (x->epoch_seconds > y->epoch_seconds) - (x->epoch_seconds < y->epoch_seconds);
}

static int compare_by_caller_callee(const void *a, const void *b)
{
    const CallRecord *x = *(const CallRecord *const *)a;
    const CallRecord *y = *(const CallRecord *const *)b;
    const int c = strcmp(x->caller, y->caller);
    return c != 0 ? c : strcmp(x->callee, y->callee);
}

/* Builds a sorted array of pointers into `records`. */
static int sorted_pointers(const CallRecord *records, size_t count,
                           int (*compare)(const void *, const void *),
                           const CallRecord ***out)
{
    const CallRecord **ptrs = ca_realloc_array(NULL, count, sizeof *ptrs);
    if (ptrs == NULL) {
        return CA_ERR_NOMEM;
    }
    for (size_t i = 0; i < count; i++) {
        ptrs[i] = &records[i];
    }
    qsort(ptrs, count, sizeof *ptrs, compare);
    *out = ptrs;
    return CA_OK;
}

/* Number of runs of equal keys in a sorted pointer array. */
static size_t count_groups(const CallRecord *const *ptrs, size_t count,
                           int (*same)(const CallRecord *, const CallRecord *))
{
    size_t groups = 0;
    for (size_t i = 0; i < count; i++) {
        if (i == 0 || !same(ptrs[i - 1], ptrs[i])) {
            groups++;
        }
    }
    return groups;
}

/* ---- Cells ----------------------------------------------------------------- */

static int same_cell(const CallRecord *a, const CallRecord *b)
{
    return strcmp(a->cell_id, b->cell_id) == 0;
}

static void fill_cell(CellStatistics *cell, const char *cell_id, const CaAccumulator *acc)
{
    memset(cell, 0, sizeof *cell);
    (void)ca_copy_string(cell->cell_id, sizeof cell->cell_id, cell_id); /* source has same size */
    cell->total_calls = acc->total;
    cell->successful_calls = acc->completed;
    cell->failed_setup_calls = acc->setup_failed;
    cell->dropped_calls = acc->dropped;
    cell->success_rate = ca_safe_ratio(acc->completed, acc->total);
    cell->drop_rate = ca_accumulator_drop_rate(acc);
    cell->setup_failure_rate = ca_safe_ratio(acc->setup_failed, acc->total);
    cell->average_duration = ca_accumulator_avg_duration(acc);
    cell->average_signal = ca_accumulator_avg_signal(acc);
    cell->average_packet_loss = ca_accumulator_avg_packet_loss(acc);
    cell->weak_signal_calls = acc->weak_signal;
    cell->first_epoch = acc->first_epoch;
    cell->last_epoch = acc->last_epoch;
}

int calculate_cell_statistics(const CallRecord *records, size_t count, CellStatistics **cells,
                              size_t *cell_count)
{
    const CallRecord **ptrs = NULL;
    CellStatistics *out = NULL;
    size_t groups, g = 0;
    CaAccumulator acc;
    int rc;

    if (cells == NULL || cell_count == NULL) {
        return CA_ERR_NULL_ARG;
    }
    *cells = NULL;
    *cell_count = 0;
    if ((rc = ca_check_records(records, count)) != CA_OK || count == 0) {
        return rc;
    }
    if ((rc = sorted_pointers(records, count, compare_by_cell, &ptrs)) != CA_OK) {
        return rc;
    }
    groups = count_groups(ptrs, count, same_cell);
    out = ca_calloc(groups, sizeof *out);
    if (out == NULL) {
        rc = CA_ERR_NOMEM;
        goto done;
    }

    ca_accumulator_init(&acc);
    for (size_t i = 0; i < count; i++) {
        if ((rc = ca_accumulator_add(&acc, ptrs[i])) != CA_OK) {
            goto done;
        }
        if (i + 1 == count || !same_cell(ptrs[i], ptrs[i + 1])) {
            fill_cell(&out[g++], ptrs[i]->cell_id, &acc);
            ca_accumulator_init(&acc);
        }
    }
    *cells = out;
    *cell_count = groups;
    out = NULL;

done:
    ca_free(out);
    ca_free(ptrs);
    return rc;
}

void free_cell_statistics(CellStatistics *cells)
{
    ca_free(cells);
}

/* ---- Failure codes --------------------------------------------------------- */

static int compare_code_stats(const void *a, const void *b)
{
    const FailureCodeStatistics *x = a;
    const FailureCodeStatistics *y = b;
    if (x->count != y->count) {
        return x->count < y->count ? 1 : -1;
    }
    return (x->status_code > y->status_code) - (x->status_code < y->status_code);
}

int calculate_failure_code_statistics(const CallRecord *records, size_t count,
                                      FailureCodeStatistics **codes, size_t *code_count)
{
    enum { CODE_RANGE = CA_MAX_STATUS_CODE - CA_MIN_STATUS_CODE + 1 };
    size_t *histogram;
    FailureCodeStatistics *out;
    size_t distinct = 0, k = 0;
    int rc;

    if (codes == NULL || code_count == NULL) {
        return CA_ERR_NULL_ARG;
    }
    *codes = NULL;
    *code_count = 0;
    if ((rc = ca_check_records(records, count)) != CA_OK || count == 0) {
        return rc;
    }
    histogram = ca_calloc(CODE_RANGE, sizeof *histogram);
    if (histogram == NULL) {
        return CA_ERR_NOMEM;
    }
    for (size_t i = 0; i < count; i++) {
        const int code = records[i].status_code;
        if (code < CA_MIN_STATUS_CODE || code > CA_MAX_STATUS_CODE) {
            ca_free(histogram);
            return CA_ERR_INVALID_ARG;
        }
        if (histogram[code - CA_MIN_STATUS_CODE]++ == 0) {
            distinct++;
        }
    }
    out = ca_calloc(distinct, sizeof *out);
    if (out == NULL) {
        ca_free(histogram);
        return CA_ERR_NOMEM;
    }
    for (int i = 0; i < CODE_RANGE; i++) {
        if (histogram[i] == 0) {
            continue;
        }
        out[k].status_code = i + CA_MIN_STATUS_CODE;
        out[k].outcome = call_outcome_for_status(out[k].status_code);
        out[k].count = histogram[i];
        out[k].share = ca_safe_ratio(histogram[i], count);
        k++;
    }
    ca_free(histogram);
    qsort(out, distinct, sizeof *out, compare_code_stats);
    *codes = out;
    *code_count = distinct;
    return CA_OK;
}

void free_failure_code_statistics(FailureCodeStatistics *codes)
{
    ca_free(codes);
}

/* ---- Time windows ---------------------------------------------------------- */

static int64_t window_floor(int64_t epoch, int64_t window_seconds)
{
    int64_t q = epoch / window_seconds;
    if (epoch % window_seconds != 0 && epoch < 0) {
        q -= 1;
    }
    return q * window_seconds;
}

static void fill_window(TimeWindowStatistics *w, int64_t start, int64_t size,
                        const CaAccumulator *acc)
{
    memset(w, 0, sizeof *w);
    w->window_start = start;
    w->window_end = start + size;
    w->total_calls = acc->total;
    w->successful_calls = acc->completed;
    w->failed_setup_calls = acc->setup_failed;
    w->dropped_calls = acc->dropped;
    w->drop_rate = ca_accumulator_drop_rate(acc);
    w->setup_failure_rate = ca_safe_ratio(acc->setup_failed, acc->total);
    w->average_signal = ca_accumulator_avg_signal(acc);
    w->average_packet_loss = ca_accumulator_avg_packet_loss(acc);
}

int calculate_time_window_statistics(const CallRecord *records, size_t count,
                                     int64_t window_seconds, TimeWindowStatistics **windows,
                                     size_t *window_count)
{
    const CallRecord **ptrs = NULL;
    TimeWindowStatistics *out = NULL;
    size_t groups = 0, g = 0;
    CaAccumulator acc;
    int rc;

    if (windows == NULL || window_count == NULL) {
        return CA_ERR_NULL_ARG;
    }
    *windows = NULL;
    *window_count = 0;
    if (window_seconds < 1 || window_seconds > CA_MAX_WINDOW_SECONDS) {
        return CA_ERR_INVALID_ARG;
    }
    if ((rc = ca_check_records(records, count)) != CA_OK || count == 0) {
        return rc;
    }
    if ((rc = sorted_pointers(records, count, compare_by_epoch, &ptrs)) != CA_OK) {
        return rc;
    }
    for (size_t i = 0; i < count; i++) {
        if (i == 0 || window_floor(ptrs[i]->epoch_seconds, window_seconds) !=
                          window_floor(ptrs[i - 1]->epoch_seconds, window_seconds)) {
            groups++;
        }
    }
    out = ca_calloc(groups, sizeof *out);
    if (out == NULL) {
        rc = CA_ERR_NOMEM;
        goto done;
    }

    ca_accumulator_init(&acc);
    for (size_t i = 0; i < count; i++) {
        const int64_t start = window_floor(ptrs[i]->epoch_seconds, window_seconds);
        if ((rc = ca_accumulator_add(&acc, ptrs[i])) != CA_OK) {
            goto done;
        }
        if (i + 1 == count || window_floor(ptrs[i + 1]->epoch_seconds, window_seconds) != start) {
            fill_window(&out[g++], start, window_seconds, &acc);
            ca_accumulator_init(&acc);
        }
    }
    *windows = out;
    *window_count = groups;
    out = NULL;

done:
    ca_free(out);
    ca_free(ptrs);
    return rc;
}

void free_time_window_statistics(TimeWindowStatistics *windows)
{
    ca_free(windows);
}

/* ---- Callers --------------------------------------------------------------- */

static int same_caller(const CallRecord *a, const CallRecord *b)
{
    return strcmp(a->caller, b->caller) == 0;
}

int calculate_caller_statistics(const CallRecord *records, size_t count,
                                CallerStatistics **callers, size_t *caller_count)
{
    const CallRecord **ptrs = NULL;
    CallerStatistics *out = NULL;
    size_t groups, g = 0, distinct_callees = 0;
    CaAccumulator acc;
    int rc;

    if (callers == NULL || caller_count == NULL) {
        return CA_ERR_NULL_ARG;
    }
    *callers = NULL;
    *caller_count = 0;
    if ((rc = ca_check_records(records, count)) != CA_OK || count == 0) {
        return rc;
    }
    if ((rc = sorted_pointers(records, count, compare_by_caller_callee, &ptrs)) != CA_OK) {
        return rc;
    }
    groups = count_groups(ptrs, count, same_caller);
    out = ca_calloc(groups, sizeof *out);
    if (out == NULL) {
        rc = CA_ERR_NOMEM;
        goto done;
    }

    ca_accumulator_init(&acc);
    for (size_t i = 0; i < count; i++) {
        const int new_caller = i == 0 || !same_caller(ptrs[i - 1], ptrs[i]);
        if (new_caller || strcmp(ptrs[i - 1]->callee, ptrs[i]->callee) != 0) {
            distinct_callees++;
        }
        if ((rc = ca_accumulator_add(&acc, ptrs[i])) != CA_OK) {
            goto done;
        }
        if (i + 1 == count || !same_caller(ptrs[i], ptrs[i + 1])) {
            CallerStatistics *c = &out[g++];
            (void)ca_copy_string(c->caller, sizeof c->caller, ptrs[i]->caller);
            c->calls_made = acc.total;
            c->distinct_callees = distinct_callees;
            c->successful_calls = acc.completed;
            c->failed_setup_calls = acc.setup_failed;
            c->dropped_calls = acc.dropped;
            c->short_calls = acc.short_calls;
            c->average_duration = ca_accumulator_avg_duration(&acc);
            c->total_duration = acc.duration_sum;
            c->first_epoch = acc.first_epoch;
            c->last_epoch = acc.last_epoch;
            ca_accumulator_init(&acc);
            distinct_callees = 0;
        }
    }
    *callers = out;
    *caller_count = groups;
    out = NULL;

done:
    ca_free(out);
    ca_free(ptrs);
    return rc;
}

void free_caller_statistics(CallerStatistics *callers)
{
    ca_free(callers);
}
