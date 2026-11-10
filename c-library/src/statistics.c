/*
 * statistics.c - whole-log statistics.
 */
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "ca_internal.h"

static int compare_string_ptr(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Counts distinct values of a string field located at `offset` in each record. */
static int count_distinct(const CallRecord *records, size_t count, size_t offset, size_t *out)
{
    const char **keys;
    size_t distinct = 0;

    *out = 0;
    if (count == 0) {
        return CA_OK;
    }
    keys = ca_realloc_array(NULL, count, sizeof *keys);
    if (keys == NULL) {
        return CA_ERR_NOMEM;
    }
    for (size_t i = 0; i < count; i++) {
        keys[i] = (const char *)&records[i] + offset;
    }
    qsort(keys, count, sizeof *keys, compare_string_ptr);
    for (size_t i = 0; i < count; i++) {
        if (i == 0 || strcmp(keys[i], keys[i - 1]) != 0) {
            distinct++;
        }
    }
    ca_free(keys);
    *out = distinct;
    return CA_OK;
}

int calculate_statistics(const CallRecord *records, size_t count, CallStatistics *stats)
{
    CaAccumulator acc;
    CallStatistics result;
    size_t established;
    int rc;

    if (stats == NULL) {
        return CA_ERR_NULL_ARG;
    }
    memset(stats, 0, sizeof *stats);
    if ((rc = ca_check_records(records, count)) != CA_OK) {
        return rc;
    }

    ca_accumulator_init(&acc);
    for (size_t i = 0; i < count; i++) {
        if ((rc = ca_accumulator_add(&acc, &records[i])) != CA_OK) {
            return rc;
        }
    }

    memset(&result, 0, sizeof result);
    if ((rc = count_distinct(records, count, offsetof(CallRecord, cell_id),
                             &result.unique_cells)) != CA_OK ||
        (rc = count_distinct(records, count, offsetof(CallRecord, caller),
                             &result.unique_callers)) != CA_OK) {
        return rc;
    }

    established = ca_accumulator_established(&acc);
    result.total_calls = acc.total;
    result.successful_calls = acc.completed;
    result.failed_setup_calls = acc.setup_failed;
    result.dropped_calls = acc.dropped;
    result.unknown_calls = acc.unknown;
    result.success_rate = ca_safe_ratio(acc.completed, acc.total);
    result.drop_rate = ca_accumulator_drop_rate(&acc);
    result.setup_failure_rate = ca_safe_ratio(acc.setup_failed, acc.total);
    result.average_duration = ca_accumulator_avg_duration(&acc);
    result.duration_stddev = established == 0 ? 0.0 : sqrt(acc.duration_m2 / (double)established);
    result.min_duration = acc.min_duration;
    result.max_duration = acc.max_duration;
    result.average_signal = ca_accumulator_avg_signal(&acc);
    result.average_packet_loss = ca_accumulator_avg_packet_loss(&acc);
    result.weak_signal_calls = acc.weak_signal;
    result.first_epoch = count == 0 ? 0 : acc.first_epoch;
    result.last_epoch = count == 0 ? 0 : acc.last_epoch;

    *stats = result;
    return CA_OK;
}
