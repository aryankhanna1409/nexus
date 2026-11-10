/*
 * anomaly.c - robust outlier detection over cells, time windows, callers and
 * individual call durations.
 *
 * Each group metric is compared against the median of its peers using a
 * robust z-score, z = (x - median) / max(1.4826 * MAD, floor). A group is
 * flagged only when z reaches the threshold AND the absolute deviation reaches
 * a minimum delta, so that tiny but tightly clustered baselines do not turn
 * negligible differences into alerts.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ca_internal.h"

#define FLOOR_RATE 0.01        /* 1 percentage point */
#define FLOOR_SIGNAL_DBM 1.0
#define FLOOR_PACKET_LOSS 0.5
#define FLOOR_VOLUME 1.0
#define FLOOR_DURATION 1.0

typedef struct {
    CallAnomaly *items;
    size_t count;
    size_t cap;
} AnomalyList;

void anomaly_config_default(AnomalyConfig *config)
{
    if (config == NULL) {
        return;
    }
    config->z_threshold = 3.5;
    config->duration_z_threshold = 10.0;
    config->min_peer_groups = 3;
    config->min_calls_per_cell = 20;
    config->min_calls_per_window = 10;
    config->min_calls_per_caller = 20;
    config->min_established_for_duration = 30;
    config->window_seconds = 300;
    config->min_rate_delta = 0.05;
    config->min_signal_delta_dbm = 6.0;
    config->min_packet_loss_delta = 3.0;
    config->min_volume_ratio = 2.0;
    config->min_short_call_ratio = 0.6;
    config->max_anomalies = 1000;
}

void free_call_anomalies(CallAnomaly *anomalies)
{
    ca_free(anomalies);
}

static int validate_config(const AnomalyConfig *c)
{
    if (!(c->z_threshold > 0.0) || !(c->duration_z_threshold > 0.0) ||
        c->min_peer_groups < 2 || c->window_seconds < 1 || c->window_seconds > 86400 ||
        !(c->min_rate_delta >= 0.0) || !(c->min_signal_delta_dbm >= 0.0) ||
        !(c->min_packet_loss_delta >= 0.0) || !(c->min_volume_ratio >= 0.0) ||
        !(c->min_short_call_ratio >= 0.0 && c->min_short_call_ratio <= 1.0)) {
        return CA_ERR_INVALID_ARG;
    }
    return CA_OK;
}

static int list_push(AnomalyList *list, const CallAnomaly *anomaly)
{
    if (list->count == list->cap) {
        const size_t new_cap = list->cap == 0 ? 16 : list->cap * 2;
        CallAnomaly *grown;
        if (new_cap < list->cap) {
            return CA_ERR_OVERFLOW;
        }
        grown = ca_realloc_array(list->items, new_cap, sizeof *grown);
        if (grown == NULL) {
            return CA_ERR_NOMEM;
        }
        list->items = grown;
        list->cap = new_cap;
    }
    list->items[list->count++] = *anomaly;
    return CA_OK;
}

static void init_anomaly(CallAnomaly *a, CallAnomalyType type, const char *subject, double value,
                         double baseline, double z, double threshold, size_t sample_size)
{
    memset(a, 0, sizeof *a);
    a->type = type;
    (void)ca_copy_string(a->subject, sizeof a->subject, subject); /* subjects are < CA_FIELD_LEN */
    a->value = value;
    a->baseline = baseline;
    a->z_score = z;
    a->score = ca_anomaly_score(z, threshold);
    a->severity = ca_severity_for_score(a->score);
    a->sample_size = sample_size;
    a->record_index = -1;
}

/*
 * Signed robust z-scores (positive = deviation in `direction`) for n values.
 * Writes the peer median to *median.
 */
static int robust_scores(const double *values, size_t n, int direction, double floor,
                         double *median, double *z)
{
    double *sorted = ca_realloc_array(NULL, n, sizeof *sorted);
    double *scratch = ca_realloc_array(NULL, n, sizeof *scratch);
    double med, mad;

    if (sorted == NULL || scratch == NULL) {
        ca_free(sorted);
        ca_free(scratch);
        return CA_ERR_NOMEM;
    }
    memcpy(sorted, values, n * sizeof *sorted);
    med = ca_median_inplace(sorted, n);
    mad = ca_mad(values, n, med, scratch);
    for (size_t i = 0; i < n; i++) {
        z[i] = (double)direction * ca_robust_z(values[i], med, mad, floor);
    }
    ca_free(sorted);
    ca_free(scratch);
    *median = med;
    return CA_OK;
}

/* ---- Cells ----------------------------------------------------------------- */

typedef enum { CELL_DROP, CELL_SETUP_FAIL, CELL_SIGNAL, CELL_LOSS, CELL_METRIC_COUNT } CellMetric;

static double cell_value(const CellStatistics *c, CellMetric m)
{
    switch (m) {
    case CELL_DROP: return c->drop_rate;
    case CELL_SETUP_FAIL: return c->setup_failure_rate;
    case CELL_SIGNAL: return c->average_signal;
    case CELL_LOSS: return c->average_packet_loss;
    case CELL_METRIC_COUNT:
    default: return 0.0;
    }
}

static size_t cell_sample(const CellStatistics *c, CellMetric m)
{
    return m == CELL_DROP ? c->successful_calls + c->dropped_calls : c->total_calls;
}

static void describe_cell(CallAnomaly *a, CellMetric m, const CellStatistics *c)
{
    switch (m) {
    case CELL_DROP:
        snprintf(a->description, sizeof a->description,
                 "Cell %s drop rate %.1f%% vs peer median %.1f%% (%zu established calls)",
                 c->cell_id, a->value * 100.0, a->baseline * 100.0, a->sample_size);
        break;
    case CELL_SETUP_FAIL:
        snprintf(a->description, sizeof a->description,
                 "Cell %s setup failure rate %.1f%% vs peer median %.1f%% (%zu calls)",
                 c->cell_id, a->value * 100.0, a->baseline * 100.0, a->sample_size);
        break;
    case CELL_SIGNAL:
        snprintf(a->description, sizeof a->description,
                 "Cell %s average signal %.1f dBm vs peer median %.1f dBm (%zu calls)",
                 c->cell_id, a->value, a->baseline, a->sample_size);
        break;
    case CELL_LOSS:
        snprintf(a->description, sizeof a->description,
                 "Cell %s average packet loss %.1f%% vs peer median %.1f%% (%zu calls)",
                 c->cell_id, a->value, a->baseline, a->sample_size);
        break;
    case CELL_METRIC_COUNT:
    default:
        break;
    }
}

static int detect_cells(const CallRecord *records, size_t count, const AnomalyConfig *cfg,
                        AnomalyList *out)
{
    static const CallAnomalyType types[CELL_METRIC_COUNT] = {
        CA_ANOMALY_CELL_DROP_RATE, CA_ANOMALY_CELL_SETUP_FAILURE_RATE,
        CA_ANOMALY_CELL_LOW_SIGNAL, CA_ANOMALY_CELL_PACKET_LOSS,
    };
    const int directions[CELL_METRIC_COUNT] = {1, 1, -1, 1};
    const double floors[CELL_METRIC_COUNT] = {FLOOR_RATE, FLOOR_RATE, FLOOR_SIGNAL_DBM,
                                              FLOOR_PACKET_LOSS};
    const double deltas[CELL_METRIC_COUNT] = {cfg->min_rate_delta, cfg->min_rate_delta,
                                              cfg->min_signal_delta_dbm,
                                              cfg->min_packet_loss_delta};
    CellStatistics *cells = NULL;
    size_t n_cells = 0;
    size_t *idx = NULL;
    double *values = NULL, *z = NULL;
    int rc;

    if ((rc = calculate_cell_statistics(records, count, &cells, &n_cells)) != CA_OK ||
        n_cells < cfg->min_peer_groups) {
        goto done;
    }
    idx = ca_realloc_array(NULL, n_cells, sizeof *idx);
    values = ca_realloc_array(NULL, n_cells, sizeof *values);
    z = ca_realloc_array(NULL, n_cells, sizeof *z);
    if (idx == NULL || values == NULL || z == NULL) {
        rc = CA_ERR_NOMEM;
        goto done;
    }

    for (int m = 0; m < CELL_METRIC_COUNT; m++) {
        size_t n = 0;
        double median;
        for (size_t i = 0; i < n_cells; i++) {
            if (cell_sample(&cells[i], (CellMetric)m) >= cfg->min_calls_per_cell) {
                idx[n] = i;
                values[n] = cell_value(&cells[i], (CellMetric)m);
                n++;
            }
        }
        if (n < cfg->min_peer_groups) {
            continue;
        }
        if ((rc = robust_scores(values, n, directions[m], floors[m], &median, z)) != CA_OK) {
            goto done;
        }
        for (size_t k = 0; k < n; k++) {
            const CellStatistics *c = &cells[idx[k]];
            CallAnomaly a;
            if (z[k] < cfg->z_threshold ||
                (double)directions[m] * (values[k] - median) < deltas[m]) {
                continue;
            }
            init_anomaly(&a, types[m], c->cell_id, values[k], median, z[k], cfg->z_threshold,
                         cell_sample(c, (CellMetric)m));
            a.window_start = c->first_epoch;
            a.window_end = c->last_epoch;
            describe_cell(&a, (CellMetric)m, c);
            if ((rc = list_push(out, &a)) != CA_OK) {
                goto done;
            }
        }
    }

done:
    ca_free(z);
    ca_free(values);
    ca_free(idx);
    free_cell_statistics(cells);
    return rc;
}

/* ---- Time windows ---------------------------------------------------------- */

static int detect_windows(const CallRecord *records, size_t count, const AnomalyConfig *cfg,
                          AnomalyList *out)
{
    TimeWindowStatistics *windows = NULL;
    size_t n_windows = 0;
    size_t *idx = NULL;
    double *values = NULL, *z = NULL;
    double median;
    size_t n = 0;
    int rc;

    if ((rc = calculate_time_window_statistics(records, count, cfg->window_seconds, &windows,
                                               &n_windows)) != CA_OK ||
        n_windows < cfg->min_peer_groups) {
        goto done;
    }
    idx = ca_realloc_array(NULL, n_windows, sizeof *idx);
    values = ca_realloc_array(NULL, n_windows, sizeof *values);
    z = ca_realloc_array(NULL, n_windows, sizeof *z);
    if (idx == NULL || values == NULL || z == NULL) {
        rc = CA_ERR_NOMEM;
        goto done;
    }

    /* Drop-rate spikes in windows with enough established calls. */
    for (size_t i = 0; i < n_windows; i++) {
        if (windows[i].successful_calls + windows[i].dropped_calls >= cfg->min_calls_per_window) {
            idx[n] = i;
            values[n] = windows[i].drop_rate;
            n++;
        }
    }
    if (n >= cfg->min_peer_groups) {
        if ((rc = robust_scores(values, n, 1, FLOOR_RATE, &median, z)) != CA_OK) {
            goto done;
        }
        for (size_t k = 0; k < n; k++) {
            const TimeWindowStatistics *w = &windows[idx[k]];
            char subject[CA_FIELD_LEN];
            CallAnomaly a;
            if (z[k] < cfg->z_threshold || values[k] - median < cfg->min_rate_delta) {
                continue;
            }
            ca_format_epoch(w->window_start, subject, sizeof subject);
            init_anomaly(&a, CA_ANOMALY_WINDOW_DROP_RATE, subject, values[k], median, z[k],
                         cfg->z_threshold, w->successful_calls + w->dropped_calls);
            a.window_start = w->window_start;
            a.window_end = w->window_end;
            snprintf(a.description, sizeof a.description,
                     "Window %s drop rate %.1f%% vs median %.1f%% (%zu established calls)",
                     subject, a.value * 100.0, a.baseline * 100.0, a.sample_size);
            if ((rc = list_push(out, &a)) != CA_OK) {
                goto done;
            }
        }
    }

    /* Call-volume spikes across all non-empty windows. */
    for (size_t i = 0; i < n_windows; i++) {
        values[i] = (double)windows[i].total_calls;
    }
    if ((rc = robust_scores(values, n_windows, 1, FLOOR_VOLUME, &median, z)) != CA_OK) {
        goto done;
    }
    for (size_t i = 0; i < n_windows; i++) {
        const TimeWindowStatistics *w = &windows[i];
        char subject[CA_FIELD_LEN];
        CallAnomaly a;
        if (z[i] < cfg->z_threshold || values[i] < cfg->min_volume_ratio * median) {
            continue;
        }
        ca_format_epoch(w->window_start, subject, sizeof subject);
        init_anomaly(&a, CA_ANOMALY_WINDOW_VOLUME_SPIKE, subject, values[i], median, z[i],
                     cfg->z_threshold, w->total_calls);
        a.window_start = w->window_start;
        a.window_end = w->window_end;
        snprintf(a.description, sizeof a.description,
                 "Window %s carried %zu calls vs median %.1f per window", subject,
                 w->total_calls, median);
        if ((rc = list_push(out, &a)) != CA_OK) {
            goto done;
        }
    }

done:
    ca_free(z);
    ca_free(values);
    ca_free(idx);
    free_time_window_statistics(windows);
    return rc;
}

/* ---- Callers --------------------------------------------------------------- */

static int detect_callers(const CallRecord *records, size_t count, const AnomalyConfig *cfg,
                          AnomalyList *out)
{
    CallerStatistics *callers = NULL;
    size_t n_callers = 0;
    double *values = NULL, *z = NULL;
    double median;
    int rc;

    if ((rc = calculate_caller_statistics(records, count, &callers, &n_callers)) != CA_OK ||
        n_callers < cfg->min_peer_groups) {
        goto done;
    }
    values = ca_realloc_array(NULL, n_callers, sizeof *values);
    z = ca_realloc_array(NULL, n_callers, sizeof *z);
    if (values == NULL || z == NULL) {
        rc = CA_ERR_NOMEM;
        goto done;
    }
    for (size_t i = 0; i < n_callers; i++) {
        values[i] = (double)callers[i].calls_made;
    }
    if ((rc = robust_scores(values, n_callers, 1, FLOOR_VOLUME, &median, z)) != CA_OK) {
        goto done;
    }
    for (size_t i = 0; i < n_callers; i++) {
        const CallerStatistics *c = &callers[i];
        const double short_ratio =
            ca_safe_ratio(c->short_calls + c->failed_setup_calls, c->calls_made);
        CallAnomaly a;
        if (c->calls_made < cfg->min_calls_per_caller || z[i] < cfg->z_threshold ||
            short_ratio < cfg->min_short_call_ratio) {
            continue;
        }
        init_anomaly(&a, CA_ANOMALY_CALLER_HIGH_VOLUME, c->caller, values[i], median, z[i],
                     cfg->z_threshold, c->calls_made);
        a.window_start = c->first_epoch;
        a.window_end = c->last_epoch;
        snprintf(a.description, sizeof a.description,
                 "Caller %s placed %zu calls to %zu callees (median %.1f); %.0f%% short or "
                 "unanswered",
                 c->caller, c->calls_made, c->distinct_callees, median, short_ratio * 100.0);
        if ((rc = list_push(out, &a)) != CA_OK) {
            goto done;
        }
    }

done:
    ca_free(z);
    ca_free(values);
    free_caller_statistics(callers);
    return rc;
}

/* ---- Individual call durations -------------------------------------------- */

static int is_established(const CallRecord *r)
{
    const CallOutcome o = call_outcome_for_status(r->status_code);
    return o == CALL_COMPLETED || o == CALL_DROPPED;
}

static int detect_durations(const CallRecord *records, size_t count, const AnomalyConfig *cfg,
                            AnomalyList *out)
{
    double *values = NULL, *z = NULL;
    size_t *idx = NULL;
    size_t n = 0;
    double median;
    int rc = CA_OK;

    idx = ca_realloc_array(NULL, count, sizeof *idx);
    values = ca_realloc_array(NULL, count, sizeof *values);
    z = ca_realloc_array(NULL, count, sizeof *z);
    if (idx == NULL || values == NULL || z == NULL) {
        rc = CA_ERR_NOMEM;
        goto done;
    }
    for (size_t i = 0; i < count; i++) {
        if (is_established(&records[i])) {
            idx[n] = i;
            values[n] = (double)records[i].duration;
            n++;
        }
    }
    if (n < cfg->min_established_for_duration || n == 0) {
        goto done;
    }
    if ((rc = robust_scores(values, n, 1, FLOOR_DURATION, &median, z)) != CA_OK) {
        goto done;
    }
    for (size_t k = 0; k < n; k++) {
        const CallRecord *r = &records[idx[k]];
        CallAnomaly a;
        if (z[k] < cfg->duration_z_threshold) {
            continue;
        }
        init_anomaly(&a, CA_ANOMALY_CALL_DURATION, r->caller, values[k], median, z[k],
                     cfg->duration_z_threshold, 1);
        a.window_start = r->epoch_seconds;
        a.window_end = r->epoch_seconds + r->duration;
        a.record_index = (int64_t)idx[k];
        snprintf(a.description, sizeof a.description,
                 "Call %s -> %s on %s lasted %d s vs median %.0f s", r->caller, r->callee,
                 r->cell_id, r->duration, median);
        if ((rc = list_push(out, &a)) != CA_OK) {
            goto done;
        }
    }

done:
    ca_free(z);
    ca_free(values);
    ca_free(idx);
    return rc;
}

/* ---- Entry point ----------------------------------------------------------- */

static int compare_anomalies(const void *a, const void *b)
{
    const CallAnomaly *x = a;
    const CallAnomaly *y = b;
    int c;
    if (x->score != y->score) {
        return x->score < y->score ? 1 : -1;
    }
    if (x->type != y->type) {
        return x->type < y->type ? -1 : 1;
    }
    c = strcmp(x->subject, y->subject);
    if (c != 0) {
        return c;
    }
    return (x->record_index > y->record_index) - (x->record_index < y->record_index);
}

int detect_call_anomalies(const CallRecord *records, size_t count, const AnomalyConfig *config,
                          CallAnomaly **anomalies, size_t *anomaly_count)
{
    AnomalyConfig cfg;
    AnomalyList list = {NULL, 0, 0};
    int rc;

    if (anomalies == NULL || anomaly_count == NULL) {
        return CA_ERR_NULL_ARG;
    }
    *anomalies = NULL;
    *anomaly_count = 0;
    if ((rc = ca_check_records(records, count)) != CA_OK) {
        return rc;
    }
    if (config != NULL) {
        cfg = *config;
    } else {
        anomaly_config_default(&cfg);
    }
    if ((rc = validate_config(&cfg)) != CA_OK || count == 0) {
        return rc;
    }

    if ((rc = detect_cells(records, count, &cfg, &list)) != CA_OK ||
        (rc = detect_windows(records, count, &cfg, &list)) != CA_OK ||
        (rc = detect_callers(records, count, &cfg, &list)) != CA_OK ||
        (rc = detect_durations(records, count, &cfg, &list)) != CA_OK) {
        ca_free(list.items);
        return rc;
    }

    if (list.count == 0) {
        ca_free(list.items);
        return CA_OK;
    }
    qsort(list.items, list.count, sizeof *list.items, compare_anomalies);
    if (cfg.max_anomalies != 0 && list.count > cfg.max_anomalies) {
        list.count = cfg.max_anomalies;
    }
    *anomalies = list.items;
    *anomaly_count = list.count;
    return CA_OK;
}
