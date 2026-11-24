/*
 * call_analyzer.h - Aegis-Net call-log (CDR) analysis library.
 *
 * Conventions
 *   - Functions returning int return CA_OK (0) or a negative CaStatus.
 *   - Arrays returned through out-parameters are allocated by the library and
 *     must be released with the matching free_* function. On failure, output
 *     pointers are set to NULL and output counts to 0.
 *   - Fixed-size string fields are always NUL-terminated. Inputs that do not
 *     fit are rejected, never silently truncated.
 *   - The library keeps no global mutable state; calls are re-entrant.
 *
 * CSV schema (header line optional, columns in this order):
 *   timestamp,caller,callee,cell_id,duration,status_code,signal_strength,packet_loss
 */
#ifndef CALL_ANALYZER_H
#define CALL_ANALYZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && defined(CA_BUILDING_SHARED)
#define CA_API __attribute__((visibility("default")))
#else
#define CA_API
#endif

#define CA_VERSION_MAJOR 1
#define CA_VERSION_MINOR 0
#define CA_VERSION_PATCH 0

#define CA_FIELD_LEN 32          /* size of string fields incl. NUL */
#define CA_DESCRIPTION_LEN 160
#define CA_ERROR_MESSAGE_LEN 128
#define CA_MAX_LINE_LENGTH 1024  /* longer CSV lines are rejected */
#define CA_DEFAULT_MAX_RECORDS ((size_t)10000000)

/* Validation ranges. */
#define CA_MAX_DURATION_SECONDS 86400
#define CA_MIN_STATUS_CODE 100
#define CA_MAX_STATUS_CODE 999
#define CA_MIN_SIGNAL_DBM (-150)
#define CA_MAX_SIGNAL_DBM 0
#define CA_MAX_PACKET_LOSS_PERCENT 100

/* Thresholds used by aggregations. */
#define CA_WEAK_SIGNAL_DBM (-105)   /* signal <= this is "weak" */
#define CA_SHORT_CALL_SECONDS 5     /* established call shorter than this */

typedef enum {
    CA_OK = 0,
    CA_ERR_NULL_ARG = -1,
    CA_ERR_INVALID_ARG = -2,
    CA_ERR_IO = -3,
    CA_ERR_NOMEM = -4,
    CA_ERR_PARSE = -5,
    CA_ERR_OVERFLOW = -6,
    CA_ERR_LIMIT = -7
} CaStatus;

/* Status-code classes (SIP-inspired, defined by Aegis-Net):
 *   200-299 completed, 900-999 dropped after establishment,
 *   300-899 setup failure, 100-199 provisional/unknown. */
typedef enum {
    CALL_UNKNOWN = 0,
    CALL_COMPLETED = 1,
    CALL_SETUP_FAILED = 2,
    CALL_DROPPED = 3
} CallOutcome;

typedef struct {
    char timestamp[CA_FIELD_LEN];  /* normalised "YYYY-MM-DDTHH:MM:SSZ" */
    char caller[CA_FIELD_LEN];
    char callee[CA_FIELD_LEN];
    char cell_id[CA_FIELD_LEN];
    int duration;                  /* seconds */
    int status_code;
    int signal_strength;           /* dBm */
    int packet_loss;               /* percent */
    int64_t epoch_seconds;         /* timestamp as seconds since 1970-01-01 UTC */
} CallRecord;

typedef struct {
    int strict;          /* non-zero: first invalid row fails the whole parse */
    size_t max_records;  /* 0 means CA_DEFAULT_MAX_RECORDS */
} ParseOptions;

typedef struct {
    size_t lines_read;        /* physical lines, including header and blanks */
    size_t records_parsed;
    size_t records_rejected;
    int header_present;
    size_t first_error_line;  /* 1-based; 0 if no error */
    int first_error;          /* CaStatus of the first rejected row */
    char first_error_message[CA_ERROR_MESSAGE_LEN];
} ParseReport;

typedef struct {
    size_t total_calls;
    size_t successful_calls;
    size_t failed_setup_calls;
    size_t dropped_calls;
    size_t unknown_calls;
    double success_rate;        /* successful / total */
    double drop_rate;           /* dropped / (successful + dropped) */
    double setup_failure_rate;  /* failed_setup / total */
    double average_duration;    /* over established calls */
    double duration_stddev;     /* population stddev over established calls */
    int min_duration;           /* over established calls; 0 if none */
    int max_duration;
    double average_signal;      /* over all calls */
    double average_packet_loss; /* over all calls */
    size_t weak_signal_calls;
    size_t unique_cells;
    size_t unique_callers;
    int64_t first_epoch;
    int64_t last_epoch;
} CallStatistics;

typedef struct {
    char cell_id[CA_FIELD_LEN];
    size_t total_calls;
    size_t successful_calls;
    size_t failed_setup_calls;
    size_t dropped_calls;
    double success_rate;
    double drop_rate;
    double setup_failure_rate;
    double average_duration;
    double average_signal;
    double average_packet_loss;
    size_t weak_signal_calls;
    int64_t first_epoch;
    int64_t last_epoch;
} CellStatistics;

typedef struct {
    int status_code;
    CallOutcome outcome;
    size_t count;
    double share;  /* count / total calls */
} FailureCodeStatistics;

typedef struct {
    int64_t window_start;  /* inclusive, epoch seconds, aligned to window size */
    int64_t window_end;    /* exclusive */
    size_t total_calls;
    size_t successful_calls;
    size_t failed_setup_calls;
    size_t dropped_calls;
    double drop_rate;
    double setup_failure_rate;
    double average_signal;
    double average_packet_loss;
} TimeWindowStatistics;

typedef struct {
    char caller[CA_FIELD_LEN];
    size_t calls_made;
    size_t distinct_callees;
    size_t successful_calls;
    size_t failed_setup_calls;
    size_t dropped_calls;
    size_t short_calls;       /* established and shorter than CA_SHORT_CALL_SECONDS */
    double average_duration;  /* over established calls */
    uint64_t total_duration;
    int64_t first_epoch;
    int64_t last_epoch;
} CallerStatistics;

typedef enum {
    CA_ANOMALY_CELL_DROP_RATE = 0,
    CA_ANOMALY_CELL_SETUP_FAILURE_RATE,
    CA_ANOMALY_CELL_LOW_SIGNAL,
    CA_ANOMALY_CELL_PACKET_LOSS,
    CA_ANOMALY_WINDOW_DROP_RATE,
    CA_ANOMALY_WINDOW_VOLUME_SPIKE,
    CA_ANOMALY_CALLER_HIGH_VOLUME,
    CA_ANOMALY_CALL_DURATION,
    CA_ANOMALY_TYPE_COUNT
} CallAnomalyType;

typedef enum {
    CA_SEVERITY_LOW = 0,
    CA_SEVERITY_MEDIUM,
    CA_SEVERITY_HIGH,
    CA_SEVERITY_CRITICAL
} CallSeverity;

typedef struct {
    CallAnomalyType type;
    CallSeverity severity;
    char subject[CA_FIELD_LEN];  /* cell id, caller, or window start timestamp */
    int64_t window_start;        /* time span covered by the evidence */
    int64_t window_end;
    double value;                /* observed value */
    double baseline;             /* peer median */
    double z_score;              /* robust z-score */
    double score;                /* 0..1, 0.5 at the configured threshold */
    size_t sample_size;          /* calls behind `value` */
    int64_t record_index;        /* index into the input for per-call anomalies, else -1 */
    char description[CA_DESCRIPTION_LEN];
} CallAnomaly;

typedef struct {
    double z_threshold;            /* robust z needed for group-level anomalies */
    double duration_z_threshold;   /* robust z needed for per-call duration outliers */
    size_t min_peer_groups;        /* groups needed to form a baseline */
    size_t min_calls_per_cell;
    size_t min_calls_per_window;
    size_t min_calls_per_caller;
    size_t min_established_for_duration;
    int64_t window_seconds;
    double min_rate_delta;         /* absolute drop / setup-failure rate increase */
    double min_signal_delta_dbm;
    double min_packet_loss_delta;  /* percentage points */
    double min_volume_ratio;       /* window volume vs median */
    double min_short_call_ratio;   /* caller anomaly requires this share of short or
                                      failed-setup calls */
    size_t max_anomalies;          /* highest-scoring anomalies kept; 0 = no cap */
} AnomalyConfig;

typedef struct {
    size_t call_record;
    size_t call_statistics;
    size_t cell_statistics;
    size_t failure_code_statistics;
    size_t time_window_statistics;
    size_t caller_statistics;
    size_t call_anomaly;
    size_t anomaly_config;
    size_t parse_options;
    size_t parse_report;
} CaStructSizes;

/* ---- Library information ---------------------------------------------- */
CA_API const char *call_analyzer_version(void);
CA_API const char *call_analyzer_strerror(int status);
CA_API void call_analyzer_struct_sizes(CaStructSizes *sizes);
CA_API CallOutcome call_outcome_for_status(int status_code);
CA_API const char *call_outcome_name(CallOutcome outcome);
CA_API const char *call_anomaly_type_name(CallAnomalyType type);
CA_API const char *call_severity_name(CallSeverity severity);

/* ---- Parsing ----------------------------------------------------------- */
CA_API void parse_options_default(ParseOptions *opts);

/* Lenient parse with default options: invalid rows are skipped. */
CA_API int parse_call_log(const char *filepath, CallRecord **records, size_t *count);

/* opts and report may be NULL. */
CA_API int parse_call_log_ex(const char *filepath, const ParseOptions *opts,
                             CallRecord **records, size_t *count, ParseReport *report);

/* Parse CSV text held in memory. data need not be NUL-terminated. */
CA_API int parse_call_log_buffer(const char *data, size_t len, const ParseOptions *opts,
                                 CallRecord **records, size_t *count, ParseReport *report);

CA_API void free_call_records(CallRecord *records);

/* ---- Aggregation -------------------------------------------------------- */
/* count == 0 is valid and yields zeroed statistics. records may be NULL iff count == 0. */
CA_API int calculate_statistics(const CallRecord *records, size_t count, CallStatistics *stats);

/* Sorted by cell_id ascending. */
CA_API int calculate_cell_statistics(const CallRecord *records, size_t count,
                                     CellStatistics **cells, size_t *cell_count);
CA_API void free_cell_statistics(CellStatistics *cells);

/* Sorted by count descending, then status_code ascending. */
CA_API int calculate_failure_code_statistics(const CallRecord *records, size_t count,
                                             FailureCodeStatistics **codes, size_t *code_count);
CA_API void free_failure_code_statistics(FailureCodeStatistics *codes);

/* Non-empty windows only, sorted by window_start. window_seconds in [1, 86400]. */
CA_API int calculate_time_window_statistics(const CallRecord *records, size_t count,
                                            int64_t window_seconds,
                                            TimeWindowStatistics **windows, size_t *window_count);
CA_API void free_time_window_statistics(TimeWindowStatistics *windows);

/* Sorted by caller ascending. */
CA_API int calculate_caller_statistics(const CallRecord *records, size_t count,
                                       CallerStatistics **callers, size_t *caller_count);
CA_API void free_caller_statistics(CallerStatistics *callers);

/* ---- Anomaly detection -------------------------------------------------- */
CA_API void anomaly_config_default(AnomalyConfig *config);

/* config may be NULL (defaults). Results sorted by score descending. */
CA_API int detect_call_anomalies(const CallRecord *records, size_t count,
                                 const AnomalyConfig *config,
                                 CallAnomaly **anomalies, size_t *anomaly_count);
CA_API void free_call_anomalies(CallAnomaly *anomalies);

#ifdef __cplusplus
}
#endif

#endif /* CALL_ANALYZER_H */
