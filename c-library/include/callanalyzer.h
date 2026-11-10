/*
 * callanalyzer.h - a small C library for analysing telecom call logs (CDRs).
 *
 * Input is CSV with these columns (a header line is optional):
 *   timestamp,caller,callee,cell_id,duration,status_code,signal_strength,packet_loss
 *   2026-03-01T14:05:00Z,+15550001,+15550002,CELL-102,184,200,-82,1
 *
 * Status codes:  200-299 completed, 900-999 dropped mid-call,
 *                300-899 failed to connect, 100-199 unknown.
 *
 * Rules for every function:
 *   - Returns CA_OK (0) or a negative CaStatus.
 *   - Arrays handed back through pointers are allocated by the library;
 *     release them with ca_free().
 */
#ifndef CALLANALYZER_H
#define CALLANALYZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CA_VERSION "2.0.0"
#define CA_ID_LEN 32          /* cell ids and phone numbers, incl. NUL */
#define CA_MAX_LINE 1024      /* longer CSV lines are rejected */

typedef enum {
    CA_OK = 0,
    CA_ERR_NULL_ARG = -1,
    CA_ERR_IO = -2,
    CA_ERR_NOMEM = -3,
    CA_ERR_PARSE = -4
} CaStatus;

typedef enum {
    CA_CALL_UNKNOWN = 0,
    CA_CALL_COMPLETED = 1,
    CA_CALL_SETUP_FAILED = 2,
    CA_CALL_DROPPED = 3
} CaOutcome;

typedef struct {
    char cell_id[CA_ID_LEN];
    int64_t epoch;        /* seconds since 1970-01-01 UTC */
    int duration;         /* seconds, 0..86400 */
    int status_code;      /* 100..999 */
    int signal_dbm;       /* -150..0 */
    int packet_loss;      /* percent, 0..100 */
} CaRecord;

typedef struct {
    size_t lines;         /* lines read, including header and blank lines */
    size_t parsed;
    size_t rejected;
    size_t first_error_line;   /* 1-based, 0 if none */
    char first_error[96];
} CaParseReport;

typedef struct {
    size_t total, completed, setup_failed, dropped, unknown;
    double success_rate;        /* completed / total */
    double drop_rate;           /* dropped / (completed + dropped) */
    double setup_failure_rate;  /* setup_failed / total */
    double avg_duration;        /* over completed + dropped calls */
    double avg_signal_dbm;
    double avg_packet_loss;
    size_t unique_cells;
    int64_t first_epoch, last_epoch;
} CaStats;

typedef struct {
    char cell_id[CA_ID_LEN];
    CaStats stats;
} CaCellStats;

typedef enum {
    CA_SEV_LOW = 0, CA_SEV_MEDIUM, CA_SEV_HIGH, CA_SEV_CRITICAL
} CaSeverity;

typedef struct {
    char cell_id[CA_ID_LEN];
    char metric[24];      /* drop_rate, setup_failure_rate, avg_signal_dbm, avg_packet_loss */
    double value;         /* this cell */
    double baseline;      /* median across cells */
    double z_score;       /* robust z-score, positive = worse */
    CaSeverity severity;
    size_t calls;         /* calls behind the value */
} CaAnomaly;

const char *ca_version(void);
const char *ca_strerror(int status);
const char *ca_severity_name(CaSeverity severity);
CaOutcome ca_outcome(int status_code);
void ca_free(void *ptr);

/* Parse CSV text in memory (need not be NUL-terminated). Invalid rows are
 * skipped and counted in report, which may be NULL. */
int ca_parse_buffer(const char *data, size_t len, CaRecord **records,
                    size_t *count, CaParseReport *report);

/* Read a whole file and parse it. */
int ca_parse_file(const char *path, CaRecord **records, size_t *count,
                  CaParseReport *report);

int ca_stats(const CaRecord *records, size_t count, CaStats *out);

/* One entry per cell, sorted by cell_id. */
int ca_cell_stats(const CaRecord *records, size_t count,
                  CaCellStats **cells, size_t *cell_count);

/* Compare every cell with its peers using median and MAD (robust z-score).
 * Cells with fewer than min_calls calls are ignored. Results are sorted
 * worst first. */
int ca_detect_anomalies(const CaCellStats *cells, size_t cell_count,
                        double z_threshold, size_t min_calls,
                        CaAnomaly **anomalies, size_t *anomaly_count);

#ifdef __cplusplus
}
#endif

#endif /* CALLANALYZER_H */
