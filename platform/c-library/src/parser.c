/*
 * parser.c - CSV call-log parsing and per-row validation.
 *
 * Supported CSV dialect: comma separator, optional header line, optional
 * UTF-8 BOM, LF or CRLF line endings, blank lines ignored, RFC 4180 style
 * double-quoted fields ("" escapes a quote) without embedded newlines.
 */
#include <stdio.h>
#include <string.h>

#include "ca_internal.h"

#define CA_NUM_COLUMNS 8
#define CA_MAX_FIELD_BYTES 64
#define CA_READ_CHUNK 8192
#define CA_INITIAL_CAPACITY 256
/* Row messages leave room for the "line N: " prefix in ParseReport. */
#define CA_ROW_ERROR_LEN 96

static const char *const k_columns[CA_NUM_COLUMNS] = {
    "timestamp", "caller", "callee", "cell_id",
    "duration", "status_code", "signal_strength", "packet_loss",
};

typedef struct {
    FILE *fp;
    const char *mem;
    size_t mem_len;
    size_t mem_pos;
    char chunk[CA_READ_CHUNK];
    size_t chunk_len;
    size_t chunk_pos;
    int io_error;
} LineSource;

typedef struct {
    char values[CA_NUM_COLUMNS][CA_MAX_FIELD_BYTES];
    size_t count;
} CsvFields;

void parse_options_default(ParseOptions *opts)
{
    if (opts == NULL) {
        return;
    }
    opts->strict = 0;
    opts->max_records = CA_DEFAULT_MAX_RECORDS;
}

void free_call_records(CallRecord *records)
{
    ca_free(records);
}

/* ---- Line reading ---------------------------------------------------------- */

static int source_getc(LineSource *src)
{
    if (src->fp == NULL) {
        if (src->mem_pos >= src->mem_len) {
            return EOF;
        }
        return (unsigned char)src->mem[src->mem_pos++];
    }
    if (src->chunk_pos >= src->chunk_len) {
        src->chunk_len = fread(src->chunk, 1, sizeof src->chunk, src->fp);
        src->chunk_pos = 0;
        if (src->chunk_len == 0) {
            if (ferror(src->fp)) {
                src->io_error = 1;
            }
            return EOF;
        }
    }
    return (unsigned char)src->chunk[src->chunk_pos++];
}

/*
 * Reads one line into `line` (capacity `cap`), without the line terminator.
 * Over-long lines are consumed to the end and flagged. Returns 0 at EOF.
 */
static int read_line(LineSource *src, char *line, size_t cap, int *too_long, int *has_nul)
{
    size_t len = 0;
    int any = 0;
    int c;

    *too_long = 0;
    *has_nul = 0;
    while ((c = source_getc(src)) != EOF) {
        any = 1;
        if (c == '\n') {
            break;
        }
        if (c == '\0') {
            *has_nul = 1;
        }
        if (len + 1 < cap) {
            line[len++] = (char)c;
        } else {
            *too_long = 1;
        }
    }
    if (!any) {
        return 0;
    }
    if (len > 0 && line[len - 1] == '\r') {
        len--;
    }
    line[len] = '\0';
    return 1;
}

/* ---- CSV splitting --------------------------------------------------------- */

static int is_blank(char c)
{
    return c == ' ' || c == '\t';
}

static int line_is_blank(const char *line)
{
    for (; *line != '\0'; line++) {
        if (!is_blank(*line)) {
            return 0;
        }
    }
    return 1;
}

static int split_csv(const char *line, CsvFields *out, char *err, size_t err_size)
{
    const char *p = line;

    out->count = 0;
    for (;;) {
        char *dst;
        size_t len = 0;

        if (out->count == CA_NUM_COLUMNS) {
            snprintf(err, err_size, "too many fields (expected %d)", CA_NUM_COLUMNS);
            return CA_ERR_PARSE;
        }
        dst = out->values[out->count];
        while (is_blank(*p)) {
            p++;
        }
        if (*p == '"') {
            p++;
            for (;;) {
                if (*p == '\0') {
                    snprintf(err, err_size, "unterminated quoted field %zu", out->count + 1);
                    return CA_ERR_PARSE;
                }
                if (*p == '"') {
                    if (p[1] != '"') {
                        p++;
                        break;
                    }
                    p++;
                }
                if (len + 1 >= CA_MAX_FIELD_BYTES) {
                    snprintf(err, err_size, "field %zu too long", out->count + 1);
                    return CA_ERR_OVERFLOW;
                }
                dst[len++] = *p++;
            }
            while (is_blank(*p)) {
                p++;
            }
            if (*p != ',' && *p != '\0') {
                snprintf(err, err_size, "unexpected character after quoted field %zu",
                         out->count + 1);
                return CA_ERR_PARSE;
            }
        } else {
            while (*p != ',' && *p != '\0') {
                if (*p == '"') {
                    snprintf(err, err_size, "stray quote in field %zu", out->count + 1);
                    return CA_ERR_PARSE;
                }
                if (len + 1 >= CA_MAX_FIELD_BYTES) {
                    snprintf(err, err_size, "field %zu too long", out->count + 1);
                    return CA_ERR_OVERFLOW;
                }
                dst[len++] = *p++;
            }
            while (len > 0 && is_blank(dst[len - 1])) {
                len--;
            }
        }
        dst[len] = '\0';
        out->count++;
        if (*p == '\0') {
            return CA_OK;
        }
        p++; /* skip ',' */
    }
}

/* ---- Row interpretation ---------------------------------------------------- */

static int ascii_equal_ci(const char *a, const char *b)
{
    for (; *a != '\0' && *b != '\0'; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
    }
    return *a == *b;
}

static int looks_like_header(const CsvFields *fields)
{
    return fields->count > 0 && ascii_equal_ci(fields->values[0], k_columns[0]);
}

static int validate_header(const CsvFields *fields, char *err, size_t err_size)
{
    if (fields->count != CA_NUM_COLUMNS) {
        snprintf(err, err_size, "header has %zu columns, expected %d", fields->count,
                 CA_NUM_COLUMNS);
        return CA_ERR_PARSE;
    }
    for (size_t i = 0; i < CA_NUM_COLUMNS; i++) {
        if (!ascii_equal_ci(fields->values[i], k_columns[i])) {
            snprintf(err, err_size, "header column %zu is not '%s'", i + 1, k_columns[i]);
            return CA_ERR_PARSE;
        }
    }
    return CA_OK;
}

static int parse_identifier(const char *value, int (*valid)(const char *), const char *name,
                            char *dst, char *err, size_t err_size)
{
    if (strlen(value) >= CA_FIELD_LEN) {
        snprintf(err, err_size, "%s longer than %d characters", name, CA_FIELD_LEN - 1);
        return CA_ERR_OVERFLOW;
    }
    if (!valid(value)) {
        snprintf(err, err_size, "invalid %s", name);
        return CA_ERR_PARSE;
    }
    return ca_copy_string(dst, CA_FIELD_LEN, value);
}

static int parse_int_field(const char *value, const char *name, long min, long max, int *out,
                           char *err, size_t err_size)
{
    const int rc = ca_parse_int(value, min, max, out);
    if (rc == CA_ERR_PARSE) {
        snprintf(err, err_size, "%s is not an integer", name);
    } else if (rc != CA_OK) {
        snprintf(err, err_size, "%s out of range [%ld, %ld]", name, min, max);
    }
    return rc;
}

static int build_record(const CsvFields *f, CallRecord *r, char *err, size_t err_size)
{
    int rc;

    if (f->count != CA_NUM_COLUMNS) {
        snprintf(err, err_size, "expected %d fields, got %zu", CA_NUM_COLUMNS, f->count);
        return CA_ERR_PARSE;
    }
    memset(r, 0, sizeof *r);

    rc = ca_parse_timestamp(f->values[0], &r->epoch_seconds);
    if (rc != CA_OK) {
        snprintf(err, err_size, "invalid timestamp");
        return rc;
    }
    ca_format_epoch(r->epoch_seconds, r->timestamp, sizeof r->timestamp);

    if ((rc = parse_identifier(f->values[1], ca_valid_party, "caller", r->caller, err,
                               err_size)) != CA_OK ||
        (rc = parse_identifier(f->values[2], ca_valid_party, "callee", r->callee, err,
                               err_size)) != CA_OK ||
        (rc = parse_identifier(f->values[3], ca_valid_cell_id, "cell_id", r->cell_id, err,
                               err_size)) != CA_OK) {
        return rc;
    }
    if ((rc = parse_int_field(f->values[4], "duration", 0, CA_MAX_DURATION_SECONDS,
                              &r->duration, err, err_size)) != CA_OK ||
        (rc = parse_int_field(f->values[5], "status_code", CA_MIN_STATUS_CODE,
                              CA_MAX_STATUS_CODE, &r->status_code, err, err_size)) != CA_OK ||
        (rc = parse_int_field(f->values[6], "signal_strength", CA_MIN_SIGNAL_DBM,
                              CA_MAX_SIGNAL_DBM, &r->signal_strength, err, err_size)) != CA_OK ||
        (rc = parse_int_field(f->values[7], "packet_loss", 0, CA_MAX_PACKET_LOSS_PERCENT,
                              &r->packet_loss, err, err_size)) != CA_OK) {
        return rc;
    }
    return CA_OK;
}

/* ---- Driver ---------------------------------------------------------------- */

static int append_record(CallRecord **buf, size_t *n, size_t *cap, size_t max_records,
                         const CallRecord *record)
{
    if (*n >= max_records) {
        return CA_ERR_LIMIT;
    }
    if (*n == *cap) {
        size_t new_cap = *cap == 0 ? CA_INITIAL_CAPACITY : *cap * 2;
        CallRecord *grown;
        if (new_cap < *cap || new_cap > max_records) {
            new_cap = max_records;
        }
        grown = ca_realloc_array(*buf, new_cap, sizeof **buf);
        if (grown == NULL) {
            return CA_ERR_NOMEM;
        }
        *buf = grown;
        *cap = new_cap;
    }
    (*buf)[(*n)++] = *record;
    return CA_OK;
}

static void note_rejection(ParseReport *rep, int rc, const char *msg)
{
    rep->records_rejected++;
    if (rep->first_error_line == 0) {
        rep->first_error_line = rep->lines_read;
        rep->first_error = rc;
        snprintf(rep->first_error_message, sizeof rep->first_error_message, "line %zu: %s",
                 rep->lines_read, msg);
    }
}

static int parse_source(LineSource *src, const ParseOptions *opts_in, CallRecord **records,
                        size_t *count, ParseReport *report)
{
    ParseOptions opts;
    ParseReport local_report;
    ParseReport *rep = report != NULL ? report : &local_report;
    char line[CA_MAX_LINE_LENGTH + 2]; /* + CR + NUL */
    char err[CA_ROW_ERROR_LEN];
    CsvFields fields;
    CallRecord *buf = NULL;
    size_t n = 0, cap = 0;
    int seen_content = 0;
    int too_long, has_nul;
    int rc = CA_OK;

    memset(rep, 0, sizeof *rep);
    parse_options_default(&opts);
    if (opts_in != NULL) {
        opts.strict = opts_in->strict;
        if (opts_in->max_records != 0) {
            opts.max_records = opts_in->max_records;
        }
    }

    while (read_line(src, line, sizeof line, &too_long, &has_nul)) {
        const char *text = line;
        CallRecord record;
        int row_rc;

        rep->lines_read++;
        if (rep->lines_read == 1 && strncmp(line, "\xEF\xBB\xBF", 3) == 0) {
            text += 3;
        }

        if (too_long) {
            row_rc = CA_ERR_LIMIT;
            snprintf(err, sizeof err, "line longer than %d bytes", CA_MAX_LINE_LENGTH);
        } else if (has_nul) {
            row_rc = CA_ERR_PARSE;
            snprintf(err, sizeof err, "embedded NUL byte");
        } else if (line_is_blank(text)) {
            continue;
        } else {
            row_rc = split_csv(text, &fields, err, sizeof err);
            if (row_rc == CA_OK && !seen_content && looks_like_header(&fields)) {
                seen_content = 1;
                rc = validate_header(&fields, err, sizeof err);
                if (rc != CA_OK) {
                    note_rejection(rep, rc, err);
                    goto fail;
                }
                rep->header_present = 1;
                continue;
            }
            if (row_rc == CA_OK) {
                row_rc = build_record(&fields, &record, err, sizeof err);
            }
        }
        seen_content = 1;

        if (row_rc != CA_OK) {
            note_rejection(rep, row_rc, err);
            if (opts.strict) {
                rc = row_rc;
                goto fail;
            }
            continue;
        }
        rc = append_record(&buf, &n, &cap, opts.max_records, &record);
        if (rc != CA_OK) {
            goto fail;
        }
        rep->records_parsed++;
    }
    if (src->io_error) {
        rc = CA_ERR_IO;
        goto fail;
    }

    *records = buf;
    *count = n;
    return CA_OK;

fail:
    ca_free(buf);
    rep->records_parsed = 0;
    return rc;
}

int parse_call_log_buffer(const char *data, size_t len, const ParseOptions *opts,
                          CallRecord **records, size_t *count, ParseReport *report)
{
    LineSource src;

    if (records == NULL || count == NULL) {
        return CA_ERR_NULL_ARG;
    }
    *records = NULL;
    *count = 0;
    if (data == NULL && len > 0) {
        return CA_ERR_NULL_ARG;
    }
    memset(&src, 0, sizeof src);
    src.mem = data;
    src.mem_len = len;
    return parse_source(&src, opts, records, count, report);
}

int parse_call_log_ex(const char *filepath, const ParseOptions *opts, CallRecord **records,
                      size_t *count, ParseReport *report)
{
    LineSource src;
    int rc;

    if (records == NULL || count == NULL) {
        return CA_ERR_NULL_ARG;
    }
    *records = NULL;
    *count = 0;
    if (filepath == NULL) {
        return CA_ERR_NULL_ARG;
    }
    memset(&src, 0, sizeof src);
    src.fp = fopen(filepath, "rb");
    if (src.fp == NULL) {
        if (report != NULL) {
            memset(report, 0, sizeof *report);
        }
        return CA_ERR_IO;
    }
    rc = parse_source(&src, opts, records, count, report);
    if (fclose(src.fp) != 0 && rc == CA_OK) {
        free_call_records(*records);
        *records = NULL;
        *count = 0;
        rc = CA_ERR_IO;
    }
    return rc;
}

int parse_call_log(const char *filepath, CallRecord **records, size_t *count)
{
    return parse_call_log_ex(filepath, NULL, records, count, NULL);
}
