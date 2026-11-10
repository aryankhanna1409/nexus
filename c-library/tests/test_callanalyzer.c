/* Unit tests for libcallanalyzer. Run with `make -C c-library test`. */
#include "callanalyzer.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                 \
        }                                                               \
    } while (0)

static int parse(const char *csv, CaRecord **r, size_t *n, CaParseReport *rep)
{
    return ca_parse_buffer(csv, strlen(csv), r, n, rep);
}

static void test_valid_rows_and_header(void)
{
    const char *csv =
        "timestamp,caller,callee,cell_id,duration,status_code,signal_strength,packet_loss\r\n"
        "2026-03-01T14:05:00Z,+15550001,+15550002,CELL-102,184,200,-82,1\n"
        "\n"
        "2024-02-29T23:59:59,+1,+2,CELL-1,0,903,-150,100\n";
    CaRecord *r;
    size_t n;
    CaParseReport rep;
    CHECK(parse(csv, &r, &n, &rep) == CA_OK);
    CHECK(n == 2 && rep.parsed == 2 && rep.rejected == 0 && rep.lines == 4);
    CHECK(strcmp(r[0].cell_id, "CELL-102") == 0);
    CHECK(r[0].epoch == 1772373900);  /* 2026-03-01T14:05:00Z */
    CHECK(r[1].status_code == 903 && r[1].signal_dbm == -150);
    ca_free(r);
}

static void test_bad_rows_are_rejected_not_fatal(void)
{
    const char *csv =
        "2026-02-30T00:00:00Z,+1,+2,C1,10,200,-80,0\n"   /* no Feb 30 */
        "2026-03-01T00:00:00Z,+1,+2,C1,-1,200,-80,0\n"   /* negative duration */
        "2026-03-01T00:00:00Z,+1,+2,C1,10,1000,-80,0\n"  /* status out of range */
        "2026-03-01T00:00:00Z,+1,+2,C 1,10,200,-80,0\n"  /* space in cell id */
        "2026-03-01T00:00:00Z,+1,+2,C1,10,200,-80\n"     /* missing column */
        "2026-03-01T00:00:00Z,+1,+2,C1,10,200,-80,0,9\n" /* extra column */
        "2026-03-01T00:00:00Z,+1,+2,C1,1x,200,-80,0\n"   /* junk number */
        "2026-03-01T00:00:00Z,+1,+2,C1,10,200,-80,0\n";  /* the one good row */
    CaRecord *r;
    size_t n;
    CaParseReport rep;
    CHECK(parse(csv, &r, &n, &rep) == CA_OK);
    CHECK(n == 1 && rep.rejected == 7);
    CHECK(rep.first_error_line == 1 && strcmp(rep.first_error, "bad timestamp") == 0);
    ca_free(r);
}

static void test_long_line_and_long_id(void)
{
    char csv[2 * CA_MAX_LINE];
    CaRecord *r;
    size_t n;
    CaParseReport rep;
    memset(csv, 'a', sizeof(csv) - 2);
    csv[sizeof(csv) - 2] = '\n';
    csv[sizeof(csv) - 1] = '\0';
    CHECK(parse(csv, &r, &n, &rep) == CA_OK && n == 0 && rep.rejected == 1);
    ca_free(r);

    CHECK(parse("2026-03-01T00:00:00Z,+1,+2,CELL-0123456789012345678901234567,1,200,-80,0\n",
                &r, &n, &rep) == CA_OK);
    CHECK(n == 0 && strcmp(rep.first_error, "bad cell_id") == 0);
    ca_free(r);
}

static void test_null_args_and_empty(void)
{
    CaRecord *r = (CaRecord *)1;
    size_t n = 9;
    CaStats s;
    CHECK(ca_parse_buffer(NULL, 5, &r, &n, NULL) == CA_ERR_NULL_ARG);
    CHECK(ca_parse_buffer("", 0, &r, &n, NULL) == CA_OK && r == NULL && n == 0);
    CHECK(ca_parse_file("/no/such/file.csv", &r, &n, NULL) == CA_ERR_IO);
    CHECK(ca_stats(NULL, 0, &s) == CA_OK && s.total == 0);
}

static void test_statistics(void)
{
    const char *csv =
        "2026-03-01T00:00:00Z,+1,+2,A,100,200,-80,0\n"
        "2026-03-01T00:01:00Z,+1,+2,A,50,901,-90,10\n"
        "2026-03-01T00:02:00Z,+1,+2,B,0,486,-100,2\n"
        "2026-03-01T00:03:00Z,+1,+2,B,0,180,-70,0\n";
    CaRecord *r;
    size_t n, nc;
    CaStats s;
    CaCellStats *cells;
    CHECK(parse(csv, &r, &n, NULL) == CA_OK && n == 4);
    CHECK(ca_stats(r, n, &s) == CA_OK);
    CHECK(s.completed == 1 && s.dropped == 1 && s.setup_failed == 1 && s.unknown == 1);
    CHECK(fabs(s.drop_rate - 0.5) < 1e-9);          /* 1 dropped of 2 established */
    CHECK(fabs(s.setup_failure_rate - 0.25) < 1e-9);
    CHECK(fabs(s.avg_duration - 75.0) < 1e-9);
    CHECK(s.unique_cells == 2 && s.last_epoch - s.first_epoch == 180);
    CHECK(ca_cell_stats(r, n, &cells, &nc) == CA_OK && nc == 2);
    CHECK(strcmp(cells[0].cell_id, "A") == 0 && cells[0].stats.total == 2);
    CHECK(fabs(cells[1].stats.avg_signal_dbm + 85.0) < 1e-9);
    ca_free(cells);
    ca_free(r);
}

static void test_anomaly_flags_only_the_bad_cell(void)
{
    CaCellStats cells[8];
    CaAnomaly *an;
    size_t na;
    memset(cells, 0, sizeof(cells));
    for (int i = 0; i < 8; i++) {
        snprintf(cells[i].cell_id, CA_ID_LEN, "CELL-%d", 101 + i);
        cells[i].stats.total = 500;
        cells[i].stats.drop_rate = 0.010 + 0.001 * i;
        cells[i].stats.setup_failure_rate = 0.02;
        cells[i].stats.avg_signal_dbm = -85.0 - 0.3 * i;
        cells[i].stats.avg_packet_loss = 0.5;
    }
    cells[3].stats.drop_rate = 0.12;
    cells[3].stats.avg_packet_loss = 6.0;
    CHECK(ca_detect_anomalies(cells, 8, 3.5, 50, &an, &na) == CA_OK);
    CHECK(na == 2);
    for (size_t i = 0; i < na; i++) CHECK(strcmp(an[i].cell_id, "CELL-104") == 0);
    CHECK(na == 2 && an[0].z_score >= an[1].z_score);
    ca_free(an);

    /* Fewer than 5 eligible peers: no baseline, no anomalies. */
    CHECK(ca_detect_anomalies(cells, 4, 3.5, 50, &an, &na) == CA_OK && na == 0 && an == NULL);
    CHECK(ca_detect_anomalies(cells, 8, 0.0, 50, &an, &na) == CA_ERR_PARSE);
}

int main(void)
{
    test_valid_rows_and_header();
    test_bad_rows_are_rejected_not_fatal();
    test_long_line_and_long_id();
    test_null_args_and_empty();
    test_statistics();
    test_anomaly_flags_only_the_bad_cell();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("c tests: all passed\n");
    return 0;
}
