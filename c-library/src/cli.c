/*
 * callanalyzer - command-line front end for the library.
 *
 *   callanalyzer calls.csv            human-readable summary
 *   callanalyzer --json calls.csv     machine-readable output
 */
#include "callanalyzer.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void print_json(const CaStats *s, const CaCellStats *cells, size_t nc,
                       const CaAnomaly *an, size_t na, const CaParseReport *rep, double secs)
{
    printf("{\"version\":\"%s\",\"seconds\":%.4f,", ca_version(), secs);
    printf("\"parse\":{\"parsed\":%zu,\"rejected\":%zu},", rep->parsed, rep->rejected);
    printf("\"overall\":{\"total\":%zu,\"success_rate\":%.4f,\"drop_rate\":%.4f,"
           "\"setup_failure_rate\":%.4f,\"unique_cells\":%zu},",
           s->total, s->success_rate, s->drop_rate, s->setup_failure_rate, s->unique_cells);
    printf("\"cells\":[");
    for (size_t i = 0; i < nc; i++)
        printf("%s{\"cell_id\":\"%s\",\"total\":%zu,\"drop_rate\":%.4f,\"setup_failure_rate\":%.4f,"
               "\"avg_signal_dbm\":%.2f,\"avg_packet_loss\":%.2f}",
               i ? "," : "", cells[i].cell_id, cells[i].stats.total, cells[i].stats.drop_rate,
               cells[i].stats.setup_failure_rate, cells[i].stats.avg_signal_dbm,
               cells[i].stats.avg_packet_loss);
    printf("],\"anomalies\":[");
    for (size_t i = 0; i < na; i++)
        printf("%s{\"cell_id\":\"%s\",\"metric\":\"%s\",\"value\":%.4f,\"baseline\":%.4f,"
               "\"z_score\":%.2f,\"severity\":\"%s\"}",
               i ? "," : "", an[i].cell_id, an[i].metric, an[i].value, an[i].baseline,
               an[i].z_score, ca_severity_name(an[i].severity));
    printf("]}\n");
}

static void print_text(const CaStats *s, const CaCellStats *cells, size_t nc,
                       const CaAnomaly *an, size_t na, const CaParseReport *rep, double secs)
{
    printf("callanalyzer %s: %zu calls in %.3f s (%zu rows rejected)\n\n",
           ca_version(), s->total, secs, rep->rejected);
    printf("overall  success %.1f%%  drop %.2f%%  setup failure %.2f%%\n\n",
           100 * s->success_rate, 100 * s->drop_rate, 100 * s->setup_failure_rate);
    printf("%-10s %8s %7s %7s %8s %6s\n", "cell", "calls", "drop%", "fail%", "signal", "loss%");
    for (size_t i = 0; i < nc; i++)
        printf("%-10s %8zu %7.2f %7.2f %8.1f %6.2f\n", cells[i].cell_id, cells[i].stats.total,
               100 * cells[i].stats.drop_rate, 100 * cells[i].stats.setup_failure_rate,
               cells[i].stats.avg_signal_dbm, cells[i].stats.avg_packet_loss);
    printf("\n%zu anomal%s\n", na, na == 1 ? "y" : "ies");
    for (size_t i = 0; i < na; i++)
        printf("  [%-8s] %-10s %-19s %9.3f vs median %9.3f (z=%.1f)\n",
               ca_severity_name(an[i].severity), an[i].cell_id, an[i].metric, an[i].value,
               an[i].baseline, an[i].z_score);
}

int main(int argc, char **argv)
{
    int json = argc == 3 && strcmp(argv[1], "--json") == 0;
    const char *path = argc == 2 ? argv[1] : json ? argv[2] : NULL;
    CaRecord *recs = NULL;
    CaCellStats *cells = NULL;
    CaAnomaly *an = NULL;
    CaParseReport rep;
    CaStats stats;
    size_t n = 0, nc = 0, na = 0;
    double t0;
    int rc;

    if (!path) {
        fprintf(stderr, "usage: %s [--json] calls.csv\n", argv[0]);
        return 2;
    }
    t0 = now_seconds();
    rc = ca_parse_file(path, &recs, &n, &rep);
    if (rc == CA_OK) rc = ca_stats(recs, n, &stats);
    if (rc == CA_OK) rc = ca_cell_stats(recs, n, &cells, &nc);
    if (rc == CA_OK) rc = ca_detect_anomalies(cells, nc, 3.5, 50, &an, &na);
    if (rc != CA_OK) {
        fprintf(stderr, "callanalyzer: %s: %s\n", path, ca_strerror(rc));
        ca_free(recs);
        ca_free(cells);
        return 1;
    }
    if (json) print_json(&stats, cells, nc, an, na, &rep, now_seconds() - t0);
    else print_text(&stats, cells, nc, an, na, &rep, now_seconds() - t0);
    ca_free(recs);
    ca_free(cells);
    ca_free(an);
    return 0;
}
