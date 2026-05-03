

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/termbits.h>  /* Definition of TIOC*WINSZ constants */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h> 
#include <pthread.h>
#include <unistd.h>

#include "wireguard_ffi.h"
#include "wg_bench_client.h"

static void handle_signal(int sig) {
    switch (sig) {
        case SIGINT:
            fprintf(stderr, "benchmark interrupted\n");
            break;

        case SIGTERM:
            fprintf(stderr, "benchmark terminated\n");
            break;
    }
}

static double timespec_elapsed(const struct timespec *a, const struct timespec* b) {
    double result = (a->tv_sec - b->tv_sec) * 1000000000.0;
    return (double)(result + a->tv_nsec - b->tv_nsec) / 1000000000.0;
}

static void print_header() {
    printf("%012s %012s %012s %012s %08s  %-12s\n",
           "TXPKT", "RXPKT", "TXBYTES", "RXBYTES", "ERRORS", "TRANSFERRED");
}

static void print_stats(const struct wg_bench_statistics* st, double elapsed) {
    uintmax_t total_errors = 0;
    uintmax_t total_bytes = atomic_load(&st->tx_bytes) + atomic_load(&st->rx_bytes);
    for (int i = 0; i < WG_BENCH_MAX_ERRORS; i++) {
        total_errors += atomic_load(&st->errors[i]);
    }

    // Estimate the total throughput.
    char xfer[32];
    if (total_bytes > 1000000000) {
        snprintf(xfer, sizeof(xfer), "%.3F GB", total_bytes / 1000000000.0);
    } else if (total_bytes > 1000000) {
        snprintf(xfer, sizeof(xfer), "%.3F MB", total_bytes / 1000000.0);
    } else if (total_bytes > 1000) {
        snprintf(xfer, sizeof(xfer), "%.3F kB", total_bytes / 1000.0);
    } else {
        snprintf(xfer, sizeof(xfer), "%.3F B", total_bytes);
    }

    char tpbuf[32];
    double throughput = (double)total_bytes / elapsed;
    if (throughput > 1000000000) {
        snprintf(tpbuf, sizeof(tpbuf), "%s (%.3F GB/s)", xfer, throughput / 1000000000.0);
    } else if (throughput > 1000000) {
        snprintf(tpbuf, sizeof(tpbuf), "%s (%.3F MB/s)", xfer, throughput / 1000000.0);
    } else if (throughput > 1000) {
        snprintf(tpbuf, sizeof(tpbuf), "%s (%.3F kB/s)", xfer, throughput / 1000.0);
    } else {
        snprintf(tpbuf, sizeof(tpbuf), "%s (%.3F B/s)", xfer, throughput);
    }

    // Prepare the status to write.
    char linebuf[96];
    int len = snprintf(linebuf, sizeof(linebuf), "\r%12lu %12lu %12lu %12lu %8lu  %-s",
                       atomic_load(&st->tx_packets), atomic_load(&st->rx_packets),
                       atomic_load(&st->tx_bytes), atomic_load(&st->rx_bytes),
                       total_errors, tpbuf);

    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        // This is a terminal.
        if (ws.ws_col < sizeof(linebuf)) {
            len = ws.ws_col - 1;
        } else {
            memset(linebuf + len, ' ', sizeof(linebuf) - len);
            len = sizeof(linebuf);
        }
        write(STDOUT_FILENO, linebuf, len);

    } else {
        // Some other file.
        linebuf[len] = '\n';
        linebuf[len+1] = '\0';
        puts(linebuf+1);
    }
}

static void print_usage(FILE* fp, const char* name) {
    fprintf(fp, "Usage: %s [OPTIONS]\n");
    fprintf(fp, "Run FFI benchmarks for the boringtun library.\n");
    fprintf(fp, "\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "\t--jobs, -j NUM   create NUM parallel threads\n");
    fprintf(fp, "\t--help, -h       display this message and exit\n");
}

int main(int argc, char* argv[]) {
    const char* shortopts = "hj:";
    const struct option longopts[] = {
        {"help", no_argument,       0, 'h'},
        {"jobs", required_argument, 0, 'j'},
        {NULL, 0, 0, 0}
    };
    unsigned int num_workers = 1;

    // Parse options
    while (true) {
        int index;
        int opt = getopt_long(argc, argv, shortopts, longopts, &index);
        if (opt < 0) {
            break;
        }

        char* endp;
        switch (opt) {
            case 'j':
                num_workers = strtoul(optarg, &endp, 10);
                if (*endp != '\0' || (num_workers == 0)) {
                    fprintf(stderr, "Invalid thread count: %s\n", optarg);
                    return 1;
                }
                break;

            case 'h':
                print_usage(stdout, argv[0]);
                return 0;
            
            default:
                break;
        }
    }

    srand(time(0));

    // This thread should handle signals.
    struct sigaction action = {
        .sa_handler = handle_signal,
    };
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    // Create a socket pair for the two clients to communicate over.
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);

    // Create two benchmark clients.
    struct wg_bench_client* a = wg_bench_create(sv[0]);
    struct wg_bench_client* b = wg_bench_create(sv[1]);

    // Connect the two clients.
    wg_bench_connect(a, b->pubkey);
    wg_bench_connect(b, a->pubkey);

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    end.tv_sec = start.tv_sec + 10;
    end.tv_nsec = start.tv_nsec;
    print_header();

    // Launch workers.
    wg_bench_start_handshake(a);
    for (int i = 0; i < num_workers; i++) {
        wg_bench_start_recv(a);
        wg_bench_start_recv(b);
        wg_bench_start_send(a);
        wg_bench_start_send(b);
    }

    do {
        struct timespec now;
        struct wg_bench_statistics stats;
        clock_gettime(CLOCK_MONOTONIC, &now);

        // Fetch and render the statistics.
        memset(&stats, 0, sizeof(stats));
        wg_bench_fetch_stats(a, &stats);
        wg_bench_fetch_stats(b, &stats);
        print_stats(&stats, timespec_elapsed(&now, &start));

        // Check for the end condition.
        if (end.tv_sec > now.tv_sec) continue;
        if (end.tv_sec < now.tv_sec) break;
        if (end.tv_nsec < now.tv_nsec) break;
    } while(usleep(100000) == 0);
    printf("\n");

    wg_bench_close(a);
    wg_bench_close(b);
}
