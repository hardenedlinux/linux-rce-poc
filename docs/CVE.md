# CVE-2026-98432 — CVE record and references

Last checked: **2026-11-19**. Vendor scores, affected ranges and patch status
change; use the linked trackers for the current state.

## Identification

| Field | Value |
|---|---|
| CVE | **CVE-2026-98432** |
| Class | Use-after-free (race condition) |
| Component | Linux kernel IPv4 TCP handshake (`inet_opt` / `ireq_opt`) |
| Reachability | Remote, unauthenticated; TCP SYN/retransmission path |
| Public research | Anthropic Frontier Red Team, 2026-10-27 |
| Upstream fix | `e3f33b0a1d89` — “ipv4: free inet_opt and ireq_opt after an RCU grace period” |
| Lab target | Ubuntu 24.04.4, `6.8.0-106-generic`, stock cmdline — vulnerable |

## Root cause

`tcp_v4_syn_recv_sock()` transfers ownership of `ireq->ireq_opt` to the child
socket (`newinet->inet_opt`) without copying it. Another CPU can process a
retransmitted SYN for the same request socket and build a SYN-ACK from
`tcp_check_req()`.

`tcp_v4_send_synack()` and `inet_csk_route_req()` read `ireq->ireq_opt` under
`rcu_read_lock()` only, and `ip_build_and_send_pkt()` / `ip_options_build()`
then read `opt->optlen` twice. The child socket can be destroyed while the
SYN-ACK is still being built. `inet_sock_destruct()` frees `inet_opt` with a
plain `kfree()` instead of `kfree_rcu()`, producing the use-after-free.

The request-socket migration variant is analogous: `inet_reqsk_clone()` makes
the old request and its clone share `ireq_opt`; `tcp_v4_reqsk_destructor()`
frees it with a plain `kfree()`. That path requires
`net.ipv4.tcp_migrate_req=1` or a BPF `SK_REUSEPORT` migration program.

## Fix

The upstream fix changes the two destructors to free the options after an RCU
grace period:

`inet_sock_destruct()` in `net/ipv4/af_inet.c`:

```diff
-	kfree(rcu_dereference_protected(inet->inet_opt, 1));
+	kfree_rcu(rcu_dereference_protected(inet->inet_opt, 1), rcu);
```

`tcp_v4_reqsk_destructor()` in `net/ipv4/tcp_ipv4.c`:

```diff
-	kfree(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1));
+	kfree_rcu(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1), rcu);
```

Upstream commit: `e3f33b0a1d89` (“ipv4: free inet_opt and ireq_opt after an
RCU grace period”). The CVE record and the patch are in the kernel security
repository linked below.

## Affected and fixed versions

* Ubuntu’s advisory and public trackers describe the issue as affecting Linux
  **4.4 and later**; the exact range depends on the vendor backport. Use the
  vendor tracker for your kernel.
* The **Ubuntu 24.04.4 `6.8.0-106-generic`** image used by this lab is
  vulnerable. Ubuntu 24.04 is fixed in **`6.8.0-149.149`**; the 2026-11-09
  blog announced the proposed packages, and the fix was subsequently released
  to the security/updates pocket in mid-November 2026. Check the Ubuntu CVE
  page and security notices for the current package state.
* Multiple vendors have shipped fixes (for example Red Hat, AlmaLinux and
  Amazon Linux); see the references below. Do not assume an image is fixed
  from the kernel version alone.

## Severity and impact

* The kernel CNA score reported for CVE-2026-98432 is **9.8**; Red Hat rates it
  **Important (8.1)**. Public vendor scores range from about **5.9 to 9.8**
  because they weight the race and the service assumptions differently.
* The bug is reachable before application-level authentication: it is in the
  TCP handshake, not in a particular daemon.
* The public research demonstrated remote root against a server with an
  **MPTCP listener**. This lab reproduces that path with target-side
  instrumentation. The plain-TCP path (for example `sshd`) is described by the
  advisory but is **not solved** by this lab; see `../README.md` and
  `CAPABILITY.md`.

## Check your own kernel

```sh
uname -r
cat /proc/cmdline

# On Ubuntu with Ubuntu Pro:
pro fix CVE-2026-98432 --dry-run
```

Compare the installed kernel with the Ubuntu CVE page before relying on a
version number. For this lab, `6.8.0-106-generic` is the vulnerable baseline.

## Mitigation notes

Vendor guidance includes updating the kernel and, where patching is not yet
possible, dropping IPv4 packets with options at the network edge (and
restricting MPTCP where it is not needed). Validate any such rule against
legitimate traffic before deploying it; IPv4 options are rare but not
forbidden. This repository is a lab PoC, not a mitigation guide.

## References

* NVD — <https://nvd.nist.gov/vuln/detail/CVE-2026-98432>
* Kernel CVE record (mbox) — <https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2026/CVE-2026-98432.mbox>
* Red Hat CVE — <https://access.redhat.com/security/cve/CVE-2026-98432>
* Red Hat bug 2553390 — <https://bugzilla.redhat.com/show_bug.cgi?id=2553390>
* Red Hat RHSB-2026-016 — <https://access.redhat.com/security/vulnerabilities/RHSB-2026-016>
* Ubuntu CVE page — <https://ubuntu.com/security/CVE-2026-98432>
* Ubuntu fix status (proposed pocket) — <https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432>
* Akamai research — <https://www.akamai.com/blog/security-research/cve-2026-98432-remote-uaf-linux-kernels-tcp-stack>
* Anthropic Frontier Red Team — <https://www.anthropic.com/research/discovering-vulnerabilities-with-claude>
* AWS security bulletin — <https://aws.amazon.com/security/security-bulletins/2026-160-aws/>
* AlmaLinux advisory — <https://almalinux.org/blog/2026-10-30-cve-2026-98432/>
* Cloud Security Alliance research note — <https://labs.cloudsecurityalliance.org/research/csa-research-note-linux-tcp-mptcp-cve-2026-98432-20261101-cs/>

## Scope of this document

This page records public CVE information for context. The exploitability and
lab results are documented in [`../README.md`](../README.md),
[`CAPABILITY.md`](CAPABILITY.md) and [`SETTINGS.md`](SETTINGS.md). The lab is
authorized local research only; do not run the exploit against systems you do
not own or have written permission to test.
