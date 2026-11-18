# Multi-queue tap lab (measurement topology)

The socket-link lab is single-queue.  To test a realistic multi-queue server,
create a host bridge and four multi-queue taps.  This needs host root (or
CAP_NET_ADMIN), so run this once in your terminal:

```bash
sudo bash lab/mq-setup.sh
```

It creates `br-cve` and `tap-cve-{target,instrumented,legacy,attacker}`,
owned by your user, each attached to the bridge.  Teardown:

```bash
sudo bash lab/mq-teardown.sh
```

Boot a role on the tap link:

```bash
cd <project-root>
LAB_NET=tap NO_WAIT=1 bash lab/launch.sh target      # or legacy-debug / attacker
sleep 15
bash lab/ssh.sh target 'echo ok'
bash lab/labnet.sh target                             # configure 192.168.89.2
```

The QEMU management NIC stays on user-net (SSH `:2223` / `:2224`); only the
lab NIC is the tap.  In the guest, configure queues and RFS:

```bash
bash lab/ssh.sh target 'sudo sh /mnt/lab/lab/mq-config.sh ens4'
```

If QEMU cannot open the tap as your user (`Operation not permitted`), run the
launch script with `sudo` or grant the QEMU binary CAP_NET_ADMIN.  The tap
devices are already owned by your user, so the normal path should work.
