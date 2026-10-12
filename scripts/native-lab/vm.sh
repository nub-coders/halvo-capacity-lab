#!/usr/bin/env bash
# Ubuntu 24.04 guest with its own kernel. Host packages/services are never changed.
set -euo pipefail
umask 077
prepare=false
resume=false
network_only=false
benchmark_only=false
runtime_tree_only=false
case "${1:-}" in
  --prepare) prepare=true; shift ;;
  --resume) resume=true; shift ;;
  --network-only) resume=true; network_only=true; shift ;;
  --benchmark-only) resume=true; benchmark_only=true; shift ;;
  --runtime-tree-only) resume=true; runtime_tree_only=true; shift ;;
esac
if [ "$(id -u)" != 0 ] || [ "$#" != 1 ] || [[ ! "$1" =~ ^/var/tmp/halvo-native-vm-[A-Za-z0-9_-]+$ ]]; then
  echo 'Usage: sudo bash scripts/native-lab/vm.sh [--prepare|--resume|--network-only|--benchmark-only|--runtime-tree-only] /var/tmp/halvo-native-vm-NAME' >&2
  exit 1
fi
. /etc/os-release
# The guest is pinned to the 24.04 cloud image below and is independent of the
# host distro (TCG emulation, self-contained qemu extraction), so the host may
# move on: 24.04 is where the lab was validated, 26.04 is the current host.
# Everything guest-side keeps its pins regardless.
case "$ID:$VERSION_ID:$(uname -m)" in
  ubuntu:24.04:x86_64|ubuntu:26.04:x86_64) ;;
  *) echo 'This runner requires an Ubuntu 24.04 or 26.04 x86-64 host.' >&2; exit 1 ;;
esac
lab_dir="$1"
source_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
if [ -e "$lab_dir" ] || [ -L "$lab_dir" ]; then
  if [ -L "$lab_dir" ] || [ ! -d "$lab_dir" ] ||
     [ "$(stat -c '%u:%a' "$lab_dir")" != 0:700 ] ||
     [ ! -f "$lab_dir/.halvo-native-vm" ] || [ -L "$lab_dir/.halvo-native-vm" ] ||
     [ "$(cat "$lab_dir/.halvo-native-vm")" != qemu-phase0-v1 ]; then
    echo 'Refusing a directory not exclusively owned by this VM lab.' >&2; exit 1
  fi
else
  mkdir -m 0700 "$lab_dir"
  printf 'qemu-phase0-v1\n' > "$lab_dir/.halvo-native-vm"
fi
# The root-owned 0700 parent prevents other users replacing these paths.
if find "$lab_dir" -maxdepth 1 -type l -print -quit | read -r _; then
  echo 'Refusing symlinks in the lab directory.' >&2; exit 1
fi
exec 9> "$lab_dir/lock"
flock -n 9 || { echo 'This VM lab is already running.' >&2; exit 1; }
mkdir -p "$lab_dir/downloads" "$lab_dir/tools" "$lab_dir/seed" "$lab_dir/results"
tools_dir="$lab_dir/tools"
local_libs="$tools_dir/usr/lib/x86_64-linux-gnu:$tools_dir/lib/x86_64-linux-gnu"
local_tool() { env LD_LIBRARY_PATH="$local_libs" QEMU_MODULE_DIR="$tools_dir/usr/lib/x86_64-linux-gnu/qemu" "$tools_dir/usr/bin/$@"; }

if [ ! -f "$lab_dir/.tools-ready" ]; then
  # Ask apt to resolve its signed package metadata, then only download/extract.
  LC_ALL=C apt-get --simulate --no-install-recommends --no-upgrade --reinstall install \
    qemu-system-x86 qemu-utils genisoimage > "$lab_dir/tools-plan.log"
  mapfile -t packages < <(awk '/^Inst / { for (i=3; i<=NF; i++) if (substr($i,1,1)=="(") { print $2 "=" substr($i,2); break } }' "$lab_dir/tools-plan.log")
  if [ "${#packages[@]}" = 0 ]; then echo 'No QEMU packages resolved.' >&2; exit 1; fi
  (
    cd "$lab_dir/downloads"
    apt-get download "${packages[@]}" > "$lab_dir/tools-download.log" 2>&1
    for package in ./*.deb; do dpkg-deb -x "$package" "$tools_dir"; done
  )
  local_tool qemu-system-x86_64 --version > "$lab_dir/qemu-version.txt"
  local_tool qemu-img --version >> "$lab_dir/qemu-version.txt"
  local_tool genisoimage --version >> "$lab_dir/qemu-version.txt" 2>&1
  touch "$lab_dir/.tools-ready"
fi

# Pin the actual image bytes: no moving "current" image or silently new checksum.
image_url=https://cloud-images.ubuntu.com/noble/20260926/noble-server-cloudimg-amd64.img
image_sha=6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2
if [ ! -f "$lab_dir/base.img" ]; then
  curl --fail --silent --show-error --location --retry 3 --max-time 900 "$image_url" -o "$lab_dir/base.img.part"
  printf '%s  %s\n' "$image_sha" "$lab_dir/base.img.part" | sha256sum -c -
  mv "$lab_dir/base.img.part" "$lab_dir/base.img"
fi
printf '%s  %s\n' "$image_sha" "$lab_dir/base.img" | sha256sum -c -
printf '%s\n%s\n' "$image_url" "$image_sha" > "$lab_dir/image-source.txt"
if [ ! -f "$lab_dir/guest.qcow2" ]; then
  local_tool qemu-img create -f qcow2 -F qcow2 -b "$lab_dir/base.img" "$lab_dir/guest.qcow2" 16G
fi
if [ ! -f "$lab_dir/vm-id" ]; then cat /proc/sys/kernel/random/uuid > "$lab_dir/vm-id"; fi
for key in client-key host-key; do
  if [ ! -f "$lab_dir/$key" ]; then
    ssh-keygen -q -t ed25519 -N '' -C halvo-disposable-lab -f "$lab_dir/$key"
  fi
done
python3 - "$lab_dir" <<'PY'
import json, re, sys
from pathlib import Path
lab = Path(sys.argv[1])
vm_id = (lab / 'vm-id').read_text().strip()
assert re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', vm_id)
config = {
    'hostname': 'halvo-native-lab', 'disable_root': True, 'ssh_pwauth': False,
    'users': [{'name': 'lab', 'shell': '/bin/bash', 'lock_passwd': True,
               'sudo': ['ALL=(ALL) NOPASSWD:ALL'],
               'ssh_authorized_keys': ['restrict ' + (lab / 'client-key.pub').read_text().strip()]}],
    'ssh_keys': {'ed25519_private': (lab / 'host-key').read_text(),
                 'ed25519_public': (lab / 'host-key.pub').read_text()},
    'write_files': [
        {'path': '/etc/halvo-native-lab', 'permissions': '0600', 'content': 'qemu-phase0-v1\n'},
        {'path': '/etc/halvo-native-lab-vm-id', 'permissions': '0600', 'content': vm_id + '\n'},
    ],
}
(lab / 'seed/user-data').write_text('#cloud-config\n' + json.dumps(config))
(lab / 'seed/meta-data').write_text(json.dumps({'instance-id': vm_id, 'local-hostname': 'halvo-native-lab'}))
PY
local_tool genisoimage -quiet -output "$lab_dir/seed.iso" -volid cidata -joliet -rock \
  "$lab_dir/seed/user-data" "$lab_dir/seed/meta-data"
if "$prepare"; then
  printf 'Prepared without booting: %s\nRun: sudo bash %s %s\n' "$lab_dir" "$0" "$lab_dir"
  exit 0
fi

payload=(provision.sh probe.py network_probe.py benchmark.py syscalls.policy guard.py static-package-lock.json runtime_tree.py runtime-tree-manifest.json)
for file in "${payload[@]}"; do
  if [ ! -f "$source_dir/$file" ] || [ -L "$source_dir/$file" ]; then
    echo "Missing regular allowlisted input: $file" >&2; exit 1
  fi
done
port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)"
# The calibrated 2-vCPU shape is the measurement default. The runtime-tree
# build is not a measurement — it is hours of TCG emulation — so its mode may
# take more of the host via HALVO_LAB_TREE_CPUS (guest vCPUs = host CPUs pinned,
# capped at half the machine). The evidence file records what was used.
tree_cpus="${HALVO_LAB_TREE_CPUS:-2}"
case "$tree_cpus" in ''|*[!0-9]*|0*) tree_cpus=2 ;; esac
[ "$runtime_tree_only" = true ] && [ "$tree_cpus" -gt 8 ] && tree_cpus=8
[ "$runtime_tree_only" != true ] && tree_cpus=2
cpu_ids="$(python3 -c "import os; print(','.join(map(str, sorted(os.sched_getaffinity(0))[:$tree_cpus])))")"
printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$lab_dir/host-key.pub")" > "$lab_dir/known-hosts"
ssh_args=(-F /dev/null -i "$lab_dir/client-key" -p "$port" -o BatchMode=yes
  -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$lab_dir/known-hosts"
  -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=3 -o ConnectionAttempts=1
  -o ServerAliveInterval=10 -o ServerAliveCountMax=3 lab@127.0.0.1)
ssh_guest() { ssh "${ssh_args[@]}" "$@"; }
qemu_pid=''
cleanup() {
  if [ -n "$qemu_pid" ] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
result_dir="$lab_dir/results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$result_dir"
# Two CPU cores, 2.5 GiB guest RAM, 6 GiB maximum address space, 70 minute lifetime.
# No host directories, disks, service sockets, credentials, or public listeners.
# QEMU's setuid/setgid drop needs elevateprivileges=allow; -runas removes all root
# IDs before guest execution, while seccomp still applies NoNewPrivs and denies spawn.
# Hardware virtualization when the host exposes a usable /dev/kvm (KVM-capable
# runners); fall back to TCG software emulation otherwise. KVM rejects the
# TCG-only thread option.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  qemu_accel=kvm
else
  qemu_accel=tcg,thread=multi
fi
timeout --signal=TERM --kill-after=10s 70m \
  prlimit --as=6442450944 --nofile=1024 --core=0 -- \
  nice -n 10 taskset --cpu-list "$cpu_ids" \
  env -i PATH=/usr/bin:/bin HOME="$lab_dir" TMPDIR="$lab_dir" LD_LIBRARY_PATH="$local_libs" \
  QEMU_MODULE_DIR="$tools_dir/usr/lib/x86_64-linux-gnu/qemu" \
  "$tools_dir/usr/bin/qemu-system-x86_64" \
  -no-user-config -nodefaults -machine q35 -accel "$qemu_accel" -cpu max -smp "$tree_cpus" -m 2560 \
  -uuid "$(cat "$lab_dir/vm-id")" -name halvo-native-lab \
  -L "$tools_dir/usr/share/qemu" -bios "$tools_dir/usr/share/seabios/bios-256k.bin" \
  -drive "file=$lab_dir/guest.qcow2,format=qcow2,if=virtio,discard=unmap" \
  -drive "file=$lab_dir/seed.iso,format=raw,media=cdrom,readonly=on" \
  -netdev "user,id=labnet,hostfwd=tcp:127.0.0.1:$port-:22" \
  -device virtio-net-pci,netdev=labnet,romfile= \
  -display none -monitor none -serial "file:$result_dir/serial.log" \
  -runas nobody -sandbox on,obsolete=deny,elevateprivileges=allow,spawn=deny,resourcecontrol=deny \
  </dev/null > "$result_dir/qemu.log" 2>&1 9>&- &
qemu_pid=$!
wait_guest() {
  local deadline=$((SECONDS + 900))
  until ssh_guest true >/dev/null 2>&1; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
      cat "$result_dir/qemu.log" >&2; echo 'QEMU exited before SSH was ready.' >&2; return 1
    fi
    if (( SECONDS >= deadline )); then echo 'Guest SSH startup timed out.' >&2; return 1; fi
    sleep 3
  done
}
printf 'Booting disposable guest; logs: %s\n' "$result_dir"
wait_guest
ssh_guest 'sudo cloud-init status --wait' > "$result_dir/cloud-init.log" 2>&1
ssh_guest 'sudo install -d -m 0755 /opt/halvo-lab /results'
copy_payload() {
  for file in "${payload[@]}"; do
    test -f "$source_dir/$file" && test ! -L "$source_dir/$file" || return 1
  done
  tar -C "$source_dir" -cf - "${payload[@]}" | ssh_guest 'sudo tar -C /opt/halvo-lab -xf -'
}
copy_payload
sha256sum "${payload[@]/#/$source_dir/}" > "$result_dir/provision-sources.sha256"
printf 'Provisioning only inside the disposable guest.\n'
provision_status=0
if "$resume"; then
  ssh_guest 'sudo bash /opt/halvo-lab/provision.sh --check' > "$result_dir/provision.log" 2>&1 || provision_status=$?
else
# 50 minutes of provision time: a full nsjail compile under software emulation
# exceeds the original 40-minute budget, and the killed-build repair in
# provision.sh needs one clean full build to converge.
timeout --kill-after=10s 50m ssh "${ssh_args[@]}" \
  'sudo timeout --kill-after=10s 49m bash /opt/halvo-lab/provision.sh' \
  > "$result_dir/provision.log" 2>&1 || provision_status=$?
fi
if [ "$provision_status" != 0 ]; then
  echo "Guest provisioning failed ($provision_status); see $result_dir/provision.log" >&2
  exit "$provision_status"
fi
# Provisioning can take time under TCG; record and run the current probe sources.
copy_payload
sha256sum "${payload[@]/#/$source_dir/}" > "$result_dir/lab-sources.sha256"
# Pull diagnostics without extracting guest-controlled paths as host root.
collect_results() {
  timeout --kill-after=10s 2m ssh "${ssh_args[@]}" 'sudo tar -C /results -cf - .' > "$result_dir/guest-results.tar"
  ssh_guest 'sudo journalctl -b --no-pager -n 300' > "$result_dir/journal.log" || true
}
if "$benchmark_only"; then
  printf 'Running dedicated guarded memory fixtures inside the guest.\n'
  benchmark_status=0
  timeout --kill-after=10s 18m ssh "${ssh_args[@]}" \
    'sudo timeout --kill-after=10s 17m python3 /opt/halvo-lab/benchmark.py' \
    > "$result_dir/benchmark.log" 2>&1 || benchmark_status=$?
  ssh_guest 'sudo cat /results/benchmark.json' > "$result_dir/benchmark.json" || true
  collect_results
  if [ "$benchmark_status" != 0 ]; then
    echo "Guest benchmark failed ($benchmark_status); results: $result_dir" >&2
    exit "$benchmark_status"
  fi
  python3 - "$result_dir/benchmark.json" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
assert report['backend'] == 'native' and report['scope'] == 'fixture-process-memory'
assert report['passed'] and len(report['cases']) == 4
print(json.dumps({'passed': report['passed'], 'cases': len(report['cases'])}))
PY
elif "$runtime_tree_only"; then
printf 'Building the pinned python runtime tree inside the guest.\n'
tree_status=0
timeout --kill-after=10s 60m ssh "${ssh_args[@]}" \
  'sudo timeout --kill-after=10s 59m python3 /opt/halvo-lab/runtime_tree.py --manifest /opt/halvo-lab/runtime-tree-manifest.json --results-dir /results' \
  > "$result_dir/runtime-tree.log" 2>&1 || tree_status=$?
ssh_guest 'sudo cat /results/runtime-tree.json' > "$result_dir/runtime-tree.json" || true
collect_results
if [ "$tree_status" != 0 ]; then
  echo "Guest runtime-tree build failed ($tree_status); see $result_dir/runtime-tree.log" >&2
  exit "$tree_status"
fi
python3 - "$result_dir/runtime-tree.json" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
assert report['manifest']['revision'] == '3.13.15'
assert report['sanity']['reports_pinned_revision'] and report['sanity']['pip_available']
print(json.dumps({'interpreter': report['interpreter_path'],
                  'build_seconds': report['build_seconds'],
                  'reused': report['reused'], 'pgo_used': report['pgo_used']}, indent=2))
PY
exit 0
else
if ! "$network_only"; then
printf 'Running the guarded probe inside the guest.\n'
probe_status=0
timeout --kill-after=10s 34m ssh "${ssh_args[@]}" \
  'sudo env HALVO_LAB_KEEP_RUNNING=1 timeout --kill-after=10s 33m python3 /opt/halvo-lab/probe.py' \
  > "$result_dir/probe.log" 2>&1 || probe_status=$?
collect_results
ssh_guest 'sudo cat /results/probe.json' > "$result_dir/probe.json" || true
ssh_guest 'sudo cat /opt/halvo-lab-package-versions.txt' > "$result_dir/guest-packages.txt" || true
if [ "$probe_status" != 0 ]; then
  echo "Guest probe failed ($probe_status); results: $result_dir" >&2; exit "$probe_status"
fi
python3 - "$result_dir/probe.json" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
print(json.dumps({"passed": report['passed'], "docker_absent": report['docker_absent'],
                  "checks": len(report['checks'])}, indent=2))
raise SystemExit(0 if report['passed'] and report['docker_absent'] else 1)
PY

printf 'Checking persistent worker supervision and data across a guest reboot.\n'
timeout --kill-after=10s 3m ssh "${ssh_args[@]}" \
  'sudo python3 /opt/halvo-lab/probe.py --prepare-reboot' > "$result_dir/reboot-prepare.log" 2>&1
ssh_guest 'sudo cat /results/reboot-before.json' > "$result_dir/reboot-before.json"
old_boot_id="$(ssh_guest 'cat /proc/sys/kernel/random/boot_id')"
ssh_guest 'sudo python3 /opt/halvo-lab/guard.py >/dev/null && sudo systemctl reboot' \
  > "$result_dir/reboot-command.log" 2>&1 || true
deadline=$((SECONDS + 180))
while ssh_guest true >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then echo 'Guest did not go offline for reboot.' >&2; exit 1; fi
  sleep 2
done
wait_guest
new_boot_id="$(ssh_guest 'cat /proc/sys/kernel/random/boot_id')"
if [ "$new_boot_id" = "$old_boot_id" ]; then echo 'Guest boot identity did not change.' >&2; exit 1; fi
printf '%s\n%s\n' "$old_boot_id" "$new_boot_id" > "$result_dir/boot-ids.txt"
reboot_status=0
timeout --kill-after=10s 3m ssh "${ssh_args[@]}" \
  'sudo python3 /opt/halvo-lab/probe.py --verify-reboot' \
  > "$result_dir/reboot-verify.log" 2>&1 || reboot_status=$?
collect_results
ssh_guest 'sudo cat /results/reboot.json' > "$result_dir/reboot.json" || true
if [ "$reboot_status" != 0 ]; then
  echo "Guest reboot check failed ($reboot_status); results: $result_dir" >&2; exit "$reboot_status"
fi
python3 - "$result_dir/reboot.json" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
print(json.dumps(report, indent=2))
raise SystemExit(0 if report['passed'] else 1)
PY
fi
printf 'Running the packet-policy experiment inside the guest.\n'
net_status=0
timeout --kill-after=10s 9m ssh "${ssh_args[@]}" \
  'sudo python3 /opt/halvo-lab/network_probe.py' \
  > "$result_dir/network-probe.log" 2>&1 || net_status=$?
collect_results
ssh_guest 'sudo cat /results/network.json' > "$result_dir/network.json" || true
if [ "$net_status" != 0 ]; then
  echo "Guest packet-policy experiment failed ($net_status); results: $result_dir" >&2; exit "$net_status"
fi
python3 - "$result_dir/network.json" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]),
                  "drop_packets": report.get("drop_packets")}, indent=2))
raise SystemExit(0 if report["passed"] else 1)
PY
fi
# Graceful shutdown is guarded inside the guest. The trap still stops QEMU on errors.
ssh_guest 'sudo python3 /opt/halvo-lab/guard.py >/dev/null && sudo systemctl poweroff' \
  > "$result_dir/shutdown.log" 2>&1 || true
deadline=$((SECONDS + 120))
while kill -0 "$qemu_pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 2; done
if kill -0 "$qemu_pid" 2>/dev/null; then
  echo 'Guest shutdown timed out; terminating its owned QEMU process.' >&2
else
  wait "$qemu_pid"
  qemu_pid=''
fi
printf 'Results: %s\n' "$result_dir"
