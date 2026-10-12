#!/usr/bin/env bash
# Capacity launcher derived from frozen payload18. Original vm.sh stays intact.
# External generator uses CPUs2,3, guest uses CPUs0,1; loopback forwarding only.
set -euo pipefail
umask 077
prepare=false
provision_only=false
resume=false
network_only=false
benchmark_only=false
resource_backend=''
docker_reference_only=false
build_backend=''
validate_backend=''
capacity_backend=''
capacity_preflight=false
external_mode=''
case "${1:-}" in
  --prepare) prepare=true; shift ;;
  --provision-only) provision_only=true; shift ;;
  --resume) resume=true; shift ;;
  --network-only) resume=true; network_only=true; shift ;;
  --benchmark-only) resume=true; benchmark_only=true; shift ;;
  --resource-native) resume=true; resource_backend=native; shift ;;
  --resource-docker) resume=true; resource_backend=docker; shift ;;
  --provision-docker) resume=true; docker_reference_only=true; shift ;;
  --build-native) resume=true; build_backend=native; shift ;;
  --build-docker) resume=true; build_backend=docker; shift ;;
  --validate-native) resume=true; resource_backend=native; build_backend=native; validate_backend=native; shift ;;
  --validate-docker) resume=true; resource_backend=docker; build_backend=docker; validate_backend=docker; shift ;;
  --capacity-native) resume=true; capacity_backend=native; shift ;;
  --capacity-docker) resume=true; capacity_backend=docker; shift ;;
  --capacity-preflight) resume=true; capacity_preflight=true; shift ;;
  --external-preflight-native) resume=true; capacity_backend=native; external_mode=preflight; shift ;;
  --external-preflight-docker) resume=true; capacity_backend=docker; external_mode=preflight; shift ;;
  --external-capacity-native) resume=true; capacity_backend=native; external_mode=capacity; shift ;;
  --external-capacity-docker) resume=true; capacity_backend=docker; external_mode=capacity; shift ;;
esac
if [ -z "$external_mode" ]; then
  echo 'Usage: vm-capacity.sh --external-{preflight|capacity}-{native|docker} /var/tmp/halvo-native-vm-NAME' >&2
  exit 1
fi
if [ "$(id -u)" != 0 ] || [ "$#" != 1 ] || [[ ! "$1" =~ ^/var/tmp/halvo-native-vm-[A-Za-z0-9_-]+$ ]]; then
  echo 'Usage: sudo bash scripts/native-lab/vm.sh [--prepare|--provision-only|--resume|--network-only|--benchmark-only|--resource-native|--resource-docker|--provision-docker|--build-native|--build-docker|--validate-native|--validate-docker|--capacity-native|--capacity-docker] /var/tmp/halvo-native-vm-NAME' >&2
  exit 1
fi
# Serialize launchers across lab directories before touching any guest files.
# The process check also covers older launchers and the runtime-tree supervisor
# between its windows. Offline preparation does not boot a guest.
if ! "$prepare"; then
  exec 8>/run/halvo-native-lab.lock
  flock -n 8 || { echo 'Another native-lab launcher is active.' >&2; exit 1; }
  if pgrep -f '(^|/)[q]emu-system-[^/ ]+( |$)' >/dev/null ||
     pgrep -f '(^|/)[w]indow_loop\.sh( |$)' >/dev/null; then
    echo 'Another QEMU guest or runtime-tree supervisor is active; retry after it finishes.' >&2
    exit 1
  fi
fi
. /etc/os-release
# Match the main launcher's supported hosts; the guest stays pinned to Ubuntu
# 24.04 with its own kernel and locally extracted QEMU tools on either host.
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
               'ssh_authorized_keys': ['restrict,port-forwarding,permitopen="127.0.0.1:*" ' + (lab / 'client-key.pub').read_text().strip()]}],
    'ssh_keys': {'ed25519_private': (lab / 'host-key').read_text(),
                 'ed25519_public': (lab / 'host-key.pub').read_text()},
    'write_files': [
        {'path': '/etc/halvo-native-lab', 'permissions': '0600', 'content': 'qemu-phase0-v1\n'},
         {'path': '/etc/halvo-native-lab-vm-id', 'permissions': '0600', 'content': vm_id + '\n'},
        {'path': '/etc/ssh/sshd_config.d/00-halvo-capacity.conf', 'permissions': '0600',
         'content': 'AllowTcpForwarding local\nPermitOpen 127.0.0.1:*\nPermitListen none\n'},
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

payload=(provision.sh probe.py network_probe.py benchmark.py benchmark_compare.py syscalls.policy guard.py static-package-lock.json)
if [ -n "$resource_backend" ] || "$docker_reference_only" || [ -n "$build_backend" ]; then
  payload+=(benchmark_mix.py benchmark_docker.py benchmark.Dockerfile provision-docker-reference.sh)
fi
if [ -n "$build_backend" ]; then
  payload+=(benchmark_builds.py)
fi
if [ -n "$capacity_backend" ] || "$capacity_preflight"; then
  payload+=(capacity.py capacity_client.py capacity_fixtures.py capacity_guest.py capacity_relay.py)
fi
if [ "$capacity_backend" = docker ]; then
  payload+=(prepare-capacity-docker.sh capacity.Dockerfile)
fi
if "$capacity_preflight"; then
  payload+=(capacity_preflight.py)
fi
for file in "${payload[@]}"; do
  if [ ! -f "$source_dir/$file" ] || [ -L "$source_dir/$file" ]; then
    echo "Missing regular allowlisted input: $file" >&2; exit 1
  fi
done
payload_sha256=''
if [ -n "$capacity_backend" ]; then
  [ -f "$source_dir/SHA256SUMS" ] || { echo 'Capacity mode requires the frozen SHA256SUMS manifest.' >&2; exit 1; }
  payload_sha256="$(sha256sum "$source_dir/SHA256SUMS" | awk '{print $1}')"
  (cd "$source_dir" && sha256sum -c SHA256SUMS >/dev/null)
fi
port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)"
cpu_ids="$(python3 -c 'import os; print(",".join(map(str, sorted(os.sched_getaffinity(0))[:2])))')"
python3 -c 'import os; assert {0,1,2,3}.issubset(os.sched_getaffinity(0)), "Four approved host CPUs are required"'
cpu_ids=0,1
host_public="$(awk 'NF >= 2 {print $1 " " $2}' "$lab_dir/host-key.pub")"
[[ "$host_public" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]] || { echo 'Malformed lab host public key.' >&2; exit 1; }
# A key comment is not part of its identity. Emit exactly the three fields
# required by the strict external validator; never relax that validator.
printf '[127.0.0.1]:%s %s\n' "$port" "$host_public" > "$lab_dir/known-hosts"
ssh_args=(-F /dev/null -i "$lab_dir/client-key" -p "$port" -o BatchMode=yes
  -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$lab_dir/known-hosts"
  -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=30 -o ConnectionAttempts=1
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
# Initial compilation under TCG can exceed the ordinary provisioning window.
vm_lifetime=70m
provision_outer=40m
provision_inner=39m
if "$provision_only"; then
  vm_lifetime=90m
  provision_outer=60m
  provision_inner=59m
fi
if [ -n "$build_backend" ] || [ -n "$validate_backend" ]; then
  vm_lifetime=150m
fi
if [ -n "$capacity_backend" ]; then
  vm_lifetime=120m
fi
if "$capacity_preflight"; then
  vm_lifetime=30m
fi
if [ "$external_mode" = preflight ]; then
  vm_lifetime=45m
fi
# Two CPU cores, 2.5 GiB guest RAM, 6 GiB maximum address space; bounded lifetime.
# No host directories, disks, service sockets, credentials, or public listeners.
# QEMU's setuid/setgid drop needs elevateprivileges=allow; -runas removes all root
# IDs before guest execution, while seccomp still applies NoNewPrivs and denies spawn.
# Hardware virtualization when the host exposes a usable /dev/kvm (KVM-capable
# runners); fall back to TCG software emulation otherwise. KVM rejects the
# TCG-only thread/tb-size options, so the accelerator string differs per path.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  qemu_accel=kvm
else
  qemu_accel=tcg,thread=multi,tb-size=128
fi
timeout --signal=TERM --kill-after=10s "$vm_lifetime" \
  prlimit --as=6442450944 --nofile=1024 --core=0 -- \
  nice -n 10 taskset --cpu-list "$cpu_ids" \
  env -i PATH=/usr/bin:/bin HOME="$lab_dir" TMPDIR="$lab_dir" LD_LIBRARY_PATH="$local_libs" \
  QEMU_MODULE_DIR="$tools_dir/usr/lib/x86_64-linux-gnu/qemu" \
  "$tools_dir/usr/bin/qemu-system-x86_64" \
  -no-user-config -nodefaults -machine q35 -accel "$qemu_accel" -cpu max -smp 2 -m 2560 \
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
timeout --kill-after=10s "$provision_outer" ssh "${ssh_args[@]}" \
  "sudo timeout --kill-after=10s $provision_inner bash /opt/halvo-lab/provision.sh" \
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
  ssh_guest 'sudo cat /opt/halvo-lab-package-versions.txt' > "$result_dir/guest-packages.txt" || true
  ssh_guest 'sudo journalctl -b --no-pager -n 300' > "$result_dir/journal.log" || true
}
run_builds() {
  local build_command build_status
  if [ "$build_backend" = docker ]; then
    ssh_guest 'sudo bash /opt/halvo-lab/provision-docker-reference.sh --check' \
      > "$result_dir/docker-reference-check.log" 2>&1
    build_command='set -o pipefail; sudo timeout --kill-after=45s 115m python3 /opt/halvo-lab/benchmark_builds.py --backend docker --image "$(sudo cat /var/lib/halvo-docker-reference/docker-reference-image-id)" | sudo tee /results/benchmark-builds.json'
  else
    build_command='set -o pipefail; sudo timeout --kill-after=45s 115m python3 /opt/halvo-lab/benchmark_builds.py --backend native | sudo tee /results/benchmark-builds.json'
  fi
  build_status=0
  timeout --kill-after=10s 116m ssh "${ssh_args[@]}" "$build_command" \
    > "$result_dir/benchmark-builds.log" 2>&1 || build_status=$?
  ssh_guest 'sudo cat /results/benchmark-builds.json' > "$result_dir/benchmark-builds.json" || true
  collect_results
  python3 - "$result_dir/benchmark-builds.json" "$build_status" <<'PY'
import json, sys
from pathlib import Path
assert sys.argv[2] == '0', f'Build collector exit: {sys.argv[2]}'
report = json.loads(Path(sys.argv[1]).read_text())
assert report['passed'], 'Build/retention collector failed; see saved report'
print('Build/retention collector passed; compare the paired reports separately.')
PY
}
run_network() {
  local net_status
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
}
external_status=0
if [ -n "$external_mode" ]; then
  printf 'External %s in the %s guest; host CPUs2,3, guest CPUs0,1.\n' "$external_mode" "$capacity_backend"
  ssh_guest "sudo install -d -m 0755 /results/external-$(cat "$lab_dir/vm-id")"
  image_args=()
  if [ "$capacity_backend" = docker ]; then
    timeout --kill-after=10s 10m ssh "${ssh_args[@]}" \
      'if sudo test -f /results/capacity-image.json; then sudo bash /opt/halvo-lab/prepare-capacity-docker.sh --check; else sudo bash /opt/halvo-lab/prepare-capacity-docker.sh; fi' \
      > "$result_dir/capacity-image.log" 2>&1 || external_status=$?
    if [ "$external_status" = 0 ]; then
      derived="$(ssh_guest 'sudo cat /results/capacity-image-id')"
      [[ "$derived" =~ ^sha256:[0-9a-f]{64}$ ]] || external_status=1
      image_args=(--image "$derived")
      ssh_guest 'sudo cat /results/capacity-image.json' > "$result_dir/capacity-image.json" || external_status=1
    fi
  fi
  # Resolve only descendants of our Popen-owned timeout wrapper, never guess a
  # QEMU PID from a global process match. External code verifies it independently.
  actual_qemu="$(python3 - "$qemu_pid" "$tools_dir/usr/bin/qemu-system-x86_64" <<'PY'
import sys
from pathlib import Path
pending, found = [int(sys.argv[1])], []
while pending:
    pid = pending.pop()
    try:
        args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        if args and args[0].decode() == sys.argv[2]:
            found.append(pid)
        pending.extend(map(int, Path(f'/proc/{pid}/task/{pid}/children').read_text().split()))
    except FileNotFoundError:
        pass
assert len(found) == 1, 'No unique owned QEMU process'
print(found[0])
PY
)"
  if [ "$external_status" = 0 ]; then
    timeout --kill-after=30s 70m nice -n 10 taskset --cpu-list 2,3 \
      python3 -B "$source_dir/capacity_external.py" --lab-dir "$lab_dir" --ssh-port "$port" \
      --qemu-pid "$actual_qemu" --backend "$capacity_backend" --payload-sha256 "$payload_sha256" \
      --mode "$external_mode" --output "$result_dir/capacity-external.json" "${image_args[@]}" \
      > "$result_dir/capacity-external.log" 2>&1 || external_status=$?
  fi
  ssh_guest "sudo cat /results/external-$(cat "$lab_dir/vm-id")/guest-control.json" \
    > "$result_dir/guest-control.json" || true
  collect_results || external_status=1
  python3 - "$result_dir/capacity-external.json" "$external_status" "$external_mode" <<'PY' || external_status=1
import json, sys
from pathlib import Path
assert sys.argv[2] == '0', f'External collector exit: {sys.argv[2]}'
r = json.loads(Path(sys.argv[1]).read_text())
assert r['passed'] is True and r['cleanup']['passed'] is True
assert r['phase0_complete'] is False
if sys.argv[3] == 'preflight':
    assert r['scope'] == 'external-generator-path-preflight' and r['capacity_evidence'] is False
    assert r['collection_valid'] is False and len(r['rates']) == 1
else:
    assert r['scope'] == 'request-capacity' and r['collection_valid'] is True
print('External path completed; paired gate verdict remains separate.')
PY
elif "$docker_reference_only"; then
  printf 'Preparing Docker only inside the disposable reference guest.\n'
  docker_status=0
  timeout --kill-after=10s 40m ssh "${ssh_args[@]}" \
    'sudo timeout --kill-after=10s 39m bash /opt/halvo-lab/provision-docker-reference.sh' \
    > "$result_dir/docker-reference-provision.log" 2>&1 || docker_status=$?
  collect_results
  if [ "$docker_status" != 0 ]; then
    echo "Docker reference preparation failed ($docker_status); see saved log." >&2
    exit "$docker_status"
  fi
  ssh_guest 'sudo bash /opt/halvo-lab/provision-docker-reference.sh --check' \
    > "$result_dir/docker-reference-check.log" 2>&1
elif [ -n "$build_backend" ] && [ -z "$validate_backend" ]; then
  run_builds
elif [ -n "$resource_backend" ]; then
  if [ "$resource_backend" = docker ]; then
    ssh_guest 'sudo bash /opt/halvo-lab/provision-docker-reference.sh --check' \
      > "$result_dir/docker-reference-check.log" 2>&1
    resource_command='set -o pipefail; sudo python3 /opt/halvo-lab/guard.py >/dev/null && sudo python3 /opt/halvo-lab/benchmark_docker.py --image "$(sudo cat /var/lib/halvo-docker-reference/docker-reference-image-id)" | sudo tee /results/benchmark.json'
    mix_command='set -o pipefail; sudo timeout --kill-after=45s 18m python3 /opt/halvo-lab/benchmark_mix.py --backend docker --image "$(sudo cat /var/lib/halvo-docker-reference/docker-reference-image-id)" | sudo tee /results/benchmark-mix.json'
  else
    resource_command='sudo python3 /opt/halvo-lab/benchmark.py'
    mix_command='set -o pipefail; sudo timeout --kill-after=45s 18m python3 /opt/halvo-lab/benchmark_mix.py --backend native | sudo tee /results/benchmark-mix.json'
  fi
  printf 'Running sequential and concurrent resource fixtures in the %s guest.\n' "$resource_backend"
  resource_status=0
  timeout --kill-after=10s 18m ssh "${ssh_args[@]}" "$resource_command" \
    > "$result_dir/benchmark.log" 2>&1 || resource_status=$?
  mix_status=$resource_status
  if [ "$resource_status" = 0 ]; then
    timeout --kill-after=10s 20m ssh "${ssh_args[@]}" "$mix_command" \
      > "$result_dir/benchmark-mix.log" 2>&1 || mix_status=$?
  fi
  ssh_guest 'sudo cat /results/benchmark.json' > "$result_dir/benchmark.json" || true
  ssh_guest 'sudo cat /results/benchmark-mix.json' > "$result_dir/benchmark-mix.json" || true
  collect_results
  python3 - "$result_dir" "$resource_status" "$mix_status" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
assert sys.argv[2:] == ['0', '0'], f'Collector exits: {sys.argv[2:]}'
for name in ('benchmark.json', 'benchmark-mix.json'):
    report = json.loads((root / name).read_text())
    assert report['passed'], f'{name} failed; see saved report'
print('Sequential and concurrent collectors passed; compare the paired reports separately.')
PY
  if [ -n "$validate_backend" ]; then
    run_builds
    if [ "$validate_backend" = native ]; then
      run_network
    fi
  fi
elif [ -n "$capacity_backend" ]; then
  printf 'Running request-capacity collection in the %s guest.\n' "$capacity_backend"
  if [ "$capacity_backend" = docker ]; then
    ssh_guest 'sudo bash /opt/halvo-lab/provision-docker-reference.sh --check' \
      > "$result_dir/docker-reference-check.log" 2>&1
    capacity_command='sudo timeout --kill-after=45s 60m python3 /opt/halvo-lab/capacity.py --backend docker --image "$(sudo cat /var/lib/halvo-docker-reference/docker-reference-image-id)" --results-dir /results --payload-sha256 '"$payload_sha256"
  else
    capacity_command="sudo timeout --kill-after=45s 60m python3 /opt/halvo-lab/capacity.py --backend native --results-dir /results --payload-sha256 $payload_sha256"
  fi
  capacity_status=0
  timeout --kill-after=10s 65m ssh "${ssh_args[@]}" "$capacity_command" \
    > "$result_dir/capacity.log" 2>&1 || capacity_status=$?
  ssh_guest 'sudo cat /results/capacity.json' > "$result_dir/capacity.json" || true
  collect_results
  python3 - "$result_dir/capacity.json" "$capacity_status" <<'PY'
import json, sys
from pathlib import Path
assert sys.argv[2] == '0', f'Capacity collector exit: {sys.argv[2]}'
report = json.loads(Path(sys.argv[1]).read_text())
assert report['scope'] == 'request-capacity'
assert report['passed'] and report['collection_valid']
print(json.dumps({'passed': report['passed'], 'capacity_rps': report.get('capacity_rps')}, indent=2))
PY
elif "$capacity_preflight"; then
  printf 'Running generator selfcheck only; no tenant capacity collection.\n'
  preflight_status=0
  timeout --kill-after=10s 8m ssh "${ssh_args[@]}" \
    'sudo python3 /opt/halvo-lab/guard.py >/dev/null && sudo timeout --kill-after=45s 7m python3 -B /opt/halvo-lab/capacity_preflight.py --output /results/capacity-selfcheck.json' \
    > "$result_dir/capacity-selfcheck.log" 2>&1 || preflight_status=$?
  ssh_guest 'sudo cat /results/capacity-selfcheck.json' > "$result_dir/capacity-selfcheck.json" || true
  collect_results
  # Verify evidence before success, but always attempt guarded shutdown even
  # when selfcheck fails. The original report is retained without mutation.
  python3 - "$result_dir/capacity-selfcheck.json" "$preflight_status" <<'PY' || preflight_status=1
import json, sys
from pathlib import Path
r = json.loads(Path(sys.argv[1]).read_text())
assert sys.argv[2] == '0', f'Selfcheck exit: {sys.argv[2]}'
assert r['scope'] == 'load-generator-selfcheck' and r['capacity_evidence'] is False
assert r['phase0_complete'] is False and r['passed'] is True
assert r['rate_per_second'] == 256 and r['duration_seconds'] == 60
assert r['summary']['completed'] == 15360 and r['summary']['failed'] == 0
assert r['cleanup']['passed'] and r['cleanup']['server_stopped']
print('In-guest generator selfcheck passed; this is not a capacity verdict.')
PY
elif "$provision_only"; then
  ssh_guest 'sudo bash /opt/halvo-lab/provision.sh --check' > "$result_dir/provision-check.log" 2>&1
  collect_results
  printf 'Fresh disposable guest provisioned and checked.\n'
elif "$benchmark_only"; then
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
else
if ! "$network_only"; then
printf 'Running the guarded probe inside the guest.\n'
probe_status=0
timeout --kill-after=10s 34m ssh "${ssh_args[@]}" \
  'sudo env HALVO_LAB_KEEP_RUNNING=1 timeout --kill-after=10s 33m python3 /opt/halvo-lab/probe.py' \
  > "$result_dir/probe.log" 2>&1 || probe_status=$?
collect_results
ssh_guest 'sudo cat /results/probe.json' > "$result_dir/probe.json" || true
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
run_network
fi
# Graceful shutdown is guarded inside the guest. The trap still stops QEMU on errors.
ssh_guest 'sudo python3 /opt/halvo-lab/guard.py >/dev/null && sudo systemctl poweroff' \
  > "$result_dir/shutdown.log" 2>&1 || true
deadline=$((SECONDS + 120))
while kill -0 "$qemu_pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 2; done
if kill -0 "$qemu_pid" 2>/dev/null; then
  echo 'Guest shutdown timed out; terminating its owned QEMU process.' >&2
  external_status=1
  shutdown_graceful=false
else
  wait "$qemu_pid" || external_status=1
  qemu_pid=''
  shutdown_graceful=true
fi
if [ "$external_status" = 0 ]; then
  python3 -B - "$source_dir" "$result_dir/capacity-external.json" "$external_mode" <<'PY' \
    > "$result_dir/instrument-validation.json" || external_status=1
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import capacity_external_validate as validation
try:
    validation.validate(json.loads(Path(sys.argv[2]).read_text()), preflight=sys.argv[3] == 'preflight')
    result = {'passed': True, 'phase0_complete': False, 'scope': 'external-instrument-validation'}
except Exception as error:
    result = {'passed': False, 'phase0_complete': False, 'reasons': [str(error)]}
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result['passed'] else 1)
PY
fi
printf '{"phase0_complete":false,"graceful_shutdown":%s,"launcher_exit":%s}\n' \
  "$shutdown_graceful" "$external_status" > "$result_dir/launcher-cleanup.json"
printf 'Results: %s\n' "$result_dir"
if [ -n "$external_mode" ]; then
  exit "$external_status"
fi
if "$capacity_preflight"; then
  exit "$preflight_status"
fi
