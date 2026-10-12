#!/usr/bin/env bash
# Diagnostic-only derivative of frozen28 vm-capacity.sh; loopback guest only.
set -euo pipefail
umask 077
usage() { echo 'Usage: vm-docker-inspect.sh --external-diagnostic-docker /var/tmp/halvo-native-vm-NAME' >&2; }
if [ "$#" != 2 ] || [ "${1:-}" != --external-diagnostic-docker ] ||
   [[ ! "${2:-}" =~ ^/var/tmp/halvo-native-vm-[A-Za-z0-9_-]+$ ]]; then
  usage; exit 1
fi
[ "$(id -u)" = 0 ] || { usage; exit 1; }
shift
# Global serialization is acquired before touching guest files.
exec 8>/run/halvo-native-lab.lock
flock -n 8 || { echo 'Another native-lab launcher is active.' >&2; exit 1; }
if pgrep -f '(^|/)[q]emu-system-[^/ ]+( |$)' >/dev/null ||
   pgrep -f '(^|/)[w]indow_loop\.sh( |$)' >/dev/null; then
  echo 'Another QEMU guest or runtime-tree supervisor is active.' >&2; exit 1
fi
. /etc/os-release
case "$ID:$VERSION_ID:$(uname -m)" in
  ubuntu:24.04:x86_64|ubuntu:26.04:x86_64) ;;
  *) echo 'This runner requires an Ubuntu 24.04 or 26.04 x86-64 host.' >&2; exit 1 ;;
esac
lab_dir="$1"
source_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# Never overwrite execution references, even if the launcher was staged in a lab.
case "$source_dir/" in "$lab_dir/"*) echo 'Source execution references must be outside the lab.' >&2; exit 1 ;; esac
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
if find "$lab_dir" -maxdepth 1 -type l -print -quit | read -r _; then
  echo 'Refusing symlinks in the lab directory.' >&2; exit 1
fi
exec 9> "$lab_dir/lock"
flock -n 9 || { echo 'This VM lab is already running.' >&2; exit 1; }
mkdir -p "$lab_dir/downloads" "$lab_dir/tools" "$lab_dir/seed" "$lab_dir/results"
tools_dir="$lab_dir/tools"
local_libs="$tools_dir/usr/lib/x86_64-linux-gnu:$tools_dir/lib/x86_64-linux-gnu"
local_tool() { timeout --kill-after=10s 5m env LD_LIBRARY_PATH="$local_libs" QEMU_MODULE_DIR="$tools_dir/usr/lib/x86_64-linux-gnu/qemu" "$tools_dir/usr/bin/$@"; }
if [ ! -f "$lab_dir/.tools-ready" ]; then
  LC_ALL=C timeout --kill-after=10s 5m apt-get --simulate --no-install-recommends --no-upgrade --reinstall install \
    qemu-system-x86 qemu-utils genisoimage > "$lab_dir/tools-plan.log"
  mapfile -t packages < <(awk '/^Inst / { for (i=3; i<=NF; i++) if (substr($i,1,1)=="(") { print $2 "=" substr($i,2); break } }' "$lab_dir/tools-plan.log")
  [ "${#packages[@]}" != 0 ] || { echo 'No QEMU packages resolved.' >&2; exit 1; }
  (
    cd "$lab_dir/downloads"
    timeout --kill-after=10s 10m apt-get download "${packages[@]}" > "$lab_dir/tools-download.log" 2>&1
    for package in ./*.deb; do timeout --kill-after=10s 2m dpkg-deb -x "$package" "$tools_dir"; done
  )
  local_tool qemu-system-x86_64 --version > "$lab_dir/qemu-version.txt"
  local_tool qemu-img --version >> "$lab_dir/qemu-version.txt"
  local_tool genisoimage --version >> "$lab_dir/qemu-version.txt" 2>&1
  touch "$lab_dir/.tools-ready"
fi
image_url=https://cloud-images.ubuntu.com/noble/20260926/noble-server-cloudimg-amd64.img
image_sha=6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2
if [ ! -f "$lab_dir/base.img" ]; then
  timeout --kill-after=10s 15m curl --fail --silent --show-error --location --retry 3 --max-time 900 \
    "$image_url" -o "$lab_dir/base.img.part"
  printf '%s  %s\n' "$image_sha" "$lab_dir/base.img.part" | sha256sum -c -
  mv "$lab_dir/base.img.part" "$lab_dir/base.img"
fi
printf '%s  %s\n' "$image_sha" "$lab_dir/base.img" | sha256sum -c -
printf '%s\n%s\n' "$image_url" "$image_sha" > "$lab_dir/image-source.txt"
if [ ! -f "$lab_dir/guest.qcow2" ]; then
  local_tool qemu-img create -f qcow2 -F qcow2 -b "$lab_dir/base.img" "$lab_dir/guest.qcow2" 16G
fi
# Retain the disk but issue fresh cloud-init/SSH identities for this invocation.
cat /proc/sys/kernel/random/uuid > "$lab_dir/vm-id"
for key in client-key host-key; do
  rm -f -- "$lab_dir/$key" "$lab_dir/$key.pub"
  timeout --kill-after=10s 1m ssh-keygen -q -t ed25519 -N '' -C halvo-disposable-lab -f "$lab_dir/$key"
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
payload=(provision.sh syscalls.policy guard.py static-package-lock.json
  benchmark.py benchmark_compare.py probe.py
  capacity.py capacity_client.py capacity_fixtures.py capacity_guest.py capacity_relay.py
  prepare-capacity-docker.sh capacity.Dockerfile provision-docker-reference.sh docker_inspect_trace_guest.py)
for file in "${payload[@]}" docker_inspect_diagnostic.py vm-docker-inspect.sh SHA256SUMS DIAGNOSTIC-SHA256SUMS; do
  [ -f "$source_dir/$file" ] && [ ! -L "$source_dir/$file" ] || { echo "Missing regular input: $file" >&2; exit 1; }
done
# Verify every manifest entry before any guest work. Do not accept absolute,
# traversal, symlink, malformed, or duplicate entries.
python3 - "$source_dir" <<'PY'
import re, sys
from pathlib import Path
root = Path(sys.argv[1])
entries = []
for line in (root / 'SHA256SUMS').read_text().splitlines():
    match = re.fullmatch(r'[0-9a-f]{64}  ([A-Za-z0-9_.-]+)', line)
    assert match, 'Malformed diagnostic manifest'
    name = match[1]
    assert name not in ('.', '..') and not (root / name).is_symlink()
    assert (root / name).is_file(), f'Missing manifest input: {name}'
    entries.append(name)
assert len(entries) == len(set(entries)), 'Duplicate manifest entries'
PY
(cd "$source_dir" && sha256sum --strict -c SHA256SUMS >/dev/null)
(cd "$source_dir" && sha256sum --strict -c DIAGNOSTIC-SHA256SUMS >/dev/null)
diagnostic_manifest_sha256="$(sha256sum "$source_dir/DIAGNOSTIC-SHA256SUMS" | awk '{print $1}')"
payload_sha256="$(sha256sum "$source_dir/SHA256SUMS" | awk '{print $1}')"
expected_image=sha256:da38db8b3347ab4f61eaa54bd09cd6601fb8f42a31a43ad1767d25262dd9e2f8
# Fail before boot if the independent diagnostic validator has not been supplied.
python3 - "$source_dir/docker_inspect_diagnostic.py" <<'PY'
import ast, sys
from pathlib import Path
tree = ast.parse(Path(sys.argv[1]).read_text())
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'validate_diagnostic']
assert len(functions) == 1, 'Host adapter must define validate_diagnostic'
assert [a.arg for a in functions[0].args.args] == ['report', 'expected_payload', 'expected_image', 'expected_vm_id'], 'Unexpected validator interface'
PY
port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)"
python3 -c 'import os; assert {0,1,2,3}.issubset(os.sched_getaffinity(0)), "Four approved host CPUs are required"'
cpu_ids=0,1
host_public="$(awk 'NF >= 2 {print $1 " " $2}' "$lab_dir/host-key.pub")"
[[ "$host_public" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]] || { echo 'Malformed lab host public key.' >&2; exit 1; }
printf '[127.0.0.1]:%s %s\n' "$port" "$host_public" > "$lab_dir/known-hosts"
ssh_args=(-F /dev/null -i "$lab_dir/client-key" -p "$port" -o BatchMode=yes
  -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$lab_dir/known-hosts"
  -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=30 -o ConnectionAttempts=1
  -o ServerAliveInterval=10 -o ServerAliveCountMax=3 lab@127.0.0.1)
ssh_guest() { timeout --kill-after=10s 2m ssh "${ssh_args[@]}" "$@"; }
result_dir="$lab_dir/results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$result_dir"
qemu_pid=''
actual_qemu=''
collector_status=1
evidence_status=0
validation_status=1
shutdown_status=1
shutdown_graceful=false
qemu_wait_status=0
forced_termination=false
vm_lifetime=45m
validate_instrument() {
  # BEGIN DIAGNOSTIC VALIDATION RECEIPT
  timeout --kill-after=10s 1m python3 -B - "$source_dir" "$result_dir/docker-inspect-diagnostic.json" \
    "$payload_sha256" "$expected_image" "$(cat "$lab_dir/vm-id")" "$collector_status" \
    "$evidence_status" "$shutdown_graceful" "$qemu_wait_status" "$shutdown_status" <<'PY' \
    > "$result_dir/instrument-validation.json"
import importlib, inspect, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
result = {'passed': False, 'phase0_complete': False, 'capacity_evidence': False,
          'collection_valid': False, 'scope': 'docker-health-diagnostic-instrument-validation',
          'independent_diagnostic_accepted': False, 'reasons': []}
try:
    report = json.loads(Path(sys.argv[2]).read_text())
    for name in ('capacity_evidence', 'collection_valid', 'phase0_complete'):
        if report.get(name) is not False:
            raise ValueError(f'{name} must be strictly false')
    validation = importlib.import_module('docker_inspect_diagnostic')
    validator = getattr(validation, 'validate_diagnostic', None)
    if not callable(validator):
        raise ValueError('Independent validate_diagnostic function is unavailable')
    inspect.signature(validator).bind(report, sys.argv[3], sys.argv[4], sys.argv[5])
    # Contract: True only after schema, identity, guard/image, trace, time,
    # request bounds and collector cleanup have independently been accepted.
    accepted = validator(report, sys.argv[3], sys.argv[4], sys.argv[5]) is True
    result['independent_diagnostic_accepted'] = accepted
    if not accepted:
        raise ValueError('Independent diagnostic validator did not return True')
    if sys.argv[6:8] != ['0', '0']:
        raise ValueError(f'Collector/evidence exits: {sys.argv[6:8]}')
    if sys.argv[8:11] != ['true', '0', '0']:
        raise ValueError(f'Launcher shutdown was not clean: {sys.argv[8:11]}')
    result['passed'] = accepted
except Exception as error:
    result['reasons'].append(str(error)[:1024])
print(json.dumps(result, sort_keys=True, allow_nan=False))
raise SystemExit(0 if result['passed'] else 1)
PY
  # END DIAGNOSTIC VALIDATION RECEIPT
}
cleanup() {
  local launch_status=$? deadline stopped=true
  trap - EXIT INT TERM
  set +e
  # Always attempt guarded poweroff, including collector and provisioning errors.
  if [ -n "$qemu_pid" ]; then
    ssh_guest 'sudo python3 /opt/halvo-lab/guard.py >/dev/null && sudo systemctl poweroff' \
      > "$result_dir/shutdown.log" 2>&1
    shutdown_status=$?
    deadline=$((SECONDS + 120))
    while kill -0 "$qemu_pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 2; done
    if kill -0 "$qemu_pid" 2>/dev/null; then
      forced_termination=true
      if [ -n "$actual_qemu" ] && kill -0 "$actual_qemu" 2>/dev/null; then
        # actual_qemu was resolved only from this launcher's descendant tree.
        kill "$actual_qemu" 2>/dev/null
      fi
      kill "$qemu_pid" 2>/dev/null
      deadline=$((SECONDS + 15))
      while kill -0 "$qemu_pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 1; done
      # timeout owns a separate process group. Verify ownership before KILL.
      if kill -0 "$qemu_pid" 2>/dev/null; then
        if python3 - "$qemu_pid" <<'PY'
import os, sys
pid = int(sys.argv[1])
raise SystemExit(0 if os.getpgid(pid) == pid else 1)
PY
        then kill -KILL -- "-$qemu_pid" 2>/dev/null; fi
        kill -KILL "$qemu_pid" 2>/dev/null
      fi
      if [ -n "$actual_qemu" ] && kill -0 "$actual_qemu" 2>/dev/null; then
        if python3 - "$actual_qemu" "$tools_dir/usr/bin/qemu-system-x86_64" <<'PY'
import sys
from pathlib import Path
pid, executable = int(sys.argv[1]), sys.argv[2]
try:
    args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    raise SystemExit(0 if args and args[0].decode() == executable else 1)
except (FileNotFoundError, UnicodeError):
    raise SystemExit(1)
PY
        then kill -KILL "$actual_qemu" 2>/dev/null; fi
      fi
    fi
    wait "$qemu_pid"
    qemu_wait_status=$?
    if [ "$forced_termination" = false ] && [ "$qemu_wait_status" = 0 ] && [ "$shutdown_status" = 0 ]; then
      shutdown_graceful=true
    fi
    if [ -n "$actual_qemu" ] && kill -0 "$actual_qemu" 2>/dev/null; then stopped=false; fi
    qemu_pid=''
  fi
  validate_instrument
  validation_status=$?
  # A timeout/import failure must still leave a failed validation receipt.
  if [ ! -s "$result_dir/instrument-validation.json" ]; then
    printf '{"passed":false,"phase0_complete":false,"capacity_evidence":false,"collection_valid":false,"reasons":["validation process failed or timed out"]}\n' > "$result_dir/instrument-validation.json"
  fi
  if [ "$launch_status" = 0 ]; then
    if [ "$collector_status" != 0 ]; then launch_status=$collector_status
    elif [ "$evidence_status" != 0 ]; then launch_status=$evidence_status
    elif [ "$validation_status" != 0 ] || [ "$stopped" != true ]; then launch_status=1; fi
  fi
  printf '{"phase0_complete":false,"capacity_evidence":false,"collection_valid":false,"graceful_shutdown":%s,"shutdown_command_exit":%s,"qemu_wait_exit":%s,"forced_termination":%s,"owned_qemu_stopped":%s,"collector_exit":%s,"evidence_exit":%s,"validation_exit":%s,"launcher_exit":%s}\n' \
    "$shutdown_graceful" "$shutdown_status" "$qemu_wait_status" "$forced_termination" "$stopped" \
    "$collector_status" "$evidence_status" "$validation_status" "$launch_status" > "$result_dir/launcher-cleanup.json"
  printf 'Results: %s\n' "$result_dir"
  exit "$launch_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Owned tools, two CPU cores, 2.5 GiB RAM, 6 GiB address space, bounded lifetime.
# No host mounts, daemon sockets, public listeners or host credentials in guest.
timeout --signal=TERM --kill-after=10s "$vm_lifetime" \
  prlimit --as=6442450944 --nofile=1024 --core=0 -- \
  nice -n 10 taskset --cpu-list "$cpu_ids" \
  env -i PATH=/usr/bin:/bin HOME="$lab_dir" TMPDIR="$lab_dir" LD_LIBRARY_PATH="$local_libs" \
  QEMU_MODULE_DIR="$tools_dir/usr/lib/x86_64-linux-gnu/qemu" \
  "$tools_dir/usr/bin/qemu-system-x86_64" \
  -no-user-config -nodefaults -machine q35 -accel tcg,thread=multi,tb-size=128 -cpu max -smp 2 -m 2560 \
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
copy_payload() {
  (cd "$source_dir" && sha256sum --strict -c SHA256SUMS >/dev/null) || return
  for file in "${payload[@]}"; do
    test -f "$source_dir/$file" && test ! -L "$source_dir/$file" || return 1
  done
  timeout --kill-after=10s 2m tar -C "$source_dir" -cf - "${payload[@]}" |
    ssh_guest 'sudo tar -C /opt/halvo-lab -xf -'
}
collect_results() {
  local status=0
  ssh_guest 'sudo tar -C /results -cf - .' > "$result_dir/guest-results.tar" || status=$?
  ssh_guest 'sudo cat /opt/halvo-lab-package-versions.txt' > "$result_dir/guest-packages.txt" || status=$?
  ssh_guest 'sudo journalctl -b --no-pager -n 300' > "$result_dir/journal.log" || status=$?
  return "$status"
}
printf 'Booting diagnostic guest; logs: %s\n' "$result_dir"
wait_guest
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
timeout --kill-after=10s 5m ssh "${ssh_args[@]}" 'sudo cloud-init status --wait' > "$result_dir/cloud-init.log" 2>&1
ssh_guest 'sudo install -d -m 0755 /opt/halvo-lab /results'
copy_payload
  sha256sum "${payload[@]/#/$source_dir/}" > "$result_dir/provision-sources.sha256"
ssh_guest 'sudo bash /opt/halvo-lab/provision.sh --check' > "$result_dir/provision.log" 2>&1
ssh_guest 'sudo python3 /opt/halvo-lab/guard.py' > "$result_dir/guard.log" 2>&1
# Retained Docker image CHECK ONLY. Missing image metadata is a failure;
# the preparation helper is never called without --check.
timeout --kill-after=10s 5m ssh "${ssh_args[@]}" \
  'sudo test -f /results/capacity-image.json && sudo test -f /results/capacity-image-id && sudo bash /opt/halvo-lab/provision-docker-reference.sh --check && sudo bash /opt/halvo-lab/prepare-capacity-docker.sh --check' \
  > "$result_dir/capacity-image.log" 2>&1
derived="$(ssh_guest 'sudo cat /results/capacity-image-id')"
[ "$derived" = "$expected_image" ] || { echo 'Retained Docker image differs from diagnostic pin.' >&2; exit 1; }
ssh_guest 'sudo cat /results/capacity-image.json' > "$result_dir/capacity-image.json"
ssh_guest "sudo install -d -m 0755 /results/external-$(cat "$lab_dir/vm-id")"
  sha256sum "${payload[@]/#/$source_dir/}" > "$result_dir/lab-sources.sha256"
  printf '%s  DIAGNOSTIC-SHA256SUMS\n' "$diagnostic_manifest_sha256" > "$result_dir/diagnostic-lineage-pin.sha256"
(cd "$source_dir" && sha256sum --strict -c SHA256SUMS >/dev/null)
collector_status=0
timeout --kill-after=30s 20m nice -n 10 taskset --cpu-list 2,3 \
  python3 -B "$source_dir/docker_inspect_diagnostic.py" --backend docker --lab-dir "$lab_dir" --ssh-port "$port" \
  --qemu-pid "$actual_qemu" --payload-sha256 "$payload_sha256" --image "$expected_image" \
  --mode diagnostic --output "$result_dir/docker-inspect-diagnostic.json" \
  > "$result_dir/docker-inspect-diagnostic.log" 2>&1 || collector_status=$?
# Preserve the collector's report byte-for-byte, including its failure report.
ssh_guest "sudo cat /results/external-$(cat "$lab_dir/vm-id")/guest-control.json" \
  > "$result_dir/guest-control.json" || evidence_status=$?
collect_results || evidence_status=$?
# EXIT trap powers off and validates; no network experiment or benchmark follows.
exit "$collector_status"
