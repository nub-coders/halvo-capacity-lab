#!/usr/bin/env bash
# Reproducible Phase 0 lab. Downloads tools locally; never installs host packages.
set -euo pipefail
if [ "$(id -u)" != 0 ]; then echo 'Run as root on Ubuntu 24.04.' >&2; exit 1; fi
if [ "$#" != 1 ] || [[ ! "$1" =~ ^/var/tmp/halvo-native-[A-Za-z0-9_-]+$ ]]; then
  echo 'Usage: sudo bash scripts/native-lab/run.sh /var/tmp/halvo-native-EXPERIMENT' >&2
  exit 1
fi
lab_dir="$1"
if [ "${HALVO_LAB_MOUNT_NAMESPACE:-}" != "$(readlink /proc/self/ns/mnt)" ]; then
  exec unshare --mount --propagation private /bin/bash -c \
    'export HALVO_LAB_MOUNT_NAMESPACE="$(readlink /proc/self/ns/mnt)"; exec /bin/bash "$@"' \
    halvo-native-lab "$0" "$@"
fi
source_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
if [ -L "$lab_dir" ]; then echo 'Lab directory cannot be a symlink.' >&2; exit 1; fi
if [ -e "$lab_dir" ] && [ ! -f "$lab_dir/.halvo-native-lab" ]; then
  echo 'Refusing an existing directory without our lab marker.' >&2; exit 1
fi
mkdir -p -m 0700 "$lab_dir"
touch "$lab_dir/.halvo-native-lab"
exec 9> "$lab_dir/lock"
flock -n 9 || { echo 'This lab is already running.' >&2; exit 1; }
mkdir -p "$lab_dir/tools" "$lab_dir/downloads" "$lab_dir/results"
rootfs="$lab_dir/rootfs"
nspawn="$lab_dir/tools/usr/bin/systemd-nspawn"

if [ ! -x "$nspawn" ]; then
  (
    cd "$lab_dir/downloads"
    systemd_version="$(dpkg-query -W -f='${Version}' libsystemd-shared)"
    apt-get download debootstrap "systemd-container=$systemd_version"
    for package in ./*.deb; do dpkg-deb -x "$package" "$lab_dir/tools"; done
  )
fi
if [ ! -f "$lab_dir/.bootstrap-complete" ]; then
  DEBOOTSTRAP_DIR="$lab_dir/tools/usr/share/debootstrap" \
    "$lab_dir/tools/usr/sbin/debootstrap" --components=main,universe --variant=minbase \
    --include=systemd,dbus,iproute2,iputils-ping,ca-certificates,curl,python3,python3-venv,python3-dev,build-essential,git,libprotobuf-dev,protobuf-compiler,libnl-route-3-dev,flex,bison,libtool,autoconf,pkg-config,xfsprogs,nftables,nginx \
    noble "$rootfs" http://archive.ubuntu.com/ubuntu > "$lab_dir/bootstrap.log" 2>&1
  touch "$lab_dir/.bootstrap-complete"
fi
touch "$rootfs/etc/halvo-native-lab"
printf 'halvo-native-lab\n' > "$rootfs/etc/hostname"
printf '#!/bin/sh\nexit 101\n' > "$rootfs/usr/sbin/policy-rc.d"
chmod 0755 "$rootfs/usr/sbin/policy-rc.d"
if [ ! -f "$lab_dir/.provision-complete" ]; then
  # Only trusted, pinned provisioning code has network access. The test boot below
  # has a private network and gets no host home, credentials, or service sockets.
  systemd-run --quiet --wait --pipe --collect --unit="halvo-native-provision-$$" \
    --property=MemoryMax=2G --property=CPUQuota=200% --property=RuntimeMaxSec=30min \
    "$nspawn" --quiet --settings=no --register=no --link-journal=no \
    --directory="$rootfs" --resolv-conf=copy-host \
    --bind-ro="$source_dir:/opt/halvo-lab" \
    /bin/bash /opt/halvo-lab/provision.sh > "$lab_dir/provision.log" 2>&1
  touch "$lab_dir/.provision-complete"
fi
cat > "$rootfs/etc/systemd/system/halvo-phase0-probe.service" <<'UNIT'
[Unit]
Description=Disposable Halvo native runner experiment
After=network.target
[Service]
Type=oneshot
Environment=HALVO_LAB_HOST_SECRET=must-not-reach-the-sandbox
ExecStart=/usr/bin/python3 /opt/halvo-lab/probe.py
TimeoutStartSec=5min
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p "$rootfs/etc/systemd/system/multi-user.target.wants"
ln -sf ../halvo-phase0-probe.service "$rootfs/etc/systemd/system/multi-user.target.wants/halvo-phase0-probe.service"
if [ ! -f "$lab_dir/quota.img" ]; then
  truncate -s 512M "$lab_dir/quota.img"
  mkfs.xfs -q "$lab_dir/quota.img"
fi
mkdir -p "$lab_dir/quota"
mount -o loop,prjquota "$lab_dir/quota.img" "$lab_dir/quota"
mkdir -p "$lab_dir/quota/app-a"
chown 65001:65001 "$lab_dir/quota/app-a"
xfs_quota -x -c "project -s -p $lab_dir/quota/app-a 101" "$lab_dir/quota" > "$lab_dir/quota.log"
xfs_quota -x -c 'limit -p bsoft=16m bhard=16m ihard=512 101' "$lab_dir/quota"
rm -f "$lab_dir/results/probe.json" "$lab_dir/results/error.json"
systemd-run --quiet --wait --pipe --collect --unit="halvo-native-boot-$$" \
  --property=MemoryMax=2G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=1024 --property=RuntimeMaxSec=6min --property=Delegate=yes \
  nsenter --mount="/proc/$$/ns/mnt" -- \
  "$nspawn" --quiet --settings=no --register=no --link-journal=no \
  --boot --directory="$rootfs" --private-network --machine="halvo-native-$$" \
  --bind-ro="$source_dir:/opt/halvo-lab" --bind="$lab_dir/results:/results" \
  --bind="$lab_dir/quota:/quota" \
  > "$lab_dir/boot.log" 2>&1
python3 - "$lab_dir/results/probe.json" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
print(json.dumps(report, indent=2))
raise SystemExit(0 if report['passed'] and report['docker_absent'] else 1)
PY
