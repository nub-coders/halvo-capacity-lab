#!/usr/bin/env bash
# Runs only INSIDE the disposable root filesystem, never on the production host.
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
lab_kind="$(/usr/bin/python3 "$source_dir/guard.py")"
if [ "$lab_kind" = qemu ]; then
  # TCG device discovery can exceed the cloud image's 90-second default.
  # Keep both boot mounts required, but allow a bounded five-minute discovery.
  /usr/bin/python3 - <<'PY'
from pathlib import Path
import subprocess

fstab = Path('/etc/fstab')
original = fstab.read_text()
lines = []
for line in original.splitlines():
    fields = line.split()
    if not line.lstrip().startswith('#') and len(fields) >= 4 and fields[1] in ('/boot', '/boot/efi'):
        options = [option for option in fields[3].split(',')
                   if not option.startswith('x-systemd.device-timeout=')]
        fields[3] = ','.join(options + ['x-systemd.device-timeout=300s'])
        line = '\t'.join(fields)
    lines.append(line)
updated = '\n'.join(lines) + '\n'
if updated != original:
    fstab.write_text(updated)
    subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=60)
PY
fi
if [ "${1:-}" = --check ]; then
  # Resume a known disposable guest without reinstalling unchanged tools.
  test -s /opt/halvo-lab-package-versions.txt
  test "$(/opt/node/bin/node --version)" = v22.23.3
  /usr/bin/python3 -c 'import sys; assert sys.version_info[:2] == (3, 12)'
  test "$(git -C /opt/nsjail rev-parse HEAD)" = f100fd917c6d3ed0fd15d868528b735cb5fb1a1a
  cmp /usr/local/bin/nsjail /opt/nsjail/nsjail
  cmp "$source_dir/static-package-lock.json" /opt/halvo-fixtures/static/package-lock.json
  test -s /opt/halvo-fixtures/markupsafe.tar.gz
  mountpoint -q /quota
  test "$(findmnt -n -o FSTYPE -T /quota)" = xfs
  printf 'Reusing the provisioned disposable guest; runtime/fixture checks passed.\n'
  exit 0
fi
export DEBIAN_FRONTEND=noninteractive
# A rebooted persistent guest starts unattended-upgrades/apt-daily on its own;
# the disposable lab provisions deterministically instead. The lock timeout
# below still covers any upgrade already holding dpkg when we arrive.
systemctl disable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
apt-get -o DPkg::Lock::Timeout=300 update
apt-get -o DPkg::Lock::Timeout=300 -y install --no-install-recommends python3-dev python3-venv python3-setuptools python3-wheel \
  build-essential git ca-certificates curl xz-utils libprotobuf-dev protobuf-compiler \
  libnl-route-3-dev flex bison libtool autoconf pkg-config xfsprogs nftables nginx iproute2
cd /opt
if [ ! -d nsjail ]; then git clone https://github.com/google/nsjail.git; fi
git -C nsjail checkout --detach f100fd917c6d3ed0fd15d868528b735cb5fb1a1a
git -C nsjail submodule update --init --recursive
# A provisioning window killed by its timeout leaves truncated .o files that
# make then treats as current, and the link fails with undefined references
# forever after. Until one build has fully succeeded (marker below), every
# window restarts the nsjail compile from a clean tree; once installed, later
# windows skip straight past it. The marker name carries the pinned commit so
# a future re-pin rebuilds by construction.
if [ ! -e /opt/nsjail/.halvo-built-f100fd91 ]; then
  make -C nsjail clean >/dev/null 2>&1 || true
  make -C nsjail -j2
  install -m 0755 nsjail/nsjail /usr/local/bin/nsjail
  touch /opt/nsjail/.halvo-built-f100fd91
fi
curl -fL --retry 3 -o /tmp/node.tar.xz https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz
printf '%s\n' 'df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de  /tmp/node.tar.xz' | sha256sum -c -
mkdir -p /opt/node
tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1
ln -sf /opt/node/bin/node /usr/local/bin/node
ln -sf /opt/node/bin/npm /usr/local/bin/npm
rm /tmp/node.tar.xz
mkdir -p /opt/halvo-fixtures/static
cat > /opt/halvo-fixtures/static/package.json <<'JSON'
{"name":"halvo-static-probe","private":true,"version":"1.0.0","type":"module","scripts":{"build":"vite build"},"dependencies":{"react":"18.3.1","react-dom":"18.3.1","vite":"6.4.2"}}
JSON
cat > /opt/halvo-fixtures/static/index.html <<'HTML'
<!doctype html><html><head><title>Halvo native fixture</title></head><body><div id="root"></div><script type="module" src="/main.jsx"></script></body></html>
HTML
cat > /opt/halvo-fixtures/static/main.jsx <<'JS'
import React from 'react';
import { createRoot } from 'react-dom/client';
createRoot(document.getElementById('root')).render(React.createElement('h1', null, 'Native Halvo'));
JS
cd /opt/halvo-fixtures/static
# Cache the fixed public fixture without executing package lifecycle hooks.
# The probe installs offline and executes those hooks only inside NsJail.
cp "$source_dir/static-package-lock.json" package-lock.json
npm ci --ignore-scripts --no-audit --no-fund --cache /opt/halvo-fixtures/npm-cache
rm -rf /opt/halvo-fixtures/static/node_modules
/usr/bin/python3 - <<'PY'
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

# Fetch a fixed public source archive without running its build backend outside
# the sandbox. The experiment installs/compiles it offline inside NsJail.
source_url = 'https://files.pythonhosted.org/packages/87/5b/aae44c6655f3801e81aa3eef09dbbf012431987ba564d7231722f68df02d/MarkupSafe-2.1.5.tar.gz'
digest = 'd283d37a890ba4c1ae73ffadf8046435c76e7bc2247bbb63c00bd1a709c6544b'
with urlopen(source_url, timeout=30) as response:
    content = response.read(2 * 1024 * 1024)
assert hashlib.sha256(content).hexdigest() == digest
Path('/opt/halvo-fixtures/markupsafe.tar.gz').write_bytes(content)
Path('/opt/halvo-fixtures/markupsafe-source.json').write_text(json.dumps({
    'name': 'MarkupSafe', 'version': '2.1.5', 'url': source_url, 'sha256': digest,
}, indent=2) + '\n')
PY
if [ "$lab_kind" = qemu ]; then
  # Entirely inside the guest. Never mount quota images on the live host.
  mkdir -p /var/lib/halvo-lab /quota
  if [ ! -f /var/lib/halvo-lab/quota.img ]; then
    truncate -s 1G /var/lib/halvo-lab/quota.img
    mkfs.xfs -q /var/lib/halvo-lab/quota.img
  fi
  if ! mountpoint -q /quota; then
    mount -o loop,prjquota /var/lib/halvo-lab/quota.img /quota
  fi
  mkdir -p /quota/app-a
  chown 65001:65001 /quota/app-a
  xfs_quota -x -c 'project -s -p /quota/app-a 101' /quota
  xfs_quota -x -c 'limit -p bsoft=16m bhard=16m ihard=512 101' /quota
  if ! grep -q '^/var/lib/halvo-lab/quota.img ' /etc/fstab; then
    printf '/var/lib/halvo-lab/quota.img /quota xfs loop,prjquota 0 0\n' >> /etc/fstab
  fi
fi
dpkg-query -W > /opt/halvo-lab-package-versions.txt
apt-get clean
