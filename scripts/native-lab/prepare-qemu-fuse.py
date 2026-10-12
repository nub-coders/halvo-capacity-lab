#!/usr/bin/env python3
"""Extract a signed, pinned FUSE3 dependency into lab tools; never apt-install."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import subprocess
from urllib.request import urlopen

SNAPSHOT = 'https://snapshot.ubuntu.com/ubuntu/20260926T000000Z/'
DIST = 'dists/noble/'
INDEX = 'main/binary-amd64/Packages.xz'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fetch(url, output, bound):
    with urlopen(url, timeout=90) as response:
        content = response.read(bound + 1)
    if len(content) > bound:
        raise ValueError('download exceeds its declared bound')
    with output.open('xb') as stream:
        stream.write(content)


def prepare(lab):
    if os.geteuid() != 0 or not re.fullmatch(r'/var/tmp/halvo-native-vm-[A-Za-z0-9_-]+', str(lab)) \
            or lab.resolve(strict=True) != lab or lab.stat().st_uid != 0 \
            or lab.stat().st_mode & 0o777 != 0o700 \
            or (lab / '.halvo-native-vm').read_text().strip() != 'qemu-phase0-v1':
        raise ValueError('expected a root-owned, exclusively marked disposable lab')
    target = lab / 'tools/usr/lib/x86_64-linux-gnu'
    if target.resolve(strict=True) != target or not target.is_dir():
        raise ValueError('lab tools library path is absent or contains symlinks')
    work = lab / 'qemu-fuse-repair-noble-base'
    work.mkdir(mode=0o700)  # An incomplete/failed attempt is not overwritten.
    release = work / 'InRelease'
    fetch(SNAPSHOT + DIST + 'InRelease', release, 2_000_000)
    checked = subprocess.run(['gpgv', '--keyring', '/usr/share/keyrings/ubuntu-archive-keyring.gpg',
        str(release)], capture_output=True, text=True, timeout=30)
    if checked.returncode:
        raise ValueError('Ubuntu signed release verification failed')
    text = release.read_text()
    if '\nCodename: noble\n' not in text or '\nSuite: noble\n' not in text:
        raise ValueError('signed release distribution identity differs')
    entries, sha_section = {}, False
    for line in text.splitlines():
        if line == 'SHA256:':
            sha_section = True
        elif sha_section and line.startswith(' '):
            checksum, size, name = line.split()
            entries[name] = (checksum, int(size))
        elif sha_section:
            break
    checksum, size = entries[INDEX]
    packages = work / 'Packages.xz'
    fetch(SNAPSHOT + DIST + INDEX, packages, size)
    if packages.stat().st_size != size or digest(packages) != checksum:
        raise ValueError('package index differs from signed SHA256')
    candidate = None
    for paragraph in lzma.decompress(packages.read_bytes()).decode().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in paragraph.splitlines() if ': ' in line and not line.startswith(' '))
        if fields.get('Package') == 'libfuse3-3' and fields.get('Architecture') == 'amd64':
            candidate = fields
    if candidate is None or not re.fullmatch(r'pool/[A-Za-z0-9_./+~-]+\.deb', candidate['Filename']):
        raise ValueError('signed index lacks the fixed FUSE3 package')
    archive = work / 'libfuse3-3.deb'
    fetch(SNAPSHOT + candidate['Filename'], archive, int(candidate['Size']))
    if digest(archive) != candidate['SHA256'] or archive.stat().st_size != int(candidate['Size']):
        raise ValueError('library archive differs from signed package index')
    extracted = work / 'extracted'
    subprocess.run(['dpkg-deb', '-x', str(archive), str(extracted)], check=True, timeout=30)
    libraries = list(extracted.rglob('libfuse3.so.3*'))
    if len(libraries) != 2 or len({p.name for p in libraries}) != 2:
        raise ValueError('unexpected FUSE3 archive library population')
    for path in libraries:
        destination = target / path.name
        if destination.exists() or destination.is_symlink():
            raise ValueError('refusing to overwrite an existing lab library')
        if path.is_symlink():
            link = os.readlink(path)
            if '/' in link or link not in {p.name for p in libraries}:
                raise ValueError('unexpected library symlink target')
            destination.symlink_to(link)
        else:
            destination.write_bytes(path.read_bytes())
            destination.chmod(0o644)
    env = {**os.environ, 'LD_LIBRARY_PATH': f'{target}:{lab / "tools/lib/x86_64-linux-gnu"}'}
    qemu = lab / 'tools/usr/bin/qemu-system-x86_64'
    version = subprocess.run([str(qemu), '--version'], env=env, capture_output=True,
                             text=True, check=True, timeout=30).stdout.strip()
    result = {'scope': 'lab-local-qemu-dependency-repair', 'host_packages_changed': False,
        'production': False, 'phase0_complete': False, 'snapshot': SNAPSHOT,
        'release_sha256': digest(release), 'index_sha256': digest(packages),
        'package': candidate['Package'], 'version': candidate['Version'],
        'archive_sha256': digest(archive), 'qemu_sha256': digest(qemu), 'qemu_version': version,
        'library_sha256': {p.name: digest(p) for p in libraries if not p.is_symlink()}}
    with (work / 'receipt.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lab', type=Path)
    args = parser.parse_args()
    prepare(args.lab)
