#!/usr/bin/env bash
# A fresh disposable Docker guest only. Never call this against the host daemon.
set -euo pipefail
umask 077
source_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
test "$(/usr/bin/python3 "$source_dir/guard.py")" = qemu
test "$(id -u)" = 0
if [ "${1:-}" = --check ] && [ "$#" = 1 ]; then
  /usr/bin/python3 - "$source_dir" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import capacity_fixtures, benchmark
r = json.loads(Path('/results/capacity-image.json').read_text())
image = Path('/results/capacity-image-id').read_text().strip()
assert r['image'] == image and r['scope'] == 'capacity-only-derived-image'
assert r['reference_image'] == Path('/var/lib/halvo-docker-reference/docker-reference-image-id').read_text().strip()
assert r['fixture_sha256'] == {n: benchmark.fixture_digest(f) for n, f in capacity_fixtures.FIXTURES.items()}
for name, content in (('capacity_fixtures.py', Path(sys.argv[1], 'capacity_fixtures.py').read_bytes()),
                      ('server.py', capacity_fixtures.PYTHON_SERVER.encode()),
                      ('Dockerfile', Path(sys.argv[1], 'capacity.Dockerfile').read_bytes())):
    assert r['context_sha256'][name] == hashlib.sha256(content).hexdigest()
assert subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect',
                       '--format', '{{.Id}}', image], check=True, capture_output=True,
                       text=True, timeout=30).stdout.strip() == image
print('Existing capacity-only image identity verified; no build or mutation.')
PY
  exit 0
fi
test "$#" = 0
test -s /var/lib/halvo-docker-reference/docker-reference-image-id
test ! -e /results/capacity-image.json
test ! -e /results/capacity-image-id
reference="$(cat /var/lib/halvo-docker-reference/docker-reference-image-id)"
[[ "$reference" =~ ^sha256:[0-9a-f]{64}$ ]]
docker=(docker --host unix:///var/run/docker.sock)
test "$("${docker[@]}" image inspect --format '{{.Id}}' "$reference")" = "$reference"
context="$(mktemp -d /var/lib/halvo-docker-reference/capacity-context-XXXXXXXX)"
cp "$source_dir/capacity.Dockerfile" "$context/Dockerfile"
cp "$source_dir/capacity_fixtures.py" "$context/capacity_fixtures.py"
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 - "$source_dir" "$context" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import capacity_fixtures
Path(sys.argv[2], 'server.py').write_text(capacity_fixtures.PYTHON_SERVER)
PY
# Docker COPY retains these root-owned modes; probes and residents use UID1000.
chmod 0644 "$context/capacity_fixtures.py" "$context/server.py"
# No network resolution, pull, apt or npm step. An unsuccessful image build is
# invalid evidence in this fresh overlay; it is not retried in place.
DOCKER_BUILDKIT=0 "${docker[@]}" image build --pull=false --network=none \
  --build-arg "REFERENCE_IMAGE=$reference" --iidfile /results/capacity-image-id "$context"
derived="$(cat /results/capacity-image-id)"
[[ "$derived" =~ ^sha256:[0-9a-f]{64}$ ]]
test "$derived" != "$reference"
test "$("${docker[@]}" image inspect --format '{{.Id}}' "$derived")" = "$derived"
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 - "$source_dir" "$reference" "$derived" "$context" <<'PY'
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import capacity_fixtures
import benchmark
context = Path(sys.argv[4])
r = {'scope': 'capacity-only-derived-image', 'production': False,
     'phase0_complete': False, 'reference_image': sys.argv[2], 'image': sys.argv[3],
     'fixture_sha256': {name: benchmark.fixture_digest(fixture)
                        for name, fixture in capacity_fixtures.FIXTURES.items()},
     'context_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(context.iterdir())}}
with Path('/results/capacity-image.json').open('x') as stream:
    json.dump(r, stream, allow_nan=False, sort_keys=True, indent=2)
    stream.write('\n')
PY
printf 'Capacity-only derived image: %s\n' "$derived"
