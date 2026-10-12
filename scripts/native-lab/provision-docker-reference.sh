#!/usr/bin/env bash
# Docker exists only in this explicitly selected disposable reference guest.
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
test "$(/usr/bin/python3 "$source_dir/guard.py")" = qemu
inputs=(benchmark.Dockerfile benchmark.py benchmark_compare.py probe.py guard.py)
reference_dir=/var/lib/halvo-docker-reference
mkdir -p -m 0700 "$reference_dir"
if [ "${1:-}" = --check ]; then
  systemctl is-active --quiet docker
  (cd "$source_dir" && sha256sum -c "$reference_dir/docker-reference-sources.sha256")
  image_id="$(cat "$reference_dir/docker-reference-image-id")"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]
  test "$(docker --host unix:///var/run/docker.sock image inspect --format '{{.Id}}' "$image_id")" = "$image_id"
  printf 'Disposable Docker reference image and sources match.\n'
  exit 0
fi
test "$#" = 0
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update
apt-get -o DPkg::Lock::Timeout=300 -y install --no-install-recommends docker.io
systemctl enable --now docker

context="$(mktemp -d "$reference_dir/build-XXXXXX")"
for file in "${inputs[@]}"; do
  test -f "$source_dir/$file" && test ! -L "$source_dir/$file"
  cp "$source_dir/$file" "$context/$file"
done
docker --host unix:///var/run/docker.sock build --force-rm \
  -f "$context/benchmark.Dockerfile" \
  --iidfile "$reference_dir/docker-reference-image-id" \
  -t halvo-native-lab-reference:fixture "$context"
(cd "$source_dir" && sha256sum "${inputs[@]}") > "$reference_dir/docker-reference-sources.sha256"
dpkg-query -W > /results/docker-reference-package-versions.txt
docker --host unix:///var/run/docker.sock version > /results/docker-reference-version.txt
