#!/usr/bin/env bash
# Chain runtime-tree build windows back-to-back until the evidence lands.
#
# One guest window is ~70 minutes and a full CPython build needs several, so a
# supervisor outside ZCode's lifecycle must start the next window when one
# ends. This script is that supervisor: it is meant to run as the halvo
# tree-window systemd unit and simply re-invokes vm.sh, checking between
# windows whether the manifest revision's evidence (build + pip stage) is
# already recorded.
set -u

lab_dir="$1"
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
max_windows="${HALVO_LAB_TREE_WINDOWS:-14}"

is_done() {
  # The pip stage is last and names its manifest revision; when it exists the
  # build and sanity stages necessarily completed before it.
  compgen -G "$lab_dir/results/*/runtime-tree-pip.json" > /dev/null
}

for window in $(seq 1 "$max_windows"); do
  if is_done; then
    echo "evidence complete; exiting after $((window - 1)) chained windows"
    exit 0
  fi
  echo "=== chained window $window/$max_windows: $(date -u +%FT%TZ) ==="
  bash "$script_dir/vm.sh" --runtime-tree-only "$lab_dir" \
    || echo "window $window ended nonzero; continuing"
  sleep 30
done
echo "attempt budget of $max_windows windows spent without complete evidence"
exit 1
