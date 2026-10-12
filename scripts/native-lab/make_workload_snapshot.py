#!/usr/bin/env python3
"""Produce the limited legacy-workload-metadata.json projection from Docker.

Read-only: the only Docker operation is `inspect` over containers that carry
the platform's `paas.role=workload` label. The output contains exactly the
fields `inventory.py` accepts — no environment values, commands, image tags,
network settings, or mount sources beyond what the classifier whitelists — so
the snapshot can be handed around for the storage/configuration preparation
review without leaking tenant configuration.

Redirect stdout to a private file; keep it out of any repository.
"""

import argparse
import json
import subprocess

MOUNT_FIELDS = ("Type", "Name", "Source", "Destination", "Driver", "Mode", "RW", "Propagation")


def _labels(info: dict) -> dict:
    return (info.get("Config") or {}).get("Labels") or {}


def project(info: dict) -> dict | None:
    """One inspect record -> the classifier projection, or None for non-workloads."""
    labels = _labels(info)
    if labels.get("paas.role") != "workload" or not labels.get("paas.app"):
        return None
    name = (info.get("Name") or "").lstrip("/")
    host_config = info.get("HostConfig") or {}
    memory_limit = host_config.get("Memory")
    cpu_nanos = host_config.get("NanoCpus")
    root_readonly = host_config.get("ReadonlyRootfs")
    mounts = [
        {key: mount[key] for key in MOUNT_FIELDS if key in mount}
        for mount in (info.get("Mounts") or [])
    ]
    return {
        "app": labels["paas.app"][:255],
        "name": name[:255],
        "state": (info.get("State") or {}).get("Status"),
        "image_id": info.get("Image"),
        "ports": {port: True for port in ((info.get("Config") or {}).get("ExposedPorts") or {})},
        "mounts": mounts,
        "root_readonly": root_readonly if isinstance(root_readonly, bool) else None,
        "memory_limit": int(memory_limit) if memory_limit else None,
        "cpu_nanos": int(cpu_nanos) if cpu_nanos else None,
        "disk_options": host_config.get("StorageOpt") or None,
    }


def collect(inspect_all) -> list:
    """inspect_all() must return the raw `docker inspect` records (injectable for tests)."""
    rows = []
    for info in inspect_all():
        row = project(info)
        if row is not None:
            rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker", help="docker CLI to invoke")
    args = parser.parse_args()

    listed = subprocess.run(
        [args.docker, "ps", "-aq", "--filter", "label=paas.role=workload"],
        capture_output=True, text=True, check=True,
    )
    ids = listed.stdout.split()
    if not ids:
        print("[]")
        return 0
    inspected = subprocess.run(
        [args.docker, "inspect", *ids], capture_output=True, text=True, check=True
    )
    print(json.dumps(collect(lambda: json.loads(inspected.stdout)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
