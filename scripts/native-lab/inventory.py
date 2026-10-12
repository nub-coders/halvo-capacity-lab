#!/usr/bin/env python3
"""Classify an explicit local Docker metadata snapshot without querying Docker/DB.

Input is the limited legacy-workload-metadata.json projection, not raw inspect.
No environment, commands, credentials, mount sources, or customer file contents
are emitted. Labels/container names are not authoritative database identities.
Readiness cannot be established from this metadata; source/runtime review remains
mandatory. Redirect JSON stdout to a local report file if retention is needed.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re

FIELDS = {"app", "name", "state", "image_id", "ports", "mounts", "root_readonly",
          "memory_limit", "cpu_nanos", "disk_options"}
MOUNT_FIELDS = {"Type", "Name", "Source", "Destination", "Driver", "Mode", "RW", "Propagation"}
FORBIDDEN_BINDS = {"/", "/proc", "/sys", "/var/run/docker.sock", "/run/docker.sock",
                   "/run/containerd/containerd.sock"}
CLASSES = ("ready", "configuration-needed", "blocked", "unknown")


def classify(row):
    if not isinstance(row, dict) or set(row) - FIELDS:
        raise ValueError("Use the limited metadata projection; raw inspect/extra fields are rejected")
    if not all(isinstance(row.get(key), str) and 0 < len(row[key]) <= 255 for key in ("app", "name")):
        raise ValueError("Each workload requires an app label and container name")
    readonly = row.get("root_readonly")
    if readonly is not None and not isinstance(readonly, bool):
        raise ValueError("root_readonly must be boolean or null")
    mounts, reasons, blocked = [], [], False
    if not isinstance(row.get("mounts") or [], list):
        raise ValueError("mounts must be a list or null")
    for mount in row.get("mounts") or []:
        if not isinstance(mount, dict) or set(mount) - MOUNT_FIELDS:
            raise ValueError("Unsupported mount metadata fields")
        kind, destination, writable = mount.get("Type"), mount.get("Destination"), mount.get("RW")
        if kind not in ("bind", "volume", "tmpfs", "npipe", "cluster") or not isinstance(destination, str):
            raise ValueError("Mount type/destination metadata is invalid")
        if not PurePosixPath(destination).is_absolute() or ".." in PurePosixPath(destination).parts:
            raise ValueError("Mount destination must be an absolute path without traversal")
        if writable is not None and not isinstance(writable, bool):
            raise ValueError("Mount RW metadata must be boolean or null")
        mounts.append({"type": kind, "destination": destination, "writable": writable})
        if kind == "bind" and str(PurePosixPath(destination)) in FORBIDDEN_BINDS:
            blocked = True
    if blocked:
        reasons.append("Legacy bind targets a host/control location excluded by the native contract; remap or remove it before migration")
    if any(mount["type"] == "bind" for mount in mounts):
        reasons.append("Host bind mounts require ownership, dependency, and per-app storage remapping review")
    if any(mount["type"] == "volume" for mount in mounts):
        reasons.append("Volumes require a data inventory, consistency plan, UID/GID mapping, and verified transfer")
    if readonly is False:
        reasons.append("Writable root requires data review; this does not establish whether data is stored there")
    if mounts and not reasons:
        reasons.append("Mounted storage requires review against immutable releases and private /data")
    classification = "blocked" if blocked else "configuration-needed" if reasons else "unknown"
    ports = row.get("ports") or {}
    if not isinstance(ports, dict) or any(
        not re.fullmatch(r"[0-9]+/(tcp|udp|sctp)", key) or not 1 <= int(key.split("/")[0]) <= 65535
        for key in ports
    ):
        raise ValueError("ports must contain valid Docker EXPOSE keys")
    resources = {}
    for source, target in (("memory_limit", "memory_limit_bytes"), ("cpu_nanos", "nano_cpus")):
        value = row.get(source)
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError(f"{source} must be a nonnegative integer or null")
        resources[target] = value
    image = row.get("image_id")
    if image is not None and (not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
        raise ValueError("image_id must be an immutable SHA256 ID or null, not a registry reference")
    state = row.get("state")
    if state not in (None, "running", "paused", "exited", "dead", "created", "restarting", "removing"):
        raise ValueError("Unsupported container state metadata")
    return {
        "app_label": row["app"], "container_name": row["name"], "state": state, "image_id": image,
        "classification": classification, "reasons": reasons,
        "native_compatibility": "unknown", "root_readonly": readonly, "mounts": mounts,
        "declared_ports": sorted(ports), "resources": resources,
        "storage_options_present": bool(row.get("disk_options")), "disk_enforcement": "unverified",
    }


def inventory(rows):
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError("Snapshot must be a list of at most 10,000 workload records")
    workloads = [classify(row) for row in rows]
    counts = Counter(row["classification"] for row in workloads)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification_scope": "Storage/configuration preparation; native source/runtime compatibility remains unknown",
        "container_count": len(workloads), "distinct_app_labels": len({row["app_label"] for row in workloads}),
        "classifications": {name: counts[name] for name in CLASSES}, "workloads": workloads,
        "limitations": [
            "Metadata preparation review only: zero workloads can be declared ready from this snapshot.",
            "App labels/names are not verified database identities, owners, or a complete tenant inventory.",
            "Source availability, runtime/version, native packages, commands, secrets, and customer files were not inspected.",
            "Image IDs do not prove image-only deployment; missing EXPOSE does not prove worker-only behavior.",
            "Data contents, domains, scheduled rebuilds, billing checkpoints, and rollback requirements remain unverified.",
            "Mount source paths/names, commands, environment values, credentials, and customer file contents are omitted.",
            "Preparation classifications can change after review; unknown runtime compatibility still blocks a cutover decision.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True, help="Explicit local safe-metadata JSON file")
    args = parser.parse_args()
    try:
        if not args.snapshot.is_file():
            raise ValueError("Snapshot must be an existing regular metadata file")
        with args.snapshot.open("rb") as stream:
            content = stream.read(4 * 1024 * 1024 + 1)
        if len(content) > 4 * 1024 * 1024:
            raise ValueError("Metadata snapshot exceeds 4 MiB")
        print(json.dumps(inventory(json.loads(content)), indent=2))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
