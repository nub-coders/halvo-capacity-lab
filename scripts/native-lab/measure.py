#!/usr/bin/env python3
"""Read-only Phase 0 snapshot; capture BOTH control and workload hosts per backend.

Select whole platform-owned directories covering runtimes, data, logs, caches,
and retained releases. Use equal sources, limits, capacity, and retention for
comparisons. Paths are scanned by GNU du for allocated bytes, not apparent size
or Docker virtual image sizes. No services, counters, or caches are changed.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

CGROUP_ROOT = Path("/sys/fs/cgroup")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def directories(values):
    paths = []
    for value in values:
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_dir() or path == Path("/"):
            raise ValueError(f"Select a directory other than /: {value}")
        if any(path == old or path in old.parents or old in path.parents for old in paths):
            raise ValueError(f"Duplicate or overlapping measurement directory: {value}")
        paths.append(path)
    return paths


def open_cgroup(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Cgroup must be an absolute path without traversal: {value}")
    try:
        parts = path.relative_to(CGROUP_ROOT).parts
    except ValueError:
        raise ValueError(f"Cgroup must be inside {CGROUP_ROOT}: {value}") from None
    fd = os.open(CGROUP_ROOT, DIRECTORY_FLAGS)
    try:
        for part in parts:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except OSError as error:
        os.close(fd)
        raise ValueError(f"Cgroup is missing, inaccessible, or contains a symlink: {value}") from error


def cgroup_snapshot(value):
    fd = open_cgroup(value)
    result = {"path": str(Path(value)), "unavailable": []}
    try:
        for name in ("memory.current", "memory.peak", "cpu.stat", "memory.events", "pids.current"):
            try:
                counter = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                result[name] = None
                result["unavailable"].append(name)
                continue
            with os.fdopen(counter) as stream:
                value = stream.read(65536).strip()
            result[name] = (
                {key: int(number) for key, number in (line.split() for line in value.splitlines())}
                if name in ("cpu.stat", "memory.events") else int(value)
            )
        return result
    finally:
        os.close(fd)


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout


def collect(args):
    started = datetime.now(timezone.utc).isoformat()
    paths = directories(args.path)
    # Validate every requested cgroup before starting any directory scan.
    cgroups = [cgroup_snapshot(value) for value in args.cgroup]
    du_version = command(["du", "--version"]).splitlines()[0]
    if "GNU coreutils" not in du_version:
        raise ValueError("GNU du is required for allocated-byte measurements")
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            memory[key] = int(value.split()[0]) * 1024
    disk = command(["du", "--summarize", "--block-size=1", "--null", "--", *map(str, paths)])
    result = {
        "schema_version": 1,
        "backend": args.backend, "role": args.role, "label": args.label,
        "scan_started_at": started,
        "host": {
            "kernel": platform.release(), "architecture": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "systemd": command(["systemd", "--version"]).splitlines()[0] if shutil.which("systemd") else None,
            "memory_bytes": memory,
        },
        "cgroups": cgroups,
        "disk": [{"path": path, "allocated_bytes": int(size)}
                 for size, path in (row.split("\t", 1) for row in disk.split("\0") if row)],
        "measurement": {
            "du": du_version,
            "notes": [
                "Capture BOTH hosts and all owned runtimes, logs, caches, data, and retained releases.",
                "du does not follow nested symlinks; hard links count once across paths in argument order.",
                "Mounts are traversed; avoid bind/overlay aliases of already measured data.",
                "Live snapshots are not atomic; cgroup peaks cover their lifetime, not this scan alone.",
                "No savings total is inferred; compare equal sources, limits, capacity, and retention.",
            ],
        },
    }
    result["scan_finished_at"] = datetime.now(timezone.utc).isoformat()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("docker", "native"), required=True)
    parser.add_argument("--role", choices=("control", "workload"), required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--path", action="append", required=True, help="Whole owned directory; repeat as needed")
    parser.add_argument("--cgroup", action="append", default=[], help="Explicit /sys/fs/cgroup/... directory")
    args = parser.parse_args()
    try:
        print(json.dumps(collect(args), indent=2))
    except subprocess.CalledProcessError as error:
        parser.error(f"{error.cmd[0]} failed: {error.stderr.strip()}")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
