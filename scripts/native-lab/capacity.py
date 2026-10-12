#!/usr/bin/env python3
"""Guarded Phase 0 request-capacity collection in the disposable QEMU guest.

This collector is deliberately a lab instrument, not an application runner.
It starts only the fixed fixtures from :mod:`benchmark`, enters their network
namespaces for health and request traffic, and records enough identity and
resource evidence to reject an ambiguous run.  No production paths, service
units, containers, or image tags are accepted.
"""

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import benchmark
import capacity_fixtures
import probe
from guard import require_lab


REPORT_TYPE = "halvo-native-lab-capacity"
COLLECTOR_VERSION = "phase0-capacity-v2-external"
SCHEMA_VERSION = 1

ROUTE_ORDER = ("python", "static", "node")
ALL_FIXTURES = ("python", "static", "node", "worker")
ROUTE_WEIGHTS = {"python": 70, "static": 20, "node": 10}
RATES_PER_SECOND = (1, 2, 4, 8, 16, 32, 64, 128)
WARMUP_SECONDS = 60
MEASUREMENT_SECONDS = 120
# Public fixed-profile aliases make the contract easy to inspect from tests and
# from a guest-side operator without duplicating benchmark definitions.
FIXTURES = capacity_fixtures.FIXTURES
RATES = RATES_PER_SECOND
WINDOW = {"warmup_seconds": WARMUP_SECONDS, "measurement_seconds": MEASUREMENT_SECONDS}

# A request is never allowed to wait forever in either the fixture client or
# the parent collector.  The guest is software-emulated, so the queue guard
# is deliberately a little wider than one normal scheduling tick.
REQUEST_TIMEOUT_SECONDS = 30.0
GENERATOR_LAG_LIMIT_SECONDS = 0.5
CLIENT_QUEUE_LAG_LIMIT_SECONDS = 2.0
CLIENT_START_TIMEOUT_SECONDS = 30
PHASE_DRAIN_TIMEOUT_SECONDS = 40
READINESS_TIMEOUT_SECONDS = 120
MAX_CLIENT_OUTSTANDING = 4096
MAX_PROTOCOL_LINE_BYTES = 16384
HEALTH_CHECK_INTERVAL_SECONDS = 5.0
HEALTH_COMMAND_TIMEOUT_SECONDS = 30.0
HEALTH_CHECK_TIMEOUT_SECONDS = 90.0
ERROR_RATE_MAX = 0.01

# All four residents must survive the complete fixed schedule.  This is a
# bound for the sandboxed workload, not a resource limit and not a production
# service timeout.
TOTAL_SCHEDULE_SECONDS = len(RATES_PER_SECOND) * (WARMUP_SECONDS + MEASUREMENT_SECONDS)
MAX_RESIDENT_RUNTIME_SECONDS = TOTAL_SCHEDULE_SECONDS + 600
MAX_COLLECTION_SECONDS = TOTAL_SCHEDULE_SECONDS + 1800

LIMITS = dict(benchmark.LIMITS)
DOCKER = ("docker", "--host", "unix:///var/run/docker.sock")
DOCKER_LABEL = "halvo.native-lab-capacity"
IDENTIFIER = re.compile(r"[0-9a-f]{64}\Z")
RUN_IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")
PAYLOAD_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

SOURCE_FILES = ("capacity.py", "capacity_client.py", "capacity_fixtures.py", "benchmark.py", "probe.py", "guard.py",
                "syscalls.policy")


class CapacityError(RuntimeError):
    """A bounded collector or input failure that invalidates the report."""


class GeneratorBottleneck(CapacityError):
    """The request generator could not maintain the requested open-loop rate."""


class ResidentFailure(CapacityError):
    """A resident exited, restarted, lost its limit, or hit OOM."""


def _finite_number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


def validate_route_weights(weights):
    """Validate and normalize the fixed deterministic route profile."""
    if not isinstance(weights, dict) or set(weights) != set(ROUTE_ORDER):
        raise ValueError("route weights must contain Python, static, and Node")
    values = {}
    for route in ROUTE_ORDER:
        value = weights[route]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("route weights must be positive integers")
        values[route] = value
    if sum(values.values()) != 100:
        raise ValueError("route weights must total 100")
    return values


def validate_schedule(rate, duration, weights=ROUTE_WEIGHTS):
    """Validate one fixed-rate phase and return its exact request count."""
    if isinstance(rate, bool) or not isinstance(rate, int) or rate <= 0:
        raise ValueError("rate must be a positive integer")
    if isinstance(duration, bool) or not isinstance(duration, int) or duration <= 0:
        raise ValueError("duration must be a positive integer")
    validate_route_weights(dict(weights))
    count = rate * duration
    if count <= 0 or count > 10_000_000:
        raise ValueError("schedule is outside the bounded request count")
    return count


def _route_cycle(weights):
    """Build a deterministic, exact-weight cycle for integer percentages.

    The approved profile has a short hand-reviewed cycle.  The generic branch
    uses evenly spaced ideal positions and deterministic collision resolution;
    it keeps this pure helper useful for tests without creating another runtime
    configuration knob.
    """
    values = validate_route_weights(dict(weights))
    if values == ROUTE_WEIGHTS:
        return ("python", "python", "static", "python", "node",
                "python", "static", "python", "python", "python")
    divisor = math.gcd(*values.values())
    counts = [values[route] // divisor for route in ROUTE_ORDER]
    length = sum(counts)
    slots = [None] * length
    # Place larger routes first at their ideal midpoints.  A forward search is
    # deterministic and guarantees that every route gets exactly its quota.
    for route, count in sorted(zip(ROUTE_ORDER, counts), key=lambda item: (-item[1], item[0])):
        for index in range(count):
            ideal = int(((index + 0.5) * length) / count)
            ideal = min(length - 1, ideal)
            for offset in range(length):
                slot = (ideal + offset) % length
                if slots[slot] is None:
                    slots[slot] = route
                    break
            else:  # pragma: no cover - the quota proof makes this unreachable.
                raise ValueError("could not construct route cycle")
    return tuple(slots)


def weighted_routes(count, weights=ROUTE_WEIGHTS):
    """Return the first ``count`` entries of the deterministic route cycle."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("count must be a non-negative integer")
    cycle = _route_cycle(dict(weights))
    return tuple(cycle[index % len(cycle)] for index in range(count))


def iter_schedule(rate, duration, weights=ROUTE_WEIGHTS):
    """Yield deterministic ``(index, offset_seconds, route)`` schedule rows."""
    count = validate_schedule(rate, duration, weights)
    routes = weighted_routes(count, weights)
    for index, route in enumerate(routes):
        yield {"index": index, "offset_seconds": index / rate, "route": route}


def percentile(values, quantile):
    """Return a linear-interpolated percentile, or ``None`` for no samples."""
    if isinstance(quantile, bool) or not isinstance(quantile, (int, float)) \
            or not 0 <= quantile <= 100 or not math.isfinite(quantile):
        raise ValueError("quantile must be between 0 and 100")
    numbers = sorted(_finite_number(value, "sample") for value in values)
    if not numbers:
        return None
    if len(numbers) == 1:
        return numbers[0]
    position = (len(numbers) - 1) * quantile / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return numbers[lower]
    return numbers[lower] + (numbers[upper] - numbers[lower]) * (position - lower)


def _round(value):
    return None if value is None else round(float(value), 6)


def _outcome_error(outcome):
    error = outcome.get("error")
    if error:
        return str(error)
    if outcome.get("ok") is True and outcome.get("status") == 200:
        return None
    if outcome.get("status") is not None:
        return "http_status"
    return "transport_error"


def aggregate_outcomes(outcomes, duration_seconds, weights=ROUTE_WEIGHTS):
    """Aggregate raw request outcomes without discarding individual results.

    The returned structure is JSON-safe and contains one summary per route,
    error counts, successful goodput, and all latency observations.  It is
    intentionally independent of subprocesses and clocks so boundary cases
    can be tested without starting a guest or Docker.
    """
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)) \
            or duration_seconds <= 0 or not math.isfinite(duration_seconds):
        raise ValueError("duration_seconds must be positive and finite")
    values = validate_route_weights(dict(weights))
    if not isinstance(outcomes, (list, tuple)):
        raise ValueError("outcomes must be a sequence")
    grouped = {route: [] for route in ROUTE_ORDER}
    for outcome in outcomes:
        if not isinstance(outcome, dict) or outcome.get("route") not in grouped:
            raise ValueError("outcome has an unknown route")
        if "id" not in outcome or isinstance(outcome["id"], bool) \
                or not isinstance(outcome["id"], int) or outcome["id"] < 0:
            raise ValueError("outcome id must be an integer")
        status = outcome.get("status")
        if status is not None and (isinstance(status, bool) or not isinstance(status, int)
                                   or not 100 <= status <= 599):
            raise ValueError("outcome status must be an HTTP status or null")
        if "ok" in outcome and not isinstance(outcome["ok"], bool):
            raise ValueError("outcome ok must be boolean")
        error = outcome.get("error")
        if error is not None and (not isinstance(error, str) or len(error) > 100):
            raise ValueError("outcome error must be a bounded string or null")
        grouped[outcome["route"]].append(dict(outcome))

    routes = {}
    all_latencies = []
    total_successes = 0
    total_completed = 0
    errors = Counter()
    for route in ROUTE_ORDER:
        rows = grouped[route]
        latencies = []
        successes = 0
        for row in rows:
            latency = row.get("latency_ms")
            if latency is not None:
                _finite_number(latency, "latency_ms")
                if latency < 0:
                    raise ValueError("latency_ms cannot be negative")
                latencies.append(float(latency))
                all_latencies.append(float(latency))
            if row.get("ok") is True and row.get("status") == 200:
                successes += 1
            error = _outcome_error(row)
            if error:
                errors[error] += 1
        completed = len(rows)
        total_completed += completed
        total_successes += successes
        summary = {
            "weight_percent": values[route],
            "scheduled": completed,
            "completed": completed,
            "successful": successes,
            "failed": completed - successes,
            "goodput_rps": _round(successes / duration_seconds),
            "error_rate": _round((completed - successes) / completed) if completed else 1.0,
            "latency_ms": {
                "count": len(latencies),
                "min": _round(min(latencies) if latencies else None),
                "p50": _round(percentile(latencies, 50)),
                "p95": _round(percentile(latencies, 95)),
                "p99": _round(percentile(latencies, 99)),
                "max": _round(max(latencies) if latencies else None),
            },
            "errors": dict(sorted(Counter(_outcome_error(row) for row in rows
                                            if _outcome_error(row)).items())),
        }
        routes[route] = summary

    requested = sum(len(grouped[route]) for route in ROUTE_ORDER)
    return {
        "scheduled": requested,
        "completed": total_completed,
        "successful": total_successes,
        "failed": requested - total_successes,
        "goodput_rps": _round(total_successes / duration_seconds),
        "error_rate": _round((requested - total_successes) / requested) if requested else 1.0,
        "latency_ms": {
            "count": len(all_latencies),
            "min": _round(min(all_latencies) if all_latencies else None),
            "p50": _round(percentile(all_latencies, 50)),
            "p95": _round(percentile(all_latencies, 95)),
            "p99": _round(percentile(all_latencies, 99)),
            "max": _round(max(all_latencies) if all_latencies else None),
        },
        "errors": dict(sorted(errors.items())),
        "routes": routes,
    }


def validate_cli_values(backend, image, payload_sha256):
    """Pure validation for the public backend/image/payload contract."""
    if backend not in ("native", "docker"):
        raise ValueError("--backend must be native or docker")
    if backend == "docker":
        if not isinstance(image, str) or not IDENTIFIER.fullmatch(image[7:]) \
                or not image.startswith("sha256:"):
            raise ValueError("--image must be an exact local sha256:<64-hex> image ID")
    elif image is not None:
        raise ValueError("--image is valid only with --backend docker")
    if not isinstance(payload_sha256, str) or not PAYLOAD_DIGEST.fullmatch(payload_sha256):
        raise ValueError("--payload-sha256 must be a lowercase SHA-256 digest")


def validate_results_dir(value):
    """Return an existing, non-symlink absolute results directory."""
    if isinstance(value, Path):
        path = value
    elif isinstance(value, str) and value:
        path = Path(value)
    else:
        raise ValueError("--results-dir must name an existing directory")
    if not path.is_absolute() or "\x00" in str(path) or path.is_symlink():
        raise ValueError("--results-dir must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError("--results-dir cannot be resolved") from error
    if resolved != path or not path.is_dir():
        raise ValueError("--results-dir must be an existing non-symlink directory")
    return path


def _safe_regular_file(path):
    if path.is_symlink() or not path.is_file():
        raise CapacityError(f"Expected a regular payload file: {path}")
    return path


def file_digest(path):
    path = _safe_regular_file(Path(path))
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _fixture_identity(name):
    fixture = FIXTURES[name]
    return {
        "fixture_sha256": benchmark.fixture_digest(fixture),
        "runtime": fixture["runtime"],
        "argv": list(fixture["argv"]),
        "port": fixture["port"],
        "response": fixture["response"],
        "response_sha256": hashlib.sha256(fixture["response"].encode()).hexdigest(),
        "workers": fixture["workers"],
    }


def source_identities():
    root = Path(__file__).resolve().parent
    return {name: file_digest(root / name) for name in SOURCE_FILES}


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def make_report(backend, run_id, results_dir, image, payload_sha256):
    payload = {"source_files_sha256": source_identities()}
    report = {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "collector": {
            "name": REPORT_TYPE,
            "version": COLLECTOR_VERSION,
            "source_files_sha256": payload["source_files_sha256"],
        },
        "scope": "request-capacity",
        "experiment_scope": "disposable-qemu-guest-only",
        "production": False,
        "backend": backend,
        "image": image,
        "payload_sha256": payload_sha256,
        "run_id": run_id,
        "results_dir": str(results_dir),
        "started_at": _utc_now(),
        "ended_at": None,
        "passed": False,
        "collection_valid": False,
        "phase0_complete": False,
        "environment": {
            **benchmark.environment(),
            "architecture": platform.machine(),
            "boot_id": _boot_id(),
            "lab_marker": Path("/etc/halvo-native-lab").read_text().strip(),
            "vm_id": Path("/etc/halvo-native-lab-vm-id").read_text().strip(),
        },
        "configuration": {
            "route_order": list(ROUTE_ORDER),
            "route_weights_percent": dict(ROUTE_WEIGHTS),
            "rates_per_second": list(RATES_PER_SECOND),
            "warmup_seconds": WARMUP_SECONDS,
            "measurement_seconds": MEASUREMENT_SECONDS,
            "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
            "schedule": "fixed-open-loop-deterministic-cycle",
        },
        "expected_limits": dict(LIMITS),
        "fixtures": {name: _fixture_identity(name) for name in ALL_FIXTURES},
        "payload": payload,
        "residents": {},
        "rates": [],
        "errors": [],
        "cleanup": {"attempted": False, "passed": False, "evidence": [], "errors": []},
    }
    return report


def _report_json(report):
    """Serialize a report strictly, rejecting NaN and accidental non-JSON data."""
    return json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"


def write_report(output, report):
    output = Path(output)
    if output.name != "capacity.json" or output.parent.is_symlink() or output.is_symlink():
        raise CapacityError("capacity report path must be a non-symlink results file")
    text = _report_json(report)
    temporary = output.parent / f".capacity.{report['run_id']}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise CapacityError("stale capacity report temporary file exists")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_cgroup_path(root, control_group):
    if not isinstance(control_group, str) or not control_group.startswith("/") \
            or ".." in Path(control_group).parts:
        raise ResidentFailure("workload cgroup path is not absolute and bounded")
    path = Path(root) / control_group.lstrip("/")
    if not path.exists() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ResidentFailure("workload cgroup path is missing or contains a symlink")
    return path


def limits_at(cgroup):
    values = {}
    for name in LIMITS:
        path = Path(cgroup) / name
        if path.is_symlink():
            raise ResidentFailure(f"cgroup limit file is a symlink: {name}")
        try:
            values[name] = path.read_text().strip()
        except OSError as error:
            raise ResidentFailure(f"could not read enforced limit {name}") from error
    return values


def memory_events_at(cgroup):
    path = Path(cgroup) / "memory.events"
    if path.is_symlink():
        raise ResidentFailure("memory.events is a symlink")
    values = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdigit():
            raise ResidentFailure("malformed memory.events")
        values[fields[0]] = int(fields[1])
    if not {"oom", "oom_kill"}.issubset(values):
        raise ResidentFailure("memory.events is missing OOM counters")
    return values


def cgroup_processes(cgroup):
    path = Path(cgroup) / "cgroup.procs"
    if path.is_symlink():
        raise ResidentFailure("cgroup.procs is a symlink")
    try:
        return tuple(path.read_text().split())
    except FileNotFoundError:
        return ()


def cgroup_empty(cgroup):
    try:
        events = dict(row.split() for row in (Path(cgroup) / "cgroup.events").read_text().splitlines())
    except FileNotFoundError:
        return True
    if events.get("populated") not in ("0", 0):
        return False
    return not cgroup_processes(cgroup)


def process_start(pid):
    try:
        return benchmark.pid_identity(pid)
    except (FileNotFoundError, ProcessLookupError, OSError) as error:
        raise ResidentFailure(f"resident process {pid} disappeared") from error


def pid_unified_cgroup(pid):
    """Resolve a live process's own cgroups v2 path from procfs.

    This is the cheap health-sampling primitive: one procfs read and no
    subprocess, so the monitor does not compete with the residents for the
    guest's two vCPUs under load.
    """
    try:
        rows = [line.split(":", 2)
                for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()]
    except (FileNotFoundError, ProcessLookupError, OSError) as error:
        raise ResidentFailure(f"resident process {pid} cgroup is unreadable") from error
    unified = [row[2] for row in rows if len(row) == 3 and row[:2] == ["0", ""]]
    if len(unified) != 1:
        raise ResidentFailure("resident did not expose one cgroups v2 path")
    return _safe_cgroup_path("/sys/fs/cgroup", unified[0])



def worker_checkpoint(pid):
    path = Path(f"/proc/{pid}/root/tmp/checkpoint")
    try:
        value = path.read_text().strip()
    except (FileNotFoundError, OSError) as error:
        raise ResidentFailure("worker checkpoint is missing") from error
    if not value.isdigit():
        raise ResidentFailure("worker checkpoint is malformed")
    return int(value)


def describe_error(error):
    if isinstance(error, CapacityError):
        return str(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return f"{error.cmd!s} timed out"
    if isinstance(error, subprocess.CalledProcessError):
        return f"command exited {error.returncode}: {error.cmd!s}"
    return str(error)


def _diagnostic_json(value, depth=0):
    """Retain malformed protocol evidence without invalidating report JSON."""
    if depth > 32:
        return "<diagnostic nesting exceeded 32 levels>"
    if isinstance(value, float) and not math.isfinite(value):
        return f"<non-finite number: {value!r}>"
    if isinstance(value, dict):
        return {str(key): _diagnostic_json(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_diagnostic_json(item, depth + 1) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class ResidentManager:
    """Common health, readiness, and cleanup behavior for one backend."""

    def __init__(self, run_id):
        if not RUN_IDENTIFIER.fullmatch(run_id):
            raise ValueError("invalid run identifier")
        self.run_id = run_id
        self.entries = {}
        self.cleanup_evidence = []
        self.cleanup_errors = []
        self.prepared = False

    def prepare(self, report):  # pragma: no cover - backend implementations.
        raise NotImplementedError

    def preflight(self):  # pragma: no cover - backend implementations.
        raise NotImplementedError

    def launch_all(self):  # pragma: no cover - backend implementations.
        raise NotImplementedError

    def client_target(self, route):
        return self.entries[route]["pid"]

    def _state(self, entry):  # pragma: no cover - backend implementations.
        raise NotImplementedError

    def _stop_entry(self, entry):  # pragma: no cover - backend implementations.
        raise NotImplementedError

    def _check_ownership(self, entry):  # pragma: no cover - backend implementations.
        raise NotImplementedError

    def _record_state(self, entry, state):
        pid = state.get("pid", entry["pid"])
        if pid != entry["pid"] or process_start(pid) != entry["pid_start_time"]:
            raise ResidentFailure(f"{entry['name']} exited or restarted")
        if not state.get("active", False):
            raise ResidentFailure(f"{entry['name']} is not active")
        if state.get("oom_killed", False):
            raise ResidentFailure(f"{entry['name']} was OOM-killed")
        if state.get("restart_count", 0) != entry["restart_count"]:
            entry["restarts"] = max(entry.get("restarts", 0), state.get("restart_count", 0))
            raise ResidentFailure(f"{entry['name']} restarted")
        limits = limits_at(entry["cgroup"])
        if limits != LIMITS:
            raise ResidentFailure(f"{entry['name']} effective cgroup limits changed")
        events = memory_events_at(entry["cgroup"])
        baseline = entry["memory_events"]
        ooms = max(events.get("oom", 0) - baseline.get("oom", 0),
                   events.get("oom_kill", 0) - baseline.get("oom_kill", 0), 0)
        entry["ooms"] = ooms
        if ooms:
            raise ResidentFailure(f"{entry['name']} hit an OOM event")
        if not cgroup_processes(entry["cgroup"]):
            raise ResidentFailure(f"{entry['name']} cgroup is empty")
        entry["last_state"] = state
        entry["last_limits"] = limits
        entry["last_memory_events"] = events
        return state

    def check_all(self):
        snapshots = {}
        for name in ALL_FIXTURES:
            entry = self.entries.get(name)
            state = None
            try:
                if entry is None:
                    raise ResidentFailure(f"resident fixture {name} was not launched")
                state = self._state(entry)
                snapshots[name] = self._record_state(entry, state)
            except Exception as error:
                error.resident_snapshots = snapshots
                error.resident_fixture = name
                error.resident_state = state
                raise
        return snapshots

    def _probe_ready(self, entry):
        self._record_state(entry, self._state(entry))
        fixture = entry["fixture"]
        try:
            if fixture["port"] is None:
                worker_checkpoint(entry["pid"])
                return True
            return benchmark.ready(entry["pid"], fixture)
        except (FileNotFoundError, OSError, ValueError, ResidentFailure,
                subprocess.SubprocessError):
            return False

    def wait_ready(self):
        pending = set(ALL_FIXTURES)
        attempts = Counter()
        deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
        while pending and time.monotonic() < deadline:
            for name in tuple(pending):
                attempts[name] += 1
                if self._probe_ready(self.entries[name]):
                    self.entries[name]["readiness"] = {
                        "ready": True,
                        "attempts": attempts[name],
                        "observed_at_monotonic": time.monotonic(),
                    }
                    pending.remove(name)
            if pending:
                time.sleep(0.25)
        if pending:
            raise ResidentFailure("missing readiness: " + ", ".join(sorted(pending)))
        self.check_all()
        return {name: dict(self.entries[name]["readiness"]) for name in ALL_FIXTURES}

    def worker_progress(self):
        worker = self.entries["worker"]
        self._record_state(worker, self._state(worker))
        return worker_checkpoint(worker["pid"])

    def resident_report(self):
        result = {}
        for name in ALL_FIXTURES:
            entry = self.entries.get(name)
            if entry is None:
                continue
            result[name] = {
                "fixture_sha256": entry["fixture"]["fixture_sha256"],
                "runtime": entry["fixture"]["runtime"],
                "argv": list(entry["fixture"]["argv"]),
                "pid": entry.get("pid"),
                "pid_start_time": entry.get("pid_start_time"),
                "cgroup": str(entry.get("cgroup")) if entry.get("cgroup") else None,
                "unit": entry.get("unit"),
                "container_id": entry.get("container_id"),
                "configuration_sha256": entry.get("configuration_sha256"),
                "enforced_limits": entry.get("last_limits", entry.get("limits", {})),
                "memory_events": entry.get("last_memory_events", entry.get("memory_events", {})),
                "readiness": dict(entry.get("readiness", {"ready": False})),
                "restarts": entry.get("restarts", 0),
                "ooms": entry.get("ooms", 0),
                "workers": entry["fixture"]["workers"],
            }
        return result

    def cleanup(self):
        """Stop/remove only entries owned by this run and verify emptiness."""
        self.cleanup_evidence = []
        self.cleanup_errors = []
        for name in reversed(ALL_FIXTURES):
            entry = self.entries.get(name)
            if entry is None:
                continue
            evidence = {"name": name, "owned": False, "stopped": False, "empty": False}
            try:
                self._check_ownership(entry)
                evidence["owned"] = True
                self._stop_entry(entry)
                evidence["stopped"] = True
                evidence["empty"] = cgroup_empty(entry["cgroup"])
                if not evidence["empty"]:
                    raise CapacityError(f"{name} cgroup remained populated")
            except Exception as error:
                self.cleanup_errors.append(f"{name}: {describe_error(error)}")
            self.cleanup_evidence.append(evidence)
        return {
            "attempted": bool(self.entries),
            "passed": bool(self.entries) and not self.cleanup_errors,
            "evidence": self.cleanup_evidence,
            "errors": self.cleanup_errors,
        }


class NativeResidents(ResidentManager):
    def __init__(self, run_id):
        super().__init__(run_id)
        self.workspace = None
        self.units = []

    def preflight(self):
        if os.geteuid() != 0:
            raise CapacityError("native capacity collection requires root in the guest")
        if any(shutil.which(tool) for tool in ("docker", "podman", "containerd")):
            raise CapacityError("native capacity collection refuses a Docker-capable guest")
        units = probe.call("systemctl", "list-units", "--state=active", "--no-legend",
                           "--plain", "halvo-*", check=True, timeout=30).stdout
        if units.strip():
            raise CapacityError("active Halvo units exist; refusing stale or unowned workload processes")

    def _make_workspace(self):
        if not probe.LAB.is_dir() or probe.LAB.is_symlink():
            raise CapacityError("native lab workspace is missing or a symlink")
        self.workspace = Path(tempfile.mkdtemp(prefix=f"capacity-{self.run_id}-",
                                                dir=str(probe.LAB)))
        self.workspace.chmod(0o755)
        root = self.workspace / "root"
        for directory in ("usr", "bin", "lib", "lib64", "opt/node", "app", "tmp",
                          "data", "dev", "proc"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        for device in ("null", "zero", "urandom"):
            (root / "dev" / device).touch()
        capacity_fixtures.write_fixtures(self.workspace / "app")

    def _config(self, name):
        fixture = FIXTURES[name]
        config = probe.configuration(runtime=MAX_RESIDENT_RUNTIME_SECONDS)
        config = config.replace(probe.mount(probe.LAB / "root", "/"),
                                probe.mount(self.workspace / "root", "/"))
        config = config.replace(probe.mount(probe.APP, "/app", True),
                                probe.mount(self.workspace / "app", "/app"))
        config = config.replace(probe.mount("/quota/app-a", "/data", True), "")
        config = config.replace("rlimit_nproc_type: HARD", "rlimit_nproc: 128")
        path = self.workspace / f"{name}.cfg"
        path.write_text(config)
        path.chmod(0o644)
        return path, fixture

    def prepare(self, report):
        self._make_workspace()
        runtimes = {}
        for name in ALL_FIXTURES:
            runtime = FIXTURES[name]["runtime"]
            if runtime not in runtimes:
                runtimes[runtime] = benchmark.runtime_identity(runtime)
        report["payload"]["runtime_identities"] = runtimes
        report["payload"]["nsjail_sha256"] = file_digest("/usr/local/bin/nsjail")
        report["payload"]["syscalls_policy_sha256"] = file_digest(
            Path(__file__).resolve().with_name("syscalls.policy"))
        report["payload"]["workspace_fixture_sha256"] = {
            name: benchmark.fixture_digest(FIXTURES[name]) for name in ALL_FIXTURES
        }
        self.prepared = True

    def launch_all(self):
        if not self.prepared or self.workspace is None:
            raise CapacityError("native residents were not prepared")
        for name in ALL_FIXTURES:
            config_path, fixture = self._config(name)
            unit = f"halvo-capacity-{self.run_id}-{name}.service"
            log = self.workspace / f"{name}.log"
            self.units.append(unit)
            probe.call(
                "systemd-run", "--quiet", f"--unit={unit}",
                "--property=Type=exec", "--property=MemoryAccounting=yes",
                "--property=CPUAccounting=yes", "--property=MemoryMax=256M",
                "--property=MemorySwapMax=0", "--property=CPUQuota=50%",
                "--property=CPUQuotaPeriodSec=100ms", "--property=TasksMax=128",
                "--property=LimitNOFILE=256", "--property=KillMode=control-group",
                f"--property=RuntimeMaxSec={MAX_RESIDENT_RUNTIME_SECONDS}s",
                "--property=TimeoutStopSec=3s", "--property=OOMPolicy=kill",
                "--property=StandardOutput=null",
                f"--property=StandardError=append:{log}",
                "/usr/local/bin/nsjail", "--config", str(config_path), "--", *fixture["argv"],
                timeout=30,
            )
            self._capture_native_entry(name, unit, fixture, config_path)
        self.wait_ready()

    def _capture_native_entry(self, name, unit, fixture, config_path):
        deadline = time.monotonic() + 30
        state = {}
        cgroup = None
        while time.monotonic() < deadline:
            state = probe.properties(unit)
            if state.get("ActiveState") not in ("active", "activating"):
                raise ResidentFailure(f"{name} failed before cgroup capture")
            if state.get("ControlGroup"):
                cgroup = _safe_cgroup_path("/sys/fs/cgroup", state["ControlGroup"])
                try:
                    pid = benchmark.jail_pid(cgroup)
                    start = process_start(pid)
                    limits = limits_at(cgroup)
                    if limits != LIMITS:
                        raise ResidentFailure(f"{name} effective cgroup limits differ from specification")
                    entry = {
                        "name": name, "fixture": _fixture_identity(name),
                        "unit": unit, "pid": pid, "pid_start_time": start,
                        "cgroup": cgroup, "invocation_id": state.get("InvocationID"),
                        "configuration_sha256": file_digest(config_path),
                        "limits": limits, "last_limits": limits,
                        "memory_events": memory_events_at(cgroup),
                        "restart_count": int(state.get("NRestarts", "0") or 0),
                        "restarts": 0, "ooms": 0,
                    }
                    self.entries[name] = entry
                    return
                except (FileNotFoundError, RuntimeError, ResidentFailure):
                    pass
            time.sleep(0.1)
        raise ResidentFailure(f"{name} did not expose a stable resident cgroup")

    def _state(self, entry):
        # Mirror the Docker health path: derive liveness from the main process
        # and the unit's own cgroup rather than a `systemctl show` round-trip on
        # every sample, so the monitor does not compete with the residents under
        # load. The systemd invocation and restart counter are re-verified at
        # cleanup, not on the hot path; a real restart (KillMode=control-group,
        # Restart=no) kills the held pid and is caught, and OOM-kills are read
        # from the cgroup's own memory.events counter.
        pid = entry["pid"]
        if process_start(pid) != entry["pid_start_time"]:
            raise ResidentFailure(f"{entry['name']} main process restarted")
        cgroup = pid_unified_cgroup(pid)
        if cgroup != entry["cgroup"]:
            raise ResidentFailure(f"{entry['name']} systemd cgroup changed")
        events = memory_events_at(cgroup)
        baseline = entry["memory_events"]
        return {
            "active": True,
            "pid": pid,
            "restart_count": entry["restart_count"],
            "oom_killed": events.get("oom_kill", 0) - baseline.get("oom_kill", 0) > 0,
            "invocation_id": entry.get("invocation_id"),
        }

    def _check_ownership(self, entry):
        state = probe.properties(entry["unit"])
        current = state.get("InvocationID")
        if current and entry.get("invocation_id") and current != entry["invocation_id"]:
            raise CapacityError(f"refusing cleanup of unit with a different invocation: {entry['unit']}")

    def _stop_entry(self, entry):
        result = probe.call("systemctl", "stop", entry["unit"], check=False, timeout=15)
        if result.returncode:
            raise CapacityError(f"stopping {entry['unit']} failed")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            state = probe.properties(entry["unit"])
            if not state or state.get("ActiveState") in ("inactive", "failed"):
                break
            time.sleep(0.1)
        if not cgroup_empty(entry["cgroup"]):
            raise CapacityError(f"unit {entry['unit']} still has processes")
        reset = probe.call("systemctl", "reset-failed", entry["unit"], check=False, timeout=15)
        if reset.returncode:
            raise CapacityError(f"reset-failed failed for {entry['unit']}")

    def cleanup(self):
        result = super().cleanup()
        # A launch can succeed and then fail before its cgroup is captured.
        # The UUID-bearing unit name is still ours, so stop only those exact
        # units and record the extra cleanup evidence.
        captured_units = {entry.get("unit") for entry in self.entries.values()}
        for unit in self.units:
            if unit in captured_units:
                continue
            evidence = {"unit": unit, "owned": True, "stopped": False}
            try:
                state = probe.properties(unit)
                if state and state.get("ActiveState") in ("active", "activating"):
                    stopped = probe.call("systemctl", "stop", unit, check=False, timeout=15)
                    if stopped.returncode:
                        raise CapacityError(f"stopping {unit} failed")
                reset = probe.call("systemctl", "reset-failed", unit, check=False, timeout=15)
                if reset.returncode:
                    raise CapacityError(f"reset-failed failed for {unit}")
                evidence["stopped"] = True
            except Exception as error:
                self.cleanup_errors.append(f"{unit}: {describe_error(error)}")
            self.cleanup_evidence.append(evidence)
        if self.cleanup_errors:
            result["errors"] = self.cleanup_errors
            result["passed"] = False
        if self.workspace is not None and not self.cleanup_errors:
            try:
                if self.workspace.is_symlink() or self.workspace.parent != probe.LAB:
                    raise CapacityError("refusing to remove an unowned native workspace")
                shutil.rmtree(self.workspace)
                result["workspace_removed"] = not self.workspace.exists()
                if not result["workspace_removed"]:
                    raise CapacityError("native workspace remained after cleanup")
            except Exception as error:
                self.cleanup_errors.append(f"workspace: {describe_error(error)}")
                result["errors"] = self.cleanup_errors
                result["passed"] = False
        elif self.workspace is not None:
            result["workspace_removed"] = False
        return result


class DockerResidents(ResidentManager):
    def __init__(self, run_id, image):
        super().__init__(run_id)
        self.image = image
        self.owned = []
        self.image_runtime_identities = {}
        self.image_fixture_digests = {}

    @staticmethod
    def call(*args, timeout=60, check=True):
        return subprocess.run((*DOCKER, *args), check=check, capture_output=True,
                              text=True, timeout=timeout)

    def inspect_container(self, identifier, timeout=HEALTH_COMMAND_TIMEOUT_SECONDS):
        if not IDENTIFIER.fullmatch(identifier):
            raise CapacityError("Docker returned an invalid container identity")
        value = json.loads(self.call("container", "inspect", identifier, timeout=timeout).stdout)
        if len(value) != 1 or value[0].get("Id") != identifier:
            raise CapacityError("Docker container identity changed")
        return value[0]

    def validate_image(self):
        if not isinstance(self.image, str) or not self.image.startswith("sha256:") \
                or not IDENTIFIER.fullmatch(self.image[7:]):
            raise ValueError("--image must be an exact local sha256 image ID")
        value = json.loads(self.call("image", "inspect", self.image, timeout=30).stdout)
        if len(value) != 1 or value[0].get("Id") != self.image:
            raise CapacityError("requested Docker image is unavailable locally")
        config = value[0].get("Config", {})
        if config.get("Volumes"):
            raise CapacityError("capacity images must not declare automatic volumes")
        inherited = config.get("Env") or []
        if not isinstance(inherited, list):
            raise CapacityError("Docker image environment is malformed")
        seen = set()
        for item in inherited:
            if not isinstance(item, str) or "=" not in item:
                raise CapacityError("Docker image environment contains a malformed entry")
            key = item.split("=", 1)[0]
            if key not in benchmark.ENV or key in seen:
                raise CapacityError("Docker image environment adds an unapproved setting")
            seen.add(key)

    def preflight(self):
        if os.geteuid() != 0:
            raise CapacityError("Docker capacity collection requires root in the guest")
        self.validate_image()
        stale = self.call("container", "ls", "-aq", "--filter", f"label={DOCKER_LABEL}",
                          timeout=30).stdout.split()
        stale_names = self.call("container", "ls", "-aq", "--filter", "name=halvo-capacity-",
                               timeout=30).stdout.split()
        stale = sorted(set(stale) | set(stale_names))
        for identifier in stale:
            if not IDENTIFIER.fullmatch(identifier):
                raise CapacityError("Docker returned an invalid stale container identity")
        if stale:
            raise CapacityError("stale or unowned capacity containers exist; refusing to mix runs")

    def _create(self, purpose, argv):
        name = f"halvo-capacity-{self.run_id}-{purpose}"
        command = ["container", "create", "--pull", "never", "--name", name,
                   "--label", f"{DOCKER_LABEL}={self.run_id}", "--network", "none",
                   "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--user", "1000:1000", "--memory", "256m", "--memory-swap", "256m",
                   "--cpus", "0.5", "--pids-limit", "128", "--ulimit", "nofile=256:256",
                   "--ulimit", "nproc=128:128", "--restart", "no", "--stop-timeout", "3",
                   "--no-healthcheck", "--log-driver", "local", "--log-opt", "max-size=1m",
                   "--log-opt", "max-file=1", "--log-opt", "compress=false", "--workdir", "/app"]
        for key, value in sorted(benchmark.ENV.items()):
            command.extend(("--env", f"{key}={value}"))
        command.extend(("--entrypoint", argv[0], self.image, *argv[1:]))
        identifier = self.call(*command, timeout=60).stdout.strip()
        if not IDENTIFIER.fullmatch(identifier):
            raise CapacityError("Docker did not return a complete created container ID")
        self.owned.append(identifier)
        return identifier

    def _remove(self, identifier):
        state = self.inspect_container(identifier)
        labels = state.get("Config", {}).get("Labels", {}) or {}
        if labels.get(DOCKER_LABEL) != self.run_id:
            raise CapacityError("refusing cleanup of a container without this run's ownership label")
        result = self.call("container", "rm", "--force", identifier, timeout=30, check=False)
        if result.returncode:
            raise CapacityError(f"Docker removal failed for {identifier}")
        remaining = self.call("container", "ls", "-aq", "--no-trunc", "--filter",
                              f"id={identifier}", timeout=30).stdout.split()
        if remaining:
            raise CapacityError(f"Docker container {identifier} survived removal")

    def _image_json(self, args):
        identifier = self._create("probe-" + uuid.uuid4().hex[:12],
                                 ["/usr/bin/python3", "/app/capacity_fixtures.py", *args])
        try:
            try:
                result = self.call("container", "start", "--attach", identifier,
                                   timeout=120)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                # Only this fixed image probe may expose stderr. Inspect output
                # and stdout stay private; the guest report allows 512 characters.
                reason = (f"exited {error.returncode}" if isinstance(error, subprocess.CalledProcessError)
                          else "timed out")
                stderr = (error.stderr or "")[-400:]
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                raise CapacityError(f"Docker image identity probe {reason}; stderr: {stderr.strip()}") from error
            state = self.inspect_container(identifier)["State"]
            if state.get("Running") or state.get("ExitCode") != 0:
                raise CapacityError("Docker image identity probe failed")
            return json.loads(result.stdout)
        finally:
            self._remove(identifier)
            if identifier in self.owned:
                self.owned.remove(identifier)

    def prepare(self, report):
        for name in ALL_FIXTURES:
            actual = self._image_json(["--fixture-digest", name])
            expected = benchmark.fixture_digest(FIXTURES[name])
            if actual != expected:
                raise CapacityError(f"Docker image bytes do not match the {name} fixture")
            self.image_fixture_digests[name] = actual
        for name in ALL_FIXTURES:
            runtime = FIXTURES[name]["runtime"]
            if runtime not in self.image_runtime_identities:
                self.image_runtime_identities[runtime] = self._image_json(["--identity", runtime])
        report["payload"]["image_fixture_sha256"] = self.image_fixture_digests
        report["payload"]["runtime_identities"] = self.image_runtime_identities
        self.prepared = True

    def launch_all(self):
        if not self.prepared:
            raise CapacityError("Docker residents were not prepared")
        for name in ALL_FIXTURES:
            fixture = FIXTURES[name]
            identifier = self._create(name, fixture["argv"])
            self.call("container", "start", identifier, timeout=30)
            self._capture_docker_entry(name, identifier, fixture)
        self.wait_ready()

    def _container_cgroup(self, pid, identifier):
        path = pid_unified_cgroup(pid)
        if path.name not in (identifier, f"docker-{identifier}.scope"):
            raise ResidentFailure("Docker cgroup does not match the complete container ID")
        return path

    def _capture_docker_entry(self, name, identifier, fixture):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = self.inspect_container(identifier)
            status = state.get("State", {})
            if not status.get("Running"):
                raise ResidentFailure(f"{name} container exited before capture")
            pid = status.get("Pid")
            if isinstance(pid, int) and pid > 0:
                try:
                    cgroup = self._container_cgroup(pid, identifier)
                    start = process_start(pid)
                    limits = limits_at(cgroup)
                except (FileNotFoundError, OSError):
                    time.sleep(0.1)
                    continue
                if limits != LIMITS:
                    raise ResidentFailure(f"{name} Docker limits differ from specification")
                labels = state.get("Config", {}).get("Labels", {}) or {}
                if labels.get(DOCKER_LABEL) != self.run_id:
                    raise ResidentFailure(f"{name} Docker ownership label mismatch")
                entry = {
                    "name": name, "fixture": _fixture_identity(name),
                    "container_id": identifier, "pid": pid, "pid_start_time": start,
                    "cgroup": cgroup, "limits": limits, "last_limits": limits,
                    "memory_events": memory_events_at(cgroup),
                    "restart_count": int(state["RestartCount"]),
                    "restarts": 0, "ooms": 0,
                }
                self.entries[name] = entry
                return
            time.sleep(0.1)
        raise ResidentFailure(f"{name} Docker process did not stabilize")

    def _state(self, entry):
        # Health sampling reads the resident's own cgroup and main-process
        # procfs directly instead of calling `docker inspect` on every sample.
        # Inside the two-vCPU guest the inspect subprocess and its daemon
        # round-trip compete with the residents under load and trip the health
        # deadline before the request error budget can score a window; the
        # cgroup/procfs path imposes no such cost and is the same evidence the
        # record check already relies on. The container-ID-named cgroup re-binds
        # ownership every sample; the label/Id inspection stays at capture and
        # cleanup. A real restart changes the held pid and is caught; OOM-kills
        # are read from the cgroup's own memory.events counter.
        pid = entry["pid"]
        if process_start(pid) != entry["pid_start_time"]:
            raise ResidentFailure(f"{entry['name']} main process restarted")
        cgroup = self._container_cgroup(pid, entry["container_id"])
        if cgroup != entry["cgroup"]:
            raise ResidentFailure(f"{entry['name']} Docker cgroup changed")
        events = memory_events_at(cgroup)
        baseline = entry["memory_events"]
        return {
            "active": True,
            "pid": pid,
            "restart_count": entry["restart_count"],
            "oom_killed": events.get("oom_kill", 0) - baseline.get("oom_kill", 0) > 0,
        }

    def _check_ownership(self, entry):
        state = self.inspect_container(entry["container_id"])
        labels = state.get("Config", {}).get("Labels", {}) or {}
        if labels.get(DOCKER_LABEL) != self.run_id:
            raise CapacityError("refusing cleanup of an unowned Docker container")

    def _stop_entry(self, entry):
        self._remove(entry["container_id"])
        if entry["container_id"] in self.owned:
            self.owned.remove(entry["container_id"])
        if not cgroup_empty(entry["cgroup"]):
            raise CapacityError(f"Docker cgroup remained populated for {entry['name']}")

    def cleanup(self):
        result = super().cleanup()
        for identifier in list(self.owned):
            try:
                self._remove(identifier)
                self.owned.remove(identifier)
            except Exception as error:
                self.cleanup_errors.append(f"container {identifier}: {describe_error(error)}")
        if self.cleanup_errors:
            result["errors"] = self.cleanup_errors
            result["passed"] = False
        result["owned_containers_remaining"] = list(self.owned)
        return result


class ClientPool:
    """One bounded, external request client per HTTP fixture."""

    def __init__(self, manager):
        self.manager = manager
        self.processes = {}
        self.selector = selectors.DefaultSelector()
        self.buffers = {}
        self.pending = {}
        self.received = []
        self.closed = False
        self.close_evidence = None

    def start(self):
        script = Path(__file__).resolve().with_name("capacity_client.py")
        _safe_regular_file(script)
        for route in ROUTE_ORDER:
            fixture = FIXTURES[route]
            pid = self.manager.client_target(route)
            command = ["nsenter", f"--net=/proc/{pid}/ns/net", "--", "/usr/bin/python3",
                       str(script), "--port", str(fixture["port"]), "--expected",
                       fixture["response"], "--timeout", str(REQUEST_TIMEOUT_SECONDS),
                       "--workers", "4", "--queue-size", "512"]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, bufsize=0)
            # Register ownership before any further validation so a failed
            # pipe, cgroup, or protocol check still terminates this exact child.
            self.processes[route] = process
            if process.stdin is None or process.stdout is None:
                raise GeneratorBottleneck(f"{route} client did not expose pipes")
            try:
                cgroup_rows = [line.split(":", 2)
                               for line in Path(f"/proc/{process.pid}/cgroup").read_text().splitlines()]
                unified = [row[2] for row in cgroup_rows
                           if len(row) == 3 and row[:2] == ["0", ""]]
                client_cgroup = _safe_cgroup_path(
                    "/sys/fs/cgroup", unified[0]) if len(unified) == 1 else None
            except (FileNotFoundError, OSError, ResidentFailure) as error:
                raise GeneratorBottleneck("request client cgroup could not be identified") from error
            if client_cgroup == self.manager.entries[route]["cgroup"]:
                raise GeneratorBottleneck("request client entered the measured fixture cgroup")
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            self.buffers[route] = bytearray()
            self.selector.register(process.stdout.fileno(), selectors.EVENT_READ, route)
        deadline = time.monotonic() + CLIENT_START_TIMEOUT_SECONDS
        ready = set()
        while ready != set(ROUTE_ORDER) and time.monotonic() < deadline:
            self._read_available(0.1)
            for route, record in self.received:
                if record.get("type") != "ready" or type(record.get("protocol")) is not int \
                        or record["protocol"] != 1 or route in ready:
                    raise GeneratorBottleneck(f"{route} client returned invalid readiness evidence")
                ready.add(route)
            self.received.clear()
            for route, process in self.processes.items():
                if process.poll() is not None:
                    raise GeneratorBottleneck(f"{route} request client exited during startup")
        if ready != set(ROUTE_ORDER):
            raise GeneratorBottleneck("request client readiness timed out")

    def _read_available(self, timeout):
        for key, _ in self.selector.select(timeout):
            route = key.data
            fd = key.fd
            # Bound work per poll so a chatty pipe cannot starve dispatch.  A
            # batch of many short complete lines is not an oversized line.
            bytes_read = 0
            while bytes_read < 262144:
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    self.selector.unregister(fd)
                    raise GeneratorBottleneck(f"{route} request client closed its output")
                buffer = self.buffers[route]
                buffer.extend(chunk)
                bytes_read += len(chunk)
                while b"\n" in buffer:
                    line, _, remainder = buffer.partition(b"\n")
                    buffer = bytearray(remainder)
                    self.buffers[route] = buffer
                    if len(line) > MAX_PROTOCOL_LINE_BYTES:
                        raise GeneratorBottleneck(f"{route} request client returned an oversized record")
                    try:
                        record = json.loads(line)
                    except (TypeError, ValueError, RecursionError) as error:
                        failure = GeneratorBottleneck(f"{route} request client returned invalid JSON")
                        failure.protocol_failure = {"route": route, "raw_line": line.decode("utf-8", errors="replace")}
                        raise failure from error
                    if not isinstance(record, dict):
                        raise GeneratorBottleneck(f"{route} request client returned an invalid record")
                    self.received.append((route, record))
                    if len(self.received) > MAX_CLIENT_OUTSTANDING + len(ROUTE_ORDER):
                        raise GeneratorBottleneck("request client record backlog exceeded its bound")
                if len(buffer) > MAX_PROTOCOL_LINE_BYTES:
                    raise GeneratorBottleneck(f"{route} request client returned an oversized partial record")

    def _take_records(self, phase_origin):
        outcomes = []
        records, self.received = self.received, []
        for index, (route, record) in enumerate(records):
            try:
                outcome = self._validate_result(route, record, phase_origin)
            except GeneratorBottleneck as error:
                # Keep the offending raw record, unsatisfied request metadata,
                # and already validated rows when a batch fails mid-poll.
                self.received = records[index + 1:] + self.received
                error.validated_outcomes = outcomes
                error.protocol_failure = {"route": route, "record": record}
                raise
            self.pending.pop(record["id"])
            outcomes.append(outcome)
        return outcomes

    def _validate_result(self, route, record, phase_origin):
        if record.get("type") != "result" or isinstance(record.get("id"), bool) \
                or not isinstance(record.get("id"), int) or record["id"] < 0:
            raise GeneratorBottleneck(f"{route} request client protocol error")
        request_id = record["id"]
        metadata = self.pending.get(request_id)
        if metadata is None or metadata["route"] != route \
                or ("route" in record and record["route"] != route):
            raise GeneratorBottleneck("request client returned an unknown or duplicate request")
        scheduled = record.get("scheduled_at")
        if isinstance(scheduled, bool) or not isinstance(scheduled, (int, float)) or not math.isfinite(scheduled) \
                or abs(scheduled - metadata["scheduled_at"]) > 0.001:
            raise GeneratorBottleneck("request client returned a mismatched schedule")
        if record.get("error") in ("client_queue_full", "protocol_error"):
            raise GeneratorBottleneck(f"{route} request client reported a generator bottleneck")
        started = record.get("started_at")
        ended = record.get("ended_at")
        if isinstance(started, bool) or isinstance(ended, bool) \
                or not isinstance(started, (int, float)) or not isinstance(ended, (int, float)) \
                or not math.isfinite(started) or not math.isfinite(ended) \
                or started < metadata["scheduled_at"] or ended < started \
                or started < metadata.get("dispatch_started_at", metadata["scheduled_at"]) \
                or ended > time.monotonic():
            raise GeneratorBottleneck("request client returned invalid timing")
        latency = (ended - started) * 1000
        client_queue_lag = started - metadata["scheduled_at"]
        if client_queue_lag > CLIENT_QUEUE_LAG_LIMIT_SECONDS:
            raise GeneratorBottleneck("request client queue became a generator bottleneck")
        status = record.get("status")
        if status is not None and (not isinstance(status, int) or isinstance(status, bool)
                                   or not 100 <= status <= 599):
            raise GeneratorBottleneck("request client returned an invalid HTTP status")
        ok = record.get("ok")
        if not isinstance(ok, bool):
            raise GeneratorBottleneck("request client returned an invalid outcome")
        error = record.get("error")
        if error is not None and (not isinstance(error, str) or len(error) > 100):
            raise GeneratorBottleneck("request client returned an invalid error")
        if ok and (status != 200 or error is not None):
            raise GeneratorBottleneck("request client returned inconsistent success evidence")
        version = record.get("http_version")
        reused = record.get("connection_reused")
        if version is not None and (type(version) is not int or version not in (10, 11)) \
                or type(reused) is not bool or (ok and version != 11):
            raise GeneratorBottleneck("request client returned invalid HTTP/keep-alive evidence")
        return {
            "id": request_id, "route": route,
            "scheduled_offset_ms": _round((metadata["scheduled_at"] - phase_origin) * 1000),
            "dispatch_lag_ms": _round(metadata["dispatch_lag"] * 1000),
            "client_queue_lag_ms": _round(client_queue_lag * 1000),
            "started_offset_ms": _round((started - phase_origin) * 1000),
            "ended_offset_ms": _round((ended - phase_origin) * 1000),
            "latency_ms": _round(latency), "status": status, "ok": ok, "error": error,
            "http_version": version, "connection_reused": reused,
        }

    def send(self, route, request_id, scheduled_at, phase_origin):
        if isinstance(request_id, bool) or not isinstance(request_id, int) or request_id < 0 \
                or request_id in self.pending or route not in ROUTE_ORDER:
            raise GeneratorBottleneck("invalid or duplicate dispatch identity")
        if len(self.pending) >= MAX_CLIENT_OUTSTANDING:
            raise GeneratorBottleneck("request generator outstanding queue exceeded its bound")
        process = self.processes.get(route)
        if process is None or process.poll() is not None:
            raise GeneratorBottleneck(f"{route} request client is not running")
        now = time.monotonic()
        lag = now - scheduled_at
        if lag > GENERATOR_LAG_LIMIT_SECONDS:
            raise GeneratorBottleneck(f"open-loop dispatch lag exceeded {GENERATOR_LAG_LIMIT_SECONDS}s")
        command = json.dumps({"type": "request", "id": request_id,
                              "scheduled_at": scheduled_at}, separators=(",", ":"),
                             allow_nan=False).encode() + b"\n"
        try:
            written = os.write(process.stdin.fileno(), command)
        except (BlockingIOError, BrokenPipeError, OSError) as error:
            raise GeneratorBottleneck(f"{route} request client pipe is a generator bottleneck") from error
        if written != len(command):
            raise GeneratorBottleneck(f"{route} request client accepted a partial command")
        lag = time.monotonic() - scheduled_at
        self.pending[request_id] = {
            "route": route, "scheduled_at": scheduled_at,
            "dispatch_lag": lag, "phase_origin": phase_origin,
            "dispatch_started_at": now,
        }
        if lag > GENERATOR_LAG_LIMIT_SECONDS:
            raise GeneratorBottleneck(f"open-loop dispatch lag exceeded {GENERATOR_LAG_LIMIT_SECONDS}s")
        return lag

    def poll(self, timeout=0):
        self._read_available(timeout)
        return self._take_records(next(iter(self.pending.values()))["phase_origin"]
                                  if self.pending else time.monotonic())

    def close(self):
        if self.closed:
            return self.close_evidence
        self.closed = True
        errors = []
        evidence = []
        for route, process in self.processes.items():
            item = {"route": route, "pid": process.pid, "terminated": False, "survived": False}
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except Exception as error:
                errors.append(f"{route} client stdin cleanup: {describe_error(error)}")
            try:
                if process.poll() is None:
                    process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.terminate()
                    item["terminated"] = True
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                        process.wait(timeout=5)
                        errors.append(f"{route} client required SIGKILL")
                    except Exception as error:
                        errors.append(f"{route} client kill cleanup: {describe_error(error)}")
                except Exception as error:
                    errors.append(f"{route} client termination: {describe_error(error)}")
            except Exception as error:
                errors.append(f"{route} client wait cleanup: {describe_error(error)}")
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                    errors.append(f"{route} client survived graceful cleanup")
            except Exception as error:
                errors.append(f"{route} client final cleanup: {describe_error(error)}")
            item["survived"] = process.poll() is None
            if item["survived"]:
                errors.append(f"{route} client survived cleanup")
            if process.returncode not in (None, 0):
                errors.append(f"{route} client exited with status {process.returncode}")
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError as error:
                        errors.append(f"{route} client output cleanup: {describe_error(error)}")
            evidence.append(item)
        try:
            self.selector.close()
        except Exception as error:
            errors.append(f"client selector cleanup: {describe_error(error)}")
        self.close_evidence = {"passed": not errors, "clients": evidence, "errors": errors}
        return self.close_evidence


class PhaseMonitor:
    """Single non-overlapping health probe; dispatch only reads its evidence.

    Backend commands have individual timeouts.  No executor queue or detached
    per-tick tasks can accumulate when a guest is slow.  The final probe runs
    after the worker is joined, before accepting any phase.
    """

    def __init__(self, manager):
        self.manager = manager
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.snapshots = []
        self.failure = None
        self.started_at = None
        self.thread = threading.Thread(target=self._run, name="capacity-health", daemon=True)

    def _sample(self, kind):
        started = time.monotonic()
        with self.lock:
            self.started_at = started
        row = {"kind": kind, "started_at_monotonic": started, "passed": False}
        try:
            row["residents"] = copy.deepcopy(self.manager.check_all())
            if hasattr(self.manager, "resident_report"):
                row["resident_evidence"] = copy.deepcopy(self.manager.resident_report())
            checkpoint = self.manager.worker_progress()
            if isinstance(checkpoint, bool) or not isinstance(checkpoint, int) or checkpoint < 0:
                raise ResidentFailure("worker checkpoint is invalid")
            row["worker_checkpoint"] = checkpoint
            if self.snapshots and checkpoint < self.snapshots[-1].get("worker_checkpoint", checkpoint):
                raise ResidentFailure("worker checkpoint regressed during the phase")
            row["ended_at_monotonic"] = time.monotonic()
            if row["ended_at_monotonic"] - started > HEALTH_CHECK_TIMEOUT_SECONDS:
                raise ResidentFailure("resident health check exceeded its bound")
            row["passed"] = True
        except Exception as error:
            row["error"] = describe_error(error)
            row["failed_fixture"] = getattr(error, "resident_fixture", None)
            row["failed_state"] = copy.deepcopy(getattr(error, "resident_state", None))
            row.setdefault("residents", copy.deepcopy(getattr(error, "resident_snapshots", {})))
            with self.lock:
                self.failure = row["error"]
            if hasattr(self.manager, "resident_report"):
                try:
                    row["resident_evidence"] = copy.deepcopy(self.manager.resident_report())
                except Exception as evidence_error:
                    row["evidence_error"] = describe_error(evidence_error)
        finally:
            row.setdefault("ended_at_monotonic", time.monotonic())
            with self.lock:
                if len(self.snapshots) >= int(MAX_COLLECTION_SECONDS / HEALTH_CHECK_INTERVAL_SECONDS) + 4:
                    self.failure = "resident snapshot history exceeded its collection bound"
                    self.stop.set()
                else:
                    self.snapshots.append(row)
                self.started_at = None
            self.ready.set()

    def _run(self):
        self._sample("before")
        while not self.stop.wait(HEALTH_CHECK_INTERVAL_SECONDS):
            if self.failure:
                return
            self._sample("periodic")

    def start(self):
        self.thread.start()
        if not self.ready.wait(HEALTH_CHECK_TIMEOUT_SECONDS):
            raise ResidentFailure("initial resident health check timed out")
        self.check()

    def check(self):
        with self.lock:
            failure = self.failure
            started = self.started_at
        if failure:
            raise ResidentFailure(failure)
        if started is not None and time.monotonic() - started > HEALTH_CHECK_TIMEOUT_SECONDS:
            raise ResidentFailure("asynchronous resident health check timed out")

    def finish(self, verify=True):
        self.stop.set()
        if self.thread.ident is not None:
            self.thread.join(HEALTH_CHECK_TIMEOUT_SECONDS)
        if self.thread.is_alive():
            with self.lock:
                self.failure = self.failure or "resident monitor did not stop within its bound"
            raise ResidentFailure(self.failure)
        if verify:
            self.check()
            self._sample("after")
            self.check()
            if self.snapshots[-1]["worker_checkpoint"] <= self.snapshots[0]["worker_checkpoint"]:
                self.failure = "worker checkpoint did not advance through the phase"
                raise ResidentFailure(self.failure)

    def evidence(self):
        with self.lock:
            return {"interval_seconds": HEALTH_CHECK_INTERVAL_SECONDS,
                    "check_timeout_seconds": HEALTH_CHECK_TIMEOUT_SECONDS,
                    "monitor_stopped": not self.thread.is_alive(),
                    "snapshots": copy.deepcopy(self.snapshots), "failure": self.failure}


def run_phase(manager, clients, rate, duration, phase, request_id_start):
    """Run a complete open-loop window, followed by a bounded result drain.

    On failure the exception's phase_evidence retains partial raw outcomes,
    pending requests, phase/drain timing and monitor diagnostics.
    """
    count = validate_schedule(rate, duration)
    if isinstance(request_id_start, bool) or not isinstance(request_id_start, int) or request_id_start < 0:
        raise ValueError("request_id_start must be a non-negative integer")
    monitor = PhaseMonitor(manager)
    outcomes, dispatch_lags = [], []
    timings = {"requested_duration_seconds": duration}
    drain = {"started_at_monotonic": None, "ended_at_monotonic": None,
             "pending_at_start": None, "pending_at_end": None, "completed": False,
             "outcome_ids": []}
    dispatched = 0
    try:
        if clients.pending:
            raise GeneratorBottleneck("phase began with outstanding requests")
        monitor.start()
        phase_origin = time.monotonic()
        phase_end = phase_origin + duration
        timings.update({"origin_monotonic": phase_origin, "scheduled_end_monotonic": phase_end})

        def poll_until(target):
            while time.monotonic() < target:
                monitor.check()
                outcomes.extend(clients.poll(min(0.05, max(0, target - time.monotonic()))))

        for scheduled in iter_schedule(rate, duration):
            target = phase_origin + scheduled["offset_seconds"]
            poll_until(target)
            monitor.check()
            outcomes.extend(clients.poll(0))
            # send measures the real pipe write, after polling.  Compatible
            # adapters may return None; the completion clock is then used.
            lag = clients.send(scheduled["route"], request_id_start + scheduled["index"],
                               target, phase_origin)
            if lag is None:
                lag = time.monotonic() - target
            _finite_number(lag, "dispatch lag")
            dispatched += 1
            dispatch_lags.append(lag * 1000)
            if lag < 0 or lag > GENERATOR_LAG_LIMIT_SECONDS:
                raise GeneratorBottleneck(f"{phase} open-loop schedule fell behind")
        timings["last_dispatch_monotonic"] = time.monotonic()
        # The final request is scheduled at duration - 1/rate; keep collecting
        # and monitoring for the remaining interval before beginning the drain.
        poll_until(phase_end)
        timings["window_ended_monotonic"] = time.monotonic()
        timings["actual_duration_seconds"] = timings["window_ended_monotonic"] - phase_origin
        drain["started_at_monotonic"] = time.monotonic()
        drain["pending_at_start"] = sorted(clients.pending)
        pre_drain_count = len(outcomes)
        deadline = drain["started_at_monotonic"] + PHASE_DRAIN_TIMEOUT_SECONDS
        while clients.pending and time.monotonic() < deadline:
            monitor.check()
            outcomes.extend(clients.poll(min(0.05, max(0, deadline - time.monotonic()))))
        outcomes.extend(clients.poll(0))
        drain["ended_at_monotonic"] = time.monotonic()
        drain["pending_at_end"] = sorted(clients.pending)
        drain["outcome_ids"] = [row["id"] for row in outcomes[pre_drain_count:]]
        if clients.pending:
            raise GeneratorBottleneck(f"{phase} request client did not return {len(clients.pending)} outcomes")
        drain["completed"] = True
        monitor.finish()
        outcomes.sort(key=lambda row: row["id"])
        if len(outcomes) != count:
            raise GeneratorBottleneck(f"{phase} returned {len(outcomes)} of {count} outcomes")
        # Independently verify the exact schedule even for offline adapters.
        for scheduled, row in zip(iter_schedule(rate, duration), outcomes):
            if isinstance(row.get("id"), bool) or not isinstance(row.get("id"), int) \
                    or row.get("id") != request_id_start + scheduled["index"] \
                    or row.get("route") != scheduled["route"]:
                raise GeneratorBottleneck("phase result identity/route does not match the schedule")
            for key in ("scheduled_offset_ms", "dispatch_lag_ms", "client_queue_lag_ms",
                        "started_offset_ms", "ended_offset_ms", "latency_ms"):
                _finite_number(row.get(key), key)
            if abs(row["scheduled_offset_ms"] - scheduled["offset_seconds"] * 1000) > 0.001 \
                    or not 0 <= row["dispatch_lag_ms"] <= GENERATOR_LAG_LIMIT_SECONDS * 1000 \
                    or not 0 <= row["client_queue_lag_ms"] <= CLIENT_QUEUE_LAG_LIMIT_SECONDS * 1000 \
                    or row["started_offset_ms"] < row["scheduled_offset_ms"] \
                    or row["ended_offset_ms"] < row["started_offset_ms"] \
                    or row["ended_offset_ms"] > (time.monotonic() - phase_origin) * 1000 \
                    or row["latency_ms"] < 0 \
                    or abs(row["ended_offset_ms"] - row["started_offset_ms"] - row["latency_ms"]) > 0.001 \
                    or abs(row["started_offset_ms"] - row["scheduled_offset_ms"] - row["client_queue_lag_ms"]) > 0.001:
                raise GeneratorBottleneck("phase result timing does not match the schedule")
        summary = aggregate_outcomes(outcomes, duration)
        summary.update({"phase": phase, "timings": timings, "drain": drain,
                        "health_checks": monitor.evidence()})
        summary["generator"] = {
            "scheduled": count, "dispatched": dispatched, "completed": len(outcomes),
            "max_dispatch_lag_ms": _round(max(dispatch_lags)),
            "p50_dispatch_lag_ms": _round(percentile(dispatch_lags, 50)),
            "p95_dispatch_lag_ms": _round(percentile(dispatch_lags, 95)), "bottleneck": False,
        }
        return outcomes, summary
    except Exception as error:
        outcomes.extend(getattr(error, "validated_outcomes", []))
        dispatched = max(dispatched, len({row["id"] for row in outcomes} | set(clients.pending)))
        timings["aborted_at_monotonic"] = time.monotonic()
        if "origin_monotonic" in timings:
            timings["elapsed_until_abort_seconds"] = timings["aborted_at_monotonic"] - timings["origin_monotonic"]
        if drain["started_at_monotonic"] is not None and drain["ended_at_monotonic"] is None:
            drain["ended_at_monotonic"] = timings["aborted_at_monotonic"]
            drain["outcome_ids"] = [row["id"] for row in outcomes[pre_drain_count:]]
        try:
            monitor.finish(verify=False)
        except Exception as monitor_error:
            timings["monitor_shutdown_error"] = describe_error(monitor_error)
        drain["pending_at_end"] = sorted(clients.pending)
        error.phase_evidence = _diagnostic_json({"phase": phase, "timings": timings, "drain": drain,
                                "dispatched": dispatched, "outcomes": outcomes,
                                "dispatch_lags_ms": dispatch_lags,
                                "pending": copy.deepcopy(clients.pending),
                                "unprocessed_records": copy.deepcopy(getattr(clients, "received", [])),
                                "health_checks": monitor.evidence(),
                                "protocol_failure": getattr(error, "protocol_failure", None)})
        raise


def run_rate(manager, clients, rate, request_id_start):
    warmup_outcomes, warmup = run_phase(manager, clients, rate, WARMUP_SECONDS,
                                        "warmup", request_id_start)
    before_worker = warmup["health_checks"]["snapshots"][0]["worker_checkpoint"]
    after_warmup_worker = warmup["health_checks"]["snapshots"][-1]["worker_checkpoint"]
    try:
        measurement_outcomes, measurement = run_phase(
            manager, clients, rate, MEASUREMENT_SECONDS, "measurement",
            request_id_start + rate * WARMUP_SECONDS)
    except Exception as error:
        error.completed_warmup = {"summary": warmup, "raw_outcomes": warmup_outcomes}
        raise
    measurement_before_worker = measurement["health_checks"]["snapshots"][0]["worker_checkpoint"]
    after_worker = measurement["health_checks"]["snapshots"][-1]["worker_checkpoint"]
    if measurement_before_worker < after_warmup_worker:
        error = ResidentFailure("worker checkpoint regressed between phases")
        error.completed_warmup = {"summary": warmup, "raw_outcomes": warmup_outcomes}
        error.phase_evidence = {"summary": measurement, "outcomes": measurement_outcomes}
        raise error
    error_rate = measurement["error_rate"]
    accepted = error_rate <= ERROR_RATE_MAX
    return {
        "rate_per_second": rate,
        "warmup": {
            "summary": warmup,
            "outcomes": len(warmup_outcomes),
            "worker_checkpoint_before": before_worker,
            "worker_checkpoint_after": after_warmup_worker,
        },
        "measurement": {
            "summary": measurement,
            "worker_checkpoint_before": measurement_before_worker,
            "worker_checkpoint_after": after_worker,
        },
        "raw_outcomes": {
            route: [row for row in measurement_outcomes if row["route"] == route]
            for route in ROUTE_ORDER
        },
        "warmup_raw_outcomes": {
            route: [row for row in warmup_outcomes if row["route"] == route]
            for route in ROUTE_ORDER
        },
        "routes": measurement["routes"],
        "latency_ms": measurement["latency_ms"],
        "generator": measurement["generator"],
        "readiness": manager.resident_report(),
        "accepted": accepted,
        "passed": accepted,
        "error_rate": error_rate,
        "goodput_rps": measurement["goodput_rps"],
        "errors": measurement["errors"],
    }


def _remove_old_report(output):
    if output.is_symlink():
        raise CapacityError("existing capacity.json is a symlink")
    if output.exists() and not output.is_file():
        raise CapacityError("existing capacity.json path is not a regular file")
    # Replacement is atomic later.  A stale regular report is not trusted as
    # evidence, but does not need to be unlinked before the guarded run.


def collect(backend, results_dir, image=None, payload_sha256=None):
    """Collect a report after the disposable-guest guard and read-only preflight."""
    validate_cli_values(backend, image, payload_sha256)
    lab_kind = require_lab()
    if lab_kind != "qemu":
        raise SystemExit("Request-capacity collection requires the disposable QEMU guest")
    results_dir = validate_results_dir(results_dir)
    output = results_dir / "capacity.json"
    _remove_old_report(output)
    run_id = uuid.uuid4().hex
    report = make_report(backend, run_id, results_dir, image, payload_sha256)
    manager = NativeResidents(run_id) if backend == "native" else DockerResidents(run_id, image)
    clients = None
    request_id = 0
    try:
        try:
            manager.preflight()
            manager.prepare(report)
            manager.launch_all()
            report["residents"] = manager.resident_report()
            clients = ClientPool(manager)
            clients.start()
            for rate in RATES_PER_SECOND:
                try:
                    rate_result = run_rate(manager, clients, rate, request_id)
                except Exception as error:
                    report["rates"].append({
                        "rate_per_second": rate,
                        "passed": False,
                        "aborted": True,
                        "errors": [describe_error(error)],
                        "phase_evidence": getattr(error, "phase_evidence", None),
                        "completed_warmup": getattr(error, "completed_warmup", None),
                    })
                    raise
                report["rates"].append(rate_result)
                request_id += rate * (WARMUP_SECONDS + MEASUREMENT_SECONDS)
                report["residents"] = manager.resident_report()
        except Exception as error:
            report["errors"].append(describe_error(error))
    finally:
        if clients is not None:
            report["cleanup"]["client_processes"] = clients.close()
            if not report["cleanup"]["client_processes"]["passed"]:
                report["errors"].extend(report["cleanup"]["client_processes"].get("errors", []))
        resident_cleanup = manager.cleanup()
        report["cleanup"].update(resident_cleanup)
        if resident_cleanup.get("errors"):
            report["errors"].extend(resident_cleanup["errors"])
        report["residents"] = manager.resident_report()
        report["ended_at"] = _utc_now()
        safety_failure = bool(report["errors"])
        report["collection_valid"] = bool(report["rates"]) and any(
            row.get("accepted") for row in report["rates"]
        ) and not safety_failure and report["cleanup"].get("passed", False)
        report["passed"] = report["collection_valid"]
        if report["rates"]:
            passing = [row["rate_per_second"] for row in report["rates"] if row.get("accepted")]
            report["capacity_rps"] = max(passing) if passing else None
        else:
            report["capacity_rps"] = None
        write_report(output, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("native", "docker"), required=True)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--image", help="Exact local Docker image ID (sha256:<64 hex>)")
    parser.add_argument("--payload-sha256", required=True,
                        help="SHA-256 digest of the frozen payload manifest")
    args = parser.parse_args(argv)
    try:
        validate_cli_values(args.backend, args.image, args.payload_sha256)
        validate_results_dir(args.results_dir)
    except ValueError as error:
        parser.error(str(error))

    def timeout_handler(signum, frame):
        raise CapacityError("capacity collection exceeded its fixed global bound")

    previous = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(MAX_COLLECTION_SECONDS)
    try:
        report = collect(args.backend, args.results_dir, args.image, args.payload_sha256)
    except (CapacityError, OSError, subprocess.SubprocessError, ValueError) as error:
        parser.error(describe_error(error))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    print(json.dumps({"report": str(Path(args.results_dir) / "capacity.json"),
                      "passed": report["passed"],
                      "collection_valid": report["collection_valid"],
                      "capacity_rps": report.get("capacity_rps")}, sort_keys=True), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
