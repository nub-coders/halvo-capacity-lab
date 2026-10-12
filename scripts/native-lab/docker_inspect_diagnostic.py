#!/usr/bin/env python3
"""Diagnostic-only Docker inspect latency run; never capacity evidence."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import re
import select
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import capacity  # noqa: E402
import capacity_external as external  # noqa: E402

RATE = 16
WINDOW_SECONDS = 180
DRAIN_SECONDS = 40
INSPECT_SECONDS = WINDOW_SECONDS + 20
INSPECT_INTERVAL_SECONDS = 5.0
INSPECT_TIMEOUT_SECONDS = 5.0
HOST_CPUS = {2, 3}
ROUTES = tuple(capacity.ROUTE_ORDER) + ("worker",)
READINESS_TIMEOUT_SECONDS = len(ROUTES) * INSPECT_TIMEOUT_SECONDS + 10.0

READINESS_MARKER = {
    "diagnostic": "docker-container-inspect-latency",
    "event": "startup_ready",
    "startup_identity_complete": True,
    "startup_fixture_count": len(ROUTES),
}

TRACE_SCRIPT = r'''
import argparse
import json
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--duration", type=float, required=True)
parser.add_argument("--interval", type=float, required=True)
parser.add_argument("--timeout", type=float, required=True)
parser.add_argument("--id", action="append", required=True)
args = parser.parse_args()
ids = {}
for item in args.id:
    route, sep, value = item.partition("=")
    if not sep or route in ids or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise SystemExit("invalid diagnostic container identity")
    ids[route] = value
started = time.monotonic()
next_cycle = started
samples = []
while time.monotonic() - started < args.duration:
    cycle_started = time.monotonic()
    for route in ("python", "static", "node", "worker"):
        begin = time.monotonic()
        row = {"route": route, "started_monotonic": begin, "passed": False}
        try:
            result = subprocess.run(
                ["docker", "--host", "unix:///var/run/docker.sock", "container", "inspect", ids[route]],
                check=True, capture_output=True, text=True, timeout=args.timeout)
            row.update({"passed": True, "returncode": result.returncode})
        except subprocess.TimeoutExpired:
            row["error"] = "TimeoutExpired"
        except subprocess.CalledProcessError as error:
            row.update({"error": "CalledProcessError", "returncode": error.returncode})
        except OSError as error:
            row.update({"error": type(error).__name__})
        row["ended_monotonic"] = time.monotonic()
        row["elapsed_seconds"] = row["ended_monotonic"] - begin
        samples.append(row)
    next_cycle += args.interval
    delay = next_cycle - time.monotonic()
    if delay > 0:
        time.sleep(delay)
ended = time.monotonic()
print(json.dumps({
    "diagnostic": "docker-container-inspect-latency",
    "duration_seconds": ended - started,
    "interval_seconds": args.interval,
    "timeout_seconds": args.timeout,
    "container_routes": sorted(ids),
    "samples": samples,
}, separators=(",", ":")))
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bounded_error(error):
    if isinstance(error, subprocess.TimeoutExpired):
        return "TimeoutExpired"
    return str(error)[:512]


def run_load(pool):
    origin = time.monotonic()
    outcomes = []
    dispatch_lags = []
    errors = []
    dispatched = 0
    try:
        for scheduled in capacity.iter_schedule(RATE, WINDOW_SECONDS):
            target = origin + scheduled["offset_seconds"]
            while time.monotonic() < target:
                outcomes.extend(pool.poll(min(0.05, max(0, target - time.monotonic()))))
            lag = pool.send(scheduled["route"], scheduled["index"], target, origin)
            dispatch_lags.append(lag)
            dispatched += 1
        end = origin + WINDOW_SECONDS
        while time.monotonic() < end:
            outcomes.extend(pool.poll(min(0.05, max(0, end - time.monotonic()))))
        deadline = time.monotonic() + DRAIN_SECONDS
        while pool.pending and time.monotonic() < deadline:
            outcomes.extend(pool.poll(min(0.05, max(0, deadline - time.monotonic()))))
        outcomes.extend(pool.poll(0))
    except Exception as error:
        errors.append(bounded_error(error))
    return {
        "rate_per_second": RATE,
        "window_seconds": WINDOW_SECONDS,
        "drain_seconds": DRAIN_SECONDS,
        "scheduled": RATE * WINDOW_SECONDS,
        "dispatched": dispatched,
        "outcomes": len(outcomes),
        "pending_at_end": len(pool.pending),
        "successful": sum(1 for row in outcomes if row.get("ok") is True),
        "failed": sum(1 for row in outcomes if row.get("ok") is not True),
        "max_dispatch_lag_ms": max(dispatch_lags, default=0) * 1000,
        "errors": errors,
        "capacity_evidence": False,
    }


def start_tracer(lab_dir, ssh_port, container_ids):
    remote = ["sudo", "-n", "/usr/bin/python3", "-B", "/opt/halvo-lab/docker_inspect_trace_guest.py",
              "--duration", str(INSPECT_SECONDS),
              "--interval", str(INSPECT_INTERVAL_SECONDS), "--timeout", str(INSPECT_TIMEOUT_SECONDS)]
    for route in ROUTES:
        remote += ["--id", f"{route}={container_ids[route]}"]
    command = external.ssh_command(lab_dir, ssh_port) + ["lab@127.0.0.1", shlex.join(remote)]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    assert process.stdout is not None
    return process


def validate_readiness_marker(line):
    """Accept only the fixed, sanitized startup marker from the guest."""
    try:
        marker = json.loads(line, object_pairs_hook=_unique_marker_object)
    except (TypeError, ValueError):
        return False
    return (isinstance(marker, dict) and set(marker) == set(READINESS_MARKER) and
            type(marker["diagnostic"]) is str and
            marker["diagnostic"] == READINESS_MARKER["diagnostic"] and
            type(marker["event"]) is str and marker["event"] == READINESS_MARKER["event"] and
            marker["startup_identity_complete"] is True and
            type(marker["startup_fixture_count"]) is int and
            marker["startup_fixture_count"] == len(ROUTES))


def _unique_marker_object(pairs):
    marker = {}
    for key, value in pairs:
        if key in marker:
            raise ValueError("duplicate readiness marker field")
        marker[key] = value
    return marker


def wait_for_readiness(process, timeout=READINESS_TIMEOUT_SECONDS):
    """Read and validate the marker without blocking past its bound."""
    stream = process.stdout
    if stream is None:
        return "missing"
    # In-process tests may supply a StringIO-like stream rather than a pipe.
    # Real tracer processes use the selectable Popen pipe below.
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        line = stream.readline(capacity.MAX_PROTOCOL_LINE_BYTES + 1)
        if not line:
            return "missing"
        if len(line) > capacity.MAX_PROTOCOL_LINE_BYTES:
            return "invalid"
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        return "ready" if validate_readiness_marker(line) else "invalid"
    deadline = time.monotonic() + timeout
    line = bytearray()
    while len(line) < capacity.MAX_PROTOCOL_LINE_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        try:
            readable, _, _ = select.select([stream], [], [], remaining)
        except (OSError, ValueError):
            return "missing"
        if not readable:
            return "timeout"
        # Read only the ready byte: readline can block past the deadline or
        # buffer part of the final report before communicate drains the pipe.
        chunk = os.read(fd, 1)
        if not chunk:
            return "invalid" if line else "missing"
        line.extend(chunk)
        if chunk == b"\n":
            return "ready" if validate_readiness_marker(line) else "invalid"
    return "invalid"


def run_load_after_readiness(tracer, pool):
    """Gate load start on one valid guest startup marker."""
    readiness = wait_for_readiness(tracer)
    if readiness != "ready":
        return readiness, None
    return readiness, run_load(pool)


def validate_diagnostic(report, expected_payload, expected_image, expected_vm_id):
    """Independent receipt validator used by the diagnostic launcher."""
    assert isinstance(report, dict)
    assert report.get("scope") == "docker-health-probe-diagnostic"
    assert report.get("backend") == "docker"
    assert report.get("production") is False
    assert report.get("errors") == []
    assert report.get("image") == expected_image
    assert report.get("payload_sha256") == expected_payload
    assert report.get("phase0_complete") is False
    assert report.get("capacity_evidence") is False
    assert report.get("collection_valid") is False
    assert report.get("passed") is True
    assert report.get("diagnostic_completed") is True
    initial = report.get("guest_initial_report")
    final = report.get("guest_final_report")
    external.validate_guest_report(initial, "docker", expected_image, expected_payload,
                                   vm_id=expected_vm_id)
    external.validate_guest_report(final, "docker", expected_image, expected_payload,
                                    initial=initial)
    assert initial.get("errors") == []
    assert final.get("errors") == []
    assert final.get("cleanup", {}).get("passed") is True
    cleanup = report.get("cleanup")
    assert isinstance(cleanup, dict) and cleanup.get("passed") is True
    for key in ("control", "clients", "forward"):
        assert cleanup[key].get("passed") is True
        assert cleanup[key].get("errors", []) == []
    assert cleanup["control"].get("reply", {}).get("ok") is True
    external._validate_cleanup(cleanup["control"]["reply"])
    load = report.get("load")
    assert isinstance(load, dict)
    assert load.get("rate_per_second") == 16
    assert load.get("window_seconds") == 180
    assert load.get("capacity_evidence") is False
    assert load.get("scheduled") == load.get("dispatched") == 2880
    assert load.get("pending_at_end") == 0
    assert load.get("errors") == []
    trace = report.get("inspect_trace")
    assert isinstance(trace, dict)
    assert set(trace) == {"scope", "phase0_complete", "capacity_evidence", "profile", "fixtures",
                          "startup_identity_complete", "startup_fixture_count", "samples",
                          "sample_count", "diagnostic_completed", "aborted", "error",
                          "observation_error"}
    assert trace.get("scope") == "docker-health-probe-diagnostic"
    assert trace.get("phase0_complete") is False and trace.get("capacity_evidence") is False
    assert trace.get("profile") == {"duration_seconds": 200.0,
                                      "interval_seconds": 5.0,
                                      "timeout_seconds": 5.0}
    assert trace.get("startup_identity_complete") is True
    assert trace.get("startup_fixture_count") == len(ROUTES)
    ids = report.get("container_ids_sha256")
    assert isinstance(ids, dict) and set(ids) == set(ROUTES)
    # Startup coverage is independent of the number of subsequent observations.
    # A timeout on the very first sampling operation is a useful diagnostic.
    fixtures = trace.get("fixtures")
    assert isinstance(fixtures, dict) and set(fixtures) == set(ROUTES)
    for name in ROUTES:
        identity = fixtures[name]
        assert isinstance(identity, dict)
        assert set(identity) == {"purpose", "pid", "pid_start_time", "pid_namespace",
                                 "container_id_sha256"}
        assert identity.get("purpose") == name
        assert type(identity.get("pid")) is int and identity["pid"] > 0
        assert type(identity.get("pid_start_time")) is int and identity["pid_start_time"] > 0
        assert isinstance(identity.get("pid_namespace"), str)
        assert re.fullmatch(r"pid:\[[0-9]+\]", identity["pid_namespace"])
        resident = initial.get("residents", {}).get(name, {})
        container_id = resident.get("container_id")
        assert isinstance(container_id, str) and re.fullmatch(r"[0-9a-f]{64}", container_id)
        assert ids[name] == hashlib.sha256(container_id.encode("ascii")).hexdigest()
        assert identity["container_id_sha256"] == ids[name]
        assert identity["pid"] == resident.get("pid")
        assert identity["pid_start_time"] == resident.get("pid_start_time")
    samples = trace.get("samples")
    assert isinstance(samples, list) and trace.get("sample_count") == len(samples)
    assert type(trace.get("sample_count")) is int and 1 <= len(samples) <= 164
    assert trace.get("diagnostic_completed") is True
    assert trace.get("error") is None
    error = trace.get("observation_error")
    if error is not None:
        assert isinstance(error, dict)
        assert trace.get("aborted") is True
        assert error.get("category") in {"timeout", "docker_error"}
        assert error.get("category") == samples[-1].get("category")
    else:
        assert trace.get("aborted") is False
    for row in samples + ([error] if error is not None else []):
        assert isinstance(row, dict)
        assert set(row).issubset({"operation", "category", "fixture", "elapsed_seconds",
                                  "pid", "pid_start_time", "pid_namespace", "returncode"})
        assert row.get("operation") == "container_inspect"
        assert row.get("fixture") in ("python", "static", "node", "worker")
        assert row.get("category") in {"ok", "timeout", "docker_error"}
        elapsed = row.get("elapsed_seconds")
        assert type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
        if "returncode" in row:
            assert type(row["returncode"]) is int
        for key in ("pid", "pid_start_time", "pid_namespace"):
            if key in row:
                assert row[key] == fixtures[row["fixture"]][key]
        if row.get("category") == "ok":
            assert all(key in row for key in ("pid", "pid_start_time", "pid_namespace"))
    # No raw Docker output or capacity claim may be smuggled into other levels.
    def sanitized(value):
        if isinstance(value, dict):
            for key, child in value.items():
                assert key not in {"stdout", "stderr", "raw", "raw_output", "docker_output",
                                   "capacity", "capacity_claim", "capacity_estimate", "capacity_rps",
                                   "goodput_rps", "rate_summaries", "rates"}
                if key in {"phase0_complete", "capacity_evidence", "collection_valid"}:
                    assert child is False
                sanitized(child)
        elif isinstance(value, list):
            for child in value:
                sanitized(child)
    sanitized(report)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-dir", required=True)
    parser.add_argument("--ssh-port", required=True, type=int)
    parser.add_argument("--backend", choices=("docker",), required=True)
    parser.add_argument("--qemu-pid", required=True, type=int)
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=("diagnostic",), required=True)
    args = parser.parse_args()
    if args.backend != "docker" or args.image != "sha256:da38db8b3347ab4f61eaa54bd09cd6601fb8f42a31a43ad1767d25262dd9e2f8":
        raise SystemExit("diagnostic backend/image mismatch")
    lab_dir = Path(args.lab_dir)
    output = Path(args.output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise SystemExit("diagnostic output must be new")
    external.verify_qemu(args.qemu_pid, lab_dir)
    affinity = external._affinity()
    external._check_affinity(affinity, HOST_CPUS)
    vm_id = (lab_dir / "vm-id").read_text().strip()
    remote = ["sudo", "-n", "/usr/bin/python3", "-B", "/opt/halvo-lab/capacity_guest.py",
              "--backend", "docker", "--payload-sha256", args.payload_sha256,
              "--results-dir", "/results/external-" + vm_id, "--image", args.image]
    command = external.ssh_command(lab_dir, args.ssh_port) + ["lab@127.0.0.1", shlex.join(remote)]
    channel = forward = pool = tracer = None
    readiness_ok = False
    report = {
        "schema_version": 1,
        "report_type": "halvo-native-lab-docker-health-diagnostic",
        "scope": "docker-health-probe-diagnostic",
        "production": False,
        "backend": "docker",
        "image": args.image,
        "payload_sha256": args.payload_sha256,
        "capacity_evidence": False,
        "collection_valid": False,
        "phase0_complete": False,
        "diagnostic_completed": False,
        "started_at": capacity._utc_now(),
        "errors": [],
        "cleanup": {},
    }
    try:
        channel = external.ControlChannel(command, affinity=affinity)
        ready = channel.start()
        initial = ready["report"]
        external.validate_guest_report(initial, "docker", args.image, args.payload_sha256, vm_id=vm_id)
        report["guest_initial_report"] = initial
        container_ids = {name: initial["residents"][name]["container_id"] for name in ROUTES}
        report["container_ids_sha256"] = {name: hashlib.sha256(value.encode()).hexdigest()
                                           for name, value in container_ids.items()}
        forward = external.ForwardProcess(lab_dir, args.ssh_port, ready["endpoints"], affinity=affinity)
        ports = forward.start()
        manager = external.ExternalManager(channel, initial, forward=forward)
        pool = external.ExternalPool(manager, ports, affinity=affinity)
        manager.pool = pool
        pool.start()
        tracer = start_tracer(lab_dir, args.ssh_port, container_ids)
        readiness, load = run_load_after_readiness(tracer, pool)
        raw = b""
        if readiness == "ready":
            readiness_ok = True
            report["load"] = load
            try:
                raw, _ = tracer.communicate(timeout=INSPECT_SECONDS + 90)
            except subprocess.TimeoutExpired:
                tracer.kill()
                raw, _ = tracer.communicate(timeout=10)
                report["errors"].append("inspect tracer exceeded its bound")
        else:
            # A missing, malformed, or late marker means startup identity was
            # not proven to the host.  Never start load or retain capacity
            # evidence in that case.
            report["errors"].append("inspect tracer readiness " + readiness)
            if tracer.poll() is None:
                tracer.kill()
            try:
                raw, _ = tracer.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                report["errors"].append("inspect tracer exceeded its bound")
        raw = raw.decode("utf-8", errors="replace")
        if raw:
            try:
                report["inspect_trace"] = json.loads(raw.strip().splitlines()[-1])
            except (ValueError, IndexError):
                report["errors"].append("inspect tracer returned invalid JSON")
        else:
            report["errors"].append("inspect tracer returned no JSON")
    except Exception as error:
        report["errors"].append(bounded_error(error))
    finally:
        if channel is not None:
            try:
                control = channel.finish()
                report["cleanup"]["control"] = control
                if control.get("reply"):
                    report["guest_final_report"] = control["reply"].get("report")
                    try:
                        external._validate_cleanup(control["reply"])
                    except Exception as error:
                        report["errors"].append("guest cleanup validation: " + bounded_error(error))
            except Exception as error:
                report["errors"].append("guest control cleanup: " + bounded_error(error))
        if pool is not None:
            try:
                report["cleanup"]["clients"] = pool.close()
            except Exception as error:
                report["errors"].append("client cleanup: " + bounded_error(error))
        if forward is not None:
            try:
                report["cleanup"]["forward"] = forward.close()
            except Exception as error:
                report["errors"].append("forward cleanup: " + bounded_error(error))
        report["cleanup"]["passed"] = not report["errors"] and all(
            isinstance(value, dict) and value.get("passed") is True
            for key, value in report["cleanup"].items() if key != "passed")
        report["ended_at"] = capacity._utc_now()
        report["diagnostic_completed"] = (readiness_ok and bool(report.get("inspect_trace")) and
                                           report["cleanup"].get("passed") is True)
        report["passed"] = report["diagnostic_completed"]
        report["source_files_sha256"] = {
            name: digest(ROOT / name) for name in ("capacity.py", "capacity_guest.py", "capacity_external.py",
                                                    "capacity_preflight.py", "capacity_async_client.py",
                                                    "capacity_fixtures.py", "capacity_relay.py",
                                                    "docker_inspect_trace_guest.py", Path(__file__).name)
        }
        output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    return 0 if report["diagnostic_completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
