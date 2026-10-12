#!/usr/bin/env python3
"""Bounded, read-only Docker inspect diagnostics for the marked lab guest.

This program intentionally accepts one fixed diagnostic profile.  It never
enumerates Docker objects and never includes Docker's response or exception
text in its report.  The module is also usable by the offline unit tests with
the subprocess and lab guard replaced by mocks.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from guard import require_lab


SCOPE = "docker-health-probe-diagnostic"
PHASE0_COMPLETE = False
CAPACITY_EVIDENCE = False

FIXTURES = ("python", "static", "node", "worker")
FIXTURE_SET = frozenset(FIXTURES)
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
PROFILE = {"duration_seconds": 200.0, "interval_seconds": 5.0,
           "timeout_seconds": 5.0}
READINESS_MARKER = {
    "diagnostic": "docker-container-inspect-latency",
    "event": "startup_ready",
    "startup_identity_complete": True,
    "startup_fixture_count": len(FIXTURES),
}

# Four fixtures per five-second cycle for the 200-second window.  The extra
# row permits an error to be persisted at the wall boundary without allowing
# an unbounded in-memory or JSON response.
MAX_SAMPLES = len(FIXTURES) * (int(PROFILE["duration_seconds"] /
                                   PROFILE["interval_seconds"]) + 1)
MAX_OUTPUT_BYTES = 64 * 1024
MAX_DOCKER_STDOUT_BYTES = 2 * 1024 * 1024
MAX_DOCKER_STDERR_BYTES = 64 * 1024
MAX_WALL_SECONDS = 240.0
DOCKER = ("docker", "--host", "unix:///var/run/docker.sock", "container", "inspect")
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class InputError(ValueError):
    """A rejected command-line value without retaining the supplied value."""


class TraceStop(RuntimeError):
    """A bounded stop which has already been converted to a safe category."""

    def __init__(self, category, fixture=None, operation="container_inspect", returncode=None):
        super().__init__(category)
        self.category = category
        self.fixture = fixture
        self.operation = operation
        self.returncode = returncode


class QuietParser(argparse.ArgumentParser):
    """Do not echo arbitrary argv values in usage or diagnostics."""

    def error(self, message):  # pragma: no cover - argparse dispatch tested via main
        raise InputError("invalid arguments")


def _parser():
    parser = QuietParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--duration", required=True, type=float)
    parser.add_argument("--interval", required=True, type=float)
    parser.add_argument("--timeout", required=True, type=float)
    parser.add_argument("--id", action="append", required=True)
    return parser


def parse_args(argv=None):
    try:
        args = _parser().parse_args(argv)
    except (InputError, TypeError, ValueError, OverflowError) as error:
        raise InputError("invalid arguments") from error
    if any(not math.isfinite(value) for value in
           (args.duration, args.interval, args.timeout)):
        raise InputError("invalid arguments")
    if (args.duration != PROFILE["duration_seconds"] or
            args.interval != PROFILE["interval_seconds"] or
            args.timeout != PROFILE["timeout_seconds"]):
        raise InputError("invalid arguments")
    if len(args.id) != len(FIXTURES):
        raise InputError("invalid arguments")
    identifiers = {}
    for item in args.id:
        if not isinstance(item, str):
            raise InputError("invalid arguments")
        route, separator, identifier = item.partition("=")
        if (separator != "=" or route not in FIXTURE_SET or route in identifiers or
                CONTAINER_ID.fullmatch(identifier) is None):
            raise InputError("invalid arguments")
        identifiers[route] = identifier
    if set(identifiers) != FIXTURE_SET:
        raise InputError("invalid arguments")
    return args, identifiers


def _safe_report():
    return {
        "scope": SCOPE,
        "phase0_complete": PHASE0_COMPLETE,
        "capacity_evidence": CAPACITY_EVIDENCE,
        "profile": {key: value for key, value in PROFILE.items()},
        "fixtures": {},
        "startup_identity_complete": False,
        "startup_fixture_count": 0,
        "samples": [],
        "sample_count": 0,
        "diagnostic_completed": False,
        "aborted": False,
        "error": None,
        "observation_error": None,
    }


def _elapsed(started):
    return round(max(0.0, time.monotonic() - started), 6)


def _category_error(category, fixture, operation, started, *, returncode=None):
    row = {"operation": operation, "category": category, "fixture": fixture,
           "elapsed_seconds": _elapsed(started)}
    if isinstance(returncode, int) and not isinstance(returncode, bool):
        row["returncode"] = returncode
    return row


def _bytes_length(value):
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="replace"))
    return 0


def _decode_json(stdout):
    if _bytes_length(stdout) > MAX_DOCKER_STDOUT_BYTES:
        raise TraceStop("response_too_large")
    if isinstance(stdout, bytes):
        try:
            stdout = stdout.decode("utf-8")
        except UnicodeDecodeError as error:
            raise TraceStop("invalid_response") from error
    if not isinstance(stdout, str):
        raise TraceStop("invalid_response")
    try:
        return json.loads(stdout, object_pairs_hook=_unique_object)
    except (ValueError, TypeError, RecursionError):
        raise TraceStop("invalid_response")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def _pid_identity(pid, identifier):
    """Read only bounded identity fields for the exact inspected PID."""
    if type(pid) is not int or pid <= 0:
        raise TraceStop("pid_identity")
    try:
        stat_data = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        # The command name may contain spaces and parentheses.  The final
        # right parenthesis separates it from the stable numeric stat fields.
        fields = stat_data.rsplit(")", 1)[1].split()
        if len(fields) <= 19:
            raise TraceStop("pid_identity")
        start_time = int(fields[19])
        namespace = os.readlink(f"/proc/{pid}/ns/pid")
        if not re.fullmatch(r"pid:\[[0-9]+\]", namespace):
            raise TraceStop("pid_identity")
        rows = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
        unified = [row.split(":", 2)[2] for row in rows
                   if len(row.split(":", 2)) == 3 and row.split(":", 2)[:2] == ["0", ""]]
        if len(unified) != 1 or not unified[0].startswith("/"):
            raise TraceStop("pid_identity")
        cgroup_leaf = Path(unified[0]).name
        if cgroup_leaf not in (identifier, f"docker-{identifier}.scope"):
            raise TraceStop("pid_identity")
    except TraceStop:
        raise
    except (FileNotFoundError, PermissionError, OSError, ValueError, UnicodeError):
        raise TraceStop("pid_identity")
    return {"pid": pid, "pid_start_time": start_time,
            "pid_namespace": namespace, "cgroup_leaf": cgroup_leaf}


def _inspect(identifier, timeout):
    """Inspect exactly one caller-authorized complete container ID."""
    try:
        result = subprocess.run(
            [*DOCKER, identifier], check=True, capture_output=True, text=False,
            timeout=timeout, env=dict(SAFE_ENV))
    except subprocess.TimeoutExpired as error:
        # subprocess.run kills and reaps its exact Popen child on this path.
        raise TraceStop("timeout") from error
    except subprocess.CalledProcessError as error:
        returncode = error.returncode if type(error.returncode) is int else None
        raise TraceStop("docker_error", returncode=returncode)
    except (OSError, subprocess.SubprocessError) as error:
        raise TraceStop("docker_error") from error
    if _bytes_length(getattr(result, "stdout", b"")) > MAX_DOCKER_STDOUT_BYTES:
        raise TraceStop("response_too_large")
    if _bytes_length(getattr(result, "stderr", b"")) > MAX_DOCKER_STDERR_BYTES:
        raise TraceStop("docker_error")
    return _decode_json(getattr(result, "stdout", None))


def _validate_state(value, fixture, identifier, ownership):
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise TraceStop("invalid_response", fixture)
    state = value[0]
    if state.get("Id") != identifier:
        raise TraceStop("fixture_identity", fixture)
    config = state.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        raise TraceStop("fixture_identity", fixture)
    run_id = labels.get("halvo.native-lab-capacity")
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise TraceStop("fixture_identity", fixture)
    if ownership is not None and run_id != ownership:
        raise TraceStop("fixture_identity", fixture)
    expected_name = f"halvo-capacity-{run_id}-{fixture}"
    if state.get("Name") != "/" + expected_name:
        raise TraceStop("fixture_identity", fixture)
    status = state.get("State")
    if not isinstance(status, dict) or status.get("Running") is not True:
        raise TraceStop("fixture_identity", fixture)
    pid = status.get("Pid")
    return state, run_id, pid


def _record(report, row):
    samples = report["samples"]
    if len(samples) < MAX_SAMPLES:
        samples.append(row)
    report["sample_count"] = len(samples)


def _verify_fixture(report, fixture, identifier, ownership, started, timeout):
    try:
        state = _inspect(identifier, timeout)
        state, run_id, pid = _validate_state(state, fixture, identifier, ownership)
        identity = _pid_identity(pid, identifier)
        report["fixtures"][fixture] = {"purpose": fixture, "pid": identity["pid"],
                                       "pid_start_time": identity["pid_start_time"],
                                       "pid_namespace": identity["pid_namespace"],
                                       "container_id_sha256": hashlib.sha256(
                                            identifier.encode("ascii")).hexdigest()}
        report["startup_fixture_count"] = len(report["fixtures"])
        return run_id, identity
    except TraceStop as error:
        raise TraceStop(error.category, fixture, "startup_identity",
                        returncode=error.returncode) from error


def _verify_continuity(report, fixture, identifier, expected_run, expected_identity,
                       started, timeout):
    operation_started = time.monotonic()
    try:
        state = _inspect(identifier, timeout)
        state, run_id, pid = _validate_state(state, fixture, identifier, expected_run)
        identity = _pid_identity(pid, identifier)
        if identity != expected_identity:
            raise TraceStop("pid_identity", fixture)
        _record(report, {"operation": "container_inspect", "category": "ok",
                         "fixture": fixture, "elapsed_seconds": _elapsed(operation_started),
                         "pid": identity["pid"], "pid_start_time": identity["pid_start_time"],
                         "pid_namespace": identity["pid_namespace"]})
        return state
    except TraceStop as error:
        row = _category_error(error.category, fixture, "container_inspect", operation_started,
                               returncode=error.returncode)
        _record(report, row)
        raise TraceStop(error.category, fixture, "container_inspect",
                        returncode=error.returncode) from error


def _sleep_until(deadline, state):
    while True:
        if state["stop"]:
            raise TraceStop(state["category"], operation="schedule")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.1, remaining))


def _run_trace(report, identifiers, total_started, state):
    ownership = None
    identities = {}
    for fixture in FIXTURES:
        if state["stop"]:
            raise TraceStop(state["category"], operation="guard")
        run_id, identity = _verify_fixture(report, fixture, identifiers[fixture], ownership,
                                           total_started, PROFILE["timeout_seconds"])
        ownership = run_id if ownership is None else ownership
        identities[fixture] = identity

    # Startup coverage is evidence of authorization/identity, not a sample.
    # Only failures after this complete bounded pass can be observations.
    report["startup_identity_complete"] = True
    # This is a separate, fixed-schema line so the host can gate load start
    # without waiting for the eventual bounded report at profile completion.
    # It contains no container identifiers, Docker output, or exception text.
    _emit_readiness()
    trace_started = time.monotonic()
    trace_deadline = trace_started + PROFILE["duration_seconds"]
    next_cycle = trace_started
    while time.monotonic() < trace_deadline:
        if state["stop"]:
            raise TraceStop(state["category"], operation="schedule")
        _sleep_until(next_cycle, state)
        if time.monotonic() >= trace_deadline:
            break
        for fixture in FIXTURES:
            if state["stop"]:
                raise TraceStop(state["category"], fixture, "container_inspect")
            _verify_continuity(report, fixture, identifiers[fixture], ownership,
                               identities[fixture], total_started,
                               PROFILE["timeout_seconds"])
        next_cycle += PROFILE["interval_seconds"]
    report["diagnostic_completed"] = not state["stop"] and report["error"] is None


def _emit_readiness():
    encoded = json.dumps(READINESS_MARKER, separators=(",", ":"),
                         sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(encoded.decode("utf-8"))
        sys.stdout.flush()
    else:
        stream.write(encoded)
        stream.flush()


def _emit(report):
    report["sample_count"] = len(report["samples"])
    encoded = json.dumps(report, separators=(",", ":"), sort_keys=True,
                         allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > MAX_OUTPUT_BYTES:
        # This branch itself is bounded and contains no fixture/container data.
        report["fixtures"] = {}
        report["startup_identity_complete"] = False
        report["startup_fixture_count"] = 0
        report["samples"] = report["samples"][:8]
        report["sample_count"] = len(report["samples"])
        report["error"] = {"operation": "report", "category": "output_limit",
                            "fixture": None, "elapsed_seconds": 0.0}
        report["diagnostic_completed"] = False
        report["observation_error"] = None
        report["aborted"] = True
        encoded = json.dumps(report, separators=(",", ":"), sort_keys=True,
                             allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > MAX_OUTPUT_BYTES:
        # The fixed fallback is still a JSON report and cannot contain raw input.
        report = _safe_report()
        report["aborted"] = True
        report["error"] = {"operation": "report", "category": "output_limit",
                           "fixture": None, "elapsed_seconds": 0.0}
        encoded = json.dumps(report, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(encoded.decode("utf-8"))
        sys.stdout.flush()
    else:
        stream.write(encoded)
        stream.flush()


def main(argv=None):
    report = _safe_report()
    total_started = time.monotonic()
    try:
        _, identifiers = parse_args(argv)
    except InputError:
        report["aborted"] = True
        report["error"] = {"operation": "input", "category": "invalid_input",
                            "fixture": None, "elapsed_seconds": _elapsed(total_started)}
        _emit(report)
        return 2

    state = {"stop": False, "category": None}
    previous = {}

    def request_stop(signum, frame):
        state["stop"] = True
        state["category"] = "wall_timeout" if signum == signal.SIGALRM else "signal"

    try:
        for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, request_stop)
        signal.setitimer(signal.ITIMER_REAL, MAX_WALL_SECONDS)
        try:
            # This is deliberately the first lab/OS action after pure argv
            # validation: no output file, Docker CLI, or /proc read precedes it.
            if require_lab() != "qemu" or os.geteuid() != 0:
                raise TraceStop("guard", operation="guard")
            if state["stop"]:
                raise TraceStop(state["category"], operation="guard")
            _run_trace(report, identifiers, total_started, state)
        except SystemExit:
            # guard.require_lab uses SystemExit for its refusal paths.  Do not
            # expose that message: the report retains only the safe category.
            report["aborted"] = True
            report["error"] = _category_error("guard", None, "guard", total_started)
            report["diagnostic_completed"] = False
        except TraceStop as error:
            report["aborted"] = True
            safe_error = _category_error(error.category, error.fixture,
                                         error.operation, total_started,
                                         returncode=error.returncode)
            # A bounded Docker timeout/error is the diagnostic observation we
            # are measuring, not an instrument crash.  Guard, identity,
            # protocol and internal failures remain rejected.
            observation = (report["startup_identity_complete"] and
                           error.operation == "container_inspect" and
                           error.category in {"timeout", "docker_error"})
            report["observation_error" if observation else "error"] = safe_error
            report["diagnostic_completed"] = observation
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            report["aborted"] = True
            report["error"] = _category_error("internal_error", None, "trace", total_started)
            report["diagnostic_completed"] = False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in previous.items():
            signal.signal(number, handler)
    _emit(report)
    return 0 if report["diagnostic_completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
