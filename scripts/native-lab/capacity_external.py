#!/usr/bin/env python3
"""Fixed-profile host generator for an already-running disposable lab guest.

The CLI accepts only a marked local VM directory and pinned loopback SSH port.
Importable channel/manager/pool APIs permit local protocol stand-ins. No host
container engine, guest launcher, namespace entry, or production path is used.
"""
import argparse
import copy
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

import capacity
import capacity_preflight

HOST_CPUS = frozenset((2, 3))
GUEST_CPUS = frozenset((0, 1))
SETUP_TIMEOUT_SECONDS = 600
FINISH_TIMEOUT_SECONDS = 120
MAX_CONTROL_LINE_BYTES = 4 * 1024 * 1024
MAX_CONTROL_RECORDS = int(capacity.MAX_COLLECTION_SECONDS /
                          capacity.HEALTH_CHECK_INTERVAL_SECONDS) + 128
TRANSPORT = "guest-loopback-ssh-netns-relay-v1"
FORWARD_NOFILE_MIN = 16384
LAB_PATH = re.compile(r"/var/tmp/halvo-native-vm-[A-Za-z0-9_-]+\Z")
SOURCE_FILES = (*capacity.SOURCE_FILES, "capacity_async_client.py", "capacity_preflight.py",
                "capacity_external.py", "capacity_guest.py", "capacity_relay.py", "capacity_external_validate.py")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _finite_json(value):
    if type(value) in (int, float):
        if not math.isfinite(value):
            raise ValueError("nonfinite JSON number")
    elif isinstance(value, dict):
        for item in value.values():
            _finite_json(item)
    elif isinstance(value, list):
        for item in value:
            _finite_json(item)
    return value


def _ports(value):
    if not isinstance(value, dict) or set(value) != set(capacity.ROUTE_ORDER) \
            or any(type(port) is not int or not 1 <= port <= 65535
                   for port in value.values()) or len(set(value.values())) != 3:
        raise ValueError("endpoints must be distinct numeric ports for python/static/node")
    return dict(value)


def _affinity(pid=0):
    return sorted(os.sched_getaffinity(pid))


def _check_affinity(actual, expected):
    if actual != sorted(expected):
        raise capacity.GeneratorBottleneck("generator/child affinity changed")


def verify_qemu(pid, lab_dir, baseline=None):
    if type(pid) is not int or pid <= 0:
        raise ValueError("qemu-pid must identify the exact owned QEMU process")
    argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    argv = [arg.decode() for arg in argv if arg]
    expected = f"file={Path(lab_dir) / 'guest.qcow2'},format=qcow2,if=virtio,discard=unmap"
    accel_profiles = {"kvm": "kvm", "tcg,thread=multi,tb-size=128": "tcg"}
    accel_arg = argv[argv.index("-accel") + 1] if "-accel" in argv else ""
    if not argv or Path(argv[0]).name != "qemu-system-x86_64" or expected not in argv \
            or accel_arg not in accel_profiles or "2560" not in argv:
        raise capacity.CapacityError("QEMU identity/profile does not match this lab overlay")
    _check_affinity(_affinity(pid), GUEST_CPUS)
    evidence = {"pid": pid, "pid_start_time": capacity.process_start(pid),
                "cpu_affinity": _affinity(pid), "guest_vcpus": 2, "guest_memory_mib": 2560,
                "acceleration": accel_profiles[accel_arg], "overlay": str(Path(lab_dir) / "guest.qcow2"),
                "executable_sha256": capacity.file_digest(Path(argv[0]).resolve())}
    if baseline is not None and evidence != baseline:
        raise capacity.ResidentFailure("QEMU identity/affinity changed during collection")
    return evidence


def _regular(path):
    path = Path(path)
    if path.resolve(strict=True) != path or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("lab input must be a regular non-symlink file")
    return path


def validate_inputs(lab_dir, ssh_port, backend, image, payload_sha256, output, mode):
    """Validate all CLI paths and profile inputs before creating children/files."""
    capacity.validate_cli_values(backend, image, payload_sha256)
    if mode not in ("preflight", "capacity"):
        raise ValueError("mode must be preflight or capacity")
    if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
        raise ValueError("ssh-port must be a valid TCP port")
    lab = Path(lab_dir)
    if not LAB_PATH.fullmatch(str(lab)) or lab.resolve(strict=True) != lab \
            or not lab.is_dir() or lab.is_symlink():
        raise ValueError("lab-dir must be an existing /var/tmp/halvo-native-vm-NAME directory")
    marker = _regular(lab / ".halvo-native-vm")
    if marker.stat().st_size > 128 or marker.read_text().strip() != "qemu-phase0-v1":
        raise ValueError("lab marker identity is invalid")
    # These are the fixed filenames created by vm.sh; their contents are never
    # included in evidence or diagnostics.
    _regular(lab / "client-key")
    known = _regular(lab / "known-hosts")
    if known.stat().st_size > 65536:
        raise ValueError("known-hosts is oversized")
    rows = known.read_text().splitlines()
    if len(rows) != 1 or len(rows[0].split()) != 3 \
            or rows[0].split()[0] != f"[127.0.0.1]:{ssh_port}" \
            or rows[0].split()[1] != "ssh-ed25519":
        raise ValueError("known-hosts must pin exactly the requested loopback SSH port")
    vm_id_file = _regular(lab / "vm-id")
    if vm_id_file.stat().st_size > 128 or not re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
            vm_id_file.read_text().strip()):
        raise ValueError("lab vm-id is invalid")
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink() \
            or not destination.parent.is_dir() \
            or destination.parent.resolve(strict=True) != destination.parent:
        raise ValueError("output must be a new file in an existing non-symlink result directory")
    _check_affinity(_affinity(), HOST_CPUS)
    root = Path(__file__).resolve().parent
    for name in SOURCE_FILES:
        _regular(root / name)
    return lab, destination


def ssh_command(lab_dir, ssh_port, *, forwarding=False):
    """Fixed target; -F disables inherited forwards so explicit -L survives.

    ClearAllForwardings=yes is appropriate for the control connection. For the
    forward-only connection it must be no: OpenSSH otherwise erases even the
    explicit command-line -L entries. No user/system ssh_config is loaded.
    """
    return ["ssh", "-F", "/dev/null", "-i", str(Path(lab_dir) / "client-key"),
            "-p", str(ssh_port), "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
            "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-oForwardAgent=no",
            "-oClearAllForwardings=" + ("no" if forwarding else "yes"),
            "-oUserKnownHostsFile=" + str(Path(lab_dir) / "known-hosts"),
            "-oGlobalKnownHostsFile=/dev/null", "-oExitOnForwardFailure=yes",
            "-oServerAliveInterval=10", "-oServerAliveCountMax=3",
            "-oConnectTimeout=30", "-oConnectionAttempts=1", "-oControlMaster=no",
            "-oControlPath=none", "-oPermitLocalCommand=no", "-oRequestTTY=no"]


def _child_evidence(process):
    return {"pid": process.pid, "pid_start_time": capacity.process_start(process.pid),
            "cpu_affinity": _affinity(process.pid)}


def _stop_child(process):
    """Only signal the Popen child we own, never a discovered PID/group."""
    result = {"pid": process.pid, "terminated": False, "killed": False,
              "survived": False, "errors": []}
    try:
        if process.poll() is None:
            process.terminate()
            result["terminated"] = True
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            result["killed"] = True
            result["errors"].append("owned child required SIGKILL")
            process.wait(timeout=5)
    except Exception as error:
        result["errors"].append(capacity.describe_error(error))
    result.update(returncode=process.poll(), survived=process.poll() is None)
    result["passed"] = not result["survived"] and not result["errors"]
    return result


class ControlChannel:
    """One bounded JSONL child, serial RPC lock, and no uncertain retries.

    Pass a subprocess argv or an already-owned Popen stand-in for local tests.
    The CLI constructs argv itself and never accepts arbitrary commands.
    """
    def __init__(self, command=None, *, process=None, affinity=None):
        self.command, self.process = command, process
        self.affinity = _affinity() if affinity is None else sorted(affinity)
        self.lock = threading.Lock()
        self.selector = selectors.DefaultSelector()
        self.buffer = bytearray()
        self.records = []
        self.seq = 0
        self.broken = False
        self.ready = None
        self.startup_evidence = {}
        self.cleanup_evidence = None

    def _fail(self, message):
        self.broken = True
        raise capacity.CapacityError(message)

    def start(self, timeout=SETUP_TIMEOUT_SECONDS):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) \
                or not 0 < timeout <= SETUP_TIMEOUT_SECONDS:
            raise ValueError("invalid control startup timeout")
        if self.ready is not None or self.startup_evidence:
            raise capacity.CapacityError("control channel already started")
        if self.process is None:
            self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, bufsize=0)
        for stream in (self.process.stdin, self.process.stdout):
            if stream is None:
                self._fail("control child did not expose pipes")
            os.set_blocking(stream.fileno(), False)
        self.selector.register(self.process.stdout.fileno(), selectors.EVENT_READ)
        self.startup_evidence = _child_evidence(self.process)
        _check_affinity(self.startup_evidence["cpu_affinity"], self.affinity)
        record = self._read(time.monotonic() + timeout)
        if set(record) != {"type", "protocol", "report", "endpoints", "relay_evidence"} \
                or record["type"] != "ready" or type(record["protocol"]) is not int \
                or record["protocol"] != 1 or not isinstance(record["report"], dict) \
                or not isinstance(record["relay_evidence"], list):
            self._fail("invalid guest ready record")
        _ports(record["endpoints"])
        self.records[-1]["verified"] = True
        self.ready = copy.deepcopy(record)
        return record

    def _read(self, deadline):
        while True:
            if b"\n" in self.buffer:
                line, _, remainder = self.buffer.partition(b"\n")
                self.buffer = bytearray(remainder)
                if len(line) > MAX_CONTROL_LINE_BYTES or len(self.records) >= MAX_CONTROL_RECORDS:
                    self._fail("control protocol bounds exceeded")
                evidence = {"host_received_monotonic": time.monotonic(), "verified": False}
                self.records.append(evidence)
                try:
                    record = _finite_json(json.loads(line.decode("utf-8"),
                                                     object_pairs_hook=_unique_object))
                    if not isinstance(record, dict):
                        raise ValueError("record is not an object")
                    evidence["record"] = copy.deepcopy(record)
                except (ValueError, TypeError, RecursionError, OverflowError) as error:
                    # Do not retain SSH banners or credentials; bounded JSON
                    # records, once decoded, are the protocol evidence.
                    evidence["error"] = "invalid JSON record"
                    self._fail("guest control returned invalid JSON")
                return record
            if len(self.buffer) > MAX_CONTROL_LINE_BYTES:
                self._fail("guest control partial line exceeded its bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail("guest control deadline expired")
            for key, _ in self.selector.select(remaining):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    self.selector.unregister(key.fd)
                    self._fail("guest control EOF before reply")
                self.buffer.extend(chunk)

    def exchange(self, operation, timeout=None):
        if operation not in ("health", "finish"):
            raise ValueError("unknown control operation")
        bound = capacity.HEALTH_CHECK_TIMEOUT_SECONDS if operation == "health" else FINISH_TIMEOUT_SECONDS
        timeout = bound if timeout is None else timeout
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= bound:
            raise ValueError("invalid control timeout")
        if not self.lock.acquire(timeout=timeout):
            raise capacity.CapacityError("control exchange lock timed out")
        synchronized_failure = False
        try:
            if self.broken or self.ready is None or self.process.poll() is not None:
                raise capacity.CapacityError("control unavailable; uncertain action not repeated")
            self.verify_continuity()
            self.seq += 1
            command = json.dumps({"type": "command", "id": self.seq,
                                  "operation": operation}, separators=(",", ":")).encode() + b"\n"
            deadline = time.monotonic() + timeout
            # Tiny writes are atomic or rejected, with no replay after a short
            # write or timeout. Health runs only in PhaseMonitor's worker.
            if os.write(self.process.stdin.fileno(), command) != len(command):
                self._fail("partial guest command write")
            record = self._read(deadline)
            if record.get("type") != "reply" or type(record.get("id")) is not int \
                    or record["id"] != self.seq or type(record.get("ok")) is not bool:
                self._fail("guest reply identity mismatch")
            if operation == "health":
                expected = {"type", "id", "ok", "health"} if record["ok"] else {"type", "id", "ok", "error", "health"}
            else:
                expected = {"type", "id", "ok", "report", "cleanup"}
                if "error" in record:
                    expected.add("error")
            if set(record) != expected:
                self._fail("unexpected guest reply fields")
            self.records[-1]["verified"] = True
            if operation == "health" and not record["ok"]:
                if not isinstance(record["error"], str) or len(record["error"]) > 4096:
                    self._fail("invalid guest health error")
                synchronized_failure = True
                raise capacity.ResidentFailure("guest health failed: " + record["error"])
            return record
        except BaseException:
            # Explicit failed health replies are synchronized; other failures
            # poison the stream. Finish then uses EOF for guest finally cleanup.
            if not synchronized_failure:
                self.broken = True
            raise
        finally:
            self.lock.release()

    def verify_continuity(self):
        if self.process.poll() is not None \
                or capacity.process_start(self.process.pid) != self.startup_evidence["pid_start_time"]:
            raise capacity.ResidentFailure("control process exited/restarted")
        _check_affinity(_affinity(self.process.pid), self.affinity)

    def finish(self):
        """Try finish once; on broken streams EOF invokes guest cleanup."""
        if self.cleanup_evidence is not None:
            return copy.deepcopy(self.cleanup_evidence)
        result = {"attempted": self.process is not None, "passed": False,
                  "reply": None, "errors": []}
        self.cleanup_evidence = result
        if self.process is not None:
            try:
                result["reply"] = self.exchange("finish")
                if result["reply"]["ok"] is not True:
                    raise capacity.CapacityError("guest finish failed")
            except Exception as error:
                result["errors"].append(capacity.describe_error(error))
            finally:
                try:
                    self.process.stdin.close()
                except Exception as error:
                    result["errors"].append("control EOF cleanup: " + capacity.describe_error(error))
            # Drain rather than wait with a potentially full pipe. EOF is the
            # exit notification; no sleep/poll background loop is used.
            deadline = time.monotonic() + FINISH_TIMEOUT_SECONDS
            try:
                while self.selector.get_map():
                    events = self.selector.select(max(0, deadline - time.monotonic()))
                    if not events:
                        raise capacity.CapacityError("guest finish exit deadline expired")
                    for key, _ in events:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            self.selector.unregister(key.fd)
                        else:
                            result["errors"].append("unexpected guest output after finish")
                self.process.wait(timeout=max(0.001, deadline - time.monotonic()))
                if self.buffer:
                    result["errors"].append("unexpected buffered guest output after finish")
                if self.process.returncode != 0:
                    result["errors"].append("control child exited nonzero")
            except Exception as error:
                result["errors"].append(capacity.describe_error(error))
            result["child"] = _stop_child(self.process)
            result["errors"].extend(result["child"]["errors"])
            for stream in (self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
        self.selector.close()
        result["passed"] = result["reply"] is not None and not result["errors"]
        return copy.deepcopy(result)


def validate_guest_report(report, backend, image, payload_sha256, *, initial=None, vm_id=None):
    if not isinstance(report, dict) or report.get("report_type") != "halvo-native-lab-guest-control" \
            or type(report.get("schema_version")) is not int or report["schema_version"] != 1 \
            or report.get("production") is not False or report.get("scope") != "guest-control-evidence" \
            or report.get("phase0_complete") is not False or report.get("capacity_evidence") is not False \
            or report.get("backend") != backend or report.get("image") != image \
            or report.get("payload_sha256") != payload_sha256 \
            or not isinstance(report.get("run_id"), str) \
            or not capacity.RUN_IDENTIFIER.fullmatch(report["run_id"]):
        raise capacity.CapacityError("guest report identity differs")
    expected_sources = capacity.source_identities()
    root = Path(__file__).resolve().parent
    if report.get("relay_source_sha256") != capacity.file_digest(root / "capacity_relay.py") \
            or report.get("guest_control_source_sha256") != capacity.file_digest(root / "capacity_guest.py"):
        raise capacity.CapacityError("guest controller/relay source differs")
    for section in ("collector", "payload"):
        actual = report.get(section, {}).get("source_files_sha256")
        if not isinstance(actual, dict) or any(actual.get(key) != digest
                for key, digest in expected_sources.items()):
            raise capacity.CapacityError("guest sources differ from frozen host sources")
    # Additional guest-agent/relay identities, when supplied alongside the
    # original collector map, must agree with the same local frozen sources.
    root = Path(__file__).resolve().parent
    for section in ("collector", "payload"):
        for key in ("source_files_sha256", "new_source_files_sha256"):
            actual = report.get(section, {}).get(key, {})
            if not isinstance(actual, dict):
                raise capacity.CapacityError("guest source digest map is invalid")
            for name in SOURCE_FILES:
                if name in actual and actual[name] != capacity.file_digest(root / name):
                    raise capacity.CapacityError("guest additional source digest differs: " + name)
    if report.get("expected_limits") != capacity.LIMITS or report.get("fixtures") != {
            name: capacity._fixture_identity(name) for name in capacity.ALL_FIXTURES}:
        raise capacity.CapacityError("guest limits/fixtures differ from fixed profile")
    config = report.get("configuration", {})
    for key, expected in (("route_order", list(capacity.ROUTE_ORDER)),
                          ("route_weights_percent", capacity.ROUTE_WEIGHTS),
                          ("rates_per_second", list(capacity.RATES_PER_SECOND)),
                          ("warmup_seconds", capacity.WARMUP_SECONDS),
                          ("measurement_seconds", capacity.MEASUREMENT_SECONDS),
                          ("request_timeout_seconds", capacity.REQUEST_TIMEOUT_SECONDS)):
        if config.get(key) != expected:
            raise capacity.CapacityError("guest fixed schedule differs")
    environment = report.get("environment", {})
    if environment.get("lab_marker") != "qemu-phase0-v1" \
            or not environment.get("boot_id") or not environment.get("vm_id") \
            or (vm_id is not None and environment["vm_id"] != vm_id):
        raise capacity.CapacityError("guest VM identity differs")
    if initial is not None:
        for key in ("run_id", "backend", "image", "payload_sha256", "fixtures",
                    "expected_limits", "payload", "collector", "environment", "configuration"):
            if report.get(key) != initial.get(key):
                raise capacity.CapacityError("guest final report identity changed: " + key)
    return report


def _residents(evidence, baseline=None):
    if not isinstance(evidence, dict) or set(evidence) != set(capacity.ALL_FIXTURES):
        raise capacity.ResidentFailure("guest resident evidence is incomplete")
    for name, entry in evidence.items():
        if not isinstance(entry, dict) or entry.get("enforced_limits") != capacity.LIMITS \
                or entry.get("readiness", {}).get("ready") is not True \
                or type(entry.get("pid")) is not int or entry["pid"] <= 0 \
                or not entry.get("pid_start_time") or not isinstance(entry.get("cgroup"), str) \
                or not entry["cgroup"].startswith("/") or ".." in Path(entry["cgroup"]).parts \
                or type(entry.get("restarts")) is not int or entry["restarts"] != 0 \
                or type(entry.get("ooms")) is not int or entry["ooms"] != 0:
            raise capacity.ResidentFailure("guest resident identity/limits/health differ: " + name)
        fixture = capacity._fixture_identity(name)
        if any(entry.get(key) != fixture[key] for key in ("fixture_sha256", "runtime", "argv", "workers")):
            raise capacity.ResidentFailure("guest resident fixture differs: " + name)
        events = entry.get("memory_events")
        if not isinstance(events, dict) or not {"oom", "oom_kill"}.issubset(events) \
                or any(type(number) is not int or number < 0 for number in events.values()):
            raise capacity.ResidentFailure("guest OOM evidence invalid: " + name)
        if baseline is not None:
            if any(entry.get(key) != baseline[name].get(key) for key in (
                    "pid", "pid_start_time", "cgroup", "unit", "container_id")) \
                    or any(events[key] != baseline[name]["memory_events"][key]
                           for key in ("oom", "oom_kill")):
                raise capacity.ResidentFailure("guest resident restarted/OOM: " + name)
    return evidence


def _validate_relays(rows, endpoints, baseline=None):
    if not isinstance(rows, list) or len(rows) != 3 \
            or any(not isinstance(row, dict) for row in rows) \
            or {row.get("route") for row in rows} != set(capacity.ROUTE_ORDER):
        raise capacity.ResidentFailure("guest relay identity set is invalid")
    by_route = {row["route"]: row for row in (baseline or [])}
    for row in rows:
        route = row["route"]
        if type(row.get("pid")) is not int or row["pid"] <= 0 \
                or not row.get("pid_start_time") or row.get("listen_host") != "127.0.0.1" \
                or row.get("listen_port") != endpoints[route] or row.get("target_port") != 3000 \
                or row.get("verified") is not True or row.get("outside_fixture_cgroups") is not True \
                or not row.get("listener_inode") or not row.get("network_namespace") \
                or row.get("network_namespace") == row.get("root_network_namespace"):
            raise capacity.ResidentFailure("guest relay identity/namespace verification failed: " + route)
        if baseline is not None and any(row.get(key) != by_route[route].get(key) for key in (
                "pid", "pid_start_time", "fixture_pid", "fixture_pid_start_time", "listen_port",
                "listener_inode", "network_namespace", "root_network_namespace", "cgroup")):
            raise capacity.ResidentFailure("guest relay identity changed: " + route)


class ExternalManager:
    """PhaseMonitor adapter: exactly one health exchange per check_all call."""
    def __init__(self, channel, report=None, *, forward=None):
        self.channel = channel
        report = channel.ready["report"] if report is None else report
        self.baseline = copy.deepcopy(_residents(report.get("residents")))
        self.cache = copy.deepcopy(self.baseline)
        self.checkpoint = self.guest_monotonic = None
        self.forward = forward
        self.pool = None

    def check_all(self):
        if self.forward is not None:
            self.forward.verify_continuity()
        if self.pool is not None:
            self.pool.verify_placement()
        reply = self.channel.exchange("health")
        health = reply.get("health")
        if not isinstance(health, dict) or set(health) != {
                "residents", "resident_evidence", "worker_checkpoint", "guest_monotonic",
                "verified", "relay_evidence"} or health["verified"] is not True:
            raise capacity.ResidentFailure("guest health fields are incomplete")
        evidence = _residents(health["resident_evidence"], self.baseline)
        _validate_relays(health["relay_evidence"], self.channel.ready["endpoints"],
                         self.channel.ready["relay_evidence"])
        states = health["residents"]
        if not isinstance(states, dict) or set(states) != set(capacity.ALL_FIXTURES):
            raise capacity.ResidentFailure("guest health states are incomplete")
        for name, state in states.items():
            if not isinstance(state, dict) or state.get("active") is not True \
                    or state.get("pid") != evidence[name]["pid"] \
                    or type(state.get("restart_count")) is not int or state["restart_count"] != 0 \
                    or state.get("oom_killed") is not False:
                raise capacity.ResidentFailure("guest resident inactive/restarted: " + name)
        checkpoint, clock = health["worker_checkpoint"], health["guest_monotonic"]
        if type(checkpoint) is not int or checkpoint < 0 \
                or (self.checkpoint is not None and checkpoint < self.checkpoint):
            raise capacity.ResidentFailure("guest worker checkpoint invalid/regressed")
        capacity._finite_number(clock, "guest monotonic")
        if clock < 0 or (self.guest_monotonic is not None and clock < self.guest_monotonic):
            raise capacity.ResidentFailure("guest clock regressed")
        self.cache = copy.deepcopy(evidence)
        self.checkpoint, self.guest_monotonic = checkpoint, clock
        return copy.deepcopy(states)

    def worker_progress(self):
        if self.checkpoint is None:
            raise capacity.ResidentFailure("worker health has not been sampled")
        return self.checkpoint

    def resident_report(self):
        return copy.deepcopy(self.cache)


class ExternalPool(capacity.ClientPool):
    """Real bounded client protocol, with direct host-local loopback children."""
    def __init__(self, manager, ports, *, affinity=None):
        super().__init__(manager)
        self.ports = _ports(ports)
        self.affinity = _affinity() if affinity is None else sorted(affinity)
        self.startup_evidence = {}

    def start(self):
        _check_affinity(_affinity(), self.affinity)
        for route in capacity.ROUTE_ORDER:
            process = subprocess.Popen(
                capacity_preflight.client_command(self.ports[route], capacity.FIXTURES[route]["response"]),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0)
            self.processes[route] = process
            if process.stdin is None or process.stdout is None:
                raise capacity.GeneratorBottleneck("external client did not expose pipes")
            self.startup_evidence[route] = _child_evidence(process)
            _check_affinity(self.startup_evidence[route]["cpu_affinity"], self.affinity)
            for stream in (process.stdin, process.stdout):
                os.set_blocking(stream.fileno(), False)
            self.buffers[route] = bytearray()
            self.selector.register(process.stdout.fileno(), selectors.EVENT_READ, route)
        deadline = time.monotonic() + capacity.CLIENT_START_TIMEOUT_SECONDS
        ready = set()
        while ready != set(capacity.ROUTE_ORDER):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise capacity.GeneratorBottleneck("external clients readiness timed out")
            self._read_available(remaining)
            records, self.received = self.received, []
            for route, record in records:
                if record != {"type": "ready", "protocol": 1} \
                        or type(record.get("protocol")) is not int or route in ready:
                    raise capacity.GeneratorBottleneck("invalid external client readiness")
                ready.add(route)
        self.verify_placement()

    def verify_placement(self):
        _check_affinity(_affinity(), self.affinity)
        for route, process in self.processes.items():
            if process.poll() is not None or capacity.process_start(process.pid) != \
                    self.startup_evidence[route]["pid_start_time"]:
                raise capacity.GeneratorBottleneck("external client exited/restarted")
            _check_affinity(_affinity(process.pid), self.affinity)
            self.startup_evidence[route]["nofile_soft_limit"] = capacity_preflight.verify_client_descriptor_limit(process)


class ForwardProcess:
    """One exact-owned -N SSH child with three explicit loopback forwards."""
    def __init__(self, lab_dir, ssh_port, endpoints, *, affinity=None):
        self.lab_dir, self.ssh_port = lab_dir, ssh_port
        self.endpoints = _ports(endpoints)
        self.affinity = _affinity() if affinity is None else sorted(affinity)
        self.ports, self.process = {}, None
        self.evidence = {}
        self.cleanup_evidence = None
        self.drain_thread = None

    def start(self):
        if self.process is not None:
            raise capacity.CapacityError("SSH forwarding already started")
        reservations = []
        try:
            for route in capacity.ROUTE_ORDER:
                sock = socket.socket()
                reservations.append(sock)
                sock.bind(("127.0.0.1", 0))
                self.ports[route] = sock.getsockname()[1]
            command = ssh_command(self.lab_dir, self.ssh_port, forwarding=True) + ["-N"]
            for route in capacity.ROUTE_ORDER:
                command += ["-L", f"127.0.0.1:{self.ports[route]}:127.0.0.1:{self.endpoints[route]}"]
            command += ["lab@127.0.0.1"]
        finally:
            for sock in reservations:
                sock.close()
        # A bind race is a failed run, never a reason to retry SSH automatically.
        self.process = subprocess.Popen([*command[:1], "-v", *command[1:]],
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                        env={**os.environ, "LC_ALL": "C"})
        self.evidence = {**_child_evidence(self.process), "local_ports": dict(self.ports),
                         "guest_loopback_ports": dict(self.endpoints),
                         "continuity_checks": 0, "clear_all_forwardings": False,
                         "configuration": "/dev/null", "target": "lab@127.0.0.1"}
        self.verify_continuity()
        # OpenSSH emits these local listener confirmations after successful
        # authentication. Read them under a deadline, then continuously discard
        # diagnostics so debug traffic cannot block the forwarder. Never retain
        # authentication banners/key material in reports.
        fd = self.process.stderr.fileno()
        os.set_blocking(fd, False)
        pending, buffer = set(self.ports.values()), bytearray()
        deadline = time.monotonic() + 30
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise capacity.CapacityError("SSH forward listener readiness timed out")
                chunk = os.read(fd, 65536)
                if not chunk:
                    raise capacity.CapacityError("SSH forward exited before listener readiness")
                buffer.extend(chunk)
                while b"\n" in buffer:
                    line, _, rest = buffer.partition(b"\n")
                    buffer = bytearray(rest)
                    for port in tuple(pending):
                        if f"Local forwarding listening on 127.0.0.1 port {port}.".encode() in line:
                            pending.remove(port)
                if len(buffer) > 65536:
                    raise capacity.CapacityError("SSH forwarding diagnostic line oversized")
        self.verify_continuity()
        # Two descriptors per forwarded channel plus listeners/control overhead.
        # Change only the exact owned child; never host globals or guest quotas.
        soft, hard = resource.prlimit(self.process.pid, resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY and hard < FORWARD_NOFILE_MIN:
            raise capacity.GeneratorBottleneck("SSH forward descriptor hard limit is too low")
        if soft != resource.RLIM_INFINITY and soft < FORWARD_NOFILE_MIN:
            resource.prlimit(self.process.pid, resource.RLIMIT_NOFILE, (FORWARD_NOFILE_MIN, hard))
        self.evidence["nofile_soft_limit"] = resource.prlimit(self.process.pid, resource.RLIMIT_NOFILE)[0]
        self.evidence["listeners_ready"] = True
        self.drain_thread = threading.Thread(target=self._drain, name="capacity-forward-drain", daemon=True)
        self.drain_thread.start()
        return dict(self.ports)

    def _drain(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stderr.fileno(), selectors.EVENT_READ)
            while selector.select():
                try:
                    if not os.read(self.process.stderr.fileno(), 65536):
                        return
                except (OSError, ValueError):
                    return

    def verify_continuity(self):
        if self.process.poll() is not None or capacity.process_start(self.process.pid) != \
                self.evidence["pid_start_time"]:
            raise capacity.ResidentFailure("SSH forwarding exited/restarted")
        _check_affinity(_affinity(self.process.pid), self.affinity)
        if "nofile_soft_limit" in self.evidence:
            soft, _ = resource.prlimit(self.process.pid, resource.RLIMIT_NOFILE)
            if soft != resource.RLIM_INFINITY and soft < FORWARD_NOFILE_MIN:
                raise capacity.GeneratorBottleneck("SSH forward descriptor limit regressed")
        self.evidence["continuity_checks"] += 1
        self.evidence["last_checked_monotonic"] = time.monotonic()

    def close(self):
        if self.cleanup_evidence is None:
            self.cleanup_evidence = (_stop_child(self.process) if self.process is not None
                                     else {"passed": True, "errors": [], "attempted": False})
            if self.drain_thread is not None:
                self.drain_thread.join(5)
                if self.drain_thread.is_alive():
                    self.cleanup_evidence["passed"] = False
                    self.cleanup_evidence["errors"].append("forward drain did not stop")
            if self.process is not None and self.process.stderr is not None:
                self.process.stderr.close()
        return copy.deepcopy(self.cleanup_evidence)


def _validate_cleanup(reply):
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        raise capacity.CapacityError("guest finish did not succeed")
    cleanup = reply.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("passed") is not True \
            or cleanup.get("errors") != []:
        raise capacity.CapacityError("guest cleanup failed or lacks evidence")
    residents = cleanup.get("residents", cleanup)
    if not isinstance(residents, dict) or residents.get("passed") is not True \
            or residents.get("errors") != []:
        raise capacity.CapacityError("guest resident cleanup failed")
    rows = residents.get("evidence")
    if not isinstance(rows, list):
        raise capacity.CapacityError("guest resident cleanup evidence missing")
    for name in capacity.ALL_FIXTURES:
        matches = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
        if len(matches) != 1 or any(matches[0].get(key) is not True
                                  for key in ("owned", "stopped", "empty")):
            raise capacity.CapacityError("guest resident cleanup incomplete: " + name)
    relays = cleanup.get("relays", cleanup.get("relay_processes"))
    if not isinstance(relays, dict) or relays.get("passed") is not True or relays.get("errors") != []:
        raise capacity.CapacityError("guest relay cleanup evidence missing/failed")
    rows = relays.get("evidence")
    if not isinstance(rows, list) or len(rows) != 3 or any(not isinstance(row, dict) for row in rows) \
            or {row.get("route", row.get("name")) for row in rows} != set(capacity.ROUTE_ORDER) \
            or any(row.get("owned") is not True or row.get("stopped") is not True
                   or row.get("listener_closed") is not True or row.get("killed", False) is not False
                   or row.get("survived", False) is not False for row in rows):
        raise capacity.CapacityError("guest relay cleanup incomplete")


def collect(lab_dir, ssh_port, backend, payload_sha256, output, image=None,
            mode="preflight", *, selfcheck=None, channel_factory=ControlChannel,
            forward_factory=ForwardProcess, pool_factory=ExternalPool,
            rate_runner=None, validate=True, qemu_pid=None):
    """Collect and persist complete/partial evidence, with dependency injection.

    validate=False is for local stand-ins only; the CLI always validates paths
    and exact affinity. Injected factories receive the same fixed-profile args.
    """
    if validate:
        lab_dir, output = validate_inputs(lab_dir, ssh_port, backend, image,
                                          payload_sha256, output, mode)
        qemu = verify_qemu(qemu_pid, lab_dir)
    else:
        capacity.validate_cli_values(backend, image, payload_sha256)
        if mode not in ("preflight", "capacity"):
            raise ValueError("invalid mode")
        lab_dir, output = Path(lab_dir), Path(output)
        qemu = None
        if output.exists() or output.is_symlink() or not output.parent.is_dir():
            raise ValueError("output must be new")
    root = Path(__file__).resolve().parent
    sources = {name: capacity.file_digest(root / name) for name in SOURCE_FILES}
    affinity = _affinity()
    rates = (1,) if mode == "preflight" else capacity.RATES_PER_SECOND
    report = {"schema_version": 1, "report_type": capacity.REPORT_TYPE,
              "scope": "external-generator-path-preflight" if mode == "preflight" else "request-capacity",
              "production": False, "backend": backend, "image": image,
              "payload_sha256": payload_sha256, "passed": False,
              "collection_valid": False, "capacity_evidence": False, "phase0_complete": False,
              "started_at": capacity._utc_now(), "rates": [], "errors": [],
              "guest_initial_report": None, "guest_final_report": None,
                   "generator": {"placement": "external-host", "cpu_affinity": affinity,
                   "generator_cpus": sorted(HOST_CPUS), "guest_cpus": sorted(GUEST_CPUS),
                    **capacity_preflight.CLIENT_PROFILE,
                  "transport": TRANSPORT, "clock_domain": "host-monotonic",
                  "kernel": platform.uname()._asdict(), "python": {
                      "version": platform.python_version(), "executable": sys.executable,
                      "executable_sha256": capacity.file_digest(Path(sys.executable).resolve())},
                   "source_files_sha256": sources},
              "cleanup": {"passed": False, "errors": []}}
    channel = forward = pool = manager = None
    report["generator"]["kernel_version_sha256"] = capacity.file_digest("/proc/version")
    report["generator"]["qemu"] = qemu
    # Exclusive creation claims the output before any local/remote children.
    with output.open("x", encoding="utf-8") as stream:
        try:
            report["generator_selfcheck"] = (capacity_preflight.collect if selfcheck is None else selfcheck)()
            check = report["generator_selfcheck"]
            capacity_preflight.validate_identity(check)
            if check.get("passed") is not True or check.get("capacity_evidence") is not False \
                    or check.get("scope") != "load-generator-selfcheck" \
                    or check.get("rate_per_second") != 256 or check.get("duration_seconds") != 60 \
                    or check.get("cleanup", {}).get("passed") is not True:
                raise capacity.GeneratorBottleneck("host loopback generator selfcheck failed")
            command = ssh_command(lab_dir, ssh_port) + ["lab@127.0.0.1"]
            remote = ["sudo", "-n", "/usr/bin/python3", "-B", "/opt/halvo-lab/capacity_guest.py",
                       "--backend", backend, "--payload-sha256", payload_sha256,
                       "--results-dir", "/results/external-" + (lab_dir / "vm-id").read_text().strip()]
            if image is not None:
                remote += ["--image", image]
            command.append(shlex.join(remote))
            channel = channel_factory(command, affinity=affinity)
            ready = channel.start()
            report["guest_initial_report"] = copy.deepcopy(ready["report"])
            initial = ready["report"]
            validate_guest_report(initial, backend, image, payload_sha256,
                                  vm_id=(lab_dir / "vm-id").read_text().strip() if validate else None)
            if initial.get("errors"):
                raise capacity.CapacityError("guest initial report records errors")
            relays = ready["relay_evidence"]
            _validate_relays(relays, ready["endpoints"])
            report["guest_relay_evidence"] = copy.deepcopy(relays)
            forward = forward_factory(lab_dir, ssh_port, ready["endpoints"], affinity=affinity)
            ports = forward.start()
            manager = ExternalManager(channel, initial, forward=forward)
            pool = pool_factory(manager, ports, affinity=affinity)
            manager.pool = pool
            pool.start()
            request_id = 0
            for rate in rates:
                try:
                    result = (capacity.run_rate if rate_runner is None else rate_runner)(
                        manager, pool, rate, request_id)
                    report["rates"].append(result)
                    request_id += rate * (capacity.WARMUP_SECONDS + capacity.MEASUREMENT_SECONDS)
                except Exception as error:
                    report["rates"].append({"rate_per_second": rate, "passed": False,
                        "aborted": True, "errors": [capacity.describe_error(error)],
                        "phase_evidence": getattr(error, "phase_evidence", None),
                        "completed_warmup": getattr(error, "completed_warmup", None)})
                    raise
                if mode == "capacity" and result.get("accepted") is not True:
                    # A gate-rejected window is the measured saturation wall of this
                    # guest. The remaining frozen rates are never started: stacking a
                    # higher open-loop rate onto an already saturated guest produces
                    # a health-timeout invalidation instead of a capacity reading.
                    # Every correctness guard inside a window is unchanged; only the
                    # climb above the wall stops. Health timeouts stay invalidating.
                    report["schedule"] = {"stopped_at_rejection": rate, "phase0_complete": False}
                    break
            forward.verify_continuity()
            pool.verify_placement()
            if validate:
                verify_qemu(qemu_pid, lab_dir, qemu)
        except Exception as error:
            report["errors"].append(capacity.describe_error(error))
        finally:
            # Finish/EOF guest first, even after health/protocol/setup failures.
            if channel is not None:
                try:
                    control_cleanup = channel.finish()
                    report["cleanup"]["control"] = control_cleanup
                    report["generator"]["control_child"] = channel.startup_evidence
                    report["control_records"] = copy.deepcopy(channel.records)
                    reply = control_cleanup.get("reply")
                    if isinstance(reply, dict):
                        report["guest_final_report"] = copy.deepcopy(reply.get("report"))
                    if not control_cleanup.get("passed"):
                        raise capacity.CapacityError("guest control cleanup failed")
                    _validate_cleanup(reply)
                    final = reply["report"]
                    validate_guest_report(final, backend, image, payload_sha256,
                                          initial=report["guest_initial_report"])
                    if final.get("errors") or final.get("cleanup", {}).get("passed") is not True:
                        raise capacity.CapacityError("guest final report records errors/failed cleanup")
                except Exception as error:
                    report["errors"].append(capacity.describe_error(error))
            for name, child in (("clients", pool), ("forward", forward)):
                if child is not None:
                    try:
                        cleanup = child.close()
                        report["cleanup"][name] = cleanup
                        report["generator"][name] = (child.startup_evidence if name == "clients" else child.evidence)
                        if cleanup.get("passed") is not True:
                            report["errors"].append(name + " cleanup failed")
                    except Exception as error:
                        report["errors"].append(name + " cleanup: " + capacity.describe_error(error))
            if manager is not None:
                report["residents"] = manager.resident_report()
            initial = report.get("guest_initial_report")
            if initial is not None:
                for key in ("run_id", "collector", "payload", "environment", "fixtures",
                            "expected_limits", "configuration", "experiment_scope"):
                    report[key] = copy.deepcopy(initial[key])
                report["configuration"]["generator_placement"] = "external-host"
                report["configuration"]["transport"] = TRANSPORT
            report["cleanup"]["errors"] = list(report["errors"])
            report["cleanup"]["passed"] = channel is not None and not report["errors"]
            complete = len(report["rates"]) == len(rates) and not report["errors"] \
                and not any(row.get("aborted") for row in report["rates"])
            report["preflight_passed"] = complete and all(row.get("accepted") for row in report["rates"])
            if mode == "preflight":
                report["passed"] = report["preflight_passed"]
            if mode == "capacity":
                accepted = [row["rate_per_second"] for row in report["rates"] if row.get("accepted")]
                schedule = report.get("schedule", {})
                saturated = isinstance(schedule, dict) \
                    and schedule.get("stopped_at_rejection") is not None \
                    and not report["errors"] \
                    and not any(row.get("aborted") for row in report["rates"])
                report["capacity_rps"] = max(accepted) \
                    if (complete or saturated) and accepted else None
                report["collection_valid"] = bool(accepted) and (complete or saturated)
                report["capacity_evidence"] = report["collection_valid"]
                report["passed"] = report["collection_valid"]
            report["rate_summaries"] = [{key: row.get(key) for key in (
                "rate_per_second", "accepted", "passed", "error_rate", "goodput_rps",
                "latency_ms", "generator", "aborted")} for row in report["rates"]]
            report["ended_at"] = capacity._utc_now()
            stream.write(capacity._report_json(capacity._diagnostic_json(report)))
            stream.flush()
            os.fsync(stream.fileno())
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-dir", required=True)
    parser.add_argument("--ssh-port", required=True, type=int)
    parser.add_argument("--qemu-pid", required=True, type=int)
    parser.add_argument("--backend", required=True, choices=("native", "docker"))
    parser.add_argument("--image")
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=("preflight", "capacity"), default="preflight")
    args = parser.parse_args(argv)
    try:
        validate_inputs(args.lab_dir, args.ssh_port, args.backend, args.image,
                         args.payload_sha256, args.output, args.mode)
        verify_qemu(args.qemu_pid, Path(args.lab_dir))
    except (ValueError, OSError, capacity.CapacityError) as error:
        parser.error(capacity.describe_error(error))

    def interrupted(signum, frame):
        raise capacity.CapacityError("external collection interrupted or exceeded its fixed bound")

    previous = {kind: signal.signal(kind, interrupted)
                for kind in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
    signal.alarm(capacity.MAX_COLLECTION_SECONDS + SETUP_TIMEOUT_SECONDS + FINISH_TIMEOUT_SECONDS)
    try:
        report = collect(args.lab_dir, args.ssh_port, args.backend, args.payload_sha256,
                         args.output, args.image, args.mode, qemu_pid=args.qemu_pid)
    finally:
        signal.alarm(0)
        for kind, handler in previous.items():
            signal.signal(kind, handler)
    print(json.dumps({"output": args.output, "scope": report["scope"], "passed": report["passed"],
                      "preflight_passed": report["preflight_passed"],
                      "collection_valid": report["collection_valid"]}), flush=True)
    return 0 if (report["preflight_passed"] if args.mode == "preflight" else report["passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
