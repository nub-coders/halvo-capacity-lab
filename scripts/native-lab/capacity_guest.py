#!/usr/bin/env python3
"""Guarded protocol-v1 guest controller for an external capacity generator.

This records guest control evidence only; it never computes a capacity verdict.
"""

import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
import capacity
from guard import require_lab

PROTOCOL = 1
MAX_COMMAND_BYTES = 4096
MAX_COMMANDS = 4096
RELAY_PATH = Path("/opt/halvo-lab/capacity_relay.py")
CLEANUP_RESERVE_SECONDS = 300
FINAL_REPORT_RESERVE_SECONDS = 10


def bounded_error(error):
    # Protocol input and arbitrary exception messages are never report content.
    if isinstance(error, capacity.CapacityError):
        return capacity.describe_error(error)[:512]
    if isinstance(error, subprocess.SubprocessError):
        return "guest subprocess failed: " + type(error).__name__
    return "guest control failed: " + type(error).__name__


def emit(record):
    data = (json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n").encode()
    # Bound a stalled external reader as well as a stalled command writer.
    fd = sys.stdout.fileno()
    old_blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    deadline = time.monotonic() + 5
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_WRITE)
            while data:
                if time.monotonic() >= deadline:
                    raise capacity.CapacityError("guest control output timed out")
                if selector.select(min(0.25, max(0, deadline - time.monotonic()))):
                    try:
                        count = os.write(fd, data)
                    except BlockingIOError:
                        continue
                    data = data[count:]
    finally:
        os.set_blocking(fd, old_blocking)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise capacity.CapacityError("duplicate command field")
        value[key] = item
    return value


def reject_constant(value):
    raise capacity.CapacityError("non-finite command value")


def parse_command(line):
    if len(line) > MAX_COMMAND_BYTES or not line.endswith(b"\n"):
        raise capacity.CapacityError("oversized or unterminated command")
    try:
        command = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object,
                             parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise capacity.CapacityError("invalid JSON command") from error
    if not isinstance(command, dict) or set(command) != {"type", "id", "operation"} \
            or command["type"] != "command" or type(command["id"]) is not int \
            or command["id"] < 0 or command["operation"] not in ("health", "finish"):
        raise capacity.CapacityError("invalid protocol-v1 command fields")
    return command


def commands():
    buffer = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(sys.stdin.fileno(), selectors.EVENT_READ)
        while True:
            if not selector.select(0.25):
                continue
            chunk = os.read(sys.stdin.fileno(), MAX_COMMAND_BYTES + 1 - len(buffer))
            if not chunk:
                if buffer:
                    raise capacity.CapacityError("unterminated command at EOF")
                return
            buffer.extend(chunk)
            while b"\n" in buffer:
                end = buffer.index(b"\n") + 1
                line = bytes(buffer[:end])
                del buffer[:end]
                yield parse_command(line)
            if len(buffer) >= MAX_COMMAND_BYTES:
                raise capacity.CapacityError("oversized command")


def netns(pid):
    return os.readlink(f"/proc/{pid}/ns/net")


def unified_cgroup(pid):
    rows = [line.split(":", 2) for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()]
    values = [row[2] for row in rows if len(row) == 3 and row[:2] == ["0", ""]]
    if len(values) != 1 or not values[0].startswith("/") or ".." in Path(values[0]).parts:
        raise capacity.CapacityError("process has no unambiguous cgroup-v2 identity")
    return values[0]


def listener_present(port, inode):
    for row in Path("/proc/self/net/tcp").read_text().splitlines()[1:]:
        fields = row.split()
        if len(fields) >= 10 and fields[1] == f"0100007F:{port:04X}" \
                and fields[3] == "0A" and fields[9] == inode:
            return True
    return False


class Relays:
    def __init__(self, manager):
        self.manager = manager
        self.entries = []
        self.spawning = False
        self.root_namespace = netns(os.getpid())
        self.parent_cgroup = unified_cgroup(os.getpid())
        if self.root_namespace != netns(1):
            raise capacity.CapacityError("controller is not in the guest root network namespace")

    def fixture_identity(self, route):
        entry = self.manager.entries[route]
        self.manager._check_ownership(entry)
        if capacity.process_start(entry["pid"]) != entry["pid_start_time"] \
                or str(entry["pid"]) not in capacity.cgroup_processes(entry["cgroup"]):
            raise capacity.CapacityError("relay fixture process ownership changed")
        namespace = netns(entry["pid"])
        if namespace == self.root_namespace:
            raise capacity.CapacityError("fixture unexpectedly shares the root network namespace")
        return entry, namespace

    def start(self):
        capacity._safe_regular_file(RELAY_PATH)
        for route in capacity.ROUTE_ORDER:
            fixture, namespace = self.fixture_identity(route)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            child = None
            try:
                listener.bind(("127.0.0.1", 0))
                listener.listen(32)
                fd = listener.fileno()
                port = listener.getsockname()[1]
                inode = os.readlink(f"/proc/self/fd/{fd}").removeprefix("socket:[").removesuffix("]")
                if not listener_present(port, inode):
                    raise capacity.CapacityError("root-loopback listener ownership was not verified")
                self.spawning = True
                child = subprocess.Popen(
                    ["nsenter", f"--net=/proc/{fixture['pid']}/ns/net", "--",
                     "/usr/bin/python3", "-B", str(RELAY_PATH), "--listen-fd", str(fd),
                     "--target-port", str(capacity.FIXTURES[route]["port"])],
                    pass_fds=(fd,), close_fds=True, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
                entry = {"route": route, "process": child, "fd": fd,
                         "pid": child.pid, "pid_start_time": None,
                         "fixture_pid": fixture["pid"],
                         "fixture_pid_start_time": fixture["pid_start_time"],
                         "network_namespace": namespace, "root_network_namespace": self.root_namespace,
                         "cgroup": self.parent_cgroup, "listen_host": "127.0.0.1",
                         "listen_port": port, "listener_inode": inode,
                         "target_port": capacity.FIXTURES[route]["port"],
                         "outside_fixture_cgroups": False, "verified": False}
                # Register exact child before readiness or namespace validation.
                self.entries.append(entry)
                self.spawning = False
                entry["pid_start_time"] = capacity.process_start(child.pid)
                entry["child_ready"] = self.wait_ready(child)
                ready = entry["child_ready"]
                if ready.get("type") != "ready" or ready.get("protocol") != 1 \
                        or ready.get("pid") != child.pid or ready.get("port") != port \
                        or ready.get("target_port") != entry["target_port"]:
                    raise capacity.CapacityError("relay readiness identity mismatch")
                self.verify(entry)
            finally:
                self.spawning = False
                listener.close()

    @staticmethod
    def wait_ready(child):
        deadline = time.monotonic() + 30
        buffer = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise capacity.CapacityError("relay exited before readiness")
                if not selector.select(0.25):
                    continue
                chunk = os.read(child.stdout.fileno(), 4097 - len(buffer))
                if not chunk:
                    raise capacity.CapacityError("relay readiness pipe closed")
                buffer.extend(chunk)
                if len(buffer) > 4096:
                    raise capacity.CapacityError("relay readiness record oversized")
                if b"\n" in buffer:
                    if buffer.count(b"\n") != 1 or not buffer.endswith(b"\n"):
                        raise capacity.CapacityError("unexpected relay readiness output")
                    try:
                        value = json.loads(buffer.decode(), object_pairs_hook=unique_object,
                                           parse_constant=reject_constant)
                    except (ValueError, UnicodeError) as error:
                        raise capacity.CapacityError("invalid relay readiness JSON") from error
                    if not isinstance(value, dict):
                        raise capacity.CapacityError("invalid relay readiness record")
                    return value
        raise capacity.CapacityError("relay readiness timed out")

    def verify(self, entry):
        entry["verified"] = False
        child = entry["process"]
        fixture, namespace = self.fixture_identity(entry["route"])
        if child.poll() is not None or capacity.process_start(child.pid) != entry["pid_start_time"]:
            raise capacity.CapacityError("relay exited or restarted")
        if fixture["pid"] != entry["fixture_pid"] or namespace != entry["network_namespace"] \
                or netns(child.pid) != namespace:
            raise capacity.CapacityError("relay or fixture network namespace changed")
        group = unified_cgroup(child.pid)
        if group != self.parent_cgroup:
            raise capacity.CapacityError("relay left its controller cgroup")
        for resident in self.manager.entries.values():
            measured = "/" + str(resident["cgroup"].relative_to("/sys/fs/cgroup"))
            if group == measured or group.startswith(measured + "/"):
                raise capacity.CapacityError("relay entered a measured fixture cgroup")
        if os.readlink(f"/proc/{child.pid}/fd/{entry['fd']}") != f"socket:[{entry['listener_inode']}]" \
                or not listener_present(entry["listen_port"], entry["listener_inode"]):
            raise capacity.CapacityError("relay lost its owned root-loopback listener")
        # Recheck process continuity after reading namespace, FD and cgroup files.
        if capacity.process_start(child.pid) != entry["pid_start_time"]:
            raise capacity.CapacityError("relay process identity changed during verification")
        entry["outside_fixture_cgroups"] = True
        entry["verified"] = True
        entry["last_verified_monotonic"] = time.monotonic()

    def check(self):
        for entry in self.entries:
            self.verify(entry)
        if len(self.entries) != len(capacity.ROUTE_ORDER):
            raise capacity.CapacityError("missing route relay")
        return self.evidence()

    def evidence(self):
        return [{key: value for key, value in entry.items() if key != "process"}
                for entry in self.entries]

    def close(self):
        evidence, errors = [], []
        for entry in reversed(self.entries):
            child = entry["process"]
            row = {"route": entry["route"], "pid": child.pid, "owned": False,
                   "stopped": False, "listener_closed": False, "killed": False}
            try:
                if child.poll() is None:
                    # A failed first /proc read must not leak an unreaped child.
                    # Popen ownership prevents PID reuse until this child is reaped.
                    if entry["pid_start_time"] is None:
                        entry["pid_start_time"] = capacity.process_start(child.pid)
                    if capacity.process_start(child.pid) != entry["pid_start_time"]:
                        raise capacity.CapacityError("refusing to signal a changed relay process")
                    row["owned"] = True
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if capacity.process_start(child.pid) != entry["pid_start_time"]:
                            raise capacity.CapacityError("relay identity changed before kill")
                        child.kill()
                        row["killed"] = True
                        errors.append("relay required SIGKILL")
                        child.wait(timeout=5)
                else:
                    row["owned"] = True  # Popen reaped this exact child.
                row["stopped"] = child.poll() is not None
                row["returncode"] = child.returncode
                row["listener_closed"] = not listener_present(entry["listen_port"], entry["listener_inode"])
                if not row["listener_closed"]:
                    raise capacity.CapacityError("owned relay listener remained open")
            except Exception as error:
                errors.append(bounded_error(error))
            finally:
                if child.stdout is not None:
                    child.stdout.close()
            evidence.append(row)
        return {"attempted": bool(self.entries), "passed": not errors,
                "evidence": evidence, "errors": errors}


def run(backend, results_dir, image, payload_sha256):
    capacity.validate_cli_values(backend, image, payload_sha256)
    results_dir = capacity.validate_results_dir(results_dir)
    if results_dir != Path("/results") and Path("/results") not in results_dir.parents:
        raise ValueError("guest results directory must be /results or an existing child")
    output = results_dir / "guest-control.json"
    if output.exists() or output.is_symlink():
        raise ValueError("guest-control.json already exists; refusing overwrite")
    if require_lab() != "qemu" or os.geteuid() != 0:
        raise SystemExit("guest control requires the marked QEMU guest and root")
    # Guard is complete before any write, signal mutation, socket, or child launch.
    run_id = uuid.uuid4().hex
    report = {"schema_version": 1, "report_type": "halvo-native-lab-guest-control",
              "scope": "guest-control-evidence", "experiment_scope": "disposable-qemu-guest-only",
              "production": False, "run_id": run_id, "backend": backend,
              "image": image, "payload_sha256": payload_sha256,
              "phase0_complete": False, "collection_valid": False, "passed": False,
              "collection_errors": [], "errors": [], "residents": {}, "payload": {}}
    manager = None
    relays = None
    ready = False
    reply = None
    worker = None
    worker_advanced_at = time.monotonic()
    started = time.monotonic()
    deadline = started + capacity.MAX_COLLECTION_SECONDS
    cleanup_deadline = deadline - FINAL_REPORT_RESERVE_SECONDS
    finalizing = False
    interrupted = False

    def interrupt(signum, frame):
        nonlocal interrupted
        if relays is not None and relays.spawning:
            # Defer asynchronous exceptions until the new Popen is registered.
            interrupted = True
            return
        if finalizing and signum != signal.SIGALRM:
            interrupted = True
            return
        raise capacity.CapacityError("guest control lifetime expired" if signum == signal.SIGALRM
                                     else "guest control interrupted")

    # O_EXCL reserves this new evidence file even if setup later fails.
    with output.open("x", encoding="utf-8") as stream:
        previous = {number: signal.signal(number, interrupt)
                    for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)}
        signal.setitimer(signal.ITIMER_REAL, max(1, capacity.MAX_COLLECTION_SECONDS
                                                - CLEANUP_RESERVE_SECONDS - FINAL_REPORT_RESERVE_SECONDS))
        try:
            try:
                initial = capacity.make_report(backend, run_id, results_dir, image, payload_sha256)
                initial.update({"report_type": "halvo-native-lab-guest-control",
                                "scope": "guest-control-evidence", "collection_errors": [],
                                "protocol": PROTOCOL, "max_lifetime_seconds": capacity.MAX_COLLECTION_SECONDS,
                                "relay_source_sha256": capacity.file_digest(RELAY_PATH),
                                 "guest_control_source_sha256": capacity.file_digest(Path(__file__))})
                initial["capacity_evidence"] = False
                report = initial
                manager = (capacity.NativeResidents(run_id) if backend == "native"
                           else capacity.DockerResidents(run_id, image))
                manager.preflight()
                manager.prepare(report)
                manager.launch_all()
                report["residents"] = manager.resident_report()
                relays = Relays(manager)
                relays.start()
                if interrupted:
                    raise capacity.CapacityError("guest control interrupted during relay setup")
                worker = manager.worker_progress()
                worker_advanced_at = time.monotonic()
                report["initial_worker_checkpoint"] = worker
                report["relay_evidence"] = relays.check()
                endpoints = {entry["route"]: entry["listen_port"] for entry in relays.entries}
                emit({"type": "ready", "protocol": PROTOCOL, "report": report,
                      "endpoints": endpoints, "relay_evidence": relays.evidence()})
                ready = True
                seen = set()
                for command in commands():
                    identifier = command["id"]
                    if identifier in seen or len(seen) >= MAX_COMMANDS:
                        raise capacity.CapacityError("duplicate command ID or command limit exceeded")
                    seen.add(identifier)
                    reply = {"type": "reply", "id": identifier}
                    if command["operation"] == "finish":
                        break
                    health = {"verified": False, "guest_monotonic": time.monotonic()}
                    try:
                        if report["collection_errors"]:
                            raise capacity.ResidentFailure("a prior guest health failure invalidated this run")
                        health["residents"] = manager.check_all()
                        health["resident_evidence"] = manager.resident_report()
                        health["worker_checkpoint"] = manager.worker_progress()
                        health["relay_evidence"] = relays.check()
                        now = time.monotonic()
                        checkpoint = health["worker_checkpoint"]
                        if checkpoint < worker:
                            raise capacity.ResidentFailure("worker checkpoint regressed")
                        if checkpoint > worker:
                            worker_advanced_at = now
                        elif now - worker_advanced_at >= capacity.REQUEST_TIMEOUT_SECONDS:
                            raise capacity.ResidentFailure("worker checkpoint stopped progressing")
                        worker = checkpoint
                        health["guest_monotonic"] = now
                        health["verified"] = True
                        report["last_health"] = health
                        report["residents"] = health["resident_evidence"]
                        emit({**reply, "ok": True, "health": health})
                        reply = None
                    except Exception as error:
                        health["verified"] = False
                        health["guest_monotonic"] = time.monotonic()
                        health["diagnostic"] = True
                        report["collection_errors"].append(bounded_error(error))
                        emit({**reply, "ok": False, "error": bounded_error(error), "health": health})
                        # This reply is synchronized. Keep the command channel
                        # alive only for an explicit finish/EOF and cleanup;
                        # no later health can rehabilitate the failed run.
                        reply = None
                if reply is None:
                    report["control_end"] = "eof"
                elif "error" not in reply:
                    report["control_end"] = "finish"
            except (Exception, SystemExit) as error:
                report["collection_errors"].append(bounded_error(error))
                report["control_end"] = "error"
            finally:
                finalizing = True
                # Cleanup is part of the total lifetime, with a reserved window.
                signal.setitimer(signal.ITIMER_REAL, max(0.001, cleanup_deadline - time.monotonic()))
                relay_cleanup = {"attempted": False, "passed": True, "evidence": [], "errors": []}
                resident_cleanup = {"attempted": False, "passed": True, "evidence": [], "errors": []}
                try:
                    if relays is not None:
                        relay_cleanup = relays.close()
                        report["relay_evidence"] = relays.evidence()
                except Exception as error:
                    relay_cleanup.update({"passed": False, "errors": [bounded_error(error)]})
                try:
                    if manager is not None:
                        signal.setitimer(signal.ITIMER_REAL, max(0.001, cleanup_deadline - time.monotonic()))
                        report["residents"] = manager.resident_report()
                        resident_cleanup = manager.cleanup()
                        # No entries on read-only preflight failure is a clean no-op.
                        if not manager.entries and not getattr(manager, "owned", []) \
                                and not getattr(manager, "units", []) and not resident_cleanup.get("errors"):
                            resident_cleanup["passed"] = True
                except Exception as error:
                    resident_cleanup.update({"passed": False, "errors": [bounded_error(error)]})
                signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
                cleanup = {"attempted": True,
                           "passed": relay_cleanup["passed"] and resident_cleanup["passed"],
                           "relays": relay_cleanup, "residents": resident_cleanup,
                           "errors": relay_cleanup["errors"] + resident_cleanup["errors"]}
                report["cleanup"] = cleanup
                report["collection_errors"].extend(cleanup["errors"])
                if interrupted:
                    report["collection_errors"].append("guest control interrupted during cleanup")
                report["errors"] = list(report["collection_errors"])
                report["ended_at"] = capacity._utc_now()
                report["guest_control_complete"] = ready and cleanup["passed"] and not report["errors"]
                report["phase0_complete"] = False
                report["collection_valid"] = False
                report["passed"] = False
                report["final_worker_checkpoint"] = worker
                stream.write(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
                if reply is not None:
                    reply.setdefault("ok", cleanup["passed"])
                    reply.update({"report": report, "cleanup": cleanup})
                    emit(reply)
                else:
                    emit({"type": "error" if report["errors"] or not ready else "finished",
                          "protocol": PROTOCOL, "error": report["errors"][0] if report["errors"] else None,
                          "report": report, "cleanup": cleanup})
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for number, handler in previous.items():
                signal.signal(number, handler)
    return 0 if report["guest_control_complete"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("native", "docker"), required=True)
    parser.add_argument("--image")
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--results-dir", default="/results")
    args = parser.parse_args(argv)
    try:
        return run(args.backend, args.results_dir, args.image, args.payload_sha256)
    except (ValueError, OSError, capacity.CapacityError) as error:
        # Guard/validation failures cannot write a guest report on this machine.
        print(bounded_error(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
