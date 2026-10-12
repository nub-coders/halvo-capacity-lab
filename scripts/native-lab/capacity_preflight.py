#!/usr/bin/env python3
"""Loopback-only generator self-capacity check, never a backend verdict.

Uses the real request child processes, pipe transport, open-loop scheduler and
asynchronous health monitor. Synthetic supervisor observations deliberately do
not assert a real tenant runtime/isolation boundary. Run in each guest before
benchmarking; a host-only pass cannot validate TCG scheduling.
"""
import argparse
import json
import os
import resource
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import capacity
import capacity_async_client

BODY = b"halvo-memory"
RATE = 256  # Twice the largest approved offered rate.
DURATION = 60
SOURCE_FILES = ("capacity.py", "capacity_async_client.py", "capacity_preflight.py")
CLIENT_PROFILE = {
    "client_implementation": capacity_async_client.IMPLEMENTATION,
    # ClientPool enforces this bound across all routes, not per route.
    "max_outstanding_requests": capacity.MAX_CLIENT_OUTSTANDING,
    "max_idle_connections_per_route": capacity_async_client.MAX_IDLE_CONNECTIONS,
    "client_nofile_soft_min": capacity_async_client.MIN_NOFILE,
}


def validate_client_profile(profile):
    expected = {"client_implementation": "bounded-nonblocking-http11-v1",
                "max_outstanding_requests": 4096,
                "max_idle_connections_per_route": 32, "client_nofile_soft_min": 8192}
    if not isinstance(profile, dict) \
            or capacity_async_client.MAX_INFLIGHT != 4096 or CLIENT_PROFILE != expected \
            or any(type(profile.get(key)) is not type(value) or profile.get(key) != value
                   for key, value in expected.items()) \
            or any(key in profile for key in ("client_workers_per_route", "client_queue_size")):
        raise capacity.GeneratorBottleneck("nonblocking client profile differs")


def source_identities():
    return {name: capacity.file_digest(Path(__file__).resolve().with_name(name))
            for name in SOURCE_FILES}


def validate_identity(report):
    validate_client_profile(report)
    if report.get("source_sha256") != source_identities():
        raise capacity.GeneratorBottleneck("selfcheck client sources differ")


def client_command(port, expected):
    """Identical client engine/configuration for selfcheck and collection."""
    validate_client_profile(CLIENT_PROFILE)
    script = Path(__file__).resolve().with_name("capacity_async_client.py")
    capacity._safe_regular_file(script)
    return [sys.executable, "-B", str(script), "--host", "127.0.0.1", "--port", str(port),
            "--expected", expected, "--timeout", str(capacity.REQUEST_TIMEOUT_SECONDS),
            "--max-outstanding", str(capacity.MAX_CLIENT_OUTSTANDING),
             "--max-idle", str(capacity_async_client.MAX_IDLE_CONNECTIONS)]


def verify_client_descriptor_limit(process):
    soft, _ = resource.prlimit(process.pid, resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft < CLIENT_PROFILE["client_nofile_soft_min"]:
        raise capacity.GeneratorBottleneck("client descriptor limit is too low")
    return soft


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # This is a fast generator canary, not a tenant server. Disable artificial
    # Nagle/delayed-ACK stalls from split header/body writes; otherwise
    # persistent client connections benchmark this canary's 40-ms TCP
    # interaction instead of the generator's dispatch capacity.
    disable_nagle_algorithm = True

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


class SyntheticSupervisor:
    def __init__(self):
        self.started = time.monotonic()

    def check_all(self):
        return {name: {"active": True, "synthetic": True} for name in capacity.ALL_FIXTURES}

    def worker_progress(self):
        return int((time.monotonic() - self.started) * 1000)

    def resident_report(self):
        return {name: {"synthetic": True} for name in capacity.ALL_FIXTURES}


def start_clients(pool, port):
    for route in capacity.ROUTE_ORDER:
        child = subprocess.Popen(
            client_command(port, BODY.decode()), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0)
        pool.processes[route] = child
        if child.stdin is None or child.stdout is None:
            raise capacity.GeneratorBottleneck("selfcheck client did not expose pipes")
        os.set_blocking(child.stdin.fileno(), False)
        os.set_blocking(child.stdout.fileno(), False)
        pool.buffers[route] = bytearray()
        pool.selector.register(child.stdout.fileno(), selectors.EVENT_READ, route)
    ready = set()
    deadline = time.monotonic() + capacity.CLIENT_START_TIMEOUT_SECONDS
    while ready != set(capacity.ROUTE_ORDER) and time.monotonic() < deadline:
        pool._read_available(0.1)
        for route, record in pool.received:
            if record != {"type": "ready", "protocol": 1} \
                    or type(record.get("protocol")) is not int or route in ready:
                raise capacity.GeneratorBottleneck("invalid selfcheck client readiness")
            ready.add(route)
        pool.received.clear()
    if ready != set(capacity.ROUTE_ORDER):
        raise capacity.GeneratorBottleneck("selfcheck client readiness timed out")
    return {route: verify_client_descriptor_limit(process) for route, process in pool.processes.items()}


def collect():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    pool = capacity.ClientPool(SyntheticSupervisor())
    report = {"schema_version": 1, "scope": "load-generator-selfcheck",
               "capacity_evidence": False, "phase0_complete": False,
               "passed": False, "rate_per_second": RATE, "duration_seconds": DURATION,
               **CLIENT_PROFILE,
               "fixture": "synthetic-loopback-HTTP/1.1", "errors": [],
               "source_sha256": source_identities()}
    thread.start()
    try:
        report["client_nofile_soft_limits"] = start_clients(pool, server.server_port)
        rows, summary = capacity.run_phase(pool.manager, pool, RATE, DURATION, "selfcheck", 0)
        report.update(summary=summary, raw_outcomes=rows)
        if summary["failed"] or len(rows) != RATE * DURATION:
            raise capacity.GeneratorBottleneck("selfcheck did not sustain all requests")
        if not DURATION <= summary["timings"]["actual_duration_seconds"] <= DURATION + 0.5:
            raise capacity.GeneratorBottleneck("selfcheck measurement window differs")
        report["passed"] = True
    except Exception as error:
        report["errors"].append(capacity.describe_error(error))
        report["partial_phase"] = getattr(error, "phase_evidence", None)
    finally:
        report["cleanup"] = pool.close()
        server.shutdown()
        server.server_close()
        thread.join(5)
        report["cleanup"]["server_stopped"] = not thread.is_alive()
        if not report["cleanup"]["passed"] or thread.is_alive():
            report["passed"] = False
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="New evidence file; existing files are never overwritten")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error("output must name a new file in an existing directory")
    report = collect()
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, allow_nan=False, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "passed": report["passed"],
                      "scope": report["scope"], "errors": report["errors"]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
