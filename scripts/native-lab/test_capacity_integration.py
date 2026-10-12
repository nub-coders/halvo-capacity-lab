"""Real loopback HTTP/child-process checks; no Docker, NsJail or VM is used.

Only resident supervision is a test double. Scheduling, pipe I/O, HTTP client,
raw outcomes and health-monitor concurrency use the real instrument.
"""
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capacity
import capacity_preflight

# Reproduce the preserved faulty instrument without editing its bytes.
if os.environ.get("HALVO_CAPACITY_REGRESSION_MODULE"):
    spec = importlib.util.spec_from_file_location(
        "capacity_regression", os.environ["HALVO_CAPACITY_REGRESSION_MODULE"])
    capacity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capacity)

CLIENT = Path(__file__).with_name("capacity_client.py")
BODY = b"halvo-memory"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.observed_ports.add(self.client_address[1])
        time.sleep(self.server.response_delay)
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        try:
            if self.server.trickle_delay:
                for byte in BODY:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(self.server.trickle_delay)
            else:
                self.wfile.write(BODY)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


class Residents:
    def __init__(self, delay=0.7, fail_after=None):
        self.delay = delay
        self.fail_after = fail_after
        self.checks = 0
        self.started = time.monotonic()

    def check_all(self):
        time.sleep(self.delay)
        self.checks += 1
        if self.fail_after is not None and self.checks >= self.fail_after:
            raise capacity.ResidentFailure("injected resident failure")
        return {name: {"active": True} for name in capacity.ALL_FIXTURES}

    def worker_progress(self):
        return int((time.monotonic() - self.started) * 1000)

    def resident_report(self):
        return {name: {"readiness": {"ready": True}, "restarts": 0, "ooms": 0}
                for name in capacity.ALL_FIXTURES}


class CapacityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.response_delay = 0
        self.server.trickle_delay = 0
        self.server.observed_ports = set()
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(2)

    def client(self, workers=4, queue_size=512, timeout=30):
        return subprocess.Popen(
            [sys.executable, "-B", str(CLIENT), "--port", str(self.server.server_port),
             "--expected", BODY.decode(), "--workers", str(workers),
             "--queue-size", str(queue_size), "--timeout", str(timeout)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    def pool(self, manager):
        pool = capacity.ClientPool(manager)
        self.addCleanup(pool.close)
        for route in capacity.ROUTE_ORDER:
            child = self.client()
            pool.processes[route] = child
            os.set_blocking(child.stdin.fileno(), False)
            os.set_blocking(child.stdout.fileno(), False)
            pool.buffers[route] = bytearray()
            pool.selector.register(child.stdout.fileno(), selectors.EVENT_READ, route)
        ready = set()
        deadline = time.monotonic() + 10
        while ready != set(capacity.ROUTE_ORDER) and time.monotonic() < deadline:
            pool._read_available(0.1)
            for route, record in pool.received:
                self.assertEqual(record, {"type": "ready", "protocol": 1})
                ready.add(route)
            pool.received.clear()
        self.assertEqual(ready, set(capacity.ROUTE_ORDER))
        return pool

    def test_slow_health_probe_cannot_block_real_open_loop_http_dispatch(self):
        manager = Residents(delay=0.7)
        pool = self.pool(manager)
        rows, result = capacity.run_phase(manager, pool, 128, 6, "offline-check", 0)
        self.assertEqual(len(rows), 768)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["goodput_rps"], 128)
        self.assertEqual({r: result["routes"][r]["completed"] for r in capacity.ROUTE_ORDER},
                         {"python": 537, "static": 154, "node": 77})
        self.assertLessEqual(result["generator"]["max_dispatch_lag_ms"], 500)
        self.assertGreaterEqual(result["timings"]["actual_duration_seconds"], 6)
        self.assertLess(result["timings"]["actual_duration_seconds"], 6.5)
        self.assertTrue(result["health_checks"]["monitor_stopped"])
        self.assertTrue(all(row["passed"] for row in result["health_checks"]["snapshots"]))
        self.assertTrue(result["drain"]["completed"])
        self.assertGreaterEqual(manager.checks, 3)
        self.assertTrue(pool.close()["passed"])

    def test_monitor_failure_keeps_partial_evidence_and_rejects_the_phase(self):
        manager = Residents(delay=0, fail_after=2)
        pool = self.pool(manager)
        with patch.object(capacity, "HEALTH_CHECK_INTERVAL_SECONDS", 0.1):
            with self.assertRaises(capacity.ResidentFailure) as caught:
                capacity.run_phase(manager, pool, 128, 2, "failure-check", 0)
        evidence = caught.exception.phase_evidence
        self.assertTrue(evidence["outcomes"] or evidence["pending"])
        self.assertIn("injected resident failure", evidence["health_checks"]["failure"])
        self.assertTrue(evidence["health_checks"]["monitor_stopped"])

    def test_request_deadline_bounds_trickled_body_not_each_read(self):
        self.server.trickle_delay = 0.07
        child = self.client(workers=1, timeout=0.2)
        command = {"type": "request", "id": 0, "scheduled_at": time.monotonic()}
        output, errors = child.communicate((json.dumps(command) + "\n").encode(), timeout=5)
        self.assertEqual(child.returncode, 0, errors.decode())
        records = [json.loads(line) for line in output.splitlines()]
        self.assertEqual(len(records), 2)
        result = records[-1]
        self.assertEqual(result["error"], "timeout")
        self.assertFalse(result["ok"])
        self.assertLess(result["ended_at"] - result["started_at"], 0.5)

    def test_keepalive_reuses_socket_and_exits_after_eof(self):
        child = self.client(workers=1)
        # Space commands so a single connection is reused rather than overload.
        self.assertEqual(json.loads(child.stdout.readline()), {"type": "ready", "protocol": 1})
        for index in range(3):
            child.stdin.write((json.dumps({"type": "request", "id": index,
                                          "scheduled_at": time.monotonic()}) + "\n").encode())
            result = json.loads(child.stdout.readline())
            self.assertTrue(result["ok"])
        child.stdin.close()
        child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()
        self.assertEqual(child.returncode, 0)
        self.assertEqual(len(self.server.observed_ports), 1)

    def test_invalid_and_oversized_commands_are_rejected_without_http_requests(self):
        for value in (b'{"type":"request","id":true,"scheduled_at":0}\n',
                      b'{"type":"request","id":0,"scheduled_at":NaN}\n',
                      b'{"type":"request","id":0,"id":1,"scheduled_at":0}\n',
                      b"x" * 4097):
            with self.subTest(value=value[:50]):
                child = self.client()
                output, _ = child.communicate(value, timeout=5)
                self.assertEqual(child.returncode, 2)
                self.assertEqual(json.loads(output.splitlines()[-1])["type"], "protocol_error")
        self.assertEqual(len(self.server.observed_ports), 0)

    def test_queue_overload_reports_generator_failure_not_http_capacity(self):
        self.server.response_delay = 0.05
        child = self.client(workers=1, queue_size=1)
        commands = b"".join((json.dumps({"type": "request", "id": index,
                                       "scheduled_at": time.monotonic()}) + "\n").encode()
                            for index in range(100))
        output, _ = child.communicate(commands, timeout=5)
        results = [json.loads(line) for line in output.splitlines()[1:]]
        full = [row for row in results if row["error"] == "client_queue_full"]
        self.assertTrue(full)
        self.assertEqual(len(results), 100)
        pool = capacity.ClientPool(None)
        self.addCleanup(pool.close)
        row = full[0]
        pool.pending[row["id"]] = {"route": "python", "scheduled_at": row["scheduled_at"]}
        with self.assertRaises(capacity.GeneratorBottleneck):
            pool._validate_result("python", row, row["scheduled_at"])

    def test_fast_canary_sustains_twice_max_rate_without_claiming_backend_capacity(self):
        with patch.object(capacity_preflight, "DURATION", 2):
            report = capacity_preflight.collect()
        self.assertTrue(report["passed"], report["errors"])
        self.assertEqual(report["scope"], "load-generator-selfcheck")
        self.assertFalse(report["capacity_evidence"])
        self.assertFalse(report["phase0_complete"])
        self.assertEqual(report["summary"]["completed"], 512)
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertTrue(report["cleanup"]["passed"])


if __name__ == "__main__":
    unittest.main()
