"""Loopback/process integration of the external path, without a guest or Docker."""
from copy import deepcopy
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capacity
import capacity_external as external
import capacity_fixtures
import capacity_guest
import capacity_preflight
from test_capacity_integration import Handler, Residents, BODY

ROOT = Path(__file__).resolve().parent


def guest_report():
    residents = {}
    for index, name in enumerate(capacity.ALL_FIXTURES):
        fixture = capacity._fixture_identity(name)
        residents[name] = {key: fixture[key] for key in ("fixture_sha256", "runtime", "argv", "workers")}
        residents[name].update(pid=100 + index, pid_start_time=str(1000 + index),
            cgroup=f"/fixture/{name}", enforced_limits=capacity.LIMITS,
            readiness={"ready": True}, restarts=0, ooms=0, memory_events={"oom": 0, "oom_kill": 0})
    sources = capacity.source_identities()
    return {"report_type": "halvo-native-lab-guest-control", "schema_version": 1,
        "scope": "guest-control-evidence", "experiment_scope": "disposable-qemu-guest-only",
        "production": False, "phase0_complete": False, "capacity_evidence": False,
        "backend": "native", "image": None, "run_id": "a" * 32, "payload_sha256": "b" * 64,
        "collector": {"version": capacity.COLLECTOR_VERSION, "source_files_sha256": sources},
        "payload": {"source_files_sha256": sources, "runtime_identities": {"python": "test-only"}},
        "expected_limits": capacity.LIMITS,
        "fixtures": {name: capacity._fixture_identity(name) for name in capacity.ALL_FIXTURES},
        "configuration": {"route_order": list(capacity.ROUTE_ORDER),
            "route_weights_percent": capacity.ROUTE_WEIGHTS, "rates_per_second": list(capacity.RATES),
            "warmup_seconds": 60, "measurement_seconds": 120, "request_timeout_seconds": 30},
        "environment": {"lab_marker": "qemu-phase0-v1", "vm_id": "test-vm", "boot_id": "test-boot"},
        "relay_source_sha256": capacity.file_digest(ROOT / "capacity_relay.py"),
        "guest_control_source_sha256": capacity.file_digest(ROOT / "capacity_guest.py"),
        "residents": residents, "errors": []}


def relays(ports):
    return [{"route": route, "pid": 200 + i, "pid_start_time": str(2000 + i),
             "listen_host": "127.0.0.1", "listen_port": ports[route], "target_port": 3000,
             "verified": True, "outside_fixture_cgroups": True, "listener_inode": str(3000+i),
             "fixture_pid": 100+i, "fixture_pid_start_time": str(1000+i),
             "network_namespace": f"fixture:{route}", "root_network_namespace": "root", "cgroup": "/control"}
            for i, route in enumerate(capacity.ROUTE_ORDER)]


def control_process(report, ports, *, health_failure=False, wrong_id=False):
    # Test stand-in, not lab evidence. Exercises actual bounded JSON pipes and
    # the exact guest protocol consumed by the host scheduler/monitor.
    script = r'''
import json, sys, time
report, ports, rows, failure, wrong_id = json.loads(sys.argv[1])
print(json.dumps(dict(type='ready',protocol=1,report=report,endpoints=ports,relay_evidence=rows)),flush=True)
tick=0
for line in sys.stdin:
 c=json.loads(line); tick+=1
 if c['operation']=='health':
  health=dict(verified=not failure,relay_evidence=rows,guest_monotonic=time.monotonic(),
   worker_checkpoint=tick,resident_evidence=report['residents'],
   residents={name:dict(active=True,pid=e['pid'],restart_count=0,oom_killed=False)
              for name,e in report['residents'].items()})
  r=dict(type='reply',id=c['id']+int(wrong_id),ok=not failure,health=health)
  if failure:r['error']='injected health failure'
  print(json.dumps(r),flush=True)
 else:
  cleanup=dict(passed=True,errors=[],residents=dict(passed=True,errors=[],evidence=[
   dict(name=n,owned=True,stopped=True,empty=True) for n in report['residents']]),
   relays=dict(passed=True,errors=[],evidence=[dict(route=r,owned=True,stopped=True,
      listener_closed=True,killed=False,survived=False) for r in ports]))
  report['cleanup']=cleanup
  print(json.dumps(dict(type='reply',id=c['id'],ok=True,report=report,cleanup=cleanup)),flush=True)
  break
'''
    return subprocess.Popen([sys.executable, "-B", "-c", script,
        json.dumps([report, ports, relays(ports), health_failure, wrong_id])],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)


class ExternalPathTests(unittest.TestCase):
    def setUp(self):
        self.servers = []
        self.threads = []
        self.ports = {}
        for route in capacity.ROUTE_ORDER:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            server.response_delay = server.trickle_delay = 0
            server.observed_ports = set()
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.ports[route] = server.server_port
            self.servers.append(server); self.threads.append(thread)

    def tearDown(self):
        for server, thread in zip(self.servers, self.threads):
            server.shutdown(); server.server_close(); thread.join(2)

    def channel(self, **kwargs):
        child = control_process(guest_report(), self.ports, **kwargs)
        channel = external.ControlChannel(process=child)
        self.addCleanup(channel.finish)
        channel.start(timeout=5)
        return channel

    def test_real_http_pipes_and_control_monitor_together(self):
        channel = self.channel()
        external.validate_guest_report(channel.ready["report"], "native", None, "b" * 64)
        manager = external.ExternalManager(channel)
        pool = external.ExternalPool(manager, self.ports)
        self.addCleanup(pool.close)
        manager.pool = pool
        pool.start()
        rows, summary = capacity.run_phase(manager, pool, 16, 1, "path-check", 0)
        self.assertEqual(len(rows), 16)
        self.assertEqual(summary["failed"], 0)
        self.assertTrue(all(row["http_version"] == 11 for row in rows))
        self.assertGreater(manager.worker_progress(), 0)
        self.assertTrue(pool.close()["passed"])
        cleanup = channel.finish()
        self.assertTrue(cleanup["passed"], cleanup["errors"])
        external._validate_cleanup(cleanup["reply"])

    def test_failed_health_is_retained_and_finish_is_not_replayed(self):
        channel = self.channel(health_failure=True)
        manager = external.ExternalManager(channel)
        with self.assertRaises(capacity.ResidentFailure):
            manager.check_all()
        self.assertFalse(channel.broken)
        before = channel.seq
        first = channel.finish()
        second = channel.finish()
        self.assertEqual(first, second)
        self.assertEqual(channel.seq, before + 1)
        self.assertTrue(first["passed"], first["errors"])

    def test_reply_id_mismatch_poisoned_stream_does_not_repeat_action(self):
        channel = self.channel(wrong_id=True)
        with self.assertRaises(capacity.CapacityError):
            channel.exchange("health", timeout=2)
        self.assertTrue(channel.broken)
        before = channel.seq
        cleanup = channel.finish()
        self.assertFalse(cleanup["passed"])
        self.assertEqual(channel.seq, before)

    def test_protocol_guard_rejects_extra_duplicate_boolean_and_oversize_commands(self):
        for line in (b'{"type":"command","id":true,"operation":"health"}\n',
                     b'{"type":"command","id":1,"id":2,"operation":"finish"}\n',
                     b'{"type":"command","id":1,"operation":"health","extra":0}\n',
                     b"x" * 4097, b'{}'):
            with self.subTest(line=line[:70]):
                with self.assertRaises(capacity.CapacityError):
                    capacity_guest.parse_command(line)

    def test_unmarked_guest_rejected_before_output_or_process_mutation(self):
        with patch.object(capacity_guest, "require_lab", side_effect=SystemExit("unmarked")), \
             patch.object(capacity_guest.capacity, "validate_results_dir", return_value=Path("/results")), \
             patch.object(capacity_guest.Path, "exists", return_value=False), \
             patch.object(capacity_guest.Path, "is_symlink", return_value=False), \
             patch.object(capacity_guest.Path, "open") as opened, \
             patch.object(capacity_guest.subprocess, "Popen") as popen:
            with self.assertRaises(SystemExit):
                capacity_guest.run("native", "/results", None, "b" * 64)
            opened.assert_not_called(); popen.assert_not_called()

    def test_transparent_relay_keeps_http11_socket_reusable_and_stops(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0)); listener.listen(32)
        port, fd = listener.getsockname()[1], listener.fileno()
        command = [sys.executable, "-B", "-c",
            "import sys,socket; import capacity_relay; "
            "capacity_relay.run(socket.socket(fileno=int(sys.argv[1])),int(sys.argv[2]))",
            str(fd), str(self.ports["python"])]
        child = subprocess.Popen(command, cwd=ROOT, pass_fds=(fd,),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        listener.close()
        try:
            ready = json.loads(child.stdout.readline())
            self.assertEqual(ready["port"], port)
            import http.client
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                for _ in range(4):
                    connection.request("GET", "/")
                    response = connection.getresponse()
                    self.assertEqual(response.version, 11)
                    self.assertEqual(response.read(), BODY)
                    self.assertFalse(response.will_close)
            finally:
                connection.close()
            self.assertEqual(len(self.servers[0].observed_ports), 1)
            child.terminate()
            child.wait(timeout=3)
            self.assertEqual(child.returncode, 0)
            with socket.socket() as probe:
                self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=3)
            child.stdout.close(); child.stderr.close()

    def test_capacity_python_fixture_handles_concurrent_persistent_connections(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        source = capacity_fixtures.PYTHON_SERVER.replace("3000", str(port))
        child = subprocess.Popen([sys.executable, "-B", "-c", source],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        connections = []
        try:
            deadline = time.monotonic() + 5
            while True:
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        break
                if child.poll() is not None or time.monotonic() >= deadline:
                    self.fail("capacity fixture did not become ready")
                time.sleep(0.01)
            import http.client
            for _ in range(4):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                connections.append(connection)
                connection.request("GET", "/")
            for connection in connections:
                response = connection.getresponse()
                self.assertEqual(response.version, 11)
                self.assertEqual(response.read(), BODY)
                self.assertFalse(response.will_close)
                connection.request("GET", "/")
                self.assertEqual(connection.getresponse().read(), BODY)
        finally:
            for connection in connections:
                connection.close()
            child.terminate(); child.wait(timeout=3)
        self.assertNotEqual(capacity.FIXTURES["python"], capacity.benchmark.FIXTURES["python"])
        for name in ("static", "node", "worker"):
            self.assertEqual(capacity.FIXTURES[name], capacity.benchmark.FIXTURES[name])

    def test_relay_limits_identity_and_affinity_are_not_optional(self):
        baseline = relays(self.ports)
        external._validate_relays(baseline, self.ports)
        for key, value in (("verified", False), ("outside_fixture_cgroups", False),
                           ("listen_host", "0.0.0.0"), ("listener_inode", None)):
            rows = deepcopy(baseline); rows[0][key] = value
            with self.assertRaises(capacity.ResidentFailure):
                external._validate_relays(rows, self.ports)
        rows = deepcopy(baseline); rows[0]["pid_start_time"] = "changed"
        with self.assertRaises(capacity.ResidentFailure):
            external._validate_relays(rows, self.ports, baseline)
        with self.assertRaises(capacity.GeneratorBottleneck):
            external._check_affinity([0, 1], external.HOST_CPUS)

    def test_image_digest_reads_real_fixture_bytes_not_declarations(self):
        with tempfile.TemporaryDirectory() as temporary:
            capacity_fixtures.write_fixtures(Path(temporary))
            expected = capacity.benchmark.fixture_digest(capacity.FIXTURES["python"])
            self.assertEqual(capacity_fixtures.deployed_digest(temporary, "python"), expected)
            Path(temporary, "server.py").write_text("changed deployed file\n")
            self.assertNotEqual(capacity_fixtures.deployed_digest(temporary, "python"), expected)

    def test_forwarding_policy_remains_local_only_and_known_host_pinned(self):
        control = external.ssh_command("/var/tmp/halvo-native-vm-test", 3333)
        forwards = external.ssh_command("/var/tmp/halvo-native-vm-test", 3333, forwarding=True)
        self.assertIn("-oClearAllForwardings=yes", control)
        self.assertIn("-oClearAllForwardings=no", forwards)
        self.assertIn("-oStrictHostKeyChecking=yes", forwards)
        source = (ROOT / "vm-capacity.sh").read_text()
        self.assertIn('restrict,port-forwarding,permitopen="127.0.0.1:*"', source)
        self.assertIn('AllowTcpForwarding local', source)
        self.assertIn('PermitListen none', source)

    def test_launcher_removes_public_key_comment_without_changing_pinned_key(self):
        key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicFixture halvo-disposable-lab\n'
        formatted = subprocess.run(['awk', 'NF >= 2 {print $1 " " $2}'],
            input=key, text=True, capture_output=True, check=True).stdout.strip()
        line = '[127.0.0.1]:2222 ' + formatted
        self.assertEqual(len(line.split()), 3)
        self.assertEqual(line.split()[1:], key.split()[:2])
        source = (ROOT / 'vm-capacity.sh').read_text()
        self.assertIn('"$port" "$host_public" > "$lab_dir/known-hosts"', source)

    def test_qemu_dependency_helper_refuses_unprivileged_non_lab_before_writes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("prepare_fuse", ROOT / "prepare-qemu-fuse.py")
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        with patch.object(helper.os, "geteuid", return_value=1000), \
             patch.object(helper.Path, "mkdir") as mkdir, patch.object(helper, "fetch") as fetch:
            with self.assertRaises(ValueError):
                helper.prepare(Path("/not-a-lab"))
            mkdir.assert_not_called(); fetch.assert_not_called()

    def test_idle_keepalive_eof_is_detected_before_next_get_not_retried(self):
        def close_after_body(handler):
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(BODY)))
            handler.end_headers(); handler.wfile.write(BODY)
            handler.close_connection = True

        child = subprocess.Popen([sys.executable, "-B", str(ROOT / "capacity_client.py"),
            "--port", str(self.ports["python"]), "--expected", BODY.decode(),
            "--timeout", "1", "--workers", "1", "--queue-size", "4"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        try:
            self.assertEqual(json.loads(child.stdout.readline())["type"], "ready")
            with patch.object(Handler, "do_GET", close_after_body):
                for index in range(2):
                    child.stdin.write((json.dumps({"type": "request", "id": index,
                        "scheduled_at": time.monotonic()}) + "\n").encode())
                    row = json.loads(child.stdout.readline())
                    self.assertTrue(row["ok"], row)
                    self.assertFalse(row["connection_reused"])
                    time.sleep(0.08)
            child.stdin.close(); child.wait(timeout=3)
            self.assertEqual(child.returncode, 0)
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=3)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()

    def test_external_pool_uses_nonblocking_profile_without_relaxing_guards(self):
        profile = capacity_preflight.CLIENT_PROFILE
        self.assertEqual(profile, {"client_implementation": "bounded-nonblocking-http11-v1",
            "max_outstanding_requests": 4096, "max_idle_connections_per_route": 32,
            "client_nofile_soft_min": 8192})
        self.assertEqual(capacity.MAX_CLIENT_OUTSTANDING, 4096)
        self.assertEqual(capacity.CLIENT_QUEUE_LAG_LIMIT_SECONDS, 2.0)
        self.assertEqual(capacity.GENERATOR_LAG_LIMIT_SECONDS, 0.5)

    def test_slow_python_responses_do_not_create_the_old_32_worker_queue(self):
        # Same16RPS/8-second Python delay as the preserved frozen25 reproduction.
        # The backend is synthetic/unlimited; this checks the client, not a quota.
        self.servers[0].response_delay = 8
        manager = Residents(delay=0)
        pool = external.ExternalPool(manager, self.ports)
        self.addCleanup(pool.close)
        pool.start()
        rows, summary = capacity.run_phase(manager, pool, 16, 12, "slow-client-regression", 0)
        self.assertEqual(len(rows), 192)
        self.assertEqual(summary["failed"], 0)
        self.assertLessEqual(summary["generator"]["max_dispatch_lag_ms"], 500)
        self.assertTrue(all(row["client_queue_lag_ms"] <= 2000 for row in rows))
        self.assertGreater(len(self.servers[0].observed_ports), 32)
        self.assertTrue(pool.close()["passed"])

    def test_capacity_python_fixture_bound_matches_guest_relay_not_a_smaller_artificial_cap(self):
        self.assertIn("BoundedSemaphore(32)", capacity_fixtures.PYTHON_SERVER)
        self.assertNotIn("BoundedSemaphore(16)", capacity_fixtures.PYTHON_SERVER)


class _FakeChildren:
    """Stand-ins for the guest channel, forward and client pool: no subprocess."""

    def __init__(self, lab):
        self.initial = guest_report()
        self.ports = {route: 4000 + i for i, route in enumerate(capacity.ROUTE_ORDER)}
        self.lab = lab

    def channel_factory(self, command, affinity=None):
        outer = self

        class Channel:
            startup_evidence = {"cpu_affinity": [2, 3]}
            records = []

            def start(self):
                return {"report": outer.initial, "endpoints": outer.ports,
                        "relay_evidence": relays(outer.ports)}

            def finish(self):
                cleanup = {"passed": True, "errors": [], "residents": {"passed": True, "errors": [],
                    "evidence": [{"name": n, "owned": True, "stopped": True, "empty": True}
                                 for n in outer.initial["residents"]]},
                    "relays": {"passed": True, "errors": [], "evidence": [
                        {"route": r, "owned": True, "stopped": True, "listener_closed": True,
                         "killed": False, "survived": False} for r in outer.ports]}}
                final = deepcopy(outer.initial)
                final["cleanup"] = cleanup
                return {"passed": True, "reply": {"ok": True, "cleanup": cleanup, "report": final}}

        return Channel()

    def forward_factory(self, lab, ssh_port, endpoints, affinity=None):
        outer = self

        class Forward:
            def start(self):
                return dict(outer.ports)

            def verify_continuity(self):
                pass

            def close(self):
                return {"passed": True, "errors": []}

            @property
            def evidence(self):
                return {"listeners_ready": True, "nofile_soft_limit": 16384}

        return Forward()

    def pool_factory(self, manager, ports, affinity=None):
        class Pool:
            def start(self):
                pass

            def verify_placement(self):
                pass

            def close(self):
                return {"passed": True, "errors": []}

            @property
            def startup_evidence(self):
                return {"cpu_affinity": [2, 3], "nofile_soft_limit": 8192}

        return Pool()

    def selfcheck(self):
        return {"passed": True, "scope": "load-generator-selfcheck", "capacity_evidence": False,
                **capacity_preflight.CLIENT_PROFILE,
                "source_sha256": capacity_preflight.source_identities(),
                "client_nofile_soft_limits": {route: 8192 for route in capacity.ROUTE_ORDER},
                "rate_per_second": 256, "duration_seconds": 60,
                "summary": {"completed": 15360, "failed": 0},
                "cleanup": {"passed": True, "server_stopped": True}}


class ScheduleStopTest(unittest.TestCase):
    """A rejected window is the measured wall: the climb stops, evidence stays valid."""

    def _collect(self, rate_runner):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "vm-id").write_text("test-vm\n")
            output = lab / "capacity-external.json"
            fake = _FakeChildren(lab)
            report = external.collect(lab, 2222, "native", "b" * 64, output, mode="capacity",
                selfcheck=fake.selfcheck, channel_factory=fake.channel_factory,
                forward_factory=fake.forward_factory, pool_factory=fake.pool_factory,
                rate_runner=rate_runner, validate=False)
            return report

    def test_schedule_stops_at_first_rejected_window_and_keeps_the_collection_valid(self):
        calls = []

        def rate_runner(manager, pool, rate, request_id):
            calls.append(rate)
            accepted = rate < 16
            return {"rate_per_second": rate, "accepted": accepted, "passed": accepted,
                    "error_rate": 0.0 if accepted else capacity.ERROR_RATE_MAX * 2,
                    "goodput_rps": float(rate), "aborted": None,
                    "latency_ms": {"count": rate * 120, "p50": 50.0, "p95": 200.0,
                                   "p99": 600.0, "max": 1100.0},
                    "generator": {"bottleneck": False, "scheduled": rate * 120,
                                  "dispatched": rate * 120, "completed": rate * 120,
                                  "max_dispatch_lag_ms": 2.0}}

        report = self._collect(rate_runner)
        self.assertEqual(calls, [1, 2, 4, 8, 16], "rates above the wall must never start")
        self.assertEqual(report["schedule"], {"stopped_at_rejection": 16, "phase0_complete": False})
        self.assertTrue(report["collection_valid"])
        self.assertTrue(report["passed"])
        self.assertEqual(report["capacity_rps"], 8)
        self.assertFalse(report["capacity_evidence"] is False and report["collection_valid"])
        self.assertEqual(report["errors"], [])
        self.assertTrue(report["cleanup"]["passed"])
        self.assertEqual([row["rate_per_second"] for row in report["rates"]], [1, 2, 4, 8, 16])

    def test_failure_after_saturation_invalidates_the_collection(self):
        for failure in ("continuity", "cleanup"):
            with self.subTest(failure=failure):
                calls = []

                def continuity_failure():
                    raise capacity.ResidentFailure("SSH forwarding exited/restarted")

                def rate_runner(manager, pool, rate, request_id):
                    calls.append(rate)
                    if rate == 16:
                        if failure == "continuity":
                            manager.forward.verify_continuity = continuity_failure
                        else:
                            manager.forward.close = lambda: {
                                "passed": False, "errors": ["forward child survived"]}
                    return {"rate_per_second": rate, "accepted": rate < 16,
                            "passed": rate < 16}

                report = self._collect(rate_runner)
                self.assertEqual(calls, [1, 2, 4, 8, 16])
                self.assertEqual(report["schedule"]["stopped_at_rejection"], 16)
                self.assertTrue(report["errors"])
                self.assertFalse(report["cleanup"]["passed"])
                self.assertFalse(report["passed"])
                self.assertFalse(report["collection_valid"])
                self.assertFalse(report["capacity_evidence"])
                self.assertIsNone(report["capacity_rps"])

    def test_aborted_window_is_not_a_valid_saturation_stop(self):
        for error in (capacity.ResidentFailure("resident health timed out"),
                      capacity.GeneratorBottleneck("open-loop schedule fell behind")):
            with self.subTest(error=type(error).__name__):
                calls = []

                def rate_runner(manager, pool, rate, request_id):
                    calls.append(rate)
                    if rate == 16:
                        raise error
                    return {"rate_per_second": rate, "accepted": True, "passed": True}

                report = self._collect(rate_runner)
                self.assertEqual(calls, [1, 2, 4, 8, 16])
                self.assertTrue(report["rates"][-1]["aborted"])
                self.assertNotIn("schedule", report)
                self.assertFalse(report["passed"])
                self.assertFalse(report["collection_valid"])
                self.assertFalse(report["capacity_evidence"])
                self.assertIsNone(report["capacity_rps"])

    def test_preflight_mode_never_records_a_saturation_stop(self):
        def rate_runner(manager, pool, rate, request_id):
            return {"rate_per_second": rate, "accepted": False, "passed": False,
                    "error_rate": capacity.ERROR_RATE_MAX * 2, "goodput_rps": 0.0,
                    "aborted": None, "latency_ms": {}, "generator": {"bottleneck": False}}

        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "vm-id").write_text("test-vm\n")
            report = external.collect(lab, 2222, "native", "b" * 64, lab / "capacity-external.json",
                mode="preflight", selfcheck=_FakeChildren(lab).selfcheck,
                channel_factory=_FakeChildren(lab).channel_factory,
                forward_factory=_FakeChildren(lab).forward_factory,
                pool_factory=_FakeChildren(lab).pool_factory,
                rate_runner=rate_runner, validate=False)
            self.assertNotIn("schedule", report)
            self.assertFalse(report["passed"])


if __name__ == "__main__":
    unittest.main()
