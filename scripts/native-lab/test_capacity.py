"""Capacity scheduling, input boundaries and bounded probe diagnostics."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capacity
import capacity_guest


class CapacityPureTests(unittest.TestCase):
    def test_fixed_route_cycle_is_deterministic_and_exact(self):
        first = capacity.weighted_routes(100)
        second = capacity.weighted_routes(100)
        self.assertEqual(first, second)
        self.assertEqual({route: first.count(route) for route in capacity.ROUTE_ORDER},
                         capacity.ROUTE_WEIGHTS)
        self.assertEqual(capacity.weighted_routes(0), ())

    def test_schedule_has_fixed_count_and_offsets(self):
        rows = list(capacity.iter_schedule(2, 3))
        self.assertEqual(len(rows), 6)
        self.assertEqual([row["index"] for row in rows], list(range(6)))
        self.assertEqual([row["offset_seconds"] for row in rows],
                         [0.0, 0.5, 1.0, 1.5, 2.0, 2.5])
        self.assertEqual(capacity.validate_schedule(128, 120), 15360)
        self.assertEqual(capacity.HEALTH_CHECK_INTERVAL_SECONDS, 5.0)

    def test_schedule_and_weights_reject_invalid_inputs(self):
        invalid = (
            (0, 1), (-1, 1), (1, 0), (1, -1), (True, 1), (1, True),
        )
        for rate, duration in invalid:
            with self.subTest(rate=rate, duration=duration), self.assertRaises(ValueError):
                capacity.validate_schedule(rate, duration)
        for weights in (
            {"python": 70, "static": 20},
            {"python": 70, "static": 20, "node": 11},
            {"python": 70, "static": 20, "node": True},
            {"python": 70, "static": 20, "node": 10, "other": 0},
        ):
            with self.subTest(weights=weights), self.assertRaises(ValueError):
                capacity.validate_route_weights(weights)

    def test_percentile_and_aggregation_keep_errors_and_goodput(self):
        self.assertIsNone(capacity.percentile([], 50))
        self.assertEqual(capacity.percentile([4, 1, 2, 3], 50), 2.5)
        with self.assertRaises(ValueError):
            capacity.percentile([1, float("nan")], 50)
        with self.assertRaises(ValueError):
            capacity.percentile([1], 101)

        outcomes = [
            {"id": 0, "route": "python", "status": 200, "ok": True, "latency_ms": 1},
            {"id": 1, "route": "python", "status": 503, "ok": False,
             "error": "http_status", "latency_ms": 3},
            {"id": 2, "route": "static", "status": 200, "ok": True, "latency_ms": 2},
            {"id": 3, "route": "node", "status": None, "ok": False,
             "error": "timeout", "latency_ms": 10},
        ]
        summary = capacity.aggregate_outcomes(outcomes, 2)
        self.assertEqual(summary["successful"], 2)
        self.assertEqual(summary["failed"], 2)
        self.assertEqual(summary["goodput_rps"], 1.0)
        self.assertEqual(summary["routes"]["python"]["errors"], {"http_status": 1})
        self.assertEqual(summary["errors"], {"http_status": 1, "timeout": 1})
        self.assertEqual(summary["routes"]["node"]["latency_ms"]["p99"], 10.0)

    def test_cli_contract_rejects_tags_and_backend_mismatches_without_side_effects(self):
        digest = "a" * 64
        for image in (None, "ubuntu:latest", "sha256:short", "sha256:" + "B" * 64):
            with self.subTest(image=image), self.assertRaises(ValueError):
                capacity.validate_cli_values("docker", image, digest)
        with self.assertRaises(ValueError):
            capacity.validate_cli_values("native", "sha256:" + "a" * 64, digest)
        with self.assertRaises(ValueError):
            capacity.validate_cli_values("other", None, digest)
        with self.assertRaises(ValueError):
            capacity.validate_cli_values("native", None, "A" * 64)

        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            with self.assertRaises(ValueError):
                capacity.validate_results_dir(str(results / "missing"))
            symlink = results / "link"
            symlink.symlink_to(results, target_is_directory=True)
            with self.assertRaises(ValueError):
                capacity.validate_results_dir(symlink)

    def test_unmarked_guest_is_rejected_before_report_or_process_mutation(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(capacity, "require_lab", side_effect=SystemExit("unmarked")), \
                patch.object(capacity, "make_report") as make_report, \
                patch("subprocess.run") as run:
            with self.assertRaisesRegex(SystemExit, "unmarked"):
                capacity.collect("native", directory, payload_sha256="a" * 64)
            make_report.assert_not_called()
            run.assert_not_called()

    def test_strict_json_rejects_non_finite_values(self):
        with self.assertRaises(ValueError):
            capacity._report_json({"not_finite": float("inf")})
        self.assertEqual(json.loads(capacity._report_json({"ok": True})), {"ok": True})

    def test_transient_worker_checkpoint_gap_does_not_abort_readiness_poll(self):
        manager = object.__new__(capacity.ResidentManager)
        manager.entries = {"worker": {"fixture": {"port": None}, "pid": 123}}
        with patch.object(manager, "_record_state"), patch.object(
                manager, "_state", return_value={"active": True}), \
                patch.object(capacity, "worker_checkpoint",
                             side_effect=capacity.ResidentFailure("checkpoint not ready")):
            self.assertFalse(manager._probe_ready(manager.entries["worker"]))

    def test_image_probe_retains_bounded_stderr_on_exit_and_timeout(self):
        identifier = "c" * 64
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                manager = capacity.DockerResidents("a" * 32, "sha256:" + "b" * 64)
                failures = []

                def create(purpose, argv):
                    manager.owned.append(identifier)
                    return identifier

                def run_probe(*args, **kwargs):
                    self.assertEqual(args, ("container", "start", "--attach", identifier))
                    source = ("import sys,time; "
                              "print('PRIVATE_STDOUT=must-not-echo',flush=True); "
                              "sys.stderr.buffer.write(b'x'*1600+b'\\xff Permission denied\\n'); "
                              "sys.stderr.flush(); " + ("time.sleep(5)" if timeout else "sys.exit(2)"))
                    try:
                        return subprocess.run([sys.executable, "-B", "-c", source],
                                              capture_output=True, text=True, errors="replace",
                                              check=True, timeout=0.5)
                    except subprocess.SubprocessError as error:
                        failures.append(error)
                        raise

                with patch.object(manager, "_create", side_effect=create), \
                        patch.object(manager, "call", side_effect=run_probe), \
                        patch.object(manager, "_remove") as remove:
                    with self.assertRaises(capacity.CapacityError) as raised:
                        manager._image_json(["--fixture-digest", "python"])
                detail = capacity_guest.bounded_error(raised.exception)
                self.assertIn("Docker image identity probe", detail)
                self.assertIn("timed out" if timeout else "exited 2", detail)
                self.assertIn("Permission denied", detail)
                self.assertNotIn("PRIVATE_STDOUT", detail)
                self.assertLessEqual(len(detail), 512)
                if timeout:
                    self.assertIsInstance(failures[0].stderr, bytes)
                remove.assert_called_once_with(identifier)
                self.assertEqual(manager.owned, [])

    def test_inspect_failure_still_excludes_subprocess_output(self):
        identifier = "c" * 64
        manager = capacity.DockerResidents("a" * 32, "sha256:" + "b" * 64)
        manager.owned.append(identifier)
        error = subprocess.CalledProcessError(
            1, [*capacity.DOCKER, "container", "inspect", identifier],
            output="PRIVATE_ENV=must-not-echo", stderr="PRIVATE_STDERR=must-not-echo")
        with patch.object(manager, "_create", return_value=identifier), \
                patch.object(manager, "call", return_value=subprocess.CompletedProcess([], 0, "{}")), \
                patch.object(manager, "inspect_container", side_effect=error), \
                patch.object(manager, "_remove"):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                manager._image_json(["--fixture-digest", "python"])
        self.assertEqual(capacity_guest.bounded_error(raised.exception),
                         "guest subprocess failed: CalledProcessError")
        self.assertEqual(manager.owned, [])


class HealthSamplingTests(unittest.TestCase):
    """The per-sample health path reads cgroup/procfs and never shells out."""

    CGROUP = Path("/sys/fs/cgroup/test-resident")

    def _docker_entry(self):
        return {"name": "worker", "pid": 4321, "pid_start_time": "999",
                "container_id": "c" * 64, "cgroup": self.CGROUP,
                "memory_events": {"oom": 0, "oom_kill": 0}, "restart_count": 0}

    def _native_entry(self):
        return {"name": "worker", "pid": 4321, "pid_start_time": "999",
                "unit": "halvo-x.service", "invocation_id": "inv", "cgroup": self.CGROUP,
                "memory_events": {"oom": 0, "oom_kill": 0}, "restart_count": 0}

    @staticmethod
    def _no_subprocess(*args, **kwargs):
        raise AssertionError("health sampling must not shell out under load")

    def test_docker_health_sample_reads_cgroup_without_docker_inspect(self):
        manager = capacity.DockerResidents("a" * 32, "sha256:" + "b" * 64)
        with patch.object(capacity, "process_start", return_value="999"), \
                patch.object(manager, "_container_cgroup", return_value=self.CGROUP), \
                patch.object(capacity, "memory_events_at", return_value={"oom": 0, "oom_kill": 0}), \
                patch.object(manager, "inspect_container", side_effect=self._no_subprocess), \
                patch.object(manager, "call", side_effect=self._no_subprocess):
            state = manager._state(self._docker_entry())
        self.assertEqual(state, {"active": True, "pid": 4321,
                                 "restart_count": 0, "oom_killed": False})

    def test_docker_health_sample_detects_a_restarted_main_process(self):
        manager = capacity.DockerResidents("a" * 32, "sha256:" + "b" * 64)
        with patch.object(capacity, "process_start", return_value="1001"), \
                patch.object(manager, "_container_cgroup", return_value=self.CGROUP):
            with self.assertRaisesRegex(capacity.ResidentFailure, "restarted"):
                manager._state(self._docker_entry())

    def test_docker_health_sample_flags_a_cgroup_oom_kill(self):
        manager = capacity.DockerResidents("a" * 32, "sha256:" + "b" * 64)
        with patch.object(capacity, "process_start", return_value="999"), \
                patch.object(manager, "_container_cgroup", return_value=self.CGROUP), \
                patch.object(capacity, "memory_events_at", return_value={"oom": 2, "oom_kill": 1}):
            self.assertTrue(manager._state(self._docker_entry())["oom_killed"])

    def test_docker_health_sample_rejects_a_moved_cgroup(self):
        manager = capacity.DockerResidents("a" * 32, "sha256:" + "b" * 64)
        with patch.object(capacity, "process_start", return_value="999"), \
                patch.object(manager, "_container_cgroup",
                             return_value=Path("/sys/fs/cgroup/other")):
            with self.assertRaisesRegex(capacity.ResidentFailure, "cgroup changed"):
                manager._state(self._docker_entry())

    def test_native_health_sample_reads_cgroup_without_systemctl(self):
        manager = capacity.NativeResidents("a" * 32)
        with patch.object(capacity, "process_start", return_value="999"), \
                patch.object(capacity, "pid_unified_cgroup", return_value=self.CGROUP), \
                patch.object(capacity, "memory_events_at", return_value={"oom": 0, "oom_kill": 0}), \
                patch.object(capacity.probe, "call", side_effect=self._no_subprocess), \
                patch.object(capacity.probe, "properties", side_effect=self._no_subprocess):
            state = manager._state(self._native_entry())
        self.assertEqual(state, {"active": True, "pid": 4321, "restart_count": 0,
                                 "oom_killed": False, "invocation_id": "inv"})

    def test_native_health_sample_detects_a_restarted_main_process(self):
        manager = capacity.NativeResidents("a" * 32)
        with patch.object(capacity, "process_start", return_value="1001"), \
                patch.object(capacity, "pid_unified_cgroup", return_value=self.CGROUP):
            with self.assertRaisesRegex(capacity.ResidentFailure, "restarted"):
                manager._state(self._native_entry())


if __name__ == "__main__":
    unittest.main()
