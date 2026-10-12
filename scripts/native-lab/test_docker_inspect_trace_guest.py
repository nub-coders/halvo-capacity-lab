#!/usr/bin/env python3
"""Offline tests for the bounded guest Docker inspect tracer."""

import io
import hashlib
import json
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest import mock

import docker_inspect_trace_guest as tracer


IDS = {name: (str(index + 1) * 64) for index, name in enumerate(tracer.FIXTURES)}
ARGS = ["--duration", "200", "--interval", "5", "--timeout", "5"]
for _name in tracer.FIXTURES:
    ARGS += ["--id", f"{_name}={IDS[_name]}"]


class CaptureStdout:
    def __init__(self):
        self.buffer = io.BytesIO()

    def flush(self):
        pass


def report_from(capture):
    lines = capture.buffer.getvalue().decode("utf-8").splitlines()
    return json.loads(lines[-1])


def readiness_from(capture):
    lines = capture.buffer.getvalue().decode("utf-8").splitlines()
    return json.loads(lines[0])


def inspect_state(fixture, identifier, pid=1234):
    return [{
        "Id": identifier,
        "Name": f"/halvo-capacity-" + "a" * 32 + f"-{fixture}",
        "Config": {"Labels": {"halvo.native-lab-capacity": "a" * 32}},
        "State": {"Running": True, "Pid": pid},
    }]


class TracerTests(unittest.TestCase):
    def assert_safe_schema(self, report):
        self.assertEqual(set(report), {
            "scope", "phase0_complete", "capacity_evidence", "profile", "fixtures",
            "startup_identity_complete", "startup_fixture_count", "samples",
            "sample_count", "diagnostic_completed", "aborted", "error", "observation_error",
        })
        self.assertEqual(report["profile"], {"duration_seconds": 200.0,
                                            "interval_seconds": 5.0,
                                            "timeout_seconds": 5.0})
        self.assertEqual(report["scope"], tracer.SCOPE)
        self.assertIs(report["phase0_complete"], False)
        self.assertIs(report["capacity_evidence"], False)
        self.assertEqual(report["startup_fixture_count"], len(report["fixtures"]))
        for fixture, row in report["fixtures"].items():
            self.assertIn(fixture, tracer.FIXTURES)
            self.assertEqual(set(row), {"purpose", "pid", "pid_start_time",
                                        "pid_namespace", "container_id_sha256"})
            self.assertEqual(row["purpose"], fixture)
            self.assertEqual(row["container_id_sha256"],
                             hashlib.sha256(IDS[fixture].encode("ascii")).hexdigest())
        self.assertEqual(report["sample_count"], len(report["samples"]))
        for row in report["samples"]:
            keys = {"operation", "category", "fixture", "elapsed_seconds"}
            if row["category"] == "ok":
                keys |= {"pid", "pid_start_time", "pid_namespace"}
            elif "returncode" in row:
                keys.add("returncode")
            self.assertEqual(set(row), keys)
            self.assertEqual(row["operation"], "container_inspect")
            self.assertIn(row["fixture"], tracer.FIXTURES)
            self.assertGreaterEqual(row["elapsed_seconds"], 0)
        for key in ("error", "observation_error"):
            if report[key] is not None:
                keys = {"operation", "category", "fixture", "elapsed_seconds"}
                if "returncode" in report[key]:
                    keys.add("returncode")
                self.assertEqual(set(report[key]), keys)
                self.assertGreaterEqual(report[key]["elapsed_seconds"], 0)

    def run_main(self, fake_run, argv=ARGS, guard=None):
        capture = CaptureStdout()
        identity = {"pid": 1234, "pid_start_time": 77,
                    "pid_namespace": "pid:[4026531836]", "cgroup_leaf": IDS["python"]}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(tracer, "require_lab", guard or
                                                  mock.Mock(return_value="qemu")))
            stack.enter_context(mock.patch.object(tracer.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(tracer.signal, "signal"))
            stack.enter_context(mock.patch.object(tracer.signal, "setitimer"))
            docker = stack.enter_context(mock.patch.object(tracer.subprocess, "run",
                                                           side_effect=fake_run))
            stack.enter_context(mock.patch.object(tracer, "_pid_identity", return_value=identity))
            stack.enter_context(mock.patch.object(tracer.sys, "stdout", capture))
            result = tracer.main(argv)
        report = report_from(capture)
        self.assert_safe_schema(report)
        self.assertLessEqual(len(capture.buffer.getvalue()), tracer.MAX_OUTPUT_BYTES)
        return result, report, docker

    def test_invalid_fixed_profile_and_ids_are_rejected(self):
        with self.assertRaises(tracer.InputError):
            tracer.parse_args([*ARGS[:2], "201", *ARGS[2:]])
        with self.assertRaises(tracer.InputError):
            tracer.parse_args(ARGS[:-2] + ["--id", "python=" + "g" * 64])
        with self.assertRaises(tracer.InputError):
            tracer.parse_args(ARGS + ["--id", "python=" + IDS["python"]])

    def test_guard_runs_before_docker_or_proc_actions(self):
        capture = CaptureStdout()
        with mock.patch.object(tracer, "require_lab", side_effect=SystemExit("guard")) as guard, \
                mock.patch.object(tracer.subprocess, "run") as docker, \
                mock.patch.object(tracer, "_pid_identity") as proc, \
                mock.patch.object(tracer.sys, "stdout", capture):
            self.assertEqual(tracer.main(ARGS), 1)
        guard.assert_called_once_with()
        docker.assert_not_called()
        proc.assert_not_called()
        report = report_from(capture)
        self.assert_safe_schema(report)
        self.assertEqual(report["error"]["category"], "guard")
        self.assertFalse(report["startup_identity_complete"])
        self.assertEqual(report["startup_fixture_count"], 0)
        self.assertIsNone(report["observation_error"])

    def test_guard_rejection_is_sanitized_json_when_guard_returns_wrong_vm(self):
        capture = CaptureStdout()
        with mock.patch.object(tracer, "require_lab", return_value="systemd-nspawn"), \
                mock.patch.object(tracer.os, "geteuid", return_value=0), \
                mock.patch.object(tracer.sys, "stdout", capture):
            self.assertEqual(tracer.main(ARGS), 1)
        report = report_from(capture)
        self.assert_safe_schema(report)
        self.assertEqual(report["error"]["category"], "guard")
        self.assertEqual(report["scope"], tracer.SCOPE)
        self.assertFalse(report["phase0_complete"])
        self.assertFalse(report["capacity_evidence"])

    def test_inspect_uses_only_explicit_container_command_and_exact_timeout(self):
        result = SimpleNamespace(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch.object(tracer.subprocess, "run", return_value=result) as run:
            self.assertEqual(tracer._inspect(IDS["python"], 5), [])
        args, kwargs = run.call_args
        self.assertEqual(args[0], [*tracer.DOCKER, IDS["python"]])
        self.assertTrue(kwargs["check"])
        self.assertTrue(kwargs["capture_output"])
        self.assertEqual(kwargs["timeout"], 5)
        self.assertNotIn("ls", args[0])
        self.assertNotIn("build", args[0])
        self.assertNotIn("prune", args[0])

    def test_first_error_is_persisted_and_stops_sampling(self):
        calls = []

        def fake_run(command, **kwargs):
            fixture = next(name for name in tracer.FIXTURES if command[-1] == IDS[name])
            calls.append(fixture)
            if len(calls) == 6:
                raise tracer.subprocess.TimeoutExpired(command, 5, output=b"private", stderr=b"secret")
            return SimpleNamespace(stdout=json.dumps(inspect_state(fixture, IDS[fixture])).encode(),
                                   stderr=b"", returncode=0)

        identity = {"pid": 1234, "pid_start_time": 77,
                    "pid_namespace": "pid:[4026531836]", "cgroup_leaf": IDS["python"]}
        report = tracer._safe_report()
        state = {"stop": False, "category": None}
        with mock.patch.object(tracer.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(tracer, "_pid_identity", return_value=identity), \
                mock.patch.object(tracer, "_emit_readiness"):
            with self.assertRaises(tracer.TraceStop) as stopped:
                tracer._run_trace(report, IDS, 0.0, state)
        self.assertEqual(stopped.exception.category, "timeout")
        self.assertEqual(calls, ["python", "static", "node", "worker", "python", "static"])
        self.assertEqual(report["samples"][-1]["category"], "timeout")
        self.assertEqual(report["samples"][-1]["fixture"], "static")
        self.assertEqual(len(report["samples"]), 2)
        self.assertTrue(report["startup_identity_complete"])
        self.assertEqual(report["startup_fixture_count"], 4)
        self.assert_safe_schema(report)
        serialized = json.dumps(report)
        self.assertNotIn("private", serialized)
        self.assertNotIn("secret", serialized)

    def test_sample_and_output_bounds_are_enforced(self):
        report = tracer._safe_report()
        for number in range(tracer.MAX_SAMPLES + 30):
            tracer._record(report, {"operation": "container_inspect", "category": "ok",
                                    "fixture": "python", "elapsed_seconds": number / 1000,
                                    "pid": 1234, "pid_start_time": 77,
                                    "pid_namespace": "pid:[4026531836]"})
        self.assertEqual(len(report["samples"]), tracer.MAX_SAMPLES)
        self.assertEqual(report["sample_count"], tracer.MAX_SAMPLES)

        report["fixtures"] = {"private": "x" * (tracer.MAX_OUTPUT_BYTES * 2)}
        capture = CaptureStdout()
        with mock.patch.object(tracer.sys, "stdout", capture):
            tracer._emit(report)
        self.assertLessEqual(len(capture.buffer.getvalue()), tracer.MAX_OUTPUT_BYTES)
        bounded = report_from(capture)
        self.assert_safe_schema(bounded)
        self.assertEqual(bounded["error"]["category"], "output_limit")
        self.assertEqual(bounded["fixtures"], {})

    def test_all_startup_identities_precede_first_sample_timeout(self):
        calls = []

        def fake_run(command, **kwargs):
            fixture = next(name for name in tracer.FIXTURES if command[-1] == IDS[name])
            self.assertEqual(kwargs["timeout"], 5.0)
            calls.append(fixture)
            if len(calls) == 5:
                raise tracer.subprocess.TimeoutExpired(["PRIVATE_ARGV"], 5,
                                                        output=b"PRIVATE_OUTPUT", stderr=b"PRIVATE_STDERR")
            return SimpleNamespace(stdout=json.dumps(inspect_state(fixture, IDS[fixture])).encode(),
                                   stderr=b"PRIVATE_STDERR", returncode=0)

        result, report, docker = self.run_main(fake_run)
        self.assertEqual(result, 0)
        self.assertEqual(calls, [*tracer.FIXTURES, "python"])
        self.assertEqual(docker.call_count, 5)
        self.assertEqual(set(report["fixtures"]), set(tracer.FIXTURES))
        self.assertTrue(report["startup_identity_complete"])
        self.assertEqual(report["startup_fixture_count"], 4)
        self.assertEqual(report["sample_count"], 1)
        self.assertEqual(report["samples"][0]["category"], "timeout")
        self.assertEqual(report["samples"][0]["fixture"], "python")
        self.assertTrue(report["diagnostic_completed"])
        self.assertTrue(report["aborted"])
        self.assertIsNone(report["error"])
        self.assertEqual(report["observation_error"]["category"], "timeout")
        self.assertEqual(report["observation_error"]["fixture"], "python")
        self.assertEqual(report["observation_error"]["operation"], "container_inspect")
        for secret in ("PRIVATE_ARGV", "PRIVATE_OUTPUT", "PRIVATE_STDERR", *IDS.values()):
            self.assertNotIn(secret, json.dumps(report))

    def test_startup_failure_rejects_even_diagnostic_error_categories(self):
        for category in ("fixture_identity", "pid_identity", "timeout", "docker_error",
                         "invalid_response", "response_too_large"):
            with self.subTest(category=category):
                calls = []

                def fake_run(command, **kwargs):
                    fixture = next(name for name in tracer.FIXTURES if command[-1] == IDS[name])
                    calls.append(fixture)
                    if len(calls) == 3:
                        raise tracer.TraceStop(category)
                    return SimpleNamespace(stdout=json.dumps(inspect_state(fixture, IDS[fixture])).encode(),
                                           stderr=b"", returncode=0)

                result, report, _ = self.run_main(fake_run)
                self.assertEqual(result, 1)
                self.assertEqual(calls, ["python", "static", "node"])
                self.assertFalse(report["startup_identity_complete"])
                self.assertEqual(report["startup_fixture_count"], 2)
                self.assertEqual(report["samples"], [])
                self.assertFalse(report["diagnostic_completed"])
                self.assertIsNone(report["observation_error"])
                self.assertEqual(report["error"]["category"], category)
                self.assertEqual(report["error"]["fixture"], "node")
                self.assertEqual(report["error"]["operation"], "startup_identity")

    def test_real_startup_identity_mismatch_is_rejected(self):
        calls = []

        def fake_run(command, **kwargs):
            fixture = next(name for name in tracer.FIXTURES if command[-1] == IDS[name])
            calls.append(fixture)
            value = inspect_state(fixture, IDS[fixture])
            if fixture == "static":
                value[0]["Name"] = "/PRIVATE_WRONG_NAME"
            return SimpleNamespace(stdout=json.dumps(value).encode(), stderr=b"PRIVATE_STDERR", returncode=0)

        result, report, _ = self.run_main(fake_run)
        self.assertEqual(result, 1)
        self.assertEqual(calls, ["python", "static"])
        self.assertEqual(report["startup_fixture_count"], 1)
        self.assertFalse(report["startup_identity_complete"])
        self.assertEqual(report["error"]["category"], "fixture_identity")
        self.assertEqual(report["samples"], [])
        self.assertIsNone(report["observation_error"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_sampling_docker_error_is_a_sanitized_observation(self):
        calls = []

        def fake_run(command, **kwargs):
            fixture = next(name for name in tracer.FIXTURES if command[-1] == IDS[name])
            calls.append(fixture)
            if len(calls) == 5:
                raise tracer.subprocess.CalledProcessError(17, ["PRIVATE_ARGV"],
                                                           output=b"PRIVATE_OUTPUT", stderr=b"PRIVATE_STDERR")
            return SimpleNamespace(stdout=json.dumps(inspect_state(fixture, IDS[fixture])).encode(),
                                   stderr=b"", returncode=0)

        result, report, _ = self.run_main(fake_run)
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 5)
        self.assertTrue(report["diagnostic_completed"])
        self.assertIsNone(report["error"])
        self.assertEqual(report["observation_error"]["category"], "docker_error")
        self.assertEqual(report["observation_error"]["returncode"], 17)
        self.assertEqual(report["samples"][0]["returncode"], 17)
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_sampling_protocol_and_identity_failures_remain_rejected(self):
        for category in ("fixture_identity", "pid_identity", "invalid_response", "response_too_large"):
            with self.subTest(category=category):
                calls = []

                def fake_run(command, **kwargs):
                    fixture = next(name for name in tracer.FIXTURES if command[-1] == IDS[name])
                    calls.append(fixture)
                    if len(calls) == 5:
                        raise tracer.TraceStop(category)
                    return SimpleNamespace(stdout=json.dumps(inspect_state(fixture, IDS[fixture])).encode(),
                                           stderr=b"", returncode=0)

                result, report, _ = self.run_main(fake_run)
                self.assertEqual(result, 1)
                self.assertTrue(report["startup_identity_complete"])
                self.assertFalse(report["diagnostic_completed"])
                self.assertIsNone(report["observation_error"])
                self.assertEqual(report["error"]["category"], category)
                self.assertEqual(report["sample_count"], 1)

    def test_invalid_argv_is_sanitized_and_precedes_guard(self):
        guard = mock.Mock(return_value="qemu")
        result, report, docker = self.run_main(None, [*ARGS, "PRIVATE_ARGV"], guard)
        self.assertEqual(result, 2)
        guard.assert_not_called()
        docker.assert_not_called()
        self.assertEqual(report["error"]["category"], "invalid_input")
        self.assertIsNone(report["observation_error"])
        self.assertNotIn("PRIVATE_ARGV", json.dumps(report))

    def test_complete_profile_keeps_200_second_window_and_5_second_cycles(self):
        clock = [0.0]
        deadlines = []
        inspection_calls = []
        report = tracer._safe_report()
        identity = {"pid": 1234, "pid_start_time": 77,
                    "pid_namespace": "pid:[4026531836]", "cgroup_leaf": IDS["python"]}

        def inspect(identifier, timeout):
            self.assertEqual(timeout, 5.0)
            fixture = next(name for name in tracer.FIXTURES if identifier == IDS[name])
            inspection_calls.append(fixture)
            return inspect_state(fixture, identifier)

        def emit_readiness():
            self.assertEqual(inspection_calls, list(tracer.FIXTURES))

        def sleep_until(deadline, state):
            deadlines.append(deadline)
            clock[0] = deadline

        with mock.patch.object(tracer.time, "monotonic", side_effect=lambda: clock[0]), \
                 mock.patch.object(tracer, "_sleep_until", side_effect=sleep_until), \
                 mock.patch.object(tracer, "_inspect", side_effect=inspect) as docker, \
                 mock.patch.object(tracer, "_emit_readiness", side_effect=emit_readiness) as readiness, \
                 mock.patch.object(tracer, "_pid_identity", return_value=identity):
            tracer._run_trace(report, IDS, 0.0, {"stop": False, "category": None})
        self.assert_safe_schema(report)
        self.assertEqual(deadlines, list(range(0, 201, 5)))
        self.assertEqual(docker.call_count, 164)
        self.assertEqual(report["sample_count"], 160)
        self.assertTrue(report["diagnostic_completed"])
        self.assertTrue(report["startup_identity_complete"])
        readiness.assert_called_once_with()

    def test_timeout_and_called_process_errors_do_not_leak_exception_data(self):
        timeout = tracer.subprocess.TimeoutExpired(["docker", "TOP_SECRET"], 5,
                                                    output=b"PRIVATE", stderr=b"TOKEN")
        with mock.patch.object(tracer.subprocess, "run", side_effect=timeout) as timeout_run:
            with self.assertRaises(tracer.TraceStop) as stopped:
                tracer._inspect(IDS["python"], 5)
        timeout_run.assert_called_once()
        self.assertEqual(stopped.exception.category, "timeout")
        self.assertNotIn("PRIVATE", str(stopped.exception))
        self.assertNotIn("TOKEN", str(stopped.exception))

        failed = tracer.subprocess.CalledProcessError(17, ["docker", "PRIVATE"],
                                                       output=b"PRIVATE", stderr=b"TOKEN")
        with mock.patch.object(tracer.subprocess, "run", side_effect=failed) as failed_run:
            with self.assertRaises(tracer.TraceStop) as stopped:
                tracer._inspect(IDS["python"], 5)
        failed_run.assert_called_once()
        self.assertEqual(stopped.exception.category, "docker_error")
        self.assertNotIn("PRIVATE", str(stopped.exception))
        self.assertNotIn("TOKEN", str(stopped.exception))


if __name__ == "__main__":
    unittest.main()
