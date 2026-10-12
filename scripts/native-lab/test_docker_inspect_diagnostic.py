#!/usr/bin/env python3
"""Offline receipt tests for the host Docker-inspect diagnostic adapter."""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "base"))
SPEC = importlib.util.spec_from_file_location("docker_inspect_diagnostic", ROOT / "docker_inspect_diagnostic.py")
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


PAYLOAD = "p" * 64
IMAGE = "sha256:" + "i" * 64
VM_ID = "vm-test"
FIXTURES = ("python", "static", "node", "worker")
CONTAINERS = {name: (str(index + 1) * 64) for index, name in enumerate(FIXTURES)}


def fixture_report():
    residents = {}
    startup = {}
    ids = {}
    for index, name in enumerate(FIXTURES, 1):
        container_id = CONTAINERS[name]
        ids[name] = hashlib.sha256(container_id.encode("ascii")).hexdigest()
        residents[name] = {"container_id": container_id, "pid": 1000 + index,
                           "pid_start_time": 2000 + index}
        startup[name] = {"purpose": name, "pid": 1000 + index,
                         "pid_start_time": 2000 + index,
                         "pid_namespace": "pid:[4026531836]",
                         "container_id_sha256": ids[name]}

    initial = {"residents": residents, "errors": []}
    final = copy.deepcopy(initial)
    final["cleanup"] = {"passed": True}
    cleanup_reply = {"ok": True, "cleanup": {"passed": True, "errors": []}}
    trace = {
        "scope": "docker-health-probe-diagnostic",
        "phase0_complete": False,
        "capacity_evidence": False,
        "profile": {"duration_seconds": 200.0, "interval_seconds": 5.0,
                     "timeout_seconds": 5.0},
        "fixtures": startup,
        "startup_identity_complete": True,
        "startup_fixture_count": len(FIXTURES),
        "samples": [{"operation": "container_inspect", "category": "timeout",
                     "fixture": "python", "elapsed_seconds": 5.0}],
        "sample_count": 1,
        "diagnostic_completed": True,
        "aborted": True,
        "error": None,
        "observation_error": {"operation": "container_inspect", "category": "timeout",
                               "fixture": "python", "elapsed_seconds": 5.0},
    }
    return {
        "scope": "docker-health-probe-diagnostic", "production": False,
        "backend": "docker", "image": IMAGE, "payload_sha256": PAYLOAD,
        "phase0_complete": False, "capacity_evidence": False,
        "collection_valid": False, "passed": True, "diagnostic_completed": True,
        "errors": [], "guest_initial_report": initial, "guest_final_report": final,
        "cleanup": {"passed": True, "control": {"passed": True, "reply": cleanup_reply},
                     "clients": {"passed": True, "errors": []},
                     "forward": {"passed": True, "errors": []}},
        "load": {"rate_per_second": 16, "window_seconds": 180, "drain_seconds": 40,
                 "scheduled": 2880, "dispatched": 2880, "outcomes": 2880,
                 "pending_at_end": 0, "errors": [], "capacity_evidence": False},
        "inspect_trace": trace,
        "container_ids_sha256": ids,
    }


class DiagnosticReceiptTests(unittest.TestCase):
    def call(self, report):
        with mock.patch.object(diagnostic.external, "validate_guest_report"), \
                mock.patch.object(diagnostic.external, "_validate_cleanup"):
            return diagnostic.validate_diagnostic(report, PAYLOAD, IMAGE, VM_ID)

    def test_startup_identity_plus_one_timeout_is_accepted(self):
        self.assertTrue(self.call(fixture_report()))

    def test_incomplete_startup_identity_is_rejected(self):
        report = fixture_report()
        del report["inspect_trace"]["fixtures"]["worker"]
        with self.assertRaises(AssertionError):
            self.call(report)

    def test_flags_and_cleanup_must_be_strictly_false_and_successful(self):
        report = fixture_report()
        report["inspect_trace"]["capacity_evidence"] = 0
        with self.assertRaises(AssertionError):
            self.call(report)

        report = fixture_report()
        report["cleanup"]["clients"]["passed"] = False
        with self.assertRaises(AssertionError):
            self.call(report)

    def test_wrong_profile_is_rejected(self):
        report = fixture_report()
        report["inspect_trace"]["profile"]["timeout_seconds"] = 4.0
        with self.assertRaises(AssertionError):
            self.call(report)


class ReadinessGateTests(unittest.TestCase):
    def test_load_is_called_only_after_valid_readiness(self):
        events = []
        tracer = mock.Mock()
        pool = mock.Mock()

        def wait(process):
            events.append("readiness")
            return "ready"

        def load(value):
            self.assertIs(value, pool)
            self.assertEqual(events, ["readiness"])
            events.append("load")
            return {"capacity_evidence": False}

        with mock.patch.object(diagnostic, "wait_for_readiness", side_effect=wait), \
                mock.patch.object(diagnostic, "run_load", side_effect=load) as run:
            status, result = diagnostic.run_load_after_readiness(tracer, pool)

        self.assertEqual(status, "ready")
        self.assertEqual(result, {"capacity_evidence": False})
        run.assert_called_once_with(pool)
        self.assertEqual(events, ["readiness", "load"])

    def test_missing_or_invalid_readiness_prevents_load(self):
        for output, status in (("", "missing"), ("not-json\n", "invalid")):
            with self.subTest(status=status), \
                    mock.patch.object(diagnostic, "run_load") as run:
                process = mock.Mock(stdout=io.StringIO(output))
                actual, result = diagnostic.run_load_after_readiness(process, mock.Mock())
            self.assertEqual(actual, status)
            self.assertIsNone(result)
            run.assert_not_called()

        with mock.patch.object(diagnostic, "wait_for_readiness", return_value="timeout"), \
                mock.patch.object(diagnostic, "run_load") as run:
            actual, result = diagnostic.run_load_after_readiness(mock.Mock(), mock.Mock())
        self.assertEqual(actual, "timeout")
        self.assertIsNone(result)
        run.assert_not_called()

    def test_readiness_marker_is_strict_and_sanitized(self):
        self.assertTrue(diagnostic.validate_readiness_marker(
            json.dumps(diagnostic.READINESS_MARKER)))
        self.assertFalse(diagnostic.validate_readiness_marker(
            '{"event":"startup_ready","startup_fixture_count":4}'))
        self.assertFalse(diagnostic.validate_readiness_marker(
            json.dumps({**diagnostic.READINESS_MARKER, "container_id": "private"})))
        self.assertFalse(diagnostic.validate_readiness_marker(
            json.dumps({**diagnostic.READINESS_MARKER, "startup_fixture_count": 4.0})))

    def test_buffered_marker_is_read_even_if_ssh_process_already_exited(self):
        read_fd, write_fd = os.pipe()
        try:
            marker = json.dumps(diagnostic.READINESS_MARKER).encode() + b"\n"
            os.write(write_fd, marker)
        finally:
            os.close(write_fd)
        try:
            process = mock.Mock(stdout=os.fdopen(read_fd, "rb", buffering=0))
            process.poll.return_value = 0
            self.assertEqual(diagnostic.wait_for_readiness(process, timeout=1.0), "ready")
        finally:
            process.stdout.close()

    def test_partial_marker_cannot_extend_readiness_deadline(self):
        marker = json.dumps(diagnostic.READINESS_MARKER) + "\n"
        process = subprocess.Popen([sys.executable, "-c",
            "import sys,time; sys.stdout.write(sys.argv[1][:1]); sys.stdout.flush(); "
            "time.sleep(0.5); sys.stdout.write(sys.argv[1][1:]); sys.stdout.flush()", marker],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 2)[0])
            self.assertEqual(diagnostic.wait_for_readiness(process, timeout=0.1), "timeout")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            process.stdout.close()

    def test_final_trace_larger_than_pipe_is_drained_before_waiting(self):
        fixture = fixture_report()
        trace = fixture["inspect_trace"]
        trace.update(samples=[{"operation": "container_inspect", "category": "ok",
            "fixture": "python", "elapsed_seconds": 0.1, "pid": 1001,
            "pid_start_time": 2001, "pid_namespace": "pid:[4026531836]"}] * 160,
            sample_count=160, aborted=False, observation_error=None)
        encoded = json.dumps(trace)
        self.assertGreater(len(encoded), 4096)
        self.assertLessEqual(len(encoded), 64 * 1024)
        process = subprocess.Popen([sys.executable, "-c",
            "import sys; print(sys.argv[1], flush=True); print(sys.argv[2], flush=True)",
            json.dumps(diagnostic.READINESS_MARKER), encoded], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pipesize=4096)
        channel = mock.Mock()
        channel.start.return_value = {"report": fixture["guest_initial_report"], "endpoints": {}}
        channel.finish.return_value = fixture["cleanup"]["control"]
        forward, pool = mock.Mock(), mock.Mock()
        forward.close.return_value = pool.close.return_value = {"passed": True, "errors": []}
        try:
            with tempfile.TemporaryDirectory() as directory:
                lab = Path(directory)
                (lab / "vm-id").write_text(VM_ID)
                output = lab / "diagnostic.json"
                argv = ["diagnostic", "--backend", "docker", "--lab-dir", str(lab),
                        "--ssh-port", "2222", "--qemu-pid", "1", "--payload-sha256", PAYLOAD,
                        "--image", "sha256:da38db8b3347ab4f61eaa54bd09cd6601fb8f42a31a43ad1767d25262dd9e2f8",
                        "--mode", "diagnostic", "--output", str(output)]
                with mock.patch.object(sys, "argv", argv), \
                        mock.patch.multiple(diagnostic.external, verify_qemu=mock.Mock(),
                            _affinity=mock.Mock(return_value=[2, 3]),
                            validate_guest_report=mock.Mock(), _validate_cleanup=mock.Mock(),
                            ControlChannel=mock.Mock(return_value=channel),
                            ForwardProcess=mock.Mock(return_value=forward),
                            ExternalManager=mock.Mock(), ExternalPool=mock.Mock(return_value=pool)), \
                        mock.patch.object(diagnostic, "start_tracer", return_value=process), \
                        mock.patch.object(diagnostic, "run_load", return_value=fixture["load"]), \
                        mock.patch.object(diagnostic, "INSPECT_SECONDS", -89.5):
                    # Keep the existing +90-second wait formula to a half-second
                    # offline deadline; no guest or workload is invoked.
                    status = diagnostic.main()
                report = json.loads(output.read_text())
                self.assertEqual(status, 0, report["errors"])
                self.assertEqual(report["inspect_trace"], trace)
                self.assertFalse(report["capacity_evidence"])
                self.assertTrue(report["cleanup"]["passed"])
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            process.stdout.close()


if __name__ == "__main__":
    unittest.main()
