"""Docker benchmark guards, measured lifecycle and strictly owned cleanup."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchmark_docker as docker

ID = "a" * 64
IMAGE = "sha256:" + "b" * 64
RUN = "c" * 32


class DockerBoundaryTests(unittest.TestCase):
    def test_fixed_launch_diagnostics_are_bounded_and_inspect_output_stays_private(self):
        launch = subprocess.CalledProcessError(1, [*docker.DOCKER, "container", "start", "--attach", ID],
                                               output="x" * 10_000, stderr="ModuleNotFoundError: missing")
        detail = docker.describe_error(launch)
        self.assertIn("ModuleNotFoundError: missing", detail)
        self.assertLess(len(detail), 4300)
        inspect = subprocess.CalledProcessError(1, [*docker.DOCKER, "container", "inspect", ID],
                                                output="PRIVATE_ENV=must-not-echo", stderr="private")
        self.assertNotIn("PRIVATE_ENV", docker.describe_error(inspect))
        self.assertNotIn("private", docker.describe_error(inspect))

    def test_image_tags_are_rejected_before_calling_docker(self):
        with patch.object(docker, "call") as call:
            for image in ("ubuntu:latest", "sha256:short", "b" * 64, "sha256:" + "B" * 64):
                with self.subTest(image=image), self.assertRaises(ValueError):
                    docker.validate_image(image)
            call.assert_not_called()

    def test_automatic_image_volumes_are_refused(self):
        result = subprocess.CompletedProcess([], 0, json.dumps([
            {"Id": IMAGE, "Config": {"Volumes": {"/data": {}}}},
        ]))
        with patch.object(docker, "call", return_value=result) as call:
            with self.assertRaisesRegex(ValueError, "automatic volumes"):
                docker.validate_image(IMAGE)
            self.assertEqual(call.call_args.args, (*docker.DOCKER, "image", "inspect", IMAGE))

    def test_image_environment_cannot_add_unreported_runtime_settings(self):
        for environment in (["NODE_OPTIONS=--jitless"], ["PATH=/bin", "PATH=/other"],
                            ["PATH"], ["=missing-key"], [None], "PATH=/bin", "", {}, False, 0):
            result = subprocess.CompletedProcess([], 0, json.dumps([
                {"Id": IMAGE, "Config": {"Env": environment}},
            ]))
            with self.subTest(environment=environment), patch.object(docker, "call", return_value=result):
                with self.assertRaises(ValueError):
                    docker.validate_image(IMAGE)
        for environment in (None, [], ["PATH=/old", "HOME=/old", "LANG=C"]):
            result = subprocess.CompletedProcess([], 0, json.dumps([
                {"Id": IMAGE, "Config": {"Env": environment}},
            ]))
            with self.subTest(environment=environment), patch.object(docker, "call", return_value=result):
                docker.validate_image(IMAGE)

    def test_creation_is_local_bounded_readonly_and_not_started_implicitly(self):
        fixture = docker.benchmark.FIXTURES["node"]
        owned = []
        with patch.object(docker, "call", return_value=subprocess.CompletedProcess([], 0, ID + "\n")) as call:
            self.assertEqual(docker.create_container(IMAGE, RUN, "node", fixture["argv"], owned), ID)
        args = call.call_args.args
        self.assertEqual(args[:5], (*docker.DOCKER, "container", "create"))
        for flag, value in (("--pull", "never"), ("--network", "none"), ("--user", "1000:1000"),
                            ("--memory", "256m"), ("--memory-swap", "256m"),
                            ("--cpus", "0.5"), ("--pids-limit", "128"),
                            ("--label", f"{docker.LABEL}={RUN}"),
                            ("--entrypoint", fixture["argv"][0])):
            self.assertEqual(args[args.index(flag) + 1], value)
        for flag in ("--read-only", "--no-healthcheck"):
            self.assertIn(flag, args)
        self.assertIn("compress=false", args, "Docker local logs cannot compress with max-file=1")
        for forbidden in ("--privileged", "--volume", "--mount", "--publish", "pull", "build"):
            self.assertNotIn(forbidden, args)
        self.assertEqual(owned, [ID])

    def test_cleanup_requires_the_exact_run_label(self):
        for label in (None, "another-run"):
            state = {"Config": {"Labels": {docker.LABEL: label}}}
            with self.subTest(label=label), patch.object(docker, "inspect_container", return_value=state), \
                    patch.object(docker, "call") as call:
                with self.assertRaisesRegex(RuntimeError, "ownership label"):
                    docker.remove_owned(ID, RUN)
                call.assert_not_called()
        with patch.object(docker, "inspect_container", return_value={"Config": {"Labels": {docker.LABEL: RUN}}}), \
                patch.object(docker, "call") as call:
            docker.remove_owned(ID, RUN)
            call.assert_called_once_with(*docker.DOCKER, "container", "rm", "--force", ID)

    def test_cgroup_must_belong_to_the_full_container_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            group = root / f"docker-{ID}.scope"
            group.mkdir()
            with patch.object(docker, "CGROUP_ROOT", root):
                with patch.object(Path, "read_text", return_value=f"0::/docker-{ID}.scope\n"):
                    self.assertEqual(docker.container_cgroup(123, ID), group)
                for text in ("0::/\n", "0::/other-container\n", f"0::/../docker-{ID}.scope\n"):
                    with self.subTest(text=text), patch.object(Path, "read_text", return_value=text):
                        with self.assertRaises(RuntimeError):
                            docker.container_cgroup(123, ID)


class MeasuredLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.owned = []
        def create(image, run_id, name, argv, owned):
            owned.append(ID)
            return ID
        self.patches = [
            patch.object(docker, "create_container", side_effect=create),
            patch.object(docker, "call"),
            patch.object(docker, "inspect_container", return_value={"State": {"Pid": 123}}),
            patch.object(docker, "process_identity", return_value="456"),
            patch.object(docker, "container_cgroup", return_value=Path("/fixture-cgroup")),
            patch.object(docker, "limits_at", return_value=dict(docker.LIMITS)),
            patch.object(docker, "ready"),
            patch.object(docker, "check_running"),
            patch.object(docker.time, "sleep"),
            patch.object(docker, "cgroup_empty", return_value=True),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def measure(self, name="node"):
        return docker.measure_case(name, docker.benchmark.FIXTURES[name], IMAGE, RUN,
                                   {"version": "fixture"}, self.owned)

    def test_sampling_failure_still_removes_only_the_created_container(self):
        with patch.object(docker.benchmark, "sample_cgroup", side_effect=OSError("counter unavailable")), \
                patch.object(docker, "remove_owned") as remove:
            result = self.measure()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_passed"])
        self.assertIn("counter unavailable", result["error"])
        remove.assert_called_once_with(ID, RUN)
        self.assertEqual(self.owned, [])

    def test_limit_mismatch_cannot_produce_samples(self):
        with patch.object(docker, "limits_at", return_value={"memory.max": "max"}), \
                patch.object(docker.benchmark, "sample_cgroup") as sample, \
                patch.object(docker, "remove_owned"):
            result = self.measure()
        self.assertFalse(result["passed"])
        sample.assert_not_called()

    def test_cleanup_failure_invalidates_a_completed_sample_window(self):
        with patch.object(docker.benchmark, "sample_cgroup", side_effect=lambda group: {
                "memory_current_bytes": 10, "memory_peak_bytes": 20}), \
                patch.object(docker, "remove_owned", side_effect=RuntimeError("ownership label missing")):
            result = self.measure()
        self.assertEqual(len(result["samples"]), docker.benchmark.WINDOW["sample_count"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["cleanup_passed"])
        self.assertEqual(self.owned, [ID], "failed cleanup remains available for the outer retry")


class ImageVerificationTests(unittest.TestCase):
    def test_mismatched_image_fixture_cannot_start_a_workload(self):
        def helper(image, run_id, purpose, args, owned):
            return {"kernel": os.uname().release} if args == ["--environment"] else "wrong-digest"
        with patch.object(docker.os, "geteuid", return_value=0), \
                patch.object(docker, "validate_image"), \
                patch.object(docker, "image_json", side_effect=helper), \
                patch.object(docker, "measure_case") as measure:
            report = docker.collect(IMAGE)
        self.assertFalse(report["passed"])
        self.assertIn("Image bytes do not match", report["error"])
        measure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
