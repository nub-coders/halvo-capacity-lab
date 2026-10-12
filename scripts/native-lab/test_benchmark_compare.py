"""Reject mismatched, missing and failed benchmark evidence before comparing."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("benchmark_compare.py")
spec = importlib.util.spec_from_file_location("benchmark_compare", SCRIPT)
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def report(backend):
    return {
        "schema_version": 1, "backend": backend, "passed": True,
        "scope": "fixture-process-memory", "phase0_complete": False,
        "environment": {"architecture": "x86_64", "kernel": "6.8.0",
                        "os_release_sha256": "1" * 64, "libc_sha256": "2" * 64},
        "cases": [{
            "name": "python-http", "passed": True, "cleanup_passed": True,
            "fixture_sha256": "3" * 64,
            "runtime": {"binary_sha256": "4" * 64, "version": "3.12.3",
                        "packages_sha256": "5" * 64},
            "config": {"argv": ["/usr/bin/python3", "/app/http.py"], "env": {},
                       "workers": 1, "requests": 0, "concurrency": 1},
            "limits": {"memory.max": "268435456", "memory.swap.max": "0",
                       "cpu.max": "50000 100000", "pids.max": "128"},
            "window": dict(compare.WINDOW),
            "samples": [{"elapsed_seconds": 5.1 + index, "memory_current_bytes": 1000 + index,
                         "memory_peak_bytes": 2000 + index} for index in range(10)],
        }],
    }


class BenchmarkComparisonTests(unittest.TestCase):
    def assert_blocked(self, native, docker):
        result = compare.compare_reports(native, docker)
        self.assertFalse(result["comparable"])
        self.assertTrue(result["reasons"] or any(case["reasons"] for case in result["cases"]))
        for case in result["cases"]:
            if not case["comparable"]:
                self.assertNotIn("memory_current_median_bytes", case)
                self.assertNotIn("memory_lifetime_peak_bytes", case)

    def test_derives_only_memory_metrics_from_matching_raw_samples(self):
        native, docker = report("native"), report("docker")
        native["cases"][0]["window"]["warmup_seconds"] = 5.0
        native["cases"][0]["window"]["sample_interval_seconds"] = 1.0
        native["cases"][0]["evidence"] = {"unit": "native-unit"}
        docker["cases"][0]["evidence"] = {"container": "docker-container"}
        for sample in docker["cases"][0]["samples"]:
            sample["memory_current_bytes"] += 100
            sample["memory_peak_bytes"] += 100
        original = deepcopy(native)
        result = compare.compare_reports(docker, native)
        self.assertTrue(result["comparable"])
        self.assertEqual(result["cases"][0]["memory_current_median_bytes"], {"native": 1004.5, "docker": 1104.5})
        self.assertEqual(result["cases"][0]["memory_lifetime_peak_bytes"], {"native": 2009, "docker": 2109})
        self.assertEqual(native, original)
        self.assertIs(result["phase0_complete"], False)
        self.assertIsNone(result["storage_comparison"])
        self.assertNotIn("disk", result)

    def test_environment_and_each_identity_configuration_and_limit_must_match(self):
        changes = [(("environment", "architecture"), "arm64"),
                   (("environment", "kernel"), "6.9.0"),
                   (("environment", "os_release_sha256"), "a" * 64),
                   (("environment", "libc_sha256"), "a" * 64),
                   (("cases", 0, "fixture_sha256"), "a" * 64),
                   (("cases", 0, "runtime", "version"), "3.12.4"),
                   (("cases", 0, "runtime", "binary_sha256"), "a" * 64),
                   (("cases", 0, "runtime", "packages_sha256"), "a" * 64),
                   (("cases", 0, "config", "argv"), ["python", "selftest.py"]),
                   (("cases", 0, "config", "env"), {"MODE": "different"}),
                   (("cases", 0, "config", "workers"), 12),
                   (("cases", 0, "limits", "memory.max"), "536870912"),
                   (("cases", 0, "limits", "memory.swap.max"), "268435456"),
                   (("cases", 0, "limits", "cpu.max"), "25000 100000"),
                   (("cases", 0, "limits", "pids.max"), "32")]
        for path, value in changes:
            with self.subTest(path=path):
                native, docker = report("native"), report("docker")
                target = docker
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                self.assert_blocked(native, docker)

    def test_success_flags_cannot_replace_missing_evidence_or_cleanup(self):
        for field in ("fixture_sha256", "runtime", "config", "limits", "window", "samples", "cleanup_passed"):
            with self.subTest(field=field):
                native = report("native")
                del native["cases"][0][field]
                self.assert_blocked(native, report("docker"))
        for path in (("passed",), ("cases", 0, "passed"), ("cases", 0, "cleanup_passed")):
            native = report("native")
            target = native
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = False
            self.assert_blocked(native, report("docker"))
        self.assert_blocked({"native": {"python-http": [12.235, 12148736]}}, report("docker"))

    def test_raw_samples_require_complete_live_counters_and_actual_sampling_window(self):
        bad_samples = [None, [], report("native")["cases"][0]["samples"][:-1]]
        for key, value in (("elapsed_seconds", float("nan")), ("elapsed_seconds", float("inf")),
                           ("elapsed_seconds", True), ("elapsed_seconds", 4.9),
                           ("elapsed_seconds", 10**400),
                           ("memory_current_bytes", 0), ("memory_current_bytes", None),
                           ("memory_current_bytes", True), ("memory_current_bytes", 5000),
                           ("memory_current_bytes", 10**400),
                           ("memory_peak_bytes", 0), ("memory_peak_bytes", 1000.0)):
            samples = deepcopy(report("native")["cases"][0]["samples"])
            samples[0][key] = value
            bad_samples.append(samples)
        for bad in bad_samples:
            with self.subTest(samples=bad):
                native = report("native")
                native["cases"][0]["samples"] = bad
                self.assert_blocked(native, report("docker"))
        for key, value in (("elapsed_seconds", 5.8), ("memory_peak_bytes", 1500)):
            native = report("native")
            native["cases"][0]["samples"][1][key] = value
            self.assert_blocked(native, report("docker"))

    def test_changed_window_or_workload_and_incomplete_case_sets_are_refused(self):
        for group, key, value in (("window", "sample_count", 9), ("window", "peak_scope", "unknown"),
                                  ("window", "warmup_seconds", True), ("config", "requests", 20),
                                  ("config", "concurrency", 2), ("limits", "memory.max", "max")):
            native = report("native")
            native["cases"][0][group][key] = value
            self.assert_blocked(native, report("docker"))
        native = report("native")
        native["cases"][0]["name"] = "different-fixture"
        self.assert_blocked(native, report("docker"))
        native = report("native")
        native["cases"].append(deepcopy(native["cases"][0]))
        self.assert_blocked(native, report("docker"))
        self.assert_blocked(report("native"), report("native"))
        native = report("native")
        native["phase0_complete"] = True
        self.assert_blocked(native, report("docker"))

    def test_shifted_and_stretched_actual_windows_do_not_qualify_even_when_both_match(self):
        for elapsed in ([3605 + index for index in range(10)],
                        [5 + index for index in range(3)] + [10 + index for index in range(7)],
                        [5 + index * 1.5 for index in range(10)]):
            with self.subTest(elapsed=elapsed):
                native, docker = report("native"), report("docker")
                for value in (native, docker):
                    for sample, timestamp in zip(value["cases"][0]["samples"], elapsed):
                        sample["elapsed_seconds"] = timestamp
                self.assert_blocked(native, docker)

    def test_actual_backend_windows_must_match_within_declared_tolerances(self):
        native, docker = report("native"), report("docker")
        for index, sample in enumerate(native["cases"][0]["samples"]):
            sample["elapsed_seconds"] = 5.1 + index * (12.4 / 9)
        # Every native interval is under two seconds and its last sample is
        # before eighteen, but it is over three seconds later than Docker's.
        self.assertEqual(compare._case_errors(native["cases"][0]), [])
        self.assert_blocked(native, docker)
        for index, sample in enumerate(native["cases"][0]["samples"]):
            sample["elapsed_seconds"] = 7 + index
        self.assertTrue(compare.compare_reports(native, docker)["comparable"])

    def test_cli_exit_code_reflects_comparability_and_handles_invalid_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ("native.json", "docker.json")]
            for path, backend in zip(paths, ("native", "docker")):
                path.write_text(json.dumps(report(backend)))
            args = [sys.executable, "-B", str(SCRIPT), *map(str, paths)]
            success = subprocess.run(args, capture_output=True, text=True, check=False)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertTrue(json.loads(success.stdout)["comparable"])
            paths[1].write_text("invalid json")
            failure = subprocess.run(args, capture_output=True, text=True, check=False)
            self.assertEqual(failure.returncode, 1, failure.stderr)
            self.assertFalse(json.loads(failure.stdout)["comparable"])


if __name__ == "__main__":
    unittest.main()
