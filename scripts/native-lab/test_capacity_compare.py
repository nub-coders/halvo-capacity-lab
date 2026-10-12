"""Offline unit tests for the strict request-capacity comparator."""

from copy import deepcopy
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("capacity_compare.py")
spec = importlib.util.spec_from_file_location("capacity_compare", SCRIPT)
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def _digest(character):
    return character * 64


def _summary(requests, latency, errors=0):
    successful = requests - errors
    return {
        "scheduled": requests,
        "completed": requests,
        "successful": successful,
        "failed": errors,
        "errors": errors,
        "error_rate": errors / requests,
        "goodput_rps": successful / compare.SAMPLE_SECONDS,
        "latency_ms": {"count": 1, "p50": latency, "p95": latency, "p99": latency},
    }


def report(backend, *, capacity=64, latency=100.0, image=None):
    rates = []
    for rate in compare.RATES:
        route_counts = {
            route: rate * compare.SAMPLE_SECONDS * compare.WEIGHTS[route] // 100
            for route in compare.ROUTES
        }
        rejected = rate > capacity
        route_errors = {
            route: (max(1, math.ceil(count * 0.02)) if rejected else 0)
            for route, count in route_counts.items()
        }
        routes = {
            route: _summary(count, latency, route_errors[route])
            for route, count in route_counts.items()
        }
        aggregate = _summary(rate * compare.SAMPLE_SECONDS, latency, sum(route_errors.values()))
        aggregate["latency_ms"]["count"] = len(compare.ROUTES)
        rates.append({
            "rate_per_second": rate,
            "accepted": not rejected,
            "passed": not rejected,
            "aggregate": aggregate,
            "routes": routes,
            "latency_evidence_sha256": _digest("e"),
            "readiness": {route: {"ready": True} for route in compare.ROUTES},
            "generator": {
                "healthy": True,
                "bottleneck": False,
                "scheduled": rate * compare.SAMPLE_SECONDS,
                "dispatched": rate * compare.SAMPLE_SECONDS,
                "completed": rate * compare.SAMPLE_SECONDS,
            },
        })
    result = {
        "schema_version": 1,
        "backend": backend,
        "scope": "request-capacity",
        "passed": True,
        "payload_sha256": _digest("a"),
        "configuration": {
            "routes": list(compare.ROUTES),
            "weights": dict(compare.WEIGHTS),
            "rates": list(compare.RATES),
            "warmup_seconds": 60,
            "sample_seconds": 120,
            "limits": dict(compare.LIMITS),
        },
        "identity": {"fixture_set": "phase0-fixed-v1", "runtime": "pinned"},
        "cleanup": {"attempted": True, "passed": True, "errors": []},
        "cases": rates,
        "capacity_rps": capacity,
    }
    if backend == "docker":
        result["image"] = image or "sha256:" + "d" * 64
    return result


def trials(backend, **kwargs):
    return [report(backend, **kwargs) for _ in range(3)]


def copies(value):
    return [deepcopy(value) for _ in range(3)]


class CapacityComparisonTests(unittest.TestCase):
    def test_matching_pair_passes_and_reports_medians_and_rate_checks(self):
        native, docker = trials("native"), trials("docker")
        verdict = compare.compare_reports(native, docker)
        self.assertTrue(verdict["comparable"])
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["medians"]["capacity_rps"],
                         {"native": 64, "docker": 64})
        self.assertEqual(len(verdict["per_rate"]), 8)
        self.assertTrue(all(row["common_accepted"] for row in verdict["per_rate"][:-1]))
        self.assertFalse(verdict["per_rate"][-1]["common_accepted"])
        self.assertTrue(all(row["passed"] for row in verdict["per_rate"]
                            if row["common_accepted"]))

    def test_three_trials_use_medians(self):
        native = [report("native", capacity=value, latency=100 + index)
                  for index, value in enumerate((64, 64, 64))]
        docker = [report("docker", capacity=64, latency=100) for _ in range(3)]
        verdict = compare.compare_reports(native, docker)
        self.assertTrue(verdict["comparable"])
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["medians"]["capacity_rps"],
                         {"native": 64, "docker": 64})
        self.assertEqual(verdict["trials"], {"native": 3, "docker": 3})

    def test_capacity_gate_failure_is_comparable_but_not_passed(self):
        verdict = compare.compare_reports(trials("native", capacity=32), trials("docker"))
        self.assertTrue(verdict["comparable"])
        self.assertFalse(verdict["passed"])
        self.assertTrue(any("95%" in reason for reason in verdict["reasons"]))

    def test_error_and_latency_gates_are_applied_at_common_accepted_rates(self):
        native, docker = trials("native"), trials("docker")
        # The native latency exceeds both the p50 relative threshold and its
        # additive floor, while the error rate remains below one percent.
        for trial in native:
            for case in trial["cases"]:
                for summary in (case["aggregate"], *case["routes"].values()):
                    summary["latency_ms"].update({"p50": 250.0, "p95": 250.0, "p99": 250.0})
        verdict = compare.compare_reports(native, docker)
        self.assertTrue(verdict["comparable"])
        self.assertFalse(verdict["passed"])
        self.assertTrue(any("error or latency" in reason for reason in verdict["reasons"]))
        self.assertFalse(verdict["per_rate"][0]["checks"]["latency"]["p50"]["passed"])

    def test_raw_outcomes_are_checked_against_all_route_percentiles(self):
        native = trials("native")
        case = native[0]["cases"][0]
        raw = {}
        next_id = 0
        for route in compare.ROUTES:
            count = compare.SAMPLE_SECONDS * compare.WEIGHTS[route] // 100
            raw[route] = [{"id": next_id + index, "route": route, "ok": True,
                           "status": 200, "latency_ms": 10.0}
                          for index in range(count)]
            next_id += count
            case["routes"][route]["latency_ms"]["count"] = count
            case["routes"][route]["latency_ms"].update({"p50": 10.0, "p95": 10.0, "p99": 10.0})
        case["aggregate"]["latency_ms"]["count"] = compare.SAMPLE_SECONDS
        case["aggregate"]["latency_ms"].update({"p50": 10.0, "p95": 10.0, "p99": 10.0})
        case["raw_outcomes"] = raw
        del case["latency_evidence_sha256"]
        verdict = compare.compare_reports(native, trials("docker"))
        self.assertTrue(verdict["comparable"])
        self.assertTrue(verdict["passed"])

        raw["node"][0]["latency_ms"] = 11.0
        invalid = compare.compare_reports(native, trials("docker"))
        self.assertFalse(invalid["comparable"])
        self.assertTrue(any("p99" in reason or "p95" in reason or "p50" in reason
                            for reason in invalid["reasons"]))

    def test_rejects_missing_extra_and_mismatched_contract_evidence(self):
        mutations = []

        missing_payload = report("native")
        del missing_payload["payload_sha256"]
        mutations.append(missing_payload)

        extra_route = report("native")
        extra_route["configuration"]["weights"]["worker"] = 1
        mutations.append(extra_route)

        wrong_limits = report("native")
        wrong_limits["configuration"]["limits"]["pids.max"] = "64"
        mutations.append(wrong_limits)

        incomplete_case = report("native")
        del incomplete_case["cases"][2]["aggregate"]
        mutations.append(incomplete_case)

        invalid_percentiles = report("native")
        invalid_percentiles["cases"][0]["aggregate"]["latency_ms"]["p99"] = 1.0
        mutations.append(invalid_percentiles)

        for native in mutations:
            with self.subTest(mutation=native):
                verdict = compare.compare_reports(copies(native), trials("docker"))
                self.assertFalse(verdict["comparable"])
                self.assertFalse(verdict["passed"])
                self.assertTrue(verdict["reasons"])

    def test_rejects_failed_cleanup_readiness_oom_restart_and_generator(self):
        mutations = []

        cleanup = report("native")
        cleanup["cleanup"]["passed"] = False
        mutations.append(cleanup)

        readiness = report("native")
        readiness["cases"][0]["readiness"]["python"]["ready"] = False
        mutations.append(readiness)

        oom = report("native")
        oom["cases"][0]["readiness"]["python"]["ooms"] = 1
        mutations.append(oom)

        restart = report("native")
        restart["cases"][0]["readiness"]["python"]["restarts"] = 1
        mutations.append(restart)

        bottleneck = report("native")
        bottleneck["cases"][0]["generator"]["bottleneck"] = True
        mutations.append(bottleneck)

        for native in mutations:
            with self.subTest(mutation=native):
                verdict = compare.compare_reports(copies(native), trials("docker"))
                self.assertFalse(verdict["comparable"])
                self.assertFalse(verdict["passed"])

    def test_identity_image_and_trial_count_mismatches_are_rejected(self):
        native, docker = trials("native"), trials("docker")
        docker[0]["identity"]["runtime"] = "different"
        verdict = compare.compare_reports(native, docker)
        self.assertFalse(verdict["comparable"])
        self.assertTrue(any("identit" in reason for reason in verdict["reasons"]))

        native, docker = trials("native"), trials("docker")
        docker[0]["image"] = "sha256:" + "x" * 64
        verdict = compare.compare_reports(native, docker)
        self.assertFalse(verdict["comparable"])

        verdict = compare.compare_reports([report("native"), report("native"), report("docker")])
        self.assertFalse(verdict["comparable"])
        self.assertTrue(any("three" in reason for reason in verdict["reasons"]))

    def test_cli_is_read_only_and_exit_code_matches_verdict(self):
        native, docker = trials("native"), trials("docker")
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / f"trial-{index}.json" for index in range(6)]
            for path, value in zip(paths, (*native, *docker)):
                path.write_text(json.dumps(value), encoding="utf-8")
            before = [path.read_bytes() for path in paths]
            command = [sys.executable, "-B", str(SCRIPT), *map(str, paths)]
            success = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertTrue(json.loads(success.stdout)["passed"])
            self.assertEqual(before, [path.read_bytes() for path in paths])

            docker[0]["passed"] = False
            paths[3].write_text(json.dumps(docker[0]), encoding="utf-8")
            failure = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(failure.returncode, 1, failure.stderr)
            self.assertFalse(json.loads(failure.stdout)["comparable"])


def saturated(trial, wall):
    """Truncate a synthetic report at its first rejected rate with the marker
    the payload27 collector writes when the climb stops at the wall."""
    result = deepcopy(trial)
    result["cases"] = [case for case in trial["cases"]
                       if case["rate_per_second"] <= wall]
    result["schedule"] = {"stopped_at_rejection": wall, "phase0_complete": False}
    result["capacity_rps"] = max(case["rate_per_second"] for case in result["cases"]
                                 if case["accepted"])
    return result


class SaturationStopTests(unittest.TestCase):
    def test_marked_saturated_prefix_passes_structure_and_the_full_pair_gate(self):
        native = [saturated(report("native", capacity=8), 16) for _ in range(3)]
        docker = [saturated(report("docker", capacity=8), 16) for _ in range(3)]
        for trial in (*native, *docker):
            self.assertEqual(compare._report_errors(trial), [])
        verdict = compare.compare_reports(native, docker)
        self.assertTrue(verdict["comparable"])
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["medians"]["capacity_rps"], {"native": 8, "docker": 8})

    def test_truncated_report_without_the_marker_is_still_rejected(self):
        truncated = report("native", capacity=8)
        truncated["cases"] = [case for case in truncated["cases"]
                              if case["rate_per_second"] <= 16]
        truncated["capacity_rps"] = 8
        errors = compare._report_errors(truncated)
        self.assertTrue(any("exactly" in reason for reason in errors), errors)

    def test_marker_ending_at_an_accepted_window_is_rejected(self):
        forged = saturated(report("native", capacity=8), 16)
        forged["cases"][-1]["accepted"] = True
        forged["cases"][-1]["passed"] = True
        errors = compare._report_errors(forged)
        self.assertTrue(any("rejected window" in reason for reason in errors), errors)

    def test_marked_schedule_cannot_continue_after_an_earlier_rejection(self):
        forged = saturated(report("native", capacity=8), 16)
        forged["cases"][2] = report("native", capacity=2)["cases"][2]
        errors = compare._report_errors(forged)
        self.assertTrue(any("first rejected window" in reason for reason in errors), errors)

    def test_marked_schedule_requires_frozen_rate_order(self):
        forged = saturated(report("native", capacity=8), 16)
        forged["cases"][0], forged["cases"][1] = forged["cases"][1], forged["cases"][0]
        errors = compare._report_errors(forged)
        self.assertTrue(any("order" in reason for reason in errors), errors)

    def test_marker_requires_an_integer_rate_and_explicit_incomplete_phase0(self):
        for marker in (16.0, True):
            with self.subTest(marker=marker):
                forged = saturated(report("native", capacity=8), 16)
                forged["schedule"]["stopped_at_rejection"] = marker
                errors = compare._report_errors(forged)
                self.assertTrue(any("not a fixed rate" in reason for reason in errors), errors)
        for complete in (True, None, 0):
            with self.subTest(phase0_complete=complete):
                forged = saturated(report("native", capacity=8), 16)
                forged["schedule"]["phase0_complete"] = complete
                errors = compare._report_errors(forged)
                self.assertTrue(any("Phase 0" in reason for reason in errors), errors)

    def test_capacity_disagreement_between_saturated_pairs_is_comparable_not_passed(self):
        verdict = compare.compare_reports(
            [saturated(report("native", capacity=8), 16) for _ in range(3)],
            [saturated(report("docker", capacity=16), 32) for _ in range(3)])
        self.assertTrue(verdict["comparable"])
        self.assertFalse(verdict["passed"])
        self.assertTrue(any("95%" in reason for reason in verdict["reasons"]))


if __name__ == "__main__":
    unittest.main()
