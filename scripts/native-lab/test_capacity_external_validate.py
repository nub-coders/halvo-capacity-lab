"""Synthetic records for validator boundaries, not measured lab results."""
from copy import deepcopy
from pathlib import Path
import unittest

import capacity
import capacity_external as external
import capacity_external_validate as validation
import capacity_preflight
from test_capacity_external import guest_report


def sample_report():
    initial = guest_report()
    baseline = initial["residents"]
    cleanup = {"passed": True, "errors": [], "residents": {"passed": True, "errors": [],
        "evidence": [{"name": n, "owned": True, "stopped": True, "empty": True} for n in baseline]},
        "relays": {"passed": True, "errors": [], "evidence": [{"route": r, "owned": True,
            "stopped": True, "listener_closed": True, "killed": False} for r in capacity.ROUTE_ORDER]}}
    final = deepcopy(initial); final["cleanup"] = cleanup
    def phase(duration, start):
        rows = []
        for s in capacity.iter_schedule(1, duration):
            offset = s["offset_seconds"] * 1000
            rows.append({"id": start+s["index"], "route": s["route"], "ok": True, "status": 200,
                "error": None, "scheduled_offset_ms": offset, "dispatch_lag_ms": 1.0,
                "client_queue_lag_ms": 2.0, "started_offset_ms": offset+2, "ended_offset_ms": offset+3,
                "latency_ms": 1.0, "http_version": 11, "connection_reused": True})
        summary = capacity.aggregate_outcomes(rows, duration)
        summary.update(timings={"requested_duration_seconds": duration, "actual_duration_seconds": duration,
            "origin_monotonic": 100.0, "scheduled_end_monotonic": 100+duration, "window_ended_monotonic": 100+duration},
            drain={"completed": True, "pending_at_end": [], "started_at_monotonic": 100+duration,
                   "ended_at_monotonic": 100+duration},
            health_checks={"monitor_stopped": True, "failure": None, "interval_seconds": 5,
                "check_timeout_seconds": capacity.HEALTH_CHECK_TIMEOUT_SECONDS,
                "snapshots": [{"kind": kind, "passed": True,
                    "started_at_monotonic": clock, "ended_at_monotonic": clock+.1,
                    "resident_evidence": baseline, "worker_checkpoint": tick}
                    for kind, clock, tick in (("before", 99, 1), ("after", 101+duration, 2))]},
            generator={"scheduled": duration, "dispatched": duration, "completed": duration,
                       "bottleneck": False, "max_dispatch_lag_ms": 1.0})
        return {route: [r for r in rows if r["route"] == route] for route in capacity.ROUTE_ORDER}, summary
    warm, ws = phase(60, 0); raw, ms = phase(120, 60)
    r = {"scope": "external-generator-path-preflight", "schema_version": 1,
        "passed": True, "phase0_complete": False, "production": False, "capacity_evidence": False,
        "collection_valid": False, "errors": [], "backend": "native", "image": None,
        "payload_sha256": "b"*64, "guest_initial_report": initial, "guest_final_report": final,
        "residents": baseline, "cleanup": {"passed": True, "errors": [],
            "control": {"passed": True, "errors": [], "reply": {"ok": True, "cleanup": cleanup}},
            "clients": {"passed": True, "errors": []}, "forward": {"passed": True, "errors": []}},
        "generator_selfcheck": {"passed": True, "scope": "load-generator-selfcheck", "capacity_evidence": False,
            **capacity_preflight.CLIENT_PROFILE, "source_sha256": capacity_preflight.source_identities(),
            "client_nofile_soft_limits": {route: 8192 for route in capacity.ROUTE_ORDER},
            "rate_per_second": 256, "duration_seconds": 60, "summary": {"completed": 15360, "failed": 0},
            "cleanup": {"passed": True, "server_stopped": True}},
        "generator": {"placement": "external-host", "cpu_affinity": [2,3], "generator_cpus": [2,3],
            "guest_cpus": [0,1], "transport": external.TRANSPORT, "clock_domain": "host-monotonic",
            **capacity_preflight.CLIENT_PROFILE,
            "qemu": {"cpu_affinity": [0,1], "guest_vcpus": 2, "guest_memory_mib": 2560,
                     "acceleration": "tcg", "executable_sha256": "f"*64},
            "source_files_sha256": {name: capacity.file_digest(Path(__file__).with_name(name)) for name in external.SOURCE_FILES},
            "clients": {route: {"cpu_affinity": [2,3], "nofile_soft_limit": 8192} for route in capacity.ROUTE_ORDER},
            "control_child": {"cpu_affinity": [2,3]}, "forward": {"cpu_affinity": [2,3], "listeners_ready": True,
                "nofile_soft_limit": 16384}},
        "rates": [{"rate_per_second": 1, "warmup": {"summary": ws}, "measurement": {"summary": ms},
                   "warmup_raw_outcomes": warm, "raw_outcomes": raw}]}
    for key in ("configuration", "expected_limits", "fixtures", "environment"):
        r[key] = deepcopy(initial[key])
    r["configuration"].update(generator_placement="external-host", transport=external.TRANSPORT)
    return r


def capacity_report(wall, *, marked=True):
    """Synthetic capacity-mode report: rates below `wall` accepted with zero
    errors, the wall window rejected above the error budget, and (when marked)
    the saturation-stop schedule record the collector writes."""
    base = sample_report()
    report = deepcopy(base)
    report.update(scope="request-capacity", collection_valid=True,
                  capacity_evidence=True, passed=True)
    rates, next_id, tick = [], 0, 1
    for rate in list(capacity.RATES[:capacity.RATES.index(wall) + 1]):
        rejected = rate == wall
        windows = []
        phase_rows = []
        for kind, duration in (("warmup", 60), ("measurement", 120)):
            rows = []
            for scheduled in capacity.iter_schedule(rate, duration):
                offset = scheduled["offset_seconds"] * 1000
                failed = rejected and kind == "measurement" and scheduled["index"] % 25 == 0
                rows.append({"id": next_id + scheduled["index"], "route": scheduled["route"],
                    "ok": not failed, "status": None if failed else 200,
                    "error": "transport_error" if failed else None,
                    "scheduled_offset_ms": offset, "dispatch_lag_ms": 1.0,
                    "client_queue_lag_ms": 2.0, "started_offset_ms": offset + 2,
                    "ended_offset_ms": offset + 3, "latency_ms": 1.0,
                    "http_version": None if failed else 11, "connection_reused": True})
            summary = capacity.aggregate_outcomes(rows, duration)
            summary.update(timings={"requested_duration_seconds": duration,
                "actual_duration_seconds": duration, "origin_monotonic": 100.0,
                "scheduled_end_monotonic": 100 + duration, "window_ended_monotonic": 100 + duration},
                drain={"completed": True, "pending_at_end": [], "started_at_monotonic": 100 + duration,
                       "ended_at_monotonic": 100 + duration},
                health_checks={"monitor_stopped": True, "failure": None, "interval_seconds": 5,
                    "check_timeout_seconds": capacity.HEALTH_CHECK_TIMEOUT_SECONDS, "snapshots": [
                        {"kind": "before", "passed": True, "started_at_monotonic": 99 + tick,
                         "ended_at_monotonic": 99.1 + tick,
                         "resident_evidence": base["residents"], "worker_checkpoint": tick},
                        {"kind": "after", "passed": True, "started_at_monotonic": 101 + duration + tick,
                         "ended_at_monotonic": 101.1 + duration + tick,
                         "resident_evidence": base["residents"], "worker_checkpoint": tick + 1}]},
                generator={"scheduled": rate * duration, "dispatched": rate * duration,
                           "completed": rate * duration, "bottleneck": False,
                           "max_dispatch_lag_ms": 1.0})
            tick += 2
            windows.append(summary)
            phase_rows.append(rows)
            next_id += rate * duration
        warm_rows, raw = phase_rows
        rates.append({"rate_per_second": rate, "accepted": not rejected, "passed": not rejected,
                      "errors": [],
                      "readiness": {route: {"ready": True} for route in capacity.ROUTE_ORDER},
                      "generator": {"healthy": True, "bottleneck": False,
                                    "scheduled": rate * 120, "dispatched": rate * 120,
                                    "completed": rate * 120},
                      "warmup": {"summary": windows[0]}, "measurement": {"summary": windows[1]},
                      "warmup_raw_outcomes": {route: [r for r in warm_rows if r["route"] == route]
                                              for route in capacity.ROUTE_ORDER},
                      "raw_outcomes": {route: [r for r in raw if r["route"] == route]
                                       for route in capacity.ROUTE_ORDER}})
    report["rates"] = rates
    report["capacity_rps"] = 8
    if marked:
        report["schedule"] = {"stopped_at_rejection": wall, "phase0_complete": False}
    return report


class SaturationStopValidationTests(unittest.TestCase):
    def test_marked_saturated_prefix_is_a_valid_capacity_collection(self):
        report = capacity_report(16)
        projected = validation.validate(report)
        self.assertEqual(projected["capacity_rps"], 8)
        self.assertEqual(projected["schedule"], {"stopped_at_rejection": 16, "phase0_complete": False})
        from capacity_compare import _report_errors
        self.assertEqual(_report_errors(projected), [])

    def test_truncated_schedule_without_the_marker_is_rejected(self):
        with self.assertRaises(ValueError):
            validation.validate(capacity_report(16, marked=False))

    def test_marker_on_a_non_frozen_rate_or_accepted_wall_is_rejected(self):
        shifted = capacity_report(16)
        shifted["schedule"] = {"stopped_at_rejection": 20, "phase0_complete": False}
        with self.assertRaises(ValueError):
            validation.validate(shifted)
        unmarked_wall = capacity_report(16, marked=False)
        unmarked_wall["schedule"] = {"stopped_at_rejection": 16, "phase0_complete": False}
        # the final window is accepted in this forged shape, so the marker lies
        unmarked_wall["rates"][-1]["accepted"] = True
        unmarked_wall["rates"][-1]["passed"] = True
        with self.assertRaises(ValueError):
            validation.validate(unmarked_wall)

    def test_marked_schedule_cannot_continue_after_an_earlier_rejection(self):
        report = capacity_report(16)
        report["rates"][2] = capacity_report(4)["rates"][-1]
        with self.assertRaisesRegex(ValueError, "first rejected window"):
            validation.validate(report)

    def test_marked_schedule_requires_frozen_rate_order(self):
        report = capacity_report(16)
        report["rates"][0], report["rates"][1] = report["rates"][1], report["rates"][0]
        with self.assertRaisesRegex(ValueError, "trial rate sequence"):
            validation.validate(report)

    def test_marker_requires_an_integer_rate_and_explicit_incomplete_phase0(self):
        for marker in (16.0, True):
            with self.subTest(marker=marker):
                report = capacity_report(16)
                report["schedule"]["stopped_at_rejection"] = marker
                with self.assertRaisesRegex(ValueError, "not a frozen rate"):
                    validation.validate(report)
        for complete in (True, None, 0):
            with self.subTest(phase0_complete=complete):
                report = capacity_report(16)
                report["schedule"]["phase0_complete"] = complete
                with self.assertRaisesRegex(ValueError, "Phase 0"):
                    validation.validate(report)

    def test_slow_but_passing_resident_health_sample_within_the_monitor_bound_is_valid(self):
        # payload29 docker trials at the saturation wall under TCG recorded resident
        # health samples whose wall time ran 40-60s with passed:True, every backend
        # command under HEALTH_COMMAND_TIMEOUT_SECONDS and the monitor passing them
        # below its 90s HEALTH_CHECK_TIMEOUT_SECONDS. Such a sample is healthy by the
        # instrument's own gate and must not invalidate an otherwise complete trial.
        report = capacity_report(16)
        health = report["rates"][-1]["measurement"]["summary"]["health_checks"]
        before = health["snapshots"][0]
        slow = {"kind": "periodic", "passed": True,
                "started_at_monotonic": before["ended_at_monotonic"] + 5,
                "ended_at_monotonic": before["ended_at_monotonic"] + 5 + 57.0,
                "resident_evidence": before["resident_evidence"],
                "worker_checkpoint": before["worker_checkpoint"]}
        health["snapshots"].insert(1, slow)
        projected = validation.validate(report)
        self.assertEqual(projected["capacity_rps"], 8)

    def test_resident_health_sample_beyond_the_monitor_bound_or_failed_is_rejected(self):
        report = capacity_report(16)
        s = report["rates"][-1]["measurement"]["summary"]["health_checks"]["snapshots"][0]
        s["ended_at_monotonic"] = s["started_at_monotonic"] + capacity.HEALTH_CHECK_TIMEOUT_SECONDS + 1
        with self.assertRaisesRegex(ValueError, "resident health sample"):
            validation.validate(report)
        report = capacity_report(16)
        report["rates"][-1]["measurement"]["summary"]["health_checks"]["snapshots"][0]["passed"] = False
        with self.assertRaisesRegex(ValueError, "resident health sample"):
            validation.validate(report)


class ExternalValidationTests(unittest.TestCase):
    def test_preflight_never_becomes_capacity_evidence(self):
        report = sample_report()
        validation.validate(report, preflight=True)
        with self.assertRaises(ValueError):
            validation.validate(report)
        self.assertFalse(validation.compare([report]*6)["passed"])

    def test_incomplete_warmup_window_dispatch_identity_and_http_are_rejected(self):
        mutations = [lambda r: r["rates"][0]["warmup"]["summary"]["timings"].update(actual_duration_seconds=59),
            lambda r: r["rates"][0]["raw_outcomes"]["python"][0].update(dispatch_lag_ms=501),
            lambda r: r["rates"][0]["raw_outcomes"]["python"][0].update(id=999),
            lambda r: r["rates"][0]["raw_outcomes"]["python"][0].update(http_version=10),
            lambda r: r["rates"][0]["raw_outcomes"]["python"].pop()]
        for mutation in mutations:
            r = sample_report(); mutation(r)
            with self.assertRaises(ValueError):
                validation.validate(r, preflight=True)

    def test_worker_failure_source_drift_affinity_and_cleanup_are_rejected(self):
        mutations = [lambda r: r["rates"][0]["measurement"]["summary"]["health_checks"]["snapshots"][-1].update(worker_checkpoint=1),
            lambda r: r["generator"]["source_files_sha256"].update({"capacity_relay.py": "0"*64}),
            lambda r: r["generator"].update(cpu_affinity=[0,1]),
            lambda r: r["cleanup"]["control"]["reply"]["cleanup"]["relays"]["evidence"][0].update(listener_closed=False)]
        for mutation in mutations:
            r = sample_report(); mutation(r)
            with self.assertRaises((ValueError, capacity.CapacityError)):
                validation.validate(r, preflight=True)

    def test_legacy_or_mismatched_client_and_selfcheck_profiles_are_rejected(self):
        mutations = [lambda r: r["generator"].update(client_workers_per_route=32),
            lambda r: r["generator"].update(max_outstanding_requests=4097),
            lambda r: r["generator"].update(max_idle_connections_per_route=33),
            lambda r: r["generator"]["clients"]["python"].update(nofile_soft_limit=1024),
            lambda r: r["generator"]["forward"].update(nofile_soft_limit=1024),
            lambda r: r["generator_selfcheck"]["client_nofile_soft_limits"].update(python=1024),
            lambda r: r["generator_selfcheck"].update(client_implementation="blocking-worker-v1"),
            lambda r: r["generator_selfcheck"]["source_sha256"].update({"capacity_async_client.py": "0"*64})]
        for mutation in mutations:
            r = sample_report(); mutation(r)
            with self.assertRaises((ValueError, capacity.CapacityError)):
                validation.validate(r, preflight=True)


if __name__ == "__main__":
    unittest.main()
