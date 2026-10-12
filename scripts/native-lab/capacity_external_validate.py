#!/usr/bin/env python3
"""Read-only evidence checks for the revised external capacity instrument.

Run from the same frozen lineage as the reports. Capacity thresholds stay
fixed; this layer additionally validates the transport, raw phase evidence and
saturation-stop schedule, and refuses preflights as capacity trials.
"""
from copy import deepcopy
import argparse
import json
import math
from pathlib import Path

import capacity
import capacity_compare
import capacity_external as external


def need(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def phase(summary, rows, rate, duration, start_id, baseline):
    count = rate * duration
    need(isinstance(rows, list) and len(rows) == count, "raw phase count is incomplete")
    ordered = sorted(rows, key=lambda row: row["id"])
    for scheduled, row in zip(capacity.iter_schedule(rate, duration), ordered):
        need(type(row.get("id")) is int and row["id"] == start_id + scheduled["index"]
             and row.get("route") == scheduled["route"], "request identity/route differs")
        for key in ("scheduled_offset_ms", "dispatch_lag_ms", "client_queue_lag_ms",
                    "started_offset_ms", "ended_offset_ms", "latency_ms"):
            need(number(row.get(key)) and row[key] >= 0, "raw phase timing is invalid")
        need(abs(row["scheduled_offset_ms"] - scheduled["offset_seconds"] * 1000) <= .001
             and row["dispatch_lag_ms"] <= 500 and row["client_queue_lag_ms"] <= 2000
             and row["started_offset_ms"] >= row["scheduled_offset_ms"]
             and row["ended_offset_ms"] >= row["started_offset_ms"]
             and abs(row["ended_offset_ms"] - row["started_offset_ms"] - row["latency_ms"]) <= .001
             and abs(row["started_offset_ms"] - row["scheduled_offset_ms"] - row["client_queue_lag_ms"]) <= .001,
             "raw phase timing differs from the approved schedule/guards")
        need(type(row.get("connection_reused")) is bool and row.get("http_version") in (None, 11)
             and (row.get("ok") is not True or row["http_version"] == 11), "HTTP/1.1 evidence differs")
    recomputed = capacity.aggregate_outcomes(ordered, duration)
    for key, value in recomputed.items():
        need(summary.get(key) == value, "phase summary differs from raw outcomes: " + key)
    timing = summary["timings"]
    actual = timing["actual_duration_seconds"]
    need(number(actual) and duration <= actual <= duration + .5
         and timing["requested_duration_seconds"] == duration
         and abs(timing["scheduled_end_monotonic"] - timing["origin_monotonic"] - duration) <= 1e-6
         and abs(timing["window_ended_monotonic"] - timing["origin_monotonic"] - actual) <= 1e-6,
         "phase window is not the full approved duration")
    drain = summary["drain"]
    need(drain["completed"] is True and drain["pending_at_end"] == []
         and drain["ended_at_monotonic"] >= drain["started_at_monotonic"]
         and drain["ended_at_monotonic"] - drain["started_at_monotonic"] <= 40.5,
         "phase drain is incomplete or exceeded its bound")
    health = summary["health_checks"]
    need(health["monitor_stopped"] is True and health["failure"] is None
         and health["interval_seconds"] == 5
         and health["check_timeout_seconds"] == capacity.HEALTH_CHECK_TIMEOUT_SECONDS,
         "phase health monitor did not pass")
    samples = health["snapshots"]
    need(len(samples) >= 2 and samples[0]["kind"] == "before" and samples[-1]["kind"] == "after",
         "phase boundary health evidence is incomplete")
    checkpoints = []
    for sample in samples:
        need(sample["passed"] is True and 0 <= sample["ended_at_monotonic"] - sample["started_at_monotonic"]
             <= capacity.HEALTH_CHECK_TIMEOUT_SECONDS,
             "resident health sample failed or exceeded its bound")
        external._residents(sample["resident_evidence"], baseline)
        checkpoints.append(sample["worker_checkpoint"])
    need(all(type(value) is int and value >= 0 for value in checkpoints)
         and checkpoints == sorted(checkpoints) and checkpoints[-1] > checkpoints[0],
         "worker progress is missing or regressed")
    gen = summary["generator"]
    need(gen["bottleneck"] is False and all(gen[key] == count for key in ("scheduled", "dispatched", "completed"))
         and gen["max_dispatch_lag_ms"] == max(row["dispatch_lag_ms"] for row in ordered),
         "generator summary differs from raw phase evidence")


def _rows(case, key):
    value = case[key]
    need(isinstance(value, dict) and set(value) == set(capacity.ROUTE_ORDER), "raw route set differs")
    return [row for route in capacity.ROUTE_ORDER for row in value[route]]


def validate(report, *, preflight=False):
    expected = "external-generator-path-preflight" if preflight else "request-capacity"
    need(report["scope"] == expected and report["passed"] is True and report["errors"] == []
         and report["phase0_complete"] is False and report["production"] is False,
         "report failed, has the wrong scope, or asserts Phase 0 completion")
    need(report["collection_valid"] is (not preflight) and report["capacity_evidence"] is (not preflight),
         "preflight and capacity evidence are mixed")
    initial, final = report["guest_initial_report"], report["guest_final_report"]
    external.validate_guest_report(initial, report["backend"], report["image"], report["payload_sha256"])
    external.validate_guest_report(final, report["backend"], report["image"], report["payload_sha256"], initial=initial)
    need(final["errors"] == [], "guest recorded a collection/cleanup failure")
    generator = report["generator"]
    external.capacity_preflight.validate_client_profile(generator)
    need(generator["placement"] == "external-host" and generator["cpu_affinity"] == [2, 3]
         and generator["generator_cpus"] == [2, 3] and generator["guest_cpus"] == [0, 1]
         and generator["transport"] == external.TRANSPORT and generator["clock_domain"] == "host-monotonic",
         "generator placement/transport differs")
    qemu = generator["qemu"]
    need(qemu["cpu_affinity"] == [0, 1] and qemu["guest_vcpus"] == 2
         and qemu["guest_memory_mib"] == 2560 and qemu["acceleration"] in ("tcg", "kvm")
         and capacity.PAYLOAD_DIGEST.fullmatch(qemu.get("executable_sha256", "")),
         "guest allocation differs")
    root = Path(__file__).resolve().parent
    need(generator["source_files_sha256"] == {name: capacity.file_digest(root / name) for name in external.SOURCE_FILES},
         "generator source files differ from this frozen validator lineage")
    need(all(entry["cpu_affinity"] == [2, 3] for entry in generator["clients"].values())
         and generator["control_child"]["cpu_affinity"] == [2, 3]
         and generator["forward"]["cpu_affinity"] == [2, 3]
          and generator["forward"]["listeners_ready"] is True, "child placement/forward readiness differs")
    need(all(type(entry.get("nofile_soft_limit")) is int and entry["nofile_soft_limit"] >= 8192
             for entry in generator["clients"].values())
         and type(generator["forward"].get("nofile_soft_limit")) is int
         and generator["forward"]["nofile_soft_limit"] >= external.FORWARD_NOFILE_MIN,
         "client/forward descriptor capacity is insufficient")
    cleanup = report["cleanup"]
    need(cleanup["passed"] is True and cleanup["errors"] == [], "combined cleanup did not pass")
    for key in ("control", "clients", "forward"):
        need(cleanup[key]["passed"] is True and cleanup[key]["errors"] == [], "host child cleanup did not pass")
    external._validate_cleanup(cleanup["control"]["reply"])
    baseline = external._residents(initial["residents"])
    external._residents(report["residents"], baseline)
    check = report["generator_selfcheck"]
    external.capacity_preflight.validate_identity(check)
    need(set(check.get("client_nofile_soft_limits", {})) == set(capacity.ROUTE_ORDER)
         and all(type(value) is int and value >= 8192 for value in check["client_nofile_soft_limits"].values()),
         "selfcheck client descriptor capacity is insufficient")
    need(check["passed"] is True and check["scope"] == "load-generator-selfcheck"
         and check["capacity_evidence"] is False and check["rate_per_second"] == 256
         and check["duration_seconds"] == 60 and check["summary"]["completed"] == 15360
         and check["summary"]["failed"] == 0 and check["cleanup"]["passed"] is True
         and check["cleanup"]["server_stopped"] is True, "host generator self-capacity check failed")
    rates = (1,) if preflight else capacity.RATES
    schedule = report.get("schedule")
    stopped_at = schedule.get("stopped_at_rejection") if isinstance(schedule, dict) else None
    if stopped_at is not None:
        need(preflight is False, "schedule saturation stop is not a preflight end-state")
        need(schedule.get("phase0_complete") is False, "schedule marker asserts Phase 0 completion")
        need(type(stopped_at) is int and stopped_at in rates,
             "schedule stopped_at_rejection is not a frozen rate")
        need(report["rates"] and report["rates"][-1]["rate_per_second"] == stopped_at
             and report["rates"][-1].get("accepted") is False,
             "saturated schedule must end at the recorded rejected window")
        need(all(case.get("accepted") is True for case in report["rates"][:-1]),
             "saturated schedule must end at the first rejected window")
    expected_rates = list(rates[:rates.index(stopped_at) + 1]) if stopped_at is not None else list(rates)
    need([case["rate_per_second"] for case in report["rates"]] == expected_rates,
         "trial rate sequence is incomplete")
    next_id = 0
    for case, rate in zip(report["rates"], expected_rates):
        phase(case["warmup"]["summary"], _rows(case, "warmup_raw_outcomes"), rate, 60, next_id, baseline)
        phase(case["measurement"]["summary"], _rows(case, "raw_outcomes"), rate, 120, next_id + rate * 60, baseline)
        next_id += rate * 180
    # Project only already-verified fields into the strict capacity gate
    # comparator. Guest-control reports deliberately have passed:false because
    # control/transport evidence is not itself a capacity verdict.
    projected = {key: deepcopy(report[key]) for key in ("schema_version", "backend", "scope", "passed",
        "payload_sha256", "configuration", "expected_limits", "fixtures", "environment", "rates")}
    projected["configuration"].pop("generator_placement")
    projected["configuration"].pop("transport")
    projected["identity"] = {"runtime_identities": initial["payload"]["runtime_identities"],
                              "collector": initial["collector"], "generator_sources": generator["source_files_sha256"],
                              "qemu_executable_sha256": qemu.get("executable_sha256")}
    projected["image"] = report["image"]
    projected["cleanup"] = {"attempted": True, "passed": True, "errors": []}
    projected["capacity_rps"] = report.get("capacity_rps")
    if stopped_at is not None:
        projected["schedule"] = deepcopy(schedule)
    if not preflight:
        errors = capacity_compare._report_errors(projected)
        need(not errors, "original strict comparator rejects this trial: " + "; ".join(errors))
    return projected


def compare(reports):
    try:
        need(len(reports) == 6, "exactly six reports are required")
        need(len({r["run_id"] for r in reports}) == 6, "capacity reports repeat a run identity")
        need(len({r["environment"]["vm_id"] for r in reports}) == 6, "capacity reports repeat a VM identity")
        projected = [validate(report) for report in reports]
        result = capacity_compare.compare_reports(projected)
        result["external_instrument_valid"] = result["comparable"]
        result["phase0_complete"] = False
        return result
    except (KeyError, TypeError, ValueError, capacity.CapacityError) as error:
        return {"comparable": False, "passed": False, "external_instrument_valid": False,
                "phase0_complete": False, "reasons": [str(error)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true", help="Validate one preflight, never close a gate")
    parser.add_argument("reports", nargs="+")
    args = parser.parse_args()
    try:
        values = []
        for name in args.reports:
            path = Path(name)
            need(path.is_file() and not path.is_symlink(), "report must be a regular file")
            values.append(external._finite_json(json.loads(path.read_text(), object_pairs_hook=external._unique_object)))
            receipt = json.loads(path.with_name("launcher-cleanup.json").read_text())
            need(receipt == {"phase0_complete": False, "graceful_shutdown": True, "launcher_exit": 0},
                 "launcher/graceful guest cleanup did not pass")
        if args.preflight:
            need(len(values) == 1, "one preflight report is required")
            validate(values[0], preflight=True)
            result = {"passed": True, "scope": "external-generator-path-preflight",
                      "capacity_evidence": False, "phase0_complete": False}
        else:
            result = compare(values)
    except (OSError, KeyError, TypeError, ValueError, capacity.CapacityError) as error:
        result = {"passed": False, "phase0_complete": False, "reasons": [str(error)]}
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
