#!/usr/bin/env python3
"""Compare complete, matched fixture-memory reports without running workloads."""

import argparse
import json
import math
from pathlib import Path
import re
from statistics import median


SCOPE = "fixture-process-memory"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ENVIRONMENT = ("architecture", "kernel", "os_release_sha256", "libc_sha256")
RUNTIME = ("binary_sha256", "version", "packages_sha256")
CONFIG = ("argv", "env", "workers", "requests", "concurrency")
LIMITS = ("memory.max", "memory.swap.max", "cpu.max", "pids.max")
WINDOW = {
    "warmup_seconds": 5,
    "sample_interval_seconds": 1,
    "sample_count": 10,
    "peak_scope": "fresh-cgroup-lifetime",
}


def _digest(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 2**63 - 1


def _number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _fields(value, names):
    return isinstance(value, dict) and all(name in value for name in names)


def _case_errors(case):
    errors = []
    if not isinstance(case, dict):
        return ["case must be an object"]
    if not isinstance(case.get("name"), str) or not case["name"]:
        errors.append("case name is required")
    if case.get("passed") is not True:
        errors.append("fixture did not pass")
    if case.get("cleanup_passed") is not True:
        errors.append("cleanup did not pass")
    if not _digest(case.get("fixture_sha256")):
        errors.append("fixture digest is missing or invalid")

    runtime = case.get("runtime")
    if not _fields(runtime, RUNTIME) or not _digest(runtime["binary_sha256"]) \
            or not _digest(runtime["packages_sha256"]) \
            or not isinstance(runtime["version"], str) or not runtime["version"]:
        errors.append("runtime binary, package digest and version are required")

    config = case.get("config")
    if not _fields(config, CONFIG):
        errors.append("process configuration is incomplete")
    else:
        argv, env = config["argv"], config["env"]
        if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv) \
                or not argv[0] or not isinstance(env, dict) \
                or not all(isinstance(key, str) and key and isinstance(value, str)
                           for key, value in env.items()) \
                or not _integer(config["workers"], 1) \
                or type(config["requests"]) is not int or config["requests"] != 0 \
                or type(config["concurrency"]) is not int or config["concurrency"] != 1:
            errors.append("process configuration must describe an idle, single-instance fixture")

    limits = case.get("limits")
    if not _fields(limits, LIMITS):
        errors.append("actual cgroup limits are incomplete")
    else:
        patterns = {"memory.max": r"[1-9][0-9]*", "memory.swap.max": r"[0-9]+",
                    "cpu.max": r"[1-9][0-9]* [1-9][0-9]*", "pids.max": r"[1-9][0-9]*"}
        if any(not isinstance(limits[key], str) or re.fullmatch(pattern, limits[key]) is None
               for key, pattern in patterns.items()):
            errors.append("actual cgroup limits must be finite numeric settings")

    window = case.get("window")
    if not _fields(window, WINDOW) or any(window[key] != value for key, value in WINDOW.items()) \
            or not all(_number(window[key]) for key in ("warmup_seconds", "sample_interval_seconds")) \
            or not _integer(window["sample_count"], 1):
        errors.append("sampling window must contain ten one-second samples after five seconds of warmup")

    samples = case.get("samples")
    if not isinstance(samples, list) or len(samples) != WINDOW["sample_count"]:
        errors.append("complete raw memory samples are required")
    else:
        previous_time = None
        previous_peak = 0
        for sample in samples:
            if not _fields(sample, ("elapsed_seconds", "memory_current_bytes", "memory_peak_bytes")):
                errors.append("memory sample is incomplete")
                break
            elapsed, current, peak = (sample["elapsed_seconds"], sample["memory_current_bytes"],
                                      sample["memory_peak_bytes"])
            if not _number(elapsed) or elapsed < WINDOW["warmup_seconds"] \
                    or not _integer(current, 1) or not _integer(peak, 1) or current > peak \
                    or peak < previous_peak:
                errors.append("memory samples must contain valid live counters and monotonic lifetime peaks")
                break
            if previous_time is None and elapsed > 7:
                errors.append("first sample must be taken between five and seven seconds")
                break
            if elapsed > 18:
                errors.append("sampling must finish within eighteen seconds")
                break
            if previous_time is not None and not 0.8 - 1e-9 <= elapsed - previous_time <= 2 + 1e-9:
                errors.append("actual samples must be between 0.8 and two seconds apart")
                break
            previous_time, previous_peak = elapsed, peak
    return errors


def _report_errors(report):
    if not isinstance(report, dict):
        return ["report must be an object"]
    errors = []
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        errors.append("unsupported report schema")
    if report.get("backend") not in ("native", "docker"):
        errors.append("backend must be native or docker")
    if report.get("passed") is not True:
        errors.append("report did not pass")
    if report.get("scope") != SCOPE or report.get("phase0_complete") is not False:
        errors.append("report must cover fixture memory without claiming Phase 0 completion")
    environment = report.get("environment")
    if not _fields(environment, ENVIRONMENT) \
            or not all(isinstance(environment[key], str) and environment[key] for key in ENVIRONMENT) \
            or not _digest(environment["os_release_sha256"]) or not _digest(environment["libc_sha256"]):
        errors.append("kernel, architecture, OS and libc identities are required")
    cases = report.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("report needs fixture cases")
    else:
        names = set()
        for index, case in enumerate(cases):
            errors.extend(f"case {index + 1}: {error}" for error in _case_errors(case))
            name = case.get("name") if isinstance(case, dict) else None
            if isinstance(name, str):
                if name in names:
                    errors.append("fixture names must be unique")
                names.add(name)
    return errors


def compare_reports(first, second):
    """Return observations only when both reports establish the same experiment."""
    result = {"scope": SCOPE, "phase0_complete": False, "storage_comparison": None,
              "comparable": False, "reasons": [], "cases": []}
    for index, report in enumerate((first, second), 1):
        result["reasons"].extend(f"report {index}: {error}" for error in _report_errors(report))
    if result["reasons"]:
        return result
    if first["backend"] == second["backend"]:
        result["reasons"].append("one native report and one Docker report are required")
        return result
    reports = {report["backend"]: report for report in (first, second)}
    native, docker = reports["native"], reports["docker"]
    for key in ENVIRONMENT:
        if native["environment"][key] != docker["environment"][key]:
            result["reasons"].append(f"environment {key} differs")
    cases = {backend: {case["name"]: case for case in report["cases"]}
             for backend, report in reports.items()}
    if cases["native"].keys() != cases["docker"].keys():
        result["reasons"].append("fixture case sets differ")
    if result["reasons"]:
        return result

    for name in sorted(cases["native"]):
        left, right = cases["native"][name], cases["docker"][name]
        compared = {"name": name, "comparable": False, "reasons": []}
        if left["fixture_sha256"] != right["fixture_sha256"]:
            compared["reasons"].append("fixture content differs")
        for group, keys in (("runtime", RUNTIME), ("config", CONFIG), ("limits", LIMITS), ("window", WINDOW)):
            for key in keys:
                if left[group][key] != right[group][key]:
                    compared["reasons"].append(f"{group} {key} differs")
        for index, maximum, label in ((0, 2, "first"), (-1, 3, "last")):
            if abs(left["samples"][index]["elapsed_seconds"]
                   - right["samples"][index]["elapsed_seconds"]) > maximum:
                compared["reasons"].append(f"actual {label}-sample times differ by more than {maximum} seconds")
        if not compared["reasons"]:
            compared["comparable"] = True
            compared["memory_current_median_bytes"] = {
                backend: median(sample["memory_current_bytes"] for sample in cases[backend][name]["samples"])
                for backend in ("native", "docker")
            }
            compared["memory_lifetime_peak_bytes"] = {
                backend: max(sample["memory_peak_bytes"] for sample in cases[backend][name]["samples"])
                for backend in ("native", "docker")
            }
        result["cases"].append(compared)
    result["comparable"] = all(case["comparable"] for case in result["cases"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    try:
        result = compare_reports(json.loads(args.first.read_text()), json.loads(args.second.read_text()))
    except (OSError, ValueError) as error:
        result = {"scope": SCOPE, "phase0_complete": False, "storage_comparison": None,
                  "comparable": False, "reasons": [str(error)], "cases": []}
    print(json.dumps(result, indent=2))
    return 0 if result["comparable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
