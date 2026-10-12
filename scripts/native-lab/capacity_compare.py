#!/usr/bin/env python3
"""Strict, read-only comparison of approved Phase 0 capacity reports.

The collector is intentionally separate from this module.  This comparator
does not start a process, inspect a host, or infer a missing measurement.  It
only accepts complete ``capacity.json`` objects and applies the predeclared
request-capacity gate to the evidence they contain.
"""

import argparse
import json
import math
from pathlib import Path
import re
from statistics import median


SCHEMA_VERSION = 1
SCOPE = "request-capacity"
BACKENDS = ("native", "docker")
ROUTES = ("python", "static", "node")
WEIGHTS = {"python": 70, "static": 20, "node": 10}
RATES = (1, 2, 4, 8, 16, 32, 64, 128)
WARMUP_SECONDS = 60
SAMPLE_SECONDS = 120
REQUEST_TIMEOUT_SECONDS = 30.0

# This is the fixed fixture profile from benchmark.py.  The comparator keeps
# the values local so reading a report never imports or executes collector
# code.
LIMITS = {
    "memory.max": "268435456",
    "memory.swap.max": "0",
    "cpu.max": "50000 100000",
    "pids.max": "128",
}

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")

# Gate constants are fractions for error/percentage comparisons.  The floors
# are milliseconds and are applied as an absolute allowance as well as the
# relative allowance.
CAPACITY_RATIO = 0.95
ERROR_RATE_MARGIN = 0.005
ERROR_RATE_MAX = 0.01
LATENCY_LIMITS = {
    "p50": (0.15, 100.0),
    "p95": (0.20, 250.0),
    "p99": (0.25, 500.0),
}

_MISSING = object()


def _finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 2**63 - 1


def _digest(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _image_digest(value):
    return isinstance(value, str) and IMAGE_ID.fullmatch(value) is not None


def _same_json(left, right):
    """Compare JSON values without accepting NaN as an accidental wildcard."""
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":"),
                          allow_nan=False) == json.dumps(
                              right, sort_keys=True, separators=(",", ":"),
                              allow_nan=False)
    except (TypeError, ValueError):
        return False


def _json_value(value):
    """Return whether *value* is a finite JSON value."""
    if value is None or isinstance(value, (str, bool)):
        return True
    if type(value) in (int, float):
        try:
            return math.isfinite(value)
        except OverflowError:
            return False
    if isinstance(value, list):
        return all(_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _json_value(item)
                   for key, item in value.items())
    return False


def _append_unique(errors, message):
    if message not in errors:
        errors.append(message)


def _alias(source, names, label, errors, required=True):
    """Read one logical field from an object with a small alias set.

    Multiple spellings are allowed only when they carry identical values.  A
    report with two conflicting spellings is ambiguous and is rejected.
    """
    present = [(name, source[name]) for name in names if name in source]
    if not present:
        if required:
            errors.append(f"{label} is missing")
        return _MISSING
    first_name, first_value = present[0]
    for name, value in present[1:]:
        if not _same_json(first_value, value):
            errors.append(f"{label} has conflicting aliases {first_name} and {name}")
    return first_value


def _percentile(values, quantile):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile / 100.0
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _close(left, right, absolute=1e-6, relative=1e-6):
    return math.isclose(left, right, abs_tol=absolute, rel_tol=relative)


def _error_count(value, label, errors):
    """Normalize numeric, mapping, or list error evidence to one count."""
    if type(value) is int:
        if value < 0:
            errors.append(f"{label} must not be negative")
            return None
        return value
    if isinstance(value, dict):
        total = 0
        for key, count in value.items():
            if not isinstance(key, str) or not _integer(count):
                errors.append(f"{label} must contain non-negative integer counts")
                return None
            total += count
        return total
    if isinstance(value, list):
        return len(value)
    errors.append(f"{label} must be a count, error map, or error list")
    return None


def _metric_number(source, names, label, errors, minimum=0.0):
    value = _alias(source, names, label, errors)
    if value is _MISSING:
        return None
    if not _finite_number(value) or value < minimum:
        errors.append(f"{label} must be a finite number >= {minimum}")
        return None
    return float(value)


def _normalize_image(report, errors):
    if "image" not in report:
        if report.get("backend") == "docker":
            errors.append("Docker image identity is missing")
        return None
    image = report["image"]
    if report.get("backend") == "native":
        if image is not None:
            errors.append("native reports must not carry a Docker image identity")
        return None
    if _image_digest(image):
        return image
    if not isinstance(image, dict):
        errors.append("Docker image identity must be sha256:<64-hex> or an identity object")
        return None
    allowed = {"id", "digest"}
    if set(image) - allowed or not image:
        errors.append("Docker image identity has missing or extra fields")
        return None
    values = []
    for key in image:
        if not _image_digest(image[key]):
            errors.append("Docker image identity contains an invalid digest")
        else:
            values.append(image[key])
    if values and len(set(values)) != 1:
        errors.append("Docker image identity fields disagree")
        return None
    return values[0] if values else None


def _normalize_limits(report, config_sources, errors):
    values = []
    for source_name, source in config_sources:
        if not isinstance(source, dict):
            continue
        for key in ("limits", "expected_limits"):
            if key in source:
                values.append((f"{source_name}.{key}", source[key]))
    for key in ("limits", "expected_limits"):
        if key in report:
            values.append((f"report.{key}", report[key]))
    if not values:
        errors.append("limits are missing")
        return None
    first_name, first = values[0]
    if not isinstance(first, dict):
        errors.append(f"{first_name} must be an object")
        return None
    if set(first) != set(LIMITS) or any(first[key] != LIMITS[key] for key in LIMITS):
        errors.append("limits do not match the fixed fixture profile")
    for name, value in values[1:]:
        if not _same_json(first, value):
            errors.append(f"{name} differs from the fixed limits")
    return dict(first)


def _normalize_configuration(report, errors):
    containers = []
    for key in ("configuration", "config"):
        if key in report:
            value = report[key]
            if not isinstance(value, dict):
                errors.append(f"{key} must be an object")
            else:
                containers.append((f"report.{key}", value))

    if not containers:
        # A few approved report writers flatten this object.  Supporting the
        # flat spelling does not weaken validation: every required field is
        # still required and unknown config keys are still refused.
        flat_names = {
            "mix", "routes", "route_order", "weights", "route_weights",
            "route_weights_percent", "rates", "rates_per_second",
            "warmup_seconds", "sample_seconds", "measurement_seconds",
            "limits", "expected_limits", "request_timeout_seconds", "schedule",
        }
        flat = {key: report[key] for key in flat_names if key in report}
        if flat:
            containers.append(("report", flat))
        else:
            errors.append("configuration is missing")

    allowed = {
        "mix", "routes", "route_order", "weights", "route_weights",
        "route_weights_percent", "rates", "rates_per_second", "warmup_seconds",
        "sample_seconds", "measurement_seconds", "limits", "expected_limits",
        "request_timeout_seconds", "schedule",
    }
    for name, source in containers:
        extras = sorted(set(source) - allowed)
        if extras:
            errors.append(f"{name} has extra configuration fields: {', '.join(extras)}")

    def logical(names, label, required=True):
        values = []
        for name, source in containers:
            value = _alias(source, names, label, errors, required=False)
            if value is not _MISSING:
                values.append((name, value))
        if not values:
            if required:
                errors.append(f"{label} is missing")
            return _MISSING
        first_name, first = values[0]
        for name, value in values[1:]:
            if not _same_json(first, value):
                errors.append(f"{label} differs between configuration objects")
        return first

    routes = logical(("routes", "route_order"), "routes")
    if routes is not _MISSING:
        if not isinstance(routes, list) or tuple(routes) != ROUTES:
            errors.append("routes must be exactly python, static, node in that order")

    weights = logical(("weights", "route_weights", "route_weights_percent"), "route weights")
    if weights is not _MISSING:
        if not isinstance(weights, dict) or set(weights) != set(WEIGHTS):
            errors.append("route weights have missing or extra routes")
        elif any(type(weights[key]) is not int or weights[key] != WEIGHTS[key]
                 for key in WEIGHTS):
            errors.append("route weights do not match the fixed mix")

    rates = logical(("rates", "rates_per_second"), "rates")
    if rates is not _MISSING:
        if not isinstance(rates, list) or tuple(rates) != RATES:
            errors.append("rates must be exactly 1, 2, 4, 8, 16, 32, 64, 128")

    warmup = logical(("warmup_seconds",), "warmup_seconds")
    if warmup is not _MISSING and (type(warmup) is not int
                                   or not _finite_number(warmup)
                                   or warmup != WARMUP_SECONDS):
        errors.append("warmup_seconds must be exactly 60")

    sample = logical(("sample_seconds", "measurement_seconds"), "sample_seconds")
    if sample is not _MISSING and (type(sample) is not int
                                   or not _finite_number(sample)
                                   or sample != SAMPLE_SECONDS):
        errors.append("sample_seconds must be exactly 120")

    mix = logical(("mix",), "mix", required=False)
    if mix is not _MISSING:
        valid_mix = False
        if isinstance(mix, list):
            valid_mix = tuple(mix) == ROUTES
        elif isinstance(mix, dict):
            valid_mix = set(mix) == set(WEIGHTS) and all(
                type(mix[key]) is int and mix[key] == WEIGHTS[key] for key in WEIGHTS)
        elif isinstance(mix, str):
            valid_mix = mix in ("fixed", "request-capacity", "python:70,static:20,node:10")
        if not valid_mix:
            errors.append("mix does not match the fixed request mix")

    # These are collector metadata rather than gate inputs, but if present
    # they are fixed and must not silently vary between trials.
    for names, label, expected in (
        (("request_timeout_seconds",), "request_timeout_seconds", REQUEST_TIMEOUT_SECONDS),
        (("schedule",), "schedule", "fixed-open-loop-deterministic-cycle"),
    ):
        value = logical(names, label) if any(
            any(name in source for name in names) for _, source in containers) else _MISSING
        if value is not _MISSING and value != expected:
            errors.append(f"{label} does not match the fixed collector configuration")

    limits = _normalize_limits(report, containers, errors)
    return {
        "routes": list(ROUTES),
        "weights": dict(WEIGHTS),
        "rates": list(RATES),
        "warmup_seconds": WARMUP_SECONDS,
        "sample_seconds": SAMPLE_SECONDS,
        "limits": limits,
        "mix": mix if mix is not _MISSING else {"routes": list(ROUTES), "weights": dict(WEIGHTS)},
    }


def _normalize_latency(source, label, errors):
    if not isinstance(source, dict):
        errors.append(f"{label} latency evidence must be an object")
        return None
    count = _alias(source, ("count", "sample_count"), f"{label} latency count", errors)
    if count is _MISSING or not _integer(count, 1):
        errors.append(f"{label} latency count must be a positive integer")
        count = None
    values = {}
    for percentile_name in ("p50", "p95", "p99"):
        value = _alias(source, (percentile_name, percentile_name + "_ms"),
                       f"{label} {percentile_name}", errors)
        if value is _MISSING or not _finite_number(value) or value < 0:
            errors.append(f"{label} {percentile_name} must be a finite non-negative number")
        else:
            values[percentile_name] = float(value)
    if len(values) == 3 and not (values["p50"] <= values["p95"] <= values["p99"]):
        errors.append(f"{label} latency percentiles are not monotonic")
    return {"count": count, **values}


def _normalize_summary(source, expected_count, label, errors):
    if not isinstance(source, dict):
        errors.append(f"{label} aggregate must be an object")
        return None

    counts = {}
    for field, aliases in (
        ("scheduled", ("scheduled", "requested", "requests", "request_count", "total_requests")),
        ("completed", ("completed", "completed_requests")),
        ("successful", ("successful", "successes", "successful_requests")),
    ):
        value = _alias(source, aliases, f"{label} {field}", errors)
        if value is _MISSING or not _integer(value):
            errors.append(f"{label} {field} must be a non-negative integer")
        else:
            counts[field] = value

    error_values = []
    declared_error_rates = []
    if "error_count" in source:
        error_values.append(("error_count", source["error_count"]))
    if "failed" in source:
        error_values.append(("failed", source["failed"]))
    if "failure_count" in source:
        error_values.append(("failure_count", source["failure_count"]))
    if "errors" in source:
        error_evidence = source["errors"]
        if isinstance(error_evidence, dict) and any(
                key in error_evidence for key in ("count", "error_count")):
            error_values.append(("errors.count", error_evidence.get(
                "count", error_evidence.get("error_count"))))
            for key in ("rate", "error_rate"):
                if key in error_evidence:
                    declared_error_rates.append((f"errors.{key}", error_evidence[key], False))
            if "rate_percent" in error_evidence:
                declared_error_rates.append(("errors.rate_percent",
                                             error_evidence["rate_percent"], True))
        else:
            error_values.append(("errors", error_evidence))
    if not error_values:
        errors.append(f"{label} error count is missing")
        error_count = None
    else:
        normalized_errors = []
        for name, value in error_values:
            count = _error_count(value, f"{label} {name}", errors)
            if count is not None:
                normalized_errors.append((name, count))
        error_count = normalized_errors[0][1] if normalized_errors else None
        if normalized_errors and any(count != error_count for _, count in normalized_errors[1:]):
            errors.append(f"{label} error count fields disagree")

    if counts and expected_count is not None and counts.get("scheduled") != expected_count:
        errors.append(f"{label} scheduled count must be {expected_count}")
    if counts and counts.get("completed") != counts.get("scheduled"):
        errors.append(f"{label} completed count does not cover the scheduled requests")
    if all(field in counts for field in ("scheduled", "completed", "successful")):
        if counts["successful"] > counts["completed"]:
            errors.append(f"{label} successful count exceeds completed count")
        if error_count is not None and error_count != counts["completed"] - counts["successful"]:
            errors.append(f"{label} error count does not match successful count")

    if "error_rate" in source:
        declared_error_rates.append(("error_rate", source["error_rate"], False))
    if "error_rate_percent" in source:
        declared_error_rates.append(("error_rate_percent", source["error_rate_percent"], True))

    rate_value = _MISSING
    normalized_declared_rates = []
    for name, raw_rate, is_percent in declared_error_rates:
        if not _finite_number(raw_rate) or raw_rate < 0 or raw_rate > 100:
            errors.append(f"{label} {name} must be a finite rate from 0 through 100")
            continue
        if is_percent:
            normalized_declared_rates.append((name, float(raw_rate) / 100.0))
        else:
            # Reports in the lab have used both fractions (0.005) and
            # percentage points (0.5).  The request counts below disambiguate
            # them without allowing an inconsistent rate through.
            normalized_declared_rates.append((name, float(raw_rate)))
            normalized_declared_rates.append((name, float(raw_rate) / 100.0))
    if normalized_declared_rates:
        rate_value = normalized_declared_rates[0][1]

    derived_rate = None
    if error_count is not None and counts.get("scheduled"):
        derived_rate = error_count / counts["scheduled"]
        choices = []
        for name, raw_rate, is_percent in declared_error_rates:
            if is_percent:
                choices.append((name, float(raw_rate) / 100.0))
            else:
                choices.extend(((name, float(raw_rate)),
                                (name, float(raw_rate) / 100.0)))
        if choices:
            matching = [value for _, value in choices if _close(value, derived_rate)]
            if not matching:
                errors.append(f"{label} error_rate does not match error count")
            else:
                rate_value = derived_rate
        else:
            rate_value = derived_rate
    elif rate_value is _MISSING:
        errors.append(f"{label} error_rate cannot be derived")
        rate_value = None

    goodput = _alias(source, ("goodput_rps", "goodput"), f"{label} goodput_rps", errors)
    if goodput is _MISSING or not _finite_number(goodput) or goodput < 0:
        errors.append(f"{label} goodput_rps must be a finite non-negative number")
        goodput_value = None
    else:
        goodput_value = float(goodput)
        if counts.get("successful") is not None:
            expected_goodput = counts["successful"] / SAMPLE_SECONDS
            if not _close(goodput_value, expected_goodput, absolute=1e-5, relative=1e-6):
                errors.append(f"{label} goodput_rps does not match successful requests")

    latency_source = _alias(source, ("latency_ms", "latency", "latency_percentiles"),
                            f"{label} latency", errors, required=False)
    if latency_source is _MISSING and any(
            key in source for key in ("p50", "p95", "p99", "p50_ms", "p95_ms", "p99_ms")):
        latency_source = {
            "count": source.get("latency_count", source.get("count", _MISSING)),
            **{key: source[key] for key in ("p50", "p95", "p99", "p50_ms", "p95_ms", "p99_ms")
               if key in source},
        }
    latency = _normalize_latency(latency_source, label, errors) \
        if latency_source is not _MISSING else None
    if latency_source is _MISSING:
        errors.append(f"{label} latency percentile evidence is missing")

    return {
        **counts,
        "error_count": error_count,
        "error_rate": rate_value,
        "goodput_rps": goodput_value,
        "latency_ms": latency,
    }


def _latency_digest(case, errors):
    digest_values = []
    for key in ("latency_evidence_sha256", "outcome_sha256", "evidence_sha256",
                "raw_outcomes_sha256", "raw_latency_sha256", "raw_evidence_sha256",
                "latency_digest", "evidence_digest"):
        if key in case:
            digest_values.append((key, case[key]))
    for key in ("latency_evidence", "evidence"):
        value = case.get(key, _MISSING)
        if value is _MISSING:
            continue
        if isinstance(value, str):
            digest_values.append((key, value))
        elif isinstance(value, dict):
            for nested in ("sha256", "digest", "latency_sha256", "outcome_sha256",
                           "raw_outcomes_sha256", "raw_latency_sha256",
                           "raw_evidence_sha256"):
                if nested in value:
                    digest_values.append((f"{key}.{nested}", value[nested]))
    valid = []
    for key, value in digest_values:
        if not _digest(value):
            errors.append(f"{key} is not a SHA-256 evidence digest")
        else:
            valid.append(value)
    if valid and len(set(valid)) != 1:
        errors.append("latency evidence digests disagree")
    return valid[0] if valid else None


def _outcome_latency_values(raw, label, errors):
    """Return ``(all_values, per_route_values, row_counts)`` for raw evidence."""
    all_values = []
    per_route = {route: [] for route in ROUTES}
    row_counts = {route: 0 for route in ROUTES}
    seen_ids = set()

    if isinstance(raw, dict):
        if set(raw) != set(ROUTES):
            errors.append(f"{label} raw outcomes have missing or extra routes")
            return all_values, per_route, row_counts
        groups = [(route, raw[route]) for route in ROUTES]
    elif isinstance(raw, list):
        grouped = {route: [] for route in ROUTES}
        for row in raw:
            if not isinstance(row, dict) or row.get("route") not in grouped:
                errors.append(f"{label} raw outcomes must identify one fixed route")
                continue
            grouped[row["route"]].append(row)
        groups = [(route, grouped[route]) for route in ROUTES]
    else:
        errors.append(f"{label} raw outcomes must be a route map or list")
        return all_values, per_route, row_counts

    for route, rows in groups:
        if not isinstance(rows, list):
            errors.append(f"{label} raw outcomes for {route} must be a list")
            continue
        for row in rows:
            if not isinstance(row, dict):
                errors.append(f"{label} raw outcome for {route} must be an object")
                continue
            if "route" in row and row["route"] != route:
                errors.append(f"{label} raw outcome route is inconsistent")
            if "id" not in row or not _integer(row["id"]):
                errors.append(f"{label} raw outcome for {route} has an invalid id")
            elif row["id"] in seen_ids:
                errors.append(f"{label} raw outcomes contain a duplicate id")
            else:
                seen_ids.add(row["id"])
            if "ok" in row and not isinstance(row["ok"], bool):
                errors.append(f"{label} raw outcome ok must be boolean")
            if "status" in row and row["status"] is not None \
                    and (not _integer(row["status"], 100) or row["status"] > 599):
                errors.append(f"{label} raw outcome status is invalid")
            latency = row.get("latency_ms", row.get("latency", _MISSING))
            row_counts[route] += 1
            if latency is _MISSING or latency is None:
                continue
            if not _finite_number(latency) or latency < 0:
                errors.append(f"{label} contains invalid latency evidence")
                continue
            value = float(latency)
            all_values.append(value)
            per_route[route].append(value)
    return all_values, per_route, row_counts


def _validate_percentile_evidence(case, aggregate, routes, expected_route_counts, errors):
    raw = _MISSING
    for key in ("raw_outcomes", "outcomes", "raw", "latency_samples", "latencies"):
        if key in case:
            raw = case[key]
            break
    digest = _latency_digest(case, errors)
    all_values = []
    per_route_values = {route: [] for route in ROUTES}
    row_counts = {route: 0 for route in ROUTES}
    if raw is not _MISSING:
        if isinstance(raw, str) and _digest(raw):
            digest_values = [digest, raw] if digest is not None else [raw]
            if len(set(digest_values)) != 1:
                errors.append("latency evidence digests disagree")
            digest = raw
            raw = _MISSING
        else:
            all_values, per_route_values, row_counts = _outcome_latency_values(raw, "case", errors)
        if digest is not None:
            # A digest accompanying raw evidence is useful, but the raw values
            # remain authoritative for the percentile check.
            pass
        if raw is not _MISSING:
            for route in ROUTES:
                if row_counts[route] != expected_route_counts[route]:
                    errors.append(f"case raw outcome count for {route} is incomplete")
    elif digest is None:
        errors.append("case needs raw outcome/latency evidence or a valid evidence digest")

    def check_percentiles(summary, label, values):
        latency = summary.get("latency_ms") if summary else None
        if not latency:
            return
        count = latency.get("count")
        if values:
            if count != len(values):
                errors.append(f"{label} latency count does not match raw evidence")
            for percentile_name, quantile in (("p50", 50), ("p95", 95), ("p99", 99)):
                expected = _percentile(values, quantile)
                observed = latency.get(percentile_name)
                if expected is not None and observed is not None \
                        and not _close(observed, expected):
                    errors.append(f"{label} {percentile_name} does not match raw evidence")
        elif count is not None and count < 1:
            errors.append(f"{label} latency evidence is empty")

    check_percentiles(aggregate, "aggregate", all_values)
    for route in ROUTES:
        check_percentiles(routes.get(route), f"route {route}", per_route_values[route])

    # Raw outcomes are expected to carry enough data to validate every route's
    # latency percentiles.  A digest-only report is accepted only after the
    # structural percentile checks above.
    if raw is not _MISSING and any(not per_route_values[route] for route in ROUTES):
        errors.append("raw latency evidence is incomplete for one or more routes")


def _status_health(value, label, errors, require_marker=True):
    """Validate readiness/health evidence without interpreting request errors."""
    if isinstance(value, bool):
        if not value:
            errors.append(f"{label} is false")
        elif require_marker:
            return
        return
    if not isinstance(value, (dict, list)):
        errors.append(f"{label} health evidence must be an object or list")
        return
    marker = False

    def visit(node, path):
        nonlocal marker
        if isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}[{index}]")
            return
        if not isinstance(node, dict):
            return
        for key, child in node.items():
            current = f"{path}.{key}"
            if key in ("ready", "healthy", "passed", "ok"):
                if not isinstance(child, bool):
                    errors.append(f"{current} must be boolean")
                elif not child:
                    errors.append(f"{current} is false")
                else:
                    marker = True
            elif key == "bottleneck":
                if child is not False:
                    errors.append(f"{current} reports a failure")
                else:
                    marker = True
            elif key == "oom_killed":
                if child is not False:
                    errors.append(f"{current} reports a failure")
            elif key in ("ooms", "oom", "oom_kill", "oom_kills", "restarts", "restart_count"):
                if not _integer(child) or child != 0:
                    errors.append(f"{current} reports OOM or restart activity")
            elif key in ("errors", "failures", "health_errors"):
                if child not in (None, [], {}, 0, ""):
                    errors.append(f"{current} is non-empty")
            elif key in ("aborted", "generator_bottleneck"):
                if child is not False:
                    errors.append(f"{current} reports an aborted or bottlenecked run")
            visit(child, current)

    visit(value, label)
    if require_marker and not marker:
        errors.append(f"{label} has no successful health marker")


def _validate_generator(value, expected_count, label, errors):
    if not isinstance(value, dict):
        errors.append(f"{label} generator health is missing or not an object")
        return
    if not any(key in value for key in ("bottleneck", "healthy", "passed", "ok", "scheduled")):
        errors.append(f"{label} generator health has no status evidence")
    _status_health(value, label, errors)
    counts = []
    for key in ("scheduled", "dispatched", "completed", "requests"):
        if key in value:
            if not _integer(value[key]):
                errors.append(f"{label}.{key} must be a non-negative integer")
            else:
                counts.append((key, value[key]))
    if counts:
        first = counts[0][1]
        if any(count != first for _, count in counts[1:]):
            errors.append(f"{label} generator counts disagree")
        if expected_count is not None and first != expected_count:
            errors.append(f"{label} generator count must be {expected_count}")
    elif expected_count is not None:
        errors.append(f"{label} generator count is missing")
    for key in ("max_dispatch_lag_ms", "p95_dispatch_lag_ms", "max_queue_lag_ms"):
        if key in value and (not _finite_number(value[key]) or value[key] < 0):
            errors.append(f"{label}.{key} must be a finite non-negative number")


def _extract_case_health(case, report, errors, expected_count):
    readiness = case.get("readiness", _MISSING)
    if readiness is _MISSING and isinstance(case.get("health"), dict):
        readiness = case["health"].get("readiness", _MISSING)
    if readiness is _MISSING:
        readiness = report.get("readiness", _MISSING)
    if readiness is _MISSING:
        readiness = report.get("residents", _MISSING)
    if readiness is _MISSING:
        errors.append("readiness health evidence is missing")
    else:
        _status_health(readiness, "readiness", errors)

    generator = case.get("generator", case.get("generator_health", _MISSING))
    if generator is _MISSING and isinstance(case.get("health"), dict):
        generator = case["health"].get("generator", _MISSING)
    if generator is _MISSING:
        generator = report.get("generator", report.get("generator_health", _MISSING))
    if generator is _MISSING:
        errors.append("generator health evidence is missing")
    else:
        _validate_generator(generator, expected_count, "generator", errors)


def _normalize_case(case, rate, config, report, errors):
    label = f"rate {rate}"
    if not isinstance(case, dict):
        errors.append(f"{label} case must be an object")
        return None
    if case.get("aborted") is True or case.get("complete") is False:
        errors.append(f"{label} case is aborted or incomplete")
    for key in ("failures", "failure", "unaccounted_failures", "unaccounted_errors"):
        if key in case and case[key] not in (0, [], {}, False, None, ""):
            errors.append(f"{label} has unaccounted failures")

    case_rate = _alias(case, ("rate_per_second", "rate", "rate_rps"),
                       f"{label} rate", errors)
    if case_rate is not _MISSING and case_rate != rate:
        errors.append(f"{label} case rate does not match its fixed rate")

    accepted = case.get("accepted", _MISSING)
    passed = case.get("passed", _MISSING)
    if accepted is _MISSING and passed is _MISSING:
        errors.append(f"{label} accepted/passed status is missing")
        accepted_value = False
    else:
        if accepted is not _MISSING and not isinstance(accepted, bool):
            errors.append(f"{label} accepted must be boolean")
        if passed is not _MISSING and not isinstance(passed, bool):
            errors.append(f"{label} passed must be boolean")
        accepted_value = accepted if accepted is not _MISSING else passed
        if accepted is not _MISSING and passed is not _MISSING and accepted != passed:
            errors.append(f"{label} accepted and passed disagree")

    aggregate_source = _MISSING
    aggregate_sources = []
    if "aggregate" in case:
        aggregate_sources.append(("aggregate", case["aggregate"]))
    if isinstance(case.get("measurement"), dict):
        measurement = case["measurement"]
        aggregate_sources.append(("measurement", measurement.get("summary", measurement)))
    if "summary" in case:
        aggregate_sources.append(("summary", case["summary"]))
    if aggregate_sources:
        aggregate_source = aggregate_sources[0][1]
        for source_name, source in aggregate_sources[1:]:
            if not _same_json(aggregate_source, source):
                errors.append(f"{label} aggregate aliases disagree ({source_name})")
    if aggregate_source is _MISSING:
        errors.append(f"{label} aggregate evidence is missing")
        aggregate = None
    else:
        aggregate = _normalize_summary(aggregate_source, rate * SAMPLE_SECONDS, label, errors)

    route_candidates = []
    for source_name, candidate in (
            ("case routes", case.get("routes", _MISSING)),
            ("aggregate routes", aggregate_source.get("routes", _MISSING)
             if isinstance(aggregate_source, dict) else _MISSING),
            ("per_route", case.get("per_route", _MISSING)),
            ("route_metrics", case.get("route_metrics", _MISSING))):
        if candidate is not _MISSING:
            if not isinstance(candidate, dict) or set(candidate) != set(ROUTES):
                errors.append(f"{label} {source_name} has missing or extra entries")
            else:
                route_candidates.append((source_name, candidate))
    route_source = route_candidates[0][1] if route_candidates else _MISSING
    for source_name, candidate in route_candidates[1:]:
        if not _same_json(route_source, candidate):
            errors.append(f"{label} route aliases disagree ({source_name})")
    if not isinstance(route_source, dict) or set(route_source) != set(ROUTES):
        errors.append(f"{label} routes have missing or extra entries")
        routes = {}
    else:
        routes = {}
        for route in ROUTES:
            route_summary = _normalize_summary(
                route_source[route], rate * SAMPLE_SECONDS * WEIGHTS[route] // 100,
                f"{label} route {route}", errors)
            routes[route] = route_summary

    expected_route_counts = {
        route: rate * SAMPLE_SECONDS * WEIGHTS[route] // 100 for route in ROUTES
    }
    _validate_percentile_evidence(case, aggregate, routes, expected_route_counts, errors)
    required_count_fields = ("scheduled", "completed", "successful", "error_count")
    complete_aggregate = aggregate is not None and all(
        field in aggregate for field in required_count_fields)
    complete_routes = routes and all(
        routes.get(route) is not None
        and all(field in routes[route] for field in required_count_fields)
        for route in ROUTES)
    if complete_aggregate and complete_routes:
        total_successful = sum(routes[route]["successful"] for route in ROUTES)
        total_errors = sum(routes[route]["error_count"] for route in ROUTES)
        if aggregate["scheduled"] != sum(expected_route_counts.values()) \
                or aggregate["successful"] != total_successful \
                or aggregate["error_count"] != total_errors:
            errors.append(f"{label} aggregate counts do not equal per-route counts")
        if aggregate.get("latency_ms") and all(routes[route].get("latency_ms")
                                               for route in ROUTES):
            route_counts = sum(routes[route]["latency_ms"]["count"] for route in ROUTES)
            if aggregate["latency_ms"]["count"] != route_counts:
                errors.append(f"{label} aggregate latency count does not equal per-route counts")

    _extract_case_health(case, report, errors, rate * SAMPLE_SECONDS)
    if aggregate is not None and aggregate.get("error_rate") is not None:
        expected_accepted = aggregate["error_rate"] <= ERROR_RATE_MAX + 1e-12
        if bool(accepted_value) != expected_accepted:
            errors.append(f"{label} accepted status does not match the one-percent error budget")
    case_cleanup = case.get("cleanup", _MISSING)
    if case_cleanup is not _MISSING:
        _validate_cleanup(case_cleanup, f"{label} cleanup", errors)

    return {
        "rate_per_second": rate,
        "accepted": bool(accepted_value),
        "aggregate": aggregate,
        "routes": routes,
    }


def _validate_cleanup(value, label, errors):
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return
    if value.get("passed") is not True:
        errors.append(f"{label} did not pass")
    if "attempted" in value and value["attempted"] is not True:
        errors.append(f"{label} was not attempted")
    for key in ("errors", "failures"):
        if key in value and value[key] not in (None, [], {}, 0, ""):
            errors.append(f"{label} {key} are non-empty")
    def check_evidence(node, path):
        if isinstance(node, list):
            for index, item in enumerate(node):
                check_evidence(item, f"{path}[{index}]")
        elif isinstance(node, dict):
            for key, child in node.items():
                if key in ("owned", "stopped", "empty", "workspace_removed") \
                        and child is False:
                    errors.append(f"{path}.{key} cleanup evidence is false")
                if key == "survived" and child is True:
                    errors.append(f"{path}.{key} cleanup evidence reports a surviving process")
                check_evidence(child, f"{path}.{key}")
    check_evidence(value, label)
    _status_health(value, label, errors, require_marker=False)


def _identity_projection(report, errors):
    projection = {}
    for key in (
        "identity", "identities", "workload_identity", "fixture_identity",
        "fixture_identities", "fixtures", "runtime_identities", "environment",
    ):
        if key not in report:
            continue
        value = report[key]
        if not _json_value(value):
            errors.append(f"{key} contains invalid JSON identity evidence")
        else:
            if key == "environment" and isinstance(value, dict):
                # Boot and VM identifiers are evidence of separate trial
                # launches, not workload identity.  Stable kernel/runtime
                # fields still participate in the cross-trial match.
                value = {name: item for name, item in value.items()
                         if name not in {"boot_id", "vm_id", "run_id", "started_at", "ended_at"}}
            projection[key] = value
    return projection


def _validate_nested_limits(value, expected, label, errors):
    """Reject resident/case limit snapshots that do not equal the profile."""
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_nested_limits(item, expected, f"{label}[{index}]", errors)
    elif isinstance(value, dict):
        for key, child in value.items():
            if key in ("limits", "enforced_limits", "expected_limits"):
                if not isinstance(child, dict) or child != expected:
                    errors.append(f"{label}.{key} differs from the fixed limits")
            _validate_nested_limits(child, expected, f"{label}.{key}", errors)


def _normalize_report(report):
    errors = []
    if not isinstance(report, dict):
        return None, ["report must be an object"]
    if type(report.get("schema_version")) is not int or report["schema_version"] != SCHEMA_VERSION:
        errors.append("unsupported report schema")
    backend = report.get("backend")
    if backend not in BACKENDS:
        errors.append("backend must be native or docker")
    if report.get("scope") != SCOPE:
        errors.append("report scope must be request-capacity")
    if report.get("passed") is not True:
        errors.append("report did not pass")

    payload_sha256 = report.get("payload_sha256", _MISSING)
    if payload_sha256 is _MISSING or not _digest(payload_sha256):
        errors.append("payload_sha256 is missing or invalid")

    image = _normalize_image(report, errors) if backend in BACKENDS else None
    config = _normalize_configuration(report, errors)
    identities = _identity_projection(report, errors)
    if config is not None and config.get("limits") is not None:
        _validate_nested_limits(report, config["limits"], "report", errors)

    for key in ("errors", "failures", "unaccounted_failures", "unaccounted_errors"):
        if key in report and report[key] not in (None, [], {}, 0, "", False):
            errors.append(f"report {key} are non-empty")

    if "cleanup" not in report:
        errors.append("cleanup evidence is missing")
    else:
        _validate_cleanup(report["cleanup"], "cleanup", errors)

    if "residents" in report:
        _status_health(report["residents"], "residents", errors)

    if "cases" in report and "rates" in report \
            and not _same_json(report["cases"], report["rates"]):
        errors.append("cases and rates evidence disagree")
    case_source = report.get("cases", report.get("rates", _MISSING))
    if case_source is _MISSING or not isinstance(case_source, list):
        errors.append("per-rate cases are missing")
        case_source = []
    # A saturation-stop report carries an explicit marker and ends at the first
    # gate-rejected window; its per-rate cases must be exactly the frozen-rate
    # prefix up to and including that rejection. Reports without the marker
    # still require all eight rates.
    schedule = report.get("schedule", _MISSING)
    stopped_at = schedule.get("stopped_at_rejection") if isinstance(schedule, dict) else _MISSING
    expected_rates = list(RATES)
    if stopped_at is not _MISSING and stopped_at is not None:
        if schedule.get("phase0_complete") is not False:
            errors.append("schedule marker asserts Phase 0 completion")
        if type(stopped_at) is not int or stopped_at not in RATES:
            errors.append("schedule stopped_at_rejection is not a fixed rate")
        else:
            expected_rates = list(RATES[:RATES.index(stopped_at) + 1])
            wall = case_source[-1] if case_source else _MISSING
            if not isinstance(wall, dict) or wall.get("rate_per_second") != stopped_at \
                    or wall.get("accepted", wall.get("passed")) is not False:
                errors.append("saturation stop must end at the recorded rejected window")
    if len(case_source) != len(expected_rates):
        errors.append("per-rate cases do not match the declared schedule end-state")

    case_by_rate = {}
    if config is not None:
        for index, case in enumerate(case_source):
            declared = case.get("rate_per_second", case.get("rate", _MISSING)) \
                if isinstance(case, dict) else _MISSING
            rate = declared if declared is not _MISSING else (
                RATES[index] if index < len(RATES) else None)
            if rate not in RATES:
                errors.append(f"case {index + 1} has an unknown rate")
                continue
            if rate in case_by_rate:
                errors.append(f"rate {rate} has duplicate cases")
                continue
            case_errors = []
            normalized_case = _normalize_case(case, rate, config, report, case_errors)
            errors.extend(f"rate {rate}: {message}" for message in case_errors)
            if normalized_case is not None:
                case_by_rate[rate] = normalized_case
    if set(case_by_rate) != set(expected_rates):
        errors.append("per-rate cases do not cover exactly the declared schedule end-state")
    if stopped_at is not _MISSING and stopped_at is not None:
        if list(case_by_rate) != expected_rates:
            errors.append("saturation-stop cases must follow the fixed rate order")
        if any(not case["accepted"] for rate, case in case_by_rate.items() if rate != stopped_at):
            errors.append("saturation stop must end at the first rejected window")

    capacity_value = report.get("capacity_rps", _MISSING)
    if capacity_value is _MISSING and "capacity" in report:
        capacity_value = report["capacity"]
    if capacity_value is not _MISSING and (
            type(capacity_value) is not int or capacity_value not in RATES):
        errors.append("capacity_rps must be one of the fixed rates")
        capacity_value = None
    derived_capacity = max((rate for rate, case in case_by_rate.items() if case["accepted"]),
                           default=None)
    if report.get("passed") is True and derived_capacity is None:
        errors.append("passed report has no accepted rate")
    if capacity_value is not _MISSING and capacity_value != derived_capacity:
        errors.append("capacity_rps does not match accepted per-rate cases")
    if capacity_value is _MISSING:
        capacity_value = derived_capacity
    accepted_rates = report.get("accepted_rates", _MISSING)
    if accepted_rates is not _MISSING:
        expected_accepted = [rate for rate in RATES
                             if rate in case_by_rate and case_by_rate[rate]["accepted"]]
        if accepted_rates != expected_accepted:
            errors.append("accepted_rates does not match accepted per-rate cases")

    return {
        "backend": backend,
        "payload_sha256": payload_sha256 if payload_sha256 is not _MISSING else None,
        "image": image,
        "config": config,
        "identities": identities,
        "cases": case_by_rate,
        "capacity_rps": capacity_value,
    }, errors


def _report_errors(report):
    """Return all structural/evidence rejection reasons for one report."""
    _, errors = _normalize_report(report)
    return errors


def _normalize_input(*reports):
    """Accept single reports, report sequences, or a sequence of all reports."""
    if len(reports) == 1 and isinstance(reports[0], (list, tuple)):
        values = list(reports[0])
    elif len(reports) == 2 and all(isinstance(item, (list, tuple)) for item in reports):
        values = list(reports[0]) + list(reports[1])
    else:
        values = list(reports)
    return values


def _backend_summary(cases, rates):
    trials = []
    for case_map in cases:
        row = {}
        for rate in rates:
            case = case_map[rate]
            aggregate = case["aggregate"]
            row[rate] = {
                "accepted": case["accepted"],
                "error_rate": aggregate["error_rate"],
                "goodput_rps": aggregate["goodput_rps"],
                "latency_ms": {key: aggregate["latency_ms"][key]
                               for key in ("p50", "p95", "p99")},
            }
        trials.append(row)
    return trials


def _median_metric(trial_rows, rate, field):
    values = [row[rate][field] for row in trial_rows]
    return median(values)


def _per_rate_comparison(native_reports, docker_reports, rate):
    native_rows = _backend_summary([item["cases"] for item in native_reports], (rate,))
    docker_rows = _backend_summary([item["cases"] for item in docker_reports], (rate,))
    native_accepted = all(row[rate]["accepted"] for row in native_rows)
    docker_accepted = all(row[rate]["accepted"] for row in docker_rows)
    result = {
        "rate_per_second": rate,
        "common_accepted": native_accepted and docker_accepted,
        "accepted": {"native": native_accepted, "docker": docker_accepted},
        "native": {"trials": [row[rate] for row in native_rows]},
        "docker": {"trials": [row[rate] for row in docker_rows]},
        "checks": {},
        "passed": None,
    }
    if not result["common_accepted"]:
        return result

    native_error = _median_metric(native_rows, rate, "error_rate")
    docker_error = _median_metric(docker_rows, rate, "error_rate")
    error_allowed = min(ERROR_RATE_MAX, docker_error + ERROR_RATE_MARGIN)
    error_passed = native_error <= error_allowed + 1e-12
    result["native"]["median"] = {
        "error_rate": native_error,
        "goodput_rps": _median_metric(native_rows, rate, "goodput_rps"),
        "latency_ms": {name: median(row[rate]["latency_ms"][name] for row in native_rows)
                       for name in LATENCY_LIMITS},
    }
    result["docker"]["median"] = {
        "error_rate": docker_error,
        "goodput_rps": _median_metric(docker_rows, rate, "goodput_rps"),
        "latency_ms": {name: median(row[rate]["latency_ms"][name] for row in docker_rows)
                       for name in LATENCY_LIMITS},
    }
    result["checks"]["error_rate"] = {
        "native": native_error,
        "docker": docker_error,
        "allowed_native": error_allowed,
        "passed": error_passed,
    }
    latency_passed = True
    result["checks"]["latency"] = {}
    for name, (ratio, floor) in LATENCY_LIMITS.items():
        native_value = result["native"]["median"]["latency_ms"][name]
        docker_value = result["docker"]["median"]["latency_ms"][name]
        allowed = max(docker_value * (1.0 + ratio), docker_value + floor)
        check_passed = native_value <= allowed + 1e-9
        latency_passed = latency_passed and check_passed
        result["checks"]["latency"][name] = {
            "native_ms": native_value,
            "docker_ms": docker_value,
            "allowed_native_ms": allowed,
            "relative_limit": ratio,
            "additive_floor_ms": floor,
            "passed": check_passed,
        }
    result["passed"] = error_passed and latency_passed
    return result


def compare_reports(*reports):
    """Compare one to three trials per backend and return a JSON-safe verdict.

    The accepted call forms are ``compare_reports(native, docker)``,
    ``compare_reports([native_trials], [docker_trials])`` and one flat
    sequence containing all report objects.  No input object is mutated.
    """
    values = _normalize_input(*reports)
    result = {
        "scope": SCOPE,
        "comparable": False,
        "passed": False,
        "rejection_reasons": [],
        "gate_failures": [],
        "reasons": [],
        "trials": {"native": 0, "docker": 0},
        "medians": {},
        "per_rate": [],
        "per_rate_comparisons": [],
    }
    if len(values) < 2:
        result["rejection_reasons"].append("one or more native and Docker reports are required")
        result["reasons"] = list(result["rejection_reasons"])
        return result
    if len(values) > 6:
        result["rejection_reasons"].append("at most three trials per backend may be compared")
        result["reasons"] = list(result["rejection_reasons"])
        return result

    normalized = []
    for index, report in enumerate(values, 1):
        item, errors = _normalize_report(report)
        if errors:
            result["rejection_reasons"].extend(
                f"report {index}: {error}" for error in errors)
        if item is not None:
            normalized.append((index, item))
    grouped = {backend: [] for backend in BACKENDS}
    for index, item in normalized:
        if item["backend"] in grouped:
            grouped[item["backend"]].append((index, item))
    result["trials"] = {backend: len(grouped[backend]) for backend in BACKENDS}
    if not grouped["native"] or not grouped["docker"]:
        result["rejection_reasons"].append("one or more native and Docker reports are required")
    if any(len(grouped[backend]) > 3 for backend in BACKENDS):
        result["rejection_reasons"].append("at most three trials per backend may be compared")
    if any(len(grouped[backend]) != 3 for backend in BACKENDS):
        result["rejection_reasons"].append("exactly three valid trials per backend are required")
    if result["rejection_reasons"]:
        result["reasons"] = list(result["rejection_reasons"])
        return result

    native = [item for _, item in grouped["native"]]
    docker = [item for _, item in grouped["docker"]]

    # Every trial must describe one identical experiment.  Backend-specific
    # Docker image identity is checked within Docker trials, while the common
    # payload and workload identities must match across both backends.
    all_items = native + docker
    reference = all_items[0]
    for item in all_items[1:]:
        if item["config"] != reference["config"]:
            result["rejection_reasons"].append("configuration differs between trials")
        if item["payload_sha256"] != reference["payload_sha256"]:
            result["rejection_reasons"].append("payload_sha256 differs between trials")
        if set(item["identities"]) != set(reference["identities"]):
            result["rejection_reasons"].append("identity fields are missing or extra between trials")
        elif any(not _same_json(item["identities"][key], reference["identities"][key])
                 for key in reference["identities"]):
            result["rejection_reasons"].append("workload identities differ between trials")
    docker_images = {item["image"] for item in docker}
    if None in docker_images or len(docker_images) != 1:
        result["rejection_reasons"].append("Docker image identities are missing or mismatched")
    if any(item["image"] is not None for item in native):
        result["rejection_reasons"].append("native reports contain Docker image identities")
    if result["rejection_reasons"]:
        result["reasons"] = list(result["rejection_reasons"])
        return result

    # A median is meaningful only for matched repetition counts.  A single
    # pair remains a valid comparison; otherwise the repetition sets must be
    # balanced so one backend cannot receive extra favorable trials.
    if len(native) != len(docker):
        result["rejection_reasons"].append("native and Docker trial counts differ")
        result["reasons"] = list(result["rejection_reasons"])
        return result

    native_capacities = [item["capacity_rps"] for item in native]
    docker_capacities = [item["capacity_rps"] for item in docker]
    native_capacity = median(native_capacities)
    docker_capacity = median(docker_capacities)
    if docker_capacity <= 0:
        result["rejection_reasons"].append("Docker median capacity is not positive")
        result["reasons"] = list(result["rejection_reasons"])
        return result
    if docker_capacity >= RATES[-1]:
        result["rejection_reasons"].append(
            f"Docker did not saturate by {RATES[-1]} requests/sec; capacity is only a lower bound")
        result["reasons"] = list(result["rejection_reasons"])
        return result
    capacity_allowed = docker_capacity * CAPACITY_RATIO
    capacity_passed = native_capacity + 1e-12 >= capacity_allowed
    result["medians"] = {
        "capacity_rps": {"native": native_capacity, "docker": docker_capacity},
        "capacity_allowed_rps": capacity_allowed,
        "trial_capacity_rps": {"native": native_capacities, "docker": docker_capacities},
    }

    # Per-rate verdicts cover the rates every trial actually measured: with a
    # saturation stop the climb ends at each backend's wall, so rates above the
    # smaller wall exist on one side only and are not comparable evidence.
    covered = set.intersection(*(
        set(item["cases"]) for item in (*native, *docker)))
    for rate in RATES:
        if rate not in covered:
            continue
        result["per_rate"].append(_per_rate_comparison(native, docker, rate))
    result["per_rate_comparisons"] = list(result["per_rate"])
    common = [row for row in result["per_rate"] if row["common_accepted"]]
    if not common:
        result["rejection_reasons"].append("native and Docker have no common accepted rate")
    rate_passed = all(row["passed"] is True for row in common)
    structural_reasons = list(result["rejection_reasons"])
    if not capacity_passed:
        message = "native median capacity is below 95% of Docker median capacity"
        result["gate_failures"].append(message)
        result["rejection_reasons"].append(message)
    if not rate_passed and common:
        message = "one or more common accepted rates fail the error or latency gate"
        result["gate_failures"].append(message)
        result["rejection_reasons"].append(message)

    result["comparable"] = not structural_reasons
    result["passed"] = result["comparable"] and capacity_passed and rate_passed
    result["reasons"] = list(result["rejection_reasons"])
    return result


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path,
                        help="two to six capacity.json report files")
    args = parser.parse_args(argv)
    values = []
    load_errors = []
    for path in args.reports:
        try:
            values.append(_load(path))
        except (OSError, ValueError) as error:
            load_errors.append(f"{path}: {error}")
    result = compare_reports(values)
    if load_errors:
        result["comparable"] = False
        result["passed"] = False
        result["rejection_reasons"] = load_errors + result["rejection_reasons"]
        result["reasons"] = list(result["rejection_reasons"])
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
