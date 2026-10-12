#!/usr/bin/env python3
"""Measure fixed fixtures in an explicit local Docker image; never pull or build."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

import benchmark

DOCKER = ("docker", "--host", "unix:///var/run/docker.sock")
LABEL = "halvo.native-lab-benchmark"
CGROUP_ROOT = Path("/sys/fs/cgroup")
LIMITS = benchmark.LIMITS
IDENTIFIER = re.compile(r"[0-9a-f]{64}\Z")


def call(*argv, timeout=30, check=True):
    return subprocess.run(argv, check=check, capture_output=True, text=True, timeout=timeout)


def describe_error(error):
    # Only our fixed fixture launches may echo output. In particular, never
    # include inspect stdout: image/container configuration can contain env.
    if isinstance(error, subprocess.CalledProcessError) \
            and tuple(error.cmd[:5]) == (*DOCKER, "container", "start"):
        details = [f"Fixture launch failed with exit code {error.returncode}"]
        for name, output in (("stdout", error.stdout), ("stderr", error.stderr)):
            if output:
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                details.append(f"{name}: {output[-4096:].strip()}")
        return "\n".join(details)
    return str(error)


def inspect_container(identifier):
    if not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Docker returned an invalid container identity")
    value = json.loads(call(*DOCKER, "container", "inspect", identifier).stdout)
    if len(value) != 1 or value[0].get("Id") != identifier:
        raise RuntimeError("Docker container identity changed")
    return value[0]


def validate_image(image):
    if not isinstance(image, str) or not image.startswith("sha256:") \
            or not IDENTIFIER.fullmatch(image[7:]):
        raise ValueError("--image must be an exact local sha256 image ID")
    value = json.loads(call(*DOCKER, "image", "inspect", image).stdout)
    if len(value) != 1 or value[0].get("Id") != image:
        raise RuntimeError("The requested image is unavailable locally")
    config = value[0].get("Config", {})
    if config.get("Volumes"):
        raise ValueError("Benchmark images must not declare automatic volumes")
    inherited = config.get("Env")
    if inherited is None:
        inherited = []
    if not isinstance(inherited, list):
        raise ValueError("Benchmark image environment must be a list")
    seen = set()
    for entry in inherited:
        if not isinstance(entry, str) or "=" not in entry:
            raise ValueError("Benchmark image contains a malformed environment entry")
        key = entry.split("=", 1)[0]
        if key not in benchmark.ENV or key in seen:
            raise ValueError("Benchmark image environment must contain only unique overridden keys")
        seen.add(key)


def create_container(image, run_id, purpose, argv, owned):
    name = f"halvo-memory-{run_id}-{purpose}"
    command = [*DOCKER, "container", "create", "--pull", "never", "--name", name,
               "--label", f"{LABEL}={run_id}", "--network", "none", "--read-only",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--user", "1000:1000",
               "--memory", "256m", "--memory-swap", "256m", "--cpus", "0.5",
               "--pids-limit", "128", "--ulimit", "nofile=256:256",
               "--ulimit", "nproc=128:128", "--restart", "no", "--stop-timeout", "3",
               "--no-healthcheck", "--log-driver", "local", "--log-opt", "max-size=1m",
               "--log-opt", "max-file=1", "--log-opt", "compress=false", "--workdir", "/app"]
    for key, value in sorted(benchmark.ENV.items()):
        command.extend(("--env", f"{key}={value}"))
    command.extend(("--entrypoint", argv[0], image, *argv[1:]))
    identifier = call(*command).stdout.strip()
    if not IDENTIFIER.fullmatch(identifier):
        raise RuntimeError("Docker did not return a complete created container ID")
    owned.append(identifier)
    return identifier


def remove_owned(identifier, run_id):
    state = inspect_container(identifier)
    if state.get("Config", {}).get("Labels", {}).get(LABEL) != run_id:
        raise RuntimeError("Refusing cleanup of a container without this run's ownership label")
    call(*DOCKER, "container", "rm", "--force", identifier)


def image_json(image, run_id, purpose, args, owned):
    identifier = create_container(image, run_id, purpose,
                                  ["/usr/bin/python3", "/app/benchmark.py", *args], owned)
    result = call(*DOCKER, "container", "start", "--attach", identifier, timeout=60)
    state = inspect_container(identifier)["State"]
    if state.get("Running") or state.get("ExitCode") != 0:
        raise RuntimeError("Image identity inspection failed")
    return json.loads(result.stdout)


def process_identity(pid):
    return (Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def container_cgroup(pid, identifier):
    rows = [line.split(":", 2) for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()]
    unified = [row[2] for row in rows if row[:2] == ["0", ""]]
    if len(unified) != 1 or not unified[0].startswith("/") or ".." in Path(unified[0]).parts:
        raise RuntimeError("Container must use an identifiable cgroups v2 subtree")
    path = CGROUP_ROOT / unified[0].lstrip("/")
    if path.name not in (identifier, f"docker-{identifier}.scope"):
        raise RuntimeError("Container cgroup does not match its complete Docker ID")
    if path.resolve(strict=True) != path:
        raise RuntimeError("Container cgroup path contains a symlink")
    return path


def check_running(identifier, pid, started):
    state = inspect_container(identifier)["State"]
    if not state.get("Running") or state.get("OOMKilled") or state.get("Pid") != pid \
            or process_identity(pid) != started:
        raise RuntimeError("Fixture exited, restarted, or was killed during measurement")


def checkpoint(pid):
    return int(Path(f"/proc/{pid}/root/tmp/checkpoint").read_text())


def ready(identifier, pid, started, fixture):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        check_running(identifier, pid, started)
        try:
            if fixture["port"] is None:
                if checkpoint(pid) >= 1:
                    return
            else:
                # Enter only networking: this client remains outside the
                # measured container cgroup, mount and process namespaces.
                program = ("from urllib.request import build_opener,ProxyHandler; import sys; "
                           "r=build_opener(ProxyHandler({})).open(sys.argv[1],timeout=1); "
                           "assert r.status == 200; "
                           "assert r.read().decode() == sys.argv[2]")
                response = call("nsenter", f"--net=/proc/{pid}/ns/net", "--",
                                "/usr/bin/python3", "-c", program,
                                f"http://127.0.0.1:{fixture['port']}/", fixture["response"],
                                timeout=3, check=False)
                if response.returncode == 0:
                    return
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.2)
    raise TimeoutError("Fixture readiness timed out")


def limits_at(cgroup):
    return {name: (cgroup / name).read_text().strip() for name in LIMITS}


def cgroup_empty(cgroup):
    try:
        events = dict(row.split() for row in (cgroup / "cgroup.events").read_text().splitlines())
        return events.get("populated") == "0"
    except FileNotFoundError:
        return True


def measure_case(name, fixture, image, run_id, runtime, owned):
    result = {"name": name, "passed": False, "cleanup_passed": False,
              "fixture_sha256": benchmark.fixture_digest(fixture), "runtime": runtime,
              "config": benchmark.fixture_config(fixture), "window": dict(benchmark.WINDOW),
              "samples": []}
    identifier = create_container(image, run_id, name, fixture["argv"], owned)
    cgroup = None
    try:
        call(*DOCKER, "container", "start", identifier)
        state = inspect_container(identifier)
        pid = state["State"]["Pid"]
        started = process_identity(pid)
        cgroup = container_cgroup(pid, identifier)
        result.update(container_id=identifier, cgroup=str(cgroup), pid=pid,
                      pid_start_time=started, limits=limits_at(cgroup))
        if result["limits"] != LIMITS:
            raise RuntimeError("Effective container resource limits differ from the fixture profile")
        ready(identifier, pid, started, fixture)
        sample_started = time.monotonic()
        time.sleep(benchmark.WINDOW["warmup_seconds"])
        initial_checkpoint = checkpoint(pid) if fixture["port"] is None else None
        for index in range(benchmark.WINDOW["sample_count"]):
            if index:
                time.sleep(benchmark.WINDOW["sample_interval_seconds"])
            check_running(identifier, pid, started)
            sample = benchmark.sample_cgroup(cgroup)
            sample["elapsed_seconds"] = round(time.monotonic() - sample_started, 6)
            result["samples"].append(sample)
        check_running(identifier, pid, started)
        if fixture["port"] is not None:
            ready(identifier, pid, started, fixture)
        if initial_checkpoint is not None and checkpoint(pid) <= initial_checkpoint:
            raise RuntimeError("Worker checkpoint stopped advancing")
        result["passed"] = True
    except Exception as error:
        result["error"] = describe_error(error)
    finally:
        try:
            remove_owned(identifier, run_id)
            owned.remove(identifier)
            if cgroup is not None and not cgroup_empty(cgroup):
                raise RuntimeError("Fixture cgroup remains populated after container removal")
            result["cleanup_passed"] = True
        except Exception as error:
            result["cleanup_error"] = str(error)
            result["passed"] = False
    return result


def collect(image):
    if os.geteuid() != 0:
        raise RuntimeError("Local root access is required to inspect fixture cgroups and network namespaces")
    validate_image(image)
    run_id = uuid.uuid4().hex
    owned = []
    report = {"schema_version": 1, "backend": "docker", "passed": False,
              "scope": "fixture-process-memory", "phase0_complete": False,
              "image": image, "run_id": run_id, "cases": [], "cleanup_errors": []}
    try:
        report["environment"] = image_json(image, run_id, "environment", ["--environment"], owned)
        # The container uses the host kernel, regardless of its image OS.
        if report["environment"].get("kernel") != os.uname().release:
            raise RuntimeError("Image environment does not describe this local daemon's kernel")
        runtimes = {}
        for name, fixture in benchmark.FIXTURES.items():
            actual = image_json(image, run_id, f"digest-{name}", ["--fixture-digest", name], owned)
            if actual != benchmark.fixture_digest(fixture):
                raise RuntimeError(f"Image bytes do not match the {name} fixture")
            runtime = fixture["runtime"]
            if runtime not in runtimes:
                runtimes[runtime] = image_json(image, run_id, f"identity-{runtime}",
                                              ["--identity", runtime], owned)
            case = measure_case(name, fixture, image, run_id, runtimes[runtime], owned)
            report["cases"].append(case)
            if not case["passed"]:
                break
        report["passed"] = len(report["cases"]) == len(benchmark.FIXTURES) \
            and all(case["passed"] for case in report["cases"])
    except Exception as error:
        report["error"] = describe_error(error)
    finally:
        for identifier in list(owned):
            try:
                remove_owned(identifier, run_id)
            except Exception as error:
                report["cleanup_errors"].append(str(error))
        if report["cleanup_errors"]:
            report["passed"] = False
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Existing local sha256:<64 hex digits> image ID")
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise TimeoutError("Docker fixture benchmark interrupted or exceeded ten minutes")
    previous = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGALRM)}
    signal.alarm(10 * 60)
    try:
        try:
            report = collect(args.image)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            parser.error(str(error))
    finally:
        signal.alarm(0)
        for kind, handler in previous.items():
            signal.signal(kind, handler)
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
