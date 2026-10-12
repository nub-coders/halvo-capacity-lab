#!/usr/bin/env python3
"""Fixed, idle workload memory measurements inside the disposable NsJail lab.

The health client stays outside the measured cgroup. These are process-memory
samples, not host totals, disk savings, latency, or a Phase 0 exit decision.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import uuid

from guard import require_lab
import probe

ENV = {"PATH": "/opt/node/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}
WINDOW = {"warmup_seconds": 5, "sample_interval_seconds": 1, "sample_count": 10,
          "peak_scope": "fresh-cgroup-lifetime"}
LIMITS = {"memory.max": "268435456", "memory.swap.max": "0",
          "cpu.max": "50000 100000", "pids.max": "128"}
FIXTURES = {
    "node": {
        "files": {"node.js": "require('node:http').createServer((q,r)=>r.end('halvo-memory')).listen(3000,'127.0.0.1');\n"},
        "argv": ["/opt/node/bin/node", "/app/node.js"], "runtime": "node",
        "port": 3000, "response": "halvo-memory", "workers": 1,
    },
    "python": {
        "files": {"server.py": "from http.server import BaseHTTPRequestHandler\nfrom socketserver import TCPServer\nclass Handler(BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(200)\n        self.end_headers()\n        self.wfile.write(b'halvo-memory')\n    def log_message(self, *args):\n        pass\nwith TCPServer(('127.0.0.1', 3000), Handler) as server:\n    server.serve_forever()\n"},
        # Fixed stdlib fixtures must not load distro/user startup hooks from
        # site-packages outside the fingerprinted runtime tree.
        "argv": ["/usr/bin/python3", "-I", "-S", "/app/server.py"], "runtime": "python",
        "port": 3000, "response": "halvo-memory", "workers": 1,
    },
    "worker": {
        "files": {"worker.py": "import time\nfrom pathlib import Path\ntick = 0\nwhile True:\n    temporary = Path('/tmp/checkpoint.tmp')\n    temporary.write_text(str(tick))\n    temporary.replace('/tmp/checkpoint')\n    tick += 1\n    time.sleep(0.2)\n"},
        "argv": ["/usr/bin/python3", "-I", "-S", "/app/worker.py"], "runtime": "python",
        "port": None, "response": "", "workers": 1,
    },
    "static": {
        "files": {"site/index.html": "halvo-memory",
                  "nginx.conf": "worker_processes 1;\npid /tmp/nginx.pid;\nerror_log stderr warn;\nevents { worker_connections 32; }\nhttp { access_log off; client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; server { listen 127.0.0.1:3000; root /app/site; } }\n"},
        "argv": ["/usr/sbin/nginx", "-c", "/app/nginx.conf", "-g", "daemon off;"],
        "runtime": "nginx", "port": 3000, "response": "halvo-memory", "workers": 1,
    },
}
BINARIES = {"node": "/opt/node/bin/node", "python": "/usr/bin/python3", "nginx": "/usr/sbin/nginx"}


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fixture_digest(fixture):
    return hashlib.sha256(json.dumps(fixture["files"], sort_keys=True).encode()).hexdigest()


def fixture_config(fixture):
    return {"argv": fixture["argv"], "env": ENV, "workers": fixture["workers"],
            "requests": 0, "concurrency": 1}


def write_fixtures(root):
    for fixture in FIXTURES.values():
        for name, content in fixture["files"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o644)


def runtime_identity(runtime):
    binary = BINARIES[runtime]
    flag = "-v" if runtime == "nginx" else "--version"
    version = subprocess.run([binary, flag], check=True, capture_output=True,
                             text=True, timeout=30)
    # Include extension dependencies as well as the interpreter's own libs.
    # For example, Python loads libbz2/liblzma through stdlib extensions.
    paths = set()
    executables = [binary]
    if runtime == "python":
        paths.update(str(path) for path in Path("/usr/lib/python3.12").rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
        executables.extend(sorted(path for path in paths if path.endswith('.so')))
    linked = subprocess.run(["ldd", *executables], check=True, capture_output=True,
                            text=True, timeout=120)
    paths.update(word.removesuffix(':') for word in linked.stdout.split() if word.startswith("/"))
    packages = hashlib.sha256()
    for path in sorted(paths):
        packages.update((path + "\0" + digest(path) + "\n").encode())
    return {"binary_sha256": digest(binary),
            "version": (version.stdout + version.stderr).strip(),
            "packages_sha256": packages.hexdigest()}


def environment():
    return {"architecture": platform.machine(), "kernel": platform.release(),
            "os_release_sha256": digest("/etc/os-release"),
            "libc_sha256": digest("/lib/x86_64-linux-gnu/libc.so.6")}


def sample_cgroup(group):
    values = {}
    for name in ("memory.current", "memory.peak", "pids.current"):
        values[name] = int((group / name).read_text())
    for name in ("memory.stat", "memory.events", "cpu.stat"):
        values[name] = {key: int(value) for key, value in
                        (line.split() for line in (group / name).read_text().splitlines())}
    if values["pids.current"] <= 0 or any(values["memory.events"].get(key, 0)
                                          for key in ("oom", "oom_kill")):
        raise RuntimeError("Workload exited or hit its memory limit")
    return {"memory_current_bytes": values["memory.current"],
            "memory_peak_bytes": values["memory.peak"],
            "memory_stat": values["memory.stat"], "memory_events": values["memory.events"],
            "pids_current": values["pids.current"], "cpu_stat": values["cpu.stat"]}


def pid_identity(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def jail_pid(group):
    host_net = Path("/proc/self/ns/net").stat().st_ino
    for pid in (group / "cgroup.procs").read_text().split():
        try:
            if Path(f"/proc/{pid}/ns/net").stat().st_ino != host_net:
                return int(pid)
        except FileNotFoundError:
            continue
    raise RuntimeError("No isolated workload process yet")


def ready(pid, fixture):
    if fixture["port"] is None:
        path = Path(f"/proc/{pid}/root/tmp/checkpoint")
        return path.is_file() and path.read_text().strip().isdigit()
    result = subprocess.run(["nsenter", f"--net=/proc/{pid}/ns/net", "--",
                             "curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "2",
                             f"http://127.0.0.1:{fixture['port']}/"],
                            capture_output=True, text=True, timeout=5)
    return result.returncode == 0 and result.stdout == fixture["response"]


def native_case(name, workspace):
    fixture = FIXTURES[name]
    unit = f"halvo-memory-{name}-{uuid.uuid4().hex[:12]}.service"
    config_path = workspace / f"{name}.cfg"
    root = workspace / "root"
    config = probe.configuration(runtime=240)
    config = config.replace(probe.mount(probe.LAB / "root", "/"), probe.mount(root, "/"))
    config = config.replace(probe.mount(probe.APP, "/app", True),
                            probe.mount(workspace / "app", "/app"))
    config = config.replace(probe.mount('/quota/app-a', '/data', True), "")
    config = config.replace('rlimit_nproc_type: HARD', 'rlimit_nproc: 128')
    config_path.write_text(config)
    case = {"name": name, "passed": False, "cleanup_passed": False,
            "fixture_sha256": fixture_digest(fixture), "runtime": runtime_identity(fixture["runtime"]),
            "config": fixture_config(fixture), "window": WINDOW, "samples": []}
    group = None
    captured = {}
    try:
        probe.call("systemd-run", "--quiet", f"--unit={unit}",
                   "--property=Type=exec", "--property=MemoryAccounting=yes",
                   "--property=CPUAccounting=yes", "--property=MemoryMax=256M",
                   "--property=MemorySwapMax=0", "--property=CPUQuota=50%",
                   "--property=CPUQuotaPeriodSec=100ms", "--property=TasksMax=128",
                   "--property=LimitNOFILE=256", "--property=KillMode=control-group",
                   "--property=RuntimeMaxSec=240s", "--property=TimeoutStopSec=3s",
                   "--property=OOMPolicy=kill", "--property=StandardOutput=null",
                   f"--property=StandardError=append:{workspace / (name + '.log')}",
                   "/usr/local/bin/nsjail", "--config", str(config_path), "--", *fixture["argv"])
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            state = probe.properties(unit)
            if state.get("ActiveState") not in ("active", "activating"):
                raise RuntimeError(f"Workload failed before readiness: {state.get('Result')}")
            group = Path("/sys/fs/cgroup") / state["ControlGroup"].lstrip("/")
            try:
                pid = jail_pid(group)
                if ready(pid, fixture):
                    break
            except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired):
                pass
            time.sleep(0.25)
        else:
            raise TimeoutError("Workload did not become ready")
        invocation = state["InvocationID"]
        process_start = pid_identity(pid)
        checkpoint = Path(f"/proc/{pid}/root/tmp/checkpoint")
        before_tick = int(checkpoint.read_text()) if fixture['port'] is None else None
        case["limits"] = {key: (group / key).read_text().strip() for key in LIMITS}
        if case["limits"] != LIMITS:
            raise RuntimeError("Effective cgroup limits differ from the benchmark specification")
        case["evidence"] = {"unit": unit, "invocation_id": invocation,
                            "nsjail_sha256": digest("/usr/local/bin/nsjail"),
                            "policy_sha256": digest("/opt/halvo-lab/syscalls.policy"),
                            "configuration_sha256": digest(config_path)}
        started = time.monotonic()
        for index in range(WINDOW["sample_count"]):
            # Schedule from one clock origin. Sleeping after each observation
            # would add systemd/TCG overhead to every interval and stretch it.
            deadline = started + WINDOW['warmup_seconds'] + index * WINDOW['sample_interval_seconds']
            time.sleep(max(0, deadline - time.monotonic()))
            state = probe.properties(unit)
            if state.get("InvocationID") != invocation or state.get("ActiveState") != "active" \
                    or pid_identity(pid) != process_start:
                raise RuntimeError("Measured workload exited or restarted")
            sample = sample_cgroup(group)
            sample["elapsed_seconds"] = time.monotonic() - started
            case["samples"].append(sample)
        if not ready(pid, fixture):
            raise RuntimeError("Workload failed the post-sample health check")
        if before_tick is not None and int(checkpoint.read_text()) <= before_tick:
            raise RuntimeError("Worker made no progress during sampling")
        case["passed"] = True
    except Exception as error:
        case["error"] = str(error)
    finally:
        cleanup_errors = []
        try:
            if group is not None:
                try:
                    for pid in (group / "cgroup.procs").read_text().split():
                        try:
                            captured[pid] = pid_identity(pid)
                        except FileNotFoundError:
                            pass
                except FileNotFoundError:
                    pass
        except Exception as error:
            cleanup_errors.append(str(error))
        # Even a failed cgroup read must not bypass stopping the owned unit.
        try:
            stopped = subprocess.run(["systemctl", "stop", unit], capture_output=True,
                                     text=True, timeout=15)
            if stopped.returncode:
                raise RuntimeError("Stopping the benchmark unit failed")
        except Exception as error:
            cleanup_errors.append(str(error))
        try:
            survivors = []
            for pid, identity in captured.items():
                try:
                    if pid_identity(pid) == identity:
                        survivors.append(pid)
                except FileNotFoundError:
                    pass
            populated = group is not None and group.exists() and bool((group / "cgroup.procs").read_text().split())
            if survivors or populated:
                raise RuntimeError("Workload processes survived cleanup")
        except Exception as error:
            cleanup_errors.append(str(error))
        try:
            probe.call("systemctl", "reset-failed", unit, check=False)
        except Exception as error:
            cleanup_errors.append(str(error))
        case["cleanup_passed"] = not cleanup_errors
        if cleanup_errors:
            case["cleanup_error"] = "; ".join(cleanup_errors)
            case["passed"] = False
    return case


def run_native():
    if require_lab() != "qemu":
        raise SystemExit("Memory measurements require the disposable QEMU guest")
    # Guard precedes every mutation, including removing a stale report.
    output = Path("/results/benchmark.json")
    output.unlink(missing_ok=True)
    for name in ("docker", "podman", "containerd"):
        if shutil.which(name):
            raise RuntimeError("The native benchmark guest must remain Docker-free")
    units = probe.call("systemctl", "list-units", "--state=active", "--no-legend", "--plain", "halvo-*").stdout
    if units.strip():
        raise RuntimeError("Another Halvo lab workload is active; refusing a mixed measurement")
    report = {"schema_version": 1, "backend": "native", "passed": False,
              "scope": "fixture-process-memory", "phase0_complete": False,
              "environment": environment(), "cases": [],
              "boot_id": Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              "note": "Idle process memory including NsJail; excludes total-host, storage and build costs. TCG timings are not production latency."}
    Path("/srv/halvo-lab").mkdir(exist_ok=True)
    # Keep owned logs/configs for diagnosis; there are no tenant files here.
    workspace = Path(tempfile.mkdtemp(prefix="memory-", dir="/srv/halvo-lab"))
    workspace.chmod(0o755)
    for directory in ("usr", "bin", "lib", "lib64", "opt/node", "app", "tmp", "data", "dev", "proc"):
        (workspace / "root" / directory).mkdir(parents=True, exist_ok=True)
    for device in ("null", "zero", "urandom"):
        (workspace / "root" / "dev" / device).touch()
    write_fixtures(workspace / "app")
    for name in FIXTURES:
        report["cases"].append(native_case(name, workspace))
        output.write_text(json.dumps(report, indent=2) + "\n")
        if not report['cases'][-1]['passed']:
            break
    report["passed"] = len(report['cases']) == len(FIXTURES) and all(
        case["passed"] and case["cleanup_passed"] for case in report["cases"])
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--identity", choices=BINARIES)
    group.add_argument("--environment", action="store_true")
    group.add_argument("--fixture-digest", choices=FIXTURES)
    args = parser.parse_args()
    if args.identity:
        print(json.dumps(runtime_identity(args.identity)))
    elif args.environment:
        print(json.dumps(environment()))
    elif args.fixture_digest:
        files = {name: (Path('/app') / name).read_text()
                 for name in FIXTURES[args.fixture_digest]['files']}
        print(json.dumps(fixture_digest({'files': files})))
    else:
        result = run_native()
        print(json.dumps({"passed": result["passed"], "cases": len(result["cases"])}))
        raise SystemExit(0 if result["passed"] else 1)
