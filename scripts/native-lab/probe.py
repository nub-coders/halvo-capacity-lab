#!/usr/bin/env python3
"""Bounded real-Linux experiments, only inside the disposable native lab."""

import argparse
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import time
import uuid

from guard import require_lab

LAB = Path("/srv/halvo-lab")
OUT = Path("/results")
APP = LAB / "app-a"
DATA = Path("/quota/app-a")
UID = 65001
REBOOT_UNIT = "halvo-phase0-reboot.service"
REBOOT_CHECKPOINT = Path("/quota/app-a/reboot-checkpoint.json")


def call(*args, check=True, timeout=60):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=timeout)


def properties(unit):
    result = call("systemctl", "show", unit, check=False)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def mount(src, dst, writable=False, directory=True):
    return "mount { src: %s dst: %s is_bind: true rw: %s is_dir: %s nosuid: true }" % (
        json.dumps(str(src)), json.dumps(dst), str(writable).lower(), str(directory).lower()
    )


def configuration(runtime=45):
    lines = [
        'name: "halvo-phase0"', 'mode: ONCE', 'cwd: "/app"', 'hostname: "app-a"',
        'log_level: WARNING', f'time_limit: {runtime}', 'rlimit_as_type: INF',
        'rlimit_fsize: 64', 'rlimit_nofile: 256', 'rlimit_nproc_type: HARD',
        f'rlimit_cpu: {runtime}', 'mount_proc: true',
        f'uidmap {{ inside_id: "1000" outside_id: "{UID}" }}',
        f'gidmap {{ inside_id: "1000" outside_id: "{UID}" }}',
        'envar: "PATH=/opt/node/bin:/usr/bin:/bin"', 'envar: "HOME=/tmp"',
        'envar: "LANG=C.UTF-8"',
        'seccomp_policy_file: "/opt/halvo-lab/syscalls.policy"',
        mount(LAB / "root", "/"), mount("/usr", "/usr"), mount("/bin", "/bin"),
        mount("/lib", "/lib"), mount("/lib64", "/lib64"), mount("/opt/node", "/opt/node"),
        mount(APP, "/app", True),
        'mount { dst: "/tmp" fstype: "tmpfs" options: "size=16777216" rw: true nosuid: true nodev: true }',
    ]
    for device in ("null", "zero", "urandom"):
        lines.append(mount(f"/dev/{device}", f"/dev/{device}", True, False))
    lines.append(mount('/quota/app-a', '/data', True))
    return "\n".join(lines) + "\n"


def cgroup_snapshot(state):
    group = state.get("ControlGroup", "")
    if not group.startswith("/") or ".." in Path(group).parts:
        return {}
    root = Path("/sys/fs/cgroup") / group.lstrip("/")
    values = {}
    for name in ("cpu.max", "cpu.stat", "memory.max", "memory.peak", "memory.current",
                 "memory.events", "pids.max", "pids.current", "cgroup.events"):
        try:
            values[name] = (root / name).read_text().strip()
        except OSError as error:
            # An exited cgroup can disappear after open(), making read() return
            # ENODEV. Permission/I/O errors still invalidate the observation.
            if error.errno not in (errno.ENOENT, errno.ENODEV):
                raise
    return values


def run(label, args, memory="256M", tasks=32, expect_oom=False, runtime=45,
        expect_cpu_throttle=False, cancel_after_ready=False):
    unit = f"halvo-phase0-{label}-{uuid.uuid4().hex[:8]}.service"
    log = OUT / f"{label}.log"
    log.write_text("")
    config = LAB / "sandbox.cfg"
    config.write_text(configuration(runtime))
    started = time.monotonic()
    state = {}
    resources = {}
    observed_memory = 0
    cancelled = False
    descendants = []
    try:
        launch = call(
            "systemd-run", "--quiet", f"--unit={unit}",
            "--property=Type=exec", "--property=RemainAfterExit=yes",
            "--property=MemoryAccounting=yes", "--property=CPUAccounting=yes",
            f"--property=MemoryMax={memory}", "--property=MemorySwapMax=0",
            "--property=CPUQuota=50%", f"--property=TasksMax={tasks}",
            "--property=KillMode=control-group", "--property=TimeoutStopSec=3s",
            f"--property=RuntimeMaxSec={runtime + 5}s", "--property=OOMPolicy=kill",
            "--setenv=HALVO_LAB_HOST_SECRET=must-not-reach-the-sandbox",
            f"--property=StandardOutput=append:{log}", f"--property=StandardError=append:{log}",
            "/usr/local/bin/nsjail", "--config", str(config), "--", *args,
            check=False,
        )
        deadline = started + runtime + 10
        while time.monotonic() < deadline:
            state = properties(unit)
            snapshot = cgroup_snapshot(state)
            resources.update(snapshot)
            observed_memory = max(observed_memory, int(snapshot.get("memory.current", "0")))
            if cancel_after_ready and not cancelled and "PHASE0_READY" in log.read_text():
                group = Path("/sys/fs/cgroup") / state["ControlGroup"].lstrip("/")
                for pid in (group / "cgroup.procs").read_text().split():
                    try:
                        # Start time distinguishes a survivor from a reused PID.
                        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                        descendants.append((pid, stat[19]))
                    except FileNotFoundError:
                        pass
                call("systemctl", "stop", unit, timeout=15)
                cancelled = True
                # systemd may garbage-collect the transient unit before a later
                # poll observes SubState=dead; wait explicitly and record both.
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    state = properties(unit)
                    if not state or state.get("SubState") == "dead" \
                            or state.get("ActiveState") in ("inactive", "failed"):
                        break
                    time.sleep(0.1)
                try:
                    post_stop = (group / "cgroup.procs").read_text().split()
                except FileNotFoundError:
                    post_stop = []
                resources["post_stop_cgroup_processes"] = len(post_stop)
                resources["post_stop_state"] = {
                    key: state.get(key) for key in ("ActiveState", "SubState", "Result")
                }
                continue
            if state.get("SubState") in ("exited", "failed", "dead") or not state:
                break
            time.sleep(0.1)
        else:
            raise TimeoutError(f"{label} did not finish within its bound")
        output = log.read_text() if log.exists() else ""
        passed = (state.get("Result") == "oom-kill") if expect_oom else (
            launch.returncode == 0 and state.get("Result") == "success"
            and state.get("ExecMainStatus") == "0" and "PHASE0_PASS" in output
        )
        if expect_cpu_throttle:
            cpu_max = resources.get("cpu.max", "").split()
            cpu_stat = dict(line.split() for line in resources.get("cpu.stat", "").splitlines())
            passed = passed and len(cpu_max) == 2 and cpu_max[0] != "max" \
                and int(cpu_max[0]) * 2 == int(cpu_max[1]) \
                and int(cpu_stat.get("nr_throttled", "0")) > 0 \
                and int(cpu_stat.get("throttled_usec", "0")) > 0
        if cancel_after_ready:
            survivors = []
            for pid, start_time in descendants:
                try:
                    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                    if stat[19] == start_time:
                        survivors.append(pid)
                except FileNotFoundError:
                    pass
            # The security property is that stop terminated every descendant:
            # no survivor PIDs and an empty/removed cgroup after the stop. The
            # exact final unit SubState is systemd bookkeeping, not the property.
            stopped = not survivors and resources.get("post_stop_cgroup_processes") == 0 \
                and state.get("ActiveState") in ("inactive", "failed", None, "")
            passed = cancelled and len(descendants) >= 3 and stopped
            resources["cancelled_processes"] = len(descendants)
            resources["surviving_processes"] = survivors
        peak = resources.get("memory.peak")
        return {
            "name": label, "passed": passed,
            "duration_seconds": round(time.monotonic() - started, 3),
            "result": state.get("Result"), "exit_status": state.get("ExecMainStatus"),
            "launch_error": launch.stderr.strip() if launch.returncode else None,
            "memory_peak_bytes": int(peak) if peak and peak.isdigit() else None,
            "memory_sampled_max_bytes": observed_memory,
            "cpu_nanoseconds": state.get("CPUUsageNSec"),
            "cgroup": resources,
            "log": log.name,
        }
    finally:
        call("systemctl", "stop", unit, check=False)
        call("systemctl", "reset-failed", unit, check=False)


def python(label, source, **options):
    return run(label, ["/usr/bin/python3", "-c", source], **options)


def quota_control():
    # Use the same unprivileged UID outside the project: a root-only write
    # could still use reserved blocks on an otherwise full filesystem.
    path = Path('/quota/.quota-control')
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.fchown(fd, UID, UID)
    finally:
        os.close(fd)
    try:
        result = subprocess.run(
            ['dd', 'if=/dev/zero', f'of={path}', 'bs=1M', 'count=8', 'status=none'],
            user=UID, group=UID, extra_groups=[], capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0, result.stderr.strip()[-300:]
    finally:
        path.unlink(missing_ok=True)


def disk_quota_check(label):
    target = DATA / label
    try:
        result = python(label, f"""
from pathlib import Path
target = Path('/data') / {label!r}
try:
    with target.open('wb') as output:
        for _ in range(24): output.write(b'x' * 1024 * 1024)
except OSError as error:
    assert error.errno in (122, 28), error
    print('boundary write refused with errno', error.errno, flush=True)
else:
    raise AssertionError('Hard disk quota was not enforced')
print('PHASE0_PASS')
""")
        # Keep the refused write's allocated blocks until the control completes.
        # Unlinking first could hide global ENOSPC by freeing filesystem space.
        control_passed, control_error = quota_control()
        result["filesystem_control"] = {"passed": control_passed, "uid": UID, "error": control_error}
        result["passed"] = result["passed"] and control_passed
        return result
    finally:
        target.unlink(missing_ok=True)


def main():
    lab_kind = require_lab()
    if not Path("/quota/app-a").is_dir():
        raise RuntimeError("Required XFS project quota fixture /quota/app-a is missing")
    OUT.mkdir(exist_ok=True)
    LAB.mkdir(exist_ok=True)
    (LAB / "root").mkdir(exist_ok=True)
    # The root is read-only and owned by an unmapped UID inside NsJail. Create
    # every mount target before entering the user/mount namespace.
    for directory in ("usr", "bin", "lib", "lib64", "opt/node", "app", "tmp", "data", "dev", "proc"):
        (LAB / "root" / directory).mkdir(parents=True, exist_ok=True)
    for device in ("null", "zero", "urandom"):
        (LAB / "root" / "dev" / device).touch()
    APP.mkdir(exist_ok=True)
    os.chown(APP, UID, UID)
    (LAB / "app-b").mkdir(exist_ok=True)
    (LAB / "app-b" / "secret").write_text("other-tenant-fixture")
    Path("/root/halvo-lab-secret").write_text("host-secret-fixture")
    checks = []
    checks.append(python("filesystem", """
import os
from pathlib import Path
assert os.getuid() == 1000
assert not Path('/root/halvo-lab-secret').exists()
assert not Path('/srv/halvo-lab/app-b/secret').exists()
assert not Path('/run/systemd/private').exists()
assert not Path('/sys/fs/cgroup').exists()
assert 'HALVO_LAB_HOST_SECRET' not in os.environ
Path('/app/own-file').write_text('owned')
assert Path('/app/own-file').read_text() == 'owned'
try:
    Path('/usr/halvo-must-not-write').write_text('bad')
except OSError:
    pass
else:
    raise AssertionError('Runtime tree is writable')
status = Path('/proc/self/status').read_text()
assert 'CapEff:\\t0000000000000000' in status
assert 'NoNewPrivs:\\t1' in status
assert 'Seccomp:\\t2' in status
mounts = {line.split()[4]: line.split()[5].split(',')
          for line in Path('/proc/self/mountinfo').read_text().splitlines()}
for target in ('/', '/usr', '/bin', '/lib', '/lib64', '/opt/node'):
    assert 'ro' in mounts[target], (target, mounts[target])
assert len([p for p in Path('/proc').iterdir() if p.name.isdigit()]) <= 3
print('PHASE0_PASS')
"""))
    # Listening canaries prove that failure comes from the sandbox's namespace,
    # not from absent guest services or from the VM having no external network.
    with socket.socket(socket.AF_INET) as ipv4, socket.socket(socket.AF_INET6) as ipv6:
        ipv4.bind(('127.0.0.1', 0))
        ipv6.bind(('::1', 0))
        addresses = [(socket.AF_INET, ipv4.getsockname()), (socket.AF_INET6, ipv6.getsockname())]
        for listener, (family, address) in zip((ipv4, ipv6), addresses):
            listener.listen(4)
            with socket.socket(family) as client:
                client.settimeout(1)
                client.connect(address)
        checks.append(python("network", """
import socket
for family, address in %r:
    s = socket.socket(family)
    s.settimeout(0.5)
    try:
        assert s.connect_ex(address) != 0
    finally:
        s.close()
print('PHASE0_PASS')
""" % [(int(family), address) for family, address in addresses]))
    checks.append(python("syscalls", """
import ctypes
from pathlib import Path
libc = ctypes.CDLL(None, use_errno=True)
# getcpu(309) is normally unprivileged on x86-64 and excluded by this policy.
for syscall, args in ((165, (0, 0, 0, 0, 0)), (272, (0x10000000,)),
                      (321, (0, 0, 0)), (250, (0, 0, 0, 0, 0)), (309, (0, 0, 0))):
    assert libc.syscall(syscall, *args) == -1
    assert ctypes.get_errno() == 1
assert 'Seccomp:\\t2' in Path('/proc/self/status').read_text()
print('PHASE0_PASS')
"""))
    checks.append(run("node-http", ["/opt/node/bin/node", "-e", """
const http = require('node:http');
const server = http.createServer((req, res) => res.end('native-node'));
server.listen(3000, '127.0.0.1', async () => {
  try {
    for (let i = 0; i < 20; i++) {
      const response = await fetch('http://127.0.0.1:3000');
      if (await response.text() !== 'native-node') throw Error('wrong response');
    }
    console.log('PHASE0_PASS');
  } catch (error) { console.error(error); process.exitCode = 1; }
  finally { server.closeAllConnections(); server.close(); }
});
"""], memory="384M", tasks=64))
    checks.append(python("python-http", """
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.request import urlopen
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'native-python')
    def log_message(self, *args): pass
server = HTTPServer(('127.0.0.1', 3000), Handler)
thread = Thread(target=server.serve_forever)
thread.start()
try:
    for _ in range(20):
        assert urlopen('http://127.0.0.1:3000').read() == b'native-python'
finally:
    server.shutdown()
    server.server_close()
    thread.join()
print('PHASE0_PASS')
"""))
    checks.append(python("worker", """
import time
from pathlib import Path
for tick in range(5):
    Path('/app/worker-checkpoint').write_text(str(tick))
    time.sleep(0.2)
assert Path('/app/worker-checkpoint').read_text() == '4'
print('PHASE0_PASS')
"""))
    shutil.copytree("/opt/halvo-fixtures/static", APP / "static", dirs_exist_ok=True)
    shutil.copytree("/opt/halvo-fixtures/npm-cache", APP / "npm-cache", dirs_exist_ok=True)
    shutil.copyfile("/opt/halvo-fixtures/markupsafe.tar.gz", APP / "markupsafe.tar.gz")
    for directory, dirs, files in os.walk(APP):
        os.chown(directory, UID, UID)
        for name in files:
            os.chown(Path(directory) / name, UID, UID, follow_symlinks=False)
    checks.append(run("static-build", ["/bin/sh", "-c",
        "cd /app/static && npm ci --offline --no-audit --no-fund --cache /app/npm-cache "
        "&& npm run build && test -s dist/index.html && echo PHASE0_PASS"],
        memory="512M", tasks=64, runtime=600))
    checks.append(run("python-package-install", ["/bin/sh", "-c",
        "/usr/bin/python3 -m venv --system-site-packages /app/venv "
        "&& /app/venv/bin/python -m pip install --no-index --no-build-isolation --no-deps "
        "/app/markupsafe.tar.gz && /app/venv/bin/python -c "
        "\"import markupsafe._speedups as native; "
        "assert native.__file__.endswith('.so'), native.__file__; "
        "print('PHASE0_PASS')\""], memory="512M", tasks=64, runtime=600))
    checks.append(python("static-serving", """
from pathlib import Path
from http.client import HTTPConnection
import shutil, subprocess, time

# Fixed smoke fixtures only; immutable artifact publication belongs to Phase 2.
site_a = Path('/app/published/a')
site_b = Path('/app/published/b')
shutil.copytree('/app/static/dist', site_a, dirs_exist_ok=True)
site_b.mkdir(parents=True, exist_ok=True)
(site_b / 'index.html').write_text('<h1>Second native site</h1>')
private = Path('/app/private-source')
private.write_text('fixture-private-source')
link = site_a / 'source-link'
link.unlink(missing_ok=True)
link.symlink_to(private)
(site_a / 'listing').mkdir(exist_ok=True)
(site_a / 'listing' / 'file.txt').write_text('public file')
assert Path('/app/static/package.json').is_file()

Path('/app/nginx.conf').write_text('''
daemon off;
worker_processes 1;
pid /tmp/nginx.pid;
error_log stderr;
events { worker_connections 32; }
http {
  access_log off;
  autoindex off;
  disable_symlinks on;
  client_body_temp_path /tmp/client-body;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  server { listen 3000 default_server; server_name _; return 404; }
  server { listen 3000; server_name site-a.invalid; root /app/published/a; }
  server { listen 3000; server_name site-b.invalid; root /app/published/b; }
}
''')

def request(host, path='/'):
    connection = HTTPConnection('127.0.0.1', 3000, timeout=1)
    try:
        connection.request('GET', path, headers={'Host': host})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()

# Both virtual hosts share this one master and its one configured worker.
server = subprocess.Popen(['/usr/sbin/nginx', '-c', '/app/nginx.conf'])
try:
    for attempt in range(30):
        try:
            status, body = request('site-a.invalid')
            assert status == 200 and b'Halvo native fixture' in body
            break
        except OSError:
            if server.poll() is not None: raise RuntimeError('nginx exited')
            time.sleep(0.1)
    else: raise AssertionError('static origin never became ready')
    status_b, body_b = request('site-b.invalid')
    assert status_b == 200 and b'Second native site' in body_b and body_b != body
    assert request('unknown.invalid')[0] == 404
    assert request('site-a.invalid', '/assets/missing.js')[0] == 404
    assert request('site-a.invalid', '/package.json')[0] == 404
    assert request('site-a.invalid', '/listing/')[0] == 403
    for path in ('/source-link', '/../private-source', '/%2e%2e/%2e%2e/private-source',
                 '/%2e%2e/b/index.html', '/%2e%2e/%2e%2e/static/package.json'):
        status, content = request('site-a.invalid', path)
        assert status in (400, 403, 404), (path, status)
        assert b'fixture-private-source' not in content and b'Second native site' not in content
    assert server.poll() is None
    print('Two virtual hosts, one Nginx instance; source paths, symlinks and traversal rejected')
finally:
    server.terminate()
    server.wait(timeout=5)
print('PHASE0_PASS')
"""))
    checks.append(python("pids", """
import subprocess
children = []
limited = False
try:
    for _ in range(24):
        try:
            children.append(subprocess.Popen(['/bin/sleep', '5']))
        except BlockingIOError:
            limited = True
            break
finally:
    for child in children: child.terminate()
    for child in children: child.wait()
assert limited, 'TasksMax did not bound the process tree'
print('PHASE0_PASS')
""", tasks=12))
    checks.append(python("memory", """
blocks = []
for _ in range(48):
    blocks.append(bytearray(4 * 1024 * 1024))
raise AssertionError('MemoryMax did not enforce the limit')
""", memory="64M", expect_oom=True))
    checks.append(python("temporary-storage", """
from pathlib import Path
limited = False
try:
    with Path('/tmp/bounded-file').open('wb') as f:
        for _ in range(24): f.write(b'x' * 1024 * 1024)
except OSError as error:
    assert error.errno == 28
    limited = True
assert limited
print('PHASE0_PASS')
"""))
    checks.append(disk_quota_check("disk-quota"))
    checks.append(python("cancellation", """
import subprocess, time
child = subprocess.Popen(['/usr/bin/python3', '-c', '''
import os, signal, time
os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print('PHASE0_READY', flush=True)
while True: time.sleep(1)
'''])
while True: time.sleep(1)
""", cancel_after_ready=True))
    checks.append(python("cpu-quota", """
import time
wall = time.monotonic()
while time.monotonic() - wall < 2:
    sum(range(1000))
print('PHASE0_PASS')
""", expect_cpu_throttle=True))
    smoke_checks_pass = all(check["passed"] for check in checks)
    report = {
        "scope": ("Disposable QEMU VM. No public workloads." if lab_kind == "qemu" else
                  "Supplemental disposable nspawn environment; shares host kernel. No public workloads."),
        "nsjail_commit": "f100fd917c6d3ed0fd15d868528b735cb5fb1a1a",
        "node": call("/opt/node/bin/node", "--version").stdout.strip(),
        "python": call("/usr/bin/python3", "--version").stdout.strip(),
        "docker_absent": all(shutil.which(tool) is None for tool in ("docker", "podman", "containerd")),
        "checks": checks,
        "smoke_checks_pass": smoke_checks_pass,
        "passed": smoke_checks_pass,
        "phase0_complete": False,
        "production_ready": False,
        "guest_memory": dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines()),
        "not_yet_proven": [
            "Allowed public egress and ingress with cross-tenant packet filtering",
            "App-wide accounting of releases/cache/data against the proven disk quota",
            "Broader dependency/framework compatibility and release rollback",
            "Crash/reboot reconciliation and independent security review",
            "Production static publication/lifecycle; the shared-origin check uses fixed smoke fixtures",
            "Trusted immutable artifact publication and source validation (Phase 2)",
            "Archive/artifact traversal, cross-tenant secrets/logs and log exhaustion",
            "Equivalent Docker baseline and complete RAM/disk comparison",
        ],
    }
    (OUT / "probe.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)


def worker_count():
    state = properties(REBOOT_UNIT)
    group = state.get("ControlGroup", "")
    if state.get("ActiveState") != "active" or not group.startswith("/"):
        raise RuntimeError("Reboot worker unit is not active")
    root = Path("/sys/fs/cgroup") / group.lstrip("/")
    count = 0
    for pid in (root / "cgroup.procs").read_text().split():
        try:
            if Path(f"/proc/{pid}/cmdline").read_bytes() == b"/usr/bin/python3\0/app/reboot-worker.py\0":
                count += 1
        except FileNotFoundError:
            pass
    return count


def wait_checkpoint(ticks_after=-1, token_before=None):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            checkpoint = json.loads(REBOOT_CHECKPOINT.read_text())
            if checkpoint["ticks"] > ticks_after and checkpoint["token"] != token_before:
                if worker_count() != 1:
                    raise RuntimeError("Expected exactly one sandboxed reboot worker")
                return checkpoint
        except FileNotFoundError:
            pass
        if properties(REBOOT_UNIT).get("ActiveState") == "failed":
            raise RuntimeError("Reboot worker failed to start")
        time.sleep(0.2)
    raise TimeoutError("Reboot worker did not make progress within 45 seconds")


def prepare_reboot():
    if require_lab() != "qemu":
        raise SystemExit("Reboot checks require the disposable QEMU VM")
    if not APP.is_dir() or not Path("/quota/app-a").is_dir():
        raise RuntimeError("Run the smoke probe and provision quotas before the reboot check")
    call("systemctl", "disable", "--now", REBOOT_UNIT, check=False)
    OUT.mkdir(exist_ok=True)
    old_token = json.loads(REBOOT_CHECKPOINT.read_text())["token"] if REBOOT_CHECKPOINT.exists() else None
    (LAB / "reboot.cfg").write_text(configuration(600))
    (APP / "reboot-worker.py").write_text('''
import fcntl, json, os, time
from pathlib import Path

lock = Path('/data/reboot.lock').open('w')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
mounts = {line.split()[4]: line.split()[5].split(',')
          for line in Path('/proc/self/mountinfo').read_text().splitlines()}
assert all('ro' in mounts[target] for target in ('/', '/usr', '/bin', '/lib', '/lib64', '/opt/node'))
checkpoint = Path('/data/reboot-checkpoint.json')
restored_ticks = json.loads(checkpoint.read_text())['ticks'] if checkpoint.exists() else 0
ticks = restored_ticks
token = str(time.time_ns())
while True:
    ticks += 1
    temporary = checkpoint.with_suffix('.tmp')
    with temporary.open('w') as output:
        json.dump({'ticks': ticks, 'restored_ticks': restored_ticks,
                   'token': token, 'runtime_readonly': True}, output)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(checkpoint)
    time.sleep(1)
''')
    Path(f"/etc/systemd/system/{REBOOT_UNIT}").write_text(f"""[Unit]
Description=Disposable Halvo reboot supervision and data fixture
After=local-fs.target
RequiresMountsFor=/quota /srv/halvo-lab
[Service]
Type=exec
ExecStart=/usr/local/bin/nsjail --config /srv/halvo-lab/reboot.cfg -- /usr/bin/python3 /app/reboot-worker.py
MemoryMax=128M
MemorySwapMax=0
CPUQuota=50%
TasksMax=16
KillMode=control-group
TimeoutStopSec=3s
RuntimeMaxSec=10min
OOMPolicy=kill
StandardOutput=append:/results/reboot-worker.log
StandardError=append:/results/reboot-worker.log
[Install]
WantedBy=multi-user.target
""")
    call("systemctl", "daemon-reload")
    call("systemctl", "enable", "--now", REBOOT_UNIT)
    try:
        before = {
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "checkpoint": wait_checkpoint(token_before=old_token),
            "worker_count": worker_count(),
        }
    except Exception:
        call("systemctl", "disable", "--now", REBOOT_UNIT, check=False)
        raise
    (OUT / "reboot-before.json").write_text(json.dumps(before, indent=2) + "\n")
    print(json.dumps(before, indent=2), flush=True)


def verify_reboot():
    if require_lab() != "qemu":
        raise SystemExit("Reboot checks require the disposable QEMU VM")
    report = {
        "scope": "Systemd supervision and quota-backed worker data across a real guest reboot; not release/route reconciliation",
        "passed": False,
        "phase0_complete": False,
    }
    try:
        before = json.loads((OUT / "reboot-before.json").read_text())
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if boot_id == before["boot_id"]:
            raise RuntimeError("Guest boot ID did not change")
        checkpoint = wait_checkpoint(before["checkpoint"]["ticks"], before["checkpoint"]["token"])
        if checkpoint.get("restored_ticks", 0) < before["checkpoint"]["ticks"]:
            raise RuntimeError("Worker did not restore the pre-reboot checkpoint")
        filesystem = call("findmnt", "-n", "-o", "FSTYPE,OPTIONS", "-T", "/quota/app-a").stdout.strip()
        filesystem_type, options = filesystem.split(maxsplit=1)
        if filesystem_type != "xfs" or not ({"prjquota", "pquota"} & set(options.split(','))):
            raise RuntimeError("The XFS project-quota mount did not recover")
        count = worker_count()
        # Finish observing the worker before deliberately filling its own quota.
        call("systemctl", "stop", REBOOT_UNIT)
        quota = disk_quota_check("reboot-disk-quota")
        report.update({
            "boot_id_before": before["boot_id"], "boot_id_after": boot_id,
            "checkpoint_before": before["checkpoint"], "checkpoint_after": checkpoint,
            "worker_count": count, "filesystem": filesystem, "quota_check": quota,
            "passed": count == 1 and checkpoint["runtime_readonly"] and quota["passed"],
        })
        if not report["passed"]:
            raise RuntimeError("Reboot checks failed")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        call("systemctl", "disable", "--now", REBOOT_UNIT, check=False)
        (OUT / "reboot.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)


def execute(action="smoke"):
    # Validate before mutations and before installing cleanup. QEMU is managed
    # by the outer runner and must remain alive for result collection and reboot.
    lab_kind = require_lab()
    OUT.mkdir(exist_ok=True)
    current_report = {"smoke": "probe.json", "prepare-reboot": "reboot-before.json",
                      "verify-reboot": "reboot.json"}[action]
    for name in (current_report, "error.json"):
        (OUT / name).unlink(missing_ok=True)
    def deadline_expired(signum, frame):
        raise TimeoutError("The complete smoke probe exceeded its 20 minute bound")
    previous_handler = signal.signal(signal.SIGALRM, deadline_expired)
    signal.alarm(20 * 60)
    try:
        {"smoke": main, "prepare-reboot": prepare_reboot, "verify-reboot": verify_reboot}[action]()
    except Exception as error:
        OUT.mkdir(exist_ok=True)
        (OUT / "error.json").write_text(json.dumps({"error": str(error)}, indent=2) + "\n")
        raise
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        if lab_kind == "systemd-nspawn":
            subprocess.run(["systemctl", "poweroff"], check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--prepare-reboot", action="store_true")
    actions.add_argument("--verify-reboot", action="store_true")
    args = parser.parse_args()
    execute("prepare-reboot" if args.prepare_reboot else "verify-reboot" if args.verify_reboot else "smoke")
