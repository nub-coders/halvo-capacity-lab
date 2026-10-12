#!/usr/bin/env python3
"""Build the pinned CPython runtime tree INSIDE the disposable lab guest.

Downloads the pinned source tarball, verifies it against the manifest sha256,
builds and installs it at the production-shaped prefix
(/opt/runtimes/<kind>-<revision>), then sanity-checks the interpreter and
writes /results/runtime-tree.json as the evidence artifact.

Idempotent across the guest's bounded lifetime: if the prefix already holds an
interpreter whose recorded result matches the current manifest, the build is
skipped so a resumed run can spend its window on the next stage instead.

All argv is passed as lists (no shell), every flag is validated before use, and
every download is verified before extraction — the script runs as root in the
guest, so nothing it fetches may execute before it checks out.
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import urllib.request
import shutil

RESULT_NAME = "runtime-tree.json"
SHA256 = hashlib.sha256


def validate_manifest(raw):
    """Validate the pinned manifest fields; every field is bounded and
    shell-free because the guest runs this as root."""
    required = {"revision", "source_url", "source_sha256", "install_prefix",
                "configure_flags", "make_jobs", "notes"}
    optional = {"pip_validation", "build_resources_note"}
    if not isinstance(raw, dict) or not required <= set(raw) \
            or not set(raw) <= required | optional:
        raise ValueError(f"manifest must hold {sorted(required)} "
                         f"(plus optionally {sorted(optional)})")
    if "build_resources_note" in raw and (
            not isinstance(raw["build_resources_note"], str)
            or len(raw["build_resources_note"]) > 500):
        raise ValueError("build_resources_note must be a bounded string")
    revision = raw["revision"]
    if not isinstance(revision, str) or not revision.replace(".", "").isdigit() \
            or len(revision.split(".")) != 3:
        raise ValueError("revision must be major.minor.patch digits")
    if not isinstance(raw["source_url"], str) \
            or not raw["source_url"].startswith("https://www.python.org/ftp/python/"):
        raise ValueError("source_url must be a python.org ftp URL")
    digest = raw["source_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 \
            or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("source_sha256 must be 64 lowercase hex")
    prefix = raw["install_prefix"]
    if not isinstance(prefix, str) or not prefix.startswith("/") or ".." in prefix \
            or prefix != prefix.rstrip("/"):
        raise ValueError("install_prefix must be a clean absolute path")
    flags = raw["configure_flags"]
    if not isinstance(flags, list) or not all(isinstance(f, str) and f for f in flags) \
            or any(any(c in f for c in ";|&`$<>\n") for f in flags):
        raise ValueError("configure_flags must be clean argv words")
    if not any(f == f"--prefix={prefix}" for f in flags):
        raise ValueError("configure_flags must pin --prefix to install_prefix")
    if not isinstance(raw["make_jobs"], int) or not 1 <= raw["make_jobs"] <= 8:
        raise ValueError("make_jobs must be 1..8")
    if not isinstance(raw["notes"], list) or not all(isinstance(n, str) for n in raw["notes"]):
        raise ValueError("notes must be strings")
    if "pip_validation" in raw:
        validate_pip_section(raw["pip_validation"])
    return raw


def load_manifest(path):
    return validate_manifest(json.loads(pathlib.Path(path).read_text()))


def verify_source(path, manifest, hasher=SHA256):
    """Stream the downloaded tarball through sha256; a mismatch fails closed."""
    digest = hasher()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != manifest["source_sha256"]:
        raise ValueError(
            f"source tarball does not match the pinned sha256 "
            f"({digest.hexdigest()} != {manifest['source_sha256']}); refusing to build")


def interpreter_path(prefix, revision):
    major, minor, _ = revision.split(".")
    return f"{prefix}/bin/python{major}.{minor}"


def sanity_check(interpreter, revision, runner=subprocess.run):
    """The tree must identify itself as the pinned revision and carry pip."""
    checks = {}
    probe = runner([interpreter, "-c",
                    "import sys; print('%d.%d.%d' % sys.version_info[:3])"],
                   capture_output=True, text=True, timeout=120)
    checks["reports_pinned_revision"] = probe.returncode == 0 \
        and probe.stdout.strip() == revision
    pip = runner([interpreter, "-m", "pip", "--version"],
                 capture_output=True, text=True, timeout=120)
    checks["pip_available"] = pip.returncode == 0
    return checks


def needs_build(prefix, revision, results_dir, manifest, result_name=RESULT_NAME,
                runner=subprocess.run):
    """True unless a completed result for exactly this manifest already exists
    and its interpreter still answers the sanity probe."""
    recorded_path = pathlib.Path(results_dir) / result_name
    if not recorded_path.is_file():
        return True
    try:
        recorded = json.loads(recorded_path.read_text())
    except ValueError:
        return True
    if recorded.get("manifest") != manifest or recorded.get("reused") is not False:
        return True
    interpreter = interpreter_path(prefix, revision)
    if not pathlib.Path(interpreter).is_file():
        return True
    checks = sanity_check(interpreter, revision, runner=runner)
    return not all(checks.values())


JOURNAL_NAME = "build-journal.json"
CONFIGURE_STAMP = ".halvo-configured.json"


def configure_stamp_matches(source_dir, manifest):
    """True when a completed configure already ran with exactly these flags."""
    path = pathlib.Path(source_dir) / CONFIGURE_STAMP
    if not path.is_file():
        return False
    try:
        recorded = json.loads(path.read_text())
    except ValueError:
        return False
    return recorded == {"flags": manifest["configure_flags"]}


def write_configure_stamp(source_dir, manifest):
    path = pathlib.Path(source_dir) / CONFIGURE_STAMP
    path.write_text(json.dumps({"flags": manifest["configure_flags"]}))


def load_journal(scratch_dir, journal_name=JOURNAL_NAME):
    path = pathlib.Path(scratch_dir) / journal_name
    if not path.is_file():
        return {"windows": []}
    try:
        journal = json.loads(path.read_text())
    except ValueError:
        return {"windows": []}
    if not isinstance(journal, dict) or not isinstance(journal.get("windows"), list):
        return {"windows": []}
    return journal


def stale_objects(source_dir, killed_since):
    """Object files written during a killed window: make sees them as newer
    than their sources and links them as-is, and a truncated one fails the
    link with undefined references forever after (the nsjail lesson)."""
    stale = []
    for pattern in ("*.o", "*.a", "*.so.*", "*.so"):
        for path in pathlib.Path(source_dir).rglob(pattern):
            try:
                if path.stat().st_mtime >= killed_since:
                    stale.append(path)
            except OSError:
                continue
    return stale


def build(manifest, scratch_dir, runner=subprocess.run, download=None,
          now=time.time, journal_name=JOURNAL_NAME):
    """Download, verify, extract, configure, make, install — resumable across
    the guest's bounded windows. A full CPython build under TCG takes far more
    than one window, so the scratch tree and a window journal persist: objects
    from a killed window are recompiled, finished ones carry over. Returns the
    result payload without timestamps. `download` and `now` are injectable for
    tests."""
    started = now()
    scratch = pathlib.Path(scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    journal = load_journal(scratch_dir, journal_name)
    journal_path = scratch / journal_name
    tarball = scratch / pathlib.Path(manifest["source_url"]).name
    if download is None:
        def download(url, destination):
            request = urllib.request.Request(url, headers={"User-Agent": "halvo-lab"})
            with urllib.request.urlopen(request, timeout=300) as response, \
                    open(destination, "wb") as handle:
                shutil.copyfileobj(response, handle)
    if not tarball.is_file():
        download(manifest["source_url"], tarball)
    verify_source(tarball, manifest)

    source_dir = scratch / f"Python-{manifest['revision']}"
    if not source_dir.exists():
        runner(["tar", "-xf", str(tarball), "-C", str(scratch)], check=True, timeout=600)
    unfinished = [w for w in journal["windows"] if w.get("end") is None]
    if unfinished:
        # The last window was killed mid-make: recompile what it was writing
        # when it died, keep everything that finished before it.
        killed_since = unfinished[-1]["start"]
        stale = stale_objects(source_dir, killed_since)
        for path in stale:
            path.unlink(missing_ok=True)
    # The killed window stays in the journal with end=None — it is the honest
    # record of what happened; the new window is appended after it.
    journal["windows"].append({"start": started, "end": None,
                               "recompiled": len(stale) if unfinished else 0})
    journal_path.write_text(json.dumps(journal))

    # Configure only once: under TCG it costs most of a window's budget, and
    # re-running it every window (the cache barely helps CPython's configure)
    # was why almost no window reached make. The stamp records the exact flags
    # a completed configure ran with, so a flag change forces a fresh one and
    # an interrupted configure (no stamp) simply retries.
    configure_ran = not configure_stamp_matches(source_dir, manifest)
    steps = []
    if configure_ran:
        steps.append(["./configure", *manifest["configure_flags"]])
    steps += [
        ["make", f"-j{manifest['make_jobs']}"],
        ["make", "install"],
    ]
    for index, step in enumerate(steps):
        runner(step, check=True, timeout=7200, cwd=str(source_dir))
        if configure_ran and index == 0:
            write_configure_stamp(source_dir, manifest)
    journal["windows"][-1]["end"] = now()
    journal["windows"][-1]["configure_ran"] = configure_ran
    journal_path.write_text(json.dumps(journal))
    return {
        "manifest": manifest,
        "interpreter_path": interpreter_path(manifest["install_prefix"], manifest["revision"]),
        "build_seconds": round(now() - started, 1),
        "windows_used": len(journal["windows"]),
        "recompiled_last": journal["windows"][-1]["recompiled"],
        "configure_ran": configure_ran,
        "pgo_used": False,
        "reused": False,
    }


def write_result(results_dir, payload, result_name=RESULT_NAME):
    """Atomic evidence write: json then rename, so a torn file never reads."""
    target = pathlib.Path(results_dir)
    target.mkdir(parents=True, exist_ok=True)
    final = target / result_name
    temporary = final.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2))
    temporary.replace(final)


PIP_RESULT_NAME = "runtime-tree-pip.json"


def validate_pip_section(pip):
    """Validate the manifest's pinned-wheel section; every hash is hex-checked
    because a transcription error must fail closed at download, not silently
    install different bytes."""
    expected = {"site_target", "requirements"}
    if not isinstance(pip, dict) or set(pip) != expected:
        raise ValueError(f"pip_validation must hold exactly {sorted(expected)}")
    target = pip["site_target"]
    if not isinstance(target, str) or not target.startswith("/") or ".." in target \
            or target != target.rstrip("/"):
        raise ValueError("site_target must be a clean absolute path")
    reqs = pip["requirements"]
    if not isinstance(reqs, list) or not reqs or len(reqs) > 64:
        raise ValueError("requirements must be a non-empty list of at most 64 entries")
    seen = set()
    for entry in reqs:
        if not isinstance(entry, dict) or set(entry) != {"name", "version", "wheel", "sha256"}:
            raise ValueError("each requirement needs name, version, wheel, sha256")
        name, version, wheel, sha = entry["name"], entry["version"], entry["wheel"], entry["sha256"]
        if not all(isinstance(v, str) and v for v in (name, version, wheel, sha)):
            raise ValueError("requirement fields must be non-empty strings")
        if name in seen:
            raise ValueError(f"duplicate requirement: {name}")
        seen.add(name)
        if any(c in name for c in ";|&`$<>\n\\") or any(c in version for c in ";|&`$<>\n\\"):
            raise ValueError(f"requirement {name} has unsafe characters")
        if not wheel.endswith(".whl") or wheel != f"{name.replace('-', '_')}-{version}-py3-none-any.whl" \
                and wheel != f"{name}-{version}-py3-none-any.whl":
            raise ValueError(f"wheel filename does not match name/version for {name}")
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError(f"sha256 for {name} must be 64 lowercase hex")
    return pip


def requirements_text(requirements):
    """A pip requirements file with --require-hashes enforcement: pip then
    refuses any artifact whose bytes do not match the pinned digest."""
    lines = []
    for entry in requirements:
        lines.append(f"{entry['name']}=={entry['version']} --hash=sha256:{entry['sha256']}")
    return "\n".join(lines) + "\n"


def nsjail_pip_config(tree_prefix, site_target, wheelhouse, app_dir, runtime=300):
    """NsJail config for the offline pip install: NO network namespace sharing
    is needed (the stage is --no-index), the runtime tree and wheelhouse are
    read-only, and only the app dir (which holds site_target) is writable.
    Mirrors probe.configuration()'s containment shape."""
    uid = 65001
    lines = [
        'name: "halvo-runtime-pip"', 'mode: ONCE', 'cwd: "/app"', 'hostname: "pip"',
        'log_level: WARNING', f'time_limit: {runtime}', 'rlimit_as_type: INF',
        'rlimit_fsize: 256', 'rlimit_nofile: 256', 'rlimit_nproc_type: HARD',
        f'rlimit_cpu: {runtime}', 'mount_proc: true',
        'clone_newnet: true',
        f'uidmap {{ inside_id: "1000" outside_id: "{uid}" }}',
        f'gidmap {{ inside_id: "1000" outside_id: "{uid}" }}',
        'envar: "PATH=/usr/bin:/bin"', 'envar: "HOME=/tmp"', 'envar: "LANG=C.UTF-8"',
        'seccomp_policy_file: "/opt/halvo-lab/syscalls.policy"',
        f'mount {{ src: "{tree_prefix}" dst: "{tree_prefix}" is_bind: true is_dir: true rw: false nosuid: true }}',
        'mount { src: "/usr" dst: "/usr" is_bind: true is_dir: true rw: false nosuid: true }',
        'mount { src: "/bin" dst: "/bin" is_bind: true is_dir: true rw: false nosuid: true }',
        'mount { src: "/lib" dst: "/lib" is_bind: true is_dir: true rw: false nosuid: true }',
        'mount { src: "/lib64" dst: "/lib64" is_bind: true is_dir: true rw: false nosuid: true }',
        f'mount {{ src: "{app_dir}" dst: "/app" is_bind: true is_dir: true rw: true nosuid: true }}',
        f'mount {{ src: "{wheelhouse}" dst: "{wheelhouse}" is_bind: true is_dir: true rw: false nosuid: true }}',
        'mount { dst: "/tmp" fstype: "tmpfs" options: "size=268435456" rw: true nosuid: true nodev: true }',
    ]
    for device in ("null", "zero", "urandom"):
        lines.append(f'mount {{ src: "/dev/{device}" dst: "/dev/{device}" is_bind: true '
                     'is_dir: false rw: true nosuid: true }')
    return "\n".join(lines) + "\n"


def pip_download(interpreter, pip, work_dir, runner=subprocess.run):
    """Guest-side, outside any jail: fetch the pinned wheels with hash
    enforcement (needs egress, which the guest has). Every expected wheel must
    land, or the stage refuses to continue."""
    work = pathlib.Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    reqs = work / "requirements-pinned.txt"
    reqs.write_text(requirements_text(pip["requirements"]))
    wheelhouse = work / "wheelhouse"
    wheelhouse.mkdir(exist_ok=True)
    result = runner([interpreter, "-m", "pip", "download", "--require-hashes",
                     "-r", str(reqs), "-d", str(wheelhouse)],
                    capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise RuntimeError(f"pip download failed: {result.stderr[-400:]}")
    missing = [entry["wheel"] for entry in pip["requirements"]
               if not (wheelhouse / entry["wheel"]).is_file()]
    if missing:
        raise RuntimeError(f"wheels missing after download: {missing}")
    return wheelhouse


def pip_install_in_jail(interpreter, pip, wheelhouse, app_dir, runner=subprocess.run):
    """The actual experiment: pip install offline from the pinned artifacts,
    inside NsJail with the lab's seccomp policy, uid mapping and read-only
    runtime tree. Returns the evidence payload (without timestamps)."""
    site_target = pip["site_target"]
    config_path = pathlib.Path("/tmp/halvo-runtime-pip.cfg")
    config_path.write_text(nsjail_pip_config(str(pathlib.Path(interpreter).parent.parent),
                                             site_target, str(wheelhouse), str(app_dir)))
    command = ["/usr/local/bin/nsjail", "--config", str(config_path), "--",
               interpreter, "-m", "pip", "install", "--no-index",
               "--find-links", str(wheelhouse), "--target", site_target,
               *[f"{e['name']}=={e['version']}" for e in pip["requirements"]]]
    result = runner(command, capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise RuntimeError(f"pip install in jail failed: {result.stderr[-400:]}")
    return {"nsjail_used": True, "offline": True,
            "installed": [f"{e['name']}=={e['version']}" for e in pip["requirements"]]}


def needs_pip(args_results_dir, manifest, result_name=PIP_RESULT_NAME):
    """True unless this manifest's pip evidence is already recorded."""
    pip = manifest.get("pip_validation")
    if not pip:
        return False
    recorded = pathlib.Path(args_results_dir) / result_name
    if not recorded.is_file():
        return True
    try:
        return json.loads(recorded.read_text()).get("manifest_revision") != manifest["revision"]
    except ValueError:
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--scratch-dir", default="/var/tmp/runtime-tree-build")
    parser.add_argument("--skip-pip", action="store_true",
                        help="build or reuse the tree only; leave the pip stage for the next window")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    if not needs_build(manifest["install_prefix"], manifest["revision"],
                       args.results_dir, manifest):
        # The recorded evidence file is left untouched: it is the proof of the
        # original build, and rewriting it as "reused" would make the next run
        # rebuild.
        print(f"runtime tree already built and sane: {manifest['install_prefix']}")
    else:
        payload = build(manifest, args.scratch_dir)
        started = time.time()
        payload["sanity"] = sanity_check(payload["interpreter_path"], manifest["revision"])
        payload["sanity_seconds"] = round(time.time() - started, 1)
        if not all(payload["sanity"].values()):
            write_result(args.results_dir, payload)
            print(f"sanity checks failed: {payload['sanity']}", file=sys.stderr)
            return 1
        write_result(args.results_dir, payload)
        print(json.dumps({"interpreter": payload["interpreter_path"],
                          "build_seconds": payload["build_seconds"],
                          "sanity": payload["sanity"]}, indent=2))

    if args.skip_pip or not manifest.get("pip_validation"):
        return 0
    if not needs_pip(args.results_dir, manifest):
        print("pip validation evidence already recorded")
        return 0
    pip = validate_pip_section(manifest["pip_validation"])
    interpreter = interpreter_path(manifest["install_prefix"], manifest["revision"])
    started = time.time()
    wheelhouse = pip_download(interpreter, pip, "/var/tmp/runtime-tree-pip")
    app_dir = pathlib.Path("/srv/halvo-lab/app-pip")
    app_dir.mkdir(parents=True, exist_ok=True)
    evidence = pip_install_in_jail(interpreter, pip, wheelhouse, app_dir)
    evidence.update({
        "manifest_revision": manifest["revision"],
        "site_target": pip["site_target"],
        "seconds": round(time.time() - started, 1),
    })
    write_result(args.results_dir, evidence, result_name=PIP_RESULT_NAME)
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
