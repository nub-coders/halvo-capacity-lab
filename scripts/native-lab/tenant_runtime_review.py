#!/usr/bin/env python3
"""Per-tenant runtime compatibility review (migration plan Phase 6 step 4).

Input is the operator-exported app-fields JSON (id, name, repo_url, deploy
config, optional source_commit) — never environment values or secrets.
source_commit must be a full 40-hex SHA supplied from verified release evidence;
the tool does not establish that it is the deployed commit. Without it, the
review covers the default branch only, not the deployed application.
For each git-sourced app the
tool asks GitHub for the runtime marker files (package.json engines, .nvmrc,
runtime.txt, requirements.txt, ...) and classifies the request against the
runner catalog: which runtime kind and revision the app would need, whether
the catalog satisfies it, and which apps have no source recipe at all.

Output is a private report; keep it out of any repository. Public repos are
read unauthenticated; private repos are reported as auth-needed rather than
fetching tenant tokens here.

The classification is a review aid, not a cutover verdict: the catalog itself
is offline-planning-only, so nothing can be declared ready while the runtime
trees are unvalidated.
"""

import argparse
import json
import pathlib
import re
import subprocess
import urllib.request

MARKERS = (
    "package.json", ".nvmrc", ".node-version", "runtime.txt", ".python-version",
    "requirements.txt", "pyproject.toml", "app.json", "Dockerfile",
)
# Native or compiled dependencies that make a build meaningfully harder inside
# the sandbox: they compile C/C++ at install time or ship prebuilt binaries.
NATIVE_DEPENDENCIES = (
    "better-sqlite3", "sqlite3", "canvas", "sharp", "bcrypt", "node-gyp",
    "cypress", "playwright", "puppeteer", "grpc", "bufferutil", "utf-8-validate",
)
RAW_BASE = "https://raw.githubusercontent.com"
API_BASE = "https://api.github.com/repos"
GITHUB_REPO_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def resolve_repo(http_get, slug):
    """Canonical full_name and default branch for a repo slug.

    Apps record the repo URL at deploy time, and GitHub renames leave the
    recorded slug stale. raw.githubusercontent.com does not follow renames, so
    fetching markers from the stale slug 404s even for a public repo — every
    marker absent reads exactly like a private repo. The REST API does follow
    renames, so resolve first and fetch from the canonical name.
    """
    try:
        with http_get(f"{API_BASE}/{slug}") as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
        full_name = data.get("full_name")
        if not full_name:
            return None
        return full_name, data.get("default_branch") or "HEAD"
    except Exception:
        return None


def parse_repo(repo_url):
    """owner/repo from a GitHub URL, or None for non-GitHub sources."""
    if not repo_url:
        return None
    match = GITHUB_REPO_RE.search(repo_url.strip())
    return f"{match.group(1)}/{match.group(2)}" if match else None


def parse_nvmrc(content):
    text = content.strip().splitlines()[0].strip() if content.strip() else ""
    # "v22.12.0", "22.12", "lts/iron", "node" — only a concrete version is usable.
    match = re.fullmatch(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
    if not match:
        return {"requested": text or None, "revision": None}
    major, minor, patch = match.groups()
    revision = ".".join(part for part in (major, minor, patch) if part is not None)
    return {"requested": text, "revision": revision}


def parse_runtime_txt(content):
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("python-"):
            return line.removeprefix("python-")
    return None


def classify(app, markers):
    """One app's markers -> the runtime request and its catalog verdict."""
    package = markers.get("package.json") or {}
    engines = package.get("engines") or {}
    deps = {
        **(package.get("dependencies") or {}),
        **(package.get("devDependencies") or {}),
    }
    native = sorted(dep for dep in deps if dep in NATIVE_DEPENDENCIES)

    node_request = (
        engines.get("node")
        or (markers.get(".nvmrc") or {}).get("requested")
        or (markers.get(".node-version") or {}).get("requested")
    )
    # A fully-pinned engines range is as good as an .nvmrc revision; a range
    # like ">=20" is not, and stays a request only.
    node_revision = (
        (markers.get(".nvmrc") or {}).get("revision")
        or (markers.get(".node-version") or {}).get("revision")
    )
    # A fully-pinned engines range is as good as an .nvmrc revision; a range
    # like ">=20" is not, and stays a request only.
    if node_revision is None and node_request:
        pinned = re.fullmatch(r"v?(\d+(?:\.\d+){2})", str(node_request))
        if pinned:
            node_revision = pinned.group(1)
    python_request = engines.get("python") or markers.get("runtime.txt") \
        or markers.get(".python-version")
    if python_request:
        python_request = str(python_request).strip().removeprefix("python-")

    has_package = markers.get("package.json") is not None
    has_python_code = python_request is not None or (
        markers.get("requirements.txt") is not None
        or markers.get("pyproject.toml") is not None
    )

    if not has_package and not has_python_code:
        kind = "unknown"
    elif has_python_code and not has_package:
        kind = "python"
    elif has_package and has_python_code:
        kind = "mixed"  # polyglot needs an explicit platform decision
    else:
        kind = "node"

    start = package.get("scripts", {}).get("start")
    return {
        "runtime_kind": kind,
        "node_request": node_request,
        "node_revision": node_revision,
        "python_request": python_request,
        "has_start_script": bool(start),
        "has_procfile": markers.get("Procfile") is not None if "Procfile" in markers else None,
        "has_dockerfile": markers.get("Dockerfile") is not None,
        "native_dependencies": native,
        "native_dependency_scan": "npm-name-allowlist-only",
        "python_native_dependencies": None,
        "declared_app_json": markers.get("app.json") is not None,
    }


def fetch_marker(http_get, slug, branch, marker):
    """GET one marker file; None means absent (or unreachable — the caller
    distinguishes a fully-unreachable repo from individual absent files)."""
    url = f"{RAW_BASE}/{slug}/{branch}/{marker}"
    try:
        with http_get(url) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def list_root_names(http_get, slug, branch):
    """Root file names at the selected ref, or None if unlistable."""
    url = f"{API_BASE}/{slug}/contents?ref={branch}"
    try:
        with http_get(url) as response:
            entries = json.loads(response.read().decode("utf-8", errors="replace"))
        return [entry.get("name") for entry in entries if entry.get("name")]
    except Exception:
        return None


def default_http_get(url):
    """Open the URL and hand the response to the caller, which closes it via
    its own `with`. Do NOT context-manage it here: a response read after this
    function returns is already closed, and that failure is indistinguishable
    from a 404 once the caller's except swallows it."""
    request = urllib.request.Request(url, headers={"User-Agent": "halvo-migration-review"})
    return urllib.request.urlopen(request, timeout=15)


class _BytesResponse:
    """Minimal response object matching the `with http_get(url)` contract."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def gh_http_get(url, run=subprocess.run):
    """Authenticated variant for private repos and rate-limit headroom: API
    calls go through the operator's `gh` CLI (5000 requests/hour, and it sees
    private repos the operator can access); raw file fetches stay unauthenticated
    because raw.githubusercontent.com has no such limit and needs no identity.
    Raises on a non-zero exit so the caller's except treats it as absent."""
    if not url.startswith(f"{API_BASE}/"):
        return default_http_get(url)
    path = url[len("https://api.github.com"):]
    result = run(["gh", "api", path], capture_output=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"gh api failed: {result.stderr.decode(errors='replace')[:200]}")
    return _BytesResponse(result.stdout)


def review(apps, catalog, http_get=default_http_get):
    """The full pass: per-app rows plus aggregate counts. Never raises on a
    single app's network failure; that app is marked unreachable."""
    runtimes = {(r["kind"], r["revision"]) for r in catalog.get("runtimes", [])}
    rows = []
    for app in apps:
        commit = app.get("source_commit")
        if "source_commit" in app and (
            not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit)
        ):
            rows.append({
                "id": app["id"], "name": app["name"],
                "classification": "invalid-source-commit",
            })
            continue
        slug = parse_repo(app.get("repo_url"))
        if not slug:
            rows.append({
                "id": app["id"], "name": app["name"], "source": "non-git",
                "classification": "no-source-recipe",
            })
            continue
        resolved = resolve_repo(http_get, slug)
        if resolved is None:
            rows.append({
                "id": app["id"], "name": app["name"], "repo": slug,
                "source": "git-unreachable",
                "classification": "auth-needed-or-missing",
            })
            continue
        canonical, branch = resolved
        if commit is not None:
            branch = commit.lower()
        source_review = {
            "reviewed_ref": branch,
            "review_scope": "operator-supplied-commit-markers" if commit is not None
                            else "default-branch-markers",
        }
        raw = {m: fetch_marker(http_get, canonical, branch, m) for m in MARKERS if m != "Procfile"}
        reachable = any(value is not None for value in raw.values())
        if not reachable:
            rows.append({
                "id": app["id"], "name": app["name"], "repo": slug,
                "source": "git-unreachable",
                "classification": "auth-needed-or-missing",
                **source_review,
            })
            continue
        markers = {}
        for name, content in raw.items():
            if content is None:
                continue
            if name == "package.json":
                try:
                    markers[name] = json.loads(content)
                except ValueError:
                    markers[name] = {"_parse_error": True}
            elif name in (".nvmrc", ".node-version"):
                markers[name] = parse_nvmrc(content)
            elif name == "runtime.txt":
                markers[name] = parse_runtime_txt(content)
            else:
                markers[name] = content
        row = {
            "id": app["id"], "name": app["name"],
            "repo": canonical, "recorded_repo": slug,
            "source": "git",
            **source_review,
            "instance_size": app.get("instance_size"),
            **classify(app, markers),
        }
        # A single-file app (bot.py, music.py) has no dependency manifest for
        # the marker set to find, but is still plainly Python. Read-only one
        # extra listing rather than call it unknown.
        if row["runtime_kind"] == "unknown":
            root_names = list_root_names(http_get, canonical, branch)
            if root_names and any(name.endswith(".py") for name in root_names):
                row["runtime_kind"] = "python"
                row["evidence"] = "single-file python; no dependency manifest — deps likely live in the Dockerfile"
        requested = (row["runtime_kind"], "catalog")
        if row["runtime_kind"] == "node":
            exact = ("node", row["node_revision"]) in runtimes if row["node_revision"] else False
            row["catalog_match"] = "exact" if exact else "revision-override"
        elif row["runtime_kind"] == "python":
            row["catalog_match"] = "revision-override"
        else:
            row["catalog_match"] = "unknown"
        rows.append(row)

    counts = {}
    for row in rows:
        key = row.get("classification") or row.get("runtime_kind")
        counts[key] = counts.get(key, 0) + 1
    return {
        "scope": "runtime-marker-review",
        "deployed_commit_verified": False,
        "migration_compatibility": "not-established",
        "apps_reviewed": len(rows),
        "catalog_status": catalog.get("status"),
        "host_execution": catalog.get("host_execution"),
        "counts": counts,
        "apps": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apps", type=pathlib.Path, required=True,
                        help="operator-exported app-fields JSON (no secrets)")
    parser.add_argument("--catalog", type=pathlib.Path, required=True,
                        help="scripts/native-runner/catalog.json")
    parser.add_argument("--output", type=pathlib.Path, required=True,
                        help="where to write the private report")
    parser.add_argument("--auth", choices=("anonymous", "gh"), default="anonymous",
                        help="gh: route GitHub API calls through the authenticated "
                             "gh CLI (private repos, 5000 req/h)")
    args = parser.parse_args()
    apps = json.loads(args.apps.read_text())
    catalog = json.loads(args.catalog.read_text())
    http_get = gh_http_get if args.auth == "gh" else default_http_get
    report = review(apps, catalog, http_get=http_get)
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "apps"}, indent=2))


if __name__ == "__main__":
    main()
