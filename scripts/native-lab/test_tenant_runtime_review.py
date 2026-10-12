import json
import subprocess
import unittest
from urllib.error import URLError

from tenant_runtime_review import classify, parse_nvmrc, parse_repo, parse_runtime_txt, review


def package_json(**overrides):
    base = {
        "name": "app",
        "engines": {},
        "scripts": {},
        "dependencies": {},
        "devDependencies": {},
    }
    base.update(overrides)
    return base


class RepoParsingTest(unittest.TestCase):
    def test_https_and_ssh_and_dotgit_forms(self):
        self.assertEqual(parse_repo("https://github.com/octo/app.git"), "octo/app")
        self.assertEqual(parse_repo("git@github.com:octo/app.git"), "octo/app")
        self.assertEqual(parse_repo("https://github.com/octo/app/"), "octo/app")

    def test_platform_sources_are_not_github_repos(self):
        self.assertIsNone(parse_repo("cli-upload"))
        self.assertIsNone(parse_repo(""))
        self.assertIsNone(parse_repo("https://gitlab.com/octo/app"))


class MarkerParsingTest(unittest.TestCase):
    def test_nvmrc_concrete_versions(self):
        self.assertEqual(parse_nvmrc("v22.12.0\n"), {"requested": "v22.12.0", "revision": "22.12.0"})
        self.assertEqual(parse_nvmrc("20\n"), {"requested": "20", "revision": "20"})
        self.assertEqual(parse_nvmrc(""), {"requested": None, "revision": None})

    def test_nvmrc_symbolic_requests_have_no_revision(self):
        self.assertIsNone(parse_nvmrc("lts/iron\n")["revision"])
        self.assertIsNone(parse_nvmrc("node\n")["revision"])

    def test_runtime_txt(self):
        self.assertEqual(parse_runtime_txt("python-3.12.3\n"), "3.12.3")
        self.assertIsNone(parse_runtime_txt("node-20\n"))


class ClassifyTest(unittest.TestCase):
    def test_node_app_with_engines(self):
        result = classify({}, {"package.json": package_json(engines={"node": ">=20"})})
        self.assertEqual(result["runtime_kind"], "node")
        self.assertEqual(result["node_request"], ">=20")

    def test_python_app_without_package_json(self):
        result = classify({}, {"runtime.txt": "python-3.12.3", "requirements.txt": "flask\n"})
        self.assertEqual(result["runtime_kind"], "python")
        self.assertEqual(result["python_request"], "3.12.3")

    def test_package_and_requirements_is_mixed(self):
        result = classify({}, {"package.json": package_json(), "requirements.txt": "flask\n"})
        self.assertEqual(result["runtime_kind"], "mixed")

    def test_no_markers_is_unknown(self):
        self.assertEqual(classify({}, {})["runtime_kind"], "unknown")

    def test_native_dependencies_are_listed(self):
        result = classify({}, {"package.json": package_json(
            dependencies={"better-sqlite3": "^9", "express": "^4"},
            devDependencies={"playwright": "^1"},
        )})
        self.assertEqual(result["native_dependencies"], ["better-sqlite3", "playwright"])

    def test_start_script_detected(self):
        result = classify({}, {"package.json": package_json(scripts={"start": "node index.js"})})
        self.assertTrue(result["has_start_script"])


class ReviewTest(unittest.TestCase):
    def test_commit_pin_is_used_for_markers_and_root_listing(self):
        commit = "a" * 40
        calls = []

        def get(url):
            calls.append(url)
            if url == "https://api.github.com/repos/octo/old-name":
                return _Response(json.dumps(
                    {"full_name": "octo/new-name", "default_branch": "main"}))
            if url == f"https://api.github.com/repos/octo/new-name/contents?ref={commit}":
                return _Response(json.dumps([{"name": "bot.py"}]))
            if url.startswith(f"https://raw.githubusercontent.com/octo/new-name/{commit}/"):
                if url.endswith("Dockerfile"):
                    return _Response("FROM python:3.11-slim\n")
                raise URLError("not found")
            raise AssertionError(f"request escaped the commit pin: {url}")

        report = review(
            [{"id": 1, "name": "x", "repo_url": "https://github.com/octo/old-name",
              "source_commit": commit}],
            {"runtimes": []}, http_get=get,
        )
        row = report["apps"][0]
        self.assertEqual(row["runtime_kind"], "python")
        self.assertEqual(row["reviewed_ref"], commit)
        self.assertEqual(row["review_scope"], "operator-supplied-commit-markers")
        self.assertIn(f"https://api.github.com/repos/octo/new-name/contents?ref={commit}", calls)
        self.assertFalse(report["deployed_commit_verified"])
        self.assertEqual(report["migration_compatibility"], "not-established")
        self.assertEqual(row["native_dependency_scan"], "npm-name-allowlist-only")
        self.assertIsNone(row["python_native_dependencies"])

    def test_invalid_commit_is_rejected_without_a_branch_fallback(self):
        for commit in (None, "main", "a" * 39, "", True, 123, "../main"):
            with self.subTest(commit=commit):
                def no_fetch(url):
                    self.fail("invalid pin must not fetch any source")
                report = review(
                    [{"id": 1, "name": "x", "repo_url": "https://github.com/octo/app",
                      "source_commit": commit}],
                    {"runtimes": []}, http_get=no_fetch,
                )
                self.assertEqual(report["apps"][0]["classification"], "invalid-source-commit")

    def test_unavailable_commit_does_not_review_the_default_branch(self):
        calls = []

        def get(url):
            calls.append(url)
            if url == "https://api.github.com/repos/octo/app":
                return _Response(json.dumps({"full_name": "octo/app", "default_branch": "main"}))
            if "/main/" in url:
                return _Response(json.dumps(package_json()))
            raise URLError("not found")

        row = review(
            [{"id": 1, "name": "x", "repo_url": "https://github.com/octo/app",
              "source_commit": "a" * 40}], {"runtimes": []}, http_get=get,
        )["apps"][0]
        self.assertEqual(row["classification"], "auth-needed-or-missing")
        self.assertEqual(row["reviewed_ref"], "a" * 40)
        self.assertFalse(any("/main/" in url for url in calls))

    def fake_get(self, contents, api=None):
        def get(url):
            if "api.github.com/repos/" in url:
                slug = url.split("/repos/", 1)[1]
                if slug not in (api or {}):
                    raise URLError("not found")
                return _Response(json.dumps(api[slug]))
            path = url.rsplit("/", 1)[-1]
            if path not in contents:
                raise URLError("not found")
            return _Response(contents[path])
        return get

    def test_unreachable_repo_is_marked_not_reviewed(self):
        report = review(
            [{"id": 1, "name": "x", "repo_url": "https://github.com/octo/private"}],
            {"runtimes": []},
            http_get=self.fake_get({}),
        )
        self.assertEqual(report["apps"][0]["classification"], "auth-needed-or-missing")

    def test_renamed_repo_is_resolved_through_the_api(self):
        # The app recorded the pre-rename slug; raw.githubusercontent.com does
        # not follow renames, so markers must be fetched from the canonical name.
        def get(url):
            if "api.github.com/repos/octo/old-name" in url:
                return _Response(json.dumps(
                    {"full_name": "octo/new-name", "default_branch": "main"}))
            if url.startswith("https://raw.githubusercontent.com/octo/new-name/main/"):
                if url.endswith("package.json"):
                    return _Response(json.dumps(package_json()))
                raise URLError("not found")
            raise AssertionError(f"unexpected fetch from non-canonical name: {url}")

        report = review(
            [{"id": 1, "name": "x", "repo_url": "https://github.com/octo/old-name"}],
            {"runtimes": [{"kind": "node", "revision": "22"}]},
            http_get=get,
        )
        row = report["apps"][0]
        self.assertEqual(row["repo"], "octo/new-name")
        self.assertEqual(row["recorded_repo"], "octo/old-name")
        self.assertEqual(row["runtime_kind"], "node")

    def test_public_repo_classified_against_catalog(self):
        contents = {
            "package.json": json.dumps(package_json(
                engines={"node": "22.23.3"},
                scripts={"start": "node server.js"},
            )),
            ".nvmrc": "22.23.3\n",
        }
        report = review(
            [{"id": 1, "name": "x", "repo_url": "https://github.com/octo/app"}],
            {"runtimes": [{"kind": "node", "revision": "22.23.3"}], "status": "offline-planning-only"},
            http_get=self.fake_get(
                contents,
                api={"octo/app": {"full_name": "octo/app", "default_branch": "main"}},
            ),
        )
        row = report["apps"][0]
        self.assertEqual(row["runtime_kind"], "node")
        self.assertEqual(row["catalog_match"], "exact")
        self.assertEqual(row["reviewed_ref"], "main")
        self.assertEqual(row["review_scope"], "default-branch-markers")
        self.assertEqual(report["counts"], {"node": 1})

    def test_single_file_python_app_is_not_unknown(self):
        # bot.py + Dockerfile, no dependency manifest: still Python.
        def get(url):
            if "api.github.com/repos/octo/app" in url and "/contents" not in url:
                return _Response(json.dumps(
                    {"full_name": "octo/app", "default_branch": "main"}))
            if "/contents" in url:
                return _Response(json.dumps(
                    [{"name": "README.md"}, {"name": "bot.py"}, {"name": "Dockerfile"}]))
            if url.endswith("Dockerfile"):
                return _Response("FROM python:3.13-slim\n")
            raise URLError("not found")

        report = review(
            [{"id": 1, "name": "x", "repo_url": "https://github.com/octo/app"}],
            {"runtimes": [{"kind": "python", "revision": "3.12.3"}]},
            http_get=get,
        )
        row = report["apps"][0]
        self.assertEqual(row["runtime_kind"], "python")
        self.assertIn("single-file", row["evidence"])
        self.assertEqual(report["counts"], {"python": 1})

    def test_non_git_source_needs_a_recipe(self):
        report = review(
            [{"id": 1, "name": "x", "repo_url": "cli-upload"}],
            {"runtimes": []},
            http_get=self.fake_get({}),
        )
        self.assertEqual(report["apps"][0]["classification"], "no-source-recipe")


class _Response:
    def __init__(self, body):
        self._body = body.encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class GhAuthTest(unittest.TestCase):
    def test_api_calls_go_through_gh_and_raw_stays_anonymous(self):
        from unittest.mock import patch
        import tenant_runtime_review as tool

        calls = []

        def fake_run(argv, capture_output, timeout):
            calls.append(argv)
            return subprocess.CompletedProcess(
                argv, 0, stdout=json.dumps({"full_name": "octo/private"}).encode(), stderr=b"",
            )

        def no_anonymous_api(*a, **k):
            raise AssertionError("API call must not hit api.github.com anonymously")

        with patch.object(tool.urllib.request, "urlopen", side_effect=no_anonymous_api):
            response = tool.gh_http_get("https://api.github.com/repos/octo/private", run=fake_run)
        self.assertEqual(calls, [["gh", "api", "/repos/octo/private"]])
        with response as r:
            self.assertEqual(json.loads(r.read())["full_name"], "octo/private")

        # Non-API URLs keep the plain fetcher.
        with patch.object(tool, "default_http_get",
                          side_effect=lambda url: tool._BytesResponse(b"ok")) as opener:
            tool.gh_http_get("https://raw.githubusercontent.com/octo/private/main/package.json")
            opener.assert_called_once()

    def test_gh_failure_raises_so_the_call_counts_as_absent(self):
        import subprocess as sp
        import tenant_runtime_review as tool

        def fake_run(argv, capture_output, timeout):
            return sp.CompletedProcess(argv, 1, stdout=b"", stderr=b"Not Found")

        with self.assertRaises(RuntimeError):
            tool.gh_http_get("https://api.github.com/repos/octo/missing", run=fake_run)


class _Response:
    def __init__(self, body):
        self._body = body.encode()
        self.closed = False

    def read(self):
        if self.closed:
            raise ValueError("read of closed response")
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        return False


class DefaultHttpTest(unittest.TestCase):
    def test_response_is_still_readable_after_the_opener_returns(self):
        # default_http_get must not context-manage the response it returns:
        # the caller's `with` is what closes it, and a closed read inside the
        # caller's except block made every fetch look absent.
        from unittest.mock import patch
        import tenant_runtime_review as tool

        response = _Response('{"full_name": "octo/app"}')
        with patch.object(tool.urllib.request, "urlopen", return_value=response):
            opened = tool.default_http_get("https://api.github.com/repos/octo/app")
        with opened as r:
            data = json.loads(r.read().decode())
        self.assertEqual(data["full_name"], "octo/app")
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
