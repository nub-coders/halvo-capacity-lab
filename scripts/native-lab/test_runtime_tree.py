import hashlib
import json
import subprocess
import unittest
from pathlib import Path

import runtime_tree as tool


class ManifestTest(unittest.TestCase):
    def test_bundled_manifest_is_valid(self):
        manifest = tool.load_manifest(Path(__file__).resolve().parent / "runtime-tree-manifest.json")
        self.assertEqual(manifest["revision"], "3.13.15")
        # the pinned prefix must be what configure installs to
        self.assertIn(f"--prefix={manifest['install_prefix']}", manifest["configure_flags"])

    def test_extra_field_is_rejected(self):
        manifest = {"revision": "3.13.15", "source_url": "https://www.python.org/ftp/python/3.13.15/x.tgz",
                    "source_sha256": "a" * 64, "install_prefix": "/opt/runtimes/python-3.13.15",
                    "configure_flags": ["--prefix=/opt/runtimes/python-3.13.15"], "make_jobs": 2,
                    "notes": [], "surprise": 1}
        with self.assertRaises(ValueError):
            tool.validate_manifest(manifest)

    def test_prefix_mismatch_with_configure_flag_is_rejected(self):
        manifest = {"revision": "3.13.15", "source_url": "https://www.python.org/ftp/python/3.13.15/x.tgz",
                    "source_sha256": "a" * 64, "install_prefix": "/opt/runtimes/python-3.13.15",
                    "configure_flags": ["--prefix=/somewhere/else"], "make_jobs": 2, "notes": []}
        with self.assertRaises(ValueError):
            tool.validate_manifest(manifest)

    def test_shell_metacharacters_in_flags_are_rejected(self):
        manifest = {"revision": "3.13.15", "source_url": "https://www.python.org/ftp/python/3.13.15/x.tgz",
                    "source_sha256": "a" * 64, "install_prefix": "/opt/runtimes/python-3.13.15",
                    "configure_flags": ["--prefix=/opt/runtimes/python-3.13.15; rm -rf /"],
                    "make_jobs": 2, "notes": []}
        with self.assertRaises(ValueError):
            tool.validate_manifest(manifest)


class VerifySourceTest(unittest.TestCase):
    def test_matching_bytes_pass(self):
        payload = b"tarball bytes"
        manifest = {"source_sha256": hashlib.sha256(payload).hexdigest()}
        import tempfile
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(payload)
            handle.flush()
            tool.verify_source(handle.name, manifest)

    def test_tampered_bytes_fail_closed(self):
        manifest = {"source_sha256": "b" * 64}
        import tempfile
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b"not the pinned bytes")
            handle.flush()
            with self.assertRaises(ValueError):
                tool.verify_source(handle.name, manifest)


class SanityTest(unittest.TestCase):
    @staticmethod
    def fake_runner(revision_stdout="3.13.15", pip_returncode=0):
        def run(argv, **kwargs):
            class Result:
                returncode = pip_returncode if "-m" in argv else 0
                stdout = revision_stdout if "-c" in argv else ""
                stderr = ""
            return Result()
        return run

    def test_sane_tree_reports_pinned_revision_and_pip(self):
        checks = tool.sanity_check("/opt/runtimes/python-3.13.15/bin/python3.13",
                                   "3.13.15", runner=self.fake_runner())
        self.assertTrue(all(checks.values()))

    def test_wrong_revision_fails(self):
        checks = tool.sanity_check("/opt/runtimes/python-3.13.15/bin/python3.13",
                                   "3.13.15",
                                   runner=self.fake_runner(revision_stdout="3.12.3"))
        self.assertFalse(checks["reports_pinned_revision"])

    def test_missing_pip_fails(self):
        checks = tool.sanity_check("/opt/runtimes/python-3.13.15/bin/python3.13",
                                   "3.13.15", runner=self.fake_runner(pip_returncode=1))
        self.assertFalse(checks["pip_available"])


class NeedsBuildTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.results = Path(self.tmp.name)
        self.prefix = str(self.results / "tree")
        self.manifest = {"revision": "3.13.15", "source_sha256": "a" * 64}

    def record(self, **overrides):
        payload = {"manifest": self.manifest, "reused": False,
                   "sanity": {"reports_pinned_revision": True, "pip_available": True}}
        payload.update(overrides)
        (self.results / tool.RESULT_NAME).write_text(json.dumps(payload))

    def fake_sane(self, argv, **kwargs):
        class Result:
            returncode = 0
            stdout = "3.13.15" if "-c" in argv else ""
            stderr = ""
        return Result()

    def test_no_result_means_build(self):
        self.assertTrue(tool.needs_build(self.prefix, "3.13.15", self.results, self.manifest))

    def test_matching_result_with_sane_interpreter_is_reused(self):
        self.record()
        interpreter = Path(self.prefix) / "bin" / "python3.13"
        interpreter.parent.mkdir(parents=True)
        interpreter.write_text("#!/bin/sh\n")
        self.assertFalse(tool.needs_build(self.prefix, "3.13.15", self.results, self.manifest,
                                          runner=self.fake_sane))

    def test_different_manifest_forces_rebuild(self):
        self.record()
        interpreter = Path(self.prefix) / "bin" / "python3.13"
        interpreter.parent.mkdir(parents=True)
        interpreter.write_text("#!/bin/sh\n")
        changed = {**self.manifest, "source_sha256": "c" * 64}
        self.assertTrue(tool.needs_build(self.prefix, "3.13.15", self.results, changed,
                                         runner=self.fake_sane))

    def test_torn_or_missing_interpreter_forces_rebuild(self):
        self.record()
        self.assertTrue(tool.needs_build(self.prefix, "3.13.15", self.results, self.manifest,
                                         runner=self.fake_sane))


class BuildTest(unittest.TestCase):
    def test_build_sequence_and_result_payload(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scratch = Path(tmp.name)
        payload = b"fake tarball"
        manifest = {
            "revision": "3.13.15",
            "source_url": "https://www.python.org/ftp/python/3.13.15/Python-3.13.15.tgz",
            "source_sha256": hashlib.sha256(payload).hexdigest(),
            "install_prefix": "/opt/runtimes/python-3.13.15",
            "configure_flags": ["--prefix=/opt/runtimes/python-3.13.15",
                                "--with-ensurepip=install", "--config-cache"],
            "make_jobs": 4, "notes": [],
        }
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["tar", "-xf"]:
                (scratch / "Python-3.13.15").mkdir(exist_ok=True)

        def download(url, destination):
            Path(destination).write_bytes(payload)

        result = tool.build(manifest, scratch, runner=runner, download=download)
        self.assertEqual([c[0] for c in calls], ["tar", "./configure", "make", "make"])
        self.assertEqual(calls[1], ["./configure", "--prefix=/opt/runtimes/python-3.13.15",
                                    "--with-ensurepip=install", "--config-cache"])
        self.assertEqual(calls[2], ["make", "-j4"])
        self.assertEqual(result["interpreter_path"],
                         "/opt/runtimes/python-3.13.15/bin/python3.13")
        self.assertFalse(result["reused"])
        self.assertFalse(result["pgo_used"])
        self.assertTrue(result["configure_ran"])


class ConfigureStampTest(unittest.TestCase):
    """Configure costs most of a TCG window; only the first window may run it."""

    def make_setup(self, tmp):
        payload = b"fake tarball"
        manifest = {
            "revision": "3.13.15",
            "source_url": "https://www.python.org/ftp/python/3.13.15/Python-3.13.15.tgz",
            "source_sha256": hashlib.sha256(payload).hexdigest(),
            "install_prefix": "/opt/runtimes/python-3.13.15",
            "configure_flags": ["--prefix=/opt/runtimes/python-3.13.15"],
            "make_jobs": 4, "notes": [],
        }
        source = Path(tmp) / "Python-3.13.15"
        source.mkdir(parents=True, exist_ok=True)
        return manifest, payload, source

    def test_stamp_from_a_completed_configure_skips_it(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manifest, payload, source = self.make_setup(tmp.name)
        tool.write_configure_stamp(source, manifest)
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv[0])

        result = tool.build(manifest, tmp.name, runner=runner,
                            download=lambda url, dest: Path(dest).write_bytes(payload),
                            now=lambda: 100.0)
        self.assertNotIn("./configure", calls)
        self.assertFalse(result["configure_ran"])
        self.assertEqual(calls, ["make", "make"])

    def test_flag_change_forces_a_fresh_configure(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manifest, payload, source = self.make_setup(tmp.name)
        tool.write_configure_stamp(source, manifest)
        changed = {**manifest, "configure_flags": ["--prefix=/opt/runtimes/python-3.13.15",
                                                   "--disable-test-modules"]}
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv[0])

        result = tool.build(changed, tmp.name, runner=runner,
                            download=lambda url, dest: Path(dest).write_bytes(payload),
                            now=lambda: 100.0)
        self.assertEqual(calls, ["./configure", "make", "make"])
        self.assertTrue(result["configure_ran"])

    def test_interrupted_configure_without_stamp_retries(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manifest, payload, source = self.make_setup(tmp.name)
        # A Makefile alone must not count as configured: only the stamp does.
        (source / "Makefile").write_text("# partial configure output\n")
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv[0])

        tool.build(manifest, tmp.name, runner=runner,
                   download=lambda url, dest: Path(dest).write_bytes(payload),
                   now=lambda: 100.0)
        self.assertEqual(calls[0], "./configure")


class WriteResultTest(unittest.TestCase):
    def test_atomic_write_leaves_no_tmp_behind(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tool.write_result(tmp.name, {"manifest": {}, "sanity": {}})
        self.assertTrue((Path(tmp.name) / tool.RESULT_NAME).is_file())
        self.assertEqual(list(Path(tmp.name).glob("*.tmp")), [])


class PipSectionTest(unittest.TestCase):
    def valid_pip(self):
        return {
            "site_target": "/app/site",
            "requirements": [
                {"name": "requests", "version": "2.32.5",
                 "wheel": "requests-2.32.5-py3-none-any.whl",
                 "sha256": "a" * 64},
            ],
        }

    def test_valid_section_passes(self):
        self.assertEqual(tool.validate_pip_section(self.valid_pip()),
                         self.valid_pip())

    def test_non_hex_hash_is_rejected(self):
        pip = self.valid_pip()
        pip["requirements"][0]["sha256"] = "z" * 64
        with self.assertRaises(ValueError):
            tool.validate_pip_section(pip)

    def test_wheel_name_mismatch_is_rejected(self):
        pip = self.valid_pip()
        pip["requirements"][0]["wheel"] = "other-2.32.5-py3-none-any.whl"
        with self.assertRaises(ValueError):
            tool.validate_pip_section(pip)

    def test_duplicate_requirement_is_rejected(self):
        pip = self.valid_pip()
        pip["requirements"].append(dict(pip["requirements"][0]))
        with self.assertRaises(ValueError):
            tool.validate_pip_section(pip)

    def test_requirements_text_enforces_hashes(self):
        text = tool.requirements_text(self.valid_pip()["requirements"])
        self.assertEqual(text,
                         "requests==2.32.5 --hash=sha256:" + "a" * 64 + "\n")


class NsjailConfigTest(unittest.TestCase):
    def test_config_is_offline_and_writes_only_the_site_target(self):
        config = tool.nsjail_pip_config(
            "/opt/runtimes/python-3.13.15", "/app/site",
            "/srv/halvo-lab/wheelhouse", "/srv/halvo-lab/app-pip")
        # offline stage: a fresh network namespace, no DNS mounts, no egress
        self.assertIn("clone_newnet: true", config)
        self.assertNotIn("resolv.conf", config)
        self.assertIn('dst: "/app" is_bind: true is_dir: true rw: true', config)
        self.assertIn("/opt/runtimes/python-3.13.15", config)
        self.assertIn("rw: false", config)
        self.assertIn('seccomp_policy_file: "/opt/halvo-lab/syscalls.policy"', config)


class PipStageTest(unittest.TestCase):
    def test_download_verifies_every_expected_wheel_landed(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pip = tool.validate_pip_section({
            "site_target": "/app/site",
            "requirements": [
                {"name": "requests", "version": "2.32.5",
                 "wheel": "requests-2.32.5-py3-none-any.whl", "sha256": "a" * 64},
            ],
        })

        def fake_run(argv, **kwargs):
            # pip download succeeded but "forgot" the wheel: the stage must
            # refuse to continue toward the jail.
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            Path(tmp.name, "wheelhouse").mkdir(exist_ok=True)
            return R()

        with self.assertRaises(RuntimeError):
            tool.pip_download("/tree/bin/python3.13", pip, tmp.name, runner=fake_run)

    def test_download_writes_the_hash_enforced_requirements_file(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pip = tool.validate_pip_section({
            "site_target": "/app/site",
            "requirements": [
                {"name": "requests", "version": "2.32.5",
                 "wheel": "requests-2.32.5-py3-none-any.whl", "sha256": "a" * 64},
            ],
        })
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            Path(argv[argv.index("-d") + 1], "requests-2.32.5-py3-none-any.whl").touch()
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        tool.pip_download("/tree/bin/python3.13", pip, tmp.name, runner=fake_run)
        self.assertIn("--require-hashes", seen["argv"])
        reqs = Path(seen["argv"][seen["argv"].index("-r") + 1]).read_text()
        self.assertEqual(reqs, "requests==2.32.5 --hash=sha256:" + "a" * 64 + "\n")

    def test_install_in_jail_runs_the_built_interpreter_under_nsjail(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pip = tool.validate_pip_section({
            "site_target": "/app/site",
            "requirements": [
                {"name": "requests", "version": "2.32.5",
                 "wheel": "requests-2.32.5-py3-none-any.whl", "sha256": "a" * 64},
            ],
        })
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        evidence = tool.pip_install_in_jail(
            "/opt/runtimes/python-3.13.15/bin/python3.13", pip,
            Path(tmp.name, "wheelhouse"), Path(tmp.name, "app"), runner=fake_run)
        self.assertTrue(evidence["nsjail_used"])
        self.assertIn("/opt/runtimes/python-3.13.15/bin/python3.13", seen["argv"])
        self.assertIn("--no-index", seen["argv"])
        cfg = Path(seen["argv"][seen["argv"].index("--config") + 1]).read_text()
        self.assertIn("clone_newnet: true", cfg)


class NeedsPipTest(unittest.TestCase):
    def test_missing_evidence_means_run(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manifest = {"revision": "3.13.15", "pip_validation": {"site_target": "/app/site"}}
        self.assertTrue(tool.needs_pip(tmp.name, manifest))

    def test_matching_revision_is_reused(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manifest = {"revision": "3.13.15", "pip_validation": {"site_target": "/app/site"}}
        Path(tmp.name, tool.PIP_RESULT_NAME).write_text(
            json.dumps({"manifest_revision": "3.13.15"}))
        self.assertFalse(tool.needs_pip(tmp.name, manifest))

    def test_absent_section_never_runs(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.assertFalse(tool.needs_pip(tmp.name, {"revision": "3.13.15"}))


class BuildJournalTest(unittest.TestCase):
    def make_manifest(self, scratch):
        payload = b"fake tarball"
        return {
            "revision": "3.13.15",
            "source_url": "https://www.python.org/ftp/python/3.13.15/Python-3.13.15.tgz",
            "source_sha256": hashlib.sha256(payload).hexdigest(),
            "install_prefix": "/opt/runtimes/python-3.13.15",
            "configure_flags": ["--prefix=/opt/runtimes/python-3.13.15",
                                "--with-ensurepip=install"],
            "make_jobs": 2, "notes": [],
        }, payload

    def test_fresh_build_records_one_finished_window(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manifest, payload = self.make_manifest(tmp.name)

        def runner(argv, **kwargs):
            if argv[:2] == ["tar", "-xf"]:
                Path(tmp.name, "Python-3.13.15").mkdir(exist_ok=True)

        result = tool.build(manifest, tmp.name, runner=runner,
                            download=lambda url, dest: Path(dest).write_bytes(payload),
                            now=lambda: 1000.0)
        journal = json.loads(Path(tmp.name, tool.JOURNAL_NAME).read_text())
        self.assertEqual(len(journal["windows"]), 1)
        self.assertEqual(journal["windows"][0]["end"], 1000.0)
        self.assertEqual(result["windows_used"], 1)

    def test_killed_window_recompiles_only_its_objects(self):
        import os
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        manifest, payload = self.make_manifest(tmp.name)
        source = Path(tmp.name, "Python-3.13.15")
        source.mkdir(parents=True)

        # A previous window (start 900) was killed: its object survived as a
        # truncated file, and an older finished object must carry over.
        (source / "old.o").write_bytes(b"finished")
        os.utime(source / "old.o", (800, 800))
        (source / "torn.o").write_bytes(b"truncated")
        os.utime(source / "torn.o", (950, 950))
        (Path(tmp.name) / tool.JOURNAL_NAME).write_text(json.dumps(
            {"windows": [{"start": 900.0, "end": None}]}))

        def runner(argv, **kwargs):
            if argv[:2] == ["tar", "-xf"]:
                self.fail("a persisted source tree must not be re-extracted")

        result = tool.build(manifest, tmp.name, runner=runner,
                            download=lambda url, dest: Path(dest).write_bytes(payload),
                            now=lambda: 2000.0)
        self.assertFalse((source / "torn.o").exists(), "torn object must be recompiled")
        self.assertTrue((source / "old.o").exists(), "finished object must carry over")
        journal = json.loads(Path(tmp.name, tool.JOURNAL_NAME).read_text())
        self.assertIsNone(journal["windows"][0]["end"], "killed window must stay recorded")
        self.assertEqual(journal["windows"][1]["end"], 2000.0)
        self.assertEqual(result["windows_used"], 2)


if __name__ == "__main__":
    unittest.main()
