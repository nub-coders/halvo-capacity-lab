#!/usr/bin/env python3
"""Offline checks for the diagnostic-only VM launcher.

These tests deliberately do not invoke QEMU, Docker, SSH, or the launcher with
a valid lab.  They check the shell boundary and the failure receipts that can
be reviewed without a guest side effect.
"""
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parent
LAUNCHER = ROOT / "vm-docker-inspect.sh"
SOURCE = LAUNCHER.read_text()


class DockerInspectLauncherOfflineTests(unittest.TestCase):
    def test_shell_syntax(self):
        result = subprocess.run(["bash", "-n", str(LAUNCHER)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_diagnostic_external_boundary_is_accepted(self):
        result = subprocess.run(
            ["/usr/bin/bash", str(LAUNCHER), "--external-capacity-docker", "/var/tmp/halvo-native-vm-test"],
            capture_output=True, text=True, env={**os.environ, "PATH": "/nonexistent"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--external-diagnostic-docker", result.stderr)
        self.assertNotIn("QEMU", result.stderr)
        self.assertNotIn("ssh", result.stderr.lower())

    def test_diagnostic_isolation_and_bounds_are_static(self):
        self.assertIn("--external-diagnostic-docker", SOURCE)
        self.assertNotIn("external-capacity", SOURCE)
        self.assertNotIn("external-preflight", SOURCE)
        self.assertNotIn("run_network", SOURCE)
        self.assertIn("benchmark.py", SOURCE)
        self.assertIn("docker_inspect_trace_guest.py", SOURCE)
        self.assertIn("taskset --cpu-list 2,3", SOURCE)
        self.assertIn("cpu_ids=0,1", SOURCE)
        self.assertIn("-smp 2 -m 2560", SOURCE)
        self.assertIn("vm_lifetime=45m", SOURCE)
        self.assertIn("--mode diagnostic", SOURCE)
        self.assertIn("docker-inspect-diagnostic.json", SOURCE)
        self.assertIn("prepare-capacity-docker.sh --check", SOURCE)
        self.assertIn("expected_image=sha256:da38db8b3347ab4f61eaa54bd09cd6601fb8f42a31a43ad1767d25262dd9e2f8", SOURCE)

    def test_validation_receipt_has_no_hardcoded_success(self):
        self.assertIn("validate_diagnostic", SOURCE)
        self.assertIn("independent_diagnostic_accepted", SOURCE)
        self.assertIn("collector_status", SOURCE)
        self.assertIn("shutdown_graceful", SOURCE)
        self.assertIn('"passed":false', SOURCE)
        self.assertIn("instrument-validation.json", SOURCE)
        self.assertIn("launcher-cleanup.json", SOURCE)
        self.assertIn("exit \"$collector_status\"", SOURCE)


if __name__ == "__main__":
    unittest.main()
