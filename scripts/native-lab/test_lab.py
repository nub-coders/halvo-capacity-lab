"""Host/VM identity must be checked before mutations or shutdown cleanup."""

import errno
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe


class LaunchGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        out = patch.object(probe, "OUT", Path(temporary.name))
        out.start()
        self.addCleanup(out.stop)

    def test_host_execution_cannot_mutate_or_poweroff(self):
        with (
            patch.object(Path, "is_file", return_value=False),
            patch.object(Path, "mkdir") as mkdir,
            patch.object(Path, "write_text") as write,
            patch("subprocess.run") as run,
            patch.object(probe, "main") as main,
        ):
            with self.assertRaisesRegex(SystemExit, "without the disposable lab marker"):
                probe.execute()
            mkdir.assert_not_called()
            write.assert_not_called()
            run.assert_not_called()
            main.assert_not_called()

    def test_unrelated_container_cannot_reach_cleanup(self):
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "read_text", return_value="docker\n"),
            patch("subprocess.run") as run,
            patch.object(probe, "main") as main,
        ):
            with self.assertRaisesRegex(SystemExit, "unrelated container"):
                probe.execute()
            run.assert_not_called()
            main.assert_not_called()

    def test_qemu_identity_mismatch_cannot_mutate_or_poweroff(self):
        files = {
            "/etc/halvo-native-lab": "qemu-phase0-v1",
            "/etc/halvo-native-lab-vm-id": "00000000-0000-0000-0000-000000000001",
            "/sys/class/dmi/id/product_uuid": "00000000-0000-0000-0000-000000000002",
        }
        with (
            patch.object(Path, "is_file", lambda path: str(path) in files),
            patch.object(Path, "read_text", lambda path: files[str(path)]),
            patch.object(Path, "mkdir") as mkdir,
            patch.object(Path, "write_text") as write,
            patch("subprocess.run") as run,
            patch.object(probe, "main") as main,
        ):
            with self.assertRaisesRegex(SystemExit, "mismatched disposable VM identity"):
                probe.execute()
            mkdir.assert_not_called()
            write.assert_not_called()
            run.assert_not_called()
            main.assert_not_called()

    def test_matching_qemu_guest_stays_running(self):
        files = {
            "/etc/halvo-native-lab": "qemu-phase0-v1",
            "/etc/halvo-native-lab-vm-id": "00000000-0000-0000-0000-000000000001",
            "/sys/class/dmi/id/product_uuid": "00000000-0000-0000-0000-000000000001",
        }
        with (
            patch.object(Path, "is_file", lambda path: str(path) in files),
            patch.object(Path, "read_text", lambda path: files[str(path)]),
            patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "qemu\n")) as run,
            patch.object(probe, "main") as main,
        ):
            probe.execute()
            main.assert_called_once()
            self.assertEqual([call.args[0] for call in run.call_args_list],
                             [["systemd-detect-virt", "--vm"]])

    def test_marked_nspawn_guest_uses_its_shutdown_hook(self):
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "read_text", return_value="systemd-nspawn\n"),
            patch("subprocess.run") as run,
            patch.object(probe, "main") as main,
        ):
            probe.execute()
            main.assert_called_once()
            run.assert_called_once_with(["systemctl", "poweroff"], check=False)

    def test_direct_main_validates_before_mutation(self):
        for entry in (probe.main, probe.prepare_reboot, probe.verify_reboot):
            with (
                self.subTest(entry=entry.__name__),
                patch.object(probe, "require_lab", side_effect=SystemExit("unmarked")),
                patch.object(Path, "mkdir") as mkdir,
                patch("subprocess.run") as run,
            ):
                with self.assertRaisesRegex(SystemExit, "unmarked"):
                    entry()
                mkdir.assert_not_called()
                run.assert_not_called()

    def test_qemu_failure_records_error_without_shutdown(self):
        with (
            patch.object(probe, "require_lab", return_value="qemu"),
            patch.object(probe, "main", side_effect=RuntimeError("probe failure")),
            patch.object(Path, "mkdir"),
            patch.object(Path, "write_text") as write,
            patch("subprocess.run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "probe failure"):
                probe.execute()
            write.assert_called_once()
            run.assert_not_called()

    def test_missing_quota_is_an_error_before_mutation(self):
        with (
            patch.object(probe, "require_lab", return_value="qemu"),
            patch.object(Path, "is_dir", return_value=False),
            patch.object(Path, "mkdir") as mkdir,
        ):
            with self.assertRaisesRegex(RuntimeError, "Required XFS project quota"):
                probe.main()
            mkdir.assert_not_called()

    def test_failed_rerun_cannot_retain_a_previous_passing_report(self):
        (probe.OUT / "probe.json").write_text('{"passed": true}')
        with (
            patch.object(probe, "require_lab", return_value="qemu"),
            patch.object(probe, "main", side_effect=RuntimeError("new failure")),
        ):
            with self.assertRaisesRegex(RuntimeError, "new failure"):
                probe.execute()
        self.assertFalse((probe.OUT / "probe.json").exists())
        self.assertEqual(json.loads((probe.OUT / "error.json").read_text()), {"error": "new failure"})

    def test_cgroup_disappearance_during_read_is_transient(self):
        for code in (errno.ENOENT, errno.ENODEV):
            with patch.object(Path, "read_text", side_effect=OSError(code, "gone")):
                self.assertEqual(probe.cgroup_snapshot({"ControlGroup": "/unit"}), {})
        with patch.object(Path, "read_text", side_effect=PermissionError(errno.EACCES, "denied")):
            with self.assertRaises(PermissionError):
                probe.cgroup_snapshot({"ControlGroup": "/unit"})

    def test_quota_control_runs_before_boundary_file_cleanup(self):
        def jailed_write(label, source):
            # Execute the actual guest snippet against a temp directory. Raising
            # EDQUOT on open leaves the inode allocated until the control runs.
            translated = source.replace("Path('/data')", f"Path({str(probe.OUT)!r})")
            with patch.object(Path, "open", side_effect=OSError(errno.EDQUOT, "quota")):
                exec(translated)
            return {"passed": True}

        for label in ("disk-quota", "reboot-disk-quota"):
            target = probe.OUT / label
            target.write_bytes(b"allocated")
            def control():
                self.assertEqual(target.read_bytes(), b"allocated")
                return True, ""
            with (
                patch.object(probe, "DATA", probe.OUT),
                patch.object(probe, "python", side_effect=jailed_write),
                patch.object(probe, "quota_control", side_effect=control),
            ):
                self.assertTrue(probe.disk_quota_check(label)["passed"])
            self.assertFalse(target.exists())

    def test_reboot_rejects_a_fresh_counter_that_overtook_lost_data(self):
        (probe.OUT / "reboot-before.json").write_text(json.dumps({
            "boot_id": "old-boot", "checkpoint": {"ticks": 2, "token": "old-process"},
        }))
        read_text = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == "/proc/sys/kernel/random/boot_id":
                return "new-boot"
            return read_text(path, *args, **kwargs)
        with (
            patch.object(probe, "require_lab", return_value="qemu"),
            patch.object(Path, "read_text", read),
            patch.object(probe, "wait_checkpoint", return_value={
                "ticks": 100, "restored_ticks": 0, "token": "new-process", "runtime_readonly": True,
            }),
            patch.object(probe, "call"),
            patch.object(probe, "disk_quota_check") as quota,
        ):
            with self.assertRaisesRegex(RuntimeError, "did not restore"):
                probe.verify_reboot()
            quota.assert_not_called()
        self.assertFalse(json.loads((probe.OUT / "reboot.json").read_text())["passed"])


if __name__ == "__main__":
    unittest.main()
