"""Measurement must reject ambiguous disk coverage and cgroup path escapes."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("measure", Path(__file__).with_name("measure.py"))
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class MeasurementTests(unittest.TestCase):
    def test_disk_paths_reject_root_missing_overlap_and_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "child"
            child.mkdir()
            alias = root / "alias"
            alias.symlink_to(child, target_is_directory=True)
            self.assertEqual(measure.directories([child]), [child])
            for values in (["/"], [root / "missing"], [root, child], [child, root], [child, alias]):
                with self.subTest(values=values), self.assertRaises((ValueError, OSError)):
                    measure.directories(values)

    def test_cgroups_reject_traversal_outside_and_symlink_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cgroups = root / "cgroup"
            cgroups.mkdir()
            (cgroups / "escape").symlink_to(root, target_is_directory=True)
            with patch.object(measure, "CGROUP_ROOT", cgroups):
                for value in (root, "relative", cgroups / "missing", cgroups / "..", cgroups / "escape"):
                    with self.subTest(value=value), self.assertRaises((ValueError, OSError)):
                        measure.cgroup_snapshot(value)

    def test_counter_snapshot_and_symlink_counter_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "memory.current").write_text("4096\n")
            (root / "cpu.stat").write_text("usage_usec 123\nuser_usec 100\n")
            (root / "memory.events").write_text("oom 0\noom_kill 0\n")
            (root / "pids.current").write_text("2\n")
            with patch.object(measure, "CGROUP_ROOT", root):
                snapshot = measure.cgroup_snapshot(root)
                self.assertEqual(snapshot["memory.current"], 4096)
                self.assertEqual(snapshot["cpu.stat"], {"usage_usec": 123, "user_usec": 100})
                self.assertEqual(snapshot["unavailable"], ["memory.peak"])
                (root / "memory.peak").symlink_to(root / "memory.current")
                with self.assertRaises(OSError):
                    measure.cgroup_snapshot(root)


if __name__ == "__main__":
    unittest.main()
