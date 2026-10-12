"""Reproducible, verifiable payload-lineage freezing."""

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import freeze_lineage


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class FreezeLineageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="freeze-test-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.pred = self.root / "pred"
        self.overlay = self.root / "overlay"
        self.pred.mkdir()
        self.overlay.mkdir()
        self.files = {"a.py": b"print('a-v1')\n", "b.py": b"print('b')\n",
                      "data.txt": b"fixture bytes\n"}
        lines = []
        for name, body in self.files.items():
            (self.pred / name).write_bytes(body)
            lines.append(f"{_sha(body)}  {name}\n")
        (self.pred / "SHA256SUMS").write_text("".join(lines))
        # Overlay carries a changed a.py and an unchanged b.py.
        self.changed_body = b"print('a-v2-cheap-health')\n"
        (self.overlay / "a.py").write_bytes(self.changed_body)
        (self.overlay / "b.py").write_bytes(self.files["b.py"])

    def test_overlays_only_changed_file_and_regenerates_a_verifiable_manifest(self):
        dst = self.root / "p29"
        result = freeze_lineage.freeze(self.pred, dst, self.overlay, ["a.py"], "SHA256SUMS")
        self.assertEqual(result["files"], 3)
        self.assertEqual(set(result["changed"]), {"a.py"})
        self.assertEqual((dst / "a.py").read_bytes(), self.changed_body)
        self.assertEqual((dst / "b.py").read_bytes(), self.files["b.py"])
        manifest = (dst / "SHA256SUMS").read_text()
        self.assertIn(f"{_sha(self.changed_body)}  a.py\n", manifest)
        self.assertEqual(result["payload_sha256"], _sha(manifest.encode()))
        self.assertNotEqual(result["payload_sha256"],
                            _sha((self.pred / "SHA256SUMS").read_bytes()))
        if shutil.which("sha256sum"):
            check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=dst,
                                   capture_output=True)
            self.assertEqual(check.returncode, 0, check.stderr)

    def test_refuses_when_a_declared_file_is_identical(self):
        (self.overlay / "a.py").write_bytes(self.files["a.py"])
        dst = self.root / "p29"
        with self.assertRaisesRegex(SystemExit, "identical to predecessor"):
            freeze_lineage.freeze(self.pred, dst, self.overlay, ["a.py"], "SHA256SUMS")
        self.assertFalse(dst.exists())

    def test_refuses_an_unexpected_change_from_a_stale_predecessor_manifest(self):
        # b.py's real bytes no longer match its recorded hash: the integrity
        # guard must catch it even though only a.py was declared changed.
        (self.pred / "SHA256SUMS").write_text(
            f"{_sha(self.files['a.py'])}  a.py\n{_sha(b'stale')}  b.py\n"
            f"{_sha(self.files['data.txt'])}  data.txt\n")
        dst = self.root / "p29"
        with self.assertRaisesRegex(SystemExit, "unexpected content changes: b.py"):
            freeze_lineage.freeze(self.pred, dst, self.overlay, ["a.py"], "SHA256SUMS")
        self.assertFalse(dst.exists())

    def test_refuses_a_changed_file_absent_from_the_manifest(self):
        with self.assertRaisesRegex(SystemExit, "not in predecessor manifest"):
            freeze_lineage.freeze(self.pred, self.root / "p29", self.overlay,
                                  ["unknown.py"], "SHA256SUMS")

    def test_refuses_a_present_but_unlisted_file(self):
        (self.pred / "stray.py").write_bytes(b"unlisted\n")
        dst = self.root / "p29"
        with self.assertRaisesRegex(SystemExit, "present but unlisted: stray.py"):
            freeze_lineage.freeze(self.pred, dst, self.overlay, ["a.py"], "SHA256SUMS")
        self.assertFalse(dst.exists())

    def test_refuses_an_existing_destination(self):
        dst = self.root / "p29"
        dst.mkdir()
        with self.assertRaisesRegex(SystemExit, "already exists"):
            freeze_lineage.freeze(self.pred, dst, self.overlay, ["a.py"], "SHA256SUMS")


    def test_ignores_bytecode_cache_in_the_predecessor(self):
        # A lineage dir that has had a test run carries __pycache__/*.pyc that is
        # not in its manifest; it must not block the freeze or land in payload29.
        cache = self.pred / "__pycache__"
        cache.mkdir()
        (cache / "capacity.cpython-314.pyc").write_bytes(b"\x00bytecode")
        (self.pred / "stale.pyc").write_bytes(b"\x00bytecode")
        dst = self.root / "p29"
        result = freeze_lineage.freeze(self.pred, dst, self.overlay, ["a.py"], "SHA256SUMS")
        self.assertEqual(set(result["changed"]), {"a.py"})
        self.assertFalse((dst / "__pycache__").exists())
        self.assertFalse((dst / "stale.pyc").exists())
        if shutil.which("sha256sum"):
            check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=dst,
                                   capture_output=True)
            self.assertEqual(check.returncode, 0, check.stderr)


if __name__ == "__main__":
    unittest.main()
