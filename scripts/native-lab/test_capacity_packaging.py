"""Real image-context staging and UID 1000 reads; no Docker daemon or VM."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import benchmark
import capacity_fixtures


ROOT = Path(__file__).resolve().parent


class CapacityPackagingTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, "root is needed to reproduce root-owned COPY files")
    def test_prepared_fixtures_are_readable_by_the_image_user_under_private_umask(self):
        with tempfile.TemporaryDirectory(prefix="halvo-capacity-packaging-") as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            source, reference, results, image = (root / name for name in
                                                  ("source", "reference", "results", "app"))
            for path in (source, reference, results, image):
                path.mkdir()
                path.chmod(0o755)
            for name in ("capacity.Dockerfile", "capacity_fixtures.py", "benchmark.py",
                         "benchmark_compare.py", "probe.py"):
                shutil.copyfile(ROOT / name, source / name)
                (source / name).chmod(0o644)
            # Only this temporary copy's guest boundary and Docker CLI are stubbed.
            (source / "guard.py").write_text(
                "def require_lab(): raise AssertionError('unexpected lab operation')\n"
                "if __name__ == '__main__': print('qemu')\n")
            script = (ROOT / "prepare-capacity-docker.sh").read_text()
            script = script.replace("/var/lib/halvo-docker-reference", str(reference))
            script = script.replace("/results", str(results))
            (source / "prepare-capacity-docker.sh").write_text(script)
            original_id, derived_id = "sha256:" + "a" * 64, "sha256:" + "b" * 64
            (reference / "docker-reference-image-id").write_text(original_id + "\n")
            docker = root / "docker"
            docker.write_text("""#!/usr/bin/python3
import sys
from pathlib import Path
args = sys.argv[1:]
assert args[:2] == ['--host', 'unix:///var/run/docker.sock']
if args[2:4] == ['image', 'inspect']:
    print(args[-1])
elif args[2:4] == ['image', 'build']:
    assert '--pull=false' in args and '--network=none' in args
    Path(args[args.index('--iidfile') + 1]).write_text('sha256:' + 'b' * 64 + '\\n')
else:
    raise AssertionError(args)
""")
            docker.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
            command = ["bash", str(source / "prepare-capacity-docker.sh")]
            for args in ([], ["--check"]):
                prepared = subprocess.run(command + args, env=env, capture_output=True,
                                          text=True, timeout=30, umask=0o077)
                self.assertEqual(prepared.returncode, 0, prepared.stderr)
            receipt = json.loads((results / "capacity-image.json").read_text())
            self.assertEqual(receipt["reference_image"], original_id)
            self.assertEqual(receipt["image"], derived_id)
            self.assertFalse(receipt["phase0_complete"])
            context, = reference.glob("capacity-context-*")
            # COPY preserves the staged files' modes and root ownership. The
            # unchanged reference supplies these already-readable dependencies.
            for name in ("benchmark.py", "benchmark_compare.py", "probe.py", "guard.py"):
                shutil.copyfile(source / name, image / name)
                (image / name).chmod(0o644)
            for line in (context / "Dockerfile").read_text().splitlines():
                if line.startswith("COPY "):
                    _, filename, destination = line.split()
                    self.assertEqual(Path(destination).parent, Path("/app"))
                    shutil.copy2(context / filename, image / Path(destination).name)
            read = subprocess.run(
                ["/usr/bin/python3", "-B", "-c",
                 "import os, runpy; assert os.geteuid() == 1000; "
                 "fixture = runpy.run_path('capacity_fixtures.py'); "
                 "print(fixture['deployed_digest']('.', 'python'))"],
                cwd=image, user=1000, group=1000, extra_groups=[],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(read.stdout.strip(), benchmark.fixture_digest(capacity_fixtures.FIXTURES["python"]))
            for name in ("capacity_fixtures.py", "server.py"):
                self.assertEqual((image / name).stat().st_uid, 0)
                self.assertEqual((image / name).stat().st_mode & 0o777, 0o644)
            self.assertEqual(context.stat().st_mode & 0o777, 0o700)
            self.assertEqual((results / "capacity-image.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
