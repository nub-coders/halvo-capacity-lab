"""The benchmark guard, raw counters and fixed fixtures must fail closed."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchmark


class BenchmarkTests(unittest.TestCase):
    def test_unmarked_host_cannot_write_or_launch_anything(self):
        with patch.object(benchmark, 'require_lab', side_effect=SystemExit('unmarked')), \
                patch.object(Path, 'unlink') as unlink, patch.object(Path, 'mkdir') as mkdir, \
                patch('subprocess.run') as run:
            with self.assertRaises(SystemExit):
                benchmark.run_native()
            unlink.assert_not_called()
            mkdir.assert_not_called()
            run.assert_not_called()

    def test_missing_dead_or_oom_cgroups_are_not_zero_memory_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                benchmark.sample_cgroup(root)
            for key, value in {'memory.current': '100', 'memory.peak': '200',
                               'pids.current': '2', 'memory.stat': 'anon 60\nfile 40',
                               'memory.events': 'oom 0\noom_kill 0', 'cpu.stat': 'usage_usec 12'}.items():
                (root / key).write_text(value)
            self.assertEqual(benchmark.sample_cgroup(root)['memory_current_bytes'], 100)
            (root / 'pids.current').write_text('0')
            with self.assertRaises(RuntimeError):
                benchmark.sample_cgroup(root)
            (root / 'pids.current').write_text('2')
            (root / 'memory.events').write_text('oom 1\noom_kill 0')
            with self.assertRaises(RuntimeError):
                benchmark.sample_cgroup(root)

    def test_fixture_digest_covers_nginx_worker_configuration(self):
        fixture = benchmark.FIXTURES['static']
        changed = dict(fixture, files=dict(fixture['files']))
        changed['files']['nginx.conf'] = changed['files']['nginx.conf'].replace('worker_processes 1', 'worker_processes auto')
        self.assertNotEqual(benchmark.fixture_digest(fixture), benchmark.fixture_digest(changed))

    def test_fixed_python_server_imports_the_standard_library(self):
        # Import-only check in a temporary source directory catches a fixture
        # named http.py shadowing the standard library; starts no listener.
        with tempfile.TemporaryDirectory() as directory:
            benchmark.write_fixtures(Path(directory))
            result = subprocess.run([sys.executable, '-c', 'from http.server import HTTPServer'],
                                    cwd=directory, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_health_clients_enter_only_the_network_namespace(self):
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'halvo-memory')) as run:
            self.assertTrue(benchmark.ready(123, benchmark.FIXTURES['node']))
            argv = run.call_args.args[0]
            self.assertEqual(argv[:3], ['nsenter', '--net=/proc/123/ns/net', '--'])
            self.assertNotIn('--cgroup', argv)

    def test_python_fixtures_skip_optional_startup_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'loaded'
            (root / 'sitecustomize.py').write_text(
                "from pathlib import Path; Path(__file__).with_name('loaded').touch()\n")
            env = dict(os.environ, PYTHONPATH=directory)
            program = ('import sys; from http.server import HTTPServer; '
                       'print("site" in sys.modules)')
            control = subprocess.run([sys.executable, '-c', program], env=env,
                                     capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual(control.stdout.strip(), 'True')
            self.assertTrue(marker.exists())
            marker.unlink()
            for name in ('python', 'worker'):
                with self.subTest(fixture=name):
                    flags = benchmark.FIXTURES[name]['argv'][1:-1]
                    result = subprocess.run([sys.executable, *flags, '-c', program], env=env,
                                            capture_output=True, text=True, timeout=5, check=True)
                    self.assertEqual(result.stdout.strip(), 'False')
                    self.assertFalse(marker.exists())

    def test_failed_launch_and_cleanup_are_recorded_without_a_passing_case(self):
        def fake_call(*argv, **options):
            if argv[0] == 'systemd-run':
                raise RuntimeError('fixture launch failed')
            return subprocess.CompletedProcess(argv, 0, '', '')

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(benchmark, 'runtime_identity', return_value={}), \
                patch.object(benchmark.probe, 'call', side_effect=fake_call), \
                patch('subprocess.run', side_effect=subprocess.TimeoutExpired('systemctl', 15)) as stop:
            case = benchmark.native_case('node', Path(directory))
            self.assertFalse(case['passed'])
            self.assertFalse(case['cleanup_passed'])
            self.assertIn('fixture launch failed', case['error'])
            self.assertIn('timed out', case['cleanup_error'])
            argv = stop.call_args.args[0]
            self.assertEqual(argv[:2], ['systemctl', 'stop'])
            self.assertTrue(argv[2].startswith('halvo-memory-node-'))


if __name__ == '__main__':
    unittest.main()
