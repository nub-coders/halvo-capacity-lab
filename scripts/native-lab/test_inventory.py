"""Metadata must neither leak sensitive fields nor overstate migration readiness."""

import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("inventory.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InventoryTests(unittest.TestCase):
    def test_storage_needs_do_not_guess_runtime_or_source_support(self):
        row = {"app": "label", "name": "/container", "root_readonly": False, "ports": None,
               "mounts": [{"Type": "volume", "Destination": "/app/data", "RW": True,
                           "Source": "/secret-host-path", "Name": "private-volume-name"}]}
        report = module.inventory([row])
        workload = report["workloads"][0]
        self.assertEqual(workload["classification"], "configuration-needed")
        self.assertEqual(workload["native_compatibility"], "unknown")
        self.assertEqual(workload["declared_ports"], [])
        self.assertNotIn("secret-host-path", json.dumps(report))
        self.assertNotIn("private-volume-name", json.dumps(report))

    def test_readonly_is_unknown_and_docker_socket_blocks_current_contract(self):
        row = {"app": "label", "name": "/container", "root_readonly": True}
        self.assertEqual(module.classify(row)["classification"], "unknown")
        row["mounts"] = [{"Type": "bind", "Destination": "/run/docker.sock", "RW": False}]
        self.assertEqual(module.classify(row)["classification"], "blocked")

    def test_raw_inspection_and_invalid_metadata_fail_without_values(self):
        for extra in ({"Env": ["TOKEN=secret-value"]}, {"Cmd": ["private-command"]},
                      {"image_id": "registry/private-image"}, {"ports": {"70000/tcp": {}}}):
            with self.subTest(extra=extra), self.assertRaises(ValueError) as raised:
                module.classify({"app": "label", "name": "/container", **extra})
            self.assertNotIn("secret-value", str(raised.exception))
            self.assertNotIn("private-command", str(raised.exception))

    def test_duplicate_labels_remain_separate_unverified_containers(self):
        report = module.inventory([{"app": "same-label", "name": f"/container-{i}"} for i in range(2)])
        self.assertEqual(report["container_count"], 2)
        self.assertEqual(report["distinct_app_labels"], 1)
        self.assertEqual(report["classifications"]["ready"], 0)
        self.assertEqual(report["classifications"]["unknown"], 2)


if __name__ == "__main__":
    unittest.main()
