import json
import unittest

from make_workload_snapshot import collect, project


def inspect_record(**overrides):
    info = {
        "Name": "/myapp-0bc12c",
        "Image": "sha256:" + "a" * 64,
        "Config": {
            "Labels": {"paas.app": "myapp", "paas.role": "workload"},
            "ExposedPorts": {"3000/tcp": {}},
        },
        "State": {"Status": "running"},
        "HostConfig": {"Memory": 536870912, "NanoCpus": 500000000, "ReadonlyRootfs": False},
        "Mounts": [
            {
                "Type": "volume", "Name": "myapp-data", "Source": "/var/lib/docker/volumes/x",
                "Destination": "/data", "Driver": "local", "Mode": "", "RW": True,
                "Propagation": "",
            }
        ],
    }
    for key, value in overrides.items():
        if key == "Config":
            info["Config"] = {**info["Config"], **value}
        elif key == "HostConfig":
            info["HostConfig"] = {**info["HostConfig"], **value}
        else:
            info[key] = value
    return info


class ProjectionTest(unittest.TestCase):
    def test_projection_carries_exactly_the_classifier_whitelist(self):
        row = project(inspect_record())
        self.assertEqual(
            set(row),
            {"app", "name", "state", "image_id", "ports", "mounts", "root_readonly",
             "memory_limit", "cpu_nanos", "disk_options"},
        )
        # The projection must not carry anything beyond the whitelist: no
        # environment, commands, image tags, or network settings leak through.
        self.assertEqual(row["app"], "myapp")
        self.assertEqual(row["image_id"], "sha256:" + "a" * 64)
        self.assertEqual(row["ports"], {"3000/tcp": True})

    def test_resource_limits_of_zero_mean_unlimited(self):
        row = project(inspect_record(HostConfig={"Memory": 0, "NanoCpus": 0}))
        self.assertIsNone(row["memory_limit"])
        self.assertIsNone(row["cpu_nanos"])

    def test_root_state_preserves_boolean_facts_and_unknown(self):
        for value, expected in ((True, True), (False, False), (None, None), (0, None),
                                (1, None), ("true", None), ("false", None), ([], None), ({}, None)):
            with self.subTest(value=value):
                row = project(inspect_record(HostConfig={"ReadonlyRootfs": value}))
                self.assertIs(row["root_readonly"], expected)
        info = inspect_record()
        del info["HostConfig"]["ReadonlyRootfs"]
        self.assertIsNone(project(info)["root_readonly"])

    def test_mount_projection_keeps_only_classifier_fields(self):
        info = inspect_record()
        info["Mounts"][0]["Options"] = ["rbind"]  # extra inspect detail must be dropped
        row = project(info)
        self.assertEqual(set(row["mounts"][0]), {"Type", "Name", "Source", "Destination",
                                                 "Driver", "Mode", "RW", "Propagation"})

    def test_non_workload_containers_are_excluded(self):
        self.assertIsNone(project(inspect_record(Config={"Labels": {"paas.role": "workload"}})))
        self.assertIsNone(project(inspect_record(Config={"Labels": {"paas.app": "myapp"}})))


class CollectTest(unittest.TestCase):
    def test_collect_keeps_workloads_and_skips_the_rest(self):
        rows = collect(lambda: [
            inspect_record(),
            {"Name": "/unrelated", "Config": {"Labels": {}}},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "myapp-0bc12c")


class RoundTripTest(unittest.TestCase):
    def test_snapshot_round_trips_through_inventory(self):
        import inventory

        rows = collect(lambda: [inspect_record(Mounts=[])])
        report = inventory.inventory(rows)
        self.assertEqual(report["container_count"], 1)
        workload = report["workloads"][0]
        self.assertEqual(workload["app_label"], "myapp")
        self.assertIs(workload["root_readonly"], False)
        self.assertEqual(workload["classification"], "configuration-needed")
        self.assertEqual(workload["native_compatibility"], "unknown")
        self.assertTrue(any("Writable root" in reason for reason in workload["reasons"]))
        json.dumps(report)


if __name__ == "__main__":
    unittest.main()
