"""The packet experiment must never change the current host's network."""

import unittest
from unittest.mock import patch

import network_probe


class NetworkGuardTests(unittest.TestCase):
    def test_unmarked_host_cannot_reach_network_commands(self):
        with (
            patch.object(network_probe.os, "geteuid", return_value=0),
            patch.object(network_probe, "require_lab", side_effect=SystemExit("not the lab")),
            patch.object(network_probe, "call") as call,
            patch.object(network_probe.Path, "write_text") as write,
        ):
            with self.assertRaises(SystemExit):
                network_probe.main()
            call.assert_not_called()
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
