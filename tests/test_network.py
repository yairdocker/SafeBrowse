"""Subnet selection and generated Squid ACL, without contacting Docker."""
import importlib.util
import ipaddress
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("network", ROOT / "scripts/network.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


class NetworkTests(unittest.TestCase):
    def test_existing_supernet_is_not_selected(self):
        used = [ipaddress.ip_network("172.28.0.0/16"), ipaddress.ip_network("172.31.0.0/24")]
        self.assertEqual(str(network.choose(used)), "172.31.1.0/24")

    def test_skip_after_docker_rejects_candidate(self):
        skipped = [ipaddress.ip_network("172.31.0.0/24")]
        self.assertEqual(str(network.choose([], skipped)), "172.31.1.0/24")

    def test_generated_acl_and_state_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gateway").mkdir()
            (root / "gateway/squid.conf").write_text(
                "acl sandbox src 172.28.0.0/24 # source\nhttp_access allow sandbox\n")
            runtime = root / ".runtime"
            with patch.object(network, "RUNTIME", runtime), patch.object(network, "STATE", runtime / "network.json"), \
                 patch.object(network, "SQUID", runtime / "squid.conf"), \
                 patch.object(network, "SOURCE", root / "gateway/squid.conf"), \
                 patch.object(network, "docker_subnets", return_value=[ipaddress.ip_network("172.28.0.0/16")]):
                self.assertEqual(str(network.select()), "172.31.0.0/24")
                self.assertEqual(str(network.current()), "172.31.0.0/24")
                self.assertIn("acl sandbox src 172.31.0.0/24", network.SQUID.read_text())
                network.SQUID.write_text("acl sandbox src 0.0.0.0/0\n")
                with self.assertRaises(ValueError):
                    network.current()


if __name__ == "__main__":
    unittest.main()
