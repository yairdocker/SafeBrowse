"""Subnet selection and generated Squid ACL, without contacting Docker."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import stat
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


class GeneratedFileTests(unittest.TestCase):
    """Generated Squid configuration and state: UTF-8, LF only, and consistent with their source."""
    SOURCE = "# r\u00e8gles\nacl sandbox src 172.28.0.0/24 # source\nhttp_access allow sandbox\n"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "gateway").mkdir()
        self.source = self.root / "gateway/squid.conf"
        self.source.write_bytes(self.SOURCE.encode("utf-8"))
        runtime = self.root / ".runtime"
        for name, value in (("RUNTIME", runtime), ("STATE", runtime / "network.json"), ("SQUID", runtime / "squid.conf"),
                            ("SOURCE", self.source)):
            patcher = patch.object(network, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(network, "docker_subnets", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_generated_files_are_utf8_with_lf_only_and_keep_their_modes(self):
        opened = []
        real = tempfile.NamedTemporaryFile

        def recording(*args, **options):
            opened.append(options)
            return real(*args, **options)
        with patch.object(network.tempfile, "NamedTemporaryFile", side_effect=recording):
            self.assertEqual(str(network.select()), "172.31.0.0/24")
        squid, state = network.SQUID.read_bytes(), network.STATE.read_bytes()
        self.assertEqual(squid, self.SOURCE.replace("172.28.0.0/24", "172.31.0.0/24").encode("utf-8"))
        self.assertEqual(state, b'{"subnet": "172.31.0.0/24"}\n')
        self.assertEqual(json.loads(state), {"subnet": "172.31.0.0/24"})
        for data in (squid, state):
            self.assertNotIn(b"\r", data)
            self.assertTrue(data.endswith(b"\n"))
        # LF is requested explicitly, so the result does not depend on the platform's default.
        self.assertEqual([(options["encoding"], options["newline"]) for options in opened], [("utf-8", "\n")] * 2)
        self.assertEqual(stat.S_IMODE(network.SQUID.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(network.STATE.stat().st_mode), 0o600)
        self.assertEqual(sorted(path.name for path in network.RUNTIME.iterdir()), ["network.json", "squid.conf"])
        self.assertEqual(str(network.current()), "172.31.0.0/24")

    def test_carriage_returns_in_the_source_are_refused_and_nothing_is_written(self):
        for damaged in (self.SOURCE.replace("\n", "\r\n"), self.SOURCE + "http_access deny all\r\n", self.SOURCE + "\r"):
            with self.subTest(damaged=damaged[-12:]):
                self.source.write_bytes(damaged.encode("utf-8"))
                with self.assertRaisesRegex(RuntimeError, "carriage returns"):
                    network.select()
                self.assertFalse(network.SQUID.exists() or network.STATE.exists())

    def test_runtime_configuration_with_other_line_endings_is_not_current(self):
        network.select()
        expected = network.SQUID.read_bytes()
        for damaged in (expected.replace(b"\n", b"\r\n"), expected + b"\r"):
            with self.subTest(damaged=damaged[-4:]):
                network.SQUID.write_bytes(damaged)
                with self.assertRaises(ValueError):
                    network.current()
        network.SQUID.write_bytes(expected)
        self.assertEqual(str(network.current()), "172.31.0.0/24")
        self.source.write_bytes(self.SOURCE.replace("\n", "\r\n").encode("utf-8"))
        with self.assertRaises(RuntimeError):
            network.current()


if __name__ == "__main__":
    unittest.main()
