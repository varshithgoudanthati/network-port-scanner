import argparse
import socket
import unittest
from unittest.mock import patch
from scanner import ports, probe


class ScannerTests(unittest.TestCase):
    def test_port_ranges(self):
        self.assertEqual(ports("80,22,80,90-92"), [22, 80, 90, 91, 92])

    def test_invalid_ports(self):
        for value in ("0", "65536", "90-80", "abc", ""):
            with self.assertRaises(argparse.ArgumentTypeError):
                ports(value)

    def test_local_connections(self):
        with socket.socket() as server, socket.socket() as reserved:
            server.bind(("127.0.0.1", 0))
            server.listen()
            reserved.bind(("127.0.0.1", 0))
            for port, expected in (
                (server.getsockname()[1], "open"),
                (reserved.getsockname()[1], "closed"),
            ):
                result = probe(
                    "localhost", socket.AF_INET, "127.0.0.1", port, 1
                )
                self.assertEqual(result["status"], expected)

    def test_timeout(self):
        with patch("scanner.socket.socket") as mocked:
            connection = mocked.return_value.__enter__.return_value
            connection.connect.side_effect = socket.timeout()
            result = probe(
                "localhost", socket.AF_INET, "127.0.0.1", 80, 0.1
            )
            self.assertEqual(result["status"], "timeout")


if __name__ == "__main__":
    unittest.main()
