"""Unit tests for target and port parsing."""

import unittest
from scanner.target_parser import (
    parse_targets,
    parse_ports,
    TOP_20_PORTS,
    TOP_100_PORTS,
    TOP_1000_PORTS,
)


class TestTargetParser(unittest.TestCase):
    def test_single_ip(self):
        targets = parse_targets("192.168.1.1")
        self.assertEqual(targets, ["192.168.1.1"])

    def test_cidr_network(self):
        targets = parse_targets("192.168.1.0/30")
        self.assertEqual(targets, ["192.168.1.1", "192.168.1.2"])

    def test_ip_range_full(self):
        targets = parse_targets("10.0.0.1-10.0.0.4")
        self.assertEqual(targets, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])

    def test_ip_range_short(self):
        targets = parse_targets("192.168.1.10-12")
        self.assertEqual(targets, ["192.168.1.10", "192.168.1.11", "192.168.1.12"])

    def test_comma_delimited(self):
        targets = parse_targets("127.0.0.1, 127.0.0.2")
        self.assertEqual(targets, ["127.0.0.1", "127.0.0.2"])

    def test_invalid_target(self):
        with self.assertRaises(ValueError):
            parse_targets("999.999.999.999")

    def test_max_hosts_enforced(self):
        with self.assertRaises(ValueError):
            parse_targets("10.0.0.0/16", max_hosts=100)


class TestPortParser(unittest.TestCase):
    def test_top20_ports(self):
        ports = parse_ports("top20")
        self.assertEqual(ports, sorted(list(set(TOP_20_PORTS))))

    def test_top100_ports(self):
        ports = parse_ports("top100")
        self.assertEqual(ports, sorted(list(set(TOP_100_PORTS))))

    def test_top1000_ports(self):
        ports = parse_ports("top1000")
        self.assertGreater(len(ports), 900)
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(8080, ports)

    def test_all_ports(self):
        ports = parse_ports("all_ports")
        self.assertEqual(len(ports), 65535)
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 65535)

    def test_custom_ports_list(self):
        ports = parse_ports("custom", custom_ports="80,443,8080")
        self.assertEqual(ports, [80, 443, 8080])

    def test_custom_ports_range(self):
        ports = parse_ports("custom", custom_ports="21,22,8000-8003")
        self.assertEqual(ports, [21, 22, 8000, 8001, 8002, 8003])

    def test_invalid_port_range(self):
        with self.assertRaises(ValueError):
            parse_ports("custom", custom_ports="70000")


if __name__ == "__main__":
    unittest.main()
