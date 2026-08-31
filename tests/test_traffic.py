"""Unit tests for the traffic aggregation (no network, no Home Assistant)."""
import importlib.util
import sys
import unittest
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "custom_components" / "glinet" / "traffic.py"
_SPEC = importlib.util.spec_from_file_location("glinet_traffic", _PATH)
glinet_traffic = importlib.util.module_from_spec(_SPEC)
sys.modules["glinet_traffic"] = glinet_traffic
_SPEC.loader.exec_module(glinet_traffic)

TrafficTracker = glinet_traffic.TrafficTracker


def client(mac, rx, tx):
    """A client entry as the router sends it: counters as strings."""
    return {"mac": mac, "total_rx": str(rx), "total_tx": str(tx)}


class TestTotals(unittest.TestCase):
    def setUp(self):
        self.tracker = TrafficTracker()

    def test_sums_counters_across_clients(self):
        result = self.tracker.update([client("a", 100, 10), client("b", 200, 20)], 0.0)
        self.assertEqual(result["rx_bytes"], 300)
        self.assertEqual(result["tx_bytes"], 30)
        self.assertEqual(result["clients_counted"], 2)

    def test_accepts_int_counters_too(self):
        # total_rx_init came back as an int on real hardware, so don't assume str.
        result = self.tracker.update([{"mac": "a", "total_rx": 100, "total_tx": 10}], 0.0)
        self.assertEqual(result["rx_bytes"], 100)

    def test_falls_back_to_ip_when_mac_is_absent(self):
        result = self.tracker.update([{"ip": "192.168.8.5", "total_rx": "7", "total_tx": "1"}], 0.0)
        self.assertEqual(result["rx_bytes"], 7)

    def test_ignores_entries_without_any_key(self):
        result = self.tracker.update([{"total_rx": "999"}], 0.0)
        self.assertEqual(result["rx_bytes"], 0)
        self.assertEqual(result["clients_counted"], 0)

    def test_missing_counters_count_as_zero(self):
        result = self.tracker.update([{"mac": "a"}], 0.0)
        self.assertEqual(result["rx_bytes"], 0)

    def test_total_survives_a_client_leaving_the_list(self):
        # A phone going to sleep must not collapse the total.
        self.tracker.update([client("a", 1000, 100), client("b", 500, 50)], 0.0)
        result = self.tracker.update([client("a", 1200, 120)], 30.0)
        self.assertEqual(result["rx_bytes"], 1700)
        self.assertEqual(result["clients_counted"], 2)
        self.assertEqual(result["clients_online"], 1)

    def test_counter_going_backwards_is_pinned(self):
        # A client reboot resets its counter; the total must not decrease.
        self.tracker.update([client("a", 1000, 100)], 0.0)
        result = self.tracker.update([client("a", 5, 1)], 30.0)
        self.assertEqual(result["rx_bytes"], 1000)
        self.assertEqual(result["tx_bytes"], 100)

    def test_total_is_monotonic_across_a_churning_client_list(self):
        seen = []
        for i, payload in enumerate([
            [client("a", 100, 10), client("b", 200, 20)],
            [client("a", 150, 15)],
            [client("b", 250, 25), client("c", 10, 1)],
            [],
            [client("a", 900, 90), client("b", 900, 90), client("c", 900, 90)],
        ]):
            seen.append(self.tracker.update(payload, float(i * 30))["rx_bytes"])
        self.assertEqual(seen, sorted(seen), seen)


class TestRates(unittest.TestCase):
    def setUp(self):
        self.tracker = TrafficTracker()

    def test_no_rate_on_the_first_reading(self):
        result = self.tracker.update([client("a", 100, 10)], 0.0)
        self.assertIsNone(result["rx_rate"])
        self.assertIsNone(result["tx_rate"])

    def test_rate_is_the_delta_over_elapsed_time(self):
        self.tracker.update([client("a", 0, 0)], 0.0)
        result = self.tracker.update([client("a", 3_000_000, 300_000)], 30.0)
        self.assertAlmostEqual(result["rx_rate"], 100_000.0)
        self.assertAlmostEqual(result["tx_rate"], 10_000.0)
        # 100 kB/s is 0.8 Mbit/s, which is what the sensor publishes.
        self.assertAlmostEqual(result["rx_rate"] * 8 / 1e6, 0.8)

    def test_rate_is_zero_when_nothing_moves(self):
        self.tracker.update([client("a", 100, 10)], 0.0)
        result = self.tracker.update([client("a", 100, 10)], 30.0)
        self.assertEqual(result["rx_rate"], 0)
        self.assertEqual(result["tx_rate"], 0)

    def test_rate_never_goes_negative(self):
        self.tracker.update([client("a", 1000, 100), client("b", 1000, 100)], 0.0)
        result = self.tracker.update([client("a", 500, 50)], 30.0)
        self.assertGreaterEqual(result["rx_rate"], 0)
        self.assertGreaterEqual(result["tx_rate"], 0)

    def test_no_rate_when_no_time_elapsed(self):
        self.tracker.update([client("a", 0, 0)], 5.0)
        result = self.tracker.update([client("a", 100, 10)], 5.0)
        self.assertIsNone(result["rx_rate"])

    def test_reproduces_the_measured_download(self):
        # The 100 MB probe: 87,201,912 bytes landed on one client in 10.7s.
        self.tracker.update([client("mac", 461_039_523_647, 104_091_700_352)], 0.0)
        result = self.tracker.update(
            [client("mac", 461_039_523_647 + 87_201_912, 104_091_700_352)], 10.7)
        self.assertAlmostEqual(result["rx_rate"] * 8 / 1e6, 65.2, places=1)


if __name__ == "__main__":
    unittest.main()
