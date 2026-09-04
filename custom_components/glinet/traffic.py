"""Aggregate the per-client byte counters into router-wide traffic figures.

GL.iNet 4.x exposes no WAN-level counter. `clients get_list` is the only source
of traffic data, and each client entry carries:

- ``total_rx`` / ``total_tx``: cumulative byte counters, sent as strings. These
  were verified against a download of known size: 104,857,600 bytes downloaded
  moved the summed counters by 88,566,970 (0.84x), the shortfall being ~1.8s of
  sampling lag at the measured rate. So they are plain bytes, attributed to the
  right client, and neither doubled nor bit-valued.
- ``rx`` / ``tx``: a heavily smoothed rate that lags reality by so much it is
  useless -- during that same download it peaked at 5.72 Mbit/s against
  78.3 Mbit/s actually measured, and was still climbing after the transfer had
  finished. It is deliberately ignored here.

So the rate is derived from successive counter readings instead.

Scope: these counters are per-client accounting on the router's routed path.
That makes them a good proxy for WAN traffic -- which is what the download
above measured -- but traffic between two devices on the same LAN is switched
without traversing that path, so it is very likely absent from these figures.
That part has not been measured.

This module holds no Home Assistant imports on purpose: the arithmetic is the
part worth unit-testing.
"""
from typing import Any, Dict, List, Optional


def _as_int(value: Any) -> int:
    """Counters arrive as strings, and occasionally as ints."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class TrafficTracker:
    """Turn successive `clients get_list` payloads into totals and rates.

    The summed total is kept monotonic, which a naive sum is not:

    - a client that drops off the list keeps its last known counter, so the
      total does not collapse every time a phone goes to sleep;
    - a counter that goes backwards (the client or the router rebooted) is
      pinned to its previous value rather than dragging the total down.

    Both matter because the totals feed a ``TOTAL_INCREASING`` sensor, which
    reads any decrease as a meter reset.
    """

    def __init__(self) -> None:
        """Initialize the tracker."""
        self._totals: Dict[str, List[int]] = {}
        self._previous: Optional[List[float]] = None

    def update(self, clients: Optional[List[Dict]], timestamp: float) -> Dict[str, Any]:
        """Fold one client list in and return the current traffic figures.

        `timestamp` should come from a monotonic clock. Rates are None until a
        second reading is available.
        """
        for client in clients or []:
            key = client.get("mac") or client.get("ip")
            if not key:
                continue
            seen = self._totals.get(key, [0, 0])
            self._totals[key] = [
                max(_as_int(client.get("total_rx")), seen[0]),
                max(_as_int(client.get("total_tx")), seen[1]),
            ]

        rx_bytes = sum(value[0] for value in self._totals.values())
        tx_bytes = sum(value[1] for value in self._totals.values())

        rx_rate: Optional[float] = None
        tx_rate: Optional[float] = None
        if self._previous is not None:
            elapsed = timestamp - self._previous[0]
            if elapsed > 0:
                rx_rate = max(0, rx_bytes - self._previous[1]) / elapsed
                tx_rate = max(0, tx_bytes - self._previous[2]) / elapsed
        self._previous = [timestamp, rx_bytes, tx_bytes]

        return {
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "rx_rate": rx_rate,
            "tx_rate": tx_rate,
            "clients_counted": len(self._totals),
            "clients_online": len(clients or []),
        }
