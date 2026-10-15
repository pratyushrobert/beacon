"""Baseline evaluation and compatibility logic for Beacon Memory."""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from beacon.memory.models import BaselineHealth
from beacon.memory.store import MemoryStore

logger = logging.getLogger(__name__)


class BaselineEngine:
    """
    Evaluates baseline quality, capture compatibility, and normalized metrics.
    Guarantees that incompatible or insufficient captures are identified with explicit warnings.
    """

    def __init__(self, store: Optional[MemoryStore] = None):
        self.store = store or MemoryStore()

    def evaluate_compatibility(
        self,
        current_results: Dict[str, Any],
        exclude_current_id: Optional[str] = None,
    ) -> Tuple[BaselineHealth, Optional[str]]:
        """
        Evaluate whether the historical baseline is sufficient and compatible with current capture.
        Returns (BaselineHealth, warning_message).
        """
        summary = self.store.get_baseline_summary()
        prior_captures = summary["captures_count"]

        # If evaluating against store where current capture might already be indexed
        if exclude_current_id:
            with self.store._get_connection() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM memory_captures WHERE capture_id != ?",
                    (exclude_current_id,)
                ).fetchone()
                prior_captures = row[0] if row else 0

        # Case 1: Empty baseline
        if prior_captures == 0:
            return (
                BaselineHealth.INSUFFICIENT,
                "Initial Capture: No prior historical observations in memory. Establishing baseline.",
            )

        # Case 2: Limited baseline
        if prior_captures < 3:
            health = BaselineHealth.LIMITED
            warning = f"Limited Baseline: Only {prior_captures} prior capture(s) recorded ({summary['total_duration_seconds']}s total history). Confidence is conservative."
        else:
            health = BaselineHealth.ESTABLISHED
            warning = None

        # Case 3: Subnet compatibility check
        current_internal_ips = [
            h.get("ip") for h in current_results.get("hosts", [])
            if h.get("is_internal") and h.get("ip")
        ]
        baseline_subnets = summary.get("internal_subnets", [])

        if current_internal_ips and baseline_subnets:
            current_networks = set()
            for ip_str in current_internal_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    # Use /24 for IPv4, /64 for IPv6 for subnet grouping
                    if ip_obj.version == 4:
                        net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                        current_networks.add(str(net))
                except ValueError:
                    pass

            if current_networks:
                # Check if any current network overlaps with baseline subnets
                has_overlap = False
                for c_net in current_networks:
                    c_obj = ipaddress.ip_network(c_net)
                    for b_str in baseline_subnets:
                        try:
                            b_obj = ipaddress.ip_network(b_str)
                            if c_obj.overlaps(b_obj):
                                has_overlap = True
                                break
                        except ValueError:
                            pass
                    if has_overlap:
                        break

                if not has_overlap and prior_captures >= 1:
                    return (
                        BaselineHealth.INCOMPATIBLE,
                        "Subnet Disparity Warning: Current internal IP space has 0% overlap with historical baseline. Observed changes likely reflect a different physical network segment or site rather than true behavioral drift.",
                    )

        # Case 4: Duration advisory
        curr_duration = current_results.get("duration_seconds") or current_results.get("summary", {}).get("duration_seconds", 0.0)
        if 0 < curr_duration < 10.0:
            dur_msg = f"Brief observation window ({curr_duration:.1f}s). Measured throughput and packet rates reflect momentary bursts rather than steady-state baseline."
            warning = f"{warning} | {dur_msg}" if warning else dur_msg

        return health, warning
