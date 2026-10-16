"""Dry-run simulation firewall adapter."""

from __future__ import annotations

import logging
from typing import List, Optional, Set, Tuple

from beacon.prevention.adapters.base import FirewallAdapter

logger = logging.getLogger(__name__)


class DryRunAdapter(FirewallAdapter):
    """
    In-memory simulation adapter for testing, development, and platforms
    where active kernel firewall manipulation is not configured or desired.
    """

    def __init__(self, available: bool = True, failure_mode: Optional[str] = None):
        self._blocked_ips: Set[str] = set()
        self._available = available
        self.failure_mode = failure_mode  # "apply", "verify", "remove", None

    @property
    def name(self) -> str:
        return "dry_run"

    def is_available(self) -> Tuple[bool, str]:
        if not self._available:
            return False, "Dry-run adapter manually disabled"
        return True, "Dry-run simulation adapter active (no kernel changes)"

    def apply_block(self, ip: str) -> Tuple[bool, str]:
        if not self._available:
            return False, "Adapter unavailable"
        if self.failure_mode == "apply":
            return False, "Simulated firewall command error"

        self._blocked_ips.add(ip)
        logger.info(f"[DRY-RUN FIREWALL] Simulating egress drop rule for destination IP: {ip}")
        return True, f"Simulated block rule applied for {ip}"

    def remove_block(self, ip: str) -> Tuple[bool, str]:
        if self.failure_mode == "remove":
            return False, "Simulated firewall removal error"

        self._blocked_ips.discard(ip)
        logger.info(f"[DRY-RUN FIREWALL] Simulating removal of egress drop rule for: {ip}")
        return True, f"Simulated block rule removed for {ip}"

    def verify_rule(self, ip: str) -> bool:
        if self.failure_mode == "verify":
            return False
        return ip in self._blocked_ips

    def list_active_rules(self) -> List[str]:
        return sorted(list(self._blocked_ips))

    def clear(self) -> None:
        """Clear all simulated rules."""
        self._blocked_ips.clear()
