"""Base abstract interface for host firewall enforcement adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Set, Tuple


class FirewallAdapter(ABC):
    """Abstract base class for network firewall enforcement adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the adapter (e.g. 'dry_run', 'nftables')."""
        ...

    @abstractmethod
    def is_available(self) -> Tuple[bool, str]:
        """
        Check if the adapter is supported, tools are installed, and proper privileges exist.
        Returns (is_available, description_or_reason).
        """
        ...

    @abstractmethod
    def apply_block(self, ip: str) -> Tuple[bool, str]:
        """
        Apply a drop rule for the destination IP address.
        Must NOT flush or modify unrelated rules or chains.
        Returns (success, message).
        """
        ...

    @abstractmethod
    def remove_block(self, ip: str) -> Tuple[bool, str]:
        """
        Remove the drop rule for the destination IP address.
        Returns (success, message).
        """
        ...

    @abstractmethod
    def verify_rule(self, ip: str) -> bool:
        """
        Query actual firewall state to confirm the rule is genuinely in effect.
        Never claim success without independent state verification.
        """
        ...

    @abstractmethod
    def list_active_rules(self) -> List[str]:
        """
        Query and return list of all destination IPs currently blocked by this adapter.
        """
        ...

    def reconcile(self, expected_ips: Set[str]) -> Tuple[Set[str], Set[str]]:
        """
        Reconcile firewall state with expected set of active IPs.
        Returns (added_ips, pruned_ips).
        """
        current_ips = set(self.list_active_rules())
        missing = expected_ips - current_ips
        stale = current_ips - expected_ips

        added = set()
        for ip in missing:
            ok, _ = self.apply_block(ip)
            if ok and self.verify_rule(ip):
                added.add(ip)

        pruned = set()
        for ip in stale:
            ok, _ = self.remove_block(ip)
            if ok:
                pruned.add(ip)

        return added, pruned
