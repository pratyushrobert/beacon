"""Constrained Linux nftables firewall adapter managing only Beacon-owned tables and sets."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Set, Tuple

from beacon.prevention.adapters.base import FirewallAdapter

logger = logging.getLogger(__name__)

NFT_TABLE = "beacon_firewall"
NFT_SET = "beacon_blocked_dest"
NFT_CHAIN = "beacon_egress"


class NftablesAdapter(FirewallAdapter):
    """
    Constrained Linux nftables adapter.
    Operates strictly within an isolated table 'inet beacon_firewall'.
    Never flushes, inspects, or modifies unrelated firewall chains or tables.
    """

    def __init__(self, nft_binary: Optional[str] = None):
        self._nft_path = nft_binary or shutil.which("nft")
        self._initialized = False

    @property
    def name(self) -> str:
        return "nftables"

    def is_available(self) -> Tuple[bool, str]:
        """Check if nftables is installed and executable with appropriate privileges."""
        if sys.platform != "linux":
            return False, f"nftables adapter is only supported on Linux (running on {sys.platform})"

        if not self._nft_path:
            return False, "The 'nft' executable was not found in system PATH"

        # Test command with dry-run check or table listing to verify permissions
        try:
            res = subprocess.run(
                [self._nft_path, "--version"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode != 0:
                return False, f"nft binary check failed: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Failed executing nft check: {str(e)}"

        # Check permissions to inspect/manage nftables
        try:
            res = subprocess.run(
                [self._nft_path, "list", "tables"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode != 0:
                return False, f"Insufficient permissions to read/manage nftables (CAP_NET_ADMIN required): {res.stderr.strip()}"
        except Exception as e:
            return False, f"Error validating nftables permissions: {str(e)}"

        return True, "nftables is available with required administrative privileges"

    def _ensure_beacon_table(self) -> Tuple[bool, str]:
        """Create Beacon-owned isolated table, set, and egress drop chain if not present."""
        if self._initialized:
            return True, "Initialized"

        avail, reason = self.is_available()
        if not avail:
            return False, reason

        commands = [
            f"add table inet {NFT_TABLE}",
            f"add set inet {NFT_TABLE} {NFT_SET} {{ type ipv4_addr; flags interval; }}",
            f"add chain inet {NFT_TABLE} {NFT_CHAIN} {{ type filter hook output priority 0; policy accept; }}",
            f"add rule inet {NFT_TABLE} {NFT_CHAIN} ip daddr @{NFT_SET} drop",
        ]

        for cmd in commands:
            try:
                res = subprocess.run(
                    [self._nft_path] + cmd.split(),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode != 0 and "File exists" not in res.stderr and "already exists" not in res.stderr:
                    return False, f"nftables setup failed on '{cmd}': {res.stderr.strip()}"
            except Exception as e:
                return False, f"nftables setup exception: {str(e)}"

        self._initialized = True
        return True, "Beacon nftables structure initialized"

    def apply_block(self, ip: str) -> Tuple[bool, str]:
        """Add destination IP to Beacon's blocked set."""
        ok, msg = self._ensure_beacon_table()
        if not ok:
            return False, msg

        try:
            res = subprocess.run(
                [self._nft_path, "add", "element", "inet", NFT_TABLE, NFT_SET, f"{{ {ip} }}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 or "File exists" in res.stderr:
                return True, f"Successfully added {ip} to nftables set @{NFT_SET}"
            return False, f"nft add element failed: {res.stderr.strip()}"
        except Exception as e:
            return False, f"nft execution error: {str(e)}"

    def remove_block(self, ip: str) -> Tuple[bool, str]:
        """Remove destination IP from Beacon's blocked set."""
        if not self._nft_path:
            return False, "nft binary not found"

        try:
            res = subprocess.run(
                [self._nft_path, "delete", "element", "inet", NFT_TABLE, NFT_SET, f"{{ {ip} }}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 or "No such file or directory" in res.stderr:
                return True, f"Removed {ip} from nftables set @{NFT_SET}"
            return False, f"nft delete element failed: {res.stderr.strip()}"
        except Exception as e:
            return False, f"nft execution error: {str(e)}"

    def verify_rule(self, ip: str) -> bool:
        """Verify directly from nftables output that the IP is present in Beacon's set."""
        if not self._nft_path:
            return False

        try:
            res = subprocess.run(
                [self._nft_path, "list", "set", "inet", NFT_TABLE, NFT_SET],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                return False

            # Elements are output as e.g. "elements = { 198.51.100.1, ... }"
            return bool(re.search(r"\b" + re.escape(ip) + r"\b", res.stdout))
        except Exception:
            return False

    def list_active_rules(self) -> List[str]:
        """Parse all active destination IPs in Beacon's set."""
        if not self._nft_path:
            return []

        try:
            res = subprocess.run(
                [self._nft_path, "list", "set", "inet", NFT_TABLE, NFT_SET],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                return []

            # Extract IPv4 patterns from inside elements = { ... }
            elem_match = re.search(r"elements\s*=\s*\{([^}]+)\}", res.stdout)
            if not elem_match:
                return []

            ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", elem_match.group(1))
            return sorted(list(set(ips)))
        except Exception:
            return []

    def cleanup_table(self) -> Tuple[bool, str]:
        """Delete only Beacon's isolated table on complete shutdown or reset."""
        if not self._nft_path:
            return False, "nft binary not found"

        try:
            res = subprocess.run(
                [self._nft_path, "delete", "table", "inet", NFT_TABLE],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 or "No such file or directory" in res.stderr:
                self._initialized = False
                return True, f"Deleted table inet {NFT_TABLE}"
            return False, f"Failed deleting table: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Error deleting table: {str(e)}"
