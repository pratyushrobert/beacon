"""Firewall adapters package for Beacon threat prevention."""

from beacon.prevention.adapters.base import FirewallAdapter
from beacon.prevention.adapters.dry_run import DryRunAdapter
from beacon.prevention.adapters.nftables import NftablesAdapter

__all__ = ["FirewallAdapter", "DryRunAdapter", "NftablesAdapter"]
