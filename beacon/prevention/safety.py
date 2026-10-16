"""Target validation, allowlist protection, and collateral impact analysis for threat prevention."""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional, Set, Tuple

from beacon.prevention.models import PreventionPolicy

logger = logging.getLogger(__name__)

# Known shared infrastructure and CDN IPv4 networks for collateral impact warnings
SHARED_INFRASTRUCTURE_NETWORKS: list[tuple[ipaddress.IPv4Network, str]] = [
    (ipaddress.ip_network("1.1.1.0/24"), "Cloudflare"),
    (ipaddress.ip_network("8.8.8.0/24"), "Google"),
    (ipaddress.ip_network("8.8.4.0/24"), "Google"),
    (ipaddress.ip_network("9.9.9.0/24"), "Quad9"),
    (ipaddress.ip_network("104.16.0.0/12"), "Cloudflare"),
    (ipaddress.ip_network("104.24.0.0/13"), "Cloudflare"),
    (ipaddress.ip_network("172.64.0.0/13"), "Cloudflare"),
    (ipaddress.ip_network("151.101.0.0/16"), "Fastly"),
    (ipaddress.ip_network("199.232.0.0/16"), "Fastly"),
    (ipaddress.ip_network("23.0.0.0/12"), "Akamai"),
    (ipaddress.ip_network("104.64.0.0/10"), "Akamai"),
    (ipaddress.ip_network("13.32.0.0/15"), "AWS CloudFront"),
    (ipaddress.ip_network("54.230.0.0/16"), "AWS CloudFront"),
    (ipaddress.ip_network("142.250.0.0/15"), "Google"),
    (ipaddress.ip_network("172.217.0.0/16"), "Google"),
]


def check_collateral_impact(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Optional[str]:
    """
    Evaluate if an IP belongs to shared infrastructure (CDNs, public DNS, hyperscalers).
    Returns an explanatory caution string if collateral impact is likely.
    """
    if isinstance(ip_obj, ipaddress.IPv4Address):
        for net, provider in SHARED_INFRASTRUCTURE_NETWORKS:
            if ip_obj in net:
                return (
                    f"Shared Infrastructure Warning: Destination IP {ip_obj} resides in a known multi-tenant "
                    f"or CDN provider range ({provider} - {net}). Blocking this destination may cause collateral disruption "
                    f"to unrelated services or websites hosted on the same infrastructure. Detection confidence "
                    f"reflects observed traffic indicators, not proof of host-wide malice."
                )
    return None


def validate_block_target(
    ip_str: str,
    policy: PreventionPolicy,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate target address and enforce safety constraints.

    Returns:
        (is_valid, rejection_reason, collateral_warning)
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "Target IP address is missing or empty", None

    ip_clean = ip_str.strip()

    # 1. Syntax Validation
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
    except ValueError:
        return False, f"Invalid IP address format: '{ip_clean}'", None

    # 2. Reject Prohibited Non-Routable and System Targets
    if ip_obj.is_loopback:
        return False, f"Prohibited target: Cannot block loopback address ({ip_clean})", None

    if ip_obj.is_unspecified:
        return False, f"Prohibited target: Cannot block unspecified address ({ip_clean})", None

    if ip_obj.is_multicast:
        return False, f"Prohibited target: Cannot block multicast address ({ip_clean})", None

    if ip_obj.is_link_local:
        return False, f"Prohibited target: Cannot block link-local address ({ip_clean})", None

    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj == ipaddress.IPv4Address("255.255.255.255"):
        return False, "Prohibited target: Cannot block global broadcast address", None

    # 3. Check Explicit Critical Infrastructure
    if ip_clean in policy.critical_infrastructure:
        return False, f"Safety violation: Target {ip_clean} is designated as critical infrastructure", None

    # 4. Check Explicit Allowlisted IPs
    if ip_clean in policy.allowlist_ips:
        return False, f"Safety violation: Target {ip_clean} is in the configured allowlist", None

    # 5. Check Allowlisted CIDRs
    for cidr in policy.allowlist_cidrs:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            if ip_obj in net:
                return False, f"Safety violation: Target {ip_clean} belongs to allowlisted network {cidr}", None
        except ValueError:
            logger.warning(f"Ignoring malformed CIDR in allowlist: {cidr}")

    # 6. Check Shared Infrastructure / Collateral Impact Warning
    collateral_warning = check_collateral_impact(ip_obj)

    return True, None, collateral_warning
