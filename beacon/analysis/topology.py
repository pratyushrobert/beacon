"""Network topology analysis, subnet inference, and device role classification."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


WELL_KNOWN_DNS_PORTS = {53, 5353, 853}
WELL_KNOWN_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
WELL_KNOWN_SERVER_PORTS = {
    21, 22, 23, 25, 110, 123, 137, 138, 139, 143, 389, 445, 636, 993, 995, 1433, 1521, 3306, 3389, 5432,
}


def classify_ip_address(ip_str: str) -> Dict[str, Any]:
    """
    Classify an IP address into its network category, version, and subnet prefix.
    Explicitly tracks whether prefix length is inferred or strictly known.
    """
    ip_str = (ip_str or "").strip()
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return {
            "ip": ip_str,
            "is_valid_ip": False,
            "ip_version": None,
            "category": "unknown",
            "subnet_id": "unknown",
            "subnet_label": "Unknown Network",
            "is_internal": False,
            "is_multicast": False,
            "is_loopback": False,
            "is_link_local": False,
            "is_inferred_prefix": False,
            "prefix_length": None,
        }

    is_v6 = ip_obj.version == 6
    is_mcast = ip_obj.is_multicast
    is_loop = ip_obj.is_loopback
    is_link = ip_obj.is_link_local
    is_priv = ip_obj.is_private

    if is_loop:
        return {
            "ip": ip_str,
            "is_valid_ip": True,
            "ip_version": ip_obj.version,
            "category": "loopback",
            "subnet_id": "::1/128" if is_v6 else "127.0.0.0/8",
            "subnet_label": "Loopback (Host Internal)",
            "is_internal": True,
            "is_multicast": False,
            "is_loopback": True,
            "is_link_local": False,
            "is_inferred_prefix": False,
            "prefix_length": 128 if is_v6 else 8,
        }

    if is_mcast:
        return {
            "ip": ip_str,
            "is_valid_ip": True,
            "ip_version": ip_obj.version,
            "category": "multicast",
            "subnet_id": "ff00::/8" if is_v6 else "224.0.0.0/4",
            "subnet_label": "Multicast Broadcast Group",
            "is_internal": True,
            "is_multicast": True,
            "is_loopback": False,
            "is_link_local": False,
            "is_inferred_prefix": False,
            "prefix_length": 8 if is_v6 else 4,
        }

    if is_link:
        return {
            "ip": ip_str,
            "is_valid_ip": True,
            "ip_version": ip_obj.version,
            "category": "link_local",
            "subnet_id": "fe80::/10" if is_v6 else "169.254.0.0/16",
            "subnet_label": "Link-Local Auto-Config",
            "is_internal": True,
            "is_multicast": False,
            "is_loopback": False,
            "is_link_local": True,
            "is_inferred_prefix": False,
            "prefix_length": 10 if is_v6 else 16,
        }

    if is_priv:
        if not is_v6:
            octets = ip_str.split(".")
            first = int(octets[0])
            second = int(octets[1]) if len(octets) > 1 else 0
            third = int(octets[2]) if len(octets) > 2 else 0

            # Derive standard /24 segment while noting inferred status
            if first == 10:
                subnet_id = f"10.{second}.{third}.0/24"
                label = f"10.{second}.{third}.0/24 (Private LAN)"
            elif first == 172 and 16 <= second <= 31:
                subnet_id = f"172.{second}.{third}.0/24"
                label = f"172.{second}.{third}.0/24 (Private LAN)"
            elif first == 192 and second == 168:
                subnet_id = f"192.168.{third}.0/24"
                label = f"192.168.{third}.0/24 (Local LAN)"
            else:
                subnet_id = f"{first}.{second}.{third}.0/24"
                label = f"{first}.{second}.{third}.0/24 (Private)"

            return {
                "ip": ip_str,
                "is_valid_ip": True,
                "ip_version": 4,
                "category": "private",
                "subnet_id": subnet_id,
                "subnet_label": label,
                "is_internal": True,
                "is_multicast": False,
                "is_loopback": False,
                "is_link_local": False,
                "is_inferred_prefix": True,
                "prefix_length": 24,
            }
        else:
            # IPv6 unique local (fc00::/7)
            # Use first 4 segments (/64) for visual clustering
            parts = ip_obj.exploded.split(":")
            prefix_64 = ":".join(parts[:4]) + "::/64"
            return {
                "ip": ip_str,
                "is_valid_ip": True,
                "ip_version": 6,
                "category": "private",
                "subnet_id": prefix_64,
                "subnet_label": f"{prefix_64} (Private IPv6)",
                "is_internal": True,
                "is_multicast": False,
                "is_loopback": False,
                "is_link_local": False,
                "is_inferred_prefix": True,
                "prefix_length": 64,
            }

    # Public WAN IP
    return {
        "ip": ip_str,
        "is_valid_ip": True,
        "ip_version": ip_obj.version,
        "category": "public",
        "subnet_id": "public_wan",
        "subnet_label": "External / Public WAN",
        "is_internal": False,
        "is_multicast": False,
        "is_loopback": False,
        "is_link_local": False,
        "is_inferred_prefix": False,
        "prefix_length": None,
    }


def infer_device_role(
    ip: str,
    ip_classification: Dict[str, Any],
    observed_dst_ports: Iterable[int],
    total_inbound_bytes: int = 0,
    total_outbound_bytes: int = 0,
    bridges_subnets: bool = False,
) -> Tuple[str, str, str]:
    """
    Infer device role and return (role_name, role_badge, role_evidence).
    Roles:
      - 'gateway': Default gateway or cross-subnet router
      - 'dns_server': Domain name resolver
      - 'web_server': Web service endpoint (HTTP/HTTPS)
      - 'server': Generic network service host
      - 'workstation': Client workstation initiating sessions
      - 'external': External / Public endpoint
      - 'multicast': Multicast subscriber/group
    """
    if ip_classification.get("is_multicast"):
        return "multicast", "MC", "Multicast group address"

    if not ip_classification.get("is_internal"):
        return "external", "EXT", "Public Internet endpoint"

    ports = set(observed_dst_ports or [])

    # Check for gateway heuristic: ends in .1 or .254 in IPv4 or bridges subnets
    if ip_classification.get("ip_version") == 4:
        octets = ip.split(".")
        if len(octets) == 4:
            last = octets[-1]
            if last in ("1", "254") or bridges_subnets:
                return "gateway", "GW", "Inferred default gateway / router (.1/.254 host index)"

    if ports & WELL_KNOWN_DNS_PORTS:
        return "dns_server", "DNS", f"DNS resolver service active on port {list(ports & WELL_KNOWN_DNS_PORTS)}"

    if ports & WELL_KNOWN_WEB_PORTS:
        return "web_server", "WEB", f"HTTP/HTTPS web service active on port {list(ports & WELL_KNOWN_WEB_PORTS)}"

    if ports & WELL_KNOWN_SERVER_PORTS:
        return "server", "SRV", f"Inbound server services active on ports {list(ports & WELL_KNOWN_SERVER_PORTS)}"

    # If receives significant inbound traffic on low ports
    low_ports = [p for p in ports if p < 1024]
    if low_ports:
        return "server", "SRV", f"Listening service on well-known port {low_ports[0]}"

    return "workstation", "CLI", "Client endpoint initiating outbound network connections"


def build_network_topology(
    hosts_data: List[Dict[str, Any]],
    conversations_data: List[Dict[str, Any]],
    findings_data: Optional[List[Dict[str, Any]]] = None,
    dns_queries_by_ip: Optional[Dict[str, List[str]]] = None,
    ports_by_ip: Optional[Dict[str, Set[int]]] = None,
    max_nodes: int = 60,
) -> Dict[str, Any]:
    """
    Build structured, evidence-linked network topology nodes, subnets, and edges.
    """
    findings_list = findings_data or []
    dns_map = dns_queries_by_ip or {}
    ports_map = ports_by_ip or {}

    # Sort hosts by byte volume
    sorted_hosts = sorted(
        hosts_data,
        key=lambda h: (h.get("bytes_sent", 0) + h.get("bytes_received", 0)),
        reverse=True,
    )[:max_nodes]

    host_ips = {h["ip"] for h in sorted_hosts}

    # Detect which internal hosts communicate across multiple subnets or with external endpoints
    # To identify router / gateway candidates
    ip_classifications: Dict[str, Dict[str, Any]] = {}
    for h in sorted_hosts:
        ip = h["ip"]
        ip_classifications[ip] = classify_ip_address(ip)

    bridging_hosts: Set[str] = set()
    for conv in conversations_data:
        h1 = conv.get("host1")
        h2 = conv.get("host2")
        if h1 in ip_classifications and h2 in ip_classifications:
            sub1 = ip_classifications[h1]["subnet_id"]
            sub2 = ip_classifications[h2]["subnet_id"]
            if sub1 != sub2 and sub1 != "unknown" and sub2 != "unknown":
                # If one is internal and one is public, the internal party might be routing or client
                pass

    # Build node objects and aggregate subnets
    subnet_dict: Dict[str, Dict[str, Any]] = {}
    nodes: List[Dict[str, Any]] = []

    for h in sorted_hosts:
        ip = h["ip"]
        c = ip_classifications[ip]
        sub_id = c["subnet_id"]

        # Gather findings for this host
        h_findings = [
            f for f in findings_list
            if f.get("source_ip") == ip or f.get("destination_ip") == ip
        ]
        max_sev = "info"
        for sev in ["critical", "high", "medium", "low"]:
            if any(f.get("severity") == sev for f in h_findings):
                max_sev = sev
                break

        observed_ports = sorted(list(ports_map.get(ip, set())))
        dns_names = dns_map.get(ip, [])

        role_name, role_badge, role_evidence = infer_device_role(
            ip=ip,
            ip_classification=c,
            observed_dst_ports=observed_ports,
            total_inbound_bytes=h.get("bytes_received", 0),
            total_outbound_bytes=h.get("bytes_sent", 0),
            bridges_subnets=ip in bridging_hosts,
        )

        total_bytes = h.get("bytes_sent", 0) + h.get("bytes_received", 0)

        # Initialize or update subnet group
        if sub_id not in subnet_dict:
            subnet_dict[sub_id] = {
                "id": sub_id,
                "label": c["subnet_label"],
                "category": c["category"],
                "is_internal": c["is_internal"],
                "is_inferred_prefix": c["is_inferred_prefix"],
                "prefix_length": c["prefix_length"],
                "host_count": 0,
                "total_bytes": 0,
                "hosts": [],
                "gateway": None,
            }

        subnet_dict[sub_id]["host_count"] += 1
        subnet_dict[sub_id]["total_bytes"] += total_bytes
        subnet_dict[sub_id]["hosts"].append(ip)
        if role_name == "gateway":
            subnet_dict[sub_id]["gateway"] = ip

        node_obj = {
            "id": ip,
            "label": ip,
            "type": "host",
            "ip": ip,
            "ip_version": c["ip_version"],
            "subnet": sub_id,
            "subnet_label": c["subnet_label"],
            "subnet_category": c["category"],
            "is_inferred_prefix": c["is_inferred_prefix"],
            "prefix_length": c["prefix_length"],
            "device_role": role_name,
            "role_badge": role_badge,
            "role_evidence": role_evidence,
            "is_internal": c["is_internal"],
            "is_multicast": c["is_multicast"],
            "is_loopback": c["is_loopback"],
            "is_link_local": c["is_link_local"],
            "is_ipv6": c["ip_version"] == 6,
            "dns_names": dns_names,
            "observed_ports": observed_ports[:10],
            "packets_sent": h.get("packets_sent", 0),
            "packets_received": h.get("packets_received", 0),
            "total_bytes": total_bytes,
            "findings_count": len(h_findings),
            "severity": max_sev,
            "first_seen": h.get("first_seen"),
            "last_seen": h.get("last_seen"),
        }
        nodes.append(node_obj)

    # Build edges between participating hosts
    edges: List[Dict[str, Any]] = []
    for conv in conversations_data:
        h1 = conv.get("host1")
        h2 = conv.get("host2")
        if h1 in host_ips and h2 in host_ips:
            edges.append({
                "id": conv.get("conversation_key", f"edge_{h1}_{h2}"),
                "source": h1,
                "target": h2,
                "type": "traffic",
                "protocol": conv.get("protocol") or "unknown",
                "packet_count": conv.get("packet_count", 0),
                "byte_count": conv.get("byte_count", 0),
                "port1": conv.get("port1"),
                "port2": conv.get("port2"),
                "first_seen": conv.get("first_seen"),
                "last_seen": conv.get("last_seen"),
            })

    subnets_list = sorted(
        subnet_dict.values(),
        key=lambda s: (s["is_internal"], s["total_bytes"]),
        reverse=True,
    )

    return {
        "nodes": nodes,
        "edges": edges,
        "subnets": subnets_list,
    }
