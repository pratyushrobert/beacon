"""Tests for network topology, subnet inference, and device role classification."""

from beacon.analysis.topology import (
    classify_ip_address,
    infer_device_role,
    build_network_topology,
)


def test_classify_private_ipv4():
    # 192.168.1.50
    c1 = classify_ip_address("192.168.1.50")
    assert c1["is_valid_ip"] is True
    assert c1["ip_version"] == 4
    assert c1["category"] == "private"
    assert c1["subnet_id"] == "192.168.1.0/24"
    assert c1["is_internal"] is True
    assert c1["is_inferred_prefix"] is True
    assert c1["prefix_length"] == 24

    # 10.5.20.100
    c2 = classify_ip_address("10.5.20.100")
    assert c2["category"] == "private"
    assert c2["subnet_id"] == "10.5.20.0/24"
    assert c2["is_internal"] is True

    # 172.16.4.10
    c3 = classify_ip_address("172.16.4.10")
    assert c3["category"] == "private"
    assert c3["subnet_id"] == "172.16.4.0/24"
    assert c3["is_internal"] is True


def test_classify_public_ipv4():
    c = classify_ip_address("93.184.216.34")
    assert c["is_valid_ip"] is True
    assert c["category"] == "public"
    assert c["subnet_id"] == "public_wan"
    assert c["is_internal"] is False
    assert c["is_inferred_prefix"] is False


def test_classify_special_addresses():
    # Multicast
    m = classify_ip_address("224.0.0.251")
    assert m["category"] == "multicast"
    assert m["is_multicast"] is True
    assert m["subnet_id"] == "224.0.0.0/4"

    # Loopback
    loop = classify_ip_address("127.0.0.1")
    assert loop["category"] == "loopback"
    assert loop["is_loopback"] is True

    # Link-local
    link = classify_ip_address("169.254.42.1")
    assert link["category"] == "link_local"
    assert link["is_link_local"] is True

    # IPv6 Loopback
    v6_loop = classify_ip_address("::1")
    assert v6_loop["category"] == "loopback"
    assert v6_loop["ip_version"] == 6

    # IPv6 Link-Local
    v6_link = classify_ip_address("fe80::1ff:fe00:3a60")
    assert v6_link["category"] == "link_local"
    assert v6_link["ip_version"] == 6


def test_classify_invalid():
    inv = classify_ip_address("not_an_ip")
    assert inv["is_valid_ip"] is False
    assert inv["category"] == "unknown"


def test_infer_device_roles():
    # Gateway
    c_gw = classify_ip_address("192.168.1.1")
    role, badge, _ = infer_device_role("192.168.1.1", c_gw, observed_dst_ports=[])
    assert role == "gateway"
    assert badge == "GW"

    # DNS Server
    c_dns = classify_ip_address("192.168.1.53")
    role, badge, _ = infer_device_role("192.168.1.53", c_dns, observed_dst_ports=[53])
    assert role == "dns_server"
    assert badge == "DNS"

    # Web Server
    c_web = classify_ip_address("192.168.1.80")
    role, badge, _ = infer_device_role("192.168.1.80", c_web, observed_dst_ports=[443, 80])
    assert role == "web_server"
    assert badge == "WEB"

    # Workstation (client)
    c_cli = classify_ip_address("192.168.1.142")
    role, badge, _ = infer_device_role("192.168.1.142", c_cli, observed_dst_ports=[])
    assert role == "workstation"
    assert badge == "CLI"

    # External
    c_ext = classify_ip_address("1.1.1.1")
    role, badge, _ = infer_device_role("1.1.1.1", c_ext, observed_dst_ports=[53])
    assert role == "external"
    assert badge == "EXT"


def test_build_network_topology():
    hosts = [
        {"ip": "192.168.1.1", "packets_sent": 50, "packets_received": 50, "bytes_sent": 5000, "bytes_received": 5000},
        {"ip": "192.168.1.10", "packets_sent": 100, "packets_received": 100, "bytes_sent": 20000, "bytes_received": 20000},
        {"ip": "10.0.0.5", "packets_sent": 30, "packets_received": 30, "bytes_sent": 3000, "bytes_received": 3000},
        {"ip": "93.184.216.34", "packets_sent": 80, "packets_received": 80, "bytes_sent": 15000, "bytes_received": 15000},
    ]
    convs = [
        {"host1": "192.168.1.10", "host2": "192.168.1.1", "protocol": "tcp", "packet_count": 20, "byte_count": 2000},
        {"host1": "192.168.1.10", "host2": "93.184.216.34", "protocol": "tcp", "packet_count": 50, "byte_count": 10000},
    ]
    findings = [
        {"id": "F-001", "source_ip": "192.168.1.10", "severity": "high", "title": "Suspicious Outbound Connection"}
    ]

    topo = build_network_topology(hosts_data=hosts, conversations_data=convs, findings_data=findings)

    assert "nodes" in topo
    assert "edges" in topo
    assert "subnets" in topo

    assert len(topo["nodes"]) == 4
    assert len(topo["edges"]) == 2

    # Check that subnets correctly isolate 192.168.1.0/24 from 10.0.0.0/24 and public_wan
    subnets = {s["id"]: s for s in topo["subnets"]}
    assert "192.168.1.0/24" in subnets
    assert "10.0.0.0/24" in subnets
    assert "public_wan" in subnets

    lan_subnet = subnets["192.168.1.0/24"]
    assert lan_subnet["host_count"] == 2
    assert "192.168.1.1" in lan_subnet["hosts"]
    assert "192.168.1.10" in lan_subnet["hosts"]
    assert lan_subnet["gateway"] == "192.168.1.1"

    # Check node findings severity
    node_10 = next(n for n in topo["nodes"] if n["id"] == "192.168.1.10")
    assert node_10["severity"] == "high"
    assert node_10["findings_count"] == 1
    assert node_10["device_role"] == "workstation"
