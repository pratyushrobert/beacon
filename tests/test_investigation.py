"""Integration tests for Beacon investigation engine, caching, detection rules, reports, and API."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from beacon.api.server import app, analyses
from beacon.core.engine import AnalysisEngine
from beacon.core.modes import AnalysisMode
from beacon.core.packet_parser import ParsedPacket
from beacon.detection.engine import DetectionEngine
from beacon.exports.reports import ReportGenerator
from beacon.models import Confidence, Finding, HostStats, ConversationStats, Severity


def create_sample_packet(
    number: int,
    ip_src: str = "192.168.1.100",
    ip_dst: str = "10.0.0.1",
    src_port: int = 50000,
    dst_port: int = 80,
    transport_proto: str = "tcp",
    app_proto: str = "http",
    tcp_flags: int = 2,  # SYN
    http_method: str | None = None,
    http_uri: str | None = None,
    dns_query_name: str | None = None,
    tls_server_name: str | None = None,
    length: int = 64,
) -> ParsedPacket:
    now = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
    return ParsedPacket(
        number=number,
        timestamp=now,
        timestamp_epoch=1791979200.0 + number,
        length=length,
        ip_src=ip_src,
        ip_dst=ip_dst,
        ip_version=4,
        src_port=src_port,
        dst_port=dst_port,
        transport_proto=transport_proto,
        app_proto=app_proto,
        tcp_flags=tcp_flags,
        http_method=http_method,
        http_uri=http_uri,
        dns_query_name=dns_query_name,
        tls_server_name=tls_server_name,
        raw_data={
            "_source": {
                "layers": {
                    "frame": {"frame.number": [str(number)], "frame.len": [str(length)]},
                    "ip": {"ip.src": [ip_src], "ip.dst": [ip_dst]},
                    transport_proto: {f"{transport_proto}.srcport": [str(src_port)], f"{transport_proto}.dstport": [str(dst_port)]},
                }
            }
        },
    )


@pytest.fixture
def temp_cache_dir():
    temp_dir = tempfile.mkdtemp(prefix="beacon_test_cache_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_detection_engine_blue_port_scan():
    """Verify Blue Mode detects port scans when many distinct ports are targeted."""
    packets = [
        create_sample_packet(
            number=i,
            ip_src="192.168.1.50",
            ip_dst="10.0.0.1",
            src_port=40000 + i,
            dst_port=20 + i,
            tcp_flags=2,  # SYN
        )
        for i in range(25)
    ]
    engine = DetectionEngine(mode=AnalysisMode.BLUE)
    findings = engine.analyze(packets)
    scan_findings = [f for f in findings if f.category == "port_scanning"]
    assert len(scan_findings) >= 1
    f = scan_findings[0]
    assert f.severity in (Severity.MEDIUM, Severity.HIGH)
    assert f.source_ip == "192.168.1.50"
    assert len(f.related_packets) > 0
    assert f.next_step != ""


def test_detection_engine_red_cleartext_credentials():
    """Verify Red Mode flags cleartext credentials observed in HTTP queries."""
    packets = [
        create_sample_packet(
            number=1,
            ip_src="192.168.1.100",
            ip_dst="93.184.216.34",
            dst_port=80,
            http_method="POST",
            http_uri="/login.php?user=admin&password=SuperSecretPassword123",
        )
    ]
    engine = DetectionEngine(mode=AnalysisMode.RED)
    findings = engine.analyze(packets)
    cred_findings = [f for f in findings if f.category == "cleartext_credentials"]
    assert len(cred_findings) >= 1
    f = cred_findings[0]
    assert f.severity == Severity.HIGH
    # Ensure sensitive credentials are redacted by default in evidence
    assert "SuperSecretPassword123" not in f.description
    for ev in f.evidence:
        assert "SuperSecretPassword123" not in ev


def test_detection_engine_red_session_tokens():
    """Verify Red Mode identifies session tokens in URLs."""
    packets = [
        create_sample_packet(
            number=1,
            ip_src="192.168.1.100",
            ip_dst="93.184.216.34",
            dst_port=80,
            http_method="GET",
            http_uri="/api/v1/user?session_id=s3cur3t0k3n12345",
        )
    ]
    engine = DetectionEngine(mode=AnalysisMode.RED)
    findings = engine.analyze(packets)
    token_findings = [f for f in findings if f.category == "session_tokens"]
    assert len(token_findings) >= 1
    assert token_findings[0].severity in (Severity.MEDIUM, Severity.HIGH)


def test_analysis_engine_caching_and_mode_switching(temp_cache_dir):
    """Verify SQLite cache creation, retrieval, and mode switching without re-parsing."""
    pcap_path = temp_cache_dir / "sample.pcap"
    pcap_path.write_bytes(b"dummy pcap content")

    engine = AnalysisEngine(pcap_path=pcap_path, mode=AnalysisMode.BLUE, cache_dir=temp_cache_dir)
    packets = [
        create_sample_packet(1, ip_src="192.168.1.10", ip_dst="8.8.8.8", dst_port=53, transport_proto="udp", app_proto="dns", dns_query_name="beacon-c2.xyz"),
        create_sample_packet(2, ip_src="192.168.1.10", ip_dst="192.168.1.20", dst_port=21, app_proto="ftp"),
        create_sample_packet(3, ip_src="192.168.1.10", ip_dst="93.184.216.34", dst_port=80, app_proto="http", http_method="GET", http_uri="/secret?token=abc"),
    ]

    # Process and populate cache directly
    for p in packets:
        engine._process_packet(p)
    engine.db_conn.commit()

    cache_db = engine.cache_db

    # Verify high-performance query methods
    p_page = engine.get_packets(offset=0, limit=2)
    assert p_page["total"] == 3
    assert len(p_page["packets"]) == 2

    # Query filtered by protocol
    dns_page = engine.get_packets(protocol="dns")
    assert dns_page["total"] == 1
    assert dns_page["packets"][0]["app_proto"] == "dns"

    # Query packet detail
    pkt1 = engine.get_packet_detail(1)
    assert pkt1 is not None
    assert pkt1["number"] == 1
    assert pkt1["dns"]["query_name"] == "beacon-c2.xyz"

    # Query timeline
    timeline = engine.get_timeline_events()
    assert len(timeline) >= 1

    # Query IOCs
    iocs = engine.get_iocs()
    ioc_values = [i["value"] for i in iocs]
    assert "8.8.8.8" in ioc_values or "beacon-c2.xyz" in ioc_values

    # Query network graph
    graph = engine.get_network_graph()
    assert len(graph["nodes"]) >= 2
    assert len(graph["edges"]) >= 1

    # Global search
    search = engine.global_search("beacon-c2")
    assert len(search["packets"]) >= 1

    # Switch Mode to Red Mode on cached data
    engine_red = AnalysisEngine(pcap_path=pcap_path, mode=AnalysisMode.RED, cache_dir=temp_cache_dir)
    red_results = engine_red.analyze()
    assert red_results["mode"] == "red"
    assert "findings" in red_results


def test_report_generator():
    """Verify HTML, JSON, and CSV report exports."""
    results = {
        "pcap_file": "test.pcap",
        "mode": "blue",
        "total_packets": 100,
        "total_bytes": 65536,
        "duration_seconds": 12.5,
        "unique_hosts": 4,
        "protocols": {"tcp": 80, "udp": 20},
        "findings": [
            Finding(
                id="FIND-001",
                category="port_scanning",
                title="Possible SYN Port Scan",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Targeted 25 ports",
                source_ip="192.168.1.10",
                destination_ip="10.0.0.1",
                protocol="TCP",
                related_packets=[1, 2, 3],
                detection_rationale="Threshold exceeded",
                next_step="Inspect firewall logs",
            )
        ],
        "hosts": [
            HostStats(ip="192.168.1.10", is_internal=True, packets_sent=50, packets_received=50, bytes_sent=16384, bytes_received=16384, protocols={"tcp"})
        ],
        "conversations": [
            ConversationStats(key="192.168.1.10:45000<->10.0.0.1:80/tcp", host1="192.168.1.10", host2="10.0.0.1", port1=45000, port2=80, protocol="tcp", packet_count=100, byte_count=65536, first_seen=datetime(2026, 1, 1, 0, 0, 0), last_seen=datetime(2026, 1, 1, 0, 0, 12))
        ],
    }

    html = ReportGenerator.generate_html(results)
    assert "<!DOCTYPE html>" in html
    assert "Possible SYN Port Scan" in html
    assert "192.168.1.10" in html

    json_str = ReportGenerator.generate_json(results)
    parsed = json.loads(json_str)
    assert parsed["pcap_file"] == "test.pcap"
    assert len(parsed["findings"]) == 1

    csv_findings = ReportGenerator.generate_csv(results, "findings")
    assert "id,severity,confidence,category,title" in csv_findings
    assert "Possible SYN Port Scan" in csv_findings

    csv_hosts = ReportGenerator.generate_csv(results, "hosts")
    assert "ip,is_internal,packets_sent" in csv_hosts
    assert "192.168.1.10" in csv_hosts

    csv_convs = ReportGenerator.generate_csv(results, "conversations")
    assert "key,host1,port1,host2,port2" in csv_convs


def test_api_endpoints_full_lifecycle(temp_cache_dir):
    """Verify REST API lifecycle with TestClient."""
    client = TestClient(app)

    # Ensure analyses endpoint responds
    res = client.get("/api/analyses")
    assert res.status_code == 200
    assert "analyses" in res.json()

    # Create dummy analysis record in memory and catalog
    analysis_id = "test-analysis-123"
    results = {
        "pcap_file": "sample.pcap",
        "mode": "blue",
        "total_packets": 2,
        "total_bytes": 128,
        "duration_seconds": 1.0,
        "unique_hosts": 2,
        "protocols": {"tcp": 2},
        "findings": [
            {
                "id": "FIND-001",
                "category": "cleartext_credentials",
                "title": "Cleartext HTTP Password",
                "severity": "high",
                "confidence": "high",
                "description": "Password in URL",
                "source_ip": "192.168.1.10",
                "destination_ip": "93.184.216.34",
                "protocol": "HTTP",
                "evidence": ["password=[REDACTED]"],
                "recommendation": "Use HTTPS",
                "related_packets": [1],
                "related_conversations": [],
                "detection_rationale": "Cleartext URI",
                "next_step": "Revoke credentials",
            }
        ],
        "hosts": [
            {"ip": "192.168.1.10", "is_internal": True, "packets_sent": 1, "packets_received": 1, "total_bytes": 128, "protocols": ["tcp"]}
        ],
        "conversations": [
            {"host1": "192.168.1.10", "host2": "93.184.216.34", "port1": 50000, "port2": 80, "protocol": "tcp", "packet_count": 2, "byte_count": 128, "first_seen": 0.0, "last_seen": 1.0}
        ],
    }

    analyses[analysis_id] = {
        "id": analysis_id,
        "status": "complete",
        "filename": "sample.pcap",
        "filepath": str(temp_cache_dir / "sample.pcap"),
        "mode": "blue",
        "results": results,
    }

    # Test status endpoint
    res = client.get(f"/api/analysis/{analysis_id}/status")
    assert res.status_code == 200
    assert res.json()["status"] == "complete"

    # Test results endpoint
    res = client.get(f"/api/analysis/{analysis_id}/results")
    assert res.status_code == 200
    assert res.json()["total_packets"] == 2

    # Test findings endpoint
    res = client.get(f"/api/analysis/{analysis_id}/findings")
    assert res.status_code == 200
    assert len(res.json()["findings"]) == 1

    # Test hosts endpoint
    res = client.get(f"/api/analysis/{analysis_id}/hosts")
    assert res.status_code == 200
    assert len(res.json()["hosts"]) == 1

    # Test conversations endpoint
    res = client.get(f"/api/analysis/{analysis_id}/conversations")
    assert res.status_code == 200
    assert len(res.json()["conversations"]) == 1

    # Test export HTML
    res = client.get(f"/api/analysis/{analysis_id}/export?format=html")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]

    # Test export JSON
    res = client.get(f"/api/analysis/{analysis_id}/export?format=json")
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]

    # Test export CSV
    res = client.get(f"/api/analysis/{analysis_id}/export?format=csv&csv_type=findings")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]

    # Test delete endpoint
    res = client.delete(f"/api/analysis/{analysis_id}")
    assert res.status_code == 200
    assert analysis_id not in analyses


def test_conversation_stats_ipv6_and_numeric_robustness(temp_cache_dir):
    """Regression test: Ensure IPv6 colons and malformed endpoint strings do not cause ValueError."""
    # Create an IPv6 packet matching packet 146 in test.pcap
    pkt = create_sample_packet(
        number=146,
        ip_src="fe80::485f:2bff:fe36:72ab",
        ip_dst="ff02::fb",
        src_port=5353,
        dst_port=5353,
        transport_proto="udp",
        app_proto="dns",
    )
    pkt.ip_version = 6

    # Verify conversation key generation brackets IPv6
    conv_key = pkt.get_conversation_key()
    assert conv_key is not None
    assert "fe80::485f:2bff:fe36:72ab" in conv_key
    assert "ff02::fb" in conv_key

    # Test safe endpoint parsing helper across edge cases
    h1, h2, p1, p2 = AnalysisEngine._parse_conversation_endpoints(conv_key)
    assert h1 == "fe80::485f:2bff:fe36:72ab"
    assert h2 == "ff02::fb"
    assert p1 == 5353
    assert p2 == 5353

    # Test legacy unbracketed IPv6 key format
    legacy_key = "fe80::485f:2bff:fe36:72ab:5353<->ff02::fb:5353(udp)"
    h1_leg, h2_leg, p1_leg, p2_leg = AnalysisEngine._parse_conversation_endpoints(legacy_key)
    assert h1_leg == "fe80::485f:2bff:fe36:72ab"
    assert h2_leg == "ff02::fb"
    assert p1_leg == 5353
    assert p2_leg == 5353

    # Test port 0 preservation
    zero_port_key = "192.168.1.1:0<->192.168.1.2:80(tcp)"
    z_h1, z_h2, z_p1, z_p2 = AnalysisEngine._parse_conversation_endpoints(zero_port_key)
    assert z_p1 == 0
    assert z_p2 == 80

    # Test malformed / empty strings
    m_h1, m_h2, m_p1, m_p2 = AnalysisEngine._parse_conversation_endpoints("")
    assert m_p1 is None and m_p2 is None

    # Test AnalysisEngine._update_conversation_stats directly with IPv6 packet
    dummy_pcap = temp_cache_dir / "dummy.pcap"
    dummy_pcap.write_bytes(b"")
    engine = AnalysisEngine(dummy_pcap, cache_dir=temp_cache_dir)
    engine._update_conversation_stats(pkt, conv_key)

    cursor = engine.db_conn.cursor()
    row = cursor.execute("SELECT * FROM conversations WHERE conversation_key = ?", (conv_key,)).fetchone()
    assert row is not None
    assert row["host1"] == "fe80::485f:2bff:fe36:72ab"
    assert row["host2"] == "ff02::fb"
    assert row["port1"] == 5353
    assert row["port2"] == 5353
    assert row["packet_count"] == 1


def test_as_int_and_as_float_numeric_semantics():
    """Verify _as_int and _as_float properly handle numeric edge cases and preserve valid zero."""
    from beacon.core.packet_parser import _as_int, _as_float

    # Zero preservation
    assert _as_int(0) == 0
    assert _as_int("0") == 0
    assert _as_float(0.0) == 0.0
    assert _as_float("0.0") == 0.0

    # Float strings to int
    assert _as_int("123.0") == 123
    assert _as_int("456.78") == 456

    # Hex strings
    assert _as_int("0x20") == 32

    # None and empty strings return default
    assert _as_int("", default=None) is None
    assert _as_int("   ", default=-1) == -1
    assert _as_int(None, default=99) == 99
    assert _as_int("not_a_number", default=None) is None

    assert _as_float("", default=None) is None
    assert _as_float("   ", default=-1.0) == -1.0
    assert _as_float(None, default=99.5) == 99.5
    assert _as_float("invalid", default=None) is None


def test_analysis_engine_test_pcap_blue_and_white_modes(temp_cache_dir):
    """Integration test: Verify test.pcap runs to 100% in both Blue and White modes."""
    test_pcap = Path("examples/test.pcap")
    if not test_pcap.exists():
        pytest.skip("examples/test.pcap not present")

    # Blue Mode
    engine_blue = AnalysisEngine(test_pcap, mode=AnalysisMode.BLUE, cache_dir=temp_cache_dir)
    results_blue = engine_blue.analyze()
    assert results_blue["total_packets"] == 193
    assert results_blue["unique_hosts"] > 0
    assert len(results_blue["findings"]) > 0

    # White Mode
    engine_white = AnalysisEngine(test_pcap, mode=AnalysisMode.WHITE, cache_dir=temp_cache_dir)
    results_white = engine_white.analyze()
    assert results_white["total_packets"] == 193
    assert results_white["unique_hosts"] == results_blue["unique_hosts"]
    assert "ssh" in results_white["protocols"]


def test_evidence_graph_and_storyline(temp_cache_dir):
    """Verify evidence graph and storyline generation on sample.pcap."""
    sample_pcap = Path("examples/sample.pcap")
    if not sample_pcap.exists():
        pytest.skip("examples/sample.pcap not present")

    with AnalysisEngine(sample_pcap, mode=AnalysisMode.RED, cache_dir=temp_cache_dir) as engine:
        engine.analyze()
        ev_graph = engine.get_evidence_graph()
        assert "nodes" in ev_graph
        assert "edges" in ev_graph
        assert len(ev_graph["nodes"]) > 0

        # Check node types
        types = {n.get("type") for n in ev_graph["nodes"]}
        assert "host" in types
        assert "domain" in types

        # Check storyline
        storyline = engine.get_investigation_storyline()
        assert len(storyline) > 0
        phases = {s["phase"] for s in storyline}
        assert "RESOLUTION" in phases or "EXPOSURE" in phases

        # Check stream
        stream = engine.get_conversation_stream("192.168.1.100:54321<->93.184.216.34:80(tcp)")
        assert "turns" in stream
        assert stream["total_messages"] >= 1
        assert "hex_dump" in stream["turns"][0]


def test_compare_analyses():
    """Verify comparison logic between two capture analyses."""
    base = {
        "total_packets": 100,
        "total_bytes": 50000,
        "duration_seconds": 10.0,
        "unique_hosts": 2,
        "hosts": [{"ip": "10.0.0.1", "bytes_sent": 25000, "bytes_received": 25000}],
        "findings": [{"title": "Old Finding"}],
        "protocols": {"tcp": 90, "dns": 10},
    }
    target = {
        "total_packets": 150,
        "total_bytes": 80000,
        "duration_seconds": 15.0,
        "unique_hosts": 3,
        "hosts": [
            {"ip": "10.0.0.1", "bytes_sent": 40000, "bytes_received": 40000},
            {"ip": "10.0.0.2", "bytes_sent": 5000, "bytes_received": 5000},
        ],
        "findings": [{"title": "Old Finding"}, {"title": "New Alert"}],
        "protocols": {"tcp": 130, "dns": 10, "ssh": 10},
    }
    diff = AnalysisEngine.compare_analyses(base, target)
    assert diff["metrics_delta"]["packets_delta"] == 50
    assert len(diff["new_hosts"]) == 1
    assert diff["new_hosts"][0]["ip"] == "10.0.0.2"
    assert len(diff["new_findings"]) == 1
    assert diff["new_findings"][0]["title"] == "New Alert"
    assert "ssh" in diff["new_protocols"]


def test_graph_ip_classification_and_metrics(temp_cache_dir):
    """Verify multicast and IPv6 detection in get_network_graph and get_evidence_graph."""
    pcap_path = temp_cache_dir / "multicast_v6.pcap"
    pcap_path.write_bytes(b"dummy pcap")

    with AnalysisEngine(pcap_path, mode=AnalysisMode.WHITE, cache_dir=temp_cache_dir) as engine:
        # Create sample packets with IPv4 unicast, IPv4 multicast, and IPv6
        packets = [
            create_sample_packet(1, ip_src="192.168.1.50", ip_dst="224.0.0.251", dst_port=5353, transport_proto="udp", app_proto="mdns"),
            create_sample_packet(2, ip_src="fe80::1ff:fe23:4567:890a", ip_dst="ff02::1", dst_port=5353, transport_proto="udp", app_proto="mdns"),
            create_sample_packet(3, ip_src="192.168.1.50", ip_dst="8.8.8.8", dst_port=53, transport_proto="udp", app_proto="dns", dns_query_name="test.org"),
        ]
        for p in packets:
            engine._process_packet(p)
        engine.db_conn.commit()

        # Check get_network_graph
        net_graph = engine.get_network_graph()
        nodes_by_id = {n["id"]: n for n in net_graph["nodes"]}

        assert "224.0.0.251" in nodes_by_id
        assert nodes_by_id["224.0.0.251"]["is_multicast"] is True
        assert nodes_by_id["224.0.0.251"]["is_ipv6"] is False

        assert "ff02::1" in nodes_by_id
        assert nodes_by_id["ff02::1"]["is_multicast"] is True
        assert nodes_by_id["ff02::1"]["is_ipv6"] is True

        assert "fe80::1ff:fe23:4567:890a" in nodes_by_id
        assert nodes_by_id["fe80::1ff:fe23:4567:890a"]["is_multicast"] is False
        assert nodes_by_id["fe80::1ff:fe23:4567:890a"]["is_ipv6"] is True

        assert "192.168.1.50" in nodes_by_id
        assert nodes_by_id["192.168.1.50"]["is_multicast"] is False
        assert nodes_by_id["192.168.1.50"]["is_ipv6"] is False

        # Check get_evidence_graph
        ev_graph = engine.get_evidence_graph()
        ev_hosts = {n["id"]: n for n in ev_graph["nodes"] if n.get("type") == "host"}

        assert "224.0.0.251" in ev_hosts
        assert ev_hosts["224.0.0.251"]["is_multicast"] is True

        assert "fe80::1ff:fe23:4567:890a" in ev_hosts
        assert ev_hosts["fe80::1ff:fe23:4567:890a"]["is_ipv6"] is True


