"""Comprehensive unit and integration tests for live capture investigation views."""

import pytest
import time
from starlette.testclient import TestClient

from beacon.api.server import app
from beacon.live import get_live_service, RollingPacket
from beacon.live.models import LiveCaptureStatus


@pytest.fixture(autouse=True)
def reset_live_service():
    """Reset live service state before each test."""
    service = get_live_service()
    service.stop_capture()
    service.buffer.clear()
    service.evidence_store.clear()
    service.detection_engine.reset()
    service.total_packets = 0
    service.total_bytes = 0
    service._host_stats.clear()
    service._protocol_counts.clear()
    service._conversation_counts.clear()
    service._timeline_events.clear()
    service._extracted_iocs.clear()
    service.status = LiveCaptureStatus.STOPPED
    service.selected_interface = "eth0"
    service.start_time = time.time()
    yield service
    service.stop_capture()


def test_live_investigation_api_endpoints(reset_live_service):
    service = reset_live_service
    client = TestClient(app)

    # Ingest synthetic packets
    now = time.time()
    p1 = RollingPacket(
        number=1,
        timestamp=now,
        length=74,
        ip_src="192.168.1.50",
        ip_dst="8.8.8.8",
        src_port=53210,
        dst_port=53,
        transport_proto="udp",
        app_proto="dns",
        protocols=["eth", "ip", "udp", "dns"],
        dns_query_name="evil-c2.malicious.com",
    )
    p2 = RollingPacket(
        number=2,
        timestamp=now + 0.1,
        length=250,
        ip_src="192.168.1.50",
        ip_dst="104.21.45.12",
        src_port=49812,
        dst_port=80,
        transport_proto="tcp",
        app_proto="http",
        protocols=["eth", "ip", "tcp", "http"],
        http_method="POST",
        http_uri="/login?user=admin&password=SuperSecretPassword123",
    )
    p3 = RollingPacket(
        number=3,
        timestamp=now + 0.2,
        length=512,
        ip_src="192.168.1.50",
        ip_dst="142.250.190.46",
        src_port=50123,
        dst_port=443,
        transport_proto="tcp",
        app_proto="tls",
        protocols=["eth", "ip", "tcp", "tls"],
        tls_server_name="secure.beacon-telemetry.io",
    )

    service.ingest_synthetic_packet(p1)
    service.ingest_synthetic_packet(p2)
    service.ingest_synthetic_packet(p3)

    # 1. /api/analyses contains live entry
    res = client.get("/api/analyses")
    assert res.status_code == 200
    analyses = res.json()["analyses"]
    live_entry = next((a for a in analyses if a["id"] == "live"), None)
    assert live_entry is not None
    assert live_entry["is_live"] is True
    assert live_entry["packet_count"] == 3

    # 2. /api/analysis/live/status
    res = client.get("/api/analysis/live/status")
    assert res.status_code == 200
    st = res.json()
    assert st["id"] == "live"
    assert st["status"] == "complete"
    assert st["is_live"] is True

    # 3. /api/analysis/live/results
    res = client.get("/api/analysis/live/results")
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["total_packets"] == 3
    assert res_data["unique_hosts"] >= 3
    assert res_data["is_live"] is True

    # 4. /api/analysis/live/findings
    res = client.get("/api/analysis/live/findings")
    assert res.status_code == 200
    findings_data = res.json()
    assert "findings" in findings_data
    # Should have cleartext credential finding from p2
    assert any("Credential" in f["title"] or "Cleartext" in f["title"] for f in findings_data["findings"])

    # 5. /api/analysis/live/hosts
    res = client.get("/api/analysis/live/hosts")
    assert res.status_code == 200
    hosts_data = res.json()
    assert hosts_data["total"] >= 3
    src_host = next((h for h in hosts_data["hosts"] if h["ip"] == "192.168.1.50"), None)
    assert src_host is not None
    assert src_host["is_internal"] is True
    assert src_host["packets_sent"] == 3

    # 6. /api/analysis/live/conversations
    res = client.get("/api/analysis/live/conversations")
    assert res.status_code == 200
    conv_data = res.json()
    assert len(conv_data["conversations"]) >= 3

    # 7. /api/analysis/live/timeline
    res = client.get("/api/analysis/live/timeline")
    assert res.status_code == 200
    tl_data = res.json()
    assert tl_data["total"] >= 1

    # 8. /api/analysis/live/iocs
    res = client.get("/api/analysis/live/iocs")
    assert res.status_code == 200
    iocs_data = res.json()
    assert iocs_data["total"] >= 1
    # Check that evil-c2 domain was extracted
    ioc_vals = [i["value"] for i in iocs_data["iocs"]]
    assert any("evil-c2.malicious.com" in v for v in ioc_vals)

    # 9. /api/analysis/live/packets
    res = client.get("/api/analysis/live/packets?limit=10")
    assert res.status_code == 200
    pkts_data = res.json()
    assert pkts_data["total"] == 3
    assert len(pkts_data["packets"]) == 3

    # 10. /api/analysis/live/packet/2
    res = client.get("/api/analysis/live/packet/2")
    assert res.status_code == 200
    p2_detail = res.json()
    assert p2_detail["number"] == 2
    assert p2_detail["source"] == "192.168.1.50"
    assert len(p2_detail["findings"]) >= 1

    # 11. /api/analysis/live/packet/999 (Evicted or not found)
    res = client.get("/api/analysis/live/packet/999")
    assert res.status_code == 404
    assert "evicted" in res.json()["detail"].lower()

    # 12. /api/analysis/live/graph
    res = client.get("/api/analysis/live/graph")
    assert res.status_code == 200
    graph_data = res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert len(graph_data["nodes"]) >= 3

    # 13. /api/analysis/live/evidence-graph
    res = client.get("/api/analysis/live/evidence-graph")
    assert res.status_code == 200
    egraph_data = res.json()
    assert any(n["type"] == "domain" for n in egraph_data["nodes"])

    # 14. /api/analysis/live/storyline
    res = client.get("/api/analysis/live/storyline")
    assert res.status_code == 200
    story_data = res.json()
    assert "storyline" in story_data

    # 15. /api/analysis/live/stream
    conv_key = p2.conversation_key
    res = client.get(f"/api/analysis/live/stream/{conv_key}")
    assert res.status_code == 200
    stream_data = res.json()
    assert stream_data["total_messages"] >= 1

    # 16. /api/analysis/live/search
    res = client.get("/api/analysis/live/search?q=malicious")
    assert res.status_code == 200
    search_data = res.json()
    assert len(search_data["iocs"]) >= 1 or len(search_data["packets"]) >= 1

    # 17. /api/analysis/live/mode
    res = client.post("/api/analysis/live/mode", json={"mode": "blue"})
    assert res.status_code == 200
    assert res.json()["mode"] == "blue"

    # 18. /api/analysis/live/export
    res = client.get("/api/analysis/live/export?format=json")
    assert res.status_code == 200
    export_json = res.json()
    assert export_json["total_packets"] == 3

    # 19. /api/analysis/live/memory
    res = client.get("/api/analysis/live/memory")
    assert res.status_code == 200
    mem_briefing = res.json()
    assert mem_briefing["is_live"] is True


def test_live_buffer_eviction_and_preserved_incident_detail(reset_live_service):
    """Verify that when packets are evicted from buffer, preserved incidents are still inspectable."""
    service = reset_live_service
    client = TestClient(app)

    # Set capacity to 5
    service.buffer.capacity = 5

    # Ingest trigger packet that triggers incident (credential exposure)
    now = time.time()
    trigger_pkt = RollingPacket(
        number=10,
        timestamp=now,
        length=200,
        ip_src="10.0.0.5",
        ip_dst="10.0.0.1",
        src_port=54321,
        dst_port=80,
        transport_proto="tcp",
        app_proto="http",
        http_method="POST",
        http_uri="/login?password=SensitiveSecretKey",
    )
    service.ingest_synthetic_packet(trigger_pkt)

    # Push 10 more benign packets to evict packet #10 from rolling buffer (capacity is 5)
    for i in range(11, 21):
        p = RollingPacket(
            number=i,
            timestamp=now + (i - 10) * 0.1,
            length=64,
            ip_src="10.0.0.5",
            ip_dst="8.8.8.8",
            transport_proto="udp",
            app_proto="dns",
        )
        service.ingest_synthetic_packet(p)

    assert service.buffer.occupancy == 5
    assert service.buffer.total_evicted >= 5
    # Packet #10 is NOT in buffer
    assert service.buffer.get_packet_by_number(10) is None

    # But packet #10 was preserved in evidence store!
    res = client.get("/api/analysis/live/packet/10")
    assert res.status_code == 200
    p10_data = res.json()
    assert p10_data["number"] == 10
    assert p10_data["source"] == "10.0.0.5"

    # Packet #1 was never in buffer or incident, should return 404 with eviction message
    res_evicted = client.get("/api/analysis/live/packet/1")
    assert res_evicted.status_code == 404
    assert "evicted" in res_evicted.json()["detail"].lower()


def test_live_capture_comparison_against_live(reset_live_service):
    """Verify comparing live capture results against another capture."""
    service = reset_live_service
    client = TestClient(app)

    # Ingest synthetic packets
    now = time.time()
    service.ingest_synthetic_packet(
        RollingPacket(
            number=1,
            timestamp=now,
            length=128,
            ip_src="192.168.1.100",
            ip_dst="1.1.1.1",
            transport_proto="udp",
            app_proto="dns",
        )
    )

    # Mock an offline capture in analyses dict
    from beacon.api.server import analyses
    analyses["mock_offline"] = {
        "id": "mock_offline",
        "status": "complete",
        "filename": "offline_capture.pcap",
        "results": {
            "total_packets": 10,
            "total_bytes": 1024,
            "hosts": [{"ip": "192.168.1.100", "total_bytes": 512}],
            "conversations": [],
            "protocols": {"DNS": 10},
            "findings": [],
        },
    }

    try:
        res = client.get("/api/analysis/compare?baseline_id=mock_offline&target_id=live")
        assert res.status_code == 200
        comp = res.json()
        assert "metrics_delta" in comp
        assert "common_hosts" in comp
    finally:
        analyses.pop("mock_offline", None)

