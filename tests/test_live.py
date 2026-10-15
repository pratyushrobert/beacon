"""Comprehensive automated unit & integration test suite for Beacon Live."""

from __future__ import annotations

import struct
import tempfile
import time
from pathlib import Path
from typing import List

import pytest
from fastapi.testclient import TestClient

from beacon.api.server import app
from beacon.live.buffer import RollingPacketBuffer
from beacon.live.detection import StreamingDetectionEngine
from beacon.live.models import (
    CaptureInterface,
    EvidenceStatus,
    IncidentEvidence,
    LiveCaptureStats,
    LiveCaptureStatus,
    RollingPacket,
)
from beacon.live.pcap_writer import synthesize_ethernet_frame, write_pcap_file
from beacon.live.retention import SmartEvidenceStore
from beacon.live.service import LiveCaptureService, get_live_service
from beacon.models import Confidence, Finding, Severity


# ---------------------------------------------------------------------------
# 1. Rolling Packet Buffer Tests
# ---------------------------------------------------------------------------

def test_rolling_buffer_capacity_and_fifo_eviction():
    buf = RollingPacketBuffer(capacity=5)
    assert buf.capacity == 5
    assert buf.occupancy == 0

    for i in range(1, 10):
        pkt = RollingPacket(
            number=i,
            timestamp=100.0 + i,
            length=100,
            ip_src="192.168.1.10",
            ip_dst="192.168.1.1",
            transport_proto="tcp",
        )
        buf.append(pkt)

    assert buf.occupancy == 5
    recent = buf.get_recent(limit=10)
    assert len(recent) == 5
    # Newest is #9, oldest remaining is #5
    assert recent[0].number == 9
    assert recent[-1].number == 5

    # Test lookup by packet number
    assert buf.get_packet_by_number(9) is not None
    assert buf.get_packet_by_number(9).number == 9
    # Packet #1 should be evicted
    assert buf.get_packet_by_number(1) is None


def test_rolling_buffer_pre_trigger_window():
    buf = RollingPacketBuffer(capacity=50)
    for i in range(1, 31):
        pkt = RollingPacket(
            number=i,
            timestamp=1000.0 + i,
            length=64,
            ip_src="10.0.0.1",
            ip_dst="10.0.0.2",
            transport_proto="tcp",
        )
        buf.append(pkt)

    # Request 10 packets preceding packet #25
    pre_pkts, is_partial = buf.get_pre_trigger_window(
        trigger_number=25,
        window_count=10,
        window_seconds=20.0,
    )
    assert len(pre_pkts) == 10
    assert not is_partial
    assert pre_pkts[-1].number == 24
    assert pre_pkts[0].number == 15

    # Test partial flag when earlier context has been evicted due to buffer wrap-around
    small_buf = RollingPacketBuffer(capacity=10)
    for i in range(1, 25):
        small_buf.append(RollingPacket(
            number=i,
            timestamp=2000.0 + i,
            length=64,
            ip_src="10.0.0.1",
            ip_dst="10.0.0.2",
            transport_proto="tcp",
        ))

    pre_pkts_evicted, is_partial_evicted = small_buf.get_pre_trigger_window(
        trigger_number=24,
        window_count=15,
        window_seconds=30.0,
    )
    assert is_partial_evicted
    assert len(pre_pkts_evicted) < 15


def test_rolling_buffer_flow_and_host_queries():
    buf = RollingPacketBuffer(capacity=20)
    pkt1 = RollingPacket(number=1, timestamp=1.0, length=60, ip_src="1.1.1.1", ip_dst="2.2.2.2", transport_proto="tcp")
    pkt2 = RollingPacket(number=2, timestamp=2.0, length=80, ip_src="2.2.2.2", ip_dst="1.1.1.1", transport_proto="tcp")
    pkt3 = RollingPacket(number=3, timestamp=3.0, length=90, ip_src="3.3.3.3", ip_dst="4.4.4.4", transport_proto="udp")

    buf.append(pkt1)
    buf.append(pkt2)
    buf.append(pkt3)

    host_pkts = buf.get_packets_for_host("1.1.1.1")
    assert len(host_pkts) == 2

    conv_pkts = buf.get_packets_for_conversation(pkt1.conversation_key)
    assert len(conv_pkts) == 2


# ---------------------------------------------------------------------------
# 2. Pure-Python PCAP Exporter Tests
# ---------------------------------------------------------------------------

def test_synthesize_ethernet_frame_and_pcap_writer(tmp_path: Path):
    pkt1 = RollingPacket(
        number=1,
        timestamp=1700000000.5,
        length=120,
        ip_src="192.168.1.50",
        ip_dst="8.8.8.8",
        transport_proto="udp",
        src_port=53210,
        dst_port=53,
        dns_query_name="malicious.exfiltrate.example.com",
    )
    pkt2 = RollingPacket(
        number=2,
        timestamp=1700000001.2,
        length=250,
        ip_src="192.168.1.50",
        ip_dst="93.184.216.34",
        transport_proto="tcp",
        src_port=49152,
        dst_port=80,
        http_method="POST",
        http_uri="/login",
    )

    frame1 = synthesize_ethernet_frame(pkt1)
    assert len(frame1) > 14  # Must exceed ethernet header
    # Check EtherType IPv4 0x0800
    assert frame1[12:14] == b"\x08\x00"

    out_pcap = tmp_path / "test_out.pcap"
    count = write_pcap_file([pkt1, pkt2], out_pcap)
    assert count == 2
    assert out_pcap.exists()

    # Verify standard PCAP global header
    data = out_pcap.read_bytes()
    assert len(data) > 24
    magic, v_maj, v_min, tz, sig, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4
    assert v_maj == 2
    assert v_min == 4
    assert snaplen == 65535
    assert linktype == 1  # Ethernet


# ---------------------------------------------------------------------------
# 3. Streaming Detection Engine Tests
# ---------------------------------------------------------------------------

def test_streaming_port_scan_detection():
    engine = StreamingDetectionEngine(mode="white")
    base_ts = 1000.0

    findings = []
    # Send traffic from 10.0.0.50 to 10 distinct ports on 10.0.0.1
    for port in range(100, 110):
        pkt = RollingPacket(
            number=port,
            timestamp=base_ts + (port - 100) * 0.1,
            length=64,
            ip_src="10.0.0.50",
            ip_dst="10.0.0.1",
            transport_proto="tcp",
            src_port=50000,
            dst_port=port,
            tcp_flags="SYN",
        )
        res = engine.process_packet(pkt)
        findings.extend(res)

    assert len(findings) > 0
    scan_finding = next((f for f in findings if "Port Scan" in f.title), None)
    assert scan_finding is not None
    assert scan_finding.source_ip == "10.0.0.50"
    assert scan_finding.severity in (Severity.HIGH, Severity.CRITICAL)


def test_streaming_cleartext_credential_detection():
    engine = StreamingDetectionEngine(mode="white")
    pkt = RollingPacket(
        number=1,
        timestamp=time.time(),
        length=200,
        ip_src="192.168.1.15",
        ip_dst="192.168.1.1",
        transport_proto="tcp",
        dst_port=80,
        app_proto="http",
        http_uri="/auth/login?user=admin&password=SuperSecretPassword123!",
    )
    findings = engine.process_packet(pkt)
    assert len(findings) > 0
    cred_finding = next((f for f in findings if "Credential" in f.title), None)
    assert cred_finding is not None
    assert cred_finding.severity in (Severity.HIGH, Severity.CRITICAL)


def test_streaming_outbound_volume_surge_detection():
    engine = StreamingDetectionEngine(mode="white")
    base_ts = time.time()
    findings = []

    # Send 2 MB across 5 packets in 2 seconds
    for i in range(5):
        pkt = RollingPacket(
            number=i + 1,
            timestamp=base_ts + i * 0.2,
            length=450_000,
            ip_src="192.168.1.100",
            ip_dst="198.51.100.25",
            transport_proto="tcp",
            dst_port=443,
            direction="outbound",
        )
        res = engine.process_packet(pkt)
        findings.extend(res)

    assert len(findings) > 0
    surge_finding = next((f for f in findings if "Transfer" in f.title or "Surge" in f.title or "Exfiltration" in f.title), None)
    assert surge_finding is not None


# ---------------------------------------------------------------------------
# 4. Smart Evidence Store & Incident Retention Tests
# ---------------------------------------------------------------------------

def test_smart_evidence_retention_lifecycle(tmp_path: Path):
    store = SmartEvidenceStore(
        max_incidents=10,
        max_packets_per_incident=20,
        post_trigger_window_seconds=1.0,
        spool_dir=tmp_path,
    )
    buffer = RollingPacketBuffer(capacity=100)

    # Fill buffer with 10 pre-packets
    for i in range(1, 11):
        buffer.append(RollingPacket(
            number=i,
            timestamp=100.0 + i,
            length=64,
            ip_src="10.0.0.5",
            ip_dst="10.0.0.1",
            transport_proto="tcp",
        ))

    # Triggering packet
    trigger_pkt = RollingPacket(
        number=11,
        timestamp=111.0,
        length=200,
        ip_src="10.0.0.5",
        ip_dst="10.0.0.1",
        transport_proto="tcp",
        dst_port=22,
    )
    buffer.append(trigger_pkt)

    finding = Finding(
        id="f-1",
        category="authentication",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Unauthorized SSH Access Attempt",
        description="Repeated SSH authentication attempts detected from unauthorized host",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.1",
    )

    incident = store.trigger_incident(finding, trigger_pkt, buffer)
    assert incident.id.startswith("inc-")
    assert store.incidents_count == 1
    assert incident.evidence_status == EvidenceStatus.COLLECTING
    assert len(incident.pre_trigger_packets) == 10
    assert incident.trigger_packet.number == 11

    # Ingest post-trigger packets
    post_pkt = RollingPacket(
        number=12,
        timestamp=111.5,
        length=80,
        ip_src="10.0.0.1",
        ip_dst="10.0.0.5",
        transport_proto="tcp",
        src_port=22,
    )
    store.process_incoming_packet(post_pkt)

    # Verify post packet was retained
    inc = store.get_incident(incident.id)
    assert len(inc.post_trigger_packets) == 1
    assert inc.total_retained_packets == 12

    # Test analyst pinning
    assert not inc.analyst_pinned
    store.set_incident_pin(inc.id, True)
    assert store.get_incident(inc.id).analyst_pinned

    # Test analyst notes
    store.update_incident_notes(inc.id, "Investigated: Brute-force attempt identified.")
    assert "Brute-force" in store.get_incident(inc.id).analyst_notes

    # Test PCAP export
    out_pcap = store.export_incident_pcap(inc.id)
    assert out_pcap is not None
    assert out_pcap.exists()
    assert out_pcap.stat().st_size > 0


def test_smart_evidence_budget_enforcement(tmp_path: Path):
    store = SmartEvidenceStore(max_incidents=3, spool_dir=tmp_path)
    buffer = RollingPacketBuffer(capacity=50)

    # Create 3 incidents
    for i in range(1, 4):
        pkt = RollingPacket(number=i, timestamp=time.time() + i, length=64, ip_src=f"10.0.0.{i}", ip_dst="1.1.1.1")
        buffer.append(pkt)
        f = Finding(
            id=f"f-{i}",
            category="recon",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title=f"Alert {i}",
            description=f"Recon probe {i}",
            source_ip=f"10.0.0.{i}",
        )
        inc = store.trigger_incident(f, pkt, buffer)
        inc.evidence_status = EvidenceStatus.COMPLETE
        if i == 1:
            # Pin incident 1
            store.set_incident_pin(inc.id, True)

    assert store.incidents_count == 3
    assert store.pinned_count == 1

    # Trigger a 4th incident: unpinned oldest (incident #2) must be evicted, while pinned (#1) remains
    pkt4 = RollingPacket(number=4, timestamp=time.time() + 10, length=64, ip_src="10.0.0.4", ip_dst="1.1.1.1")
    buffer.append(pkt4)
    f4 = Finding(
        id="f-4",
        category="recon",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Alert 4",
        description="Recon probe 4",
        source_ip="10.0.0.4",
    )
    store.trigger_incident(f4, pkt4, buffer)

    assert store.incidents_count == 3
    remaining = store.get_incidents(limit=10)
    # Pinned incident #1 must still exist
    assert any(inc.analyst_pinned for inc in remaining)


# ---------------------------------------------------------------------------
# 5. Live Capture Service & Synthetic Ingestion Tests
# ---------------------------------------------------------------------------

def test_live_service_synthetic_stream():
    service = LiveCaptureService(buffer_capacity=100)
    service.mode = "white"

    events = []
    service.subscribe(lambda e: events.append(e))

    # Ingest benign packets
    base_ts = time.time()
    for i in range(1, 5):
        pkt = RollingPacket(
            number=i,
            timestamp=base_ts + i * 0.1,
            length=100,
            ip_src="192.168.1.10",
            ip_dst="192.168.1.1",
            transport_proto="tcp",
            src_port=40000 + i,
            dst_port=80,
        )
        service.ingest_synthetic_packet(pkt)

    stats = service.get_stats()
    assert stats.total_packets == 4
    assert stats.buffer_occupancy == 4
    assert "TCP" in stats.top_protocols

    # Now inject port scan to trigger detection & evidence preservation
    for port in range(200, 215):
        pkt = RollingPacket(
            number=100 + port,
            timestamp=base_ts + 2.0 + (port - 200) * 0.05,
            length=64,
            ip_src="192.168.1.200",
            ip_dst="192.168.1.1",
            transport_proto="tcp",
            src_port=55555,
            dst_port=port,
            tcp_flags="SYN",
        )
        service.ingest_synthetic_packet(pkt)

    stats_after = service.get_stats()
    assert stats_after.incidents_count >= 1
    assert len(events) >= 1
    assert events[0]["type"] == "incident"


# ---------------------------------------------------------------------------
# 6. FastAPI REST & WebSocket Integration Tests
# ---------------------------------------------------------------------------

def test_fastapi_live_endpoints():
    client = TestClient(app)

    # 1. Interfaces
    res = client.get("/api/live/interfaces")
    assert res.status_code == 200
    data = res.json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)

    # 2. Status
    res = client.get("/api/live/status")
    assert res.status_code == 200
    status_data = res.json()
    assert "status" in status_data
    assert "buffer_capacity" in status_data

    # 3. Pause & Resume
    res = client.post("/api/live/pause")
    assert res.status_code == 200
    res = client.post("/api/live/resume")
    assert res.status_code == 200

    # 4. Packets endpoint
    res = client.get("/api/live/packets?limit=10")
    assert res.status_code == 200
    assert "packets" in res.json()

    # 5. Incidents endpoint
    res = client.get("/api/live/incidents")
    assert res.status_code == 200
    assert "incidents" in res.json()

    # 6. Stop capture
    res = client.post("/api/live/stop")
    assert res.status_code == 200
    assert res.json()["status"] == "stopped"


def test_fastapi_live_incident_pin_note_export(tmp_path: Path):
    client = TestClient(app)
    service = get_live_service()

    # Ingest synthetic alert
    pkt = RollingPacket(
        number=999,
        timestamp=time.time(),
        length=150,
        ip_src="10.10.10.10",
        ip_dst="10.10.10.1",
        transport_proto="tcp",
        dst_port=80,
        http_uri="/admin?password=cleartext123",
    )
    service.ingest_synthetic_packet(pkt)

    incidents = service.evidence_store.get_incidents(limit=1)
    if not incidents:
        # Trigger manually
        f = Finding(
            id="test-f",
            category="test",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            title="Test Alert",
            description="Testing alert preservation",
            source_ip="10.10.10.10",
        )
        inc = service.evidence_store.trigger_incident(f, pkt, service.buffer)
        inc_id = inc.id
    else:
        inc_id = incidents[0].id

    # Test GET incident details
    res = client.get(f"/api/live/incidents/{inc_id}")
    assert res.status_code == 200
    assert res.json()["id"] == inc_id

    # Test POST pin
    res = client.post(f"/api/live/incidents/{inc_id}/pin", json={"pinned": True})
    assert res.status_code == 200
    assert res.json()["pinned"] is True

    # Test POST notes
    res = client.post(f"/api/live/incidents/{inc_id}/notes", json={"notes": "Analyst verified benign test"})
    assert res.status_code == 200
    assert res.json()["notes"] == "Analyst verified benign test"

    # Test GET PCAP export
    res = client.get(f"/api/live/incidents/{inc_id}/export")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert len(res.content) > 24
    # PCAP Magic check
    assert res.content[:4] == b"\xd4\xc3\xb2\xa1"
