"""Automated tests for Beacon Memory historical baseline and explainable change detection engine."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from beacon.core.engine import AnalysisEngine
from beacon.memory.baseline import BaselineEngine
from beacon.memory.detector import ChangeDetector
from beacon.memory.models import (
    BaselineHealth,
    ChangeCategory,
    ConfidenceLevel,
    FeedbackStatus,
)
from beacon.memory.store import MemoryStore


@pytest.fixture
def temp_memory_store(tmp_path: Path) -> MemoryStore:
    """Provide an isolated MemoryStore with a temporary SQLite database."""
    db_file = tmp_path / "test_beacon_memory.db"
    return MemoryStore(db_path=db_file)


def test_memory_store_lifecycle(temp_memory_store: MemoryStore) -> None:
    """Test full ingestion, indexing, and retrieval in MemoryStore."""
    store = temp_memory_store

    # Verify initial empty state
    summary = store.get_baseline_summary()
    assert summary["captures_count"] == 0
    assert summary["baseline_health"] == BaselineHealth.INSUFFICIENT.value

    # Ingest a capture
    capture_id = "cap_test_001"
    filename = "test_network_run1.pcap"
    capture_meta = {
        "start_time": 1700000000.0,
        "end_time": 1700000100.0,
        "duration_seconds": 100.0,
        "total_packets": 250,
        "total_bytes": 102400,
        "unique_hosts": 3,
        "internal_hosts_count": 2,
        "external_hosts_count": 1,
    }
    hosts = [
        {
            "ip": "192.168.1.10",
            "is_internal": True,
            "packets_sent": 150,
            "packets_received": 100,
            "bytes_sent": 60000,
            "bytes_received": 42400,
            "first_seen": 1700000001.0,
            "last_seen": 1700000099.0,
        },
        {
            "ip": "192.168.1.20",
            "is_internal": True,
            "packets_sent": 50,
            "packets_received": 50,
            "bytes_sent": 20000,
            "bytes_received": 20000,
            "first_seen": 1700000005.0,
            "last_seen": 1700000090.0,
        },
        {
            "ip": "93.184.216.34",
            "is_internal": False,
            "packets_sent": 100,
            "packets_received": 150,
            "bytes_sent": 42400,
            "bytes_received": 60000,
            "first_seen": 1700000002.0,
            "last_seen": 1700000098.0,
        },
    ]
    conversations = [
        {
            "conversation_key": "192.168.1.10:54321-93.184.216.34:80",
            "host1": "192.168.1.10",
            "host2": "93.184.216.34",
            "port1": 54321,
            "port2": 80,
            "protocol": "tcp",
            "packet_count": 200,
            "byte_count": 80000,
            "first_seen": 1700000001.0,
            "last_seen": 1700000095.0,
        }
    ]
    iocs = {
        "domains": [{"domain": "example.com", "first_seen": 1700000002.0}],
        "dns_queries": ["example.com"],
        "ips": ["93.184.216.34"],
    }
    findings = [
        {
            "title": "Cleartext HTTP Detected",
            "category": "unencrypted_credentials",
            "severity": "medium",
            "ip": "192.168.1.10",
        }
    ]

    # Ingest
    res = store.ingest_capture(
        capture_id=capture_id,
        filename=filename,
        capture_meta=capture_meta,
        hosts=hosts,
        conversations=conversations,
        iocs=iocs,
        findings=findings,
    )
    assert res["status"] == "indexed"
    assert res["capture_id"] == capture_id

    # Verify store queries
    summary_after = store.get_baseline_summary()
    assert summary_after["captures_count"] == 1
    assert summary_after["hosts_count"] == 3
    assert summary_after["destinations_count"] >= 1
    assert summary_after["relationships_count"] == 1

    captures = store.get_captures_history()
    assert len(captures) == 1
    assert captures[0]["capture_id"] == capture_id
    assert captures[0]["filename"] == filename

    known_dests = store.get_historical_destinations()
    assert "93.184.216.34" in known_dests
    assert "example.com" in known_dests

    known_hosts = store.get_historical_hosts()
    assert "192.168.1.10" in known_hosts
    assert "192.168.1.20" in known_hosts

    all_rels = store.get_historical_relationships()
    assert len(all_rels) == 1


def test_empty_baseline_handling(temp_memory_store: MemoryStore) -> None:
    """An initial capture compared against an empty baseline should report INSUFFICIENT health without crashing."""
    store = temp_memory_store
    detector = ChangeDetector(store)

    current_results: Dict[str, Any] = {
        "summary": {
            "start_time": 1700000000.0,
            "end_time": 1700000060.0,
            "duration_seconds": 60.0,
            "total_packets": 50,
            "total_bytes": 15000,
        },
        "hosts": [
            {
                "ip": "192.168.1.5",
                "is_internal": True,
                "packets_sent": 25,
                "packets_received": 25,
                "bytes_sent": 8000,
                "bytes_received": 7000,
            }
        ],
        "conversations": [],
        "iocs": {"domains": [], "dns_queries": [], "ips": []},
        "findings": [],
    }

    briefing = detector.detect_changes(
        current_results=current_results,
        capture_id="cap_first_run",
        filename="first_run.pcap",
    )

    assert briefing.baseline_captures_count == 0
    assert briefing.baseline_health == BaselineHealth.INSUFFICIENT
    assert briefing.total_changes_detected == 0
    assert briefing.baseline_warning is not None
    assert "Initial" in briefing.baseline_warning


def test_first_seen_destinations_detection(temp_memory_store: MemoryStore) -> None:
    """Detect first-seen external IPs and domains with complete explainability."""
    store = temp_memory_store

    # Ingest baseline
    store.ingest_capture(
        capture_id="cap_baseline_01",
        filename="baseline.pcap",
        capture_meta={
            "duration_seconds": 300.0,
            "total_packets": 500,
            "total_bytes": 200000,
            "unique_hosts": 2,
            "internal_hosts_count": 1,
            "external_hosts_count": 1,
        },
        hosts=[
            {"ip": "192.168.1.10", "is_internal": True, "packets_sent": 250, "packets_received": 250, "bytes_sent": 100000, "bytes_received": 100000},
            {"ip": "8.8.8.8", "is_internal": False, "packets_sent": 250, "packets_received": 250, "bytes_sent": 100000, "bytes_received": 100000},
        ],
        conversations=[
            {
                "conversation_key": "192.168.1.10:5000-8.8.8.8:53",
                "host1": "192.168.1.10",
                "host2": "8.8.8.8",
                "port1": 5000,
                "port2": 53,
                "protocol": "udp",
                "packet_count": 500,
                "byte_count": 200000,
            }
        ],
        iocs={"domains": [{"domain": "dns.google"}], "dns_queries": ["dns.google"], "ips": ["8.8.8.8"]},
        findings=[],
    )

    detector = ChangeDetector(store)

    # New capture introduces brand new external IP (198.51.100.99) and domain (c2-command.org)
    new_results = {
        "summary": {
            "duration_seconds": 60.0,
            "total_packets": 100,
            "total_bytes": 50000,
        },
        "hosts": [
            {"ip": "192.168.1.10", "is_internal": True, "packets_sent": 50, "packets_received": 50, "bytes_sent": 25000, "bytes_received": 25000},
            {"ip": "198.51.100.99", "is_internal": False, "packets_sent": 50, "packets_received": 50, "bytes_sent": 25000, "bytes_received": 25000},
        ],
        "conversations": [
            {
                "conversation_key": "192.168.1.10:49200-198.51.100.99:443",
                "host1": "192.168.1.10",
                "host2": "198.51.100.99",
                "port1": 49200,
                "port2": 443,
                "protocol": "tcp",
                "packet_count": 100,
                "byte_count": 50000,
            }
        ],
        "iocs": {
            "domains": [{"domain": "c2-command.org"}],
            "dns_queries": ["c2-command.org"],
            "ips": ["198.51.100.99"],
        },
        "findings": [],
    }

    briefing = detector.detect_changes(
        current_results=new_results,
        capture_id="cap_incident_02",
        filename="incident.pcap",
    )

    assert briefing.baseline_captures_count == 1
    assert briefing.new_destinations_count >= 1

    # Find the detected first-seen IP item
    ip_items = [i for i in briefing.items if i.entity == "198.51.100.99"]
    assert len(ip_items) == 1
    item = ip_items[0]
    assert item.category == ChangeCategory.FIRST_SEEN_DESTINATION
    assert "External destination" in item.observed_fact
    assert "prior occurrences" in item.statistical_context
    assert "exfiltration" in item.inferred_hypothesis.lower()
    assert "benign" in item.alternative_benign_explanation.lower() or "cdn" in item.alternative_benign_explanation.lower()

    # Find the detected first-seen domain item
    domain_items = [i for i in briefing.items if i.entity == "c2-command.org"]
    assert len(domain_items) == 1
    d_item = domain_items[0]
    assert d_item.category == ChangeCategory.FIRST_SEEN_DESTINATION


def test_new_communication_relationship(temp_memory_store: MemoryStore) -> None:
    """Detect new lateral communication relationships between internal hosts."""
    store = temp_memory_store

    # Ingest baseline where 192.168.1.10 only talks to gateway 192.168.1.1
    store.ingest_capture(
        capture_id="cap_base_lat",
        filename="baseline_lateral.pcap",
        capture_meta={"duration_seconds": 120.0, "total_packets": 100, "total_bytes": 50000, "unique_hosts": 2},
        hosts=[
            {"ip": "192.168.1.10", "is_internal": True, "packets_sent": 50, "packets_received": 50, "bytes_sent": 25000, "bytes_received": 25000},
            {"ip": "192.168.1.1", "is_internal": True, "packets_sent": 50, "packets_received": 50, "bytes_sent": 25000, "bytes_received": 25000},
        ],
        conversations=[
            {
                "conversation_key": "192.168.1.10:1000-192.168.1.1:80",
                "host1": "192.168.1.10",
                "host2": "192.168.1.1",
                "port1": 1000,
                "port2": 80,
                "protocol": "tcp",
                "packet_count": 100,
                "byte_count": 50000,
            }
        ],
        iocs={},
        findings=[],
    )

    detector = ChangeDetector(store)

    # New capture: 192.168.1.10 laterally communicates with 192.168.1.77 for the first time
    new_results = {
        "summary": {"duration_seconds": 60.0, "total_packets": 80, "total_bytes": 32000},
        "hosts": [
            {"ip": "192.168.1.10", "is_internal": True, "packets_sent": 40, "packets_received": 40, "bytes_sent": 16000, "bytes_received": 16000},
            {"ip": "192.168.1.77", "is_internal": True, "packets_sent": 40, "packets_received": 40, "bytes_sent": 16000, "bytes_received": 16000},
        ],
        "conversations": [
            {
                "conversation_key": "192.168.1.10:445-192.168.1.77:49152",
                "host1": "192.168.1.10",
                "host2": "192.168.1.77",
                "port1": 445,
                "port2": 49152,
                "protocol": "tcp",
                "packet_count": 80,
                "byte_count": 32000,
            }
        ],
        "iocs": {},
        "findings": [],
    }

    briefing = detector.detect_changes(
        current_results=new_results,
        capture_id="cap_lat_test",
        filename="lateral.pcap",
    )

    rel_items = [i for i in briefing.items if i.category == ChangeCategory.NEW_RELATIONSHIP]
    assert len(rel_items) >= 1
    rel = rel_items[0]
    assert "lateral" in rel.inferred_hypothesis.lower()
    assert "192.168.1.10" in rel.entity
    assert "192.168.1.77" in rel.entity


def test_volume_surge_deviation(temp_memory_store: MemoryStore) -> None:
    """Detect traffic volume deviation exceeding 3.5x baseline average."""
    store = temp_memory_store

    # Ingest baseline where 192.168.1.5 transmits at approx 100 bytes/sec
    store.ingest_capture(
        capture_id="cap_vol_base",
        filename="vol_base.pcap",
        capture_meta={"duration_seconds": 100.0, "total_packets": 100, "total_bytes": 10000, "unique_hosts": 1},
        hosts=[
            {
                "ip": "192.168.1.5",
                "is_internal": True,
                "packets_sent": 100,
                "packets_received": 0,
                "bytes_sent": 10000,
                "bytes_received": 0,
            }
        ],
        conversations=[],
        iocs={},
        findings=[],
    )

    detector = ChangeDetector(store)

    # In new capture, 192.168.1.5 transmits 500,000 bytes in 100s (5,000 bytes/sec, a 50x surge!)
    new_results = {
        "summary": {"duration_seconds": 100.0, "total_packets": 500, "total_bytes": 500000},
        "hosts": [
            {
                "ip": "192.168.1.5",
                "is_internal": True,
                "packets_sent": 500,
                "packets_received": 0,
                "bytes_sent": 500000,
                "bytes_received": 0,
            }
        ],
        "conversations": [],
        "iocs": {},
        "findings": [],
    }

    briefing = detector.detect_changes(
        current_results=new_results,
        capture_id="cap_surge_test",
        filename="surge.pcap",
    )

    surge_items = [i for i in briefing.items if i.category == ChangeCategory.VOLUME_DEVIATION]
    assert len(surge_items) == 1
    surge = surge_items[0]
    assert surge.entity == "192.168.1.5"
    assert "exfiltration" in surge.inferred_hypothesis.lower()
    assert "patch" in surge.alternative_benign_explanation.lower() or "synchronization" in surge.alternative_benign_explanation.lower()


def test_recurring_anomalies_tracking(temp_memory_store: MemoryStore) -> None:
    """Track recurring anomalies across multiple historical captures."""
    store = temp_memory_store

    finding = {
        "title": "Cleartext FTP Authentication",
        "category": "credentials",
        "severity": "high",
        "ip": "192.168.1.50",
    }

    # Ingest capture 1
    store.ingest_capture(
        capture_id="cap_rec_01",
        filename="ftp1.pcap",
        capture_meta={"duration_seconds": 60.0, "total_packets": 50, "total_bytes": 10000, "unique_hosts": 1},
        hosts=[{"ip": "192.168.1.50", "is_internal": True, "packets_sent": 25, "packets_received": 25, "bytes_sent": 5000, "bytes_received": 5000}],
        conversations=[],
        iocs={},
        findings=[finding],
    )

    # Ingest capture 2 with the same finding
    store.ingest_capture(
        capture_id="cap_rec_02",
        filename="ftp2.pcap",
        capture_meta={"duration_seconds": 60.0, "total_packets": 50, "total_bytes": 10000, "unique_hosts": 1},
        hosts=[{"ip": "192.168.1.50", "is_internal": True, "packets_sent": 25, "packets_received": 25, "bytes_sent": 5000, "bytes_received": 5000}],
        conversations=[],
        iocs={},
        findings=[finding],
    )

    recurring = store.get_recurring_anomalies()
    assert len(recurring) == 1
    rec = recurring[0]
    assert rec["occurrences"] == 2
    assert "cap_rec_01" in rec["captures"]
    assert "cap_rec_02" in rec["captures"]
    assert rec["title"] == "Cleartext FTP Authentication"


def test_subnet_disparity_warning(temp_memory_store: MemoryStore) -> None:
    """Verify baseline compatibility warns when internal IP subnets have zero overlap."""
    store = temp_memory_store

    # Ingest capture from 192.168.1.0/24
    store.ingest_capture(
        capture_id="cap_sub_01",
        filename="office_lan.pcap",
        capture_meta={"duration_seconds": 120.0, "total_packets": 100, "total_bytes": 50000, "unique_hosts": 2},
        hosts=[
            {"ip": "192.168.1.10", "is_internal": True, "packets_sent": 50, "packets_received": 50, "bytes_sent": 25000, "bytes_received": 25000},
            {"ip": "192.168.1.20", "is_internal": True, "packets_sent": 50, "packets_received": 50, "bytes_sent": 25000, "bytes_received": 25000},
        ],
        conversations=[],
        iocs={},
        findings=[],
    )

    detector = ChangeDetector(store)

    # Now analyze a capture from a completely disjoint internal space: 10.10.50.0/24
    disjoint_results = {
        "summary": {"duration_seconds": 60.0, "total_packets": 50, "total_bytes": 20000},
        "hosts": [
            {"ip": "10.10.50.5", "is_internal": True, "packets_sent": 25, "packets_received": 25, "bytes_sent": 10000, "bytes_received": 10000},
            {"ip": "10.10.50.6", "is_internal": True, "packets_sent": 25, "packets_received": 25, "bytes_sent": 10000, "bytes_received": 10000},
        ],
        "conversations": [],
        "iocs": {},
        "findings": [],
    }

    briefing = detector.detect_changes(
        current_results=disjoint_results,
        capture_id="cap_disjoint",
        filename="datacenter.pcap",
    )

    assert briefing.baseline_health == BaselineHealth.INCOMPATIBLE
    assert briefing.baseline_warning is not None
    assert "Subnet Disparity Warning" in briefing.baseline_warning


def test_brief_capture_coverage_warning(temp_memory_store: MemoryStore) -> None:
    """Verify that brief captures (<10s) produce a coverage warning."""
    store = temp_memory_store

    # Ingest baseline
    store.ingest_capture(
        capture_id="cap_dur_01",
        filename="long_capture.pcap",
        capture_meta={"duration_seconds": 200.0, "total_packets": 100, "total_bytes": 50000, "unique_hosts": 1},
        hosts=[{"ip": "192.168.1.10", "is_internal": True, "packets_sent": 50, "packets_received": 50, "bytes_sent": 25000, "bytes_received": 25000}],
        conversations=[],
        iocs={},
        findings=[],
    )

    detector = ChangeDetector(store)

    # Capture lasting only 3.2 seconds
    brief_results = {
        "summary": {"duration_seconds": 3.2, "total_packets": 10, "total_bytes": 2000},
        "hosts": [{"ip": "192.168.1.10", "is_internal": True, "packets_sent": 5, "packets_received": 5, "bytes_sent": 1000, "bytes_received": 1000}],
        "conversations": [],
        "iocs": {},
        "findings": [],
    }

    briefing = detector.detect_changes(
        current_results=brief_results,
        capture_id="cap_brief",
        filename="brief.pcap",
    )

    assert briefing.baseline_warning is not None
    assert "Brief observation window" in briefing.baseline_warning


def test_analyst_feedback_preserves_evidence(temp_memory_store: MemoryStore) -> None:
    """Saving feedback marks an item expected, adjusts priority, and preserves evidence."""
    store = temp_memory_store

    # Ingest baseline
    store.ingest_capture(
        capture_id="cap_fb_base",
        filename="fb_base.pcap",
        capture_meta={"duration_seconds": 100.0, "total_packets": 50, "total_bytes": 20000, "unique_hosts": 1},
        hosts=[{"ip": "192.168.1.10", "is_internal": True, "packets_sent": 25, "packets_received": 25, "bytes_sent": 10000, "bytes_received": 10000}],
        conversations=[],
        iocs={},
        findings=[],
    )

    # Analyst saves feedback marking 198.51.100.77 as expected corporate backup
    fb = store.save_analyst_feedback(
        target_key="198.51.100.77",
        target_type="host",
        status="expected",
        is_expected=True,
        note="Approved corporate off-site backup vault",
    )
    assert fb["status"] == "expected"
    assert fb["is_expected"] is True

    # Retrieve feedback directly
    retrieved = store.get_analyst_feedback("198.51.100.77")
    assert retrieved is not None
    assert retrieved.is_expected is True
    assert retrieved.analyst_note == "Approved corporate off-site backup vault"

    detector = ChangeDetector(store)

    # Run change detection with 198.51.100.77
    results = {
        "summary": {"duration_seconds": 60.0, "total_packets": 50, "total_bytes": 20000},
        "hosts": [
            {"ip": "192.168.1.10", "is_internal": True, "packets_sent": 25, "packets_received": 25, "bytes_sent": 10000, "bytes_received": 10000},
            {"ip": "198.51.100.77", "is_internal": False, "packets_sent": 25, "packets_received": 25, "bytes_sent": 10000, "bytes_received": 10000},
        ],
        "conversations": [],
        "iocs": {"ips": ["198.51.100.77"]},
        "findings": [],
    }

    briefing = detector.detect_changes(
        current_results=results,
        capture_id="cap_fb_test",
        filename="fb_test.pcap",
    )

    items = [i for i in briefing.items if i.entity == "198.51.100.77"]
    assert len(items) == 1
    item = items[0]
    # Evidence is preserved
    assert "External destination" in item.observed_fact
    # Feedback is attached and priority score is scaled down
    assert item.analyst_feedback is not None
    assert item.analyst_feedback["is_expected"] is True
    assert item.analyst_feedback["analyst_note"] == "Approved corporate off-site backup vault"
    assert item.priority_score <= 30.0  # Scaled by 0.3


def test_engine_memory_integration() -> None:
    """Test full integration with AnalysisEngine using real examples/sample.pcap."""
    sample_path = Path("examples/sample.pcap")
    if not sample_path.exists():
        pytest.skip("examples/sample.pcap not found")

    with AnalysisEngine(sample_path) as engine:
        # Run analysis
        engine.analyze()

        # Ingest to memory
        res = engine.record_to_memory(capture_id="cap_sample_test", notes="Integration test capture")
        assert res["status"] == "indexed"

        # Generate briefing
        briefing = engine.get_memory_briefing(capture_id="cap_sample_test")
        assert "capture_id" in briefing
        assert "baseline_health" in briefing
        assert "total_changes_detected" in briefing
        assert isinstance(briefing["items"], list)
