"""Beacon core tests. Includes mock-driven parser tests so CLI and analysis can be verified without TShark."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from beacon.core.modes import AnalysisMode, get_mode_config
from beacon.core.packet_parser import PacketParser, ParsedPacket
from beacon.models import HostStats, ConversationStats, TimelineEvent, IOC, Finding
from beacon.analysis.ioc_extractor import IOCExtractor
from beacon.analysis.packet_inspector import PacketInspector



@pytest.mark.parametrize("mode,value", [(AnalysisMode.BLUE, "blue"), (AnalysisMode.RED, "red"), (AnalysisMode.WHITE, "white")])
def test_analysis_modes(mode: AnalysisMode, value: str) -> None:
    assert mode.value == value


def test_mode_configs() -> None:
    blue = get_mode_config(AnalysisMode.BLUE)
    assert blue.name == "Blue Mode"
    assert "port_scanning" in blue.detection_categories
    red = get_mode_config(AnalysisMode.RED)
    assert red.redact_sensitive
    white = get_mode_config(AnalysisMode.WHITE)
    assert "protocol_distribution" in white.detection_categories


def test_packet_parser_app_protocol_by_port() -> None:
    assert PacketParser._determine_app_protocol([], 80, {}) == "http"
    assert PacketParser._determine_app_protocol([], 443, {}) == "https"
    assert PacketParser._determine_app_protocol([], 53, {}) == "dns"


def test_packet_parser_app_protocol_by_stack() -> None:
    assert PacketParser._determine_app_protocol(["eth", "ip", "tcp", "http"], None, {}) == "http"
    assert PacketParser._determine_app_protocol(["eth", "ip", "udp", "dns"], None, {}) == "dns"


def test_packet_parser_app_protocol_by_layer() -> None:
    assert PacketParser._determine_app_protocol([], None, {"http": {}}) == "http"
    assert PacketParser._determine_app_protocol([], None, {"dns": {}}) == "dns"


def _sample_json_packet(**overrides: object) -> dict:
    layers = {
        "frame": {
            "frame.number": ["42"],
            "frame.time": ["2026-09-17T12:00:00.000000000Z"],
            "frame.time_epoch": ["1694942400.000000000"],
            "frame.len": ["256"],
            "frame.protocols": ["eth:ip:tcp:http"],
        },
        "eth": {"eth.src": ["aa:bb:cc:dd:ee:ff"], "eth.dst": ["00:11:22:33:44:55"]},
        "ip": {"ip.src": ["192.168.1.10"], "ip.dst": ["93.184.216.34"], "ip.proto": ["6"]},
        "tcp": {"tcp.srcport": ["54321"], "tcp.dstport": ["80"]},
        "http": {"http.request.method": ["GET"], "http.request.uri": ["/index.html"]},
    }
    if "ipv6" in overrides:
        layers.pop("ip", None)
    if "udp" in overrides:
        layers.pop("tcp", None)
    if "dns" in overrides:
        layers.pop("http", None)
    layers.update(overrides)
    return {
        "_source": {
            "layers": layers,
            "captured_len": 256,
        },
    }


def test_parse_json_packet() -> None:
    packet = PacketParser.parse_json_packet(_sample_json_packet())
    assert packet is not None
    assert packet.number == 42
    assert packet.ip_src == "192.168.1.10"
    assert packet.ip_dst == "93.184.216.34"
    assert packet.src_port == 54321
    assert packet.dst_port == 80
    assert packet.transport_proto == "tcp"
    assert packet.app_proto == "http"
    assert packet.http_method == "GET"
    assert packet.http_uri == "/index.html"
    assert packet.get_direction() == "outbound"


def test_parse_json_packet_ipv6() -> None:
    packet = PacketParser.parse_json_packet(_sample_json_packet(ipv6={"ipv6.src": ["::1"], "ipv6.dst": ["::2"], "ipv6.nxt": ["6"]}))
    assert packet is not None
    assert packet.ip_version == 6


def test_parse_json_packet_dns() -> None:
    packet = PacketParser.parse_json_packet(
        _sample_json_packet(
            frame={"frame.protocols": ["eth:ip:udp:dns"], "frame.len": ["128"]},
            udp={"udp.srcport": ["12345"], "udp.dstport": ["53"]},
            dns={"dns.qry.name": ["example.com"], "dns.qry.type": ["A"]},
        )
    )
    assert packet is not None
    assert packet.app_proto == "dns"
    assert packet.dns_query_name == "example.com"


def test_parse_json_packet_invalid() -> None:
    assert PacketParser.parse_json_packet({}) is None
    assert PacketParser.parse_json_packet({"layers": {}}) is None


def test_conversation_key_bidirectional() -> None:
    a = PacketParser.parse_json_packet(_sample_json_packet())
    b = PacketParser.parse_json_packet(
        _sample_json_packet(
            ip={"ip.src": ["93.184.216.34"], "ip.dst": ["192.168.1.10"], "ip.proto": ["6"]},
            tcp={"tcp.srcport": ["80"], "tcp.dstport": ["54321"]},
        )
    )
    assert a is not None and b is not None
    assert a.get_conversation_key() == b.get_conversation_key()


def test_host_stats_totals() -> None:
    host = HostStats(ip="1.1.1.1", packets_sent=10, packets_received=5, bytes_sent=5000, bytes_received=2500)
    assert host.total_packets == 15
    assert host.total_bytes == 7500


def test_conversation_stats_duration() -> None:
    now = datetime.now(timezone.utc)
    conv = ConversationStats(key="1<->2", host1="1.1.1.1", host2="2.2.2.2", first_seen=now, last_seen=now)
    assert conv.duration_seconds == 0.0


def test_timeline_event_ordering() -> None:
    base = datetime.now(timezone.utc)
    early = TimelineEvent(timestamp=base, event_type="DNS", source="1.1.1.1", destination="8.8.8.8", protocol="dns")
    late = TimelineEvent(timestamp=base + timedelta(seconds=1), event_type="HTTP", source="1.1.1.1", destination="93.184.216.34", protocol="http")
    assert sorted([late, early], key=lambda e: e.timestamp) == [early, late]


def test_ioc_extraction_count() -> None:
    packet = ParsedPacket(
        number=1,
        timestamp=datetime.now(timezone.utc),
        timestamp_epoch=1694942400.0,
        length=64,
        raw_data={"_source": {"layers": {"frame": {}, "ip": {"ip.src": ["1.2.3.4"], "ip.dst": ["5.6.7.8"]}}}},
    )
    iocs = IOCExtractor.extract([packet, packet])
    ip_ioc = next((item for item in iocs if item.type == "ip" and item.value == "1.2.3.4"), None)
    assert ip_ioc is not None
    assert ip_ioc.count == 2


def test_packet_inspector_http() -> None:
    packet = ParsedPacket(
        number=1,
        timestamp=datetime.now(timezone.utc),
        timestamp_epoch=1694942400.0,
        length=128,
        ip_src="1.1.1.1",
        ip_dst="2.2.2.2",
        src_port=49233,
        dst_port=80,
        transport_proto="tcp",
        app_proto="http",
        http_host="example.com",
        http_uri="/index.html",
        http_method="GET",
        raw_data=_sample_json_packet(),
    )
    detail = PacketInspector.inspect(packet)
    assert detail["packet_number"] == 1
    assert detail["source"] == "1.1.1.1"
    assert detail["http"]["method"] == "GET"
    assert detail["http"]["uri"] == "/index.html"


def test_packet_inspector_dns() -> None:
    packet = ParsedPacket(
        number=2,
        timestamp=datetime.now(timezone.utc),
        timestamp_epoch=1694942400.0,
        length=96,
        ip_src="1.1.1.1",
        ip_dst="8.8.8.8",
        src_port=12345,
        dst_port=53,
        transport_proto="udp",
        app_proto="dns",
        dns_query_name="example.com",
        dns_query_type="A",
        raw_data=_sample_json_packet(dns={"dns.id": ["1234"], "dns.qry.name": ["example.com"], "dns.qry.type": ["A"]}),
    )
    detail = PacketInspector.inspect(packet)
    assert detail["dns"]["query_name"] == "example.com"
    assert detail["dns"]["id"] == "1234"


def test_packet_inspector_redacts_user_agent() -> None:
    packet = ParsedPacket(
        number=3,
        timestamp=datetime.now(timezone.utc),
        timestamp_epoch=1694942400.0,
        length=256,
        ip_src="1.1.1.1",
        ip_dst="2.2.2.2",
        src_port=49234,
        dst_port=80,
        transport_proto="tcp",
        app_proto="http",
        http_user_agent="Mozilla/5.0 Authorization=Bearer secret123",
        raw_data=_sample_json_packet(http={"http.user_agent": ["Mozilla/5.0 Authorization=Bearer secret123"]}),
    )
    detail = PacketInspector.inspect(packet)
    assert "secret123" not in detail["http"]["user_agent"]
    assert "[REDACTED]" in detail["http"]["user_agent"]


def test_missing_packet() -> None:
    assert PacketParser.parse_json_packet(None) is None
