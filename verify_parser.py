"""Quick verification script for parser."""
from datetime import datetime, timezone
from beacon.core.packet_parser import PacketParser, ParsedPacket
from beacon.analysis.ioc_extractor import IOCExtractor
from beacon.analysis.packet_inspector import PacketInspector

def sample_json_packet(**overrides):
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

# Test 1: Parse HTTP packet
packet = PacketParser.parse_json_packet(sample_json_packet())
assert packet is not None, "Parser returned None"
assert packet.number == 42, f"Expected 42, got {packet.number}"
assert packet.ip_src == "192.168.1.10", f"Expected 192.168.1.10, got {packet.ip_src}"
assert packet.src_port == 54321
assert packet.dst_port == 80
assert packet.transport_proto == "tcp"
assert packet.app_proto == "http"
assert packet.http_method == "GET"
assert packet.http_uri == "/index.html"
assert packet.get_direction() == "outbound"
print("✓ HTTP packet parsing")

# Test 2: Parse DNS packet
dns_packet = PacketParser.parse_json_packet(
    sample_json_packet(
        frame={"frame.protocols": ["eth:ip:udp:dns"], "frame.len": ["128"]},
        udp={"udp.srcport": ["12345"], "udp.dstport": ["53"]},
        dns={"dns.qry.name": ["example.com"], "dns.qry.type": ["A"]},
    )
)
assert dns_packet is not None
assert dns_packet.app_proto == "dns"
assert dns_packet.dns_query_name == "example.com"
print("✓ DNS packet parsing")

# Test 3: Parse IPv6 packet
ipv6_packet = PacketParser.parse_json_packet(
    sample_json_packet(ipv6={"ipv6.src": ["::1"], "ipv6.dst": ["::2"], "ipv6.nxt": ["6"]})
)
assert ipv6_packet is not None
assert ipv6_packet.ip_version == 6
print("✓ IPv6 packet parsing")

# Test 4: Conversation key bidirectional
a = PacketParser.parse_json_packet(sample_json_packet())
b = PacketParser.parse_json_packet(
    sample_json_packet(
        ip={"ip.src": ["93.184.216.34"], "ip.dst": ["192.168.1.10"], "ip.proto": ["6"]},
        tcp={"tcp.srcport": ["80"], "tcp.dstport": ["54321"]},
    )
)
assert a.get_conversation_key() == b.get_conversation_key()
print("✓ Bidirectional conversation key")

# Test 5: IOC extraction
packet2 = ParsedPacket(
    number=1,
    timestamp=datetime.now(timezone.utc),
    timestamp_epoch=1694942400.0,
    length=64,
    raw_data={"_source": {"layers": {"frame": {}, "ip": {"ip.src": ["1.2.3.4"], "ip.dst": ["5.6.7.8"]}}}},
)
iocs = IOCExtractor.extract([packet2, packet2])
ip_ioc = next((item for item in iocs if item.type == "ip" and item.value == "1.2.3.4"), None)
assert ip_ioc is not None
assert ip_ioc.count == 2
print("✓ IOC extraction")

# Test 6: Packet inspector
detail = PacketInspector.inspect(packet)
assert detail["packet_number"] == 42
assert detail["source"] == "192.168.1.10"
assert detail["http"]["method"] == "GET"
print("✓ Packet inspector")

# Test 7: Redaction
packet3 = ParsedPacket(
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
    raw_data=sample_json_packet(http={"http.user_agent": ["Mozilla/5.0 Authorization=Bearer secret123"]}),
)
detail3 = PacketInspector.inspect(packet3)
assert "secret123" not in detail3["http"]["user_agent"]
assert "[REDACTED]" in detail3["http"]["user_agent"]
print("✓ Redaction")

print("\nAll parser tests passed!")