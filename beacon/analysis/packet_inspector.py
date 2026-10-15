"""Deep packet inspection helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional

from beacon.core.packet_parser import ParsedPacket
from beacon.utils.formatters import first_value, redact_text


class PacketInspector:
    """Inspect a normalized packet without executing payload content."""

    @staticmethod
    def inspect(packet: ParsedPacket) -> Dict[str, Any]:
        layers = packet.raw_data.get("_source", {}).get("layers", {})
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        dns = layers.get("dns", {})
        http = layers.get("http", {})
        tls = layers.get("tls", {}) or layers.get("ssl", {})
        payload = packet.raw_data.get("_source", {}).get("captured_len", 0)
        return {
            "packet_number": packet.number,
            "timestamp": packet.timestamp.isoformat() if packet.timestamp else None,
            "length": packet.length,
            "protocols": packet.protocols,
            "application_protocol": packet.app_proto,
            "transport_protocol": packet.transport_proto,
            "source": packet.ip_src,
            "destination": packet.ip_dst,
            "source_port": packet.src_port,
            "destination_port": packet.dst_port,
            "direction": packet.get_direction(),
            "tcp": {
                "flags": first_value(tcp.get("tcp.flags")),
                "flags_text": first_value(tcp.get("tcp.flags.str")),
                "stream": first_value(tcp.get("tcp.stream")),
                "sequence": first_value(tcp.get("tcp.seq")),
                "acknowledgment": first_value(tcp.get("tcp.ack")),
                "retransmission": bool(first_value(tcp.get("tcp.retransmission"))),
            },
            "dns": {
                "id": first_value(dns.get("dns.id")),
                "flags": first_value(dns.get("dns.flags")),
                "query_name": first_value(dns.get("dns.qry.name")) or packet.dns_query_name,
                "query_type": first_value(dns.get("dns.qry.type")) or packet.dns_query_type,
                "answers": first_value(dns.get("dns.rr.data")),
            },
            "http": {
                "method": first_value(http.get("http.request.method")) or packet.http_method,
                "uri": first_value(http.get("http.request.uri")) or packet.http_uri,
                "host": first_value(http.get("http.host")) or packet.http_host,
                "user_agent": redact_text(first_value(http.get("http.user_agent")) or packet.http_user_agent or ""),
                "response_code": first_value(http.get("http.response.code")) or packet.http_response_code,
            },
            "tls": {
                "handshake_type": first_value(tls.get("tls.handshake.type")),
                "version": first_value(tls.get("tls.handshake.version")),
                "server_name": first_value(tls.get("tls.handshake.extensions_server_name")) or packet.tls_server_name,
            },
            "captured_length": payload,
        }
