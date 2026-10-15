"""Timeline event construction with meaningful security context."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Set

from beacon.core.packet_parser import ParsedPacket
from beacon.models import TimelineEvent


class TimelineBuilder:
    """Create a readable event stream from packet metadata."""

    @staticmethod
    def build(packets: Iterable[ParsedPacket]) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []

        # Track connection states for meaningful events
        tcp_streams: Dict[str, Dict] = defaultdict(dict)
        dns_lookups: Dict[str, List] = defaultdict(list)

        for packet in packets:
            if not packet.timestamp:
                continue

            # TCP connection tracking
            if packet.transport_proto == "tcp" and packet.tcp_flags:
                conv_key = packet.get_conversation_key()

                # SYN - connection initiation
                if "SYN" in str(packet.tcp_flags_text or "") and "ACK" not in str(packet.tcp_flags_text or ""):
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="TCP_SYN",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="tcp",
                            message=f"Connection attempt: {packet.ip_src}:{packet.src_port} → {packet.ip_dst}:{packet.dst_port}",
                            packet_number=packet.number,
                        )
                    )
                    if conv_key:
                        tcp_streams[conv_key]["syn"] = packet.timestamp

                # SYN-ACK - connection acknowledgment
                elif "SYN" in str(packet.tcp_flags_text or "") and "ACK" in str(packet.tcp_flags_text or ""):
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="TCP_SYNACK",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="tcp",
                            message=f"Connection acknowledged: {packet.ip_src}:{packet.src_port} ← {packet.ip_dst}:{packet.dst_port}",
                            packet_number=packet.number,
                        )
                    )

                # FIN - connection termination
                elif "FIN" in str(packet.tcp_flags_text or ""):
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="TCP_FIN",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="tcp",
                            message=f"Connection closing: {packet.ip_src}:{packet.src_port} → {packet.ip_dst}:{packet.dst_port}",
                            packet_number=packet.number,
                        )
                    )

                # RST - connection reset
                elif "RST" in str(packet.tcp_flags_text or ""):
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="TCP_RST",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="tcp",
                            message=f"Connection reset: {packet.ip_src}:{packet.src_port} ⚠ {packet.ip_dst}:{packet.dst_port}",
                            packet_number=packet.number,
                        )
                    )

            # DNS queries and responses
            elif packet.app_proto == "dns":
                if packet.dns_query_name:
                    dns_lookups[packet.dns_query_name].append(packet)
                    query_type = packet.dns_query_type or "A"
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="DNS_QUERY",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="dns",
                            message=f"DNS query: {packet.dns_query_name} ({query_type})",
                            packet_number=packet.number,
                        )
                    )

                if packet.dns_answer:
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="DNS_RESPONSE",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="dns",
                            message=f"DNS response: {packet.dns_query_name or 'unknown'} → {packet.dns_answer}",
                            packet_number=packet.number,
                        )
                    )

            # HTTP requests and responses
            elif packet.app_proto == "http":
                if packet.http_method and packet.http_uri:
                    host = packet.http_host or packet.ip_dst or "unknown"
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="HTTP_REQUEST",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="http",
                            message=f"HTTP {packet.http_method} {host}{packet.http_uri}",
                            packet_number=packet.number,
                        )
                    )

                if packet.http_response_code:
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="HTTP_RESPONSE",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="http",
                            message=f"HTTP {packet.http_response_code}",
                            packet_number=packet.number,
                        )
                    )

            # TLS/HTTPS connections
            elif packet.app_proto == "https" or packet.tls_handshake_type:
                if packet.tls_server_name:
                    events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            event_type="TLS_HANDSHAKE",
                            source=packet.ip_src or "",
                            destination=packet.ip_dst or "",
                            protocol="tls",
                            message=f"TLS connection to {packet.tls_server_name}",
                            packet_number=packet.number,
                        )
                    )

        return sorted(events, key=lambda event: event.timestamp)

