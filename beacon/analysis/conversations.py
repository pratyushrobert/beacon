"""Conversation-level traffic aggregation."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from beacon.core.packet_parser import ParsedPacket
from beacon.models import ConversationStats


class ConversationAnalyzer:
    """Build bidirectional conversation aggregates."""

    @staticmethod
    def analyze(packets: Iterable[ParsedPacket]) -> List[ConversationStats]:
        conversations: Dict[str, ConversationStats] = {}
        for packet in packets:
            key = packet.get_conversation_key()
            if not key:
                continue
            conversation = conversations.setdefault(
                key,
                ConversationStats(
                    key=key,
                    host1=packet.ip_src or "",
                    host2=packet.ip_dst or "",
                    protocol=packet.transport_proto or "unknown",
                ),
            )
            conversation.packet_count += 1
            conversation.byte_count += packet.length
            conversation.protocol = packet.transport_proto or conversation.protocol
            conversation.app_protocols.add(packet.app_proto) if packet.app_proto else None
            if packet.direction:
                conversation.directions.add(packet.direction)
            if packet.timestamp:
                conversation.first_seen = packet.timestamp if not conversation.first_seen else min(conversation.first_seen, packet.timestamp)
                conversation.last_seen = packet.timestamp if not conversation.last_seen else max(conversation.last_seen, packet.timestamp)
            if packet.ip_src and packet.ip_dst:
                hosts = sorted([packet.ip_src, packet.ip_dst])
                conversation.host1, conversation.host2 = hosts
                ports = sorted([port for port in (packet.src_port, packet.dst_port) if port])
                if len(ports) == 2:
                    conversation.port1, conversation.port2 = ports
        return sorted(conversations.values(), key=lambda item: item.byte_count, reverse=True)
