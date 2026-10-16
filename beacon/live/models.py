"""Data models and enums for Beacon Live continuous network capture and smart evidence retention."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


class LiveCaptureStatus(str, enum.Enum):
    """Lifecycle status of the live capture engine."""
    STOPPED = "stopped"
    STARTING = "starting"
    CAPTURING = "capturing"
    PAUSED = "paused"
    ERROR = "error"


class EvidenceStatus(str, enum.Enum):
    """Integrity and completeness of an incident evidence capture."""
    COLLECTING = "collecting"  # Post-trigger observation window is currently open
    COMPLETE = "complete"      # All pre-trigger, trigger, and post-trigger packets captured
    PARTIAL = "partial"        # Some pre-trigger packets were evicted from buffer prior to alert


@dataclass
class CaptureInterface:
    """Network capture interface information."""
    id: str  # Interface identifier/index (e.g. "1", "\\Device\\NPF_...")
    name: str  # Friendly name (e.g. "Wi-Fi", "eth0")
    description: str  # Hardware/driver description
    device: str  # System device path
    addresses: List[str] = field(default_factory=list)  # IP / MAC addresses
    is_loopback: bool = False
    is_up: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RollingPacket:
    """Compact decoded packet representation retained in the bounded in-memory rolling buffer."""
    number: int
    timestamp: float  # Epoch timestamp (seconds.microseconds)
    length: int  # Wire length in bytes
    ip_src: str = ""
    ip_dst: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport_proto: str = ""  # tcp, udp, icmp, etc.
    app_proto: str = ""  # http, dns, tls, etc.
    protocols: List[str] = field(default_factory=list)
    tcp_flags: Optional[str] = None
    dns_query_name: Optional[str] = None
    http_uri: Optional[str] = None
    http_method: Optional[str] = None
    tls_server_name: Optional[str] = None
    direction: str = "unknown"  # lateral, outbound, inbound, external
    raw_hex: Optional[str] = None  # Raw packet hex (when captured with -x)

    @property
    def conversation_key(self) -> str:
        """Normalized bidirectional conversation key."""
        if not self.ip_src or not self.ip_dst:
            return "unknown"
        endpoints = sorted([
            (self.ip_src, self.src_port if self.src_port is not None else -1),
            (self.ip_dst, self.dst_port if self.dst_port is not None else -1),
        ])
        first_ip, first_port = endpoints[0]
        second_ip, second_port = endpoints[1]
        proto = self.transport_proto or "ip"
        if self.src_port is not None and self.dst_port is not None:
            first_str = f"[{first_ip}]:{first_port}" if ":" in first_ip else f"{first_ip}:{first_port}"
            second_str = f"[{second_ip}]:{second_port}" if ":" in second_ip else f"{second_ip}:{second_port}"
            return f"{first_str}<->{second_str}({proto})"
        return f"{first_ip}<->{second_ip}"

    @property
    def is_reconstructed(self) -> bool:
        """Indicates whether this packet frame was reconstructed rather than preserved verbatim from the wire."""
        return not bool(self.raw_hex)

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        data["conversation_key"] = self.conversation_key
        data["is_reconstructed"] = self.is_reconstructed
        if not include_raw:
            data.pop("raw_hex", None)
        return data

    @property
    def estimated_bytes(self) -> int:
        """Estimated RAM footprint in bytes."""
        base = 250
        if self.raw_hex:
            base += len(self.raw_hex)
        return base


@dataclass
class IncidentEvidence:
    """
    Durable, evidence-retained security incident.
    Stores pre-trigger, trigger, and post-trigger packets alongside detection metadata.
    """
    id: str
    finding_id: str
    title: str
    category: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # high, medium, low
    trigger_timestamp: float
    trigger_packet_number: int
    trigger_packet: RollingPacket
    pre_trigger_packets: List[RollingPacket] = field(default_factory=list)
    post_trigger_packets: List[RollingPacket] = field(default_factory=list)
    post_trigger_window_end: float = 0.0
    evidence_status: EvidenceStatus = EvidenceStatus.COLLECTING
    missing_context_reason: Optional[str] = None
    related_hosts: List[str] = field(default_factory=list)
    related_conversations: List[str] = field(default_factory=list)
    analyst_pinned: bool = False
    analyst_notes: str = ""
    evidence_budget_exceeded: bool = False
    occurrence_count: int = 1
    last_seen_timestamp: float = 0.0

    @property
    def total_retained_packets(self) -> int:
        return len(self.pre_trigger_packets) + 1 + len(self.post_trigger_packets)

    def get_all_packets_ordered(self) -> List[RollingPacket]:
        """Return all retained packets chronologically sorted."""
        all_pkts = list(self.pre_trigger_packets) + [self.trigger_packet] + list(self.post_trigger_packets)
        return sorted(all_pkts, key=lambda p: (p.timestamp, p.number))

    def to_dict(self, include_packets: bool = True, include_raw: bool = False) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "trigger_timestamp": self.trigger_timestamp,
            "trigger_packet_number": self.trigger_packet_number,
            "evidence_status": self.evidence_status.value,
            "missing_context_reason": self.missing_context_reason,
            "related_hosts": self.related_hosts,
            "related_conversations": self.related_conversations,
            "analyst_pinned": self.analyst_pinned,
            "analyst_notes": self.analyst_notes,
            "evidence_budget_exceeded": self.evidence_budget_exceeded,
            "occurrence_count": self.occurrence_count,
            "last_seen_timestamp": self.last_seen_timestamp or self.trigger_timestamp,
            "total_retained_packets": self.total_retained_packets,
            "pre_trigger_count": len(self.pre_trigger_packets),
            "post_trigger_count": len(self.post_trigger_packets),
            "trigger_packet": self.trigger_packet.to_dict(include_raw=include_raw) if self.trigger_packet else None,
            "pre_trigger_packets": [p.to_dict(include_raw=include_raw) for p in self.pre_trigger_packets] if include_packets else [],
            "post_trigger_packets": [p.to_dict(include_raw=include_raw) for p in self.post_trigger_packets] if include_packets else [],
        }


@dataclass
class LiveCaptureStats:
    """Current telemetry metrics and aggregates of the live capture engine."""
    status: LiveCaptureStatus
    selected_interface: Optional[str]
    elapsed_seconds: float
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    buffer_capacity: int
    buffer_occupancy: int
    buffer_memory_bytes: int
    process_memory_mb: float
    dropped_packets: int
    analysis_backlog: int
    incidents_count: int
    pinned_incidents_count: int
    active_collection_windows_count: int
    top_hosts: List[Dict[str, Any]] = field(default_factory=list)
    top_protocols: Dict[str, int] = field(default_factory=dict)
    active_conversations: List[Dict[str, Any]] = field(default_factory=list)
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    capture_filter: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
