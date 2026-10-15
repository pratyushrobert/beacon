"""Shared data models used by Beacon's analysis, detection, and interfaces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Finding confidence levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class HostStats:
    """Aggregated statistics for a single network host."""

    ip: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_internal: bool = False
    protocols: set[str] = field(default_factory=set)

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["total_packets"] = self.total_packets
        data["total_bytes"] = self.total_bytes
        data["duration_seconds"] = self.duration_seconds
        data["protocols"] = sorted(self.protocols)
        return data


@dataclass
class ConversationStats:
    """Aggregated statistics for a bidirectional network conversation."""

    key: str
    host1: str
    host2: str
    port1: Optional[int] = None
    port2: Optional[int] = None
    protocol: str = "unknown"
    packet_count: int = 0
    byte_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    directions: set[str] = field(default_factory=set)
    app_protocols: set[str] = field(default_factory=set)

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    @property
    def avg_packet_interval(self) -> float:
        if self.packet_count <= 1:
            return 0.0
        return self.duration_seconds / (self.packet_count - 1)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["duration_seconds"] = self.duration_seconds
        data["avg_packet_interval"] = self.avg_packet_interval
        data["directions"] = sorted(self.directions)
        data["app_protocols"] = sorted(self.app_protocols)
        return data


@dataclass
class ProtocolStats:
    """Protocol-level traffic statistics."""

    name: str
    packet_count: int = 0
    byte_count: int = 0

    @property
    def percentage(self) -> float:
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    """A timestamped event suitable for timeline display."""

    timestamp: datetime
    event_type: str
    source: str = ""
    destination: str = ""
    protocol: str = ""
    message: str = ""
    packet_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class Finding:
    """An evidence-backed analysis finding."""

    id: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    recommendation: str = ""
    redacted: bool = False
    protocol: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_packets: List[int] = field(default_factory=list)
    related_conversations: List[str] = field(default_factory=list)
    detection_rationale: str = ""
    next_step: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        if self.timestamp:
            data["timestamp"] = self.timestamp.isoformat()
        if self.first_seen:
            data["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            data["last_seen"] = self.last_seen.isoformat()
        return data


@dataclass
class IOC:
    """A network indicator of interest."""

    type: str
    value: str
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    context: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.first_seen:
            data["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            data["last_seen"] = self.last_seen.isoformat()
        return data


@dataclass
class AnalysisResult:
    """Structured result returned by the analysis engine."""

    mode: str
    pcap_file: str
    total_packets: int = 0
    total_bytes: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    unique_hosts: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    conversations: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)
    capture_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.start_time:
            data["start_time"] = self.start_time.isoformat()
        if self.end_time:
            data["end_time"] = self.end_time.isoformat()
        return data

    def __getitem__(self, key: str) -> Any:
        """Allow compatibility with the original dictionary-style result API."""
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)
