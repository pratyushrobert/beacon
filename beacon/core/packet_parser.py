"""Packet parsing and normalization layer.

The parser intentionally treats TShark output as untrusted data.  It extracts a
small, predictable set of fields and keeps the original JSON payload for
protocol-specific inspection without executing or interpreting packet content.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _first(value: Any, default: Any = None) -> Any:
    """Return the first scalar value from a TShark JSON field."""
    if isinstance(value, list):
        for item in value:
            result = _first(item)
            if result not in (None, ""):
                return result
    elif isinstance(value, dict):
        for item in value.values():
            result = _first(item)
            if result not in (None, ""):
                return result
    return default if value in (None, "") else value


def _as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    """Safely convert a TShark field to an integer, preserving valid zero values."""
    try:
        val = _first(value)
        if val in (None, ""):
            return default
        if isinstance(val, str):
            val = val.strip()
            if not val:
                return default
            if "." in val:
                try:
                    return int(float(val))
                except (ValueError, TypeError):
                    pass
            if val.startswith(("0x", "0X")):
                try:
                    return int(val, 16)
                except (ValueError, TypeError):
                    pass
        return int(val)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    """Safely convert a TShark field to a float, preserving valid zero values."""
    try:
        val = _first(value)
        if val in (None, ""):
            return default
        if isinstance(val, str):
            val = val.strip()
            if not val:
                return default
        return float(val)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any) -> bool:
    """Convert common TShark boolean representations to bool."""
    return str(_first(value, "")).lower() in {"1", "true", "yes", "set"}


@dataclass
class ParsedPacket:
    """Normalized packet representation."""

    number: int
    timestamp: datetime
    timestamp_epoch: float
    length: int
    protocols: List[str] = None  # type: ignore[assignment]
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    ip_version: Optional[int] = None
    ip_proto: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport_proto: Optional[str] = None
    app_proto: Optional[str] = None

    # TCP metadata retained for connection and deep-packet analysis.
    tcp_flags: Optional[str] = None
    tcp_flags_text: Optional[str] = None
    tcp_stream: Optional[str] = None
    tcp_sequence: Optional[str] = None
    tcp_acknowledgment: Optional[str] = None
    tcp_retransmission: bool = False

    # Protocol metadata extracted by TShark.  Values remain strings because
    # TShark field types vary between versions and packet types.
    dns_id: Optional[str] = None
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[str] = None
    dns_answer: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_host: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_response_code: Optional[str] = None
    tls_handshake_type: Optional[str] = None
    tls_version: Optional[str] = None
    tls_server_name: Optional[str] = None
    raw_data: Dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.protocols is None:
            self.protocols = []
        if self.raw_data is None:
            self.raw_data = {}

    def get_conversation_key(self) -> Optional[str]:
        """Generate a stable bidirectional conversation key, preserving valid port 0 and bracketing IPv6."""
        if not self.ip_src or not self.ip_dst:
            return None
        endpoints = sorted(
            [
                (self.ip_src, self.src_port if self.src_port is not None else -1),
                (self.ip_dst, self.dst_port if self.dst_port is not None else -1),
            ]
        )
        first_ip, first_port = endpoints[0]
        second_ip, second_port = endpoints[1]
        proto = self.transport_proto or "unknown"
        if self.src_port is not None and self.dst_port is not None:
            first_str = f"[{first_ip}]:{first_port}" if ":" in first_ip else f"{first_ip}:{first_port}"
            second_str = f"[{second_ip}]:{second_port}" if ":" in second_ip else f"{second_ip}:{second_port}"
            return f"{first_str}<->{second_str}({proto})"
        return f"{first_ip}<->{second_ip}"

    def is_ipv4(self) -> bool:
        return self.ip_version == 4

    def is_ipv6(self) -> bool:
        return self.ip_version == 6

    def is_internal_ip(self, ip: str) -> bool:
        """Check whether an address is in a private/internal range."""
        try:
            return ip_address(ip).is_private
        except ValueError:
            return False

    def get_direction(self) -> str:
        """Determine traffic direction (lateral, outbound, inbound, external)."""
        if not self.ip_src or not self.ip_dst:
            return "unknown"
        source_internal = self.is_internal_ip(self.ip_src)
        destination_internal = self.is_internal_ip(self.ip_dst)
        if source_internal and destination_internal:
            return "lateral"
        if source_internal and not destination_internal:
            return "outbound"
        if not source_internal and destination_internal:
            return "inbound"
        return "external"

    @property
    def direction(self) -> str:
        return self.get_direction()


class PacketParser:
    """Convert TShark JSON/EK packets into normalized packet objects."""

    @staticmethod
    def _layers(packet_data: Dict[str, Any]) -> Dict[str, Any]:
        source = packet_data.get("_source", {})
        layers = source.get("layers") if isinstance(source, dict) else None
        if not layers:
            layers = packet_data.get("layers")
        return layers if isinstance(layers, dict) else {}

    @staticmethod
    def _field(layers: Dict[str, Any], layer: str, field: str, default: Any = None) -> Any:
        layer_dict = layers.get(layer)
        if not isinstance(layer_dict, dict):
            if field in layers:
                return _first(layers[field], default)
            return default

        # 1. Exact match (e.g. "frame.len" or "ip.src")
        if field in layer_dict:
            return _first(layer_dict[field], default)

        # 2. Underscored match (e.g. "frame_len" or "ip_src")
        underscored = field.replace(".", "_")
        if underscored in layer_dict:
            return _first(layer_dict[underscored], default)

        # 3. Layer prefix + underscored match (EK format: "frame_frame_len", "ip_ip_src", "udp_udp_dstport")
        ek_name = f"{layer}_{underscored}"
        if ek_name in layer_dict:
            return _first(layer_dict[ek_name], default)

        # 4. Short name without leading layer prefix (e.g. "len" instead of "frame.len")
        if field.startswith(f"{layer}."):
            short_field = field[len(layer) + 1 :]
            if short_field in layer_dict:
                return _first(layer_dict[short_field], default)
            short_under = short_field.replace(".", "_")
            if short_under in layer_dict:
                return _first(layer_dict[short_under], default)

        return default

    @staticmethod
    def _protocol_stack(frame: Dict[str, Any]) -> List[str]:
        value = (
            frame.get("frame.protocols")
            or frame.get("frame_frame_protocols")
            or frame.get("frame_protocols")
            or ""
        )
        value = _first(value, "")
        if isinstance(value, str):
            return [part.strip().lower() for part in value.split(":") if part.strip()]
        return []

    @staticmethod
    def parse_json_packet(packet_data: Dict[str, Any]) -> Optional[ParsedPacket]:
        """Parse a packet from TShark JSON or EK output."""
        try:
            layers = PacketParser._layers(packet_data)
            if not layers:
                if "index" not in packet_data:
                    logger.warning("No layers found in packet data")
                return None

            frame = layers.get("frame", {}) if isinstance(layers.get("frame"), dict) else {}
            frame_number = _as_int(PacketParser._field(layers, "frame", "frame.number"), 0) or 0
            frame_epoch = _as_float(PacketParser._field(layers, "frame", "frame.time_epoch"), 0.0) or 0.0
            frame_length = _as_int(PacketParser._field(layers, "frame", "frame.len"), 0) or 0
            frame_time = PacketParser._field(layers, "frame", "frame.time", "")
            try:
                timestamp = datetime.fromisoformat(str(frame_time).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                if frame_epoch > 0:
                    timestamp = datetime.fromtimestamp(frame_epoch)
                elif "timestamp" in packet_data:
                    try:
                        frame_epoch = float(packet_data["timestamp"]) / 1000.0
                        timestamp = datetime.fromtimestamp(frame_epoch)
                    except (ValueError, TypeError):
                        timestamp = datetime.now()
                else:
                    timestamp = datetime.now()

            if frame_epoch <= 0.0 and timestamp:
                try:
                    frame_epoch = timestamp.timestamp()
                except Exception:
                    frame_epoch = 0.0

            protocols = PacketParser._protocol_stack(frame)
            eth = layers.get("eth", {}) if isinstance(layers.get("eth"), dict) else {}
            ip = layers.get("ip", {}) if isinstance(layers.get("ip"), dict) else {}
            ipv6 = layers.get("ipv6", {}) if isinstance(layers.get("ipv6"), dict) else {}
            tcp = layers.get("tcp", {}) if isinstance(layers.get("tcp"), dict) else {}
            udp = layers.get("udp", {}) if isinstance(layers.get("udp"), dict) else {}

            if "ip" in layers:
                ip_src = PacketParser._field(layers, "ip", "ip.src")
                ip_dst = PacketParser._field(layers, "ip", "ip.dst")
                ip_version = 4
                ip_proto = _as_int(PacketParser._field(layers, "ip", "ip.proto"))
            elif "ipv6" in layers:
                ip_src = PacketParser._field(layers, "ipv6", "ipv6.src")
                ip_dst = PacketParser._field(layers, "ipv6", "ipv6.dst")
                ip_version = 6
                ip_proto = _as_int(PacketParser._field(layers, "ipv6", "ipv6.nxt"))
            else:
                ip_src = ip_dst = None
                ip_version = ip_proto = None

            if "tcp" in layers:
                src_port = _as_int(PacketParser._field(layers, "tcp", "tcp.srcport"))
                dst_port = _as_int(PacketParser._field(layers, "tcp", "tcp.dstport"))
                transport_proto = "tcp"
            elif "udp" in layers:
                src_port = _as_int(PacketParser._field(layers, "udp", "udp.srcport"))
                dst_port = _as_int(PacketParser._field(layers, "udp", "udp.dstport"))
                transport_proto = "udp"
            else:
                src_port = dst_port = None
                transport_proto = None

            app_proto = PacketParser._determine_app_protocol(protocols, dst_port, layers)
            return ParsedPacket(
                number=frame_number,
                timestamp=timestamp,
                timestamp_epoch=frame_epoch,
                length=frame_length,
                protocols=protocols,
                eth_src=PacketParser._field(layers, "eth", "eth.src"),
                eth_dst=PacketParser._field(layers, "eth", "eth.dst"),
                ip_src=ip_src,
                ip_dst=ip_dst,
                ip_version=ip_version,
                ip_proto=ip_proto,
                src_port=src_port,
                dst_port=dst_port,
                transport_proto=transport_proto,
                app_proto=app_proto,
                tcp_flags=PacketParser._field(layers, "tcp", "tcp.flags"),
                tcp_flags_text=PacketParser._field(layers, "tcp", "tcp.flags.str"),
                tcp_stream=PacketParser._field(layers, "tcp", "tcp.stream"),
                tcp_sequence=PacketParser._field(layers, "tcp", "tcp.seq"),
                tcp_acknowledgment=PacketParser._field(layers, "tcp", "tcp.ack"),
                tcp_retransmission=_as_bool(PacketParser._field(layers, "tcp", "tcp.retransmission")),
                dns_id=PacketParser._field(layers, "dns", "dns.id"),
                dns_query_name=PacketParser._field(layers, "dns", "dns.qry.name"),
                dns_query_type=PacketParser._field(layers, "dns", "dns.qry.type"),
                dns_answer=PacketParser._field(layers, "dns", "dns.a"),
                http_method=PacketParser._field(layers, "http", "http.request.method"),
                http_uri=PacketParser._field(layers, "http", "http.request.uri"),
                http_host=PacketParser._field(layers, "http", "http.host"),
                http_user_agent=PacketParser._field(layers, "http", "http.user_agent"),
                http_response_code=PacketParser._field(layers, "http", "http.response.code"),
                tls_handshake_type=PacketParser._field(layers, "tls", "tls.handshake.type")
                or PacketParser._field(layers, "ssl", "tls.handshake.type"),
                tls_version=PacketParser._field(layers, "tls", "tls.handshake.version")
                or PacketParser._field(layers, "ssl", "tls.handshake.version"),
                tls_server_name=PacketParser._field(layers, "tls", "tls.handshake.extensions_server_name")
                or PacketParser._field(layers, "ssl", "tls.handshake.extensions_server_name"),
                raw_data=packet_data,
            )
        except Exception as exc:
            logger.error("Error parsing packet: %s", exc)
            return None

    @staticmethod
    def _determine_app_protocol(
        protocols: List[str], dst_port: Optional[int], layers: Dict[str, Any]
    ) -> Optional[str]:
        """Determine the application protocol from layers, stack, and ports."""
        layer_protocols = {str(layer).lower() for layer in layers}
        if "http2" in layer_protocols:
            return "http2"
        if "http" in layer_protocols:
            return "http"
        if "dns" in layer_protocols:
            return "dns"
        if "tls" in layer_protocols or "ssl" in layer_protocols:
            return "https"
        if "ssh" in layer_protocols:
            return "ssh"
        if "ftp" in layer_protocols:
            return "ftp"
        if "smtp" in layer_protocols:
            return "smtp"
        if "pop" in layer_protocols:
            return "pop3"
        if "imap" in layer_protocols:
            return "imap"
        if "smb" in layer_protocols or "nbss" in layer_protocols:
            return "smb"

        common_protocols = {
            "http", "https", "dns", "tls", "ssh", "ftp", "smtp", "pop3", "imap", "smb"
        }
        for protocol in protocols:
            protocol = protocol.lower()
            if protocol in common_protocols:
                return "https" if protocol == "tls" else protocol

        if dst_port:
            return {
                80: "http", 443: "https", 53: "dns", 22: "ssh", 21: "ftp",
                25: "smtp", 110: "pop3", 143: "imap", 3389: "rdp", 445: "smb",
                139: "netbios", 3306: "mysql", 5432: "postgresql", 6379: "redis",
                27017: "mongodb", 8080: "http", 8443: "https",
            }.get(dst_port)
        return None

    @staticmethod
    def parse_ek_packet(ek_data: Dict[str, Any]) -> Optional[ParsedPacket]:
        """Parse a packet from TShark EK output."""
        return PacketParser.parse_json_packet(ek_data)
