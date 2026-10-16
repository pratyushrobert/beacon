"""Native pure-Python PCAP and PCAPNG reader.

Provides zero-dependency packet decoding for offline captures when TShark is
not installed on the host operating system. Extracts frames, IP/IPv6 headers,
TCP/UDP metadata, DNS queries, HTTP requests, and TLS SNI extensions.
"""

from __future__ import annotations

import io
import logging
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Magic constants for PCAP / PCAPNG
PCAP_MAGIC_MICRO_SAME = 0xA1B2C3D4
PCAP_MAGIC_MICRO_SWAP = 0xD4C3B2A1
PCAP_MAGIC_NANO_SAME = 0xA1B23C4D
PCAP_MAGIC_NANO_SWAP = 0x4D3CB2A1

PCAPNG_BLOCK_SHB = 0x0A0D0D0A
PCAPNG_BLOCK_IDB = 0x00000001
PCAPNG_BLOCK_EPB = 0x00000006
PCAPNG_BLOCK_SPB = 0x00000003
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D


def _format_mac(raw_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_bytes)


def _parse_dns_name(payload: bytes, offset: int) -> Tuple[str, int]:
    """Parse a DNS domain name supporting RFC 1035 label compression."""
    labels = []
    jumped = False
    original_offset = offset
    visited_offsets = set()

    while offset < len(payload):
        if offset in visited_offsets:
            break
        visited_offsets.add(offset)

        length = payload[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
        else:
            offset += 1
            if offset + length > len(payload):
                break
            label = payload[offset : offset + length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length

    domain = ".".join(labels)
    final_offset = original_offset if jumped else offset
    return domain, final_offset


def _parse_tls_sni(payload: bytes) -> Optional[str]:
    """Extract Server Name Indication (SNI) from TLS ClientHello."""
    try:
        # Check TLS Record: Content Type 22 (Handshake), Version 0x0301-0x0303
        if len(payload) < 45 or payload[0] != 0x16:
            return None

        # Handshake Type: 1 (ClientHello)
        handshake_type = payload[5]
        if handshake_type != 1:
            return None

        # Skip handshake header (4 bytes) + client version (2 bytes) + random (32 bytes)
        curr = 5 + 4 + 2 + 32
        if curr >= len(payload):
            return None

        # Session ID length
        session_id_len = payload[curr]
        curr += 1 + session_id_len
        if curr + 2 >= len(payload):
            return None

        # Cipher suites length
        cipher_len = struct.unpack("!H", payload[curr : curr + 2])[0]
        curr += 2 + cipher_len
        if curr + 1 >= len(payload):
            return None

        # Compression methods length
        comp_len = payload[curr]
        curr += 1 + comp_len
        if curr + 2 >= len(payload):
            return None

        # Extensions length
        extensions_len = struct.unpack("!H", payload[curr : curr + 2])[0]
        curr += 2
        ext_end = curr + extensions_len

        while curr + 4 <= ext_end and curr + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[curr : curr + 2])[0]
            ext_len = struct.unpack("!H", payload[curr + 2 : curr + 4])[0]
            curr += 4

            if ext_type == 0:  # server_name extension
                if curr + 5 <= len(payload):
                    # server_name_list_length (2B) + name_type (1B, 0=host_name) + name_length (2B)
                    name_len = struct.unpack("!H", payload[curr + 3 : curr + 5])[0]
                    server_name = payload[curr + 5 : curr + 5 + name_len].decode("ascii", errors="replace")
                    return server_name.strip()

            curr += ext_len
    except Exception:
        pass
    return None


class NativePacketDecoder:
    """Decodes raw packet link-layer bytes into normalized dictionary data."""

    @staticmethod
    def decode_packet(packet_num: int, ts_epoch: float, raw_data: bytes) -> Optional[Dict[str, Any]]:
        if len(raw_data) < 14:
            return None

        dt = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
        iso_ts = dt.isoformat()

        eth_dst = _format_mac(raw_data[0:6])
        eth_src = _format_mac(raw_data[6:12])
        eth_type = struct.unpack("!H", raw_data[12:14])[0]

        offset = 14
        # 802.1Q VLAN handling
        if eth_type == 0x8100 and len(raw_data) >= 18:
            eth_type = struct.unpack("!H", raw_data[16:18])[0]
            offset = 18

        protocols = ["eth"]
        ip_src = None
        ip_dst = None
        ip_version = None
        ip_proto = None
        transport_proto = None
        src_port = None
        dst_port = None
        app_proto = None
        tcp_flags = None
        tcp_flags_text = None
        tcp_seq = None
        tcp_ack = None
        dns_query_name = None
        dns_query_type = None
        dns_id = None
        http_method = None
        http_host = None
        http_uri = None
        http_response_code = None
        tls_server_name = None

        payload = b""

        # IPv4
        if eth_type == 0x0800 and len(raw_data) >= offset + 20:
            protocols.append("ip")
            ip_version = 4
            ihl = (raw_data[offset] & 0x0F) * 4
            ip_proto = raw_data[offset + 9]
            ip_src = socket.inet_ntoa(raw_data[offset + 12 : offset + 16])
            ip_dst = socket.inet_ntoa(raw_data[offset + 16 : offset + 20])
            payload = raw_data[offset + ihl :]

        # IPv6
        elif eth_type == 0x86DD and len(raw_data) >= offset + 40:
            protocols.append("ipv6")
            ip_version = 6
            ip_proto = raw_data[offset + 6]
            try:
                ip_src = socket.inet_ntop(socket.AF_INET6, raw_data[offset + 8 : offset + 24])
                ip_dst = socket.inet_ntop(socket.AF_INET6, raw_data[offset + 24 : offset + 40])
            except Exception:
                pass
            payload = raw_data[offset + 40 :]

        # Parse Transport Layer
        if ip_proto == 6 and len(payload) >= 20:  # TCP
            protocols.append("tcp")
            transport_proto = "tcp"
            src_port = struct.unpack("!H", payload[0:2])[0]
            dst_port = struct.unpack("!H", payload[2:4])[0]
            tcp_seq = str(struct.unpack("!I", payload[4:8])[0])
            tcp_ack = str(struct.unpack("!I", payload[8:12])[0])

            data_offset = (payload[12] >> 4) * 4
            flags = payload[13]
            flag_names = []
            if flags & 0x02: flag_names.append("SYN")
            if flags & 0x10: flag_names.append("ACK")
            if flags & 0x01: flag_names.append("FIN")
            if flags & 0x04: flag_names.append("RST")
            if flags & 0x08: flag_names.append("PSH")
            if flags & 0x20: flag_names.append("URG")

            tcp_flags = f"0x{flags:04x}"
            tcp_flags_text = ",".join(flag_names)

            app_payload = payload[data_offset:]

            # TLS SNI inspection
            if src_port == 443 or dst_port == 443 or (app_payload and app_payload.startswith(b"\x16\x03")):
                tls_sni = _parse_tls_sni(app_payload)
                if tls_sni:
                    tls_server_name = tls_sni
                    app_proto = "tls"
                    protocols.append("tls")

            # HTTP inspection
            if not app_proto and app_payload:
                for verb in [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS "]:
                    if app_payload.startswith(verb):
                        app_proto = "http"
                        protocols.append("http")
                        parts = app_payload.split(b"\r\n", 1)
                        if parts:
                            req_line = parts[0].decode("latin1", errors="replace").split()
                            if len(req_line) >= 2:
                                http_method = req_line[0]
                                http_uri = req_line[1]
                        for line in app_payload.split(b"\r\n"):
                            if line.lower().startswith(b"host:"):
                                http_host = line[5:].decode("latin1", errors="replace").strip()
                                break
                        break

                if not app_proto and app_payload.startswith(b"HTTP/1."):
                    app_proto = "http"
                    protocols.append("http")
                    parts = app_payload.split(b"\r\n", 1)[0].decode("latin1", errors="replace").split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        http_response_code = parts[1]

            # Standard Port Identification
            if not app_proto:
                ports = {src_port, dst_port}
                if 22 in ports: app_proto = "ssh"; protocols.append("ssh")
                elif 21 in ports: app_proto = "ftp"; protocols.append("ftp")
                elif 25 in ports or 587 in ports: app_proto = "smtp"; protocols.append("smtp")
                elif 80 in ports or 8080 in ports: app_proto = "http"; protocols.append("http")
                elif 443 in ports or 8443 in ports: app_proto = "tls"; protocols.append("tls")

        elif ip_proto == 17 and len(payload) >= 8:  # UDP
            protocols.append("udp")
            transport_proto = "udp"
            src_port = struct.unpack("!H", payload[0:2])[0]
            dst_port = struct.unpack("!H", payload[2:4])[0]
            app_payload = payload[8:]

            # DNS inspection (Port 53, 5353, 5355)
            if (src_port in (53, 5353, 5355) or dst_port in (53, 5353, 5355)) and len(app_payload) >= 12:
                app_proto = "dns"
                protocols.append("dns")
                tx_id = struct.unpack("!H", app_payload[0:2])[0]
                dns_id = str(tx_id)
                qdcount = struct.unpack("!H", app_payload[4:6])[0]
                if qdcount > 0:
                    try:
                        qname, qtype_offset = _parse_dns_name(app_payload, 12)
                        dns_query_name = qname
                        if qtype_offset + 2 <= len(app_payload):
                            qtype = struct.unpack("!H", app_payload[qtype_offset : qtype_offset + 2])[0]
                            type_map = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT"}
                            dns_query_type = type_map.get(qtype, str(qtype))
                    except Exception:
                        pass
            elif src_port in (67, 68) or dst_port in (67, 68):
                app_proto = "dhcp"; protocols.append("dhcp")
            elif src_port == 123 or dst_port == 123:
                app_proto = "ntp"; protocols.append("ntp")

        elif ip_proto == 1:  # ICMP
            protocols.append("icmp")
            transport_proto = "icmp"
        elif ip_proto == 58:  # ICMPv6
            protocols.append("icmpv6")
            transport_proto = "icmpv6"

        layers: Dict[str, Any] = {
            "frame": {
                "frame_frame_number": str(packet_num),
                "frame_frame_time_epoch": f"{ts_epoch:.6f}",
                "frame_frame_time": iso_ts,
                "frame_frame_len": str(len(raw_data)),
                "frame_frame_protocols": ":".join(protocols),
            },
            "eth": {
                "eth_eth_src": eth_src,
                "eth_eth_dst": eth_dst,
            },
        }

        if ip_version == 4:
            layers["ip"] = {
                "ip_ip_src": ip_src,
                "ip_ip_dst": ip_dst,
                "ip_ip_proto": str(ip_proto),
                "ip_ip_version": "4",
            }
        elif ip_version == 6:
            layers["ipv6"] = {
                "ipv6_ipv6_src": ip_src,
                "ipv6_ipv6_dst": ip_dst,
                "ipv6_ipv6_version": "6",
            }

        if transport_proto == "tcp":
            tcp_dict: Dict[str, Any] = {
                "tcp_tcp_srcport": str(src_port),
                "tcp_tcp_dstport": str(dst_port),
                "tcp_tcp_flags": tcp_flags,
                "tcp_tcp_flags_tree": {"tcp_flags_text": tcp_flags_text},
            }
            if tcp_seq: tcp_dict["tcp_tcp_seq"] = tcp_seq
            if tcp_ack: tcp_dict["tcp_tcp_ack"] = tcp_ack
            layers["tcp"] = tcp_dict

        elif transport_proto == "udp":
            layers["udp"] = {
                "udp_udp_srcport": str(src_port),
                "udp_udp_dstport": str(dst_port),
            }

        if dns_query_name:
            layers["dns"] = {
                "dns_dns_id": dns_id or "0",
                "dns_dns_qry_name": dns_query_name,
                "dns_dns_qry_type": dns_query_type or "1",
            }

        if http_method or http_response_code:
            layers["http"] = {}
            if http_method: layers["http"]["http_http_request_method"] = http_method
            if http_uri: layers["http"]["http_http_request_uri"] = http_uri
            if http_host: layers["http"]["http_http_host"] = http_host
            if http_response_code: layers["http"]["http_http_response_code"] = http_response_code

        if tls_server_name:
            layers["tls"] = {
                "tls_tls_handshake_extensions_server_name": tls_server_name,
            }

        return {
            "timestamp": f"{int(ts_epoch * 1000)}",
            "layers": layers,
        }


def read_native_pcap(stream: io.BufferedIOBase, packet_limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """Stream packets from classic PCAP file format."""
    header = stream.read(24)
    if len(header) < 24:
        return

    magic = struct.unpack("<I", header[0:4])[0]
    if magic in (PCAP_MAGIC_MICRO_SAME, PCAP_MAGIC_NANO_SAME):
        endian = "<"
        is_nano = magic == PCAP_MAGIC_NANO_SAME
    elif magic in (PCAP_MAGIC_MICRO_SWAP, PCAP_MAGIC_NANO_SWAP):
        endian = ">"
        is_nano = magic == PCAP_MAGIC_NANO_SWAP
    else:
        raise ValueError(f"Invalid PCAP file magic header: 0x{magic:08x}")

    packet_num = 0
    while True:
        if packet_limit and packet_num >= packet_limit:
            break

        hdr = stream.read(16)
        if len(hdr) < 16:
            break

        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
        raw_data = stream.read(incl_len)
        if len(raw_data) < incl_len:
            break

        packet_num += 1
        ts_epoch = ts_sec + (ts_sub / 1_000_000_000.0 if is_nano else ts_sub / 1_000_000.0)

        packet_dict = NativePacketDecoder.decode_packet(packet_num, ts_epoch, raw_data)
        if packet_dict:
            yield packet_dict


def read_native_pcapng(stream: io.BufferedIOBase, packet_limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """Stream packets from PCAPNG Next-Generation capture format."""
    packet_num = 0
    endian = "<"

    while True:
        if packet_limit and packet_num >= packet_limit:
            break

        hdr = stream.read(8)
        if len(hdr) < 8:
            break

        block_type, block_len = struct.unpack(f"{endian}II", hdr)

        # Handle Section Header Block endianness check
        if block_type == PCAPNG_BLOCK_SHB:
            body = stream.read(block_len - 8)
            if len(body) >= 4:
                bom = struct.unpack("<I", body[0:4])[0]
                endian = "<" if bom == PCAPNG_BYTE_ORDER_MAGIC else ">"
            continue

        if block_len < 12:
            break

        body_len = block_len - 12
        body = stream.read(body_len)
        trailer = stream.read(4)  # Duplicate block_len

        # Enhanced Packet Block
        if block_type == PCAPNG_BLOCK_EPB and len(body) >= 20:
            interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{endian}IIIII", body[0:20])
            raw_data = body[20 : 20 + cap_len]
            packet_num += 1

            # Microsecond timestamp calculation (standard default)
            ts_ticks = (ts_high << 32) | ts_low
            ts_epoch = ts_ticks / 1_000_000.0

            packet_dict = NativePacketDecoder.decode_packet(packet_num, ts_epoch, raw_data)
            if packet_dict:
                yield packet_dict

        # Simple Packet Block
        elif block_type == PCAPNG_BLOCK_SPB and len(body) >= 4:
            orig_len = struct.unpack(f"{endian}I", body[0:4])[0]
            raw_data = body[4 : 4 + orig_len]
            packet_num += 1
            ts_epoch = datetime.now(timezone.utc).timestamp()

            packet_dict = NativePacketDecoder.decode_packet(packet_num, ts_epoch, raw_data)
            if packet_dict:
                yield packet_dict


def read_native_packets(pcap_path: Path, packet_limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """Read PCAP or PCAPNG file using built-in native streaming decoder."""
    p = Path(pcap_path)
    if not p.is_file():
        raise FileNotFoundError(f"Capture file not found: {pcap_path}")

    with open(p, "rb") as f:
        magic = f.read(4)
        f.seek(0)

        # Check if PCAPNG
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from read_native_pcapng(f, packet_limit=packet_limit)
        else:
            yield from read_native_pcap(f, packet_limit=packet_limit)


def get_native_packet_count(pcap_path: Path) -> int:
    """Fast counting of packets in PCAP/PCAPNG file without full parsing."""
    count = 0
    for _ in read_native_packets(pcap_path):
        count += 1
    return count


def get_native_capture_info(pcap_path: Path) -> Dict[str, Any]:
    """Retrieve capture file statistics using native reader."""
    p = Path(pcap_path)
    if not p.is_file():
        raise FileNotFoundError(f"Capture file not found: {pcap_path}")

    file_size = p.stat().st_size
    first_ts = None
    last_ts = None
    count = 0

    for pkt in read_native_packets(pcap_path):
        count += 1
        epoch = float(pkt["layers"]["frame"]["frame_frame_time_epoch"])
        if first_ts is None or epoch < first_ts:
            first_ts = epoch
        if last_ts is None or epoch > last_ts:
            last_ts = epoch

    duration = (last_ts - first_ts) if (first_ts and last_ts) else 0.0

    return {
        "File name": p.name,
        "File type": "pcapng" if p.suffix.lower() == ".pcapng" else "pcap",
        "File size": f"{file_size} bytes",
        "Number of packets": str(count),
        "Capture duration": f"{duration:.3f} seconds",
        "Data rate": f"{(file_size / duration):.1f} B/s" if duration > 0 else "0 B/s",
    }
