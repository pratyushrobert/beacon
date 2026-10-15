"""Pure-Python standard PCAP exporter for retained incident packets."""

from __future__ import annotations

import ipaddress
import struct
import time
from pathlib import Path
from typing import List, Sequence, Union

from beacon.live.models import RollingPacket


def synthesize_ethernet_frame(packet: RollingPacket) -> bytes:
    """
    Synthesize a minimal valid Ethernet+IP+TCP/UDP frame for packets where raw wire
    hex was not recorded. Ensures Wireshark and TShark can always parse exported PCAPs.
    """
    # 1. Parse IPs
    try:
        src_ip_obj = ipaddress.ip_address(packet.ip_src or "192.168.1.100")
    except ValueError:
        src_ip_obj = ipaddress.ip_address("192.168.1.100")

    try:
        dst_ip_obj = ipaddress.ip_address(packet.ip_dst or "192.168.1.1")
    except ValueError:
        dst_ip_obj = ipaddress.ip_address("192.168.1.1")

    # Ethernet Header (14 bytes): Dst MAC (6), Src MAC (6), EtherType (2)
    eth_dst = bytes.fromhex("001122334455")
    eth_src = bytes.fromhex("aabbccddeeff")
    eth_type = 0x0800  # IPv4 default

    proto_num = 6 if packet.transport_proto.lower() == "tcp" else 17 if packet.transport_proto.lower() == "udp" else 1
    sport = packet.src_port or 1024
    dport = packet.dst_port or 80

    # Payload
    payload = b""
    if packet.dns_query_name:
        # Minimal DNS query payload
        payload = packet.dns_query_name.encode("utf-8", errors="ignore")
    elif packet.http_uri:
        payload = f"{packet.http_method or 'GET'} {packet.http_uri} HTTP/1.1\r\n\r\n".encode("utf-8")

    # Transport Header
    if proto_num == 6:
        # TCP Header (20 bytes): sport, dport, seq=1, ack=1, offset=5<<4, flags=0x18(ACK,PSH), win=65535, sum=0, urg=0
        trans_hdr = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0)
    elif proto_num == 17:
        # UDP Header (8 bytes): sport, dport, len, sum=0
        trans_hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    else:
        # ICMP echo
        trans_hdr = struct.pack("!BBHHH", 8, 0, 0, 1, 1)

    trans_and_data = trans_hdr + payload

    # IPv4 Header (20 bytes): ver_ihl=0x45, dscp=0, total_len, id=1, flags_frag=0x4000, ttl=64, proto, sum=0, src, dst
    if src_ip_obj.version == 4 and dst_ip_obj.version == 4:
        total_ip_len = 20 + len(trans_and_data)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total_ip_len,
            1,
            0x4000,
            64,
            proto_num,
            0,
            src_ip_obj.packed,
            dst_ip_obj.packed,
        )
        return eth_dst + eth_src + struct.pack("!H", eth_type) + ip_hdr + trans_and_data
    else:
        # IPv6 fallback
        eth_type = 0x86DD
        ip6_hdr = struct.pack(
            "!IHBB16s16s",
            0x60000000,
            len(trans_and_data),
            proto_num,
            64,
            src_ip_obj.packed if src_ip_obj.version == 6 else (b"\x00" * 12 + src_ip_obj.packed),
            dst_ip_obj.packed if dst_ip_obj.version == 6 else (b"\x00" * 12 + dst_ip_obj.packed),
        )
        return eth_dst + eth_src + struct.pack("!H", eth_type) + ip6_hdr + trans_and_data


def write_pcap_file(
    packets: Sequence[Union[RollingPacket, bytes, tuple[float, bytes]]],
    output_path: Union[str, Path],
) -> int:
    """
    Write a list of RollingPacket objects or raw byte frames to a valid standard PCAP file.
    Returns the number of packets written.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    written_count = 0
    with open(out_file, "wb") as f:
        # PCAP Global Header (24 bytes):
        # magic: 0xa1b2c3d4 (little-endian microsecond)
        # version: 2.4
        # thiszone: 0, sigfigs: 0
        # snaplen: 65535
        # network: 1 (LINKTYPE_ETHERNET)
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        for item in packets:
            if isinstance(item, RollingPacket):
                ts = item.timestamp
                if item.raw_hex:
                    try:
                        raw_data = bytes.fromhex(item.raw_hex)
                    except ValueError:
                        raw_data = synthesize_ethernet_frame(item)
                else:
                    raw_data = synthesize_ethernet_frame(item)
            elif isinstance(item, tuple):
                ts, raw_data = item
            elif isinstance(item, bytes):
                ts = time.time()
                raw_data = item
            else:
                continue

            sec = int(ts)
            usec = int(max(0.0, (ts - sec)) * 1_000_000)
            length = len(raw_data)

            # PCAP Packet Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
            f.write(struct.pack("<IIII", sec, usec, length, length))
            f.write(raw_data)
            written_count += 1

    return written_count


write_pcap = write_pcap_file

