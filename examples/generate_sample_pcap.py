"""Utility to generate a genuine, valid .pcap capture file for testing Beacon and TShark."""

import struct
import time
from pathlib import Path


def create_sample_pcap(filepath: str | Path) -> None:
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    # PCAP Global Header
    # magic: 0xa1b2c3d4 (little-endian microsecond pcap)
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # magic number
        2,           # version major
        4,           # version minor
        0,           # thiszone
        0,           # sigfigs
        65535,       # snaplen
        1,           # network (LinkType Ethernet = 1)
    )

    packets_data = []
    base_time = int(time.time()) - 3600

    def make_eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, flags, payload=b""):
        # Ethernet header (14 bytes): Dst MAC, Src MAC, EtherType (0x0800 for IPv4)
        eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
        
        # IP header (20 bytes)
        # Version 4, IHL 5 -> 0x45, DSCP/ECN 0, Total len, ID, Flags/Frag, TTL 64, Proto 6 (TCP), Chksum, Src IP, Dst IP
        ip_total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            1234,
            0x4000,
            64,
            6,  # TCP
            0,  # checksum placeholder
            bytes(map(int, src_ip.split("."))),
            bytes(map(int, dst_ip.split("."))),
        )

        # TCP header (20 bytes)
        # Src port, Dst port, Seq, Ack, Data offset (5<<4), Flags, Window 65535, Chksum 0, Urg 0
        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            1000,
            0,
            0x50,
            flags,
            65535,
            0,
            0,
        )

        return eth + ip_hdr + tcp_hdr + payload

    def make_eth_ip_udp_dns(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, qname):
        eth = dst_mac + src_mac + struct.pack("!H", 0x0800)

        # Encode DNS query
        dns_body = bytearray()
        # Header: ID 0x1234, Flags 0x0100 (standard query), QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 0
        dns_body.extend(struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0))
        # QNAME: labels
        for part in qname.split("."):
            dns_body.append(len(part))
            dns_body.extend(part.encode("ascii"))
        dns_body.append(0)  # root label
        # QTYPE 1 (A), QCLASS 1 (IN)
        dns_body.extend(struct.pack("!HH", 1, 1))

        udp_len = 8 + len(dns_body)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

        ip_total_len = 20 + udp_len
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            5678,
            0x4000,
            64,
            17,  # UDP
            0,
            bytes(map(int, src_ip.split("."))),
            bytes(map(int, dst_ip.split("."))),
        )

        return eth + ip_hdr + udp_hdr + bytes(dns_body)

    mac_a = b"\x00\x0c\x29\x1a\x2b\x3c"
    mac_b = b"\x00\x50\x56\xc0\x00\x08"

    # Packet 1: DNS Query for evil-c2-beacon.com
    pkt1 = make_eth_ip_udp_dns(mac_a, mac_b, "192.168.1.100", "8.8.8.8", 53210, 53, "evil-c2-beacon.com")
    packets_data.append((base_time, 0, pkt1))

    # Packet 2: HTTP GET with cleartext credential
    http_payload = b"GET /login.php?user=admin&token=secret_session_token_xyz123 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\n\r\n"
    pkt2 = make_eth_ip_tcp(mac_a, mac_b, "192.168.1.100", "93.184.216.34", 49152, 80, 0x18, http_payload)
    packets_data.append((base_time + 1, 100000, pkt2))

    # Packets 3-15: SYN Port scan across ports 21-35
    for i in range(15):
        port = 20 + i
        pkt = make_eth_ip_tcp(mac_a, mac_b, "192.168.1.100", "192.168.1.1", 50000 + i, port, 0x02)  # SYN
        packets_data.append((base_time + 2, 200000 + i * 5000, pkt))

    with open(path, "wb") as f:
        f.write(global_header)
        for ts_sec, ts_usec, pkt_bytes in packets_data:
            pkt_len = len(pkt_bytes)
            # Packet header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
            hdr = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
            f.write(hdr)
            f.write(pkt_bytes)

    print(f"Generated {len(packets_data)} valid packets into {path}")


if __name__ == "__main__":
    create_sample_pcap("examples/sample.pcap")
