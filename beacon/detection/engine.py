"""Detection engine for identifying security-relevant patterns in network traffic."""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from beacon.core.packet_parser import ParsedPacket
from beacon.models import Confidence, Finding, Severity
from beacon.utils.formatters import redact_text

logger = logging.getLogger(__name__)

# Sensitive keywords for session tokens and credentials
TOKEN_PATTERN = re.compile(
    r"(?i)\b(session[_-]?id|jwt|token|bearer|auth[_-]?token|phpsessid|jsessionid|asp\.net_sessionid)\b"
)
SERVER_BANNER_PATTERN = re.compile(
    r"(?i)\b(apache/[\d.]+|nginx/[\d.]+|iis/[\d.]+|openssh[_-][\d.]+|microsoft-iis/[\d.]+)"
)


class DetectionEngine:
    """Analyze packets for security-relevant patterns based on analysis mode."""

    def __init__(self, mode: str | Any = "blue"):
        if hasattr(mode, "value"):
            self.mode = mode.value.lower()
        else:
            self.mode = str(mode).lower()
        self.findings: List[Finding] = []

        # Tracking state for detections
        self._port_scan_state: Dict[str, Set[int]] = defaultdict(set)
        self._port_scan_packets: Dict[str, List[int]] = defaultdict(list)

        self._host_scan_state: Dict[str, Set[str]] = defaultdict(set)
        self._host_scan_packets: Dict[str, List[int]] = defaultdict(list)

        self._connection_attempts: Dict[Tuple[str, str, int], List[Tuple[datetime, int]]] = defaultdict(list)
        self._syn_packets: Dict[str, List[int]] = defaultdict(list)
        self._syn_ack_packets: Dict[str, List[int]] = defaultdict(list)

        self._beaconing_state: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        self._dns_queries: Dict[str, List[int]] = defaultdict(list)
        self._large_transfers: Dict[str, Tuple[int, List[int], List[str]]] = defaultdict(lambda: (0, [], []))
        self._lateral_movements: Dict[Tuple[str, str, str], List[int]] = defaultdict(list)
        self._cleartext_traffic: Dict[str, List[int]] = defaultdict(list)

    def analyze(self, packets: Iterator[ParsedPacket] | List[ParsedPacket]) -> List[Finding]:
        """Convenience alias for analyze_packets."""
        return self.analyze_packets(packets)

    def analyze_packets(self, packets: Iterator[ParsedPacket]) -> List[Finding]:
        """Run detection logic on a stream of packets."""
        self.findings = []
        packet_list = list(packets)

        if self.mode == "blue":
            self._detect_blue_mode(packet_list)
        elif self.mode == "red":
            self._detect_red_mode(packet_list)
        elif self.mode == "white":
            self._detect_white_mode(packet_list)

        return self.findings

    def _detect_blue_mode(self, packets: List[ParsedPacket]) -> None:
        """Blue Mode: Defensive detections for anomalies and attacks."""
        for packet in packets:
            if not packet.ip_src or not packet.ip_dst:
                continue

            src = packet.ip_src
            dst = packet.ip_dst
            conv_key = packet.get_conversation_key() or f"{src}<->{dst}"

            # Track for port scanning
            if packet.dst_port and packet.transport_proto == "tcp":
                self._port_scan_state[src].add(packet.dst_port)
                self._port_scan_packets[src].append(packet.number)

            # Track for host scanning
            if packet.transport_proto in ("tcp", "udp"):
                self._host_scan_state[src].add(dst)
                self._host_scan_packets[src].append(packet.number)

            # Track connection attempts and SYN flags
            if packet.transport_proto == "tcp" and packet.tcp_flags:
                flags_text = str(packet.tcp_flags_text or "")
                if packet.dst_port and packet.timestamp:
                    self._connection_attempts[(src, dst, packet.dst_port)].append(
                        (packet.timestamp, packet.number)
                    )
                if "SYN" in flags_text and "ACK" not in flags_text:
                    self._syn_packets[src].append(packet.number)
                elif "SYN" in flags_text and "ACK" in flags_text:
                    self._syn_ack_packets[dst].append(packet.number)

            # Track periodic communication for beaconing
            if conv_key and packet.timestamp:
                self._beaconing_state[conv_key].append((packet.timestamp, packet.number))

            # Track DNS queries
            if packet.app_proto == "dns" and packet.dns_query_name:
                self._dns_queries[packet.dns_query_name].append(packet.number)

            # Track volume transfers
            cur_bytes, p_nums, dsts = self._large_transfers[src]
            p_nums.append(packet.number)
            if dst not in dsts and len(dsts) < 5:
                dsts.append(dst)
            self._large_transfers[src] = (cur_bytes + packet.length, p_nums, dsts)

            # Detect cleartext protocols
            if packet.app_proto in ("ftp", "telnet", "http") or packet.dst_port in (21, 23):
                proto_name = packet.app_proto or ("telnet" if packet.dst_port == 23 else "ftp")
                self._cleartext_traffic[f"{src}->{dst}:{proto_name}"].append(packet.number)

            # Detect lateral movement (internal -> internal sensitive ports)
            if packet.is_internal_ip(src) and packet.is_internal_ip(dst):
                if packet.dst_port in (445, 139, 3389, 5985, 5986, 22):
                    service = {445: "SMB", 139: "NetBIOS", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-TLS", 22: "SSH"}.get(packet.dst_port, "RPC")
                    self._lateral_movements[(src, dst, service)].append(packet.number)

        # Evaluate rules
        self._detect_port_scanning()
        self._detect_host_scanning()
        self._detect_syn_scanning()
        self._detect_failed_connections()
        self._detect_beaconing()
        self._detect_dns_anomalies()
        self._detect_large_transfers()
        self._detect_cleartext_protocols_blue()
        self._detect_lateral_movement_blue()

    def _detect_red_mode(self, packets: List[ParsedPacket]) -> None:
        """Red Mode: Information exposure and credential leakage."""
        for packet in packets:
            if packet.app_proto == "http" or packet.dst_port in (80, 8080):
                self._detect_http_credentials(packet)
                self._detect_session_tokens(packet)
                self._detect_version_disclosure(packet)

            if packet.ip_src and packet.is_internal_ip(packet.ip_src):
                self._detect_internal_ip_exposure(packet)

            if packet.app_proto in ("ftp", "smtp", "pop3", "imap", "ssh"):
                self._detect_service_banners(packet)

            if packet.app_proto == "https" or packet.tls_server_name or packet.tls_version:
                self._detect_tls_info(packet)

    def _detect_white_mode(self, packets: List[ParsedPacket]) -> None:
        """White Mode: Neutral operational insights."""
        total_packets = len(packets)
        if total_packets == 0:
            return

        # Check for retransmissions
        retransmissions = [p.number for p in packets if p.tcp_retransmission]
        if retransmissions and len(retransmissions) > (total_packets * 0.05):
            self.findings.append(
                Finding(
                    id="high-retransmission-rate",
                    category="tcp_stats",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    title="Elevated TCP Retransmission Rate",
                    description=f"Observed {len(retransmissions)} TCP retransmissions ({len(retransmissions)/total_packets*100:.1f}% of capture).",
                    evidence=[
                        f"Retransmitted packets: {len(retransmissions)}",
                        f"Percentage of total traffic: {len(retransmissions)/total_packets*100:.1f}%",
                    ],
                    related_packets=retransmissions[:25],
                    detection_rationale="High retransmission rates indicate packet loss, link congestion, or network path instability.",
                    recommendation="Inspect network links and intermediate devices for packet drops or duplex mismatches.",
                    next_step="Filter packets with 'tcp.analysis.retransmission' to isolate the affected conversations.",
                )
            )

    def _detect_port_scanning(self) -> None:
        for src_ip, ports in self._port_scan_state.items():
            if len(ports) >= 10:
                severity = Severity.HIGH if len(ports) >= 50 else Severity.MEDIUM
                confidence = Confidence.HIGH if len(ports) >= 25 else Confidence.MEDIUM
                pkt_list = self._port_scan_packets[src_ip]

                self.findings.append(
                    Finding(
                        id=f"port-scan-{src_ip}",
                        category="port_scanning",
                        severity=severity,
                        confidence=confidence,
                        title=f"Port Scanning Detected from {src_ip}",
                        description=f"Host {src_ip} attempted connections to {len(ports)} different ports, indicating active reconnaissance.",
                        evidence=[
                            f"Total unique target ports: {len(ports)}",
                            f"Target ports sample: {sorted(list(ports))[:15]}",
                            f"Sample packet references: {pkt_list[:10]}",
                        ],
                        source_ip=src_ip,
                        related_packets=pkt_list[:25],
                        detection_rationale="A single host attempting connections across dozens of distinct ports in a short interval is typical of vulnerability scanners or port scanners such as Nmap.",
                        recommendation="Confirm whether this scanning activity is authorized. If unauthorized, isolate the source host.",
                        next_step="Inspect the earliest packets from this source host to identify the scan start time and scanning tool signature.",
                    )
                )

    def _detect_host_scanning(self) -> None:
        for src_ip, targets in self._host_scan_state.items():
            if len(targets) >= 15:
                severity = Severity.HIGH if len(targets) >= 50 else Severity.MEDIUM
                confidence = Confidence.HIGH if len(targets) >= 30 else Confidence.MEDIUM
                pkt_list = self._host_scan_packets[src_ip]

                self.findings.append(
                    Finding(
                        id=f"host-scan-{src_ip}",
                        category="host_scanning",
                        severity=severity,
                        confidence=confidence,
                        title=f"Host Scanning Detected from {src_ip}",
                        description=f"Host {src_ip} contacted {len(targets)} different destination hosts, indicating network mapping.",
                        evidence=[
                            f"Total unique target hosts: {len(targets)}",
                            f"Target hosts sample: {sorted(list(targets))[:10]}",
                            f"Sample packet references: {pkt_list[:10]}",
                        ],
                        source_ip=src_ip,
                        related_packets=pkt_list[:25],
                        detection_rationale="Rapid sequential attempts to establish connections across numerous destination IP addresses indicate horizontal network discovery.",
                        recommendation="Review the source host's authorized role and inspect for malware or unauthorized scanning utilities.",
                        next_step="Examine the destination IP ranges to verify if the scanning targeted internal subnets or external servers.",
                    )
                )

    def _detect_syn_scanning(self) -> None:
        for src_ip, syn_pkts in self._syn_packets.items():
            if len(syn_pkts) >= 15:
                ack_count = len(self._syn_ack_packets.get(src_ip, []))
                syn_count = len(syn_pkts)
                if ack_count == 0 or (syn_count / max(1, ack_count)) > 5:
                    self.findings.append(
                        Finding(
                            id=f"syn-scan-{src_ip}",
                            category="syn_scanning",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            title=f"Possible SYN Stealth Scan from {src_ip}",
                            description=f"Host {src_ip} sent {syn_count} SYN packets with very few acknowledgments ({ack_count} SYN-ACKs), characteristic of half-open SYN scanning.",
                            evidence=[
                                f"SYN packets sent: {syn_count}",
                                f"SYN-ACK packets received: {ack_count}",
                                f"SYN/ACK ratio: {syn_count / max(1, ack_count):.1f}",
                            ],
                            source_ip=src_ip,
                            related_packets=syn_pkts[:25],
                            detection_rationale="Half-open SYN scans avoid completing the three-way handshake, leaving connection attempts in an embryonic state to probe open ports rapidly.",
                            recommendation="Check firewall and IDS logs for alerts from this source IP and block if malicious.",
                            next_step="Verify if target hosts responded with RST packets indicating closed ports.",
                        )
                    )

    def _detect_failed_connections(self) -> None:
        for (src, dst, port), time_packets in self._connection_attempts.items():
            if len(time_packets) >= 5:
                timestamps = [t[0] for t in time_packets]
                pkt_nums = [t[1] for t in time_packets]
                intervals = [
                    (timestamps[i + 1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps) - 1)
                ]
                avg_interval = sum(intervals) / len(intervals) if intervals else 0

                if avg_interval < 5:
                    self.findings.append(
                        Finding(
                            id=f"failed-conn-{src}-{dst}-{port}",
                            category="connection_failures",
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            title=f"Repeated Connection Failures: {src} → {dst}:{port}",
                            description=f"Multiple rapid connection attempts ({len(timestamps)}) from {src} to {dst}:{port}.",
                            evidence=[
                                f"Attempt count: {len(timestamps)}",
                                f"Average retry interval: {avg_interval:.1f}s",
                                f"First attempt: {timestamps[0].isoformat()}",
                                f"Last attempt: {timestamps[-1].isoformat()}",
                            ],
                            source_ip=src,
                            destination_ip=dst,
                            related_packets=pkt_nums[:20],
                            related_conversations=[f"{src}<->{dst}"],
                            detection_rationale="Repeated rapid TCP retries usually indicate that the remote service is closed, unreachable, or filtering incoming requests.",
                            recommendation="Check if destination service is active and if access is permitted by network firewalls.",
                            next_step="Inspect destination responses to see whether ICMP unreachable or TCP RST packets were returned.",
                        )
                    )

    def _detect_beaconing(self) -> None:
        for conv_key, time_packets in self._beaconing_state.items():
            if len(time_packets) < 10:
                continue

            timestamps = [t[0] for t in time_packets]
            pkt_nums = [t[1] for t in time_packets]

            intervals = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            cv = std_dev / avg_interval if avg_interval > 0 else float("inf")

            if cv < 0.35 and 15 <= avg_interval <= 3600:
                severity = Severity.HIGH if avg_interval < 300 else Severity.MEDIUM
                self.findings.append(
                    Finding(
                        id=f"beaconing-{conv_key}",
                        category="periodic_beaconing",
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        title=f"Possible C2 Beaconing Pattern: {conv_key}",
                        description=f"Detected regular periodic communication with average interval of {avg_interval:.1f}s (CV: {cv:.3f}).",
                        evidence=[
                            f"Sample packet count: {len(timestamps)}",
                            f"Average callback interval: {avg_interval:.1f}s",
                            f"Standard deviation: {std_dev:.1f}s",
                            f"Coefficient of variation: {cv:.3f} (low variation indicates timer-driven beacon)",
                            f"Total duration observed: {(timestamps[-1] - timestamps[0]).total_seconds():.0f}s",
                        ],
                        related_packets=pkt_nums[:25],
                        related_conversations=[conv_key],
                        detection_rationale="Command and Control (C2) agents routinely query remote servers at steady intervals to receive commands or report heartbeat status.",
                        recommendation="Identify the process responsible for these network requests on the client host.",
                        next_step="Inspect the DNS query names and payload contents associated with this conversation.",
                    )
                )

    def _detect_dns_anomalies(self) -> None:
        for domain, pkt_nums in self._dns_queries.items():
            count = len(pkt_nums)
            if count >= 30:
                self.findings.append(
                    Finding(
                        id=f"dns-volume-{domain}",
                        category="dns_anomalies",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"High Volume DNS Queries: {domain}",
                        description=f"Observed {count} DNS queries for domain '{domain}', which may indicate DNS tunneling or polling.",
                        evidence=[
                            f"Query count: {count}",
                            f"Target domain: {domain}",
                        ],
                        related_packets=pkt_nums[:20],
                        detection_rationale="Abnormally high query volume for a single domain name is an indicator of DNS tunneling, DGA callbacks, or aggressive cache misses.",
                        recommendation="Inspect domain reputation and query record types (e.g., TXT or NULL records may indicate data tunneling).",
                        next_step="Analyze query subdomains to see if high-entropy encoded strings are being transmitted.",
                    )
                )

        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".cc", ".su"}
        for domain, pkt_nums in self._dns_queries.items():
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                self.findings.append(
                    Finding(
                        id=f"dns-suspicious-tld-{domain}",
                        category="dns_anomalies",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        title=f"DNS Query to Suspicious TLD: {domain}",
                        description=f"DNS lookup to domain '{domain}' with top-level domain frequently abused in malicious campaigns.",
                        evidence=[
                            f"Domain: {domain}",
                            f"Query count: {len(pkt_nums)}",
                        ],
                        related_packets=pkt_nums[:15],
                        detection_rationale="Certain top-level domains provide free or low-cost domain registration and statistically host a disproportionate share of phishing and malware infrastructure.",
                        recommendation="Verify whether this domain is required for business purposes.",
                        next_step="Cross-reference domain with public threat intelligence feeds or URL reputation databases.",
                    )
                )

    def _detect_large_transfers(self) -> None:
        threshold = 50 * 1024 * 1024  # 50 MB threshold
        for ip, (total_bytes, pkt_nums, dsts) in self._large_transfers.items():
            if total_bytes >= threshold:
                severity = Severity.HIGH if total_bytes >= 500 * 1024 * 1024 else Severity.MEDIUM
                self.findings.append(
                    Finding(
                        id=f"large-transfer-{ip}",
                        category="data_exfiltration",
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        title=f"Large Outbound Transfer from {ip}",
                        description=f"Host {ip} transferred {total_bytes / (1024 * 1024):.1f} MB of data.",
                        evidence=[
                            f"Source IP: {ip}",
                            f"Volume sent: {total_bytes:,} bytes ({total_bytes / (1024 * 1024):.1f} MB)",
                            f"Destinations: {', '.join(dsts)}",
                        ],
                        source_ip=ip,
                        related_packets=pkt_nums[:20],
                        detection_rationale="Significant outbound volume may indicate data staging, exfiltration, or legitimate backups.",
                        recommendation="Validate whether this outbound transfer conforms with expected host data usage policies.",
                        next_step="Identify the application protocol and destination port used for this transfer.",
                    )
                )

    def _detect_cleartext_protocols_blue(self) -> None:
        for key, pkt_nums in self._cleartext_traffic.items():
            if len(pkt_nums) >= 3:
                parts = key.split(":")
                endpoints = parts[0]
                proto = parts[1] if len(parts) > 1 else "cleartext"
                src, dst = endpoints.split("->") if "->" in endpoints else (endpoints, "")
                self.findings.append(
                    Finding(
                        id=f"cleartext-proto-{key}",
                        category="cleartext_protocols",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        title=f"Unencrypted Protocol in Use: {proto.upper()} ({endpoints})",
                        description=f"Detected cleartext {proto.upper()} traffic between {endpoints}.",
                        evidence=[
                            f"Protocol: {proto.upper()}",
                            f"Communication: {endpoints}",
                            f"Packet count: {len(pkt_nums)}",
                        ],
                        source_ip=src,
                        destination_ip=dst,
                        protocol=proto,
                        related_packets=pkt_nums[:20],
                        detection_rationale="Unencrypted protocols transmit packet headers and payloads in cleartext, leaving credentials and sensitive data vulnerable to eavesdropping.",
                        recommendation=f"Migrate to encrypted alternatives (e.g. SFTP instead of FTP, HTTPS instead of HTTP, SSH instead of Telnet).",
                        next_step="Inspect the packets for observable credentials or sensitive session information.",
                    )
                )

    def _detect_lateral_movement_blue(self) -> None:
        for (src, dst, service), pkt_nums in self._lateral_movements.items():
            if len(pkt_nums) >= 5:
                self.findings.append(
                    Finding(
                        id=f"lateral-mov-{src}-{dst}-{service}",
                        category="lateral_movement",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        title=f"Internal Administrative Protocol ({service}): {src} → {dst}",
                        description=f"Internal host {src} connected to internal host {dst} using {service}.",
                        evidence=[
                            f"Service: {service}",
                            f"Internal Source: {src}",
                            f"Internal Destination: {dst}",
                            f"Packet count: {len(pkt_nums)}",
                        ],
                        source_ip=src,
                        destination_ip=dst,
                        protocol=service.lower(),
                        related_packets=pkt_nums[:20],
                        related_conversations=[f"{src}<->{dst}"],
                        detection_rationale="Lateral movement often relies on native Windows/Unix management protocols (SMB, RDP, WinRM, SSH) to jump between systems inside a perimeter.",
                        recommendation="Verify if {src} is an authorized management workstation or jump server.",
                        next_step="Review the authentication logs on the destination system around the first observed packet timestamp.",
                    )
                )

    def _detect_http_credentials(self, packet: ParsedPacket) -> None:
        uri = packet.http_uri or ""
        if any(keyword in uri.lower() for keyword in ["password", "passwd", "pwd", "auth", "token", "apikey"]):
            self.findings.append(
                Finding(
                    id=f"http-creds-{packet.number}",
                    category="cleartext_credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="Cleartext Authentication Data in HTTP URI",
                    description=f"HTTP request contains credential parameters directly in the URL path or query string.",
                    evidence=[
                        f"Packet: {packet.number}",
                        f"Method: {packet.http_method}",
                        f"Host: {packet.http_host or packet.ip_dst}",
                        f"URI: {redact_text(uri)}",
                    ],
                    source_ip=packet.ip_src,
                    destination_ip=packet.ip_dst,
                    timestamp=packet.timestamp,
                    protocol="http",
                    related_packets=[packet.number],
                    redacted=True,
                    detection_rationale="Passing credentials or secret tokens in the URI exposes them in network taps, proxy logs, and browser history.",
                    recommendation="Never transmit sensitive credentials over unencrypted HTTP. Use POST bodies over TLS (HTTPS).",
                    next_step="Rotate the exposed credentials immediately and update the application endpoint to enforce HTTPS.",
                )
            )

    def _detect_session_tokens(self, packet: ParsedPacket) -> None:
        layers = packet.raw_data.get("_source", {}).get("layers", {})
        http_data = layers.get("http", {})
        headers_str = str(http_data)

        if TOKEN_PATTERN.search(headers_str) or (packet.http_uri and TOKEN_PATTERN.search(packet.http_uri)):
            self.findings.append(
                Finding(
                    id=f"session-token-{packet.number}",
                    category="session_tokens",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="Observable Session Token in Cleartext HTTP",
                    description=f"Cleartext HTTP request exposes session or authentication cookies/tokens.",
                    evidence=[
                        f"Packet: {packet.number}",
                        f"Method: {packet.http_method or 'GET'}",
                        f"Host: {packet.http_host or packet.ip_dst}",
                        "Token/cookie pattern identified in HTTP headers",
                    ],
                    source_ip=packet.ip_src,
                    destination_ip=packet.ip_dst,
                    timestamp=packet.timestamp,
                    protocol="http",
                    related_packets=[packet.number],
                    redacted=True,
                    detection_rationale="Session tokens transmitted over cleartext channels can be intercepted for session hijacking attacks.",
                    recommendation="Set Secure and HttpOnly flags on all session cookies and enforce HTTPS.",
                    next_step="Invalidate active session tokens and check if authorization cookies are scoped properly.",
                )
            )

    def _detect_internal_ip_exposure(self, packet: ParsedPacket) -> None:
        if packet.ip_dst and not packet.is_internal_ip(packet.ip_dst):
            if packet.app_proto == "http" and packet.http_host:
                self.findings.append(
                    Finding(
                        id=f"internal-ip-{packet.number}",
                        category="infrastructure_leakage",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        title=f"Internal IP Addressing Exposed: {packet.ip_src}",
                        description=f"Internal IP address {packet.ip_src} communicated with external host {packet.ip_dst}.",
                        evidence=[
                            f"Internal IP: {packet.ip_src}",
                            f"External Target: {packet.ip_dst}",
                            f"HTTP Host: {packet.http_host}",
                            f"Packet: {packet.number}",
                        ],
                        source_ip=packet.ip_src,
                        destination_ip=packet.ip_dst,
                        protocol=packet.app_proto,
                        related_packets=[packet.number],
                        detection_rationale="External network requests originating directly from private IP ranges without NAT can reveal internal network topology.",
                        recommendation="Ensure NAT gateways or forward proxies properly isolate internal network addressing.",
                        next_step="Check whether internal server names or hostnames appear in headers or DNS lookups.",
                    )
                )

    def _detect_service_banners(self, packet: ParsedPacket) -> None:
        layers = packet.raw_data.get("_source", {}).get("layers", {})
        raw_text = str(layers)
        match = SERVER_BANNER_PATTERN.search(raw_text)
        if match:
            banner = match.group(0)
            self.findings.append(
                Finding(
                    id=f"banner-disclosure-{packet.number}",
                    category="version_disclosure",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    title=f"Service Version Banner Disclosed: {banner}",
                    description=f"Service disclosed software version banner '{banner}' in cleartext communication.",
                    evidence=[
                        f"Banner: {banner}",
                        f"Packet: {packet.number}",
                        f"Server: {packet.ip_src}",
                    ],
                    source_ip=packet.ip_src,
                    destination_ip=packet.ip_dst,
                    protocol=packet.app_proto or "tcp",
                    related_packets=[packet.number],
                    detection_rationale="Service banners assist attackers in fingerprinting exact versions and identifying unpatched vulnerabilities.",
                    recommendation="Disable verbose banner disclosure in service configuration files (e.g. ServerTokens Prod).",
                    next_step="Check if the disclosed version has known CVEs or publicly available exploits.",
                )
            )

    def _detect_version_disclosure(self, packet: ParsedPacket) -> None:
        user_agent = packet.http_user_agent or ""
        if user_agent and not any(common in user_agent.lower() for common in ["mozilla/5.0", "chrome/", "safari/"]):
            # Distinctive tool User-Agent
            self.findings.append(
                Finding(
                    id=f"user-agent-disclosure-{packet.number}",
                    category="version_disclosure",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    title="Custom or Tool User-Agent Disclosed",
                    description=f"Observed non-standard HTTP User-Agent: {redact_text(user_agent)}",
                    evidence=[
                        f"User-Agent: {redact_text(user_agent)}",
                        f"Packet: {packet.number}",
                        f"Client: {packet.ip_src}",
                    ],
                    source_ip=packet.ip_src,
                    destination_ip=packet.ip_dst,
                    protocol="http",
                    related_packets=[packet.number],
                    redacted=True,
                    detection_rationale="Automated tools, scripts, and embedded devices often disclose distinctive User-Agent strings.",
                    recommendation="Evaluate if this client application is authorized within the network environment.",
                    next_step="Check if the User-Agent corresponds to a security testing tool (e.g., sqlmap, nikto, curl).",
                )
            )

    def _detect_tls_info(self, packet: ParsedPacket) -> None:
        tls_ver = str(packet.tls_version or "").lower()
        if any(dep in tls_ver for dep in ["0x0301", "tls 1.0", "0x0302", "tls 1.1", "0x0300", "sslv3"]):
            self.findings.append(
                Finding(
                    id=f"insecure-tls-{packet.number}",
                    category="version_disclosure",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Insecure or Deprecated TLS Version: {packet.tls_version}",
                    description=f"Host negotiated an obsolete TLS version ({packet.tls_version}) with {packet.tls_server_name or packet.ip_dst}.",
                    evidence=[
                        f"TLS Version: {packet.tls_version}",
                        f"SNI: {packet.tls_server_name or 'N/A'}",
                        f"Packet: {packet.number}",
                    ],
                    source_ip=packet.ip_src,
                    destination_ip=packet.ip_dst,
                    protocol="tls",
                    related_packets=[packet.number],
                    detection_rationale="TLS 1.0 and 1.1 are deprecated by RFC 8996 due to vulnerabilities and lack of support for modern cipher suites.",
                    recommendation="Configure servers and clients to require TLS 1.2 or TLS 1.3.",
                    next_step="Check server configuration to disable legacy TLS protocols.",
                )
            )
