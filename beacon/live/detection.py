"""Streaming detection engine for real-time traffic analysis and incident triggering."""

from __future__ import annotations

import collections
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from beacon.live.models import RollingPacket
from beacon.models import Confidence, Finding, Severity

logger = logging.getLogger(__name__)

# Sensitive pattern regexes
CLEARTEXT_AUTH_PATTERN = re.compile(
    r"(?i)(authorization:\s*basic\s+[a-zA-Z0-9+/=]+|password=|passwd=|pwd=|api[_-]?key=)",
)
TOKEN_PATTERN = re.compile(
    r"(?i)\b(session[_-]?id|bearer\s+[a-zA-Z0-9_\-\.]+|phpsessid|jsessionid)\b",
)


class StreamingDetectionEngine:
    """
    Evaluates detection rules incrementally on every arriving packet.
    Maintains strictly bounded correlation state and prunes stale records.
    """

    def __init__(self, mode: str = "white"):
        self.mode = mode.lower()

        # Bounded sliding window tracking state
        # src_ip -> deque of (timestamp, dst_port)
        self._port_scan_tracker: Dict[str, collections.deque[Tuple[float, int]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=100)
        )
        # src_ip -> deque of (timestamp, dst_ip)
        self._host_sweep_tracker: Dict[str, collections.deque[Tuple[float, str]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=100)
        )
        # (src_ip, dst_ip) -> deque of (timestamp, length)
        self._outbound_transfer_tracker: Dict[Tuple[str, str], collections.deque[Tuple[float, int]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=200)
        )
        # (src_ip, dst_ip) -> deque of timestamps
        self._beacon_intervals: Dict[Tuple[str, str], collections.deque[float]] = collections.defaultdict(
            lambda: collections.deque(maxlen=20)
        )

        # Triggered alert cooldowns: (rule_name, entity) -> timestamp
        self._rule_cooldowns: Dict[Tuple[str, str], float] = {}

        self._last_prune_time = time.time()
        self.findings: List[Finding] = []
        self.findings_count = 0
        self.findings_by_severity: Dict[str, int] = collections.defaultdict(int)

    def reset(self) -> None:
        """Reset internal sliding windows, tracking state, and findings."""
        self._port_scan_tracker.clear()
        self._host_sweep_tracker.clear()
        self._outbound_transfer_tracker.clear()
        self._beacon_intervals.clear()
        self._rule_cooldowns.clear()
        self.findings.clear()
        self.findings_count = 0
        self.findings_by_severity.clear()

    def process_packet(self, packet: RollingPacket) -> List[Finding]:
        """
        Evaluate all streaming detection rules against an arriving packet.
        Returns a list of newly triggered Finding objects.
        """
        if not packet.ip_src or not packet.ip_dst:
            return []

        now = packet.timestamp or time.time()
        findings: List[Finding] = []

        # Periodically prune stale sliding window state (every 30 seconds)
        if now - self._last_prune_time > 30.0:
            self._prune_state(now)
            self._last_prune_time = now

        proto = (packet.transport_proto or "").lower()
        direction = (packet.direction or "outbound").lower()

        # Rule 1: Port Scanning Detection (SYN or TCP connection bursts across ports)
        if proto == "tcp" and packet.dst_port:
            port_finding = self._check_port_scan(packet, now)
            if port_finding:
                findings.append(port_finding)

        # Rule 2: Host Sweep / Horizontal Reconnaissance
        if direction in ("lateral", "outbound") and proto in ("tcp", "udp", "icmp"):
            sweep_finding = self._check_host_sweep(packet, now)
            if sweep_finding:
                findings.append(sweep_finding)

        # Rule 3: Cleartext Credentials & Sensitive Information Exposure
        auth_finding = self._check_cleartext_credentials(packet, now)
        if auth_finding:
            findings.append(auth_finding)

        # Rule 4: High-Volume Outbound Transfer / Surge
        if direction == "outbound" and packet.length > 0:
            vol_finding = self._check_volume_surge(packet, now)
            if vol_finding:
                findings.append(vol_finding)

        # Rule 5: Suspicious Periodic Beaconing
        if direction == "outbound" and packet.dst_port in (80, 443, 8080, 8443):
            beacon_finding = self._check_beaconing(packet, now)
            if beacon_finding:
                findings.append(beacon_finding)


        # Rule 6: DNS Tunneling / High Entropy Query
        if packet.dns_query_name:
            dns_finding = self._check_dns_anomaly(packet, now)
            if dns_finding:
                findings.append(dns_finding)

        for f in findings:
            self.findings.append(f)
            if len(self.findings) > 500:
                self.findings.pop(0)
            self.findings_count += 1
            self.findings_by_severity[f.severity.value] += 1

        return findings

    def _check_port_scan(self, packet: RollingPacket, now: float) -> Optional[Finding]:
        src = packet.ip_src
        port = packet.dst_port
        if not port:
            return None

        tracker = self._port_scan_tracker[src]
        tracker.append((now, port))

        # Check unique ports contacted in last 20 seconds
        cutoff = now - 20.0
        recent_ports = {p for ts, p in tracker if ts >= cutoff}

        if len(recent_ports) >= 8:
            cooldown_key = ("port_scan", src)
            if now - self._rule_cooldowns.get(cooldown_key, 0.0) < 30.0:
                return None

            self._rule_cooldowns[cooldown_key] = now
            return Finding(
                id=f"live-portscan-{src}-{int(now)}",
                category="reconnaissance",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"Horizontal/Vertical Port Scan from {src}",
                description=f"Host {src} contacted {len(recent_ports)} unique destination ports within a 20-second rolling window.",
                source_ip=src,
                destination_ip=packet.ip_dst,
                timestamp=datetime.fromtimestamp(now, tz=timezone.utc),
                protocol=packet.transport_proto,
                related_packets=[packet.number],
                related_conversations=[packet.conversation_key],
                detection_rationale=f"Observed rapid connection attempts to ports: {sorted(list(recent_ports))[:10]}...",
                recommendation=f"Inspect host {src} for reconnaissance tooling, worm infection, or automated probing.",
            )
        return None

    def _check_host_sweep(self, packet: RollingPacket, now: float) -> Optional[Finding]:
        src = packet.ip_src
        dst = packet.ip_dst

        tracker = self._host_sweep_tracker[src]
        tracker.append((now, dst))

        cutoff = now - 20.0
        recent_hosts = {h for ts, h in tracker if ts >= cutoff}

        if len(recent_hosts) >= 8:
            cooldown_key = ("host_sweep", src)
            if now - self._rule_cooldowns.get(cooldown_key, 0.0) < 30.0:
                return None

            self._rule_cooldowns[cooldown_key] = now
            return Finding(
                id=f"live-sweep-{src}-{int(now)}",
                category="reconnaissance",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"Network Sweep / Subnet Probe from {src}",
                description=f"Host {src} initiated connections to {len(recent_hosts)} unique IP endpoints within 20 seconds.",
                source_ip=src,
                destination_ip=dst,
                timestamp=datetime.fromtimestamp(now, tz=timezone.utc),
                protocol=packet.transport_proto,
                related_packets=[packet.number],
                related_conversations=[packet.conversation_key],
                detection_rationale=f"Target hosts: {sorted(list(recent_hosts))[:6]}...",
                recommendation="Isolate endpoint and verify whether unauthorized subnet scanning is underway.",
            )
        return None

    def _check_cleartext_credentials(self, packet: RollingPacket, now: float) -> Optional[Finding]:
        # Check URIs or application metadata
        target_text = ""
        if packet.http_uri:
            target_text += packet.http_uri + " "

        # Check raw hex decoded as ASCII if available
        if packet.raw_hex:
            try:
                raw_bytes = bytes.fromhex(packet.raw_hex[:500])
                target_text += raw_bytes.decode("ascii", errors="ignore")
            except Exception:
                pass

        if not target_text:
            return None

        match = CLEARTEXT_AUTH_PATTERN.search(target_text)
        if match:
            cooldown_key = ("cleartext_cred", packet.ip_src)
            if now - self._rule_cooldowns.get(cooldown_key, 0.0) < 30.0:
                return None

            self._rule_cooldowns[cooldown_key] = now
            matched_sample = match.group(0)[:40]
            return Finding(
                id=f"live-cleartext-{packet.ip_src}-{int(now)}",
                category="credential_exposure",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"Cleartext Authentication / Credential Exposure from {packet.ip_src}",
                description=f"Unencrypted credential or authorization token pattern '{matched_sample}' detected in network stream.",
                source_ip=packet.ip_src,
                destination_ip=packet.ip_dst,
                timestamp=datetime.fromtimestamp(now, tz=timezone.utc),
                protocol=packet.app_proto or packet.transport_proto,
                related_packets=[packet.number],
                related_conversations=[packet.conversation_key],
                detection_rationale="Insecure authentication handshake transmitted without TLS/SSL encryption.",
                recommendation="Upgrade legacy administrative interfaces to HTTPS/SSH or enforce transport encryption.",
            )
        return None

    def _check_volume_surge(self, packet: RollingPacket, now: float) -> Optional[Finding]:
        key = (packet.ip_src, packet.ip_dst)
        tracker = self._outbound_transfer_tracker[key]
        tracker.append((now, packet.length))

        cutoff = now - 10.0
        total_recent_bytes = sum(b for ts, b in tracker if ts >= cutoff)

        # Alert if > 1.5 MB in 10 seconds to an external host
        if total_recent_bytes >= 1_500_000:
            cooldown_key = ("volume_surge", f"{packet.ip_src}->{packet.ip_dst}")
            if now - self._rule_cooldowns.get(cooldown_key, 0.0) < 60.0:
                return None

            self._rule_cooldowns[cooldown_key] = now
            mb = total_recent_bytes / (1024 * 1024)
            return Finding(
                id=f"live-surge-{packet.ip_src}-{int(now)}",
                category="data_exfiltration",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title=f"Rapid High-Volume Outbound Transfer: {mb:.1f} MB from {packet.ip_src}",
                description=f"Host {packet.ip_src} pushed {mb:.1f} MB to external destination {packet.ip_dst} within 10 seconds.",
                source_ip=packet.ip_src,
                destination_ip=packet.ip_dst,
                timestamp=datetime.fromtimestamp(now, tz=timezone.utc),
                protocol=packet.transport_proto,
                related_packets=[packet.number],
                related_conversations=[packet.conversation_key],
                detection_rationale=f"Transfer rate exceeded 150 KB/s ({mb:.2f} MB in 10s window).",
                recommendation="Validate whether destination is an authorized cloud backup, file upload, or suspicious exfiltration endpoint.",
            )
        return None

    def _check_beaconing(self, packet: RollingPacket, now: float) -> Optional[Finding]:
        key = (packet.ip_src, packet.ip_dst)
        tracker = self._beacon_intervals[key]
        tracker.append(now)

        if len(tracker) >= 6:
            # Calculate delta intervals between successive connections
            intervals = [tracker[i] - tracker[i - 1] for i in range(1, len(tracker))]
            avg_interval = sum(intervals) / len(intervals)

            # Check if regular interval between 1s and 60s
            if 1.0 <= avg_interval <= 60.0:
                # Calculate jitter (variance)
                max_deviation = max(abs(inv - avg_interval) for inv in intervals)
                if max_deviation <= 1.5:  # Very low jitter (< 1.5s variation)
                    cooldown_key = ("beaconing", f"{packet.ip_src}->{packet.ip_dst}")
                    if now - self._rule_cooldowns.get(cooldown_key, 0.0) < 60.0:
                        return None

                    self._rule_cooldowns[cooldown_key] = now
                    return Finding(
                        id=f"live-beacon-{packet.ip_src}-{int(now)}",
                        category="c2_beaconing",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        title=f"Suspicious Low-Jitter Periodic Beaconing to {packet.ip_dst}",
                        description=f"Host {packet.ip_src} maintains rigid periodic connections to {packet.ip_dst} every {avg_interval:.1f}s (jitter < {max_deviation:.2f}s).",
                        source_ip=packet.ip_src,
                        destination_ip=packet.ip_dst,
                        timestamp=datetime.fromtimestamp(now, tz=timezone.utc),
                        protocol=packet.transport_proto,
                        related_packets=[packet.number],
                        related_conversations=[packet.conversation_key],
                        detection_rationale=f"Strict periodic interval ({avg_interval:.1f}s ± {max_deviation:.1f}s across {len(intervals)} successive handshakes).",
                        recommendation="Examine endpoint process execution, command-and-control persistence, and destination reputation.",
                    )
        return None

    def _check_dns_anomaly(self, packet: RollingPacket, now: float) -> Optional[Finding]:
        query = packet.dns_query_name
        if not query:
            return None

        # Alert on abnormally long query name (> 60 characters) indicative of DNS tunneling
        if len(query) >= 60:
            cooldown_key = ("dns_tunnel", query[:25])
            if now - self._rule_cooldowns.get(cooldown_key, 0.0) < 30.0:
                return None

            self._rule_cooldowns[cooldown_key] = now
            return Finding(
                id=f"live-dns-{int(now)}",
                category="dns_tunneling",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title=f"Anomalous High-Length DNS Query ({len(query)} chars)",
                description=f"DNS query '{query[:45]}...' exceeds typical domain lengths, characteristic of DNS tunneling or data staging.",
                source_ip=packet.ip_src,
                destination_ip=packet.ip_dst,
                timestamp=datetime.fromtimestamp(now, tz=timezone.utc),
                protocol="dns",
                related_packets=[packet.number],
                related_conversations=[packet.conversation_key],
                detection_rationale=f"Query string length: {len(query)} characters.",
                recommendation="Investigate resolving client for DNS exfiltration agents or tunneling utilities.",
            )
        return None

    def _prune_state(self, now: float) -> None:
        """Prune tracking state older than 60 seconds to prevent memory growth."""
        cutoff = now - 60.0

        for key, dq in list(self._port_scan_tracker.items()):
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del self._port_scan_tracker[key]

        for key, dq in list(self._host_sweep_tracker.items()):
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del self._host_sweep_tracker[key]

        for key, dq in list(self._outbound_transfer_tracker.items()):
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del self._outbound_transfer_tracker[key]

        for key, dq in list(self._beacon_intervals.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._beacon_intervals[key]
