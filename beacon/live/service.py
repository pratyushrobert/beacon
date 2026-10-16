"""Live network capture background service for Beacon."""

from __future__ import annotations

import collections
import ctypes
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from beacon.core.packet_parser import PacketParser, ParsedPacket
from beacon.core.tshark_interface import get_tshark_interface
from beacon.live.buffer import RollingPacketBuffer
from beacon.live.detection import StreamingDetectionEngine
from beacon.live.models import (
    CaptureInterface,
    EvidenceStatus,
    IncidentEvidence,
    LiveCaptureStats,
    LiveCaptureStatus,
    RollingPacket,
)
from beacon.live.retention import SmartEvidenceStore
from beacon.models import Confidence, Finding, Severity

logger = logging.getLogger(__name__)


def get_current_process_memory_mb() -> float:
    """Return the RSS memory usage of the current process in MB across Linux and Windows."""
    # 1. Linux procfs check (zero-dependency, reads current resident memory in pages)
    if sys.platform != "win32":
        try:
            with open("/proc/self/statm", "r") as f:
                fields = f.read().split()
                if len(fields) >= 2:
                    rss_pages = int(fields[1])
                    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
                    return round((rss_pages * page_size) / (1024 * 1024), 2)
        except Exception:
            pass

    # 2. Windows Win32 API check
    if sys.platform == "win32":
        try:
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            fn = ctypes.windll.psapi.GetProcessMemoryInfo
            fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), ctypes.c_ulong]
            fn.restype = ctypes.c_int
            if fn(handle, ctypes.byref(counters), counters.cb):
                return round(counters.WorkingSetSize / (1024 * 1024), 2)
        except Exception:
            pass

    # 3. POSIX resource fallback
    try:
        import resource
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2)
    except Exception:
        return 0.0


class LiveCaptureService:
    """
    Central background service managing continuous network capture, bounded rolling buffer,
    incremental statistics, streaming detection, and evidence retention.
    """

    def __init__(self, buffer_capacity: Optional[int] = None):
        is_low_res = os.environ.get("BEACON_LOW_RESOURCE", "0") in ("1", "true", "True")
        if buffer_capacity is None:
            env_cap = os.environ.get("BEACON_BUFFER_CAPACITY")
            if env_cap and env_cap.isdigit():
                buffer_capacity = int(env_cap)
            else:
                buffer_capacity = 500 if is_low_res else 1000

        self.is_low_resource = is_low_res
        self.status = LiveCaptureStatus.STOPPED
        self.selected_interface: Optional[str] = None
        self.capture_filter: Optional[str] = None
        self.mode = "white"

        self.buffer = RollingPacketBuffer(capacity=buffer_capacity)
        max_incidents = 40 if is_low_res else 100
        max_pkts_per_incident = 60 if is_low_res else 200
        self.evidence_store = SmartEvidenceStore(
            max_incidents=max_incidents,
            max_packets_per_incident=max_pkts_per_incident,
        )
        self.detection_engine = StreamingDetectionEngine(mode=self.mode)

        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()

        # Telemetry and Incremental Statistics
        self.session_id = "live"
        self.start_time: Optional[float] = None
        self.total_packets = 0
        self.total_bytes = 0
        self.dropped_packets = 0
        self.error_message: Optional[str] = None

        # Maximum capacity bounds to prevent unbounded memory growth during 24/7 continuous runs
        self._max_conversations = 2500 if is_low_res else 5000
        self._max_hosts = 1000 if is_low_res else 2500
        self._max_iocs = 500 if is_low_res else 1000

        # Rate tracking sliding windows (timestamp, count/bytes)
        self._rate_window_packets: collections.deque[Tuple[float, int]] = collections.deque(maxlen=100)
        self._rate_window_bytes: collections.deque[Tuple[float, int]] = collections.deque(maxlen=100)

        # Compact aggregated metrics
        self._host_stats: Dict[str, Dict[str, Any]] = collections.defaultdict(
            lambda: {
                "packets_sent": 0,
                "packets_recv": 0,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "protocols": set(),
                "ports_used": set(),
                "first_seen": None,
                "last_seen": None,
                "is_internal": False,
                "is_multicast": False,
                "is_ipv6": False,
                "findings_count": 0,
            }
        )
        self._protocol_counts: Dict[str, int] = collections.defaultdict(int)
        self._conversation_counts: Dict[str, Dict[str, Any]] = collections.defaultdict(
            lambda: {
                "key": "",
                "host1": "",
                "port1": None,
                "host2": "",
                "port2": None,
                "protocol": "",
                "packets": 0,
                "bytes": 0,
                "first_seen": None,
                "last_seen": None,
            }
        )
        self._timeline_events: collections.deque[Dict[str, Any]] = collections.deque(maxlen=300 if is_low_res else 500)
        self._extracted_iocs: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # Broadcast callbacks (WebSocket / SSE subscribers)
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._lock = threading.Lock()

    def list_interfaces(self) -> List[CaptureInterface]:
        """Discover available capture interfaces using TShark."""
        tshark = get_tshark_interface()
        tshark_path = tshark.tshark_info.path or "tshark"

        interfaces: List[CaptureInterface] = []
        try:
            res = subprocess.run(
                [tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0:
                pattern = re.compile(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?")
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    m = pattern.match(line)
                    if m:
                        idx, dev, friendly = m.group(1), m.group(2), m.group(3)
                        name = friendly or dev
                        is_loop = "loopback" in dev.lower() or "loopback" in (friendly or "").lower()
                        interfaces.append(
                            CaptureInterface(
                                id=idx,
                                name=name,
                                description=friendly or dev,
                                device=dev,
                                is_loopback=is_loop,
                                is_up=True,
                            )
                        )
        except Exception as e:
            logger.error(f"Failed to list TShark interfaces: {e}")

        # Fallback default interfaces if none returned
        if not interfaces:
            interfaces.append(
                CaptureInterface(
                    id="1",
                    name="Default Interface",
                    description="Standard System Network Interface",
                    device="any",
                    is_loopback=False,
                    is_up=True,
                )
            )

        return interfaces

    get_available_interfaces = list_interfaces

    def start_capture(
        self,
        interface: Optional[str] = None,
        capture_filter: Optional[str] = None,
        buffer_capacity: int = 1000,
        mode: str = "white",
        interface_id: Optional[str] = None,
    ) -> bool:
        """Start background continuous packet capture on the selected interface."""
        target_iface = interface or interface_id or "1"
        with self._lock:
            if self.status in (LiveCaptureStatus.CAPTURING, LiveCaptureStatus.STARTING):
                logger.warning("Capture is already running")
                return True

            self.status = LiveCaptureStatus.STARTING
            self.selected_interface = target_iface

            self.capture_filter = capture_filter.strip() if capture_filter else None
            self.mode = mode.lower()

            self.buffer.capacity = buffer_capacity
            self.detection_engine = StreamingDetectionEngine(mode=self.mode)

            self.start_time = time.time()
            self.total_packets = 0
            self.total_bytes = 0
            self.dropped_packets = 0
            self.error_message = None
            self._rate_window_packets.clear()
            self._rate_window_bytes.clear()
            self._host_stats.clear()
            self._protocol_counts.clear()
            self._conversation_counts.clear()
            self._timeline_events.clear()
            self._extracted_iocs.clear()

            self._add_timeline_event(
                now=self.start_time,
                event_type="SYSTEM",
                src="Beacon Live",
                dst=self.selected_interface or "Interface",
                proto="MONITOR",
                message=f"Live capture started on interface {self.selected_interface} (Filter: {self.capture_filter or 'All traffic'})",
                packet_number=0,
            )

            self._stop_event.clear()
            self._pause_event.clear()


            self._thread = threading.Thread(
                target=self._capture_worker,
                daemon=True,
                name="BeaconLiveCaptureWorker",
            )
            self._thread.start()
            return True

    def stop_capture(self) -> bool:
        """Stop running continuous capture and terminate background process tree."""
        with self._lock:
            if self.status == LiveCaptureStatus.STOPPED:
                return True

            self._stop_event.set()
            if self._process and self._process.poll() is None:
                try:
                    if sys.platform != "win32":
                        try:
                            pgid = os.getpgid(self._process.pid)
                            os.killpg(pgid, signal.SIGTERM)
                            self._process.wait(timeout=2.0)
                        except (subprocess.TimeoutExpired, ProcessLookupError):
                            try:
                                os.killpg(pgid, signal.SIGKILL)
                            except Exception:
                                pass
                    else:
                        self._process.terminate()
                        try:
                            self._process.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            self._process.kill()
                except Exception as e:
                    logger.debug(f"Process termination note: {e}")

            self.status = LiveCaptureStatus.STOPPED
            self._process = None

            # Finalize any ongoing evidence collection windows
            self.evidence_store.finalize_expired_windows()
            logger.info("Live capture stopped cleanly.")
            import gc
            gc.collect()
            return True

    def pause_analysis(self) -> None:
        """Temporarily pause detection analysis while maintaining packet streaming."""
        self._pause_event.set()
        if self.status == LiveCaptureStatus.CAPTURING:
            self.status = LiveCaptureStatus.PAUSED

    def resume_analysis(self) -> None:
        """Resume detection analysis."""
        self._pause_event.clear()
        if self.status == LiveCaptureStatus.PAUSED:
            self.status = LiveCaptureStatus.CAPTURING

    pause_capture = pause_analysis
    resume_capture = resume_analysis


    def _capture_worker(self) -> None:
        """Background thread executing TShark stream capture."""
        tshark = get_tshark_interface()
        tshark_path = tshark.tshark_info.path or "tshark"

        cmd = [
            tshark_path,
            "-i", str(self.selected_interface),
            "-l",  # Line buffered output
            "-n",  # Disable DNS name resolution for throughput
            "-T", "ek",  # JSON Elasticsearch streaming format
            "-x",  # Include raw packet hex for byte-accurate PCAP export
        ]

        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        logger.info(f"Starting TShark live capture: {' '.join(cmd)}")

        popen_kwargs: Dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "bufsize": 1,  # Line-buffered
        }
        if sys.platform != "win32":
            popen_kwargs["start_new_session"] = True

        try:
            self._process = subprocess.Popen(cmd, **popen_kwargs)
            self.status = LiveCaptureStatus.CAPTURING
        except Exception as e:
            self.status = LiveCaptureStatus.ERROR
            self.error_message = f"Failed to start TShark process: {e}"
            logger.error(self.error_message)
            return

        packet_seq = 0
        try:
            for line in self._process.stdout:
                if self._stop_event.is_set():
                    break

                line = line.strip()
                if not line:
                    continue

                # Parse EK line
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # EK emits alternating index and layers objects
                if "index" in data and "layers" not in data:
                    continue

                parsed = PacketParser.parse_json_packet(data)
                if not parsed:
                    continue

                packet_seq += 1
                now = parsed.timestamp_epoch or time.time()

                # Extract raw hex if present
                raw_hex = None
                layers_dict = data.get("layers", {})
                if "frame_raw" in layers_dict:
                    val = layers_dict["frame_raw"]
                    raw_hex = val if isinstance(val, str) else (val[0] if isinstance(val, list) and val else None)

                # Construct lightweight RollingPacket
                rolling_pkt = RollingPacket(
                    number=packet_seq,
                    timestamp=now,
                    length=parsed.length or len(line),
                    ip_src=parsed.ip_src or "",
                    ip_dst=parsed.ip_dst or "",
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    transport_proto=parsed.transport_proto or "",
                    app_proto=parsed.app_proto or "",
                    protocols=parsed.protocols or [],
                    tcp_flags=parsed.tcp_flags_text or parsed.tcp_flags,
                    dns_query_name=parsed.dns_query_name,
                    http_uri=parsed.http_uri,
                    http_method=parsed.http_method,
                    tls_server_name=parsed.tls_server_name,
                    direction=parsed.direction,
                    raw_hex=raw_hex,
                )

                # Process packet through ingestion pipeline
                self._ingest_packet(rolling_pkt, now)

        except Exception as e:
            if not self._stop_event.is_set():
                logger.error(f"Error reading live capture stream: {e}")
                self.status = LiveCaptureStatus.ERROR
                self.error_message = str(e)
        finally:
            if self._process and self._process.poll() is not None and self._process.returncode != 0 and packet_seq == 0 and not self._stop_event.is_set():
                err_text = ""
                try:
                    if self._process.stderr:
                        err_text = self._process.stderr.read().strip()
                except Exception:
                    pass
                self.status = LiveCaptureStatus.ERROR
                if "permission" in err_text.lower() or "dumpcap" in err_text.lower():
                    self.error_message = (
                        f"Packet capture permission denied. On Debian/antiX Linux, add your user to the 'wireshark' group "
                        f"('sudo usermod -aG wireshark $USER') and configure dumpcap ('sudo dpkg-reconfigure wireshark-common'). "
                        f"Detail: {err_text}"
                    )
                else:
                    self.error_message = f"TShark capture exited with code {self._process.returncode}: {err_text}"
                logger.error(self.error_message)
            elif self.status != LiveCaptureStatus.ERROR:
                self.status = LiveCaptureStatus.STOPPED

    def _add_timeline_event(
        self,
        now: float,
        event_type: str,
        src: str,
        dst: str,
        proto: str,
        message: str,
        packet_number: int = 0,
        is_finding: bool = False,
        severity: str = "info",
    ) -> None:
        """Record chronological observation in live timeline."""
        self._timeline_events.append({
            "id": f"ev_{int(now)}_{packet_number}_{len(self._timeline_events)}",
            "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "timestamp_epoch": now,
            "event_type": event_type,
            "source": src,
            "destination": dst,
            "protocol": proto,
            "message": message,
            "packet_number": packet_number,
            "is_finding": is_finding,
            "severity": severity,
        })

    def _ingest_packet(self, packet: RollingPacket, now: float) -> None:
        """Ingest a single packet into buffer, statistics, detection, and evidence retention."""
        # 1. Update basic totals and rate sliding windows
        self.total_packets += 1
        self.total_bytes += packet.length
        self._rate_window_packets.append((now, 1))
        self._rate_window_bytes.append((now, packet.length))

        # 2. Append to bounded rolling buffer
        self.buffer.append(packet)

        # 3. Update host metrics
        if packet.ip_src:
            if len(self._host_stats) >= self._max_hosts and packet.ip_src not in self._host_stats:
                oldest_ip = min(self._host_stats.keys(), key=lambda k: self._host_stats[k].get("last_seen") or 0)
                del self._host_stats[oldest_ip]
            h_src = self._host_stats[packet.ip_src]
            h_src["packets_sent"] += 1
            h_src["bytes_sent"] += packet.length
            if h_src["first_seen"] is None:
                h_src["first_seen"] = now
                try:
                    ip_obj = ipaddress.ip_address(packet.ip_src)
                    h_src["is_internal"] = ip_obj.is_private
                    h_src["is_multicast"] = ip_obj.is_multicast
                    h_src["is_ipv6"] = ip_obj.version == 6
                except ValueError:
                    pass
            h_src["last_seen"] = now
            if packet.app_proto or packet.transport_proto:
                h_src["protocols"].add(packet.app_proto or packet.transport_proto)
            if packet.src_port:
                ports = h_src.setdefault("ports_used", set())
                if len(ports) < 40:
                    ports.add(packet.src_port)

        if packet.ip_dst:
            if len(self._host_stats) >= self._max_hosts and packet.ip_dst not in self._host_stats:
                oldest_ip = min(self._host_stats.keys(), key=lambda k: self._host_stats[k].get("last_seen") or 0)
                del self._host_stats[oldest_ip]
            h_dst = self._host_stats[packet.ip_dst]
            h_dst["packets_recv"] += 1
            h_dst["bytes_recv"] += packet.length
            if h_dst["first_seen"] is None:
                h_dst["first_seen"] = now
                try:
                    ip_obj = ipaddress.ip_address(packet.ip_dst)
                    h_dst["is_internal"] = ip_obj.is_private
                    h_dst["is_multicast"] = ip_obj.is_multicast
                    h_dst["is_ipv6"] = ip_obj.version == 6
                except ValueError:
                    pass
            h_dst["last_seen"] = now
            if packet.app_proto or packet.transport_proto:
                h_dst["protocols"].add(packet.app_proto or packet.transport_proto)
            if packet.dst_port:
                ports = h_dst.setdefault("ports_used", set())
                if len(ports) < 40:
                    ports.add(packet.dst_port)

        # 4. Update protocol metrics
        proto_label = (packet.app_proto or packet.transport_proto or "other").upper()
        self._protocol_counts[proto_label] += 1

        # 5. Update conversation metrics
        c_key = packet.conversation_key
        if c_key != "unknown":
            if len(self._conversation_counts) >= self._max_conversations and c_key not in self._conversation_counts:
                oldest_c = min(self._conversation_counts.keys(), key=lambda k: self._conversation_counts[k].get("last_seen") or 0)
                del self._conversation_counts[oldest_c]
            conv = self._conversation_counts[c_key]
            conv["key"] = c_key
            if not conv["host1"]:
                conv["host1"] = packet.ip_src or ""
                conv["port1"] = packet.src_port
                conv["host2"] = packet.ip_dst or ""
                conv["port2"] = packet.dst_port
                conv["protocol"] = (packet.app_proto or packet.transport_proto or "IP").upper()
                conv["first_seen"] = now
            conv["packets"] += 1
            conv["bytes"] += packet.length
            conv["last_seen"] = now

        # 6. Extract IOCs
        if packet.dns_query_name:
            dom = packet.dns_query_name.strip()
            if dom:
                ioc_k = ("domain", dom)
                if ioc_k not in self._extracted_iocs and len(self._extracted_iocs) >= self._max_iocs:
                    oldest_ioc = min(self._extracted_iocs.keys(), key=lambda k: self._extracted_iocs[k].get("last_seen") or 0)
                    del self._extracted_iocs[oldest_ioc]
                if ioc_k not in self._extracted_iocs:
                    self._extracted_iocs[ioc_k] = {
                        "type": "domain",
                        "value": dom,
                        "context": f"DNS Query by {packet.ip_src}",
                        "packet_number": packet.number,
                        "occurrence_count": 0,
                        "first_seen": now,
                        "last_seen": now,
                    }
                self._extracted_iocs[ioc_k]["occurrence_count"] += 1
                self._extracted_iocs[ioc_k]["last_seen"] = now

        if packet.tls_server_name:
            sni = packet.tls_server_name.strip()
            if sni:
                ioc_k = ("domain", sni)
                if ioc_k not in self._extracted_iocs and len(self._extracted_iocs) >= self._max_iocs:
                    oldest_ioc = min(self._extracted_iocs.keys(), key=lambda k: self._extracted_iocs[k].get("last_seen") or 0)
                    del self._extracted_iocs[oldest_ioc]
                if ioc_k not in self._extracted_iocs:
                    self._extracted_iocs[ioc_k] = {
                        "type": "domain",
                        "value": sni,
                        "context": f"TLS SNI by {packet.ip_src}",
                        "packet_number": packet.number,
                        "occurrence_count": 0,
                        "first_seen": now,
                        "last_seen": now,
                    }
                self._extracted_iocs[ioc_k]["occurrence_count"] += 1
                self._extracted_iocs[ioc_k]["last_seen"] = now

        if packet.http_uri:
            raw_uri = packet.http_uri.strip()
            clean_uri = re.sub(r"(?i)(password|passwd|pwd|token|key|secret)=([^&]+)", r"\1=[REDACTED]", raw_uri)
            ioc_k = ("url", clean_uri)
            if ioc_k not in self._extracted_iocs:
                self._extracted_iocs[ioc_k] = {
                    "type": "url",
                    "value": clean_uri,
                    "context": f"HTTP {packet.http_method or 'GET'} by {packet.ip_src}",
                    "packet_number": packet.number,
                    "occurrence_count": 0,
                    "first_seen": now,
                    "last_seen": now,
                }
            self._extracted_iocs[ioc_k]["occurrence_count"] += 1
            self._extracted_iocs[ioc_k]["last_seen"] = now

        if packet.ip_dst:
            try:
                ip_obj = ipaddress.ip_address(packet.ip_dst)
                if not ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback:
                    ioc_k = ("ip", packet.ip_dst)
                    if ioc_k not in self._extracted_iocs:
                        self._extracted_iocs[ioc_k] = {
                            "type": "ip",
                            "value": packet.ip_dst,
                            "context": f"External Endpoint contacted by {packet.ip_src}",
                            "packet_number": packet.number,
                            "occurrence_count": 0,
                            "first_seen": now,
                            "last_seen": now,
                        }
                    self._extracted_iocs[ioc_k]["occurrence_count"] += 1
                    self._extracted_iocs[ioc_k]["last_seen"] = now
            except ValueError:
                pass

        # 7. Add sampled timeline events
        if packet.dns_query_name and self.total_packets % 3 == 0:
            self._add_timeline_event(
                now=now,
                event_type="DNS Query",
                src=packet.ip_src,
                dst=packet.ip_dst,
                proto="DNS",
                message=f"DNS lookup for {packet.dns_query_name}",
                packet_number=packet.number,
            )
        elif packet.http_uri and self.total_packets % 3 == 0:
            self._add_timeline_event(
                now=now,
                event_type="HTTP Request",
                src=packet.ip_src,
                dst=packet.ip_dst,
                proto="HTTP",
                message=f"{packet.http_method or 'GET'} {packet.http_uri[:60]}",
                packet_number=packet.number,
            )
        elif packet.tls_server_name and self.total_packets % 3 == 0:
            self._add_timeline_event(
                now=now,
                event_type="TLS Handshake",
                src=packet.ip_src,
                dst=packet.ip_dst,
                proto="TLS",
                message=f"TLS Client Hello to {packet.tls_server_name}",
                packet_number=packet.number,
            )

        # 8. Feed to active post-trigger collection windows in evidence store
        self.evidence_store.process_incoming_packet(packet)

        # 9. Evaluate streaming detection rules (if not paused)
        if not self._pause_event.is_set():
            new_findings = self.detection_engine.process_packet(packet)
            for finding in new_findings:
                # Trigger smart evidence preservation
                incident = self.evidence_store.trigger_incident(
                    finding=finding,
                    trigger_packet=packet,
                    buffer=self.buffer,
                )
                if packet.ip_src in self._host_stats:
                    self._host_stats[packet.ip_src]["findings_count"] += 1
                if packet.ip_dst in self._host_stats:
                    self._host_stats[packet.ip_dst]["findings_count"] += 1

                self._add_timeline_event(
                    now=now,
                    event_type=f"ALERT: {finding.category.upper()}",
                    src=finding.source_ip or packet.ip_src,
                    dst=finding.destination_ip or packet.ip_dst,
                    proto=(finding.protocol or "ALERT").upper(),
                    message=f"[{finding.severity.value.upper()}] {finding.title}",
                    packet_number=packet.number,
                    is_finding=True,
                    severity=finding.severity.value,
                )

                logger.warning(f"[BEACON LIVE ALERT] {finding.title} -> Preserved Incident {incident.id}")
                self._broadcast({"type": "incident", "data": incident.to_dict()})


    def ingest_synthetic_packet(self, packet: RollingPacket) -> List[IncidentEvidence]:
        """
        Manually push a packet into the pipeline. Used for deterministic automated unit tests
        and synthetic packet stream generation without physical network interfaces.
        """
        now = packet.timestamp or time.time()
        self._ingest_packet(packet, now)

        # Return list of any newly triggered incidents
        return self.evidence_store.get_incidents(limit=5)

    def get_stats(self) -> LiveCaptureStats:
        """Compute and return real-time telemetry snapshot."""
        now = time.time()
        elapsed = (now - self.start_time) if self.start_time and self.status in (LiveCaptureStatus.CAPTURING, LiveCaptureStatus.PAUSED) else 0.0

        # Calculate rate over last 2 seconds
        cutoff_rate = now - 2.0
        recent_pkts = sum(cnt for ts, cnt in self._rate_window_packets if ts >= cutoff_rate)
        recent_bytes = sum(b for ts, b in self._rate_window_bytes if ts >= cutoff_rate)
        pps = round(recent_pkts / 2.0, 1)
        bps = round(recent_bytes / 2.0, 1)

        # Format Top 5 Communicating Hosts
        top_hosts = []
        for ip, s in sorted(
            self._host_stats.items(),
            key=lambda x: (x[1]["bytes_sent"] + x[1]["bytes_recv"]),
            reverse=True,
        )[:5]:
            top_hosts.append({
                "ip": ip,
                "packets": s["packets_sent"] + s["packets_recv"],
                "bytes": s["bytes_sent"] + s["bytes_recv"],
                "protocols": sorted(list(s["protocols"]))[:3],
            })

        # Format Top 5 Active Conversations
        active_convs = []
        for key, c in sorted(
            self._conversation_counts.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True,
        )[:5]:
            active_convs.append({
                "key": key,
                "packets": c["packets"],
                "bytes": c["bytes"],
                "last_seen": c["last_seen"],
            })

        # Process memory
        rss_mb = get_current_process_memory_mb()

        return LiveCaptureStats(
            status=self.status,
            selected_interface=self.selected_interface,
            elapsed_seconds=round(elapsed, 1),
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            packets_per_second=pps,
            bytes_per_second=bps,
            buffer_capacity=self.buffer.capacity,
            buffer_occupancy=self.buffer.occupancy,
            buffer_memory_bytes=self.buffer.estimated_bytes,
            process_memory_mb=rss_mb,
            dropped_packets=self.dropped_packets,
            analysis_backlog=0,
            incidents_count=self.evidence_store.incidents_count,
            pinned_incidents_count=self.evidence_store.pinned_count,
            active_collection_windows_count=self.evidence_store.active_windows_count,
            top_hosts=top_hosts,
            top_protocols=dict(self._protocol_counts),
            active_conversations=active_convs,
            findings_by_severity=dict(self.detection_engine.findings_by_severity),
            capture_filter=self.capture_filter,
            error_message=self.error_message,
        )

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a subscriber callback for real-time events."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Remove a subscriber callback."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _broadcast(self, event: Dict[str, Any]) -> None:
        """Notify all registered subscribers."""
        for cb in list(self._subscribers):
            try:
                cb(event)
            except Exception as e:
                logger.debug(f"Broadcast callback error: {e}")

    # -------------------------------------------------------------------------
    # Unified Investigation Query APIs for Live Real-Time Data
    # -------------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Return analysis status compatible with /api/analysis/{id}/status."""
        has_data = (self.total_packets > 0 or self.status == LiveCaptureStatus.CAPTURING)
        return {
            "id": "live",
            "status": "complete" if has_data else "pending",
            "progress": 100 if has_data else 0,
            "filename": f"Live Network Capture ({self.selected_interface or 'active'})",
            "mode": self.mode,
            "error": self.error_message,
            "is_live": True,
            "live_status": self.status.value,
        }

    def get_results(self) -> Dict[str, Any]:
        """Generate structured analysis results for the live capture session."""
        now = time.time()
        start_iso = datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat() if self.start_time else None
        end_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        dur = round((now - self.start_time) if self.start_time else 0.0, 1)

        findings_list = [f.to_dict() for f in self.detection_engine.findings]
        hosts = self.get_hosts(top=100)
        convs = self.get_conversations(top=100)
        timeline = self.get_timeline(limit=200)
        iocs = self.get_iocs()

        return {
            "id": "live",
            "mode": self.mode,
            "pcap_file": f"Live Interface ({self.selected_interface or 'active'})",
            "filename": f"Live Capture ({self.selected_interface or 'active'})",
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "start_time": start_iso,
            "end_time": end_iso,
            "duration_seconds": dur,
            "unique_hosts": len(self._host_stats),
            "protocols": dict(self._protocol_counts),
            "findings": findings_list,
            "findings_count": len(findings_list),
            "findings_by_severity": dict(self.detection_engine.findings_by_severity),
            "hosts": hosts,
            "conversations": convs,
            "timeline": timeline,
            "iocs": iocs,
            "is_live": True,
            "status": "complete" if (self.total_packets > 0 or self.status == LiveCaptureStatus.CAPTURING) else "pending",
            "live_status": self.status.value,
        }

    def get_findings(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return live findings with optional severity and category filtering."""
        findings = [f.to_dict() for f in self.detection_engine.findings]
        if severity and severity.lower() != "all":
            findings = [f for f in findings if str(f.get("severity", "")).lower() == severity.lower()]
        if category and category.lower() != "all":
            findings = [f for f in findings if category.lower() in str(f.get("category", "")).lower()]
        return findings

    def get_hosts(self, top: int = 100) -> List[Dict[str, Any]]:
        """Return host inventory with enriched metrics and live active status."""
        now = time.time()
        with self._lock:
            stats_copy = list(self._host_stats.items())

        sorted_hosts = sorted(
            stats_copy,
            key=lambda x: (x[1]["bytes_sent"] + x[1]["bytes_recv"]),
            reverse=True,
        )[:top]

        result = []
        for ip, s in sorted_hosts:
            is_active = (now - (s["last_seen"] or 0)) < 30.0 if self.status == LiveCaptureStatus.CAPTURING else False
            result.append({
                "ip": ip,
                "is_internal": s.get("is_internal", False),
                "is_multicast": s.get("is_multicast", False),
                "is_ipv6": s.get("is_ipv6", False),
                "packets_sent": s["packets_sent"],
                "packets_received": s["packets_recv"],
                "total_packets": s["packets_sent"] + s["packets_recv"],
                "bytes_sent": s["bytes_sent"],
                "bytes_received": s["bytes_recv"],
                "total_bytes": s["bytes_sent"] + s["bytes_recv"],
                "first_seen": s["first_seen"],
                "last_seen": s["last_seen"],
                "protocols": sorted(list(s.get("protocols", []))),
                "ports_used": sorted(list(s.get("ports_used", []))),
                "findings_count": s.get("findings_count", 0),
                "is_active": is_active,
            })
        return result

    def get_conversations(self, top: int = 100) -> List[Dict[str, Any]]:
        """Return network conversations with active/inactive state."""
        now = time.time()
        with self._lock:
            convs_copy = list(self._conversation_counts.items())

        sorted_convs = sorted(
            convs_copy,
            key=lambda x: x[1]["bytes"],
            reverse=True,
        )[:top]

        result = []
        for key, c in sorted_convs:
            is_active = (now - c["last_seen"]) < 30.0 if self.status == LiveCaptureStatus.CAPTURING else False
            result.append({
                "key": key,
                "host1": c["host1"],
                "host2": c["host2"],
                "port1": c["port1"],
                "port2": c["port2"],
                "protocol": c["protocol"],
                "packet_count": c["packets"],
                "byte_count": c["bytes"],
                "first_seen": c["first_seen"],
                "last_seen": c["last_seen"],
                "is_active": is_active,
            })
        return result

    def get_timeline(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return chronological timeline events from live capture."""
        with self._lock:
            events = list(self._timeline_events)
        return events[-limit:]

    def get_iocs(self) -> List[Dict[str, Any]]:
        """Return extracted IOCs sorted by occurrence count."""
        with self._lock:
            ioc_vals = list(self._extracted_iocs.values())
        return sorted(ioc_vals, key=lambda x: x.get("occurrence_count", 0), reverse=True)

    def get_packets(
        self,
        offset: int = 0,
        limit: int = 50,
        search: Optional[str] = None,
        protocol: Optional[str] = None,
        direction: Optional[str] = None,
        ip: Optional[str] = None,
        sort_by: str = "number",
        sort_dir: str = "asc",
    ) -> Dict[str, Any]:
        """Fetch paginated, filtered packets directly from rolling buffer."""
        # Get snapshot of packets from rolling buffer
        with self.buffer._lock:
            raw_packets = list(self.buffer._buffer)

        # Filter packets
        filtered: List[RollingPacket] = []
        search_lower = search.lower() if search else None
        proto_lower = protocol.lower() if protocol else None
        dir_lower = direction.lower() if direction else None

        for p in raw_packets:
            if proto_lower and not (
                proto_lower == (p.app_proto or "").lower()
                or proto_lower == (p.transport_proto or "").lower()
                or any(proto_lower == pr.lower() for pr in p.protocols)
            ):
                continue
            if dir_lower and p.direction.lower() != dir_lower:
                continue
            if ip and p.ip_src != ip and p.ip_dst != ip:
                continue
            if search_lower:
                matches_search = (
                    (p.ip_src and search_lower in p.ip_src.lower())
                    or (p.ip_dst and search_lower in p.ip_dst.lower())
                    or (p.app_proto and search_lower in p.app_proto.lower())
                    or (p.transport_proto and search_lower in p.transport_proto.lower())
                    or (p.dns_query_name and search_lower in p.dns_query_name.lower())
                    or (p.http_uri and search_lower in p.http_uri.lower())
                    or (p.tls_server_name and search_lower in p.tls_server_name.lower())
                )
                if not matches_search:
                    continue
            filtered.append(p)

        # Sort
        reverse = (sort_dir.lower() == "desc")
        if sort_by == "timestamp":
            filtered.sort(key=lambda x: x.timestamp, reverse=reverse)
        elif sort_by == "length":
            filtered.sort(key=lambda x: x.length, reverse=reverse)
        elif sort_by == "ip_src":
            filtered.sort(key=lambda x: x.ip_src, reverse=reverse)
        elif sort_by == "ip_dst":
            filtered.sort(key=lambda x: x.ip_dst, reverse=reverse)
        elif sort_by == "app_proto":
            filtered.sort(key=lambda x: x.app_proto or x.transport_proto or "", reverse=reverse)
        else:
            filtered.sort(key=lambda x: x.number, reverse=reverse)

        total = len(filtered)
        page = filtered[offset : offset + limit]

        formatted = []
        for p in page:
            ts_str = datetime.fromtimestamp(p.timestamp, tz=timezone.utc).isoformat() if p.timestamp else ""
            formatted.append({
                "number": p.number,
                "timestamp": ts_str,
                "length": p.length,
                "ip_src": p.ip_src,
                "ip_dst": p.ip_dst,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "transport_proto": p.transport_proto,
                "app_proto": p.app_proto,
                "protocols": p.protocols if isinstance(p.protocols, list) else ([p.protocols] if p.protocols else []),
                "direction": p.direction,
                "conversation_key": p.conversation_key,
                "dns_query_name": p.dns_query_name,
                "http_method": p.http_method,
                "http_host": None,
                "http_uri": p.http_uri,
                "http_response_code": None,
                "tls_server_name": p.tls_server_name,
            })

        return {
            "packets": formatted,
            "total": total,
            "offset": offset,
            "limit": limit,
            "is_live": True,
            "buffer_evicted": self.buffer.total_evicted,
        }

    def get_packet_detail(self, packet_number: int) -> Optional[Dict[str, Any]]:
        """Deep inspection of a live packet from rolling buffer or preserved incidents."""
        # Check rolling buffer first
        pkt = self.buffer.get_packet_by_number(packet_number)

        # Check preserved evidence store if not in rolling buffer
        if not pkt:
            pkt = self.evidence_store.get_packet_by_number(packet_number)

        if not pkt:
            return None

        # Correlate with active findings
        correlated_findings = []
        for finding in self.detection_engine.findings:
            f_dict = finding.to_dict()
            if packet_number in getattr(finding, "related_packets", []):
                correlated_findings.append(f_dict)
            elif finding.source_ip == pkt.ip_src and (not finding.destination_ip or finding.destination_ip == pkt.ip_dst):
                correlated_findings.append(f_dict)

        ts_str = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc).isoformat() if pkt.timestamp else ""
        return {
            "number": pkt.number,
            "timestamp": ts_str,
            "length": pkt.length,
            "source": pkt.ip_src,
            "destination": pkt.ip_dst,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "protocol": pkt.app_proto or pkt.transport_proto or "RAW",
            "protocols": pkt.protocols,
            "direction": pkt.direction,
            "conversation_key": pkt.conversation_key,
            "layers": {
                "frame": {
                    "number": pkt.number,
                    "len": pkt.length,
                    "protocols": ":".join(pkt.protocols) if pkt.protocols else (pkt.app_proto or pkt.transport_proto or "raw"),
                },
                "ip": {
                    "src": pkt.ip_src,
                    "dst": pkt.ip_dst,
                },
                "transport": {
                    "proto": pkt.transport_proto,
                    "srcport": pkt.src_port,
                    "dstport": pkt.dst_port,
                    "flags": pkt.tcp_flags,
                },
            },
            "findings": correlated_findings,
            "raw_hex": pkt.raw_hex,
            "is_evicted": False,
        }

    def get_network_graph(self, max_nodes: int = 40) -> Dict[str, Any]:
        """Generate network topology nodes, subnets, and edges from live telemetry."""
        from beacon.analysis.topology import build_network_topology

        with self._lock:
            stats_copy = list(self._host_stats.items())
            convs_copy = list(self._conversation_counts.items())
            active_findings = [f.to_dict() for f in self.detection_engine.findings]

        hosts_data = []
        ports_map = {}
        for ip, s in stats_copy:
            hosts_data.append({
                "ip": ip,
                "packets_sent": s.get("packets_sent", 0),
                "packets_received": s.get("packets_recv", 0),
                "bytes_sent": s.get("bytes_sent", 0),
                "bytes_received": s.get("bytes_recv", 0),
                "first_seen": s.get("first_seen"),
                "last_seen": s.get("last_seen"),
                "is_internal": s.get("is_internal", False),
            })
            if s.get("ports_used"):
                ports_map[ip] = set(s["ports_used"])

        convs_data = []
        for key, c in convs_copy:
            convs_data.append({
                "conversation_key": key,
                "host1": c.get("host1"),
                "host2": c.get("host2"),
                "port1": c.get("port1"),
                "port2": c.get("port2"),
                "protocol": c.get("protocol"),
                "packet_count": c.get("packets", 0),
                "byte_count": c.get("bytes", 0),
                "first_seen": c.get("first_seen"),
                "last_seen": c.get("last_seen"),
            })

        topo = build_network_topology(
            hosts_data=hosts_data,
            conversations_data=convs_data,
            findings_data=active_findings,
            ports_by_ip=ports_map,
            max_nodes=max_nodes,
        )
        topo["is_live"] = True
        return topo

    def get_evidence_graph(
        self,
        max_nodes: int = 60,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate multi-entity investigation graph (hosts, domains, findings)."""
        from beacon.analysis.topology import classify_ip_address, infer_device_role

        with self._lock:
            stats_copy = list(self._host_stats.items())
            convs_copy = list(self._conversation_counts.items())
            ioc_copy = list(self._extracted_iocs.values())
            active_findings = findings if findings is not None else [f.to_dict() for f in self.detection_engine.findings]

        sorted_hosts = sorted(
            stats_copy,
            key=lambda x: (x[1]["bytes_sent"] + x[1]["bytes_recv"]),
            reverse=True,
        )[:max(10, max_nodes // 2)]

        nodes = []
        host_ips = set()
        for ip, s in sorted_hosts:
            host_ips.add(ip)
            c = classify_ip_address(ip)
            h_findings = [f for f in active_findings if f.get("source_ip") == ip or f.get("destination_ip") == ip]
            max_sev = "info"
            for sev in ["critical", "high", "medium", "low"]:
                if any(f.get("severity") == sev for f in h_findings):
                    max_sev = sev
                    break

            role_name, role_badge, role_evidence = infer_device_role(ip, c, s.get("ports_used", []))

            nodes.append({
                "id": ip,
                "label": ip,
                "type": "host",
                "ip": ip,
                "ip_version": c["ip_version"],
                "subnet": c["subnet_id"],
                "subnet_label": c["subnet_label"],
                "subnet_category": c["category"],
                "device_role": role_name,
                "role_badge": role_badge,
                "role_evidence": role_evidence,
                "is_internal": c["is_internal"],
                "is_multicast": c["is_multicast"],
                "is_loopback": c["is_loopback"],
                "is_link_local": c["is_link_local"],
                "is_ipv6": c["ip_version"] == 6,
                "packets_sent": s["packets_sent"],
                "packets_received": s["packets_recv"],
                "total_bytes": s["bytes_sent"] + s["bytes_recv"],
                "findings_count": len(h_findings),
                "severity": max_sev,
            })

        edges = []

        # 2. Domains
        domains = [i for i in ioc_copy if i.get("type") == "domain"][:25]
        for d in domains:
            dom = d.get("value", "")
            if not dom:
                continue
            dom_sev = "high" if any(dom.lower() in str(f.get("evidence", [])).lower() or dom.lower() in f.get("title", "").lower() for f in active_findings) else "info"
            nodes.append({
                "id": f"domain:{dom}",
                "label": dom,
                "domain": dom,
                "type": "domain",
                "severity": dom_sev,
                "query_count": d.get("occurrence_count", 1),
            })

        # 3. Security Findings
        for idx, f in enumerate(active_findings[:15]):
            f_id = f"finding:{f.get('id', idx)}"
            nodes.append({
                "id": f_id,
                "label": f.get("title", "Finding"),
                "type": "finding",
                "severity": f.get("severity", "medium"),
                "confidence": f.get("confidence", "high"),
                "category": f.get("category", "security"),
                "description": f.get("description", ""),
            })

            if f.get("source_ip"):
                edges.append({
                    "id": f"edge_{f_id}_{f.get('source_ip')}",
                    "source": f_id,
                    "target": f.get("source_ip"),
                    "type": "alert",
                    "severity": f.get("severity", "medium"),
                    "label": "Alert Source",
                })
            if f.get("destination_ip") and f.get("destination_ip") != f.get("source_ip"):
                edges.append({
                    "id": f"edge_{f_id}_{f.get('destination_ip')}",
                    "source": f_id,
                    "target": f.get("destination_ip"),
                    "type": "alert",
                    "severity": f.get("severity", "medium"),
                    "label": "Alert Target",
                })

        # 4. Communicating hosts traffic
        for key, c in sorted(convs_copy, key=lambda x: x[1]["bytes"], reverse=True)[:50]:
            h1 = c["host1"]
            h2 = c["host2"]
            if h1 in host_ips and h2 in host_ips:
                edges.append({
                    "id": key,
                    "source": h1,
                    "target": h2,
                    "type": "traffic",
                    "protocol": c["protocol"] or "unknown",
                    "packet_count": c["packets"],
                    "byte_count": c["bytes"],
                    "port1": c["port1"],
                    "port2": c["port2"],
                    "first_seen": c["first_seen"],
                    "last_seen": c["last_seen"],
                })

        return {"nodes": nodes, "edges": edges, "is_live": True}

    def get_storyline(self) -> List[Dict[str, Any]]:
        """Build an investigation storyline from live detection and protocol milestones."""
        milestones: List[Dict[str, Any]] = []
        with self._lock:
            active_findings = [f.to_dict() for f in self.detection_engine.findings]
            timeline_copy = list(self._timeline_events)

        # 1. Findings converted to milestones
        for idx, f in enumerate(active_findings):
            title = f.get("title", "")
            cat = f.get("category", "").lower()
            phase = "ANOMALY"
            if "scan" in title.lower() or "scan" in cat or "sweep" in title.lower():
                phase = "RECONNAISSANCE"
            elif "cleartext" in title.lower() or "token" in title.lower() or "credential" in title.lower():
                phase = "EXPOSURE"
            elif "beacon" in title.lower() or "c2" in title.lower() or "command" in title.lower():
                phase = "COMMAND_AND_CONTROL"
            elif "internal" in title.lower() or "lateral" in title.lower() or "ssh" in title.lower() or "smb" in title.lower():
                phase = "LATERAL_MOVEMENT"

            ts = f.get("first_seen") or f.get("timestamp") or datetime.now(timezone.utc).isoformat()
            milestones.append({
                "id": f"story_finding_{idx}",
                "phase": phase,
                "timestamp": ts,
                "timestamp_epoch": f.get("timestamp_epoch", time.time()),
                "title": title,
                "summary": f.get("description", ""),
                "packet_numbers": f.get("related_packets", []),
                "source_ip": f.get("source_ip"),
                "destination_ip": f.get("destination_ip"),
                "protocol": f.get("protocol"),
                "severity": f.get("severity", "medium"),
                "confidence": f.get("confidence", "high"),
                "evidence": f.get("evidence", []),
                "next_step": f.get("next_step", "Inspect related packets in Packet Explorer"),
                "is_finding": True,
            })

        # 2. Timeline protocol observations
        for ev in timeline_copy:
            if ev.get("is_finding"):
                continue
            ev_type = ev.get("event_type", "")
            phase = "RESOLUTION" if "DNS" in ev_type else ("CONNECTION" if "TLS" in ev_type else "COMMUNICATION")
            milestones.append({
                "id": ev["id"],
                "phase": phase,
                "timestamp": ev["timestamp"],
                "timestamp_epoch": ev.get("timestamp_epoch", time.time()),
                "title": f"{ev_type}: {ev.get('source')} -> {ev.get('destination')}",
                "summary": ev.get("message", ""),
                "packet_numbers": [ev["packet_number"]] if ev.get("packet_number") else [],
                "source_ip": ev.get("source"),
                "destination_ip": ev.get("destination"),
                "protocol": ev.get("protocol"),
                "severity": ev.get("severity", "info"),
                "confidence": "high",
                "evidence": [ev.get("message", "")],
                "next_step": "Correlate with surrounding packets if suspicious",
                "is_finding": False,
            })

        milestones.sort(key=lambda m: m.get("timestamp_epoch", 0.0))
        return milestones

    def get_conversation_stream(
        self,
        conversation_key: str,
        limit: int = 150,
    ) -> Dict[str, Any]:
        """Reconstruct message turns and payload preview for a live conversation."""
        with self.buffer._lock:
            buffer_pkts = list(self.buffer._buffer)

        # Match conversation packets
        matched = [p for p in buffer_pkts if p.conversation_key == conversation_key]
        if not matched:
            # Try endpoints matching
            h1, h2, p1, p2 = self._parse_conversation_endpoints(conversation_key)
            if h1 and h2:
                matched = [
                    p for p in buffer_pkts
                    if (p.ip_src == h1 and p.ip_dst == h2) or (p.ip_src == h2 and p.ip_dst == h1)
                ]

        if not matched:
            return {
                "conversation_key": conversation_key,
                "total_messages": 0,
                "client": "",
                "server": "",
                "turns": [],
            }

        matched = matched[:limit]
        client_ip = matched[0].ip_src
        client_port = matched[0].src_port
        server_ip = matched[0].ip_dst
        server_port = matched[0].dst_port

        client_label = f"{client_ip}:{client_port}" if client_port is not None else client_ip
        server_label = f"{server_ip}:{server_port}" if server_port is not None else server_ip

        turns = []
        for p in matched:
            is_client = (p.ip_src == client_ip)
            direction = "client_to_server" if is_client else "server_to_client"
            proto = p.app_proto or p.transport_proto or "RAW"

            summary = ""
            if p.http_method:
                summary = f"{p.http_method} {p.http_uri or '/'}"
            elif p.dns_query_name:
                summary = f"DNS Query: {p.dns_query_name}"
            elif p.tls_server_name:
                summary = f"TLS SNI: {p.tls_server_name}"
            else:
                summary = f"{proto.upper()} ({p.length} bytes)"

            payload_lines = []
            if p.raw_hex:
                try:
                    raw_bytes = bytes.fromhex(p.raw_hex.replace(" ", "").replace("\n", ""))
                    ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:128])
                    payload_lines.append(f"HEX: {p.raw_hex[:64]}...")
                    payload_lines.append(f"ASCII: {ascii_preview}")
                except Exception:
                    pass

            ts_str = datetime.fromtimestamp(p.timestamp, tz=timezone.utc).isoformat() if p.timestamp else ""
            turns.append({
                "packet_number": p.number,
                "timestamp": ts_str,
                "direction": direction,
                "source": f"{p.ip_src}:{p.src_port}" if p.src_port is not None else p.ip_src,
                "destination": f"{p.ip_dst}:{p.dst_port}" if p.dst_port is not None else p.ip_dst,
                "protocol": proto.upper(),
                "summary": summary,
                "length": p.length,
                "payload_preview": "\n".join(payload_lines) if payload_lines else None,
            })

        return {
            "conversation_key": conversation_key,
            "total_messages": len(turns),
            "client": client_label,
            "server": server_label,
            "turns": turns,
        }

    def global_search(self, query: str, limit: int = 50) -> Dict[str, Any]:
        """Search across live hosts, conversations, packets, and findings."""
        q = query.lower()

        # Hosts matching
        matching_hosts = [
            {
                "ip": ip,
                "is_internal": s.get("is_internal", False),
                "packets_sent": s["packets_sent"],
                "packets_received": s["packets_recv"],
                "total_bytes": s["bytes_sent"] + s["bytes_recv"],
            }
            for ip, s in self._host_stats.items()
            if q in ip.lower()
        ][:limit]

        # Conversations matching
        matching_convs = [
            {
                "key": k,
                "host1": c["host1"],
                "host2": c["host2"],
                "protocol": c["protocol"],
                "packet_count": c["packets"],
                "byte_count": c["bytes"],
            }
            for k, c in self._conversation_counts.items()
            if q in k.lower() or q in c["host1"].lower() or q in c["host2"].lower()
        ][:limit]

        # Packets matching
        with self.buffer._lock:
            buf_pkts = list(self.buffer._buffer)

        matching_packets = []
        for p in buf_pkts:
            if (
                q in p.ip_src.lower()
                or q in p.ip_dst.lower()
                or (p.app_proto and q in p.app_proto.lower())
                or (p.dns_query_name and q in p.dns_query_name.lower())
                or (p.http_uri and q in p.http_uri.lower())
            ):
                matching_packets.append({
                    "number": p.number,
                    "timestamp": datetime.fromtimestamp(p.timestamp, tz=timezone.utc).isoformat() if p.timestamp else "",
                    "src": p.ip_src,
                    "dst": p.ip_dst,
                    "protocol": p.app_proto or p.transport_proto,
                })
                if len(matching_packets) >= limit:
                    break

        # Findings matching
        matching_findings = [
            f.to_dict()
            for f in self.detection_engine.findings
            if q in f.title.lower() or q in f.description.lower() or (f.source_ip and q in f.source_ip.lower())
        ][:limit]

        # IOCs matching
        matching_iocs = [
            i
            for i in self._extracted_iocs.values()
            if q in str(i.get("value", "")).lower()
        ][:limit]

        return {
            "hosts": matching_hosts,
            "conversations": matching_convs,
            "packets": matching_packets,
            "findings": matching_findings,
            "iocs": matching_iocs,
        }

    def get_memory_briefing(self) -> Dict[str, Any]:
        """Compute explainable change briefing for live capture against Beacon Memory baseline."""
        try:
            from beacon.memory.store import MemoryStore
            from beacon.memory.detector import ChangeDetector
            store = MemoryStore()
            detector = ChangeDetector(store)

            hosts = self.get_hosts(top=100)
            convs = self.get_conversations(top=100)
            findings = [f.to_dict() for f in self.detection_engine.findings]
            iocs = self.get_iocs()

            now = time.time()
            capture_metadata = {
                "capture_id": "live",
                "filename": f"Live Capture ({self.selected_interface or 'active'})",
                "mode": self.mode,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "start_time": self.start_time or now,
                "end_time": now,
                "duration_seconds": round((now - self.start_time) if self.start_time else 0.0, 1),
                "unique_hosts": len(hosts),
                "findings_count": len(findings),
            }

            briefing = detector.analyze(
                capture_metadata=capture_metadata,
                hosts=hosts,
                conversations=convs,
                findings=findings,
                iocs=iocs,
            )
            briefing["is_live"] = True
            return briefing
        except Exception as e:
            logger.warning(f"Error computing live memory briefing: {e}")
            return {
                "capture_id": "live",
                "is_live": True,
                "summary": "Baseline comparison is available as traffic is observed.",
                "total_anomalies": 0,
                "ranked_candidates": [],
                "first_seen_hosts": [],
                "new_conversations": [],
                "unusual_ports": [],
                "recurring_anomalies": [],
                "baseline_stats": {"total_captures": 0, "total_hosts": 0},
            }


# Singleton instance
_live_service_instance: Optional[LiveCaptureService] = None


def get_live_service() -> LiveCaptureService:
    """Get or create singleton LiveCaptureService."""
    global _live_service_instance
    if _live_service_instance is None:
        _live_service_instance = LiveCaptureService()
    return _live_service_instance
