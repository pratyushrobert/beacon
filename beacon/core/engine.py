"""Core analysis engine for processing network captures."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from beacon.core.modes import AnalysisMode, get_mode_config
from beacon.core.packet_parser import PacketParser, ParsedPacket
from beacon.core.tshark_interface import get_tshark_interface
from beacon.detection.engine import DetectionEngine

logger = logging.getLogger(__name__)
console = Console()


class AnalysisEngine:
    """Core engine for analyzing network traffic captures."""

    def __init__(
        self,
        pcap_path: Path,
        mode: AnalysisMode = AnalysisMode.WHITE,
        cache_dir: Optional[Path] = None,
    ):
        """
        Initialize analysis engine.

        Args:
            pcap_path: Path to PCAP/PCAPNG file
            mode: Analysis mode (blue/red/white)
            cache_dir: Optional directory for caching parsed data
        """
        self.pcap_path = Path(pcap_path)
        self.mode = mode
        self.mode_config = get_mode_config(mode)

        # Setup cache
        if cache_dir is None:
            cache_dir = Path("cache")
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(exist_ok=True)

        # Cache database path
        mtime = self.pcap_path.stat().st_mtime if self.pcap_path.exists() else 0
        cache_filename = f"{self.pcap_path.stem}_{mtime}.db"
        self.cache_db = self.cache_dir / cache_filename

        # TShark interface
        self.tshark = get_tshark_interface()

        # Statistics (populated during analysis)
        self.stats: Dict[str, Any] = {
            "total_packets": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
            "duration": 0.0,
            "unique_hosts": set(),
            "conversations": {},
            "protocols": defaultdict(int),
        }

        # Detection engine for security analysis
        self.detection_engine = DetectionEngine(mode=mode.value)
        self.findings: List[Any] = []

        # Load or initialize cache
        self.cache_exists = False
        self._init_cache()

    def _init_cache(self) -> None:
        """Initialize SQLite cache database with schema and migrations."""
        self.db_conn = sqlite3.connect(self.cache_db)
        self.db_conn.row_factory = sqlite3.Row
        cursor = self.db_conn.cursor()

        # Create packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                number INTEGER PRIMARY KEY,
                timestamp REAL,
                timestamp_str TEXT,
                length INTEGER,
                ip_src TEXT,
                ip_dst TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                transport_proto TEXT,
                app_proto TEXT,
                protocols TEXT,
                direction TEXT,
                conversation_key TEXT,
                dns_query_name TEXT,
                http_method TEXT,
                http_host TEXT,
                http_uri TEXT,
                http_response_code TEXT,
                tls_server_name TEXT,
                raw_json TEXT
            )
        """)

        # Migration: Add new columns if older database schema is present
        cursor.execute("PRAGMA table_info(packets)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        columns_to_add = [
            ("dns_query_name", "TEXT"),
            ("http_method", "TEXT"),
            ("http_host", "TEXT"),
            ("http_uri", "TEXT"),
            ("http_response_code", "TEXT"),
            ("tls_server_name", "TEXT"),
            ("raw_json", "TEXT"),
        ]
        for col_name, col_type in columns_to_add:
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE packets ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass

        # Create hosts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                ip TEXT PRIMARY KEY,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                first_seen REAL,
                last_seen REAL,
                is_internal INTEGER
            )
        """)

        # Create conversations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                conversation_key TEXT PRIMARY KEY,
                host1 TEXT,
                host2 TEXT,
                port1 INTEGER,
                port2 INTEGER,
                protocol TEXT,
                packet_count INTEGER DEFAULT 0,
                byte_count INTEGER DEFAULT 0,
                first_seen REAL,
                last_seen REAL
            )
        """)

        # Create indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(ip_src)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(ip_dst)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_conversation ON packets(conversation_key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_app_proto ON packets(app_proto)")

        self.db_conn.commit()

        # Check if cache is already populated
        cached_count = cursor.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        self.cache_exists = cached_count > 0
        logger.info(f"Initialized cache database: {self.cache_db} (cached: {self.cache_exists})")

    def _row_to_packet(self, row: sqlite3.Row) -> ParsedPacket:
        """Convert a database row into a ParsedPacket object."""
        raw_data = {}
        row_keys = row.keys()
        if "raw_json" in row_keys and row["raw_json"]:
            try:
                raw_data = json.loads(row["raw_json"])
            except Exception:
                raw_data = {}

        protocols = row["protocols"].split(",") if row["protocols"] else []
        timestamp = (
            datetime.fromtimestamp(row["timestamp"], tz=timezone.utc)
            if row["timestamp"]
            else datetime.now(timezone.utc)
        )

        return ParsedPacket(
            number=row["number"],
            timestamp=timestamp,
            timestamp_epoch=row["timestamp"] or 0.0,
            length=row["length"] or 0,
            protocols=protocols,
            ip_src=row["ip_src"],
            ip_dst=row["ip_dst"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            transport_proto=row["transport_proto"],
            app_proto=row["app_proto"],
            dns_query_name=row["dns_query_name"] if "dns_query_name" in row_keys else None,
            http_method=row["http_method"] if "http_method" in row_keys else None,
            http_host=row["http_host"] if "http_host" in row_keys else None,
            http_uri=row["http_uri"] if "http_uri" in row_keys else None,
            http_response_code=row["http_response_code"] if "http_response_code" in row_keys else None,
            tls_server_name=row["tls_server_name"] if "tls_server_name" in row_keys else None,
            raw_data=raw_data,
        )

    def _load_packets_from_cache(self, limit: Optional[int] = None) -> List[ParsedPacket]:
        """Reconstruct ParsedPacket objects from SQLite cache database."""
        cursor = self.db_conn.cursor()
        query = "SELECT * FROM packets ORDER BY number ASC"
        if limit:
            query += f" LIMIT {int(limit)}"
        rows = cursor.execute(query).fetchall()
        return [self._row_to_packet(row) for row in rows]

    def set_mode(self, mode: AnalysisMode) -> None:
        """Update active analysis mode."""
        self.mode = mode
        self.mode_config = get_mode_config(mode)
        self.detection_engine = DetectionEngine(mode=mode.value)

    def analyze(self, packet_limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Run full analysis on the capture file.

        Args:
            packet_limit: Optional limit on number of packets to process

        Returns:
            Dictionary containing analysis results
        """
        console.print(f"\n[bold {self.mode_config.color_theme}]{self.mode_config.name}[/] Analysis")
        console.print(f"Target: {self.pcap_path}")
        console.print(f"Focus: {self.mode_config.focus}\n")

        cursor = self.db_conn.cursor()
        cached_count = cursor.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

        if cached_count > 0 and self.cache_exists:
            console.print(f"[green]✓[/] Using cached analysis ({cached_count} packets)")
            self._load_stats_from_cache()

            # Run detection engine on cached packets
            console.print(f"[cyan]Running {self.mode_config.name} detections on cached data...[/]")
            parsed_packets = self._load_packets_from_cache(limit=packet_limit)
            self.detection_engine = DetectionEngine(mode=self.mode.value)
            self.findings = self.detection_engine.analyze_packets(iter(parsed_packets))
            console.print(f"[green]✓[/] Found {len(self.findings)} potential findings")

            return self._generate_results()

        # Get capture info
        capture_info = self.tshark.get_capture_info(self.pcap_path)
        console.print(f"Capture info: {capture_info.get('File type', 'Unknown')}")

        try:
            packet_count = self.tshark.get_packet_count(self.pcap_path)
            console.print(f"Total packets: {packet_count}")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                parse_task = progress.add_task("Processing packets...", total=packet_count)
                parsed_packets = []

                for packet_data in self.tshark.read_packets_json(
                    self.pcap_path, packet_limit=packet_limit
                ):
                    packet = PacketParser.parse_json_packet(packet_data)
                    if packet:
                        self._process_packet(packet)
                        parsed_packets.append(packet)
                        progress.update(parse_task, advance=1)

            self.db_conn.commit()
            self.cache_exists = True
            console.print(f"[green]✓[/] Processed {self.stats['total_packets']} packets")

            # Run detection engine
            console.print(f"[cyan]Running {self.mode_config.name} detections...[/]")
            self.detection_engine = DetectionEngine(mode=self.mode.value)
            self.findings = self.detection_engine.analyze_packets(iter(parsed_packets))
            console.print(f"[green]✓[/] Found {len(self.findings)} potential findings")

            return self._generate_results()

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            console.print(f"[red]✗[/] Analysis failed: {e}")
            raise

    def _process_packet(self, packet: ParsedPacket) -> None:
        """Process and cache a single packet."""
        cursor = self.db_conn.cursor()

        # Update stats
        self.stats["total_packets"] += 1
        self.stats["total_bytes"] += packet.length

        if self.stats["start_time"] is None:
            self.stats["start_time"] = packet.timestamp
        self.stats["end_time"] = packet.timestamp

        # Track hosts
        if packet.ip_src:
            self.stats["unique_hosts"].add(packet.ip_src)
        if packet.ip_dst:
            self.stats["unique_hosts"].add(packet.ip_dst)

        # Track protocols
        if packet.app_proto:
            self.stats["protocols"][packet.app_proto] += 1
        elif packet.transport_proto:
            self.stats["protocols"][packet.transport_proto] += 1

        conv_key = packet.get_conversation_key()
        direction = packet.get_direction()

        # Insert packet into cache with protocol metadata
        cursor.execute(
            """
            INSERT OR REPLACE INTO packets (
                number, timestamp, timestamp_str, length,
                ip_src, ip_dst, src_port, dst_port,
                transport_proto, app_proto, protocols,
                direction, conversation_key,
                dns_query_name, http_method, http_host,
                http_uri, http_response_code, tls_server_name,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet.number,
                packet.timestamp_epoch,
                packet.timestamp.isoformat() if packet.timestamp else "",
                packet.length,
                packet.ip_src,
                packet.ip_dst,
                packet.src_port,
                packet.dst_port,
                packet.transport_proto,
                packet.app_proto,
                ",".join(packet.protocols) if packet.protocols else "",
                direction,
                conv_key,
                packet.dns_query_name,
                packet.http_method,
                packet.http_host,
                packet.http_uri,
                packet.http_response_code,
                packet.tls_server_name,
                json.dumps(packet.raw_data) if packet.raw_data else "{}",
            ),
        )

        # Update host statistics
        if packet.ip_src:
            self._update_host_stats(packet.ip_src, packet, is_source=True)
        if packet.ip_dst:
            self._update_host_stats(packet.ip_dst, packet, is_source=False)

        # Update conversation statistics
        if conv_key:
            self._update_conversation_stats(packet, conv_key)

    def _update_host_stats(self, ip: str, packet: ParsedPacket, is_source: bool) -> None:
        """Update statistics for a host."""
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT * FROM hosts WHERE ip = ?", (ip,))
        existing = cursor.fetchone()

        if existing:
            if is_source:
                cursor.execute(
                    """
                    UPDATE hosts
                    SET packets_sent = packets_sent + 1,
                        bytes_sent = bytes_sent + ?,
                        last_seen = ?
                    WHERE ip = ?
                    """,
                    (packet.length, packet.timestamp_epoch, ip),
                )
            else:
                cursor.execute(
                    """
                    UPDATE hosts
                    SET packets_received = packets_received + 1,
                        bytes_received = bytes_received + ?,
                        last_seen = ?
                    WHERE ip = ?
                    """,
                    (packet.length, packet.timestamp_epoch, ip),
                )
        else:
            is_internal = 1 if packet.is_internal_ip(ip) else 0
            cursor.execute(
                """
                INSERT INTO hosts (
                    ip, packets_sent, packets_received,
                    bytes_sent, bytes_received,
                    first_seen, last_seen, is_internal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ip,
                    1 if is_source else 0,
                    0 if is_source else 1,
                    packet.length if is_source else 0,
                    0 if is_source else packet.length,
                    packet.timestamp_epoch,
                    packet.timestamp_epoch,
                    is_internal,
                ),
            )

    @staticmethod
    def _parse_conversation_endpoints(
        conv_key: str,
    ) -> Tuple[str, str, Optional[int], Optional[int]]:
        """Safely parse endpoints and ports from a conversation key without throwing ValueError."""
        try:
            parts = conv_key.replace("<->", "|").split("|")
            if len(parts) < 2:
                return (conv_key, "", None, None)

            has_proto_suffix = bool("(" in parts[1] and parts[1].endswith(")"))

            def _parse_endpoint(ep_str: str, expect_port: bool = True) -> Tuple[str, Optional[int]]:
                ep_str = ep_str.strip()
                if "(" in ep_str and ep_str.endswith(")"):
                    ep_str = ep_str[: ep_str.rfind("(")].strip()
                if not ep_str:
                    return ("", None)

                # Bracketed IPv6: [fe80::1]:5353 or [fe80::1]
                if ep_str.startswith("[") and "]" in ep_str:
                    close_b = ep_str.rfind("]")
                    host = ep_str[1:close_b]
                    rem = ep_str[close_b + 1 :].strip()
                    port = None
                    if rem.startswith(":"):
                        port_str = rem[1:].strip()
                        if port_str.isdigit():
                            port = int(port_str)
                    return (host, port)

                if expect_port and ":" in ep_str:
                    host_part, port_part = ep_str.rsplit(":", 1)
                    if port_part.isdigit() and 0 <= int(port_part) <= 65535:
                        return (host_part, int(port_part))
                    return (ep_str, None)

                return (ep_str, None)

            host1, port1 = _parse_endpoint(parts[0], expect_port=has_proto_suffix)
            host2, port2 = _parse_endpoint(parts[1], expect_port=has_proto_suffix)
            return (host1, host2, port1, port2)
        except Exception:
            return (conv_key, "", None, None)

    def _update_conversation_stats(self, packet: ParsedPacket, conv_key: str) -> None:
        """Update statistics for a conversation."""
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT * FROM conversations WHERE conversation_key = ?", (conv_key,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """
                UPDATE conversations
                SET packet_count = packet_count + 1,
                    byte_count = byte_count + ?,
                    last_seen = ?
                WHERE conversation_key = ?
                """,
                (packet.length, packet.timestamp_epoch, conv_key),
            )
        else:
            if packet.ip_src and packet.ip_dst:
                endpoints = sorted(
                    [
                        (packet.ip_src, packet.src_port if packet.src_port is not None else -1),
                        (packet.ip_dst, packet.dst_port if packet.dst_port is not None else -1),
                    ]
                )
                host1 = endpoints[0][0]
                port1 = endpoints[0][1] if endpoints[0][1] >= 0 else None
                host2 = endpoints[1][0]
                port2 = endpoints[1][1] if endpoints[1][1] >= 0 else None
            else:
                host1, host2, port1, port2 = self._parse_conversation_endpoints(conv_key)

            cursor.execute(
                """
                INSERT INTO conversations (
                    conversation_key, host1, host2, port1, port2,
                    protocol, packet_count, byte_count,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    conv_key,
                    host1,
                    host2,
                    port1,
                    port2,
                    packet.transport_proto,
                    1,
                    packet.length,
                    packet.timestamp_epoch,
                    packet.timestamp_epoch,
                ),
            )

    def _load_stats_from_cache(self) -> None:
        """Load statistics from SQLite cache database."""
        cursor = self.db_conn.cursor()
        result = cursor.execute("SELECT COUNT(*), SUM(length) FROM packets").fetchone()
        self.stats["total_packets"] = result[0]
        self.stats["total_bytes"] = result[1] or 0

        result = cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM packets").fetchone()
        if result[0]:
            self.stats["start_time"] = datetime.fromtimestamp(result[0], tz=timezone.utc)
            self.stats["end_time"] = datetime.fromtimestamp(result[1], tz=timezone.utc)
            self.stats["duration"] = result[1] - result[0]

        hosts = cursor.execute("SELECT ip FROM hosts").fetchall()
        self.stats["unique_hosts"] = {row[0] for row in hosts}

        protocols = cursor.execute(
            """
            SELECT CASE WHEN app_proto IS NOT NULL AND app_proto != '' THEN app_proto ELSE transport_proto END as proto,
                   COUNT(*)
            FROM packets
            WHERE (app_proto IS NOT NULL AND app_proto != '') OR transport_proto IS NOT NULL
            GROUP BY proto
            """
        ).fetchall()
        self.stats["protocols"] = {row[0]: row[1] for row in protocols}

    def _generate_results(self) -> Dict[str, Any]:
        """Generate final structured analysis results."""
        if self.stats["start_time"] and self.stats["end_time"]:
            duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()
        else:
            duration = 0.0

        results: Dict[str, Any] = {
            "mode": self.mode.value,
            "pcap_file": str(self.pcap_path),
            "total_packets": self.stats["total_packets"],
            "total_bytes": self.stats["total_bytes"],
            "start_time": self.stats["start_time"].isoformat() if self.stats["start_time"] else None,
            "end_time": self.stats["end_time"].isoformat() if self.stats["end_time"] else None,
            "duration_seconds": duration,
            "unique_hosts": len(self.stats["unique_hosts"]),
            "protocols": dict(self.stats["protocols"]),
        }

        if self.findings:
            results["findings"] = [finding.to_dict() for finding in self.findings]
            results["findings_count"] = len(self.findings)
            results["findings_by_severity"] = self._group_findings_by_severity()
        else:
            results["findings"] = []
            results["findings_count"] = 0
            results["findings_by_severity"] = {}

        return results

    def _group_findings_by_severity(self) -> Dict[str, int]:
        """Group findings by severity level."""
        from collections import Counter
        severities = Counter(finding.severity.value for finding in self.findings)
        return dict(severities)

    # -------------------------------------------------------------------------
    # High-Performance Query & Inspection APIs for GUI & CLI
    # -------------------------------------------------------------------------

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
        """Fetch paginated, filtered packets directly from SQLite cache."""
        cursor = self.db_conn.cursor()
        conditions = []
        params = []

        if protocol:
            conditions.append("(LOWER(app_proto) = ? OR LOWER(transport_proto) = ?)")
            params.extend([protocol.lower(), protocol.lower()])
        if direction:
            conditions.append("LOWER(direction) = ?")
            params.append(direction.lower())
        if ip:
            conditions.append("(ip_src = ? OR ip_dst = ?)")
            params.extend([ip, ip])
        if search:
            search_pattern = f"%{search}%"
            conditions.append(
                "(ip_src LIKE ? OR ip_dst LIKE ? OR app_proto LIKE ? OR transport_proto LIKE ? OR dns_query_name LIKE ? OR http_host LIKE ? OR http_uri LIKE ?)"
            )
            params.extend([search_pattern] * 7)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        allowed_sort = {"number", "timestamp", "length", "ip_src", "ip_dst", "app_proto"}
        sort_col = sort_by if sort_by in allowed_sort else "number"
        sort_direction = "DESC" if sort_dir.lower() == "desc" else "ASC"

        total = cursor.execute(f"SELECT COUNT(*) FROM packets {where_clause}", params).fetchone()[0]
        query = f"SELECT * FROM packets {where_clause} ORDER BY {sort_col} {sort_direction} LIMIT ? OFFSET ?"
        rows = cursor.execute(query, params + [limit, offset]).fetchall()

        packets = []
        for row in rows:
            row_keys = row.keys()
            packets.append({
                "number": row["number"],
                "timestamp": row["timestamp_str"],
                "length": row["length"],
                "ip_src": row["ip_src"],
                "ip_dst": row["ip_dst"],
                "src_port": row["src_port"],
                "dst_port": row["dst_port"],
                "transport_proto": row["transport_proto"],
                "app_proto": row["app_proto"],
                "protocols": row["protocols"].split(",") if row["protocols"] else [],
                "direction": row["direction"],
                "conversation_key": row["conversation_key"],
                "dns_query_name": row["dns_query_name"] if "dns_query_name" in row_keys else None,
                "http_method": row["http_method"] if "http_method" in row_keys else None,
                "http_host": row["http_host"] if "http_host" in row_keys else None,
                "http_uri": row["http_uri"] if "http_uri" in row_keys else None,
                "http_response_code": row["http_response_code"] if "http_response_code" in row_keys else None,
                "tls_server_name": row["tls_server_name"] if "tls_server_name" in row_keys else None,
            })

        return {
            "packets": packets,
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    def get_packet_detail(self, packet_number: int) -> Optional[Dict[str, Any]]:
        """Deep inspection of a single packet with correlated findings."""
        from beacon.analysis.packet_inspector import PacketInspector

        cursor = self.db_conn.cursor()
        row = cursor.execute("SELECT * FROM packets WHERE number = ?", (packet_number,)).fetchone()
        if not row:
            return None

        packet = self._row_to_packet(row)
        detail = PacketInspector.inspect(packet)

        # Correlate findings
        correlated_findings = []
        for finding in self.findings:
            f_dict = finding.to_dict()
            if packet_number in getattr(finding, "related_packets", []):
                correlated_findings.append(f_dict)
            elif finding.source_ip == packet.ip_src and (not finding.destination_ip or finding.destination_ip == packet.ip_dst):
                correlated_findings.append(f_dict)

        detail["findings"] = correlated_findings
        detail["conversation_key"] = row["conversation_key"]
        detail["number"] = packet_number
        return detail

    def get_timeline_events(self) -> List[Dict[str, Any]]:
        """Get chronological timeline events."""
        from beacon.analysis.timeline import TimelineBuilder

        packets = self._load_packets_from_cache()
        events = TimelineBuilder.build(packets)
        return [event.to_dict() for event in events]

    def get_iocs(self) -> List[Dict[str, Any]]:
        """Get extracted network IOCs."""
        from beacon.analysis.ioc_extractor import IOCExtractor

        packets = self._load_packets_from_cache()
        iocs = IOCExtractor.extract(packets)
        return [ioc.to_dict() for ioc in iocs]

    def get_network_graph(self, max_nodes: int = 50) -> Dict[str, Any]:
        """Generate network topology graph nodes and edges for visualization."""
        cursor = self.db_conn.cursor()
        hosts_rows = cursor.execute(
            "SELECT * FROM hosts ORDER BY bytes_sent + bytes_received DESC LIMIT ?", (max_nodes,)
        ).fetchall()

        host_ips = {row["ip"] for row in hosts_rows}
        nodes = []
        for row in hosts_rows:
            ip = row["ip"]
            is_mcast = False
            is_v6 = False
            try:
                ip_obj = ip_address(ip)
                is_mcast = ip_obj.is_multicast
                is_v6 = ip_obj.version == 6
            except ValueError:
                pass

            host_findings = [f.to_dict() for f in self.findings if f.source_ip == ip or f.destination_ip == ip]
            max_severity = "info"
            if any(f["severity"] == "critical" for f in host_findings):
                max_severity = "critical"
            elif any(f["severity"] == "high" for f in host_findings):
                max_severity = "high"
            elif any(f["severity"] == "medium" for f in host_findings):
                max_severity = "medium"
            elif any(f["severity"] == "low" for f in host_findings):
                max_severity = "low"

            nodes.append({
                "id": ip,
                "label": ip,
                "is_internal": bool(row["is_internal"]),
                "is_multicast": is_mcast,
                "is_ipv6": is_v6,
                "packets_sent": row["packets_sent"],
                "packets_received": row["packets_received"],
                "total_bytes": row["bytes_sent"] + row["bytes_received"],
                "findings_count": len(host_findings),
                "severity": max_severity,
            })

        conv_rows = cursor.execute(
            "SELECT * FROM conversations ORDER BY byte_count DESC LIMIT 100"
        ).fetchall()

        edges = []
        for row in conv_rows:
            if row["host1"] in host_ips and row["host2"] in host_ips:
                edges.append({
                    "id": row["conversation_key"],
                    "source": row["host1"],
                    "target": row["host2"],
                    "protocol": row["protocol"] or "unknown",
                    "packet_count": row["packet_count"],
                    "byte_count": row["byte_count"],
                    "port1": row["port1"],
                    "port2": row["port2"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                })

        return {"nodes": nodes, "edges": edges}

    def get_evidence_graph(
        self,
        max_nodes: int = 60,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate multi-entity investigation graph.
        Entities:
          - 'host': Communicating hosts
          - 'domain': Queried DNS domains, HTTP hosts, TLS SNIs
          - 'finding': Security findings
        Edges:
          - 'traffic': Host <-> Host
          - 'resolution': Host -> Domain
          - 'alert': Finding -> Host
        """
        cursor = self.db_conn.cursor()

        # 1. Hosts
        hosts_rows = cursor.execute(
            "SELECT * FROM hosts ORDER BY bytes_sent + bytes_received DESC LIMIT ?", (max(10, max_nodes // 2),)
        ).fetchall()

        host_nodes = []
        host_ips = set()
        active_findings = findings if findings is not None else [f.to_dict() for f in self.findings]

        for row in hosts_rows:
            ip = row["ip"]
            host_ips.add(ip)
            is_mcast = False
            is_v6 = False
            try:
                ip_obj = ip_address(ip)
                is_mcast = ip_obj.is_multicast
                is_v6 = ip_obj.version == 6
            except ValueError:
                pass

            h_findings = [f for f in active_findings if f.get("source_ip") == ip or f.get("destination_ip") == ip]
            max_sev = "info"
            for sev in ["critical", "high", "medium", "low"]:
                if any(f.get("severity") == sev for f in h_findings):
                    max_sev = sev
                    break

            host_nodes.append({
                "id": ip,
                "label": ip,
                "type": "host",
                "is_internal": bool(row["is_internal"]),
                "is_multicast": is_mcast,
                "is_ipv6": is_v6,
                "packets_sent": row["packets_sent"],
                "packets_received": row["packets_received"],
                "total_bytes": row["bytes_sent"] + row["bytes_received"],
                "findings_count": len(h_findings),
                "severity": max_sev,
            })

        nodes = list(host_nodes)
        edges = []

        # 2. Domains (DNS, TLS, HTTP)
        domain_queries = cursor.execute(
            """
            SELECT DISTINCT dns_query_name as domain, ip_src, COUNT(*) as cnt
            FROM packets
            WHERE dns_query_name IS NOT NULL AND dns_query_name != ''
            GROUP BY dns_query_name, ip_src
            LIMIT 25
            """
        ).fetchall()

        seen_domains = set()
        for r in domain_queries:
            dom = r["domain"]
            src = r["ip_src"]
            if dom not in seen_domains:
                seen_domains.add(dom)
                dom_sev = "high" if any(dom.lower() in str(f.get("evidence", [])).lower() or dom.lower() in f.get("title", "").lower() for f in active_findings) else "info"
                nodes.append({
                    "id": f"domain:{dom}",
                    "label": dom,
                    "domain": dom,
                    "type": "domain",
                    "severity": dom_sev,
                    "query_count": r["cnt"],
                })

            if src in host_ips or src:
                edges.append({
                    "id": f"edge_dns_{src}_{dom}",
                    "source": src,
                    "target": f"domain:{dom}",
                    "type": "resolution",
                    "protocol": "DNS",
                    "label": "DNS Query",
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
        conv_rows = cursor.execute(
            "SELECT * FROM conversations ORDER BY byte_count DESC LIMIT 50"
        ).fetchall()
        for row in conv_rows:
            if row["host1"] in host_ips and row["host2"] in host_ips:
                edges.append({
                    "id": row["conversation_key"],
                    "source": row["host1"],
                    "target": row["host2"],
                    "type": "traffic",
                    "protocol": row["protocol"] or "unknown",
                    "packet_count": row["packet_count"],
                    "byte_count": row["byte_count"],
                    "port1": row["port1"],
                    "port2": row["port2"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                })

        return {"nodes": nodes, "edges": edges}

    def get_investigation_storyline(
        self,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Build an investigation storyline summarizing chronological milestones across the capture.
        Phases:
          - RECONNAISSANCE: Scanning, discovery, enumeration
          - RESOLUTION: DNS domain lookups
          - CONNECTION: Handshakes and administrative sessions
          - EXPOSURE: Cleartext credentials, unencrypted secrets
          - COMMAND_AND_CONTROL: Periodic beacons, outbound callbacks
          - LATERAL_MOVEMENT: Internal pivots, SSH/SMB connections
          - ANOMALY: Abnormal packets, resets, spikes
        """
        cursor = self.db_conn.cursor()
        milestones: List[Dict[str, Any]] = []
        active_findings = findings if findings is not None else [f.to_dict() for f in self.findings]

        # 1. Findings converted to story milestones
        for idx, f in enumerate(active_findings):
            title = f.get("title", "")
            cat = f.get("category", "").lower()
            phase = "ANOMALY"
            if "scan" in title.lower() or "scan" in cat or "sweep" in title.lower():
                phase = "RECONNAISSANCE"
            elif "cleartext" in title.lower() or "token" in title.lower() or "credential" in title.lower() or "auth" in title.lower():
                phase = "EXPOSURE"
            elif "beacon" in title.lower() or "c2" in title.lower() or "command" in title.lower():
                phase = "COMMAND_AND_CONTROL"
            elif "internal" in title.lower() or "lateral" in title.lower() or "ssh" in title.lower() or "smb" in title.lower():
                phase = "LATERAL_MOVEMENT"

            ts = f.get("first_seen") or f.get("timestamp")
            epoch = 0.0
            if ts:
                try:
                    epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                except Exception:
                    epoch = 0.0
            elif f.get("related_packets"):
                first_pkt = f["related_packets"][0]
                row = cursor.execute("SELECT timestamp, timestamp_str FROM packets WHERE number = ?", (first_pkt,)).fetchone()
                if row and row[0]:
                    epoch = row[0]
                    ts = row[1] or datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

            milestones.append({
                "id": f"story_finding_{idx}",
                "phase": phase,
                "timestamp": ts or "0000-00-00T00:00:00Z",
                "timestamp_epoch": epoch,
                "title": title,
                "summary": f.get("description", ""),
                "packet_numbers": f.get("related_packets", []),
                "source_ip": f.get("source_ip"),
                "destination_ip": f.get("destination_ip"),
                "protocol": f.get("protocol"),
                "severity": f.get("severity", "medium"),
                "confidence": f.get("confidence", "high"),
                "evidence": f.get("evidence", []),
                "next_step": f.get("next_step", ""),
                "is_finding": True,
            })

        # 2. DNS query events
        dns_rows = cursor.execute(
            """
            SELECT MIN(number) as number, MIN(timestamp) as timestamp, MIN(timestamp_str) as timestamp_str,
                   ip_src, ip_dst, dns_query_name
            FROM packets
            WHERE dns_query_name IS NOT NULL AND dns_query_name != ''
            GROUP BY dns_query_name, ip_src
            ORDER BY number ASC
            LIMIT 20
            """
        ).fetchall()
        for r in dns_rows:
            qname = r["dns_query_name"]
            src = r["ip_src"]
            dst = r["ip_dst"]
            pkt = r["number"]
            ts = r["timestamp_str"]
            epoch = r["timestamp"] or 0.0

            has_finding = any(qname.lower() in str(f.get("evidence", [])).lower() or qname.lower() in f.get("title", "").lower() for f in active_findings)

            milestones.append({
                "id": f"story_dns_{pkt}",
                "phase": "RESOLUTION",
                "timestamp": ts,
                "timestamp_epoch": epoch,
                "title": f"DNS Resolution: {qname}",
                "summary": f"Host {src} initiated domain resolution for '{qname}' via DNS server {dst}",
                "packet_numbers": [pkt],
                "source_ip": src,
                "destination_ip": dst,
                "protocol": "DNS",
                "severity": "high" if has_finding else "info",
                "confidence": "high",
                "evidence": [f"Query: {qname}", f"DNS Server: {dst}"],
                "next_step": "Investigate destination IP resolution and subsequent connection attempts" if has_finding else "Verify if domain is in company baseline",
                "is_finding": False,
            })

        # 3. HTTP Transactions
        http_rows = cursor.execute(
            """
            SELECT number, timestamp, timestamp_str, ip_src, ip_dst, http_method, http_host, http_uri, http_response_code
            FROM packets
            WHERE http_method IS NOT NULL AND http_method != ''
            ORDER BY number ASC
            LIMIT 25
            """
        ).fetchall()
        for r in http_rows:
            uri = r["http_uri"] or ""
            host = r["http_host"] or r["ip_dst"]
            method = r["http_method"]
            src = r["ip_src"]
            dst = r["ip_dst"]
            pkt = r["number"]
            epoch = r["timestamp"] or 0.0
            ts = r["timestamp_str"]
            is_auth = any(k in uri.lower() for k in ["login", "token", "auth", "pass", "user", "secret"])

            milestones.append({
                "id": f"story_http_{pkt}",
                "phase": "EXPOSURE" if is_auth else "CONNECTION",
                "timestamp": ts,
                "timestamp_epoch": epoch,
                "title": f"HTTP {method} {uri[:40]}{'...' if len(uri) > 40 else ''}",
                "summary": f"Host {src} transmitted HTTP {method} request to {host} ({dst})",
                "packet_numbers": [pkt],
                "source_ip": src,
                "destination_ip": dst,
                "protocol": "HTTP",
                "severity": "high" if is_auth else "info",
                "confidence": "high",
                "evidence": [f"Method: {method}", f"Host: {host}", f"URI: {uri}"],
                "next_step": "Inspect request query parameters and headers for exposed credentials or sensitive tokens",
                "is_finding": False,
            })

        # 4. Service Sessions (SSH, FTP, etc.)
        service_rows = cursor.execute(
            """
            SELECT MIN(number) as number, MIN(timestamp) as timestamp, MIN(timestamp_str) as timestamp_str,
                   ip_src, ip_dst, src_port, dst_port, app_proto
            FROM packets
            WHERE LOWER(app_proto) IN ('ssh', 'ftp', 'telnet', 'smb', 'rdp')
            GROUP BY conversation_key
            ORDER BY number ASC
            LIMIT 15
            """
        ).fetchall()
        for r in service_rows:
            proto = (r["app_proto"] or "service").upper()
            src = r["ip_src"]
            dst = r["ip_dst"]
            pkt = r["number"]
            epoch = r["timestamp"] or 0.0
            ts = r["timestamp_str"]

            milestones.append({
                "id": f"story_service_{pkt}",
                "phase": "LATERAL_MOVEMENT",
                "timestamp": ts,
                "timestamp_epoch": epoch,
                "title": f"{proto} Session Established",
                "summary": f"Administrative {proto} connection initiated from {src}:{r['src_port']} to {dst}:{r['dst_port']}",
                "packet_numbers": [pkt],
                "source_ip": src,
                "destination_ip": dst,
                "protocol": proto,
                "severity": "medium",
                "confidence": "high",
                "evidence": [f"Service: {proto}", f"Source Port: {r['src_port']}", f"Target Port: {r['dst_port']}"],
                "next_step": f"Verify whether administrative {proto} access between these endpoints is expected",
                "is_finding": False,
            })

        milestones.sort(key=lambda m: (m["timestamp_epoch"], m["packet_numbers"][0] if m["packet_numbers"] else 0))
        return milestones

    def get_conversation_stream(
        self,
        conversation_key: str,
        limit: int = 150,
    ) -> Dict[str, Any]:
        """
        Reconstruct chronological message stream and payload turns for a conversation.
        """
        cursor = self.db_conn.cursor()

        rows = cursor.execute(
            "SELECT * FROM packets WHERE conversation_key = ? ORDER BY number ASC LIMIT ?",
            (conversation_key, limit),
        ).fetchall()

        if not rows:
            h1, h2, p1, p2 = self._parse_conversation_endpoints(conversation_key)
            if h1 and h2:
                rows = cursor.execute(
                    """
                    SELECT * FROM packets
                    WHERE (ip_src = ? AND ip_dst = ?) OR (ip_src = ? AND ip_dst = ?)
                    ORDER BY number ASC
                    LIMIT ?
                    """,
                    (h1, h2, h2, h1, limit),
                ).fetchall()

        if not rows:
            return {
                "conversation_key": conversation_key,
                "total_messages": 0,
                "client": "",
                "server": "",
                "turns": [],
            }

        client_ip = rows[0]["ip_src"]
        client_port = rows[0]["src_port"]
        server_ip = rows[0]["ip_dst"]
        server_port = rows[0]["dst_port"]

        client_label = f"{client_ip}:{client_port}" if client_port is not None else client_ip
        server_label = f"{server_ip}:{server_port}" if server_port is not None else server_ip

        turns = []
        for row in rows:
            is_client = (row["ip_src"] == client_ip)
            direction = "client_to_server" if is_client else "server_to_client"

            proto = row["app_proto"] or row["transport_proto"] or "RAW"
            summary = ""
            payload_lines = []

            if row["http_method"]:
                summary = f"{row['http_method']} {row['http_uri'] or '/'}"
            elif row["http_response_code"]:
                summary = f"HTTP {row['http_response_code']}"
            elif row["dns_query_name"]:
                summary = f"DNS Query: {row['dns_query_name']}"
            elif proto.lower() == "tcp":
                summary = f"TCP segment ({row['length']} bytes)"
            else:
                summary = f"{proto.upper()} ({row['length']} bytes)"

            if row["raw_json"]:
                try:
                    data = json.loads(row["raw_json"])
                    layers = data.get("layers") or data.get("_source", {}).get("layers", {})

                    if "http" in layers:
                        h = layers["http"]
                        for k, v in h.items():
                            if "request_line" in k or "line" in k or k == "text":
                                if isinstance(v, list):
                                    payload_lines.extend(str(item).strip() for item in v if item)
                                elif isinstance(v, str):
                                    payload_lines.append(v.strip())
                        if not payload_lines and row["http_uri"]:
                            payload_lines.append(f"{row['http_method']} {row['http_uri']} HTTP/1.1")
                            if row["http_host"]:
                                payload_lines.append(f"Host: {row['http_host']}")
                    elif "dns" in layers:
                        d = layers["dns"]
                        if row["dns_query_name"]:
                            payload_lines.append(f"Query: {row['dns_query_name']}")
                        for k, v in d.items():
                            if "rr.data" in k or "answers" in k or "resp" in k:
                                payload_lines.append(f"Answer: {v}")
                    elif "data" in layers:
                        payload_lines.append(f"Data payload ({row['length']} bytes)")
                except Exception:
                    pass

            payload_str = "\n".join(payload_lines) if payload_lines else f"{proto} payload ({row['length']} bytes)"
            raw_bytes = payload_str.encode("utf-8", errors="replace")[:128]

            hex_lines = []
            for i in range(0, len(raw_bytes), 16):
                chunk = raw_bytes[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(48)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                hex_lines.append(f"{i:04x}  {hex_part}  |{ascii_part}|")

            turns.append({
                "number": row["number"],
                "timestamp": row["timestamp_str"],
                "direction": direction,
                "sender": client_label if is_client else server_label,
                "receiver": server_label if is_client else client_label,
                "protocol": proto.upper(),
                "length": row["length"],
                "summary": summary,
                "payload_lines": payload_lines,
                "hex_dump": "\n".join(hex_lines),
            })

        return {
            "conversation_key": conversation_key,
            "total_messages": len(turns),
            "client": client_label,
            "server": server_label,
            "turns": turns,
        }

    @staticmethod
    def compare_analyses(baseline: Dict[str, Any], target: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare target analysis against a baseline capture.
        Identifies traffic drift, new hosts, resolved/new findings, and protocol changes.
        """
        b_metrics = {
            "total_packets": baseline.get("total_packets", 0),
            "total_bytes": baseline.get("total_bytes", 0),
            "duration_seconds": baseline.get("duration_seconds", 0.0),
            "unique_hosts": baseline.get("unique_hosts", 0),
            "findings_count": baseline.get("findings_count", len(baseline.get("findings", []))),
        }
        t_metrics = {
            "total_packets": target.get("total_packets", 0),
            "total_bytes": target.get("total_bytes", 0),
            "duration_seconds": target.get("duration_seconds", 0.0),
            "unique_hosts": target.get("unique_hosts", 0),
            "findings_count": target.get("findings_count", len(target.get("findings", []))),
        }

        diff_metrics = {
            "packets_delta": t_metrics["total_packets"] - b_metrics["total_packets"],
            "bytes_delta": t_metrics["total_bytes"] - b_metrics["total_bytes"],
            "duration_delta": t_metrics["duration_seconds"] - b_metrics["duration_seconds"],
            "hosts_delta": t_metrics["unique_hosts"] - b_metrics["unique_hosts"],
            "findings_delta": t_metrics["findings_count"] - b_metrics["findings_count"],
        }

        b_hosts = {h["ip"]: h for h in baseline.get("hosts", [])}
        t_hosts = {h["ip"]: h for h in target.get("hosts", [])}

        new_hosts = [t_hosts[ip] for ip in t_hosts if ip not in b_hosts]
        removed_hosts = [b_hosts[ip] for ip in b_hosts if ip not in t_hosts]

        common_hosts = []
        for ip in t_hosts:
            if ip in b_hosts:
                t_vol = t_hosts[ip].get("bytes_sent", 0) + t_hosts[ip].get("bytes_received", 0)
                b_vol = b_hosts[ip].get("bytes_sent", 0) + b_hosts[ip].get("bytes_received", 0)
                common_hosts.append({
                    "ip": ip,
                    "target_bytes": t_vol,
                    "baseline_bytes": b_vol,
                    "delta_bytes": t_vol - b_vol,
                })

        b_findings_map = {f.get("title", ""): f for f in baseline.get("findings", [])}
        t_findings_map = {f.get("title", ""): f for f in target.get("findings", [])}

        new_findings = [t_findings_map[title] for title in t_findings_map if title not in b_findings_map]
        resolved_findings = [b_findings_map[title] for title in b_findings_map if title not in t_findings_map]

        b_protos = set(baseline.get("protocols", {}).keys())
        t_protos = set(target.get("protocols", {}).keys())
        new_protocols = sorted(list(t_protos - b_protos))
        removed_protocols = sorted(list(b_protos - t_protos))

        return {
            "baseline_summary": b_metrics,
            "target_summary": t_metrics,
            "metrics_delta": diff_metrics,
            "new_hosts": new_hosts,
            "removed_hosts": removed_hosts,
            "common_hosts": sorted(common_hosts, key=lambda x: abs(x["delta_bytes"]), reverse=True)[:20],
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "new_protocols": new_protocols,
            "removed_protocols": removed_protocols,
        }

    def global_search(self, query: str, limit: int = 30) -> Dict[str, Any]:
        """Search across hosts, conversations, packets, and findings."""
        q = query.strip()
        if not q:
            return {"hosts": [], "conversations": [], "packets": [], "findings": []}

        pattern = f"%{q}%"
        cursor = self.db_conn.cursor()

        h_rows = cursor.execute(
            "SELECT * FROM hosts WHERE ip LIKE ? ORDER BY bytes_sent + bytes_received DESC LIMIT ?",
            (pattern, limit),
        ).fetchall()
        matching_hosts = [
            {"ip": r["ip"], "is_internal": bool(r["is_internal"]), "total_bytes": r["bytes_sent"] + r["bytes_received"]}
            for r in h_rows
        ]

        c_rows = cursor.execute(
            "SELECT * FROM conversations WHERE conversation_key LIKE ? OR host1 LIKE ? OR host2 LIKE ? ORDER BY byte_count DESC LIMIT ?",
            (pattern, pattern, pattern, limit),
        ).fetchall()
        matching_convs = [
            {"key": r["conversation_key"], "host1": r["host1"], "host2": r["host2"], "protocol": r["protocol"]}
            for r in c_rows
        ]

        p_rows = cursor.execute(
            """
            SELECT number, timestamp_str, ip_src, ip_dst, app_proto, transport_proto, dns_query_name, http_host, http_uri
            FROM packets
            WHERE ip_src LIKE ? OR ip_dst LIKE ? OR app_proto LIKE ? OR transport_proto LIKE ? OR dns_query_name LIKE ? OR http_host LIKE ? OR http_uri LIKE ?
            ORDER BY number ASC
            LIMIT ?
            """,
            (pattern, pattern, pattern, pattern, pattern, pattern, pattern, limit),
        ).fetchall()
        matching_packets = [
            {
                "number": r["number"],
                "timestamp": r["timestamp_str"],
                "src": r["ip_src"],
                "dst": r["ip_dst"],
                "protocol": r["app_proto"] or r["transport_proto"],
            }
            for r in p_rows
        ]

        matching_findings = [
            f.to_dict()
            for f in self.findings
            if q.lower() in f.title.lower() or q.lower() in f.description.lower() or (f.source_ip and q in f.source_ip)
        ][:limit]

        return {
            "hosts": matching_hosts,
            "conversations": matching_convs,
            "packets": matching_packets,
            "findings": matching_findings,
        }

    def record_to_memory(self, capture_id: Optional[str] = None, notes: Optional[str] = None) -> None:
        """Record current capture's compact metadata to Beacon Memory historical baseline."""
        from beacon.memory.store import MemoryStore
        store = MemoryStore(db_path=self.cache_dir / "beacon_memory.db")
        cap_id = capture_id or f"cap_{self.pcap_path.stem}"
        cursor = self.db_conn.cursor()

        hosts_rows = cursor.execute("SELECT * FROM hosts").fetchall()
        hosts = [
            {
                "ip": r["ip"],
                "is_internal": bool(r["is_internal"]),
                "packets_sent": r["packets_sent"],
                "packets_received": r["packets_received"],
                "bytes_sent": r["bytes_sent"],
                "bytes_received": r["bytes_received"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in hosts_rows
        ]

        conv_rows = cursor.execute("SELECT * FROM conversations").fetchall()
        convs = [
            {
                "conversation_key": r["conversation_key"],
                "host1": r["host1"],
                "host2": r["host2"],
                "port1": r["port1"],
                "port2": r["port2"],
                "protocol": r["protocol"],
                "packet_count": r["packet_count"],
                "byte_count": r["byte_count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in conv_rows
        ]

        iocs = self.get_iocs()

        results_payload = {
            **self._generate_results(),
            "hosts": hosts,
            "conversations": convs,
            "iocs": iocs,
            "start_time": self.stats["start_time"].timestamp() if self.stats.get("start_time") else None,
            "end_time": self.stats["end_time"].timestamp() if self.stats.get("end_time") else None,
        }

        return store.record_capture(
            capture_id=cap_id,
            filename=self.pcap_path.name,
            results=results_payload,
            notes=notes,
        )

    def get_memory_briefing(self, capture_id: Optional[str] = None) -> Dict[str, Any]:
        """Compute explainable change briefing against Beacon Memory baseline."""
        from beacon.memory.store import MemoryStore
        from beacon.memory.detector import ChangeDetector
        store = MemoryStore(db_path=self.cache_dir / "beacon_memory.db")
        detector = ChangeDetector(store)

        cursor = self.db_conn.cursor()
        hosts_rows = cursor.execute("SELECT * FROM hosts").fetchall()
        hosts = [
            {
                "ip": r["ip"],
                "is_internal": bool(r["is_internal"]),
                "packets_sent": r["packets_sent"],
                "packets_received": r["packets_received"],
                "bytes_sent": r["bytes_sent"],
                "bytes_received": r["bytes_received"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in hosts_rows
        ]

        conv_rows = cursor.execute("SELECT * FROM conversations").fetchall()
        convs = [
            {
                "conversation_key": r["conversation_key"],
                "host1": r["host1"],
                "host2": r["host2"],
                "port1": r["port1"],
                "port2": r["port2"],
                "protocol": r["protocol"],
                "packet_count": r["packet_count"],
                "byte_count": r["byte_count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in conv_rows
        ]

        iocs = self.get_iocs()
        cap_id = capture_id or f"cap_{self.pcap_path.stem}"

        results_payload = {
            **self._generate_results(),
            "hosts": hosts,
            "conversations": convs,
            "iocs": iocs,
            "start_time": self.stats["start_time"].timestamp() if self.stats.get("start_time") else None,
            "end_time": self.stats["end_time"].timestamp() if self.stats.get("end_time") else None,
        }

        briefing = detector.detect_changes(
            current_results=results_payload,
            capture_id=cap_id,
            filename=self.pcap_path.name,
            exclude_current_id=capture_id,
        )
        return briefing.to_dict()

    def close(self) -> None:
        """Close database connections and cleanup."""
        if hasattr(self, "db_conn"):
            self.db_conn.close()

    def __enter__(self) -> AnalysisEngine:
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()
