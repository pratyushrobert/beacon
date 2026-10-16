"""Local-first SQLite storage for Beacon Memory baseline metadata and analyst feedback."""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from beacon.memory.models import AnalystFeedbackRecord, BaselineHealth, FeedbackStatus

logger = logging.getLogger(__name__)


class MemoryStore:
    """
    Manages persistent, capture-linked historical network profiles and baselines.
    Stores compact telemetry without replicating raw packet payloads.
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize MemoryStore.
        Default database location: cache/beacon_memory.db
        """
        if db_path is None:
            from beacon.utils.paths import get_beacon_cache_dir
            db_path = get_beacon_cache_dir() / "beacon_memory.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        """Create baseline and memory tracking tables if not present."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_captures (
                    capture_id TEXT PRIMARY KEY,
                    filename TEXT,
                    sha256 TEXT,
                    analyzed_at REAL,
                    first_packet_time REAL,
                    last_packet_time REAL,
                    duration_seconds REAL,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    unique_hosts INTEGER,
                    internal_subnets TEXT,
                    mode TEXT,
                    notes TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_hosts (
                    ip TEXT PRIMARY KEY,
                    is_internal BOOLEAN,
                    first_seen_time REAL,
                    last_seen_time REAL,
                    first_capture_id TEXT,
                    last_capture_id TEXT,
                    captures_observed_count INTEGER DEFAULT 1,
                    total_packets_sent INTEGER DEFAULT 0,
                    total_packets_received INTEGER DEFAULT 0,
                    total_bytes_sent INTEGER DEFAULT 0,
                    total_bytes_received INTEGER DEFAULT 0,
                    observed_services TEXT,
                    observed_client_ports TEXT,
                    dns_names TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_relationships (
                    relationship_key TEXT PRIMARY KEY,
                    host1 TEXT,
                    host2 TEXT,
                    protocol TEXT,
                    first_seen_time REAL,
                    last_seen_time REAL,
                    first_capture_id TEXT,
                    last_capture_id TEXT,
                    captures_observed_count INTEGER DEFAULT 1,
                    total_packets INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    ports TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_destinations (
                    destination_key TEXT PRIMARY KEY,
                    dest_type TEXT,
                    value TEXT,
                    port INTEGER,
                    protocol TEXT,
                    first_seen_time REAL,
                    last_seen_time REAL,
                    first_capture_id TEXT,
                    last_capture_id TEXT,
                    observation_count INTEGER DEFAULT 1
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_dns_queries (
                    query_name TEXT PRIMARY KEY,
                    first_seen_time REAL,
                    last_seen_time REAL,
                    first_capture_id TEXT,
                    last_capture_id TEXT,
                    query_count INTEGER DEFAULT 1,
                    clients TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_host_baselines (
                    ip TEXT PRIMARY KEY,
                    avg_bytes_per_second REAL DEFAULT 0,
                    avg_packets_per_second REAL DEFAULT 0,
                    captures_count INTEGER DEFAULT 1,
                    typical_ports TEXT,
                    typical_peer_count REAL DEFAULT 0
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_recurring_anomalies (
                    signature TEXT PRIMARY KEY,
                    category TEXT,
                    title TEXT,
                    severity TEXT,
                    entity TEXT,
                    first_seen_time REAL,
                    last_seen_time REAL,
                    first_capture_id TEXT,
                    last_capture_id TEXT,
                    occurrences_count INTEGER DEFAULT 1,
                    captures_list TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_analyst_feedback (
                    target_key TEXT PRIMARY KEY,
                    target_type TEXT,
                    status TEXT,
                    is_expected BOOLEAN DEFAULT 0,
                    analyst_note TEXT,
                    created_at REAL,
                    updated_at REAL
                )
            """)

            conn.commit()

    def record_capture(
        self,
        capture_id: str,
        filename: str,
        results: Dict[str, Any],
        internal_subnets: Optional[List[str]] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record and index a capture into the historical baseline.
        Extracts compact summaries of hosts, conversations, DNS, and findings.
        """
        now = time.time()
        start_time = results.get("start_time") or now
        duration = max(
            0.001,
            float(results.get("duration_seconds") or results.get("summary", {}).get("duration_seconds", 0.0) or 0.001)
        )
        end_time = results.get("end_time") or (start_time + duration)

        if not internal_subnets:
            discovered_subnets = set()
            for h in results.get("hosts", []):
                if h.get("is_internal") and h.get("ip"):
                    try:
                        ip_obj = ipaddress.ip_address(h["ip"])
                        if ip_obj.version == 4:
                            net = ipaddress.ip_network(f"{h['ip']}/24", strict=False)
                            discovered_subnets.add(str(net))
                    except Exception:
                        pass
            if discovered_subnets:
                internal_subnets = sorted(list(discovered_subnets))
            else:
                internal_subnets = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]

        subnets_json = json.dumps(internal_subnets)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Ingest capture record
            cursor.execute("""
                INSERT OR REPLACE INTO memory_captures (
                    capture_id, filename, sha256, analyzed_at, first_packet_time,
                    last_packet_time, duration_seconds, packet_count, byte_count,
                    unique_hosts, internal_subnets, mode, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                capture_id,
                filename,
                results.get("sha256", ""),
                now,
                start_time,
                end_time,
                duration,
                results.get("total_packets", 0),
                results.get("total_bytes", 0),
                results.get("unique_hosts", 0),
                subnets_json,
                results.get("mode", "white"),
                notes or "",
            ))

            # 2. Ingest / Update Hosts
            hosts = results.get("hosts", [])
            for h in hosts:
                ip = h.get("ip")
                if not ip:
                    continue

                is_internal = bool(h.get("is_internal", False))
                pkts_sent = int(h.get("packets_sent", 0))
                pkts_recv = int(h.get("packets_received", 0))
                bytes_sent = int(h.get("bytes_sent", 0))
                bytes_recv = int(h.get("bytes_received", 0))

                existing = cursor.execute("SELECT * FROM memory_hosts WHERE ip = ?", (ip,)).fetchone()
                if existing:
                    cursor.execute("""
                        UPDATE memory_hosts SET
                            last_seen_time = ?,
                            last_capture_id = ?,
                            captures_observed_count = captures_observed_count + 1,
                            total_packets_sent = total_packets_sent + ?,
                            total_packets_received = total_packets_received + ?,
                            total_bytes_sent = total_bytes_sent + ?,
                            total_bytes_received = total_bytes_received + ?
                        WHERE ip = ?
                    """, (
                        end_time,
                        capture_id,
                        pkts_sent,
                        pkts_recv,
                        bytes_sent,
                        bytes_recv,
                        ip,
                    ))
                else:
                    cursor.execute("""
                        INSERT INTO memory_hosts (
                            ip, is_internal, first_seen_time, last_seen_time,
                            first_capture_id, last_capture_id, captures_observed_count,
                            total_packets_sent, total_packets_received,
                            total_bytes_sent, total_bytes_received, observed_services,
                            observed_client_ports, dns_names
                        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, '[]', '[]', '[]')
                    """, (
                        ip,
                        is_internal,
                        start_time,
                        end_time,
                        capture_id,
                        capture_id,
                        pkts_sent,
                        pkts_recv,
                        bytes_sent,
                        bytes_recv,
                    ))

                # Update Host Throughput Baseline
                total_h_bytes = bytes_sent + bytes_recv
                h_rate = total_h_bytes / duration
                h_pkt_rate = (pkts_sent + pkts_recv) / duration

                h_base = cursor.execute("SELECT * FROM memory_host_baselines WHERE ip = ?", (ip,)).fetchone()
                if h_base:
                    count = h_base["captures_count"] + 1
                    new_avg = (h_base["avg_bytes_per_second"] * (count - 1) + h_rate) / count
                    new_pkt_avg = (h_base["avg_packets_per_second"] * (count - 1) + h_pkt_rate) / count
                    cursor.execute("""
                        UPDATE memory_host_baselines SET
                            avg_bytes_per_second = ?,
                            avg_packets_per_second = ?,
                            captures_count = ?
                        WHERE ip = ?
                    """, (new_avg, new_pkt_avg, count, ip))
                else:
                    cursor.execute("""
                        INSERT INTO memory_host_baselines (
                            ip, avg_bytes_per_second, avg_packets_per_second, captures_count, typical_ports, typical_peer_count
                        ) VALUES (?, ?, ?, 1, '[]', 1)
                    """, (ip, h_rate, h_pkt_rate))

            # 3. Ingest Conversations / Relationships
            conversations = results.get("conversations", [])
            for c in conversations:
                h1 = c.get("host1")
                h2 = c.get("host2")
                if not h1 or not h2:
                    continue

                proto = c.get("protocol", "tcp")
                p1 = c.get("port1")
                p2 = c.get("port2")
                # Canonical pair key (sorted hosts)
                hosts_sorted = sorted([h1, h2])
                rel_key = f"{hosts_sorted[0]}<->{hosts_sorted[1]}:{proto}"

                c_pkts = int(c.get("packet_count", 0))
                c_bytes = int(c.get("byte_count", 0))

                existing_rel = cursor.execute("SELECT * FROM memory_relationships WHERE relationship_key = ?", (rel_key,)).fetchone()
                if existing_rel:
                    cursor.execute("""
                        UPDATE memory_relationships SET
                            last_seen_time = ?,
                            last_capture_id = ?,
                            captures_observed_count = captures_observed_count + 1,
                            total_packets = total_packets + ?,
                            total_bytes = total_bytes + ?
                        WHERE relationship_key = ?
                    """, (end_time, capture_id, c_pkts, c_bytes, rel_key))
                else:
                    ports_list = json.dumps([p for p in [p1, p2] if p])
                    cursor.execute("""
                        INSERT INTO memory_relationships (
                            relationship_key, host1, host2, protocol, first_seen_time,
                            last_seen_time, first_capture_id, last_capture_id,
                            captures_observed_count, total_packets, total_bytes, ports
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """, (
                        rel_key,
                        hosts_sorted[0],
                        hosts_sorted[1],
                        proto,
                        start_time,
                        end_time,
                        capture_id,
                        capture_id,
                        c_pkts,
                        c_bytes,
                        ports_list,
                    ))

                # Track destination endpoints (external peers and services)
                for ep, port in [(h1, p1), (h2, p2)]:
                    dest_key = f"{ep}:{port or 0}:{proto}"
                    dest_exist = cursor.execute("SELECT * FROM memory_destinations WHERE destination_key = ?", (dest_key,)).fetchone()
                    if dest_exist:
                        cursor.execute("""
                            UPDATE memory_destinations SET
                                last_seen_time = ?,
                                last_capture_id = ?,
                                observation_count = observation_count + 1
                            WHERE destination_key = ?
                        """, (end_time, capture_id, dest_key))
                    else:
                        cursor.execute("""
                            INSERT INTO memory_destinations (
                                destination_key, dest_type, value, port, protocol,
                                first_seen_time, last_seen_time, first_capture_id,
                                last_capture_id, observation_count
                            ) VALUES (?, 'ip', ?, ?, ?, ?, ?, ?, ?, 1)
                        """, (dest_key, ep, port or 0, proto, start_time, end_time, capture_id, capture_id))

            # 4. Ingest DNS Queries & IOCs
            raw_iocs = results.get("iocs", [])
            extracted_domains = set()

            if isinstance(raw_iocs, dict):
                for d in raw_iocs.get("domains", []):
                    if isinstance(d, dict):
                        name = d.get("domain") or d.get("value")
                    else:
                        name = str(d)
                    if name:
                        extracted_domains.add(name)
                for q in raw_iocs.get("dns_queries", []):
                    if isinstance(q, dict):
                        name = q.get("query") or q.get("value")
                    else:
                        name = str(q)
                    if name:
                        extracted_domains.add(name)
            elif isinstance(raw_iocs, list):
                for ioc in raw_iocs:
                    if isinstance(ioc, dict):
                        val = ioc.get("value") or ioc.get("domain")
                        itype = ioc.get("type", "domain")
                        if itype in ("domain", "hostname") and val:
                            extracted_domains.add(val)
                    elif isinstance(ioc, str):
                        extracted_domains.add(ioc)

            for val in extracted_domains:
                dns_exist = cursor.execute("SELECT * FROM memory_dns_queries WHERE query_name = ?", (val,)).fetchone()
                if dns_exist:
                    cursor.execute("""
                        UPDATE memory_dns_queries SET
                            last_seen_time = ?,
                            last_capture_id = ?,
                            query_count = query_count + 1
                        WHERE query_name = ?
                    """, (end_time, capture_id, val))
                else:
                    cursor.execute("""
                        INSERT INTO memory_dns_queries (
                            query_name, first_seen_time, last_seen_time,
                            first_capture_id, last_capture_id, query_count, clients
                        ) VALUES (?, ?, ?, ?, ?, 1, '[]')
                    """, (val, start_time, end_time, capture_id, capture_id))

                # Also add domain to destinations
                dom_dest_key = f"domain:{val}"
                if not cursor.execute("SELECT 1 FROM memory_destinations WHERE destination_key = ?", (dom_dest_key,)).fetchone():
                    cursor.execute("""
                        INSERT INTO memory_destinations (
                            destination_key, dest_type, value, port, protocol,
                            first_seen_time, last_seen_time, first_capture_id,
                            last_capture_id, observation_count
                        ) VALUES (?, 'domain', ?, 53, 'dns', ?, ?, ?, ?, 1)
                    """, (dom_dest_key, val, start_time, end_time, capture_id, capture_id))

            # 5. Ingest / Track Recurring Anomalies & Findings
            findings = results.get("findings", [])
            for f in findings:
                cat = f.get("category") or "General Anomaly"
                title = f.get("title") or "Unnamed Finding"
                sev = f.get("severity") or "medium"
                src = f.get("source_ip") or ""
                dst = f.get("destination_ip") or ""
                entity = src or dst or "Network Traffic"

                # Signature identifies repeated structural detection
                sig = f"{cat}:{title}:{entity}"

                exist_ano = cursor.execute("SELECT * FROM memory_recurring_anomalies WHERE signature = ?", (sig,)).fetchone()
                if exist_ano:
                    cap_list = json.loads(exist_ano["captures_list"] or "[]")
                    if capture_id not in cap_list:
                        cap_list.append(capture_id)
                    cursor.execute("""
                        UPDATE memory_recurring_anomalies SET
                            last_seen_time = ?,
                            last_capture_id = ?,
                            occurrences_count = occurrences_count + 1,
                            captures_list = ?
                        WHERE signature = ?
                    """, (end_time, capture_id, json.dumps(cap_list), sig))
                else:
                    cursor.execute("""
                        INSERT INTO memory_recurring_anomalies (
                            signature, category, title, severity, entity,
                            first_seen_time, last_seen_time, first_capture_id,
                            last_capture_id, occurrences_count, captures_list
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """, (
                        sig,
                        cat,
                        title,
                        sev,
                        entity,
                        start_time,
                        end_time,
                        capture_id,
                        capture_id,
                        json.dumps([capture_id]),
                    ))

            conn.commit()
            logger.info(f"Capture {capture_id} ({filename}) successfully indexed in Beacon Memory.")
            return {"status": "indexed", "capture_id": capture_id}

    def ingest_capture(
        self,
        capture_id: str,
        filename: str,
        capture_meta: Optional[Dict[str, Any]] = None,
        hosts: Optional[List[Dict[str, Any]]] = None,
        conversations: Optional[List[Dict[str, Any]]] = None,
        iocs: Optional[Dict[str, Any]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        results: Optional[Dict[str, Any]] = None,
        internal_subnets: Optional[List[str]] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convenience method to ingest a capture with either separate components or a results dict."""
        payload = dict(results or {})
        if capture_meta:
            payload.update(capture_meta)
        if hosts is not None:
            payload["hosts"] = hosts
        if conversations is not None:
            payload["conversations"] = conversations
        if iocs is not None:
            payload["iocs"] = iocs
        if findings is not None:
            payload["findings"] = findings
        return self.record_capture(
            capture_id=capture_id,
            filename=filename,
            results=payload,
            internal_subnets=internal_subnets,
            notes=notes,
        )

    def get_baseline_summary(self) -> Dict[str, Any]:
        """Return top-level metrics on the active baseline depth and coverage."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            c_count = cursor.execute("SELECT COUNT(*), SUM(duration_seconds), SUM(byte_count) FROM memory_captures").fetchone()
            captures_count = c_count[0] or 0
            total_duration = c_count[1] or 0.0
            total_bytes = c_count[2] or 0

            hosts_count = cursor.execute("SELECT COUNT(*) FROM memory_hosts").fetchone()[0]
            internal_hosts_count = cursor.execute("SELECT COUNT(*) FROM memory_hosts WHERE is_internal = 1").fetchone()[0]
            rels_count = cursor.execute("SELECT COUNT(*) FROM memory_relationships").fetchone()[0]
            dest_count = cursor.execute("SELECT COUNT(*) FROM memory_destinations").fetchone()[0]
            dns_count = cursor.execute("SELECT COUNT(*) FROM memory_dns_queries").fetchone()[0]
            anomalies_count = cursor.execute("SELECT COUNT(*) FROM memory_recurring_anomalies").fetchone()[0]
            feedback_count = cursor.execute("SELECT COUNT(*) FROM memory_analyst_feedback").fetchone()[0]

            latest_cap = cursor.execute("SELECT * FROM memory_captures ORDER BY analyzed_at DESC LIMIT 1").fetchone()

            # Compile known internal subnets across captures
            subnets_set: Set[str] = set()
            for r in cursor.execute("SELECT internal_subnets FROM memory_captures").fetchall():
                try:
                    s_list = json.loads(r["internal_subnets"] or "[]")
                    subnets_set.update(s_list)
                except Exception:
                    pass

            if captures_count >= 3:
                b_health = BaselineHealth.ESTABLISHED.value
            elif captures_count >= 1:
                b_health = BaselineHealth.LIMITED.value
            else:
                b_health = BaselineHealth.INSUFFICIENT.value

            return {
                "captures_count": captures_count,
                "baseline_health": b_health,
                "total_duration_seconds": round(total_duration, 2),
                "total_bytes": total_bytes,
                "hosts_count": hosts_count,
                "internal_hosts_count": internal_hosts_count,
                "external_hosts_count": max(0, hosts_count - internal_hosts_count),
                "relationships_count": rels_count,
                "destinations_count": dest_count,
                "dns_queries_count": dns_count,
                "recurring_anomalies_count": anomalies_count,
                "analyst_feedback_count": feedback_count,
                "internal_subnets": sorted(list(subnets_set)),
                "last_capture_analyzed_at": latest_cap["analyzed_at"] if latest_cap else None,
                "last_capture_filename": latest_cap["filename"] if latest_cap else None,
            }

    def get_historical_hosts(self, exclude_capture_id: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Return dict of historical hosts mapped by IP."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if exclude_capture_id:
                # Select hosts that appeared in at least one other capture
                rows = cursor.execute("""
                    SELECT h.*, b.avg_bytes_per_second, b.avg_packets_per_second
                    FROM memory_hosts h
                    LEFT JOIN memory_host_baselines b ON h.ip = b.ip
                    WHERE h.first_capture_id != ? OR h.captures_observed_count > 1
                """, (exclude_capture_id,)).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT h.*, b.avg_bytes_per_second, b.avg_packets_per_second
                    FROM memory_hosts h
                    LEFT JOIN memory_host_baselines b ON h.ip = b.ip
                """).fetchall()

            result = {}
            for r in rows:
                result[r["ip"]] = {
                    "ip": r["ip"],
                    "is_internal": bool(r["is_internal"]),
                    "first_seen": r["first_seen_time"],
                    "last_seen": r["last_seen_time"],
                    "captures_observed": r["captures_observed_count"],
                    "avg_bytes_per_second": r["avg_bytes_per_second"] or 0.0,
                    "avg_packets_per_second": r["avg_packets_per_second"] or 0.0,
                    "total_bytes": r["total_bytes_sent"] + r["total_bytes_received"],
                }
            return result

    def get_historical_relationships(self, exclude_capture_id: Optional[str] = None) -> Set[str]:
        """Return set of known relationship keys (host1<->host2:proto)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if exclude_capture_id:
                rows = cursor.execute("""
                    SELECT relationship_key FROM memory_relationships
                    WHERE first_capture_id != ? OR captures_observed_count > 1
                """, (exclude_capture_id,)).fetchall()
            else:
                rows = cursor.execute("SELECT relationship_key FROM memory_relationships").fetchall()
            return {r["relationship_key"] for r in rows}

    def get_historical_destinations(self, exclude_capture_id: Optional[str] = None) -> Set[str]:
        """Return set of known destination endpoint keys (IPs and domains)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if exclude_capture_id:
                rows = cursor.execute("""
                    SELECT value FROM memory_destinations
                    WHERE first_capture_id != ? OR observation_count > 1
                """, (exclude_capture_id,)).fetchall()
            else:
                rows = cursor.execute("SELECT value FROM memory_destinations").fetchall()
            return {r["value"] for r in rows}

    def get_historical_dns(self, exclude_capture_id: Optional[str] = None) -> Set[str]:
        """Return set of known DNS query names."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if exclude_capture_id:
                rows = cursor.execute("""
                    SELECT query_name FROM memory_dns_queries
                    WHERE first_capture_id != ? OR query_count > 1
                """, (exclude_capture_id,)).fetchall()
            else:
                rows = cursor.execute("SELECT query_name FROM memory_dns_queries").fetchall()
            return {r["query_name"] for r in rows}

    def get_recurring_anomalies(self) -> List[Dict[str, Any]]:
        """Return list of all recurring anomalies across historical captures."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT a.*, f.status as feedback_status, f.is_expected, f.analyst_note
                FROM memory_recurring_anomalies a
                LEFT JOIN memory_analyst_feedback f ON a.signature = f.target_key
                ORDER BY a.occurrences_count DESC, a.last_seen_time DESC
            """).fetchall()

            result = []
            for r in rows:
                result.append({
                    "signature": r["signature"],
                    "category": r["category"],
                    "title": r["title"],
                    "severity": r["severity"],
                    "entity": r["entity"],
                    "first_seen": r["first_seen_time"],
                    "last_seen": r["last_seen_time"],
                    "occurrences": r["occurrences_count"],
                    "captures": json.loads(r["captures_list"] or "[]"),
                    "feedback": {
                        "status": r["feedback_status"] or "unreviewed",
                        "is_expected": bool(r["is_expected"]),
                        "note": r["analyst_note"] or "",
                    } if r["feedback_status"] else None,
                })
            return result

    def save_analyst_feedback(
        self,
        target_key: str,
        target_type: str,
        status: str = "expected",
        is_expected: bool = True,
        note: str = "",
    ) -> Dict[str, Any]:
        """
        Record analyst review feedback for an entity or change candidate.
        Refines future prioritization without erasing underlying evidence.
        """
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            existing = cursor.execute("SELECT created_at FROM memory_analyst_feedback WHERE target_key = ?", (target_key,)).fetchone()
            created_at = existing["created_at"] if existing else now

            cursor.execute("""
                INSERT OR REPLACE INTO memory_analyst_feedback (
                    target_key, target_type, status, is_expected, analyst_note, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                target_key,
                target_type,
                status,
                1 if is_expected else 0,
                note.strip(),
                created_at,
                now,
            ))
            conn.commit()

        return {
            "target_key": target_key,
            "target_type": target_type,
            "status": status,
            "is_expected": is_expected,
            "analyst_note": note.strip(),
            "updated_at": now,
        }

    def get_all_analyst_feedback(self) -> Dict[str, Dict[str, Any]]:
        """Return dict of all analyst feedback entries mapped by target_key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT * FROM memory_analyst_feedback").fetchall()
            result = {}
            for r in rows:
                result[r["target_key"]] = {
                    "target_key": r["target_key"],
                    "target_type": r["target_type"],
                    "status": r["status"],
                    "is_expected": bool(r["is_expected"]),
                    "note": r["analyst_note"] or "",
                    "analyst_note": r["analyst_note"] or "",
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            return result

    def get_analyst_feedback(self, target_key: str) -> Optional[AnalystFeedbackRecord]:
        """Return persistent feedback record for a specific entity or target key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM memory_analyst_feedback WHERE target_key = ?", (target_key,)
            ).fetchone()
            if not row:
                return None
            status_val = row["status"]
            try:
                status_enum = FeedbackStatus(status_val)
            except ValueError:
                status_enum = FeedbackStatus.EXPECTED

            return AnalystFeedbackRecord(
                target_key=row["target_key"],
                target_type=row["target_type"] or "host",
                status=status_enum,
                is_expected=bool(row["is_expected"]),
                analyst_note=row["analyst_note"] or "",
                created_at=row["created_at"] or 0.0,
                updated_at=row["updated_at"] or 0.0,
            )

    def get_captures_history(self) -> List[Dict[str, Any]]:
        """Return chronological list of ingested capture summaries."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT * FROM memory_captures ORDER BY analyzed_at DESC
            """).fetchall()
            return [
                {
                    "capture_id": r["capture_id"],
                    "filename": r["filename"],
                    "analyzed_at": r["analyzed_at"],
                    "duration_seconds": r["duration_seconds"],
                    "packet_count": r["packet_count"],
                    "byte_count": r["byte_count"],
                    "unique_hosts": r["unique_hosts"],
                    "mode": r["mode"],
                    "notes": r["notes"],
                }
                for r in rows
            ]
