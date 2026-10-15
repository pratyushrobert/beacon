"""Host-level traffic aggregation."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Iterable, List, Optional

from beacon.core.packet_parser import ParsedPacket
from beacon.models import HostStats


class HostAnalyzer:
    """Build per-host statistics from normalized packets."""

    @staticmethod
    def analyze(packets: Iterable[ParsedPacket]) -> List[HostStats]:
        hosts: dict[str, HostStats] = {}
        for packet in packets:
            for ip in (packet.ip_src, packet.ip_dst):
                if not ip:
                    continue
                host = hosts.setdefault(
                    ip,
                    HostStats(ip=ip, is_internal=packet.is_internal_ip(ip)),
                )
                host.protocols.update(
                    protocol
                    for protocol in (packet.app_proto, packet.transport_proto)
                    if protocol
                )
                if packet.timestamp and (
                    host.first_seen is None or packet.timestamp < host.first_seen
                ):
                    host.first_seen = packet.timestamp
                if packet.timestamp and (
                    host.last_seen is None or packet.timestamp > host.last_seen
                ):
                    host.last_seen = packet.timestamp
                if packet.ip_src == ip:
                    host.packets_sent += 1
                    host.bytes_sent += packet.length
                else:
                    host.packets_received += 1
                    host.bytes_received += packet.length
        return sorted(hosts.values(), key=lambda host: host.total_bytes, reverse=True)

    @staticmethod
    def query(engine: object) -> List[HostStats]:
        """Read host aggregates from an AnalysisEngine cache."""
        cursor = engine.db_conn.cursor()
        rows = cursor.execute(
            """
            SELECT ip, packets_sent, packets_received, bytes_sent, bytes_received,
                   first_seen, last_seen, is_internal
            FROM hosts ORDER BY bytes_sent + bytes_received DESC
            """
        ).fetchall()
        result: List[HostStats] = []
        for row in rows:
            protocols = cursor.execute(
                """
                SELECT DISTINCT CASE WHEN app_proto IS NOT NULL THEN app_proto
                                     WHEN transport_proto IS NOT NULL THEN transport_proto
                                END
                FROM packets WHERE ip_src = ? OR ip_dst = ?
                  AND (app_proto IS NOT NULL OR transport_proto IS NOT NULL)
                """,
                (row["ip"], row["ip"]),
            ).fetchall()
            result.append(
                HostStats(
                    ip=row["ip"],
                    packets_sent=row["packets_sent"],
                    packets_received=row["packets_received"],
                    bytes_sent=row["bytes_sent"],
                    bytes_received=row["bytes_received"],
                    first_seen=datetime.fromtimestamp(row["first_seen"]) if row["first_seen"] else None,
                    last_seen=datetime.fromtimestamp(row["last_seen"]) if row["last_seen"] else None,
                    is_internal=bool(row["is_internal"]),
                    protocols={item[0] for item in protocols if item[0]},
                )
            )
        return result
