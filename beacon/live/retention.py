"""Smart evidence retention store for Beacon Live security incidents."""

from __future__ import annotations

import collections
import logging
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from beacon.live.buffer import RollingPacketBuffer
from beacon.live.models import EvidenceStatus, IncidentEvidence, RollingPacket
from beacon.live.pcap_writer import write_pcap_file
from beacon.models import Finding

logger = logging.getLogger(__name__)


class SmartEvidenceStore:
    """
    Durable, bounded evidence retention store.
    Preserves pre-trigger context, triggering packets, and bounded post-trigger
    traffic windows when security anomalies or suspicious patterns are detected.
    """

    def __init__(
        self,
        max_incidents: int = 100,
        max_packets_per_incident: int = 200,
        post_trigger_window_seconds: float = 5.0,
        pre_trigger_packet_count: int = 25,
        pre_trigger_window_seconds: float = 10.0,
        cooldown_seconds: float = 15.0,
        spool_dir: Optional[Path] = None,
    ):
        self.max_incidents = max_incidents
        self.max_packets_per_incident = max_packets_per_incident
        self.post_trigger_window_seconds = post_trigger_window_seconds
        self.pre_trigger_packet_count = pre_trigger_packet_count
        self.pre_trigger_window_seconds = pre_trigger_window_seconds
        self.cooldown_seconds = cooldown_seconds

        self.spool_dir = spool_dir or (Path("cache") / "live_evidence")
        self.spool_dir.mkdir(parents=True, exist_ok=True)

        self._incidents: Dict[str, IncidentEvidence] = collections.OrderedDict()
        self._lock = threading.Lock()
        self._active_collection_windows: Dict[str, IncidentEvidence] = {}
        # Cooldown map: (category, entity) -> (incident_id, last_seen_ts)
        self._cooldown_map: Dict[Tuple[str, str], Tuple[str, float]] = {}

        self._total_incidents_recorded = 0
        self._total_incidents_evicted = 0

    @property
    def incidents_count(self) -> int:
        with self._lock:
            return len(self._incidents)

    @property
    def pinned_count(self) -> int:
        with self._lock:
            return sum(1 for inc in self._incidents.values() if inc.analyst_pinned)

    @property
    def active_windows_count(self) -> int:
        with self._lock:
            return len(self._active_collection_windows)

    def trigger_incident(
        self,
        finding: Finding,
        trigger_packet: RollingPacket,
        buffer: RollingPacketBuffer,
    ) -> IncidentEvidence:
        """
        Record and preserve evidence for a security finding.
        Captures pre-trigger context from rolling buffer and opens a post-trigger
        collection window for follow-up correlation.
        """
        now = time.time()
        rule_category = finding.category or "anomaly"
        target_entity = finding.source_ip or finding.destination_ip or trigger_packet.ip_src or "unknown"
        cooldown_key = (rule_category, target_entity)

        with self._lock:
            # Check deduplication & cooldown
            if cooldown_key in self._cooldown_map:
                existing_id, last_seen = self._cooldown_map[cooldown_key]
                if (now - last_seen) < self.cooldown_seconds and existing_id in self._incidents:
                    existing_inc = self._incidents[existing_id]
                    existing_inc.occurrence_count += 1
                    existing_inc.last_seen_timestamp = now
                    self._cooldown_map[cooldown_key] = (existing_id, now)
                    # If window was still collecting, extend slightly
                    if existing_inc.evidence_status == EvidenceStatus.COLLECTING:
                        existing_inc.post_trigger_window_end = max(
                            existing_inc.post_trigger_window_end,
                            now + self.post_trigger_window_seconds,
                        )
                    return existing_inc

            # Extract pre-trigger window from rolling buffer
            pre_packets, is_partial = buffer.get_pre_trigger_window(
                trigger_number=trigger_packet.number,
                window_count=self.pre_trigger_packet_count,
                window_seconds=self.pre_trigger_window_seconds,
            )

            # Determine initial status
            init_status = EvidenceStatus.COLLECTING
            missing_reason = (
                "Preceding packets were evicted from the rolling buffer before detection triggered."
                if is_partial
                else None
            )

            # Generate unique incident ID
            inc_id = f"inc-{int(now)}-{trigger_packet.number}"

            related_hosts = set()
            if finding.source_ip:
                related_hosts.add(finding.source_ip)
            if finding.destination_ip:
                related_hosts.add(finding.destination_ip)
            if trigger_packet.ip_src:
                related_hosts.add(trigger_packet.ip_src)
            if trigger_packet.ip_dst:
                related_hosts.add(trigger_packet.ip_dst)

            related_convs = list(finding.related_conversations or [])
            if trigger_packet.conversation_key != "unknown":
                if trigger_packet.conversation_key not in related_convs:
                    related_convs.append(trigger_packet.conversation_key)

            incident = IncidentEvidence(
                id=inc_id,
                finding_id=finding.id,
                title=finding.title,
                category=rule_category,
                severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                confidence=finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
                trigger_timestamp=trigger_packet.timestamp or now,
                trigger_packet_number=trigger_packet.number,
                trigger_packet=trigger_packet,
                pre_trigger_packets=pre_packets,
                post_trigger_packets=[],
                post_trigger_window_end=now + self.post_trigger_window_seconds,
                evidence_status=init_status,
                missing_context_reason=missing_reason,
                related_hosts=sorted(list(related_hosts)),
                related_conversations=related_convs,
                analyst_pinned=False,
                analyst_notes="",
                occurrence_count=1,
                last_seen_timestamp=now,
            )

            # Enforce max incidents budget (evict oldest unpinned incident if full)
            self._enforce_incident_budget()

            self._incidents[inc_id] = incident
            self._active_collection_windows[inc_id] = incident
            self._cooldown_map[cooldown_key] = (inc_id, now)
            self._total_incidents_recorded += 1

            return incident

    def process_incoming_packet(self, packet: RollingPacket) -> None:
        """
        Check if an incoming packet falls into any active post-trigger collection windows.
        If related, append it to the incident evidence until budget or window expires.
        """
        now = time.time()
        to_close = []

        with self._lock:
            for inc_id, inc in list(self._active_collection_windows.items()):
                # Check if window expired
                if now >= inc.post_trigger_window_end:
                    to_close.append(inc_id)
                    continue

                # Check budget
                if inc.total_retained_packets >= self.max_packets_per_incident:
                    inc.evidence_budget_exceeded = True
                    to_close.append(inc_id)
                    continue

                # Determine relevance: same host, same conversation, or same flow
                is_relevant = False
                if packet.ip_src in inc.related_hosts or packet.ip_dst in inc.related_hosts:
                    is_relevant = True
                elif packet.conversation_key in inc.related_conversations:
                    is_relevant = True
                elif packet.number > inc.trigger_packet_number and (packet.timestamp - inc.trigger_timestamp) <= 3.0:
                    # Immediately sequential packet in active window
                    is_relevant = True

                if is_relevant:
                    inc.post_trigger_packets.append(packet)
                    if inc.total_retained_packets >= self.max_packets_per_incident:
                        inc.evidence_budget_exceeded = True
                        to_close.append(inc_id)

            for inc_id in to_close:
                if inc_id in self._active_collection_windows:
                    inc = self._active_collection_windows.pop(inc_id)
                    if inc.missing_context_reason:
                        inc.evidence_status = EvidenceStatus.PARTIAL
                    else:
                        inc.evidence_status = EvidenceStatus.COMPLETE

    def finalize_expired_windows(self) -> None:
        """Close any post-trigger collection windows that have exceeded their time limit."""
        now = time.time()
        with self._lock:
            expired = [
                inc_id
                for inc_id, inc in self._active_collection_windows.items()
                if now >= inc.post_trigger_window_end
            ]
            for inc_id in expired:
                inc = self._active_collection_windows.pop(inc_id)
                if inc.missing_context_reason:
                    inc.evidence_status = EvidenceStatus.PARTIAL
                else:
                    inc.evidence_status = EvidenceStatus.COMPLETE

    def _enforce_incident_budget(self) -> None:
        """Ensure total incidents do not exceed max_incidents. Protects pinned evidence."""
        while len(self._incidents) >= self.max_incidents:
            # Find oldest unpinned incident
            evicted_id = None
            for inc_id, inc in self._incidents.items():
                if not inc.analyst_pinned and inc.evidence_status != EvidenceStatus.COLLECTING:
                    evicted_id = inc_id
                    break

            if evicted_id:
                del self._incidents[evicted_id]
                self._active_collection_windows.pop(evicted_id, None)
                self._total_incidents_evicted += 1
            else:
                # All existing incidents are pinned or collecting; cannot evict
                break

    def get_incidents(
        self,
        severity_filter: Optional[str] = None,
        pinned_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[IncidentEvidence]:
        """Return list of incidents sorted newest first."""
        self.finalize_expired_windows()
        with self._lock:
            items = list(self._incidents.values())
            items.reverse()

            if severity_filter and severity_filter.lower() != "all":
                items = [i for i in items if i.severity.lower() == severity_filter.lower()]

            if pinned_only:
                items = [i for i in items if i.analyst_pinned]

            return items[offset : offset + limit]

    def get_incident(self, incident_id: str) -> Optional[IncidentEvidence]:
        """Retrieve full incident evidence details."""
        self.finalize_expired_windows()
        with self._lock:
            return self._incidents.get(incident_id)

    def get_packet_by_number(self, packet_number: int) -> Optional[RollingPacket]:
        """Find a packet across all preserved incident evidence if present."""
        self.finalize_expired_windows()
        with self._lock:
            for inc in self._incidents.values():
                for p in inc.get_all_packets_ordered():
                    if p.number == packet_number:
                        return p
            return None

    def set_incident_pin(self, incident_id: str, pinned: bool) -> bool:
        """Pin or unpin an incident to prevent eviction."""
        with self._lock:
            inc = self._incidents.get(incident_id)
            if inc:
                inc.analyst_pinned = pinned
                return True
            return False

    def update_incident_notes(self, incident_id: str, notes: str) -> bool:
        """Update analyst notes on an incident."""
        with self._lock:
            inc = self._incidents.get(incident_id)
            if inc:
                inc.analyst_notes = notes.strip()
                return True
            return False

    def export_incident_pcap(self, incident_id: str, output_path: Optional[Path] = None) -> Optional[Path]:
        """
        Export the retained packets of an incident to a valid standard PCAP file.
        Returns the output file path.
        """
        inc = self.get_incident(incident_id)
        if not inc:
            return None

        packets = inc.get_all_packets_ordered()
        if not output_path:
            out_file = self.spool_dir / f"{incident_id}.pcap"
        else:
            out_file = Path(output_path)

        write_pcap_file(packets, out_file)
        return out_file

    def clear(self) -> None:
        """Clear all incidents and active windows."""
        with self._lock:
            self._incidents.clear()
            self._active_collection_windows.clear()
            self._cooldown_map.clear()
