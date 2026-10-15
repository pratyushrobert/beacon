"""Explainable change detection engine linking new observations to historical baseline evidence."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from beacon.memory.baseline import BaselineEngine
from beacon.memory.models import (
    BaselineHealth,
    ChangeBriefing,
    ChangeCategory,
    ChangeItem,
    ConfidenceLevel,
    FeedbackStatus,
)
from beacon.memory.store import MemoryStore

logger = logging.getLogger(__name__)


class ChangeDetector:
    """
    Compares network capture observations against a local-first historical baseline.
    Generates explainable, evidence-linked change briefings and ranked investigation candidates.
    """

    def __init__(self, store: Optional[MemoryStore] = None):
        self.store = store or MemoryStore()
        self.baseline_engine = BaselineEngine(self.store)

    def detect_changes(
        self,
        current_results: Dict[str, Any],
        capture_id: str,
        filename: str,
        exclude_current_id: Optional[str] = None,
    ) -> ChangeBriefing:
        """
        Detect behavioral and structural changes between current capture and historical baseline.
        """
        # 1. Evaluate baseline health and compatibility
        health, warning = self.baseline_engine.evaluate_compatibility(
            current_results, exclude_current_id=exclude_current_id
        )

        summary = self.store.get_baseline_summary()
        prior_captures_count = summary["captures_count"]
        if exclude_current_id and prior_captures_count > 0:
            with self.store._get_connection() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM memory_captures WHERE capture_id != ?",
                    (exclude_current_id,)
                ).fetchone()
                prior_captures_count = row[0] if row else 0

        # Confidence level based on historical depth
        if prior_captures_count >= 3:
            confidence = ConfidenceLevel.HIGH
        elif prior_captures_count >= 1:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.BASELINE_FORMATION

        # If baseline is completely empty
        if prior_captures_count == 0:
            return ChangeBriefing(
                capture_id=capture_id,
                filename=filename,
                analyzed_at=current_results.get("start_time") or 0.0,
                baseline_captures_count=0,
                baseline_duration_seconds=0.0,
                baseline_health=BaselineHealth.INSUFFICIENT,
                baseline_warning="Initial Capture: Foundational baseline established. No prior historical observations available for delta comparison.",
                total_changes_detected=0,
                new_destinations_count=0,
                new_relationships_count=0,
                service_shifts_count=0,
                volume_deviations_count=0,
                recurring_anomalies_count=0,
                top_investigation_candidate=None,
                items=[],
            )

        # 2. Fetch historical state excluding current capture
        historical_hosts = self.store.get_historical_hosts(exclude_capture_id=exclude_current_id)
        historical_relationships = self.store.get_historical_relationships(exclude_capture_id=exclude_current_id)
        historical_destinations = self.store.get_historical_destinations(exclude_capture_id=exclude_current_id)
        historical_dns = self.store.get_historical_dns(exclude_capture_id=exclude_current_id)
        recurring_anomalies = {a["signature"]: a for a in self.store.get_recurring_anomalies()}
        feedback_map = self.store.get_all_analyst_feedback()

        duration = max(
            0.001,
            float(current_results.get("duration_seconds") or current_results.get("summary", {}).get("duration_seconds", 0.0) or 0.001)
        )
        items: List[ChangeItem] = []
        change_seq = 1

        # -------------------------------------------------------------
        # Category A: First-Seen External Destinations (IPs & Domains)
        # -------------------------------------------------------------
        # Check external hosts
        for h in current_results.get("hosts", []):
            ip = h.get("ip")
            if not ip or h.get("is_internal"):
                continue

            # Check if this external IP has ever been observed in baseline
            if ip not in historical_hosts and ip not in historical_destinations:
                fb = feedback_map.get(ip)
                is_exp = fb.get("is_expected", False) if fb else False
                total_b = h.get("bytes_sent", 0) + h.get("bytes_received", 0)

                base_score = 75.0 if total_b > 10000 else 65.0
                score = base_score * (0.3 if is_exp else 1.0)

                item = ChangeItem(
                    id=f"change-{change_seq}",
                    category=ChangeCategory.FIRST_SEEN_DESTINATION,
                    title=f"First-Seen External Endpoint: {ip}",
                    entity=ip,
                    entity_type="host",
                    observed_fact=f"External destination {ip} observed for the first time ({h.get('packets_sent', 0) + h.get('packets_received', 0)} pkts, {self._format_bytes(total_b)}). Not present in {prior_captures_count} previous baseline capture(s).",
                    statistical_context=f"0 prior occurrences in baseline across {prior_captures_count} capture(s) ({summary['total_duration_seconds']}s history).",
                    inferred_hypothesis="First-seen external destination; candidate new cloud dependency, telemetry destination, or potential exfiltration/C2 channel.",
                    alternative_benign_explanation="New legitimate SaaS service, CDN server rotation, operating system telemetry update, or cloud infrastructure expansion.",
                    confidence=confidence,
                    priority_score=score,
                    severity="high" if total_b > 50000 else "medium",
                    first_seen_timestamp=h.get("first_seen") or current_results.get("start_time"),
                    comparison_context=f"Compared against {prior_captures_count} historical capture(s)",
                    evidence_links={
                        "packets_filter": ip,
                        "host_ip": ip,
                    },
                    analyst_feedback=fb,
                )
                items.append(item)
                change_seq += 1

        # Check DNS queries / domains
        raw_curr_iocs = current_results.get("iocs", [])
        curr_domains = set()
        if isinstance(raw_curr_iocs, dict):
            for d in raw_curr_iocs.get("domains", []):
                if isinstance(d, dict):
                    name = d.get("domain") or d.get("value")
                else:
                    name = str(d)
                if name:
                    curr_domains.add(name)
            for q in raw_curr_iocs.get("dns_queries", []):
                if isinstance(q, dict):
                    name = q.get("query") or q.get("value")
                else:
                    name = str(q)
                if name:
                    curr_domains.add(name)
        elif isinstance(raw_curr_iocs, list):
            for ioc in raw_curr_iocs:
                if isinstance(ioc, dict):
                    val = ioc.get("value") or ioc.get("domain")
                    itype = ioc.get("type", "domain")
                    if itype in ("domain", "hostname") and val:
                        curr_domains.add(val)
                elif isinstance(ioc, str):
                    curr_domains.add(ioc)

        for domain in sorted(list(curr_domains)):
            if domain and domain not in historical_dns and domain not in historical_destinations:
                fb = feedback_map.get(domain)
                is_exp = fb.get("is_expected", False) if fb else False
                score = 70.0 * (0.3 if is_exp else 1.0)

                item = ChangeItem(
                    id=f"change-{change_seq}",
                    category=ChangeCategory.FIRST_SEEN_DESTINATION,
                    title=f"First-Seen Queried Domain: {domain}",
                    entity=domain,
                    entity_type="domain",
                    observed_fact=f"DNS query name '{domain}' resolved for the first time. Never recorded in prior {prior_captures_count} baseline capture(s).",
                    statistical_context=f"0 prior occurrences in baseline DNS index ({summary['dns_queries_count']} total known domains).",
                    inferred_hypothesis="First-seen domain resolution; potential new external integration, dynamic DNS lookup, or threat infrastructure interaction.",
                    alternative_benign_explanation="New software package repository, ad/analytics network, legitimate partner portal, or CDN alias.",
                    confidence=confidence,
                    priority_score=score,
                    severity="medium",
                    first_seen_timestamp=current_results.get("start_time"),
                    comparison_context=f"Compared against {prior_captures_count} historical capture(s)",
                    evidence_links={
                        "packets_filter": domain,
                    },
                    analyst_feedback=fb,
                )
                items.append(item)
                change_seq += 1

        # -------------------------------------------------------------
        # Category B: New Communication Relationships (Host Pairs)
        # -------------------------------------------------------------
        for conv in current_results.get("conversations", []):
            h1 = conv.get("host1")
            h2 = conv.get("host2")
            proto = conv.get("protocol") or "tcp"
            if not h1 or not h2:
                continue

            hosts_sorted = sorted([h1, h2])
            rel_key = f"{hosts_sorted[0]}<->{hosts_sorted[1]}:{proto}"

            if rel_key not in historical_relationships:
                fb = feedback_map.get(rel_key)
                is_exp = fb.get("is_expected", False) if fb else False

                # Check if this is an internal-to-internal lateral pair
                h1_obj = next((h for h in current_results.get("hosts", []) if h.get("ip") == h1), {})
                h2_obj = next((h for h in current_results.get("hosts", []) if h.get("ip") == h2), {})
                is_lateral = h1_obj.get("is_internal") and h2_obj.get("is_internal")

                ports = [str(p) for p in [conv.get("port1"), conv.get("port2")] if p]
                port_str = f" (ports {', '.join(ports)})" if ports else ""
                c_bytes = conv.get("byte_count", 0)

                base_score = 80.0 if is_lateral else 65.0
                score = base_score * (0.3 if is_exp else 1.0)

                item = ChangeItem(
                    id=f"change-{change_seq}",
                    category=ChangeCategory.NEW_RELATIONSHIP,
                    title=f"New Communication Pair: {h1} ↔ {h2}",
                    entity=rel_key,
                    entity_type="relationship",
                    observed_fact=f"{'Internal lateral pair' if is_lateral else 'Host pair'} {h1} ↔ {h2} exchanged {conv.get('packet_count', 0)} {proto.upper()} packets ({self._format_bytes(c_bytes)}){port_str}. Pair never communicated in baseline.",
                    statistical_context=f"0 prior exchanges between these endpoints across {prior_captures_count} baseline captures.",
                    inferred_hypothesis="New lateral communication relationship; potential internal administrative session, lateral traversal, or peer-to-peer sync.",
                    alternative_benign_explanation="Authorized administrative login, remote assistance session, internal service deployment, or automated backup.",
                    confidence=confidence,
                    priority_score=score,
                    severity="high" if is_lateral and any(p in ("22", "3389", "445") for p in ports) else "medium",
                    first_seen_timestamp=conv.get("first_seen") or current_results.get("start_time"),
                    comparison_context=f"Compared against {prior_captures_count} historical capture(s)",
                    evidence_links={
                        "packets_filter": h1,
                        "conversation_key": conv.get("conversation_key", rel_key),
                    },
                    analyst_feedback=fb,
                )
                items.append(item)
                change_seq += 1

        # -------------------------------------------------------------
        # Category C: Unusual Service or Protocol Shift
        # -------------------------------------------------------------
        # Detect hosts offering or communicating on ports never seen in baseline
        for h in current_results.get("hosts", []):
            ip = h.get("ip")
            if not ip or ip not in historical_hosts:
                continue

            hist_data = historical_hosts[ip]
            if hist_data["captures_observed"] >= 1:
                # Compare active ports for this host in current capture
                curr_convs = [
                    c for c in current_results.get("conversations", [])
                    if c.get("host1") == ip or c.get("host2") == ip
                ]
                curr_ports = set()
                for c in curr_convs:
                    if c.get("host1") == ip and c.get("port1"):
                        curr_ports.add(c.get("port1"))
                    if c.get("host2") == ip and c.get("port2"):
                        curr_ports.add(c.get("port2"))

                # Check if unusual high-risk or administrative ports are newly active
                high_risk_ports = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 4444: "Metasploit/Raw", 8080: "Alt-HTTP"}
                new_high_risk = curr_ports.intersection(high_risk_ports.keys())

                for port in new_high_risk:
                    service_name = high_risk_ports[port]
                    shift_key = f"{ip}:port:{port}"
                    fb = feedback_map.get(shift_key)
                    is_exp = fb.get("is_expected", False) if fb else False
                    score = 85.0 * (0.3 if is_exp else 1.0)

                    item = ChangeItem(
                        id=f"change-{change_seq}",
                        category=ChangeCategory.UNUSUAL_SERVICE,
                        title=f"Unusual Service Activity on Host {ip} (Port {port}/{service_name})",
                        entity=shift_key,
                        entity_type="service",
                        observed_fact=f"Host {ip} observed actively engaging in {service_name} on port {port}. This port was not active on this host in prior baseline captures.",
                        statistical_context=f"Active in current capture; 0 prior occurrences on this specific host across {hist_data['captures_observed']} historical observation(s).",
                        inferred_hypothesis=f"Shift in host role or service exposure; potential newly opened listening service, administrative pivot, or unauthorized protocol execution.",
                        alternative_benign_explanation="System administrator remote connection, server provisioning, development service test, or port redirection.",
                        confidence=confidence,
                        priority_score=score,
                        severity="high",
                        first_seen_timestamp=current_results.get("start_time"),
                        comparison_context=f"Compared against {hist_data['captures_observed']} historical observations of this host",
                        evidence_links={
                            "packets_filter": f"{ip} port {port}",
                            "host_ip": ip,
                        },
                        analyst_feedback=fb,
                    )
                    items.append(item)
                    change_seq += 1

        # -------------------------------------------------------------
        # Category D: Traffic Volume & Rate Deviations
        # -------------------------------------------------------------
        for h in current_results.get("hosts", []):
            ip = h.get("ip")
            if not ip or ip not in historical_hosts:
                continue

            hist_data = historical_hosts[ip]
            hist_avg_rate = hist_data.get("avg_bytes_per_second", 0.0)
            total_curr_bytes = h.get("bytes_sent", 0) + h.get("bytes_received", 0)
            curr_rate = total_curr_bytes / duration

            # Only flag if host transferred meaningful volume (>= 5 KB) and has historical baseline
            if hist_data["captures_observed"] >= 1 and total_curr_bytes >= 5120 and hist_avg_rate > 10.0:
                ratio = curr_rate / hist_avg_rate
                if ratio >= 3.5:
                    drift_key = f"drift:{ip}:volume"
                    fb = feedback_map.get(drift_key)
                    is_exp = fb.get("is_expected", False) if fb else False
                    score = min(90.0, (50.0 + ratio * 5.0)) * (0.3 if is_exp else 1.0)

                    item = ChangeItem(
                        id=f"change-{change_seq}",
                        category=ChangeCategory.VOLUME_DEVIATION,
                        title=f"Significant Throughput Surge on Host {ip} ({ratio:.1f}x)",
                        entity=ip,
                        entity_type="host",
                        observed_fact=f"Host {ip} transferred {self._format_bytes(total_curr_bytes)} in {duration:.1f}s ({self._format_bytes(curr_rate)}/s). Historical baseline average for this host is {self._format_bytes(hist_avg_rate)}/s.",
                        statistical_context=f"{ratio:.1f}x throughput increase above historical baseline mean ({self._format_bytes(hist_avg_rate)}/s across {hist_data['captures_observed']} observations).",
                        inferred_hypothesis="Elevated traffic volume; potential bulk data transfer, exfiltration, or abnormal network consumption.",
                        alternative_benign_explanation="Software patch download, scheduled cloud synchronization, OS telemetry push, or benchmark test.",
                        confidence=confidence,
                        priority_score=score,
                        severity="high" if ratio >= 8.0 else "medium",
                        first_seen_timestamp=h.get("first_seen") or current_results.get("start_time"),
                        comparison_context=f"Normalized against duration ({duration:.1f}s) and historical host average",
                        evidence_links={
                            "packets_filter": ip,
                            "host_ip": ip,
                        },
                        analyst_feedback=fb,
                    )
                    items.append(item)
                    change_seq += 1

        # -------------------------------------------------------------
        # Category E: Recurring Anomalies
        # -------------------------------------------------------------
        for f in current_results.get("findings", []):
            cat = f.get("category") or "General Anomaly"
            title = f.get("title") or "Unnamed Finding"
            src = f.get("source_ip") or ""
            dst = f.get("destination_ip") or ""
            entity = src or dst or "Network Traffic"

            sig = f"{cat}:{title}:{entity}"
            if sig in recurring_anomalies:
                rec_info = recurring_anomalies[sig]
                if rec_info.get("occurrences", 1) >= 2:
                    fb = feedback_map.get(sig)
                    is_exp = fb.get("is_expected", False) if fb else False
                    score = 90.0 * (0.3 if is_exp else 1.0)

                    item = ChangeItem(
                        id=f"change-{change_seq}",
                        category=ChangeCategory.RECURRING_ANOMALY,
                        title=f"Recurring Threat Detection: {title}",
                        entity=sig,
                        entity_type="anomaly",
                        observed_fact=f"Security detection '{title}' associated with {entity} observed again in this capture. Detected across {rec_info.get('occurrences')} historical captures.",
                        statistical_context=f"Recurring anomaly signature observed in {rec_info.get('occurrences')} separate capture sessions.",
                        inferred_hypothesis="Persistent uncontained threat activity, repetitive automated attack script, or persistent configuration weakness.",
                        alternative_benign_explanation="Scheduled internal security scanner, routine monitoring probe, or known benign protocol anomaly.",
                        confidence=confidence,
                        priority_score=score,
                        severity=f.get("severity", "medium"),
                        first_seen_timestamp=rec_info.get("first_seen"),
                        comparison_context=f"Tracked across {rec_info.get('occurrences')} capture sessions",
                        evidence_links={
                            "packets_filter": entity,
                            "finding_id": f.get("id"),
                        },
                        analyst_feedback=fb,
                    )
                    items.append(item)
                    change_seq += 1

        # 3. Sort items by priority score (descending)
        items.sort(key=lambda x: x.priority_score, reverse=True)

        # 4. Compute change briefing metrics
        new_dests = sum(1 for i in items if i.category == ChangeCategory.FIRST_SEEN_DESTINATION)
        new_rels = sum(1 for i in items if i.category == ChangeCategory.NEW_RELATIONSHIP)
        service_shifts = sum(1 for i in items if i.category == ChangeCategory.UNUSUAL_SERVICE)
        vol_drifts = sum(1 for i in items if i.category == ChangeCategory.VOLUME_DEVIATION)
        rec_anomalies = sum(1 for i in items if i.category == ChangeCategory.RECURRING_ANOMALY)

        top_cand = items[0].to_dict() if items else None

        return ChangeBriefing(
            capture_id=capture_id,
            filename=filename,
            analyzed_at=current_results.get("start_time") or 0.0,
            baseline_captures_count=prior_captures_count,
            baseline_duration_seconds=summary["total_duration_seconds"],
            baseline_health=health,
            baseline_warning=warning,
            total_changes_detected=len(items),
            new_destinations_count=new_dests,
            new_relationships_count=new_rels,
            service_shifts_count=service_shifts,
            volume_deviations_count=vol_drifts,
            recurring_anomalies_count=rec_anomalies,
            top_investigation_candidate=top_cand,
            items=items,
        )

    @staticmethod
    def _format_bytes(bytes_val: float) -> str:
        """Format byte counts into human-readable strings."""
        if not bytes_val and bytes_val != 0:
            return "0 B"
        k = 1024.0
        sizes = ["B", "KB", "MB", "GB", "TB"]
        b = abs(float(bytes_val))
        if b < 1:
            return "0 B"
        import math
        i = min(len(sizes) - 1, int(math.floor(math.log(b, k))))
        val = bytes_val / math.pow(k, i)
        return f"{val:.1f} {sizes[i]}"
