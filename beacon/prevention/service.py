"""Prevention service coordinating safety policies, firewall enforcement, expiry, and audit trails."""

from __future__ import annotations

import logging
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from beacon.models import Confidence, Finding
from beacon.prevention.adapters.base import FirewallAdapter
from beacon.prevention.adapters.dry_run import DryRunAdapter
from beacon.prevention.adapters.nftables import NftablesAdapter
from beacon.prevention.models import (
    AuditLogEntry,
    BlockRule,
    BlockStatus,
    EnforcementMode,
    PreventionPolicy,
)
from beacon.prevention.persistence import PreventionStore
from beacon.prevention.safety import validate_block_target

logger = logging.getLogger(__name__)


class PreventionService:
    """
    Central threat prevention service.
    Orchestrates policy evaluation, safety boundaries, adapter enforcement,
    timer-based expiration, and audit trail maintenance.
    """

    def __init__(
        self,
        adapter: Optional[FirewallAdapter] = None,
        store: Optional[PreventionStore] = None,
    ):
        self.store = store or PreventionStore()

        # Load persisted policy or use default
        saved_policy = self.store.load_policy()
        self.policy = saved_policy if saved_policy else PreventionPolicy()

        # Choose adapter: Nftables on Linux if available, otherwise DryRun
        if adapter is not None:
            self.adapter = adapter
        else:
            if sys.platform == "linux":
                nft = NftablesAdapter()
                avail, _ = nft.is_available()
                self.adapter = nft if avail else DryRunAdapter()
            else:
                self.adapter = DryRunAdapter()

        self._lock = threading.RLock()
        self._block_timestamps: List[float] = []  # For rate limiting
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._stop_event = threading.Event()

        # Startup reconciliation
        self.startup_reconciliation()

        # Background expiry worker thread
        self._expiry_thread = threading.Thread(
            target=self._expiry_worker,
            name="BeaconPreventionExpiryWorker",
            daemon=True,
        )
        self._expiry_thread.start()

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register subscriber callback for real-time prevention events."""
        with self._lock:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Unregister subscriber callback."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _broadcast(self, event: Dict[str, Any]) -> None:
        for cb in list(self._subscribers):
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Error notifying prevention subscriber: {e}")

    def update_policy(self, updated: PreventionPolicy) -> PreventionPolicy:
        """Update and persist prevention policy."""
        with self._lock:
            self.policy = updated
            self.store.save_policy(self.policy)
            self._log_audit(
                action="POLICY_UPDATED",
                details=f"Mode set to {self.policy.mode.value}, auto_protect={self.policy.auto_protect_enabled}",
            )
            self._broadcast({"type": "policy_updated", "policy": self.policy.to_dict()})
            return self.policy

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic status of the prevention engine."""
        with self._lock:
            avail, reason = self.adapter.is_available()
            active_rules = self.store.list_active_rules()
            return {
                "mode": self.policy.mode.value,
                "auto_protect_enabled": self.policy.auto_protect_enabled,
                "adapter_name": self.adapter.name,
                "adapter_available": avail,
                "adapter_status_message": reason,
                "active_rule_count": len(active_rules),
                "max_active_rules": self.policy.max_active_rules,
                "default_duration_seconds": self.policy.default_duration_seconds,
                "max_duration_seconds": self.policy.max_duration_seconds,
            }

    def _check_rate_limit(self) -> bool:
        """Sliding-window check to prevent runaway auto-blocking."""
        now = time.time()
        self._block_timestamps = [t for t in self._block_timestamps if now - t <= 60.0]
        if len(self._block_timestamps) >= self.policy.rate_limit_blocks_per_minute:
            return False
        return True

    def _record_rate_limit_hit(self) -> None:
        self._block_timestamps.append(time.time())

    def _log_audit(
        self,
        action: str,
        destination_ip: str = "",
        rule_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        details: str = "",
        user: str = "system",
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            action=action,
            destination_ip=destination_ip,
            rule_id=rule_id,
            finding_id=finding_id,
            details=details,
            user=user,
        )
        self.store.record_audit(entry)
        return entry

    def evaluate_finding(self, finding: Finding, is_live: bool = False) -> Optional[BlockRule]:
        """
        Evaluate a security finding against current prevention policy.
        Guarantees:
        - Never blocks traffic from offline PCAP analysis.
        - Only targets destination IP.
        - Enforces strict safety, allowlists, confidence thresholds, and verification.
        """
        # Strict guarantee: Offline PCAP analysis NEVER modifies firewall state
        if not is_live:
            return None

        # Threat blocking targets suspicious destination IP only
        target_ip = getattr(finding, "destination_ip", None)
        if not target_ip or not isinstance(target_ip, str):
            return None

        target_ip = target_ip.strip()

        with self._lock:
            # Check for existing active or pending rule for this IP
            existing = self.store.get_active_rule_for_ip(target_ip)
            if existing and existing.is_active:
                return existing

            # Validate target address & safety checks
            is_valid, reject_reason, collateral_warning = validate_block_target(target_ip, self.policy)
            if not is_valid:
                rule = BlockRule(
                    destination_ip=target_ip,
                    finding_id=getattr(finding, "id", None),
                    finding_title=getattr(finding, "title", "Security Finding"),
                    severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                    confidence=getattr(finding, "confidence", "medium").value if hasattr(getattr(finding, "confidence", None), "value") else str(getattr(finding, "confidence", "medium")),
                    status=BlockStatus.DETECTED_ONLY,
                    adapter_name=self.adapter.name,
                    error_message=reject_reason,
                    collateral_warning=collateral_warning,
                    applied_by="system",
                )
                self.store.save_rule(rule)
                self._log_audit(
                    action="REJECTED_SAFETY",
                    destination_ip=target_ip,
                    rule_id=rule.id,
                    finding_id=finding.id,
                    details=f"Target rejected by safety validator: {reject_reason}",
                )
                return rule

            # Check Policy Mode
            duration = min(self.policy.default_duration_seconds, self.policy.max_duration_seconds)
            now = time.time()

            # Mode 1: MONITOR_ONLY (Default)
            if self.policy.mode == EnforcementMode.MONITOR_ONLY:
                rule = BlockRule(
                    destination_ip=target_ip,
                    finding_id=getattr(finding, "id", None),
                    finding_title=getattr(finding, "title", "Security Finding"),
                    severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                    confidence=getattr(finding, "confidence", "medium").value if hasattr(getattr(finding, "confidence", None), "value") else str(getattr(finding, "confidence", "medium")),
                    duration_seconds=duration,
                    expires_at=now + duration,
                    status=BlockStatus.DETECTED_ONLY,
                    adapter_name=self.adapter.name,
                    collateral_warning=collateral_warning,
                    applied_by="system",
                    metadata={"reason": "Monitor-only policy active"},
                )
                self.store.save_rule(rule)
                self._log_audit(
                    action="MONITOR_DETECTED",
                    destination_ip=target_ip,
                    rule_id=rule.id,
                    finding_id=finding.id,
                    details="Threat detected. No block action taken under monitor-only policy.",
                )
                return rule

            # Mode 2: ASK_BEFORE_BLOCKING
            if self.policy.mode == EnforcementMode.ASK_BEFORE_BLOCKING:
                rule = BlockRule(
                    destination_ip=target_ip,
                    finding_id=getattr(finding, "id", None),
                    finding_title=getattr(finding, "title", "Security Finding"),
                    severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                    confidence=getattr(finding, "confidence", "medium").value if hasattr(getattr(finding, "confidence", None), "value") else str(getattr(finding, "confidence", "medium")),
                    duration_seconds=duration,
                    expires_at=now + duration,
                    status=BlockStatus.PENDING_APPROVAL,
                    adapter_name=self.adapter.name,
                    collateral_warning=collateral_warning,
                    applied_by="system",
                )
                self.store.save_rule(rule)
                self._log_audit(
                    action="PROPOSED",
                    destination_ip=target_ip,
                    rule_id=rule.id,
                    finding_id=finding.id,
                    details="Threat block proposed. Awaiting explicit user approval.",
                )
                self._broadcast({"type": "rule_proposed", "rule": rule.to_dict()})
                return rule

            # Mode 3: AUTOMATIC
            if self.policy.mode == EnforcementMode.AUTOMATIC:
                # Gating: Requires explicit opt-in flag
                if not self.policy.auto_protect_enabled:
                    logger.warning("Automatic mode configured but auto_protect_enabled is False. Defaulting to Ask.")
                    rule = BlockRule(
                        destination_ip=target_ip,
                        finding_id=getattr(finding, "id", None),
                        finding_title=getattr(finding, "title", "Security Finding"),
                        severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                        confidence=getattr(finding, "confidence", "medium").value if hasattr(getattr(finding, "confidence", None), "value") else str(getattr(finding, "confidence", "medium")),
                        duration_seconds=duration,
                        expires_at=now + duration,
                        status=BlockStatus.PENDING_APPROVAL,
                        adapter_name=self.adapter.name,
                        collateral_warning=collateral_warning,
                        applied_by="system",
                    )
                    self.store.save_rule(rule)
                    return rule

                # Gating: Must meet high confidence requirement
                f_conf = getattr(finding, "confidence", Confidence.LOW)
                conf_val = f_conf.value if hasattr(f_conf, "value") else str(f_conf).lower()
                if conf_val != Confidence.HIGH.value:
                    rule = BlockRule(
                        destination_ip=target_ip,
                        finding_id=getattr(finding, "id", None),
                        finding_title=getattr(finding, "title", "Security Finding"),
                        severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                        confidence=conf_val,
                        duration_seconds=duration,
                        expires_at=now + duration,
                        status=BlockStatus.DETECTED_ONLY,
                        adapter_name=self.adapter.name,
                        error_message="Automatic block requires HIGH confidence",
                        collateral_warning=collateral_warning,
                        applied_by="system",
                    )
                    self.store.save_rule(rule)
                    self._log_audit(
                        action="SKIPPED_LOW_CONFIDENCE",
                        destination_ip=target_ip,
                        rule_id=rule.id,
                        finding_id=finding.id,
                        details=f"Confidence '{conf_val}' below required HIGH threshold for autonomous block.",
                    )
                    return rule

                # Gating: Active rules count bound
                active_count = len(self.store.list_active_rules())
                if active_count >= self.policy.max_active_rules:
                    rule = BlockRule(
                        destination_ip=target_ip,
                        finding_id=getattr(finding, "id", None),
                        finding_title=getattr(finding, "title", "Security Finding"),
                        severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                        confidence=conf_val,
                        status=BlockStatus.FAILED,
                        adapter_name=self.adapter.name,
                        error_message=f"Active rule limit reached ({self.policy.max_active_rules})",
                        applied_by="system",
                    )
                    self.store.save_rule(rule)
                    self._log_audit(
                        action="CAPACITY_EXCEEDED",
                        destination_ip=target_ip,
                        details="Active rule limit reached. Block not applied.",
                    )
                    return rule

                # Gating: Rate limit check
                if not self._check_rate_limit():
                    rule = BlockRule(
                        destination_ip=target_ip,
                        finding_id=getattr(finding, "id", None),
                        finding_title=getattr(finding, "title", "Security Finding"),
                        severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                        confidence=conf_val,
                        status=BlockStatus.FAILED,
                        adapter_name=self.adapter.name,
                        error_message="Block rate limit exceeded",
                        applied_by="system",
                    )
                    self.store.save_rule(rule)
                    self._log_audit(
                        action="RATE_LIMITED",
                        destination_ip=target_ip,
                        details="Enforcement rate limit exceeded (10 blocks/min).",
                    )
                    return rule

                # Execute autonomous enforcement
                return self._apply_and_verify(
                    destination_ip=target_ip,
                    duration_seconds=duration,
                    finding_id=getattr(finding, "id", None),
                    finding_title=getattr(finding, "title", "Security Finding"),
                    severity=getattr(finding, "severity", "medium").value if hasattr(getattr(finding, "severity", None), "value") else str(getattr(finding, "severity", "medium")),
                    confidence=conf_val,
                    collateral_warning=collateral_warning,
                    applied_by="system",
                )

        return None

    def manual_block(
        self,
        destination_ip: str,
        duration_seconds: Optional[int] = None,
        reason: str = "Manual operator block",
        user: str = "operator",
    ) -> BlockRule:
        """Explicitly apply a block rule to a destination IP."""
        with self._lock:
            target_ip = destination_ip.strip()
            is_valid, reject_reason, collateral_warning = validate_block_target(target_ip, self.policy)
            if not is_valid:
                raise ValueError(f"Safety constraint violation: {reject_reason}")

            dur = duration_seconds or self.policy.default_duration_seconds
            dur = max(10, min(dur, self.policy.max_duration_seconds))

            return self._apply_and_verify(
                destination_ip=target_ip,
                duration_seconds=dur,
                finding_id=None,
                finding_title=reason,
                severity="medium",
                confidence="high",
                collateral_warning=collateral_warning,
                applied_by=user,
            )

    def approve_block(
        self,
        rule_id: str,
        duration_seconds: Optional[int] = None,
        user: str = "operator",
    ) -> BlockRule:
        """Approve a previously proposed / pending block rule."""
        with self._lock:
            rule = self.store.get_rule(rule_id)
            if not rule:
                raise KeyError(f"Rule ID '{rule_id}' not found")

            if rule.status == BlockStatus.ACTIVE and rule.is_active:
                return rule

            # Re-validate target
            is_valid, reject_reason, collateral_warning = validate_block_target(rule.destination_ip, self.policy)
            if not is_valid:
                rule.status = BlockStatus.FAILED
                rule.error_message = reject_reason
                self.store.save_rule(rule)
                self._log_audit(
                    action="APPROVAL_REJECTED_SAFETY",
                    destination_ip=rule.destination_ip,
                    rule_id=rule.id,
                    details=reject_reason or "",
                    user=user,
                )
                raise ValueError(f"Target safety validation failed: {reject_reason}")

            dur = duration_seconds or rule.duration_seconds
            dur = max(10, min(dur, self.policy.max_duration_seconds))

            applied_rule = self._apply_and_verify(
                destination_ip=rule.destination_ip,
                duration_seconds=dur,
                finding_id=rule.finding_id,
                finding_title=rule.finding_title,
                severity=rule.severity,
                confidence=rule.confidence,
                collateral_warning=collateral_warning,
                applied_by=user,
                existing_rule_id=rule.id,
            )
            return applied_rule

    def revoke_block(
        self,
        rule_id: str,
        reason: str = "Operator revoked",
        user: str = "operator",
    ) -> BlockRule:
        """Revoke and remove an active or pending block rule."""
        with self._lock:
            rule = self.store.get_rule(rule_id)
            if not rule:
                raise KeyError(f"Rule ID '{rule_id}' not found")

            # Remove from firewall
            ok, msg = self.adapter.remove_block(rule.destination_ip)
            rule.status = BlockStatus.REVOKED
            rule.metadata["revocation_reason"] = reason
            rule.metadata["revoked_by"] = user
            self.store.save_rule(rule)

            self._log_audit(
                action="REVOKED",
                destination_ip=rule.destination_ip,
                rule_id=rule.id,
                details=f"Block revoked: {reason} ({msg})",
                user=user,
            )
            self._broadcast({"type": "rule_revoked", "rule": rule.to_dict()})
            return rule

    def _apply_and_verify(
        self,
        destination_ip: str,
        duration_seconds: int,
        finding_id: Optional[str],
        finding_title: str,
        severity: str,
        confidence: str,
        collateral_warning: Optional[str],
        applied_by: str,
        existing_rule_id: Optional[str] = None,
    ) -> BlockRule:
        """Apply rule to firewall adapter and independently verify state before claiming success."""
        now = time.time()
        rule_id = existing_rule_id or f"rule_{int(now)}_{destination_ip.replace('.', '_')}"

        rule = BlockRule(
            id=rule_id,
            destination_ip=destination_ip,
            finding_id=finding_id,
            finding_title=finding_title,
            severity=severity,
            confidence=confidence,
            created_at=now,
            duration_seconds=duration_seconds,
            expires_at=now + duration_seconds,
            status=BlockStatus.PENDING_APPROVAL,
            adapter_name=self.adapter.name,
            verified=False,
            collateral_warning=collateral_warning,
            applied_by=applied_by,
        )

        # 1. Check adapter availability
        avail, avail_reason = self.adapter.is_available()
        if not avail:
            rule.status = BlockStatus.FAILED
            rule.error_message = f"Adapter unavailable: {avail_reason}"
            self.store.save_rule(rule)
            self._log_audit(
                action="FAILED",
                destination_ip=destination_ip,
                rule_id=rule.id,
                finding_id=finding_id,
                details=rule.error_message,
                user=applied_by,
            )
            return rule

        # 2. Apply block via adapter
        apply_ok, apply_msg = self.adapter.apply_block(destination_ip)
        if not apply_ok:
            rule.status = BlockStatus.FAILED
            rule.error_message = f"Firewall command failed: {apply_msg}"
            self.store.save_rule(rule)
            self._log_audit(
                action="FAILED",
                destination_ip=destination_ip,
                rule_id=rule.id,
                finding_id=finding_id,
                details=rule.error_message,
                user=applied_by,
            )
            return rule

        # 3. Independent State Verification
        # Never claim success without verifying firewall state!
        verified = self.adapter.verify_rule(destination_ip)
        if not verified:
            # Verification failed: Rollback immediately
            self.adapter.remove_block(destination_ip)
            rule.status = BlockStatus.FAILED
            rule.verified = False
            rule.error_message = "Firewall state verification failed after rule injection; rolled back."
            self.store.save_rule(rule)
            self._log_audit(
                action="VERIFICATION_FAILED_ROLLBACK",
                destination_ip=destination_ip,
                rule_id=rule.id,
                finding_id=finding_id,
                details=rule.error_message,
                user=applied_by,
            )
            return rule

        # 4. Verified & Active
        rule.status = BlockStatus.ACTIVE
        rule.verified = True
        self.store.save_rule(rule)
        self._record_rate_limit_hit()
        self._log_audit(
            action="APPLIED",
            destination_ip=destination_ip,
            rule_id=rule.id,
            finding_id=finding_id,
            details=f"Drop rule active ({duration_seconds}s) via {self.adapter.name}. State verified.",
            user=applied_by,
        )
        self._broadcast({"type": "rule_applied", "rule": rule.to_dict()})
        return rule

    def _expiry_worker(self) -> None:
        """Periodic background worker checking for and releasing expired temporary blocks."""
        while not self._stop_event.is_set():
            try:
                time.sleep(5.0)
                now = time.time()
                with self._lock:
                    active_rules = self.store.list_active_rules()
                    for rule in active_rules:
                        if now >= rule.expires_at:
                            self.adapter.remove_block(rule.destination_ip)
                            rule.status = BlockStatus.EXPIRED
                            self.store.save_rule(rule)
                            self._log_audit(
                                action="EXPIRED",
                                destination_ip=rule.destination_ip,
                                rule_id=rule.id,
                                details=f"Temporary block window ({rule.duration_seconds}s) expired.",
                                user="system",
                            )
                            self._broadcast({"type": "rule_expired", "rule": rule.to_dict()})
            except Exception as e:
                logger.error(f"Error in prevention expiry worker: {e}")

    def startup_reconciliation(self) -> None:
        """Reconcile active database rules with actual firewall adapter on startup."""
        with self._lock:
            now = time.time()
            active_rules = self.store.list_active_rules()
            expected_ips: Set[str] = set()

            for rule in active_rules:
                if now >= rule.expires_at:
                    rule.status = BlockStatus.EXPIRED
                    self.store.save_rule(rule)
                    self._log_audit(
                        action="EXPIRED_AT_STARTUP",
                        destination_ip=rule.destination_ip,
                        rule_id=rule.id,
                        details="Expired while system was offline.",
                    )
                else:
                    expected_ips.add(rule.destination_ip)

            added, pruned = self.adapter.reconcile(expected_ips)
            if added or pruned:
                self._log_audit(
                    action="STARTUP_RECONCILIATION",
                    details=f"Firewall reconciled: {len(added)} added, {len(pruned)} pruned.",
                )

    def shutdown(self) -> None:
        """Gracefully terminate background workers."""
        self._stop_event.set()


# Module-level singleton
_prevention_service: Optional[PreventionService] = None


def get_prevention_service() -> PreventionService:
    global _prevention_service
    if _prevention_service is None:
        _prevention_service = PreventionService()
    return _prevention_service
