"""Safe threat prevention and modular network blocking models for Beacon."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import uuid

from beacon.models import Confidence, Severity


class EnforcementMode(str, Enum):
    """Enforcement policy mode."""

    MONITOR_ONLY = "monitor"  # Default: Observe only, no blocking proposals
    ASK_BEFORE_BLOCKING = "ask"  # Require explicit user approval before blocking
    AUTOMATIC = "auto"  # Autonomous blocking for high-confidence threats (disabled by default)


class BlockStatus(str, Enum):
    """Lifecycle state of an enforcement rule."""

    PENDING_APPROVAL = "pending_approval"  # Proposed by finding, awaiting human sign-off
    ACTIVE = "active"  # Enforced in firewall and verified
    EXPIRED = "expired"  # Automatically released after time window
    REVOKED = "revoked"  # Manually released by user
    FAILED = "failed"  # Adapter failed to apply or verify rule
    DETECTED_ONLY = "detected_only"  # Prohibited target, safety violation, or monitor mode


@dataclass
class PreventionPolicy:
    """Configurable threat prevention policy."""

    mode: EnforcementMode = EnforcementMode.MONITOR_ONLY
    auto_protect_enabled: bool = False
    default_duration_seconds: int = 900  # 15 minutes default
    max_duration_seconds: int = 86400  # 24 hours maximum upper limit
    max_active_rules: int = 100  # Bounded rule count to prevent state exhaustion
    rate_limit_blocks_per_minute: int = 10  # Max blocks within a 60-second window
    allowlist_ips: Set[str] = field(default_factory=set)
    allowlist_cidrs: List[str] = field(default_factory=list)
    critical_infrastructure: Set[str] = field(default_factory=set)  # Default gateways, DNS
    min_confidence: Confidence = Confidence.HIGH

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "auto_protect_enabled": self.auto_protect_enabled,
            "default_duration_seconds": self.default_duration_seconds,
            "max_duration_seconds": self.max_duration_seconds,
            "max_active_rules": self.max_active_rules,
            "rate_limit_blocks_per_minute": self.rate_limit_blocks_per_minute,
            "allowlist_ips": sorted(list(self.allowlist_ips)),
            "allowlist_cidrs": list(self.allowlist_cidrs),
            "critical_infrastructure": sorted(list(self.critical_infrastructure)),
            "min_confidence": self.min_confidence.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PreventionPolicy:
        mode_val = data.get("mode", EnforcementMode.MONITOR_ONLY.value)
        try:
            mode = EnforcementMode(mode_val)
        except ValueError:
            mode = EnforcementMode.MONITOR_ONLY

        min_conf_val = data.get("min_confidence", Confidence.HIGH.value)
        try:
            min_conf = Confidence(min_conf_val)
        except ValueError:
            min_conf = Confidence.HIGH

        return cls(
            mode=mode,
            auto_protect_enabled=bool(data.get("auto_protect_enabled", False)),
            default_duration_seconds=int(data.get("default_duration_seconds", 900)),
            max_duration_seconds=int(data.get("max_duration_seconds", 86400)),
            max_active_rules=int(data.get("max_active_rules", 100)),
            rate_limit_blocks_per_minute=int(data.get("rate_limit_blocks_per_minute", 10)),
            allowlist_ips=set(data.get("allowlist_ips", [])),
            allowlist_cidrs=list(data.get("allowlist_cidrs", [])),
            critical_infrastructure=set(data.get("critical_infrastructure", [])),
            min_confidence=min_conf,
        )


@dataclass
class BlockRule:
    """An enforcement rule targeting a suspicious destination IP."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    destination_ip: str = ""
    finding_id: Optional[str] = None
    finding_title: str = ""
    severity: str = "medium"
    confidence: str = "high"
    created_at: float = field(default_factory=time.time)
    duration_seconds: int = 900
    expires_at: float = field(default_factory=lambda: time.time() + 900)
    status: BlockStatus = BlockStatus.PENDING_APPROVAL
    adapter_name: str = "dry_run"
    verified: bool = False
    error_message: Optional[str] = None
    collateral_warning: Optional[str] = None
    applied_by: str = "system"  # "system" (auto) or "user" (manual/approved)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.status == BlockStatus.ACTIVE and time.time() < self.expires_at

    @property
    def remaining_seconds(self) -> float:
        if self.status != BlockStatus.ACTIVE:
            return 0.0
        return max(0.0, round(self.expires_at - time.time(), 1))

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["is_active"] = self.is_active
        data["remaining_seconds"] = self.remaining_seconds
        return data


@dataclass
class AuditLogEntry:
    """Audit record of any threat-prevention action or safety decision."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: float = field(default_factory=time.time)
    action: str = ""  # PROPOSED, APPROVED, APPLIED, REMOVED, EXPIRED, REVOKED, REJECTED_SAFETY, FAILED
    destination_ip: str = ""
    rule_id: Optional[str] = None
    finding_id: Optional[str] = None
    details: str = ""
    user: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
