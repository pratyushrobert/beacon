"""Data models and enums for Beacon Memory historical baseline and change detection."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class ChangeCategory(str, enum.Enum):
    """Category of behavioral or structural change."""
    FIRST_SEEN_DESTINATION = "first_seen_destination"
    NEW_RELATIONSHIP = "new_relationship"
    UNUSUAL_SERVICE = "unusual_service"
    VOLUME_DEVIATION = "volume_deviation"
    RECURRING_ANOMALY = "recurring_anomaly"
    BEHAVIORAL_DRIFT = "behavioral_drift"


class ConfidenceLevel(str, enum.Enum):
    """Confidence level based on historical depth and data coverage."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BASELINE_FORMATION = "baseline_formation"


class BaselineHealth(str, enum.Enum):
    """Quality and depth of the historical baseline."""
    ESTABLISHED = "established"  # 3+ captures, good duration
    LIMITED = "limited"          # 1-2 captures
    INSUFFICIENT = "insufficient" # Empty or 0 prior captures
    INCOMPATIBLE = "incompatible" # Disjoint subnets or zero overlapping entities


class FeedbackStatus(str, enum.Enum):
    """Analyst review status for an entity, relationship, or anomaly."""
    UNREVIEWED = "unreviewed"
    EXPECTED = "expected"
    INVESTIGATING = "investigating"
    ACKNOWLEDGED = "acknowledged"


@dataclass
class ChangeItem:
    """
    An explainable change detected between a new observation and historical baseline.
    Separates concrete observed facts from statistical context and security hypotheses.
    """
    id: str
    category: ChangeCategory
    title: str
    entity: str
    entity_type: str  # 'host' | 'domain' | 'relationship' | 'service' | 'anomaly'
    observed_fact: str  # Concrete packet-derived metric description
    statistical_context: str  # Deviation, baseline comparison metric, occurrence frequency
    inferred_hypothesis: str  # Potential security implication
    alternative_benign_explanation: str  # Plausible non-malicious explanation
    confidence: ConfidenceLevel
    priority_score: float  # 0.0 - 100.0 for ranking
    severity: str  # 'critical' | 'high' | 'medium' | 'low' | 'info'
    first_seen_timestamp: Optional[float] = None
    comparison_context: str = "Compared against historical baseline"
    evidence_links: Dict[str, Any] = field(default_factory=dict)
    analyst_feedback: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        data = asdict(self)
        data["category"] = self.category.value
        data["confidence"] = self.confidence.value
        return data


@dataclass
class ChangeBriefing:
    """
    Executive change briefing summarizing network behavioral evolution.
    """
    capture_id: str
    filename: str
    analyzed_at: float
    baseline_captures_count: int
    baseline_duration_seconds: float
    baseline_health: BaselineHealth
    baseline_warning: Optional[str]
    total_changes_detected: int
    new_destinations_count: int
    new_relationships_count: int
    service_shifts_count: int
    volume_deviations_count: int
    recurring_anomalies_count: int
    top_investigation_candidate: Optional[Dict[str, Any]]
    items: List[ChangeItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        data = asdict(self)
        data["baseline_health"] = self.baseline_health.value
        data["items"] = [item.to_dict() if isinstance(item, ChangeItem) else item for item in self.items]
        return data


@dataclass
class RecurringAnomaly:
    """An anomaly or finding signature tracked across multiple historical captures."""
    signature: str
    category: str
    title: str
    severity: str
    entity: str
    first_seen: float
    last_seen: float
    occurrences: int
    captures: List[str] = field(default_factory=list)
    analyst_feedback: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalystFeedbackRecord:
    """Persistent analyst annotation and expectation status."""
    target_key: str
    target_type: str  # 'host' | 'relationship' | 'destination' | 'anomaly'
    status: FeedbackStatus
    is_expected: bool
    analyst_note: str
    created_at: float
    updated_at: float

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
