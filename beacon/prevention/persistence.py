"""Persistent storage for threat prevention policy, block rules, and audit logs."""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from beacon.prevention.models import AuditLogEntry, BlockRule, BlockStatus, PreventionPolicy
from beacon.utils.paths import get_beacon_data_dir

logger = logging.getLogger(__name__)


class PreventionStore:
    """SQLite-backed persistent store for prevention state, active rules, and audit trails."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            data_dir = get_beacon_data_dir()
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "prevention.db"

        self.db_path = Path(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create necessary tables and indices if not present."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS prevention_policy (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS block_rules (
                    id TEXT PRIMARY KEY,
                    destination_ip TEXT NOT NULL,
                    finding_id TEXT,
                    finding_title TEXT,
                    severity TEXT,
                    confidence TEXT,
                    created_at REAL NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    adapter_name TEXT NOT NULL,
                    verified INTEGER NOT NULL,
                    error_message TEXT,
                    collateral_warning TEXT,
                    applied_by TEXT NOT NULL,
                    metadata TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_ip ON block_rules (destination_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_status ON block_rules (status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_expires ON block_rules (expires_at)")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS prevention_audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    action TEXT NOT NULL,
                    destination_ip TEXT,
                    rule_id TEXT,
                    finding_id TEXT,
                    details TEXT,
                    user TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON prevention_audit_log (timestamp DESC)")
            conn.commit()

    def save_policy(self, policy: PreventionPolicy) -> None:
        """Persist current policy configuration."""
        data_json = json.dumps(policy.to_dict())
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO prevention_policy (key, value) VALUES ('current_policy', ?)",
                (data_json,),
            )
            conn.commit()

    def load_policy(self) -> Optional[PreventionPolicy]:
        """Load stored policy configuration if available."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM prevention_policy WHERE key = 'current_policy'"
            ).fetchone()
            if row:
                try:
                    data = json.loads(row["value"])
                    return PreventionPolicy.from_dict(data)
                except Exception as e:
                    logger.error(f"Failed parsing stored policy: {e}")
        return None

    def save_rule(self, rule: BlockRule) -> None:
        """Insert or update a block rule."""
        meta_json = json.dumps(rule.metadata)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO block_rules (
                    id, destination_ip, finding_id, finding_title, severity, confidence,
                    created_at, duration_seconds, expires_at, status, adapter_name,
                    verified, error_message, collateral_warning, applied_by, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.id,
                    rule.destination_ip,
                    rule.finding_id,
                    rule.finding_title,
                    rule.severity,
                    rule.confidence,
                    rule.created_at,
                    rule.duration_seconds,
                    rule.expires_at,
                    rule.status.value,
                    rule.adapter_name,
                    1 if rule.verified else 0,
                    rule.error_message,
                    rule.collateral_warning,
                    rule.applied_by,
                    meta_json,
                ),
            )
            conn.commit()

    def get_rule(self, rule_id: str) -> Optional[BlockRule]:
        """Fetch a specific rule by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM block_rules WHERE id = ?", (rule_id,)).fetchone()
            if row:
                return self._row_to_rule(row)
        return None

    def get_active_rule_for_ip(self, ip: str) -> Optional[BlockRule]:
        """Fetch active rule for destination IP if exists."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM block_rules WHERE destination_ip = ? AND status = 'active'",
                (ip,),
            ).fetchone()
            if row:
                return self._row_to_rule(row)
        return None

    def list_rules(self, status: Optional[str] = None) -> List[BlockRule]:
        """List rules with optional status filter."""
        query = "SELECT * FROM block_rules"
        params = []
        if status and status.lower() != "all":
            query += " WHERE status = ?"
            params.append(status.lower())
        query += " ORDER BY created_at DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_rule(r) for r in rows]

    def list_active_rules(self) -> List[BlockRule]:
        """List currently active rules."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM block_rules WHERE status = 'active' ORDER BY expires_at ASC"
            ).fetchall()
            return [self._row_to_rule(r) for r in rows]

    def record_audit(self, entry: AuditLogEntry) -> None:
        """Insert an audit log record."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO prevention_audit_log (
                    id, timestamp, action, destination_ip, rule_id, finding_id, details, user
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.timestamp,
                    entry.action,
                    entry.destination_ip,
                    entry.rule_id,
                    entry.finding_id,
                    entry.details,
                    entry.user,
                ),
            )
            conn.commit()

    def get_audit_log(self, limit: int = 100) -> List[AuditLogEntry]:
        """Retrieve recent audit log entries."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM prevention_audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                AuditLogEntry(
                    id=r["id"],
                    timestamp=r["timestamp"],
                    action=r["action"],
                    destination_ip=r["destination_ip"] or "",
                    rule_id=r["rule_id"],
                    finding_id=r["finding_id"],
                    details=r["details"] or "",
                    user=r["user"] or "system",
                )
                for r in rows
            ]

    def _row_to_rule(self, row: sqlite3.Row) -> BlockRule:
        try:
            meta = json.loads(row["metadata"]) if row["metadata"] else {}
        except Exception:
            meta = {}

        try:
            status = BlockStatus(row["status"])
        except ValueError:
            status = BlockStatus.DETECTED_ONLY

        return BlockRule(
            id=row["id"],
            destination_ip=row["destination_ip"],
            finding_id=row["finding_id"],
            finding_title=row["finding_title"] or "",
            severity=row["severity"] or "medium",
            confidence=row["confidence"] or "high",
            created_at=row["created_at"],
            duration_seconds=row["duration_seconds"],
            expires_at=row["expires_at"],
            status=status,
            adapter_name=row["adapter_name"],
            verified=bool(row["verified"]),
            error_message=row["error_message"],
            collateral_warning=row["collateral_warning"],
            applied_by=row["applied_by"],
            metadata=meta,
        )
