"""Comprehensive tests for Beacon safe threat prevention and network blocking."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from beacon.api.server import app
from beacon.models import Confidence, Finding, Severity
from beacon.prevention.adapters.dry_run import DryRunAdapter
from beacon.prevention.adapters.nftables import (
    NFT_CHAIN,
    NFT_SET,
    NFT_TABLE,
    NftablesAdapter,
)
from beacon.prevention.models import (
    BlockRule,
    BlockStatus,
    EnforcementMode,
    PreventionPolicy,
)
from beacon.prevention.persistence import PreventionStore
from beacon.prevention.safety import (
    SHARED_INFRASTRUCTURE_NETWORKS,
    validate_block_target,
)
from beacon.prevention.service import PreventionService


@pytest.fixture
def temp_store(tmp_path: Path):
    """Provide an isolated SQLite database store for prevention tests."""
    db_path = tmp_path / "test_prevention.db"
    return PreventionStore(db_path=db_path)


@pytest.fixture
def dry_adapter():
    """Provide a fresh DryRunAdapter."""
    return DryRunAdapter()


@pytest.fixture
def service(temp_store, dry_adapter):
    """Provide a PreventionService instance isolated with temp store and dry adapter."""
    svc = PreventionService(adapter=dry_adapter, store=temp_store)
    yield svc
    svc.shutdown()


# =====================================================================
# 1. POLICY DEFAULTS & CONFIGURATION
# =====================================================================

def test_policy_defaults():
    """Policy must default to MONITOR_ONLY, auto_protect disabled, 15m expiry."""
    policy = PreventionPolicy()
    assert policy.mode == EnforcementMode.MONITOR_ONLY
    assert policy.auto_protect_enabled is False
    assert policy.default_duration_seconds == 900  # 15 minutes
    assert policy.max_duration_seconds == 86400  # 24 hours
    assert policy.max_active_rules == 100
    assert policy.rate_limit_blocks_per_minute == 10
    assert policy.min_confidence == Confidence.HIGH

    d = policy.to_dict()
    assert d["mode"] == "monitor"
    assert d["auto_protect_enabled"] is False
    assert d["default_duration_seconds"] == 900


def test_service_initial_status(service):
    """Service status should reflect default monitor-only configuration."""
    status = service.get_status()
    assert status["mode"] == "monitor"
    assert status["auto_protect_enabled"] is False
    assert status["adapter_name"] == "dry_run"
    assert status["adapter_available"] is True
    assert status["active_rule_count"] == 0
    assert status["max_active_rules"] == 100


# =====================================================================
# 2. SAFETY CHECKS & PROHIBITED TARGETS
# =====================================================================

@pytest.mark.parametrize(
    "prohibited_ip,expected_substring",
    [
        ("127.0.0.1", "Loopback"),
        ("127.0.0.53", "Loopback"),
        ("::1", "Loopback"),
        ("0.0.0.0", "Unspecified"),
        ("::", "Unspecified"),
        ("255.255.255.255", "Broadcast"),
        ("224.0.0.1", "Multicast"),
        ("ff02::1", "Multicast"),
        ("169.254.169.254", "Link-local"),
    ],
)
def test_safety_rejects_special_addresses(prohibited_ip, expected_substring):
    """Safety validator must reject loopback, broadcast, multicast, link-local, unspecified."""
    policy = PreventionPolicy()
    is_valid, reason, _ = validate_block_target(prohibited_ip, policy)
    assert is_valid is False
    assert expected_substring.lower() in reason.lower()


def test_safety_rejects_allowlist_and_critical_infra():
    """Safety validator must reject explicitly allowlisted IPs and default gateways."""
    policy = PreventionPolicy(
        allowlist_ips={"192.168.1.50"},
        allowlist_cidrs=["10.0.0.0/8"],
        critical_infrastructure={"192.168.1.1", "8.8.4.4"},
    )
    # Explicit IP allowlist
    ok, reason, _ = validate_block_target("192.168.1.50", policy)
    assert not ok
    assert "allowlist" in reason.lower()

    # CIDR allowlist
    ok, reason, _ = validate_block_target("10.5.20.1", policy)
    assert not ok
    assert "allowlisted" in reason.lower()

    # Critical infra
    ok, reason, _ = validate_block_target("192.168.1.1", policy)
    assert not ok
    assert "critical infrastructure" in reason.lower()


def test_safety_collateral_impact_warning():
    """Multi-tenant CDN IPs must pass validation but produce explicit cautionary warnings."""
    policy = PreventionPolicy()

    # Cloudflare Anycast
    ok, _, warning = validate_block_target("1.1.1.1", policy)
    assert ok is True
    assert warning is not None
    assert "Cloudflare" in warning

    # Google Public DNS
    ok, _, warning = validate_block_target("8.8.8.8", policy)
    assert ok is True
    assert warning is not None
    assert "Google" in warning

    # Quad9
    ok, _, warning = validate_block_target("9.9.9.9", policy)
    assert ok is True
    assert warning is not None
    assert "Quad9" in warning

    # Normal public IP has no collateral warning
    ok, _, warning = validate_block_target("198.51.100.42", policy)
    assert ok is True
    assert warning is None


def test_manual_block_safety_violation_raises(service):
    """Calling manual_block on a prohibited IP must raise ValueError."""
    with pytest.raises(ValueError, match="Safety constraint violation"):
        service.manual_block("127.0.0.1")

    with pytest.raises(ValueError, match="Safety constraint violation"):
        service.manual_block("255.255.255.255")


# =====================================================================
# 3. EXPLICIT OPT-IN & POLICY MODE HANDLING
# =====================================================================

def test_monitor_only_mode(service):
    """In MONITOR_ONLY mode, live findings create DETECTED_ONLY rules without blocking."""
    finding = Finding(
        id="find_test_1",
        category="c2",
        title="Command and Control Communication",
        description="Beaconing detected to suspicious IP",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        destination_ip="198.51.100.55",
    )
    rule = service.evaluate_finding(finding, is_live=True)
    assert rule is not None
    assert rule.status == BlockStatus.DETECTED_ONLY
    assert rule.destination_ip == "198.51.100.55"
    assert "198.51.100.55" not in service.adapter.list_active_rules()

    # Check audit log
    audit = service.store.get_audit_log(limit=5)
    assert any(a.action == "MONITOR_DETECTED" for a in audit)


def test_ask_before_blocking_mode(service):
    """In ASK_BEFORE_BLOCKING mode, findings create PENDING_APPROVAL rules awaiting sign-off."""
    service.update_policy(PreventionPolicy(mode=EnforcementMode.ASK_BEFORE_BLOCKING))

    finding = Finding(
        id="find_test_2",
        category="exfiltration",
        title="Data Exfiltration",
        description="High volume upload to external host",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        destination_ip="198.51.100.66",
    )
    rule = service.evaluate_finding(finding, is_live=True)
    assert rule is not None
    assert rule.status == BlockStatus.PENDING_APPROVAL
    # Not yet applied to firewall adapter
    assert "198.51.100.66" not in service.adapter.list_active_rules()

    audit = service.store.get_audit_log(limit=5)
    assert any(a.action == "PROPOSED" for a in audit)


def test_automatic_mode_requires_explicit_opt_in(service):
    """Automatic mode without auto_protect_enabled=True must default to PENDING_APPROVAL."""
    service.update_policy(
        PreventionPolicy(
            mode=EnforcementMode.AUTOMATIC,
            auto_protect_enabled=False,  # NOT opted in!
        )
    )

    finding = Finding(
        id="find_test_3",
        category="intrusion",
        title="High Severity Threat",
        description="Severe compromise indicator",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        destination_ip="198.51.100.77",
    )
    rule = service.evaluate_finding(finding, is_live=True)
    assert rule is not None
    assert rule.status == BlockStatus.PENDING_APPROVAL
    assert "198.51.100.77" not in service.adapter.list_active_rules()


# =====================================================================
# 4. CONFIDENCE THRESHOLD GATING FOR AUTOMATIC BLOCKING
# =====================================================================

def test_automatic_mode_rejects_medium_and_low_confidence(service):
    """Even with auto_protect enabled, MEDIUM and LOW confidence findings must not block."""
    service.update_policy(
        PreventionPolicy(
            mode=EnforcementMode.AUTOMATIC,
            auto_protect_enabled=True,
            min_confidence=Confidence.HIGH,
        )
    )

    # Medium confidence
    med_finding = Finding(
        id="find_med",
        category="reconnaissance",
        title="Possible Port Scan",
        description="Multiple SYN packets",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        destination_ip="198.51.100.81",
    )
    rule_med = service.evaluate_finding(med_finding, is_live=True)
    assert rule_med.status == BlockStatus.DETECTED_ONLY
    assert "HIGH confidence" in rule_med.error_message
    assert "198.51.100.81" not in service.adapter.list_active_rules()

    # Low confidence
    low_finding = Finding(
        id="find_low",
        category="policy",
        title="Unusual User-Agent",
        description="Unknown UA string",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        destination_ip="198.51.100.82",
    )
    rule_low = service.evaluate_finding(low_finding, is_live=True)
    assert rule_low.status == BlockStatus.DETECTED_ONLY
    assert "198.51.100.82" not in service.adapter.list_active_rules()

    # High confidence succeeds
    high_finding = Finding(
        id="find_high",
        category="c2",
        title="Confirmed Malware C2",
        description="Exact hash and beacon pattern match",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        destination_ip="198.51.100.83",
    )
    rule_high = service.evaluate_finding(high_finding, is_live=True)
    assert rule_high.status == BlockStatus.ACTIVE
    assert rule_high.verified is True
    assert "198.51.100.83" in service.adapter.list_active_rules()


# =====================================================================
# 5. MANUAL OPERATOR APPROVAL & REVOCATION WORKFLOW
# =====================================================================

def test_approval_and_revocation_workflow(service):
    """Operator approves a proposed rule, verifies active status, and revokes it."""
    # 1. Propose rule in ASK mode
    service.update_policy(PreventionPolicy(mode=EnforcementMode.ASK_BEFORE_BLOCKING))
    finding = Finding(
        id="find_workflow",
        category="brute_force",
        title="Brute Force Attacker",
        description="100 failed logins",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        destination_ip="198.51.100.90",
    )
    rule = service.evaluate_finding(finding, is_live=True)
    assert rule.status == BlockStatus.PENDING_APPROVAL

    # 2. Operator approves rule
    approved = service.approve_block(rule.id, duration_seconds=600, user="sec_analyst")
    assert approved.status == BlockStatus.ACTIVE
    assert approved.verified is True
    assert approved.applied_by == "sec_analyst"
    assert "198.51.100.90" in service.adapter.list_active_rules()

    # Audit log should show APPLIED
    audit = service.store.get_audit_log(limit=5)
    assert any(a.action == "APPLIED" and a.destination_ip == "198.51.100.90" for a in audit)

    # 3. Operator revokes rule
    revoked = service.revoke_block(approved.id, reason="Resolved threat", user="sec_lead")
    assert revoked.status == BlockStatus.REVOKED
    assert "198.51.100.90" not in service.adapter.list_active_rules()

    audit = service.store.get_audit_log(limit=5)
    assert any(a.action == "REVOKED" and a.destination_ip == "198.51.100.90" for a in audit)


def test_manual_block_workflow(service):
    """Operator directly creates a manual block."""
    rule = service.manual_block(
        destination_ip="198.51.100.95",
        duration_seconds=300,
        reason="Incident #404 investigation",
        user="soc_team",
    )
    assert rule.status == BlockStatus.ACTIVE
    assert rule.verified is True
    assert rule.duration_seconds == 300
    assert "198.51.100.95" in service.adapter.list_active_rules()


# =====================================================================
# 6. BOUNDS & RATE LIMITING
# =====================================================================

def test_max_active_rules_bound(temp_store, dry_adapter):
    """System must reject further blocks when max_active_rules capacity is reached."""
    svc = PreventionService(adapter=dry_adapter, store=temp_store)
    try:
        # Set max_active_rules to 2 for deterministic test
        svc.update_policy(
            PreventionPolicy(
                mode=EnforcementMode.AUTOMATIC,
                auto_protect_enabled=True,
                max_active_rules=2,
            )
        )

        svc.manual_block("198.51.100.1")
        svc.manual_block("198.51.100.2")

        # 3rd block via auto-evaluate
        finding = Finding(
            id="find_capacity",
            category="test",
            title="Capacity Test Finding",
            description="Capacity Test Finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            destination_ip="198.51.100.3",
        )
        rule = svc.evaluate_finding(finding, is_live=True)
        assert rule.status == BlockStatus.FAILED
        assert "Active rule limit reached" in rule.error_message
        assert "198.51.100.3" not in svc.adapter.list_active_rules()
    finally:
        svc.shutdown()


def test_sliding_window_rate_limiting(temp_store, dry_adapter):
    """System must throttle blocks when rate limit is exceeded."""
    svc = PreventionService(adapter=dry_adapter, store=temp_store)
    try:
        svc.update_policy(
            PreventionPolicy(
                mode=EnforcementMode.AUTOMATIC,
                auto_protect_enabled=True,
                rate_limit_blocks_per_minute=2,
            )
        )

        svc.manual_block("198.51.100.11")
        svc.manual_block("198.51.100.12")

        # 3rd block exceeds 2 blocks/min limit
        finding = Finding(
            id="find_rate",
            category="test",
            title="Rate Test Finding",
            description="Rate Test Finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            destination_ip="198.51.100.13",
        )
        rule = svc.evaluate_finding(finding, is_live=True)
        assert rule.status == BlockStatus.FAILED
        assert "rate limit exceeded" in rule.error_message.lower()
        assert "198.51.100.13" not in svc.adapter.list_active_rules()
    finally:
        svc.shutdown()


# =====================================================================
# 7. INDEPENDENT VERIFICATION FAILURE & IMMEDIATE ROLLBACK
# =====================================================================

def test_verification_failure_triggers_immediate_rollback(temp_store):
    """If adapter.verify_rule returns False after apply, system rolls back immediately."""
    # DryRunAdapter configured with failure_mode="verify"
    failing_adapter = DryRunAdapter(failure_mode="verify")
    svc = PreventionService(adapter=failing_adapter, store=temp_store)
    try:
        rule = svc.manual_block("198.51.100.99")
        assert rule.status == BlockStatus.FAILED
        assert rule.verified is False
        assert "verification failed" in rule.error_message.lower()

        # Target IP must NOT remain in adapter
        assert "198.51.100.99" not in failing_adapter.list_active_rules()

        # Audit log must record VERIFICATION_FAILED_ROLLBACK
        audit = svc.store.get_audit_log(limit=5)
        assert any(a.action == "VERIFICATION_FAILED_ROLLBACK" for a in audit)
    finally:
        svc.shutdown()


def test_adapter_unavailable_handling(temp_store):
    """When adapter is unavailable, rules fail gracefully without crashing."""
    unavail_adapter = DryRunAdapter(available=False)
    svc = PreventionService(adapter=unavail_adapter, store=temp_store)
    try:
        rule = svc.manual_block("198.51.100.70")
        assert rule.status == BlockStatus.FAILED
        assert "Adapter unavailable" in rule.error_message
    finally:
        svc.shutdown()


# =====================================================================
# 8. EXPIRY & STARTUP RECONCILIATION
# =====================================================================

def test_startup_reconciliation_cleans_expired_and_restores_active(tmp_path):
    """Startup reconciliation cleans up expired rules and re-applies unexpired ones."""
    db_path = tmp_path / "recon_test.db"
    store = PreventionStore(db_path=db_path)
    now = time.time()

    # Rule 1: Expired while system was down
    expired_rule = BlockRule(
        id="rule_old",
        destination_ip="198.51.100.101",
        created_at=now - 1200,
        duration_seconds=600,
        expires_at=now - 600,  # in the past!
        status=BlockStatus.ACTIVE,
        verified=True,
    )
    store.save_rule(expired_rule)

    # Rule 2: Still active with remaining time
    active_rule = BlockRule(
        id="rule_live",
        destination_ip="198.51.100.102",
        created_at=now - 100,
        duration_seconds=600,
        expires_at=now + 500,  # 500s remaining!
        status=BlockStatus.ACTIVE,
        verified=True,
    )
    store.save_rule(active_rule)

    # Launch service with a fresh adapter
    fresh_adapter = DryRunAdapter()
    svc = PreventionService(adapter=fresh_adapter, store=store)
    try:
        # Expired rule should be marked EXPIRED
        r1 = store.get_rule("rule_old")
        assert r1.status == BlockStatus.EXPIRED

        # Active rule should remain active and be restored to firewall
        r2 = store.get_rule("rule_live")
        assert r2.status == BlockStatus.ACTIVE
        assert "198.51.100.102" in fresh_adapter.list_active_rules()

        # Audit log should note EXPIRED_AT_STARTUP
        audit = store.get_audit_log(limit=10)
        assert any(a.action == "EXPIRED_AT_STARTUP" and a.destination_ip == "198.51.100.101" for a in audit)
    finally:
        svc.shutdown()


# =====================================================================
# 9. OFFLINE PCAP ANALYSIS ISOLATION GUARANTEE
# =====================================================================

def test_offline_pcap_analysis_never_blocks(service):
    """CRITICAL: evaluate_finding with is_live=False must return None and NEVER modify firewall."""
    finding = Finding(
        id="find_offline",
        category="c2",
        title="High Severity Historical Threat",
        description="Evidence found in imported PCAP file",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        destination_ip="198.51.100.200",
    )

    result = service.evaluate_finding(finding, is_live=False)
    assert result is None

    # Firewall must remain completely empty
    assert len(service.adapter.list_active_rules()) == 0

    # Database rules must have no records
    assert len(service.store.list_active_rules()) == 0

    # No audit log entry should be created for offline evaluation
    audit = service.store.get_audit_log(limit=5)
    assert len(audit) == 0


# =====================================================================
# 10. API AUTHENTICATION & REST ENDPOINTS
# =====================================================================

def test_prevention_api_unauthenticated_without_pin():
    """When BEACON_PIN is not set, prevention routes work in local development mode."""
    client = TestClient(app)
    if "BEACON_PIN" in os.environ:
        del os.environ["BEACON_PIN"]

    res = client.get("/api/prevention/status")
    assert res.status_code == 200
    assert "mode" in res.json()

    res = client.get("/api/prevention/rules")
    assert res.status_code == 200
    assert "rules" in res.json()


def test_prevention_api_pin_protection():
    """When BEACON_PIN is set, prevention routes require X-Beacon-PIN header."""
    os.environ["BEACON_PIN"] = "guard123"
    client = TestClient(app)

    try:
        # 1. Unauthenticated request -> 401
        res = client.get("/api/prevention/status")
        assert res.status_code == 401

        # 2. Wrong PIN -> 401
        res = client.get("/api/prevention/status", headers={"X-Beacon-PIN": "wrong"})
        assert res.status_code == 401

        # 3. Correct PIN -> 200
        res = client.get("/api/prevention/status", headers={"X-Beacon-PIN": "guard123"})
        assert res.status_code == 200
        assert res.json()["adapter_name"] is not None

        # 4. Prohibited target block -> 400 with safety error
        block_fail = client.post(
            "/api/prevention/block",
            headers={"X-Beacon-PIN": "guard123"},
            json={"destination_ip": "127.0.0.1", "duration_seconds": 60},
        )
        assert block_fail.status_code == 400
        assert "Safety constraint violation" in block_fail.json()["detail"]

        # 5. Valid manual block via API
        block_ok = client.post(
            "/api/prevention/block",
            headers={"X-Beacon-PIN": "guard123"},
            json={"destination_ip": "198.51.100.222", "duration_seconds": 60, "reason": "API test block"},
        )
        assert block_ok.status_code == 200
        data = block_ok.json()
        assert data["status"] == "active"
        rule_id = data["id"]

        # 6. Revoke block via API
        revoke_res = client.post(
            f"/api/prevention/rules/{rule_id}/revoke",
            headers={"X-Beacon-PIN": "guard123"},
            json={"reason": "Test finished"},
        )
        assert revoke_res.status_code == 200
        assert revoke_res.json()["status"] == "revoked"

        # 7. Audit trail endpoint
        audit_res = client.get("/api/prevention/audit", headers={"X-Beacon-PIN": "guard123"})
        assert audit_res.status_code == 200
        assert len(audit_res.json()["audit_log"]) > 0

    finally:
        del os.environ["BEACON_PIN"]


# =====================================================================
# 11. LINUX NFTABLES ADAPTER ISOLATION & COMMAND CONSTRAINTS
# =====================================================================

def test_nftables_constants_and_table_isolation():
    """Nftables adapter must use isolated table and set names, never touching default tables."""
    assert NFT_TABLE == "beacon_firewall"
    assert NFT_SET == "beacon_blocked_dest"
    assert NFT_CHAIN == "beacon_egress"

    adapter = NftablesAdapter(nft_binary="/nonexistent/nft")
    assert adapter.name == "nftables"

    # Availability check on non-Linux or without binary
    avail, reason = adapter.is_available()
    if sys.platform != "linux":
        assert not avail
        assert "only supported on Linux" in reason
    else:
        assert not avail
        assert "not found" in reason or "check failed" in reason
