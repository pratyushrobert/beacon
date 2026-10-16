"""Tests for Beacon remote access, PIN authentication, and low-resource deployment."""

import os
from pathlib import Path
from fastapi.testclient import TestClient
from beacon.api.server import app, verify_access_pin


def test_auth_status_open_mode():
    """When BEACON_PIN is not set, auth_required is False and authenticated is True."""
    client = TestClient(app)
    if "BEACON_PIN" in os.environ:
        del os.environ["BEACON_PIN"]

    res = client.get("/api/auth/status")
    assert res.status_code == 200
    data = res.json()
    assert data["auth_required"] is False
    assert data["authenticated"] is True


def test_auth_status_pin_protected():
    """When BEACON_PIN is set, unauthenticated requests report auth_required True."""
    os.environ["BEACON_PIN"] = "secr3t"
    client = TestClient(app)

    try:
        # Without PIN header
        res = client.get("/api/auth/status")
        assert res.status_code == 200
        data = res.json()
        assert data["auth_required"] is True
        assert data["authenticated"] is False

        # With wrong PIN header
        res = client.get("/api/auth/status", headers={"X-Beacon-PIN": "wrong"})
        assert res.status_code == 200
        data = res.json()
        assert data["auth_required"] is True
        assert data["authenticated"] is False

        # With correct PIN header
        res = client.get("/api/auth/status", headers={"X-Beacon-PIN": "secr3t"})
        assert res.status_code == 200
        data = res.json()
        assert data["auth_required"] is True
        assert data["authenticated"] is True

        # POST /api/auth/verify with wrong pin
        verify_fail = client.post("/api/auth/verify", json={"pin": "wrong"})
        assert verify_fail.status_code == 401

        # POST /api/auth/verify with correct pin
        verify_ok = client.post("/api/auth/verify", json={"pin": "secr3t"})
        assert verify_ok.status_code == 200
        assert verify_ok.json()["success"] is True

        # Test protected action: /api/live/start without PIN should fail with 401
        start_fail = client.post("/api/live/start", json={"interface": "eth0"})
        assert start_fail.status_code == 401

    finally:
        del os.environ["BEACON_PIN"]


def test_system_status_endpoint():
    """GET /api/system/status returns RSS memory usage, low-resource profile, and buffer status."""
    client = TestClient(app)
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.json()
    assert "process_memory_mb" in data
    assert isinstance(data["process_memory_mb"], (int, float))
    assert data["process_memory_mb"] > 0
    assert "low_resource_mode" in data
    assert "buffer_capacity" in data
    assert "incidents_count" in data


def test_spa_static_files_serving():
    """FastAPI serves compiled SPA index.html for root and client routes."""
    client = TestClient(app)
    dist_index = Path(__file__).resolve().parent.parent / "web" / "dist" / "index.html"
    if dist_index.exists():
        res = client.get("/")
        assert res.status_code == 200
        assert "html" in res.headers.get("content-type", "").lower()

        res_route = client.get("/upload")
        assert res_route.status_code == 200
        assert "html" in res_route.headers.get("content-type", "").lower()
