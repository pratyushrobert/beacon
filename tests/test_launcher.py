"""Tests for cross-platform launcher, single instance lock, port resolution, and frontend assets discovery."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from beacon.launcher import (
    SingleInstanceLock,
    check_existing_beacon,
    find_available_port,
    is_port_in_use,
    wait_for_backend_ready,
)
from beacon.utils.paths import (
    find_frontend_dist,
    get_beacon_cache_dir,
    get_beacon_data_dir,
    get_beacon_lock_path,
    get_beacon_logs_dir,
)


# =========================================================================
# 1. Path & Directory Resolution Tests
# =========================================================================

def test_get_beacon_data_dir(tmp_path: Path) -> None:
    """Test data directory resolution and creation."""
    custom_dir = tmp_path / "custom_data"
    with patch.dict(os.environ, {"BEACON_DATA_DIR": str(custom_dir)}):
        resolved = get_beacon_data_dir()
        assert resolved == custom_dir
        assert resolved.is_dir()


def test_get_beacon_cache_dir_env(tmp_path: Path) -> None:
    """Test cache directory resolution via environment variable."""
    custom_cache = tmp_path / "custom_cache"
    with patch.dict(os.environ, {"BEACON_CACHE_DIR": str(custom_cache)}):
        resolved = get_beacon_cache_dir()
        assert resolved == custom_cache
        assert resolved.is_dir()


def test_get_beacon_logs_dir(tmp_path: Path) -> None:
    """Test logs directory resolution under data dir."""
    with patch.dict(os.environ, {"BEACON_DATA_DIR": str(tmp_path)}):
        logs_dir = get_beacon_logs_dir()
        assert logs_dir == tmp_path / "logs"
        assert logs_dir.is_dir()


def test_find_frontend_dist_source() -> None:
    """Test that pre-built web/dist is found in repository layout."""
    dist = find_frontend_dist()
    if dist is None or not (dist / "index.html").is_file():
        pytest.skip("web/dist not built yet; run 'npm run build' inside web/ first")
    assert dist is not None
    assert dist.is_dir()
    assert (dist / "index.html").is_file()


def test_find_frontend_dist_env_override(tmp_path: Path) -> None:
    """Test that BEACON_FRONTEND_DIR overrides default paths."""
    fake_dist = tmp_path / "fake_dist"
    fake_dist.mkdir()
    (fake_dist / "index.html").write_text("<html></html>")

    with patch.dict(os.environ, {"BEACON_FRONTEND_DIR": str(fake_dist)}):
        dist = find_frontend_dist()
        assert dist == fake_dist


# =========================================================================
# 2. Port & Network Utility Tests
# =========================================================================

def test_is_port_in_use() -> None:
    """Test port listening detection with an ephemeral server socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        assert is_port_in_use("127.0.0.1", port) is True

    # After closing, port should not be in use
    assert is_port_in_use("127.0.0.1", port) is False


def test_find_available_port() -> None:
    """Test finding an open port starting from a given base port."""
    port = find_available_port("127.0.0.1", 8900)
    assert 8900 <= port < 8950


def test_check_existing_beacon_none() -> None:
    """Test probing an unused port returns None."""
    assert check_existing_beacon("127.0.0.1", 59999, timeout=0.1) is None


def test_wait_for_backend_ready_timeout() -> None:
    """Test readiness check timeout on dead port."""
    ready = wait_for_backend_ready("127.0.0.1", 59998, timeout=0.3)
    assert ready is False


# =========================================================================
# 3. Single Instance Lock Tests
# =========================================================================

def test_single_instance_lock_lifecycle(tmp_path: Path) -> None:
    """Verify lock acquisition, metadata storage, and clean release."""
    lock_file = tmp_path / "test.lock"
    lock1 = SingleInstanceLock(lock_file=lock_file)

    # First acquire succeeds
    assert lock1.acquire("127.0.0.1", 8000) is True
    assert lock1.acquired is True
    assert lock_file.exists()

    # Read written metadata
    meta = lock1.read_existing_metadata()
    assert meta is not None
    assert meta["port"] == 8000
    assert meta["host"] == "127.0.0.1"
    assert meta["pid"] == os.getpid()

    # Second acquire fails while first is holding the lock
    lock2 = SingleInstanceLock(lock_file=lock_file)
    assert lock2.acquire("127.0.0.1", 8001) is False
    assert lock2.acquired is False

    # First release cleans up
    lock1.release()
    assert lock1.acquired is False
    assert not lock_file.exists()

    # Now second acquire succeeds
    assert lock2.acquire("127.0.0.1", 8001) is True
    assert lock2.acquired is True
    lock2.release()


def test_check_existing_beacon_success() -> None:
    """Verify check_existing_beacon parses valid healthy response."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps({"status": "healthy", "version": "0.1.0"}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        info = check_existing_beacon("127.0.0.1", 8000)
        assert info is not None
        assert info["status"] == "healthy"
        assert info["version"] == "0.1.0"


def test_launch_beacon_existing_instance_opens_browser() -> None:
    """Verify launch_beacon redirects to existing instance without duplicate server start."""
    from beacon.launcher import launch_beacon

    with patch("beacon.launcher.is_port_in_use", return_value=True):
        with patch("beacon.launcher.check_existing_beacon", return_value={"status": "healthy", "version": "0.1.0"}):
            with patch("webbrowser.open") as mock_open:
                code = launch_beacon(port=8000, open_browser=True)
                assert code == 0
                mock_open.assert_called_once_with("http://127.0.0.1:8000/")

