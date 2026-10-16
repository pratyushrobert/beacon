"""Path resolution utilities for cross-platform execution, packaging, and persistent data."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


def get_beacon_data_dir() -> Path:
    """
    Get the user-specific persistent data directory.
    Respects BEACON_DATA_DIR env var, otherwise defaults to ~/.beacon.
    """
    env_dir = os.environ.get("BEACON_DATA_DIR")
    if env_dir:
        data_dir = Path(env_dir).resolve()
    else:
        data_dir = Path.home() / ".beacon"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_beacon_cache_dir() -> Path:
    """
    Get the cache directory for PCAP parsing and analysis index.
    Respects BEACON_CACHE_DIR env var. If in a source repository with a local cache/,
    uses ./cache for development parity, otherwise uses ~/.beacon/cache.
    """
    env_dir = os.environ.get("BEACON_CACHE_DIR")
    if env_dir:
        cache_dir = Path(env_dir).resolve()
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    # In local development repository with ./cache present
    local_cache = Path("cache")
    if local_cache.is_dir() and Path("pyproject.toml").is_file():
        return local_cache.resolve()

    cache_dir = get_beacon_data_dir() / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_beacon_logs_dir() -> Path:
    """Get the log directory (~/.beacon/logs)."""
    logs_dir = get_beacon_data_dir() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def get_beacon_lock_path() -> Path:
    """Get the lock file path used to detect and prevent duplicate instances."""
    return get_beacon_data_dir() / "beacon.lock"


def find_frontend_dist() -> Optional[Path]:
    """
    Locate pre-built React production frontend assets across:
    1. BEACON_FRONTEND_DIR environment variable
    2. PyInstaller bundle directory (sys._MEIPASS)
    3. Application executable directory (one-folder PyInstaller or portable distribution)
    4. Source repository layout (repo_root / web / dist)
    """
    # 1. Environment variable override
    env_dir = os.environ.get("BEACON_FRONTEND_DIR")
    if env_dir:
        candidate = Path(env_dir).resolve()
        if candidate.is_dir() and (candidate / "index.html").is_file():
            return candidate

    # 2. PyInstaller bundle directory (_MEIPASS)
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        for sub in [Path(meipass) / "web" / "dist", Path(meipass) / "dist"]:
            if sub.is_dir() and (sub / "index.html").is_file():
                return sub.resolve()

    # 3. Executable directory (for PyInstaller one-folder mode or standalone release folder)
    exe_dir = Path(sys.executable).parent.resolve()
    for sub in [
        exe_dir / "web" / "dist",
        exe_dir / "dist",
        exe_dir / "_internal" / "web" / "dist",
        exe_dir / "resources" / "web" / "dist",
    ]:
        if sub.is_dir() and (sub / "index.html").is_file():
            return sub.resolve()

    # 4. Source repository layout
    source_candidate = Path(__file__).resolve().parent.parent.parent / "web" / "dist"
    if source_candidate.is_dir() and (source_candidate / "index.html").is_file():
        return source_candidate.resolve()

    return None
