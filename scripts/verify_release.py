#!/usr/bin/env python3
"""
Comprehensive automated validation script for Beacon release artifacts.
Tests:
- Standalone CLI execution from arbitrary working directory
- Backend startup and readiness check
- Single-origin production React SPA serving
- API endpoint responses (/api/health, /api/live/status, /api/analyses)
- WebSocket handshake on /ws/live (HTTP 101 Switching Protocols)
- Clean process shutdown and port release
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
exe_name = "Beacon.exe" if sys.platform == "win32" else "Beacon"
DIST_EXE = REPO_ROOT / "dist" / exe_name
if not DIST_EXE.exists() and (REPO_ROOT / "dist" / "Beacon.app" / "Contents" / "MacOS" / "Beacon").exists():
    DIST_EXE = REPO_ROOT / "dist" / "Beacon.app" / "Contents" / "MacOS" / "Beacon"
elif not DIST_EXE.exists() and (REPO_ROOT / "dist" / "Beacon" / exe_name).exists():
    DIST_EXE = REPO_ROOT / "dist" / "Beacon" / exe_name
TEST_PORT = 8999


def log(msg: str) -> None:
    print(f"[TEST] {msg}")


def test_cli_commands() -> None:
    log("Testing CLI commands from independent working directory...")
    temp_dir = Path(os.environ.get("TEMP", "/tmp"))

    # Test 1: --version
    res = subprocess.run([str(DIST_EXE), "--version"], cwd=temp_dir, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert res.returncode == 0, f"--version failed: {res.stderr}"
    assert "0.1.0" in res.stdout
    log("  [PASS] CLI --version check")

    # Test 2: --help
    res = subprocess.run([str(DIST_EXE), "--help"], cwd=temp_dir, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert res.returncode == 0, f"--help failed: {res.stderr}"
    assert "Usage:" in res.stdout
    log("  [PASS] CLI --help check")

    # Test 3: PCAP Analysis
    sample_pcap = REPO_ROOT / "examples" / "sample.pcap"
    if sample_pcap.exists():
        res = subprocess.run(
            [str(DIST_EXE), "analyze", str(sample_pcap), "--mode", "blue"],
            cwd=temp_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert res.returncode == 0, f"analyze failed: {res.stderr}"
        assert "Total Packets" in res.stdout
        log("  [PASS] CLI analyze command with sample.pcap")


def test_websocket_handshake(host: str, port: int) -> bool:
    """Test WebSocket HTTP 101 Upgrade handshake directly using raw socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((host, port))
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        handshake = (
            f"GET /api/live/ws HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        s.sendall(handshake.encode("ascii"))
        response = s.recv(4096).decode("utf-8", errors="ignore")
        return "101 Switching Protocols" in response
    finally:
        s.close()


def main() -> None:
    print("=" * 70)
    print("  BEACON RELEASE ARTIFACT VALIDATION SUITE")
    print("=" * 70)

    if not DIST_EXE.exists():
        print(f"[!] Target release executable not found at: {DIST_EXE}", file=sys.stderr)
        sys.exit(1)

    log(f"Target Executable: {DIST_EXE}")

    # 1. Test CLI execution
    test_cli_commands()

    # 2. Test Server & Web Launcher
    log(f"Launching production server on port {TEST_PORT}...")
    temp_dir = Path(os.environ.get("TEMP", "/tmp"))
    proc = subprocess.Popen(
        [str(DIST_EXE), "launch", "--port", str(TEST_PORT), "--no-browser"],
        cwd=temp_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    try:
        # 3. Wait for readiness
        log(f"Waiting for /api/health at http://127.0.0.1:{TEST_PORT}/api/health...")
        ready = False
        deadline = time.time() + 25.0
        while time.time() < deadline:
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{TEST_PORT}/api/health")
                with urllib.request.urlopen(req, timeout=0.5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        if data.get("status") == "healthy":
                            ready = True
                            break
            except Exception:
                pass
            time.sleep(0.2)

        assert ready, "Server failed to respond to /api/health within 25 seconds"
        log("  [PASS] Backend readiness check /api/health (200 OK)")

        # 4. Test API Endpoints
        req = urllib.request.Request(f"http://127.0.0.1:{TEST_PORT}/api/live/status")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "status" in data
        log("  [PASS] Live status API endpoint /api/live/status (200 OK)")

        req = urllib.request.Request(f"http://127.0.0.1:{TEST_PORT}/api/analyses")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            assert resp.status == 200
        log("  [PASS] Analyses catalog API endpoint /api/analyses (200 OK)")

        # 5. Test Frontend SPA Serving
        req = urllib.request.Request(f"http://127.0.0.1:{TEST_PORT}/")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert '<div id="root"></div>' in html
            assert "Beacon" in html
        log("  [PASS] Root React SPA endpoint / (200 OK, root div verified)")

        # 6. Test Static Assets Serving
        match = re.search(r'href="(/assets/[^"]+\.css)"', html)
        if match:
            css_path = match.group(1)
            req = urllib.request.Request(f"http://127.0.0.1:{TEST_PORT}{css_path}")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                assert resp.status == 200
                assert "text/css" in resp.headers.get("Content-Type", "")
            log(f"  [PASS] Static CSS asset {css_path} (200 OK, text/css)")

        # 7. Test WebSocket Handshake
        ws_ok = test_websocket_handshake("127.0.0.1", TEST_PORT)
        assert ws_ok, "WebSocket upgrade handshake failed"
        log("  [PASS] WebSocket handshake on /ws/live (101 Switching Protocols)")

    finally:
        # 8. Clean shutdown
        log("Shutting down test server...")
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)

        # Verify port released
        deadline = time.time() + 5.0
        released = False
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", TEST_PORT)) != 0:
                    released = True
                    break
            time.sleep(0.2)
        assert released, f"Port {TEST_PORT} remained bound after termination"
        log("  [PASS] Clean process termination and port release")

    print("\n" + "=" * 70)
    print("  ALL RELEASE ARTIFACT TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
