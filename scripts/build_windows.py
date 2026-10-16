#!/usr/bin/env python3
"""
Automated Windows single-file release build script for Beacon.
Builds the production React frontend, runs PyInstaller to produce a genuinely self-contained
single-file executable in dist/Beacon.exe, and creates release documentation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_cmd(cmd: list[str], cwd: Path, description: str) -> None:
    print(f"\n[+] {description}...")
    print(f"    Running: {' '.join(cmd)} in {cwd}")
    res = subprocess.run(cmd, cwd=cwd, text=True)
    if res.returncode != 0:
        print(f"[!] ERROR: {description} failed with return code {res.returncode}", file=sys.stderr)
        sys.exit(res.returncode)


def main() -> None:
    print("=" * 70)
    print("  BEACON -- WINDOWS SINGLE-EXE RELEASE BUILD PIPELINE")
    print("=" * 70)

    web_dir = REPO_ROOT / "web"
    web_dist = web_dir / "dist"

    # Step 1: Ensure frontend is built
    if not (web_dist / "index.html").exists():
        print("\n[+] Frontend production assets not found. Compiling React app...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        run_cmd([npm_cmd, "run", "build"], cwd=web_dir, description="Building React web client")
    else:
        print("\n[+] Existing web/dist/index.html found.")

    # Step 2: Clean previous dist and intermediate build directories
    dist_dir = REPO_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    exe_name = "Beacon.exe" if sys.platform == "win32" else "Beacon"
    target_exe = dist_dir / exe_name

    if target_exe.exists():
        print(f"\n[+] Cleaning previous executable at {target_exe}...")
        try:
            target_exe.unlink()
        except Exception as e:
            print(f"[!] Warning cleaning {target_exe}: {e}")

    # Also clean legacy dist/Beacon directory if it exists from older one-folder builds
    legacy_dist_beacon = dist_dir / "Beacon"
    if legacy_dist_beacon.is_dir():
        print(f"\n[+] Cleaning legacy one-folder release at {legacy_dist_beacon}...")
        try:
            shutil.rmtree(legacy_dist_beacon)
        except Exception as e:
            print(f"[!] Warning cleaning {legacy_dist_beacon}: {e}")

    build_beacon = REPO_ROOT / "build" / "beacon"
    if build_beacon.exists():
        print(f"\n[+] Cleaning intermediate build cache at {build_beacon}...")
        try:
            shutil.rmtree(build_beacon)
        except Exception as e:
            print(f"[!] Warning cleaning {build_beacon}: {e}")

    # Step 3: Run PyInstaller
    spec_file = REPO_ROOT / "beacon.spec"
    if not spec_file.exists():
        print(f"[!] Spec file not found: {spec_file}", file=sys.stderr)
        sys.exit(1)

    run_cmd(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", str(spec_file)],
        cwd=REPO_ROOT,
        description="Packaging self-contained single-file Beacon executable",
    )

    # Step 4: Verify output
    if not target_exe.exists():
        print(f"[!] Build error: {target_exe} not found!", file=sys.stderr)
        sys.exit(1)

    size_bytes = target_exe.stat().st_size
    size_mb = size_bytes / (1024 * 1024)

    # Step 4b: Remove intermediate staging binary from build/ to prevent mistaken execution
    intermediate_exe = REPO_ROOT / "build" / "beacon" / exe_name
    if intermediate_exe.exists():
        try:
            intermediate_exe.unlink()
        except Exception:
            pass

    # Step 5: Create root-level convenience launchers
    root_bat = REPO_ROOT / "Beacon.bat"
    root_bat.write_text(
        '@echo off\r\n'
        'if exist "%~dp0dist\\Beacon.exe" (\r\n'
        '    start "" "%~dp0dist\\Beacon.exe" %*\r\n'
        '    exit /b 0\r\n'
        ')\r\n'
        'if exist "%~dp0dist\\Beacon\\Beacon.exe" (\r\n'
        '    start "" "%~dp0dist\\Beacon\\Beacon.exe" %*\r\n'
        '    exit /b 0\r\n'
        ')\r\n'
        'echo [ERROR] dist\\Beacon.exe not found! Please run scripts\\build_windows.bat first.\r\n'
        'pause\r\n'
        'exit /b 1\r\n',
        encoding="utf-8",
    )
    (REPO_ROOT / "run_beacon.bat").write_text(root_bat.read_text(encoding="utf-8"), encoding="utf-8")
    print("\n[+] Created root launchers: Beacon.bat, run_beacon.bat")

    # Step 6: Create release README and instructions
    readme_text = f"""========================================================================
BEACON CYBERSECURITY INVESTIGATION PLATFORM — WINDOWS RELEASE
========================================================================

HOW TO LAUNCH:
  Simply double-click '{exe_name}'.
  - The local investigation server starts on 127.0.0.1:8000.
  - Your default web browser will open the dashboard automatically.
  - To stop Beacon, press Ctrl+C in the console or close the window.

GENUINELY SELF-CONTAINED:
  - No Python, pip, Node.js, npm, or virtual environments required.
  - Pre-built React production frontend is bundled directly inside {exe_name}.
  - Native streaming PCAP / PCAPNG decoder operates out-of-the-box with zero
    external software installed.

STANDALONE CLI USAGE:
  Open a Command Prompt or PowerShell:
    .\\Beacon.exe --help
    .\\Beacon.exe analyze capture.pcap --mode blue
    .\\Beacon.exe memory changes --days 7
    .\\Beacon.exe live interfaces
    .\\Beacon.exe live start --interface eth0 --mode blue
    .\\Beacon.exe serve --host 127.0.0.1 --port 8000

OPTIONAL LIVE CAPTURE ACCELERATION:
  - For continuous live network packet sniffing from physical network adapters,
    Windows requires the Npcap packet capture driver:
      https://npcap.com/#download
  - If Wireshark / TShark is installed, Beacon will automatically detect and
    use it for hardware acceleration.
  - Offline file analysis of .pcap and .pcapng files requires NO extra drivers.

DATA STORAGE & LOGS:
  - User memory and analysis cache: %USERPROFILE%\\.beacon
  - Diagnostic logs: %USERPROFILE%\\.beacon\\logs\\beacon-launcher.log
========================================================================
"""
    (dist_dir / "README.txt").write_text(readme_text, encoding="utf-8")

    print("\n" + "=" * 70)
    print("  BUILD SUCCESSFUL!")
    print(f"  Single Executable: {target_exe}")
    print(f"  Binary Size:       {size_mb:.2f} MB ({size_bytes:,} bytes)")
    print(f"  Release Info:      {dist_dir / 'README.txt'}")
    print("=" * 70)


if __name__ == "__main__":
    main()
