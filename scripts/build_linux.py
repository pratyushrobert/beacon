#!/usr/bin/env python3
"""
Automated Linux single-file release build script for Beacon.
Builds the production React frontend, runs PyInstaller to produce a genuinely self-contained
single-file executable in dist/Beacon, sets executable permissions, and creates release documentation.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_cmd(cmd: list[str], cwd: Path, description: str) -> None:
    print(f"\n[+] {description}...")
    print(f"    Running: {' '.join(cmd)} in {cwd}")
    res = subprocess.run(cmd, cwd=cwd, text=True)
    if res.returncode != 0:
        print(f"[!] ERROR: {description} failed with return code {res.returncode}", file=sys.stderr)
        sys.exit(res.returncode)


def main() -> None:
    print("=" * 70)
    print("  BEACON -- LINUX SINGLE-FILE RELEASE BUILD PIPELINE")
    print("=" * 70)

    if sys.platform != "linux":
        print(f"[!] Warning: build_linux.py is intended for Linux hosts. Current platform: {sys.platform}")

    web_dir = REPO_ROOT / "web"
    web_dist = web_dir / "dist"

    # Step 1: Ensure frontend is built
    if not (web_dist / "index.html").exists():
        print("\n[+] Frontend production assets not found. Compiling React app...")
        npm_cmd = shutil.which("npm") or "npm"
        run_cmd([npm_cmd, "run", "build"], cwd=web_dir, description="Building React web client")
    else:
        print("\n[+] Existing web/dist/index.html found.")

    # Step 2: Clean previous dist and intermediate build directories
    dist_dir = REPO_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    target_exe = dist_dir / "Beacon"

    if target_exe.exists():
        print(f"\n[+] Cleaning previous Linux executable at {target_exe}...")
        try:
            target_exe.unlink()
        except Exception as e:
            print(f"[!] Warning cleaning {target_exe}: {e}")

    # Also clean legacy dist/beacon-linux directory if it exists
    legacy_dist = dist_dir / "beacon-linux"
    if legacy_dist.is_dir():
        print(f"\n[+] Cleaning legacy distribution directory at {legacy_dist}...")
        try:
            shutil.rmtree(legacy_dist)
        except Exception as e:
            print(f"[!] Warning cleaning {legacy_dist}: {e}")

    workpath = REPO_ROOT / "build" / "beacon-linux"
    if workpath.exists():
        print(f"\n[+] Cleaning intermediate build cache at {workpath}...")
        try:
            shutil.rmtree(workpath)
        except Exception as e:
            print(f"[!] Warning cleaning {workpath}: {e}")

    # Step 3: Run PyInstaller
    spec_file = REPO_ROOT / "beacon.spec"
    if not spec_file.exists():
        print(f"[!] Spec file not found: {spec_file}", file=sys.stderr)
        sys.exit(1)

    run_cmd(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--workpath",
            str(workpath),
            "--distpath",
            str(dist_dir),
            str(spec_file),
        ],
        cwd=REPO_ROOT,
        description="Packaging self-contained single-file Linux Beacon executable",
    )

    # Step 4: Verify output
    if not target_exe.exists():
        print(f"[!] Build error: {target_exe} not found!", file=sys.stderr)
        sys.exit(1)

    # Ensure executable bit
    try:
        current_stat = os.stat(target_exe)
        os.chmod(target_exe, current_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception as e:
        print(f"[!] Warning setting executable bit: {e}")

    size_bytes = target_exe.stat().st_size
    size_mb = size_bytes / (1024 * 1024)

    # Step 5: Update bin/beacon convenience symlink/script
    bin_dir = REPO_ROOT / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_beacon = bin_dir / "beacon"
    bin_beacon.write_text(
        '#!/usr/bin/env bash\n'
        'DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"\n'
        'if [ -f "$DIR/dist/Beacon" ]; then\n'
        '    exec "$DIR/dist/Beacon" "$@"\n'
        'fi\n'
        'echo "[ERROR] dist/Beacon not found! Please run scripts/build_linux.sh first." >&2\n'
        'exit 1\n',
        encoding="utf-8",
    )
    try:
        bin_beacon.chmod(0o755)
    except Exception:
        pass

    # Step 6: Create Linux Release Documentation
    readme_text = f"""========================================================================
BEACON CYBERSECURITY INVESTIGATION PLATFORM — LINUX RELEASE
========================================================================

HOW TO LAUNCH:
  Simply execute 'Beacon':
    ./Beacon

  - The local investigation server starts on 127.0.0.1:8000.
  - Your default web browser opens the dashboard automatically.
  - To stop Beacon, press Ctrl+C in the terminal.

GENUINELY SELF-CONTAINED:
  - No Python, pip, Node.js, npm, or virtual environments required.
  - Pre-built React production frontend is bundled directly inside the binary.
  - Native streaming PCAP / PCAPNG decoder operates out-of-the-box with zero
    external software installed.
  - Root privileges are NOT required for offline PCAP/PCAPNG file analysis.

STANDALONE CLI USAGE:
  ./Beacon --help
  ./Beacon analyze capture.pcap --mode blue
  ./Beacon memory changes --days 7
  ./Beacon live interfaces
  ./Beacon live start --interface eth0 --mode blue
  ./Beacon serve --host 127.0.0.1 --port 8000

OPTIONAL LIVE CAPTURE ACCELERATION:
  - For continuous live network packet sniffing from physical network interfaces,
    Linux requires packet capture capabilities:
      sudo apt install -y tshark
      sudo usermod -a -G wireshark $USER
  - Or grant cap_net_raw,cap_net_admin capabilities to dumpcap.
  - Offline file analysis requires NO extra privileges or software.

DATA STORAGE & LOGS:
  - User memory database and catalog: ~/.beacon/
  - Diagnostic logs: ~/.beacon/logs/beacon-launcher.log
========================================================================
"""
    (dist_dir / "README-Linux.txt").write_text(readme_text, encoding="utf-8")

    print("\n" + "=" * 70)
    print("  LINUX BUILD SUCCESSFUL!")
    print(f"  Single Executable: {target_exe}")
    print(f"  Binary Size:       {size_mb:.2f} MB ({size_bytes:,} bytes)")
    print(f"  Release Info:      {dist_dir / 'README-Linux.txt'}")
    print("=" * 70)


if __name__ == "__main__":
    main()
