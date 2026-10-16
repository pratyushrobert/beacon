#!/usr/bin/env python3
"""
Automated macOS release build script for Beacon.
Builds the production React frontend, runs PyInstaller to produce a genuinely self-contained
single-file executable in dist/Beacon and an Application Bundle in dist/Beacon.app,
applies ad-hoc code signing, and creates release documentation.
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
    print("  BEACON -- macOS RELEASE PACKAGING PIPELINE")
    print("=" * 70)

    if sys.platform != "darwin":
        print(f"[!] ERROR: build_macos.py must be run on a macOS host.", file=sys.stderr)
        print(f"    Current platform: {sys.platform}", file=sys.stderr)
        print(f"    Cross-compiling native Mach-O binaries and Apple Application Bundles", file=sys.stderr)
        print(f"    from Windows or Linux is not supported by PyInstaller.", file=sys.stderr)
        print(f"    Please execute this script directly on macOS (Apple Silicon or Intel x86_64).", file=sys.stderr)
        sys.exit(1)

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
    target_app = dist_dir / "Beacon.app"

    if target_exe.exists():
        print(f"\n[+] Cleaning previous macOS executable at {target_exe}...")
        try:
            target_exe.unlink()
        except Exception as e:
            print(f"[!] Warning cleaning {target_exe}: {e}")

    if target_app.exists():
        print(f"\n[+] Cleaning previous macOS app bundle at {target_app}...")
        try:
            shutil.rmtree(target_app)
        except Exception as e:
            print(f"[!] Warning cleaning {target_app}: {e}")

    workpath = REPO_ROOT / "build" / "beacon-macos"
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
        description="Packaging self-contained macOS Beacon release",
    )

    # Step 4: Verify output
    if not target_exe.exists():
        print(f"[!] Build error: {target_exe} not found!", file=sys.stderr)
        sys.exit(1)

    # Ensure executable permissions
    try:
        current_stat = os.stat(target_exe)
        os.chmod(target_exe, current_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception as e:
        print(f"[!] Warning setting executable bit: {e}")

    # Step 5: Ad-hoc code signing for local execution
    if shutil.which("codesign"):
        print("\n[+] Applying ad-hoc code signature...")
        try:
            subprocess.run(["codesign", "--force", "-s", "-", str(target_exe)], check=False)
            if target_app.exists():
                subprocess.run(["codesign", "--force", "--deep", "-s", "-", str(target_app)], check=False)
            print("[✓] Ad-hoc signature applied.")
        except Exception as e:
            print(f"[!] Warning during ad-hoc codesign: {e}")

    size_bytes = target_exe.stat().st_size
    size_mb = size_bytes / (1024 * 1024)

    # Step 6: Create macOS Release Documentation
    readme_text = f"""========================================================================
BEACON CYBERSECURITY INVESTIGATION PLATFORM — macOS RELEASE
========================================================================

TWO WAYS TO LAUNCH:
  1. Finder (Desktop GUI):
     Double-click 'Beacon.app' in this directory.
  2. Terminal (CLI & Headless):
     ./Beacon

  - The local investigation server starts on 127.0.0.1:8000.
  - Your default web browser opens the dashboard automatically.
  - To stop Beacon, press Ctrl+C in the Terminal or close the process.

GENUINELY SELF-CONTAINED:
  - No Python, pip, Node.js, npm, or virtual environments required.
  - Pre-built React production frontend is bundled directly inside the binary.
  - Native streaming PCAP / PCAPNG decoder operates out-of-the-box with zero
    external software installed.

GATEKEEPER & CODE SIGNING:
  macOS Gatekeeper blocks downloaded, un-notarized applications by default.
  If you see "Beacon cannot be opened because Apple cannot check it for malicious software":
    1. In Finder, Right-Click (or Control-Click) 'Beacon.app' and choose 'Open'.
    2. Click 'Open' in the dialog.
    Or in Terminal:
      xattr -d com.apple.quarantine Beacon.app
      xattr -d com.apple.quarantine Beacon

STANDALONE CLI USAGE:
  ./Beacon --help
  ./Beacon analyze capture.pcap --mode blue
  ./Beacon memory changes --days 7
  ./Beacon live interfaces
  ./Beacon live start --interface en0 --mode blue
  ./Beacon serve --host 127.0.0.1 --port 8000

OPTIONAL LIVE CAPTURE ACCELERATION:
  - Offline file analysis of .pcap and .pcapng files works with zero privileges.
  - Continuous live packet sniffing from macOS network adapters (en0, etc.)
    requires read access to Berkeley Packet Filter devices (/dev/bpf*):
      Install Wireshark via Homebrew (brew install --cask wireshark)
      which installs the ChmodBPF LaunchDaemon.

DATA STORAGE & LOGS:
  - User memory and catalog: ~/.beacon/
  - Diagnostic logs: ~/.beacon/logs/beacon-launcher.log
========================================================================
"""
    (dist_dir / "README-macOS.txt").write_text(readme_text, encoding="utf-8")

    print("\n" + "=" * 70)
    print("  macOS BUILD SUCCESSFUL!")
    print(f"  CLI Executable: {target_exe} ({size_mb:.2f} MB)")
    if target_app.exists():
        print(f"  App Bundle:     {target_app}")
    print(f"  Release Info:   {dist_dir / 'README-macOS.txt'}")
    print("=" * 70)


if __name__ == "__main__":
    main()
