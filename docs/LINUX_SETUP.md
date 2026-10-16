# Beacon — Linux Installation & Setup Guide
**Target System:** antiX Linux / Debian-based distributions  
**Python Version:** Python 3.13+  
**Target Directory:** `~/Projects/beacon`  
**Virtual Environment:** `~/Projects/beacon/.venv`

---

## 1. Overview & Security Architecture

Beacon is designed to run securely and efficiently on lightweight Linux distributions (such as antiX Linux and Debian).

### Crucial Principle: Non-Root Operation
> [!IMPORTANT]
> **Never run Beacon, Python, or `pip` as `root` (e.g. `sudo python -m beacon` or `sudo pip install`).**
> 
> - **Offline PCAP Analysis:** Analyzing existing PCAP/PCAPNG files requires **no special privileges**. Any regular user can run full blue/red/white analyses and historical memory comparisons.
> - **Live Network Capture:** Continuous packet capture uses TShark/dumpcap. Packet capture privileges are safely granted via Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) using the Debian `wireshark` group, keeping the Beacon application process unprivileged.

---

## 2. System Prerequisites (Debian & antiX Linux)

Open a terminal and install the required system packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tshark wireshark-common libcap2-bin
```

### Configure Non-Root Capture Privileges
During installation, or by running the command below, Debian will ask:  
*"Should non-superusers be able to capture packets?"*

1. Run the reconfigure utility:
   ```bash
   sudo dpkg-reconfigure wireshark-common
   ```
   Select **`<Yes>`** and press Enter.

2. Add your user account to the `wireshark` group:
   ```bash
   sudo usermod -aG wireshark $USER
   ```

3. Activate the new group in your current shell (or log out and back in):
   ```bash
   newgrp wireshark
   ```

4. Verify capture permission without root:
   ```bash
   dumpcap -D
   ```
   You should see your network interfaces (e.g. `eth0`, `wlan0`) listed without permission errors.

---

## 3. Virtual Environment & Dependency Installation

Navigate to your Beacon project directory:

```bash
cd ~/Projects/beacon
```

### A. Create and Activate the Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### B. Upgrade Core Build Tools
Ensure modern build tools are present in `.venv`:
```bash
pip install --upgrade pip setuptools wheel
```

### C. Install Beacon in Editable Mode
Install Beacon along with all dependencies defined in `pyproject.toml` and `requirements.txt`:

```bash
pip install -e .
```

*(Optional) If you are developing or running test suites, install development dependencies:*
```bash
pip install -e ".[dev]"
```

---

## 4. Why Previous Installation Errors Occurred & How They Were Resolved

### 1. `Preparing metadata (pyproject.toml) did not run successfully`
- **Root Cause:** Older requirement locks used rigid `==` pins (e.g. `numpy==1.26.4`, `pandas==2.2.2`). These versions do not publish pre-built binary wheels for Python 3.13. Pip was forced to attempt building C extensions from source without complete C compiler tools, crashing during metadata generation.
- **Fix:** Dependency declarations in `pyproject.toml` and `requirements.txt` now specify compatible `>=` ranges (`numpy>=1.26.0`, `pandas>=2.2.0`). Pip automatically selects modern wheels with native Python 3.13 wheels (such as NumPy 2.x and Pandas 2.2.3+).

### 2. `ModuleNotFoundError: No module named 'rich'`
- **Root Cause:** Python was run directly against `beacon/` without installing the project into the virtual environment.
- **Fix:** Running `pip install -e .` links the `beacon` package into `.venv/lib/python3.13/site-packages`, resolving all CLI and core imports seamlessly.

### 3. `TypeError: TyperOption.__init__() got an unexpected keyword argument 'flag_value'`
- **Root Cause:** A brittle monkey-patch in `beacon/cli/main.py` passed `flag_value` into `TyperOption.__init__`. Under Typer 0.27+ and Click 8.5+, `TyperOption.__init__` no length accepts `flag_value`.
- **Fix:** The startup patch now safely intercepts `click.Option.__init__` and normalizes default flags using `click.core.UNSET`. All CLI commands, subcommands, and flags now parse cleanly without crashes.

---

## 5. Verifying Your Installation

### Run the Test Suite
Verify that all 101 unit and regression tests pass in your virtual environment:

```bash
pytest
```

### Verify the Beacon CLI
```bash
# Verify version
beacon version-info

# Check help menu
beacon --help
```

---

## 6. Usage Guide

### Offline PCAP/PCAPNG Analysis
Analyze any capture file with defensive (blue), adversary-simulation (red), or baseline (white) modes:

```bash
# Blue team defensive analysis
beacon analyze capture.pcap --mode blue

# White mode with packet limit and JSON export
beacon analyze capture.pcap --mode white --limit 5000 --output report.json

# Host inventory and communication matrix
beacon hosts capture.pcap
beacon conversations capture.pcap
beacon timeline capture.pcap
```

### Historical Beacon Memory
Compare captures against past historical baselines:

```bash
# Inspect changes across capture sessions
beacon memory changes --days 7

# View executive briefing of recurring anomalies
beacon memory briefing
```

### Live Network Capture & Retention
Run continuous live capture without unbounded memory growth:

```bash
# List available network interfaces
beacon live interfaces

# Start live monitoring on an interface (e.g., eth0)
beacon live start --interface eth0 --mode blue

# Check live capture telemetry and buffer status
beacon live status

# Review preserved security incidents
beacon live incidents
```

### Web GUI & Remote Dashboard
Launch the FastAPI web server to inspect network evidence visually:

```bash
# Start Web GUI locally (accessible at http://localhost:8000)
beacon serve --host 127.0.0.1 --port 8000

# Start Web GUI for remote local network access
beacon serve --host 0.0.0.0 --port 8000
```

---

## 7. Linux Runtime Hardening Features

- **Process Tree Cleanup:** On Linux, `LiveCaptureService` starts packet capture processes with `start_new_session=True` and stops them using `os.killpg(pgid, signal.SIGTERM)`. This ensures child `dumpcap` instances are never orphaned if Beacon terminates.
- **Zero-Dependency RSS Memory Tracking:** Linux resident set size is sampled directly from `/proc/self/statm` (pages × `SC_PAGE_SIZE`), avoiding heavyweight external packages while ensuring accurate memory telemetry.
- **Capinfos Fallback:** If `capinfos` is absent on minimal Linux installations, Beacon automatically falls through to TShark IO statistics (`-q -z io,stat,0`) and line counting without throwing `FileNotFoundError`.
- **Evidence Integrity:** Synthesized packet representations in the live ring buffer carry an explicit `is_reconstructed: bool` flag to ensure synthesized data is never confused with verbatim wire packets.
