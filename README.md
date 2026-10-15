# Beacon — Cybersecurity Network Traffic Analysis Platform

Beacon is a professional, modular PCAP/PCAPNG network traffic analysis platform built on top of **TShark**. It transforms raw network traffic captures into actionable security intelligence.

Beacon is designed to help an analyst answer:
> **"What happened in this network capture, what is unusual or exposed, what evidence supports that conclusion, and what should I investigate next?"**

Beacon complements Wireshark rather than replacing it. TShark serves as the underlying decoding engine, while Beacon adds structured investigation, useful detections, evidence correlation, explanations, navigation, and reporting.

---

## Philosophy & Core Principles

- **Evidence-Driven Analysis**: Every finding must be backed by real packet data and traceable to the exact relevant packets or conversations. We never label activity as "malicious" merely because it is unusual, preferring qualified descriptors such as *Possible Port Scan* or *Unusual DNS Behavior*.
- **Fact vs. Inference Separation**: Clearly distinguish what was directly observed in the protocol layers from what is inferred from communication patterns.
- **Contextual Reduction**: Distill millions of packets into meaningful hosts, conversations, anomalies, and indicators of interest (IOCs) without losing access to raw packet details.
- **Safety by Default**: Treat all uploaded captures and protocol values as untrusted input. Sensitive credentials and tokens are redacted by default.

---

## Operating Modes

Beacon operates across three specialized analysis modes without duplicating the underlying engine:

### 🔵 Blue Mode — Defensive Investigation
- **Focus**: Anomaly detection, reconnaissance, attack indicators, and lateral movement.
- **Detections**: Port and host scans, SYN/UDP/ICMP scanning indicators, connection failures, periodic C2 beaconing patterns, DNS anomalies/tunneling, data exfiltration volume thresholds, and cleartext protocol usage.

### 🔴 Red Mode — Information Exposure
- **Focus**: Observable cleartext credentials, tokens, and infrastructure leakage.
- **Detections**: HTTP basic authentication and passwords in URLs, session cookies, API tokens, internal IP disclosure, software version disclosure, server banners, and TLS SNI exposure (redacted by default).

### ⚪ White Mode — Neutral Analysis
- **Focus**: Exploration of traffic volume, hosts, conversations, protocols, and timelines.
- **Detections & Metrics**: Protocol distribution, top talkers, connection durations, packet rates, and network inventory.

---

## Architecture Overview

```
PCAP / PCAPNG Upload / CLI Input
            │
            ▼
    TShark Interface (tshark -T ek / json)
            │
            ▼
   Packet Parser & Normalizer (ParsedPacket)
            │
            ▼
   Analysis Engine (SQLite Metadata Cache & Indexing)
            │
            ├──────────────────────────┐
            ▼                          ▼
     Detection Engine            Analysis Modules
(Blue / Red / White Rules) (Hosts, Convs, Timeline, IOCs)
            │                          │
            └──────────┬───────────────┘
                       │
       ┌───────────────┴───────────────┐
       ▼                               ▼
  REST API (FastAPI)              CLI (Typer + Rich)
       │
       ▼
React Web GUI (Tailwind + Recharts)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full design specifications.

---

## Prerequisites

1. **Python 3.10+**
2. **Wireshark / TShark 4.0+**
   - **Windows**: Download from [Wireshark Official Site](https://www.wireshark.org/download.html) and ensure `tshark.exe` is in your system PATH (e.g., `C:\Program Files\Wireshark`).
   - **Linux**: `sudo apt-get install tshark` (or `sudo yum install wireshark`)
   - **macOS**: `brew install wireshark`
3. **Node.js 18+ and npm** (for Web GUI)

---

## Installation & Setup

### 1. Python Environment

```bash
# Clone or navigate to the repository
cd D:\Project\Becon-claude

# Install core and API requirements
pip install -r requirements.txt -r requirements-api.txt
```

Verify your setup:
```bash
python verify_setup.py
```

### 2. Web Frontend Setup

```bash
cd web
npm install
npm run build
cd ..
```

---

## Quick Start

### Running the Web Interface

**Terminal 1 — API Server:**
```bash
python -m uvicorn beacon.api.server:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend Dev Server:**
```bash
cd web
npm run dev
```

Open your browser at **`http://localhost:3000`** (or access the API docs at `http://localhost:8000/docs`).
For full GUI instructions and troubleshooting, see [docs/GUI_SETUP.md](docs/GUI_SETUP.md).

---

### CLI Usage

Beacon provides rich CLI commands for terminal workflows:

```bash
# Full capture analysis
python -m beacon analyze capture.pcap --mode blue

# Inspect security findings with verbose evidence
python -m beacon findings capture.pcap --mode blue --verbose

# Filter findings by severity
python -m beacon findings capture.pcap --mode blue --severity high

# Host analysis (top 20 talkers)
python -m beacon hosts capture.pcap --top 20

# Network conversations
python -m beacon conversations capture.pcap --top 20

# Protocol distribution
python -m beacon protocols capture.pcap

# Event timeline
python -m beacon timeline capture.pcap

# Extract network Indicators of Compromise (IOCs)
python -m beacon ioc capture.pcap

# Deep packet inspection (TShark decoded layers)
python -m beacon packet capture.pcap 42

# Capture metadata
python -m beacon info capture.pcap

# Version and system info
python -m beacon version-info
```

---

## Running Tests

Run the test suite with pytest:
```bash
python -m pytest -v
```

Run parser self-tests:
```bash
python verify_parser.py
```

---

## Contributing & License

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for coding conventions, test requirements, and submission processes.
Beacon is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
