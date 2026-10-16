# Beacon Architecture

## System Overview

Beacon is a modular cybersecurity network traffic investigation platform built on a strict separation of concerns:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User Interfaces                                 │
│  ┌───────────────────────┐          ┌───────────────────────────────┐  │
│  │       CLI App         │          │         Web Dashboard         │  │
│  │   (Typer + Rich)      │          │     (React 18 SPA + Vite)     │  │
│  └───────────┬───────────┘          └───────────────┬───────────────┘  │
│              │                                      │ (HTTP / WS)      │
└──────────────┼──────────────────────────────────────┼──────────────────┘
               │                                      │
┌──────────────┼──────────────────────────────────────┼──────────────────┐
│              ▼                                      ▼                  │
│                        FastAPI Application Server                      │
│        • Single-origin SPA serving (`web/dist/`)                       │
│        • REST API (`/api/analyses`, `/api/live`, `/api/prevention`)    │
│        • Real-Time Telemetry WebSocket (`/ws/live`)                    │
│        • Optional Access PIN Authentication (`X-Beacon-PIN`)           │
└─────────────────────────────────┬──────────────────────────────────────┘
                                  │
┌─────────────────────────────────┼──────────────────────────────────────┐
│                                 ▼                                      │
│                     Beacon Core Engine Pipeline                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ AnalysisEngine: Chunked Packet Ingestion & Session Indexing      │  │
│  │ PacketParser: 5-Tuple Hashing, Protocol Demuxing & Normalization │  │
│  └──────────────┬──────────────────┬──────────────────┬─────────────┘  │
│                 │                  │                  │                │
│                 ▼                  ▼                  ▼                │
│       ┌──────────────────┐ ┌───────────────┐ ┌────────────────┐        │
│       │ Detection Engine │ │Topology Engine│ │ Beacon Memory  │        │
│       │ (Blue/Red/White) │ │(Subnets/Roles)│ │ (Baseline/Drift│        │
│       └─────────┬────────┘ └───────┬───────┘ └────────┬───────┘        │
│                 │                  │                  │                │
│                 └──────────────────┼──────────────────┘                │
│                                    ▼                                   │
│                       ┌─────────────────────────┐                      │
│                       │ Threat Prevention Engine│                      │
│                       │ (Safety/Policy/Adapters)│                      │
│                       └────────────┬────────────┘                      │
└────────────────────────────────────┼───────────────────────────────────┘
                                     │
┌────────────────────────────────────┼───────────────────────────────────┐
│                                    ▼                                   │
│                     Ingestion & Hardware Interfaces                    │
│  ┌───────────────────────────────┐   ┌──────────────────────────────┐  │
│  │  pcap_native.py (Zero-dep)    │   │  tshark_interface.py (TShark)│  │
│  │  Pure-Python PCAP/PCAPNG Demux│   │  JSON/EK Subprocess Runner   │  │
│  └──────────────┬────────────────┘   └──────────────┬───────────────┘  │
│                 │                                   │                  │
│                 └─────────────────┬─────────────────┘                  │
│                                   ▼                                    │
│                 ┌───────────────────────────────────┐                  │
│                 │ Offline PCAP/PCAPNG or Live Capture│                 │
│                 └───────────────────────────────────┘                  │
└────────────────────────────────────────────────────────────────────────┘
```

## Data Flow & Processing Lifecycle

### 1. Ingestion Phase
1. **Source Selection**: User provides an offline capture file (`.pcap`, `.pcapng`) or selects a live network adapter.
2. **Decoder Selection**:
   - If TShark is installed, Beacon accelerates dissection via `tshark_interface.py`.
   - If TShark is absent, Beacon transparently activates `pcap_native.py`, a pure-Python streaming demuxer supporting classic PCAP and Next-Gen PCAPNG (SHB, IDB, EPB, SPB) without external binaries.
3. **Stream Normalization**: Raw frames are normalized into `ParsedPacket` structures with bidirectional socket hashes (`ip_src:port` $\leftrightarrow$ `ip_dst:port`) and application layer fields.

### 2. Analysis & Correlation Phase
1. **Session Indexing**: Session statistics (bytes, packets, durations, protocols) are committed to SQLite cache tables.
2. **Topology Mapping**: The `TopologyEngine` infers private CIDR boundaries and assigns device roles:
   - `[GW]` Gateway
   - `[SRV]` Server
   - `[CLI]` Client
   - `[EXT]` External WAN Destination
3. **Heuristic Detection**: The `DetectionEngine` evaluates deterministic security rules according to the active mode (`Blue`, `Red`, `White`).
4. **Historical Memory**: The `MemoryDetector` compares observed activity against local baseline profiles (`~/.beacon/memory.db`) to identify first-seen destinations and volume surges.

### 3. Threat Prevention Phase (Live Monitoring Only)
1. **Safety Gating**: Security findings from live traffic are evaluated by `PreventionService`.
2. **Prohibited Targets**: Loopback, broadcast, multicast, link-local, unspecified, default gateways, and allowlisted subnets are rejected.
3. **Collateral Warnings**: Multi-tenant CDN and hyperscaler destinations (Cloudflare, AWS, Google, Fastly, Akamai, Quad9) attach cautionary alerts.
4. **Policy Enforcement**:
   - `Monitor Only` (default): Detections logged; firewall untouched.
   - `Ask Before Blocking`: Rules queued as `PENDING_APPROVAL` for human sign-off.
   - `Automatic`: Qualified high-confidence findings apply temporary drop rules targeting the suspicious destination IP.
5. **State Verification & Rollback**: Rules are verified via adapter queries; verification failures trigger immediate rollback.
6. **Time-to-Live**: Active rules expire automatically after a configurable duration (default: 15 minutes).

### 4. Presentation & Delivery Phase
1. **Web Dashboard**: Single-origin React application renders real-time topology graphs, findings, timelines, and prevention controls.
2. **CLI**: Rich terminal views format host tables, conversation statistics, timelines, and audit logs.
3. **Reports**: Self-contained HTML executive reports, structured JSON exports, and CSV summaries.

## Core Module Structure

| Module | Core Responsibility |
|---|---|
| [`beacon.core.engine`](file:///D:/Project/Becon-claude/beacon/core/engine.py) | Main analysis orchestration, chunked packet processing, SQLite caching |
| [`beacon.core.packet_parser`](file:///D:/Project/Becon-claude/beacon/core/packet_parser.py) | Protocol dissection and packet normalization |
| [`beacon.core.pcap_native`](file:///D:/Project/Becon-claude/beacon/core/pcap_native.py) | Pure-Python zero-dependency PCAP/PCAPNG streaming decoder |
| [`beacon.core.tshark_interface`](file:///D:/Project/Becon-claude/beacon/core/tshark_interface.py) | Subprocess interface for TShark-accelerated decoding |
| [`beacon.analysis`](file:///D:/Project/Becon-claude/beacon/analysis/) | Analytical modules: `hosts`, `conversations`, `timeline`, `ioc_extractor`, `topology` |
| [`beacon.detection.engine`](file:///D:/Project/Becon-claude/beacon/detection/engine.py) | Deterministic rule evaluators for Blue, Red, and White modes |
| [`beacon.live`](file:///D:/Project/Becon-claude/beacon/live/) | Continuous ring buffer, smart evidence retention, and live capture service |
| [`beacon.memory`](file:///D:/Project/Becon-claude/beacon/memory/) | SQLite baseline storage and explainable behavioral drift detection |
| [`beacon.prevention`](file:///D:/Project/Becon-claude/beacon/prevention/) | Modular threat blocking, safety validators, DryRun & Nftables adapters |
| [`beacon.api.server`](file:///D:/Project/Becon-claude/beacon/api/server.py) | FastAPI server, WebSocket endpoints, static SPA mounting, PIN verification |
| [`beacon.cli.main`](file:///D:/Project/Becon-claude/beacon/cli/main.py) | Typer + Rich command-line application |
| [`beacon.exports.reports`](file:///D:/Project/Becon-claude/beacon/exports/reports.py) | HTML, JSON, and CSV report generators |

## Design Principles

1. **Separation of Concerns**: CLI and Web UI consume identical core engines and models.
2. **Evidence-Based Auditing**: Every security finding cites specific packet frame numbers and observed fields.
3. **Bounded Memory Consumption**: Streaming ingestion, chunked processing, and FIFO ring buffers guarantee predictable RAM usage.
4. **Local-First & Private**: Analysis runs entirely locally without transmitting packet metadata to third parties.
5. **Human-in-the-Loop Prevention**: Prevention defaults to passive monitoring; automated actions require explicit operator opt-in.
