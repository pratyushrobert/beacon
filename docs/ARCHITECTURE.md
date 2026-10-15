# Beacon Architecture

## System Overview

Beacon is a modular network traffic analysis platform built on a clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                      User Interfaces                         │
│  ┌──────────────┐              ┌──────────────┐            │
│  │   CLI App    │              │   GUI App    │            │
│  │  (Typer)     │              │  (Electron)  │            │
│  └──────┬───────┘              └──────┬───────┘            │
│         │                             │                     │
│         └─────────────┬───────────────┘                     │
└───────────────────────┼─────────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────────┐
│                       ▼                                      │
│              Analysis Engine API                             │
│    ┌──────────────────────────────────────┐                │
│    │  • Mode Management (Blue/Red/White)  │                │
│    │  • Result Aggregation                │                │
│    │  • Finding Correlation               │                │
│    └─────────────┬────────────────────────┘                │
└──────────────────┼──────────────────────────────────────────┘
                   │
┌──────────────────┼──────────────────────────────────────────┐
│                  ▼                                           │
│         Core Processing Modules                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Packet     │  │  Detection   │  │   Timeline   │     │
│  │   Parser     │  │   Engine     │  │   Builder    │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            ▼                                 │
│                   ┌─────────────────┐                       │
│                   │  Data Storage   │                       │
│                   │   (SQLite)      │                       │
│                   └────────┬────────┘                       │
└────────────────────────────┼──────────────────────────────┘
                             │
┌────────────────────────────┼──────────────────────────────┐
│                            ▼                               │
│                   TShark Interface                         │
│              ┌─────────────────────────┐                  │
│              │  • Subprocess Runner    │                  │
│              │  • JSON/EK Parsing      │                  │
│              │  • Stream Processing    │                  │
│              └───────────┬─────────────┘                  │
└──────────────────────────┼────────────────────────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   TShark     │
                    │   Binary     │
                    └──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  PCAP/PCAPNG │
                    │    Files     │
                    └──────────────┘
```

## Data Flow

### 1. Ingestion Phase
1. User provides PCAP/PCAPNG file
2. TShark Interface validates file and extracts metadata
3. Packets are streamed through TShark in JSON/EK format
4. Packet Parser normalizes data into `ParsedPacket` objects
5. Data is cached in SQLite for fast re-analysis

### 2. Analysis Phase
1. Analysis Engine loads mode-specific configuration
2. Packets are processed in chunks to manage memory
3. Host and conversation statistics are aggregated
4. Detection Engine runs mode-specific rules
5. Findings are correlated across packets
6. Timeline events are constructed

### 3. Presentation Phase
1. Results are formatted for CLI or GUI
2. Findings are ranked by severity and confidence
3. Reports are generated (HTML/PDF/JSON)
4. IOCs are extracted and indexed

## Module Responsibilities

### `beacon.core`
- **tshark_interface.py**: TShark subprocess management, output parsing
- **packet_parser.py**: Normalization of packet data into Python objects
- **engine.py**: Main analysis orchestration and caching
- **modes.py**: Mode definitions and configurations

### `beacon.detection`
- **rules.py**: Rule schema and loading
- **engine.py**: Detection logic and correlation
- **signatures/**: YAML rule definitions

### `beacon.cli`
- **main.py**: Typer CLI application
- **commands/**: Subcommands (analyze, packet, ioc, report)

### `beacon.gui`
- **app/**: Electron/React application
- **backend/**: FastAPI server (optional local web UI)

### `beacon.exports`
- **html.py**: HTML report generation
- **pdf.py**: PDF export via WeasyPrint
- **json.py**: Structured JSON export
- **csv.py**: CSV export for spreadsheets

### `beacon.utils`
- **ioc_extractor.py**: IP, domain, hash extraction
- **timeline.py**: Event grouping and chronology
- **validators.py**: Input validation

## Development Phases

### ✅ Stage 1: Core Foundation (Current)
- [x] Project structure
- [x] TShark integration
- [x] Basic packet parsing
- [x] SQLite caching
- [x] CLI skeleton

### 🚧 Stage 2: White Mode Data
- [ ] Complete host/conversation mapping
- [ ] Protocol statistics
- [ ] DNS/HTTP/TLS extraction
- [ ] Basic timeline

### 📋 Stage 3: Threat Intel
- [ ] Automated IOC extraction
- [ ] IP/Domain/Hash indexing
- [ ] Pivot tables

### 📋 Stage 4: Blue Mode
- [ ] Detection rule engine
- [ ] Port/host scanning detection
- [ ] Beaconing analysis
- [ ] Traffic anomaly detection

### 📋 Stage 5: Red Mode
- [ ] Credential extraction
- [ ] Metadata leak detection
- [ ] Sensitive data redaction

### 📋 Stage 6: Deep Analysis
- [ ] Single packet deep dive
- [ ] Context correlation
- [ ] Related packet linking

### 📋 Stage 7: Timeline
- [ ] Event grouping
- [ ] Logical flow construction
- [ ] Visual timeline

### 📋 Stage 8: CLI Polish
- [ ] All subcommands
- [ ] Output formats (JSON/CSV)
- [ ] Interactive filters

### 📋 Stage 9: GUI
- [ ] Dashboard
- [ ] Network graph
- [ ] Packet explorer
- [ ] Theme switching

### 📋 Stage 10: Reporting
- [ ] HTML templates
- [ ] PDF generation
- [ ] Executive summaries

### 📋 Stage 11: Hardening
- [ ] Comprehensive testing
- [ ] Error handling
- [ ] Performance optimization
- [ ] Malformed packet handling

### 📋 Stage 12: Future Features
- [ ] Threat intel feed integration
- [ ] AI assistant (evidence-based)
- [ ] Plugin system

## Design Principles

1. **Separation of Concerns**: CLI and GUI consume the same core engine
2. **Evidence-Based**: Never claim malicious behavior without packet proof
3. **Memory Efficiency**: Stream processing, chunked parsing, SQLite caching
4. **Progressive Disclosure**: Quick overview → detailed findings → deep packet analysis
5. **Security First**: Treat PCAPs as hostile, never execute payloads
6. **Professional UX**: Clear, actionable output with proper severity/confidence ratings
