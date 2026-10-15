# Contributing to Beacon

Beacon is in active development. Contributions are welcome!

## Development Setup

```bash
# Clone repository
git clone <repository-url>
cd beacon

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install TShark (required)
# See README.md for platform-specific instructions
```

## Code Style

Beacon follows standard Python conventions:

```bash
# Format code
black beacon/ tests/

# Lint code
ruff check beacon/ tests/

# Type checking
mypy beacon/
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=beacon --cov-report=html

# Run specific test
pytest tests/test_core.py::test_analysis_modes -v

# Run with verbose output
pytest -v -s
```

## Development Workflow

1. **Choose a Stage**: See `docs/ARCHITECTURE.md` for the development roadmap
2. **Create Feature Branch**: `git checkout -b feature/stage-X-feature-name`
3. **Write Tests First**: Add tests in `tests/`
4. **Implement Feature**: Follow existing patterns
5. **Run Tests**: Ensure all tests pass
6. **Format & Lint**: Run black and ruff
7. **Submit PR**: With clear description

## Project Structure

```
beacon/
├── core/          # Core analysis engine
├── detection/     # Detection rules and engine
├── cli/           # Command-line interface
├── gui/           # Graphical interface
├── exports/       # Report generation
├── utils/         # Utility functions
└── rules/         # Detection rule definitions
```

## Key Design Principles

1. **Evidence-Based**: Never claim malicious behavior without packet proof
2. **Memory Efficient**: Stream processing, no full-file loads
3. **Separation of Concerns**: CLI/GUI use same core engine
4. **Security First**: Treat PCAPs as hostile input
5. **Professional Output**: Clear, actionable findings

## Adding Detection Rules

Detection rules (Stage 4+) should follow this pattern:

```yaml
# beacon/rules/blue/port_scan.yaml
id: blue_port_scan_001
name: Port Scanning Detection
description: Detects systematic port scanning behavior
severity: high
confidence: medium
category: port_scanning
conditions:
  - type: connection_pattern
    threshold: 20
    timeframe: 60s
    flags: SYN
evidence:
  - source_ip
  - destination_ports
  - timestamps
explanation: |
  Detected {count} SYN packets to different ports on {target}
  within {timeframe} seconds, indicating possible port scan.
recommendation: |
  Investigate source IP {source_ip} for malicious intent.
  Block if confirmed as unauthorized scanning.
references:
  - https://attack.mitre.org/techniques/T1046/
```

## Testing Guidelines

- Write tests for all new features
- Use fixtures for common test data
- Mock TShark calls in unit tests (don't require actual PCAP files)
- Integration tests can use small example PCAPs

## Documentation

- Update README.md for user-facing changes
- Update ARCHITECTURE.md for structural changes
- Add docstrings to all public functions
- Include examples in docstrings

## Questions?

Open an issue or start a discussion!
