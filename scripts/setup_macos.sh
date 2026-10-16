#!/usr/bin/env bash
# =========================================================================
# Beacon — macOS Environment Setup Automation Script
# Configures Python 3.10+ virtual environment, installs dependencies,
# verifies TShark discovery, and configures BPF permissions advice.
# =========================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_DIR"

echo "======================================================================"
echo "  BEACON — macOS ENVIRONMENT SETUP"
echo "  Target: $REPO_DIR"
echo "======================================================================"

# 1. Locate Python 3.10+
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PY_VER="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        MAJOR="$(echo "$PY_VER" | cut -d. -f1)"
        MINOR="$(echo "$PY_VER" | cut -d. -f2)"
        if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON_BIN="$candidate"
            echo "[✓] Found suitable Python: $PYTHON_BIN (v$PY_VER)"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[!] No Python 3.10+ found."
    echo "    Please install Python via Homebrew: brew install python@3.12"
    exit 1
fi

# 2. Check for TShark
echo "[+] Checking for TShark / Wireshark..."
TSHARK_FOUND=false
for p in "$(which tshark 2>/dev/null)" "/usr/local/bin/tshark" "/opt/homebrew/bin/tshark" "/Applications/Wireshark.app/Contents/MacOS/tshark"; do
    if [ -n "$p" ] && [ -x "$p" ]; then
        echo "[✓] Found TShark: $p"
        TSHARK_FOUND=true
        break
    fi
done

if [ "$TSHARK_FOUND" = false ]; then
    echo "[!] TShark was not detected in standard paths."
    echo "    To install via Homebrew: brew install --cask wireshark"
    echo "    Beacon can still perform basic setup, but analysis requires TShark."
fi

# 3. Create Virtual Environment
VENV_DIR="$REPO_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment at $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    echo "[✓] Existing virtual environment found at $VENV_DIR"
fi

# 4. Install Dependencies
echo "[+] Installing Beacon Python dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
"$VENV_DIR/bin/pip" install -r "$REPO_DIR/requirements.txt"
"$VENV_DIR/bin/pip" install -e "$REPO_DIR"

# 5. Check BPF permissions for packet capture
if [ -d "/Library/Application Support/Wireshark/ChmodBPF" ]; then
    echo "[✓] ChmodBPF LaunchDaemon detected for non-root live capture."
else
    echo "[i] Note: Live packet capture on macOS requires ChmodBPF permissions."
    echo "    Standard installation of Wireshark .dmg provides this automatically."
fi

# 6. Ensure launcher is executable
chmod +x "$REPO_DIR/bin/beacon" 2>/dev/null || true

echo ""
echo "======================================================================"
echo "  macOS SETUP COMPLETE!"
echo "  To launch Beacon: ./bin/beacon"
echo "======================================================================"
