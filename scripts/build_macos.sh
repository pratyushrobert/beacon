#!/usr/bin/env bash
# =========================================================================
# Beacon — macOS Single-File & App Bundle Release Packaging Script
# Compiles React frontend, executes PyInstaller, and produces dist/Beacon & dist/Beacon.app
# =========================================================================

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

echo "======================================================================"
echo "  BEACON — macOS RELEASE PACKAGING PIPELINE"
echo "======================================================================"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "[!] ERROR: build_macos.sh must be executed on a macOS system." >&2
    echo "    Current OS: $(uname -s)" >&2
    echo "    PyInstaller cannot cross-compile macOS Mach-O binaries or .app bundles from other platforms." >&2
    echo "    Please run this script on macOS (Apple Silicon or Intel)." >&2
    exit 1
fi

# 1. Locate suitable Python interpreter
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[!] ERROR: Python 3 was not found in PATH." >&2
    exit 1
fi

echo "[+] Using Python interpreter: $($PYTHON_BIN --version 2>&1)"

# 2. Check if PyInstaller is available; create temporary build venv if needed
if ! $PYTHON_BIN -m PyInstaller --version >/dev/null 2>&1; then
    echo "[!] PyInstaller not found in current environment."
    BUILD_VENV="/tmp/beacon_macos_build_venv"
    if [ ! -d "$BUILD_VENV" ]; then
        echo "[+] Creating temporary build virtual environment at $BUILD_VENV..."
        $PYTHON_BIN -m venv "$BUILD_VENV" || {
            echo "[!] Failed to create venv. Please ensure Python 3 includes venv." >&2
            exit 1
        }
    fi
    echo "[+] Installing PyInstaller and dependencies in build venv..."
    "$BUILD_VENV/bin/pip" install --upgrade pip
    "$BUILD_VENV/bin/pip" install pyinstaller -r "$REPO_DIR/requirements.txt"
    PYTHON_BIN="$BUILD_VENV/bin/python"
fi

# 3. Run build_macos.py
$PYTHON_BIN "$REPO_DIR/scripts/build_macos.py"

echo ""
echo "======================================================================"
echo "  macOS build complete: dist/Beacon and dist/Beacon.app"
echo "  CLI usage: ./dist/Beacon"
echo "  GUI usage: open dist/Beacon.app"
echo "======================================================================"
