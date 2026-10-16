#!/usr/bin/env bash
# =========================================================================
# Beacon — Linux Single-File Release Packaging Script
# Compiles React frontend, executes PyInstaller, and produces dist/Beacon
# =========================================================================

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

echo "======================================================================"
echo "  BEACON — LINUX SINGLE-FILE RELEASE PACKAGING PIPELINE"
echo "======================================================================"

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
    BUILD_VENV="/tmp/beacon_linux_build_venv"
    if [ ! -d "$BUILD_VENV" ]; then
        echo "[+] Creating temporary build virtual environment at $BUILD_VENV..."
        $PYTHON_BIN -m venv "$BUILD_VENV" || {
            echo "[!] Failed to create venv. Please install python3-venv (e.g. sudo apt install python3-venv)." >&2
            exit 1
        }
    fi
    echo "[+] Installing PyInstaller and dependencies in build venv..."
    "$BUILD_VENV/bin/pip" install --upgrade pip
    "$BUILD_VENV/bin/pip" install pyinstaller -r "$REPO_DIR/requirements.txt"
    PYTHON_BIN="$BUILD_VENV/bin/python"
fi

# 3. Run build_linux.py
$PYTHON_BIN "$REPO_DIR/scripts/build_linux.py"

echo ""
echo "======================================================================"
echo "  Linux build complete: dist/Beacon"
echo "  Run standalone with: ./dist/Beacon"
echo "======================================================================"
