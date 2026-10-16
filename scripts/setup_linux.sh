#!/usr/bin/env bash
# =========================================================================
# Beacon — Automated Linux / antiX Setup Script
# Sets up system packages, non-root TShark privileges, virtual environment,
# production frontend build, and desktop launcher shortcut.
# =========================================================================

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

echo "======================================================================"
echo "  BEACON CYBERSECURITY INVESTIGATION PLATFORM — LINUX SETUP"
echo "  Target: antiX Linux / Debian"
echo "  Directory: $REPO_DIR"
echo "======================================================================"

# 1. System prerequisites check
echo ""
echo "[+] Step 1: Checking system prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
    MISSING_PKGS=()
    for pkg in python3 python3-venv python3-pip tshark wireshark-common libcap2-bin; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            MISSING_PKGS+=("$pkg")
        fi
    done

    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        echo "[!] Missing system packages: ${MISSING_PKGS[*]}"
        echo "    Installing packages with apt (sudo required)..."
        sudo apt update
        sudo apt install -y "${MISSING_PKGS[@]}"
    else
        echo "[✓] All required system packages are installed."
    fi
else
    echo "[!] Non-Debian system detected. Please ensure Python 3.10+, pip, and TShark are installed."
fi

# 2. Non-root Wireshark/dumpcap capture permissions
echo ""
echo "[+] Step 2: Checking non-root packet capture permissions..."
if getent group wireshark >/dev/null 2>&1; then
    if ! id -nG "$USER" | grep -qw "wireshark"; then
        echo "[!] Adding user $USER to the 'wireshark' group for unprivileged packet capture..."
        sudo usermod -aG wireshark "$USER"
        echo "[!] User added to 'wireshark' group."
        echo "    Note: If capturing live traffic in the same login session, run 'newgrp wireshark' or log out and back in."
    else
        echo "[✓] User $USER is already a member of the 'wireshark' group."
    fi
fi

# 3. Create virtual environment
echo ""
echo "[+] Step 3: Setting up project virtual environment at $REPO_DIR/.venv..."
if [ ! -d "$REPO_DIR/.venv" ]; then
    python3 -m venv "$REPO_DIR/.venv"
fi

source "$REPO_DIR/.venv/bin/activate"
pip install --upgrade pip setuptools wheel
pip install -e .

# 4. Frontend production compilation
echo ""
echo "[+] Step 4: Checking production frontend assets..."
if [ ! -f "$REPO_DIR/web/dist/index.html" ]; then
    if command -v npm >/dev/null 2>&1; then
        echo "[+] Building React production frontend..."
        cd "$REPO_DIR/web"
        npm install
        npm run build
        cd "$REPO_DIR"
    else
        echo "[!] npm not found. If running without Node.js, ensure pre-built web/dist is present."
    fi
else
    echo "[✓] Pre-built web/dist/index.html is ready."
fi

# 5. Make launcher executable
echo ""
echo "[+] Step 5: Configuring executable permissions on launchers..."
chmod +x "$REPO_DIR/bin/beacon"
chmod +x "$REPO_DIR/scripts/build_linux.sh" || true

# 6. Install desktop launcher
echo ""
echo "[+] Step 6: Installing desktop shortcut..."
mkdir -p "$HOME/.local/share/applications"
cp "$REPO_DIR/beacon.desktop" "$HOME/.local/share/applications/beacon.desktop"

DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
if [ -d "$DESKTOP_DIR" ]; then
    cp "$REPO_DIR/beacon.desktop" "$DESKTOP_DIR/beacon.desktop"
    chmod +x "$DESKTOP_DIR/beacon.desktop"
    echo "[✓] Desktop shortcut created at $DESKTOP_DIR/beacon.desktop"
fi

echo ""
echo "======================================================================"
echo "  SETUP COMPLETE!"
echo "======================================================================"
echo "  To start Beacon with one click:"
echo "    - Double-click 'Beacon' on your desktop or application menu"
echo "    - Or run: $REPO_DIR/bin/beacon"
echo ""
echo "  To run CLI analysis:"
echo "    $REPO_DIR/bin/beacon analyze capture.pcap --mode blue"
echo "======================================================================"
