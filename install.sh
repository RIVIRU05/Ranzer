#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  RANZER - One-command installer
#  Usage:  bash install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════════╗"
echo "║          RANZER  Installer               ║"
echo "╚══════════════════════════════════════════╝"
echo

# ── Preflight ─────────────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: This installer is for Linux only."
    exit 1
fi

for cmd in sudo python3 dpkg; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found."
        exit 1
    fi
done

# ── Build ─────────────────────────────────────────────────────────────────────
echo "Step 1/2 - Building package..."
echo
bash "$ROOT/build_deb.sh"

# ── Install ───────────────────────────────────────────────────────────────────
DEB=$(ls "$ROOT"/ranzer_*.deb 2>/dev/null | head -1)
if [[ -z "$DEB" ]]; then
    echo "ERROR: Build failed - .deb not found."
    exit 1
fi

echo "Step 2/2 - Installing $(basename "$DEB")..."
sudo dpkg -i "$DEB"
sudo apt-get install -f -y 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
echo
echo "╔══════════════════════════════════════════╗"
echo "║   RANZER installed successfully!         ║"
echo "╚══════════════════════════════════════════╝"
echo
echo "  Launch:    ranzer gui"
echo "  Or search 'RANZER' in your application menu"
echo
echo "  Uninstall: sudo dpkg -r ranzer"
echo
