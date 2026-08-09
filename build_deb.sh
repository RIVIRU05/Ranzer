#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  RANZER - .deb Package Builder
#  Must be run on a Debian / Ubuntu / Kali Linux machine.
#  Usage:  bash build_deb.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PACKAGE="ranzer"
VERSION="1.0"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
DEB_NAME="${PACKAGE}_${VERSION}_${ARCH}"

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build_output"
STAGE="$BUILD/${DEB_NAME}"

# ── Preflight ─────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════╗"
echo "║     RANZER  .deb  Package  Builder       ║"
echo "╚══════════════════════════════════════════╝"
echo

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: This script must run on Linux (detected: $(uname -s))"
    exit 1
fi

for cmd in python3 dpkg-deb sudo; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Run: sudo apt install python3 dpkg"
        exit 1
    fi
done

# ── Step 1: Install all dependencies system-wide ──────────────────────────────
echo "[1/5] Installing dependencies..."

sudo apt-get update -qq

# watchdog and psutil are reliably in apt on all architectures
sudo apt-get install -y python3-watchdog python3-psutil

# Pillow (python3-pil) sometimes has repo gaps on arm64 - try apt first,
# fall back to pip if the package isn't available
if sudo apt-get install -y python3-pil python3-pil.imagetk python3-tk 2>/dev/null; then
    echo "      Pillow installed via apt"
else
    echo "      apt unavailable for Pillow - falling back to pip..."
    pip3 install --quiet --break-system-packages Pillow
fi

# PyInstaller is not in apt - install system-wide via pip
pip3 install --quiet --break-system-packages pyinstaller

echo "      OK"

# ── Step 2: PyInstaller bundle ────────────────────────────────────────────────
echo "[2/5] Bundling app with PyInstaller (may take ~1–2 min)..."
cd "$ROOT"
rm -rf "$BUILD/pyinstaller_work" "$BUILD/dist"
pyinstaller ranzer.spec \
    --distpath "$BUILD/dist" \
    --workpath "$BUILD/pyinstaller_work" \
    --noconfirm \
    --clean \
    2>&1 | grep -E "^(ERROR|WARNING|Building|COLLECT)" || true
echo "      OK - bundle: $BUILD/dist/ranzer/"

# ── Step 3: .deb directory structure ─────────────────────────────────────────
echo "[3/5] Assembling .deb structure..."
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/opt/ranzer"
mkdir -p "$STAGE/usr/local/bin"
mkdir -p "$STAGE/usr/share/applications"
mkdir -p "$STAGE/usr/share/icons/hicolor/256x256/apps"

cp -r "$BUILD/dist/ranzer/." "$STAGE/opt/ranzer/"
ln -sf /opt/ranzer/ranzer "$STAGE/usr/local/bin/ranzer"
cp "$ROOT/packaging/ranzer.desktop" "$STAGE/usr/share/applications/"
cp "$ROOT/ranzer/gui/logo.png" \
   "$STAGE/usr/share/icons/hicolor/256x256/apps/ranzer.png"

INSTALLED_KB=$(du -sk "$STAGE" | cut -f1)
sed \
    -e "s/^Architecture: .*/Architecture: ${ARCH}/" \
    -e "s/^Installed-Size: .*/Installed-Size: ${INSTALLED_KB}/" \
    "$ROOT/packaging/debian/control" > "$STAGE/DEBIAN/control"

cp "$ROOT/packaging/debian/postinst" "$STAGE/DEBIAN/"
cp "$ROOT/packaging/debian/prerm"    "$STAGE/DEBIAN/"
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"
echo "      OK"

# ── Step 4: Build .deb ───────────────────────────────────────────────────────
echo "[4/5] Building .deb..."
dpkg-deb --build --root-owner-group "$STAGE" "$ROOT/${DEB_NAME}.deb"
echo "      OK"

# ── Done ─────────────────────────────────────────────────────────────────────
SIZE=$(du -sh "$ROOT/${DEB_NAME}.deb" | cut -f1)
echo
echo "[5/5] ✓  Package ready!"
echo
echo "  File : ${ROOT}/${DEB_NAME}.deb  (${SIZE})"
echo
