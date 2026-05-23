#!/bin/sh
# Install the freshly built utun-capable vpnc over the MacPorts binary that
# VpncBar and the sudoers rule already point at. Backs up the original once.
# Run with sudo:  sudo ./install-utun-vpnc.sh
set -e

SRC="$(cd "$(dirname "$0")" && pwd)/bin/vpnc"
DEST="/opt/local/sbin/vpnc"

[ -f "$SRC" ] || { echo "error: build first — missing $SRC (run: make CRYPTO_NONE=yes SCRIPT_PATH=/opt/local/etc/vpnc/vpnc-script)"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "error: run with sudo"; exit 1; }

if [ ! -f "$DEST.macports.bak" ]; then
    cp -p "$DEST" "$DEST.macports.bak"
    echo "backed up original  -> $DEST.macports.bak"
fi

cp "$SRC" "$DEST"
chmod 755 "$DEST"
echo "installed utun vpnc -> $DEST"
"$DEST" --version | head -1
echo "To revert: sudo cp $DEST.macports.bak $DEST"
