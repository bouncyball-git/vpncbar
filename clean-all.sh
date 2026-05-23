#!/bin/sh
# Remove all build artifacts: the VpncBar.app output and the vpnc-utun object
# files / binaries / generated icon. Source files are left untouched.
set -e
cd "$(dirname "$0")"

# So vpnc-utun/Makefile can find libgcrypt-config while parsing (even for clean).
export PATH="/opt/local/bin:$PATH"

echo "Cleaning VpncBar app build (build/)…"
rm -rf build

echo "Cleaning vpnc-utun (objects + bin/)…"
if [ -f vpnc-utun/Makefile ]; then
    make -C vpnc-utun clean >/dev/null 2>&1 || true
fi
rm -rf vpnc-utun/bin

echo "Cleaning generated icon set + logs…"
rm -rf src/VpncBar.iconset VpncBar.iconset   # intermediate; src/VpncBar.icns is kept
rm -f ./*.log

echo "Done. Source intact — rebuild with ./build.sh (app) and ./build-vpnc.sh (vpnc)."
