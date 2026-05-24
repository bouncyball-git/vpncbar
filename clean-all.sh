#!/bin/sh
# Remove all build artifacts: the VpncBar.app output and the vendored vpnc
# object files / binaries / generated icon. Source files are left untouched.
set -e
cd "$(dirname "$0")"

# So vendor/vpnc/Makefile can find libgcrypt-config while parsing (even for clean).
export PATH="/opt/local/bin:$PATH"

echo "Cleaning VpncBar app build (bin/)…"
rm -rf bin

echo "Cleaning vendor/vpnc (objects + bin/)…"
if [ -f vendor/vpnc/Makefile ]; then
    make -C vendor/vpnc clean >/dev/null 2>&1 || true
fi
rm -rf vendor/vpnc/bin

echo "Cleaning generated icon set + logs…"
rm -rf src/VpncBar.iconset VpncBar.iconset   # intermediate; src/VpncBar.icns is kept
rm -f ./*.log

echo "Done. Source intact — rebuild with ./build.sh (app) and ./build-vpnc.sh (vpnc)."
