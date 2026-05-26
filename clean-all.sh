#!/bin/sh
# Remove all build artifacts: the VpncBar.app output, the vendored vpnc objects/
# binaries, the statically-built crypto deps (libgcrypt + libgpg-error), and the
# generated icon. Source files are left untouched.
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"

# Our static libgcrypt-config (so vendor/vpnc/Makefile parses for the `clean` target).
export PATH="$ROOT/vendor/deps/bin:$PATH"

echo "Cleaning VpncBar app build (bin/)…"
rm -rf bin

echo "Cleaning vendor/vpnc (objects + bin/)…"
if [ -f vendor/vpnc/Makefile ]; then
    make -C vendor/vpnc clean >/dev/null 2>&1 || true
fi
rm -rf vendor/vpnc/bin

echo "Cleaning static crypto deps (vendor/deps: libgcrypt + libgpg-error)…"
rm -rf vendor/deps

echo "Cleaning generated icon set + logs…"
rm -rf src/VpncBar.iconset VpncBar.iconset   # intermediate; src/VpncBar.icns is kept
rm -f ./*.log

echo "Done. Source intact."
echo "Rebuild: ./build-vpnc.sh (re-downloads & recompiles libgcrypt + libgpg-error, then vpnc)"
echo "         ./build.sh       (the app)"
