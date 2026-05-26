#!/bin/sh
# Remove build artifacts.  Usage:  ./clean.sh [all|app|deps|vpnc|pkg]   (default: all)
#
#   app    VpncBar.app build (bin/) + generated icon set
#   vpnc   vendored vpnc objects + binaries (vendor/vpnc)
#   deps   static crypto libs (vendor/deps: libgcrypt + libgpg-error)
#   pkg    installer artifacts (build/ staging + dist/ .pkg)
#   all    everything above + logs   (default)
#
# Source files are never touched.
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"

clean_app() {
    echo "Cleaning app build (bin/) + generated icon…"
    rm -rf bin
    rm -rf src/VpncBar.iconset VpncBar.iconset   # intermediate; src/VpncBar.icns is kept
}

clean_vpnc() {
    echo "Cleaning vendor/vpnc (objects + bin/)…"
    if [ -f vendor/vpnc/Makefile ]; then
        # vendor/deps/bin on PATH so the Makefile parses for the `clean` target.
        ( export PATH="$ROOT/vendor/deps/bin:$PATH"; make -C vendor/vpnc clean >/dev/null 2>&1 ) || true
    fi
    rm -f vendor/vpnc/src/*.o
    rm -rf vendor/vpnc/bin
}

clean_deps() {
    echo "Cleaning static crypto deps (vendor/deps: libgcrypt + libgpg-error)…"
    rm -rf vendor/deps
}

clean_pkg() {
    echo "Cleaning installer artifacts (build/ staging + dist/ .pkg)…"
    rm -rf build dist
}

TARGET="${1:-all}"
case "$TARGET" in
    app)  clean_app ;;
    vpnc) clean_vpnc ;;
    deps) clean_deps ;;
    pkg)  clean_pkg ;;
    all)  clean_app; clean_vpnc; clean_deps; clean_pkg; rm -f ./*.log ;;
    *)    echo "usage: $0 [all|app|deps|vpnc|pkg]   (default: all)" >&2; exit 1 ;;
esac

echo "Done ($TARGET). Source intact."
[ "$TARGET" = all ] || [ "$TARGET" = deps ] && \
    echo "Note: rebuilding vpnc after cleaning deps re-downloads & recompiles libgcrypt + libgpg-error."
exit 0
