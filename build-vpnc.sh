#!/bin/sh
# Build the utun-capable vpnc (in ./vpnc) for macOS without certificate support,
# which we don't use (PSK + XAUTH only). Produces ./vpnc/bin/vpnc.
#
#   CRYPTO_NONE=yes   skip GnuTLS/OpenSSL cert code; core crypto via libgcrypt
#   SCRIPT_PATH=...   bake in the network-config script so the binary is self-contained
#
# Override the script path if vpnc-script lives elsewhere:
#   SCRIPT_PATH=/usr/local/etc/vpnc/vpnc-script ./build-vpnc.sh
set -e
cd "$(dirname "$0")"

VPNC_DIR="vpnc"
SCRIPT_PATH="${SCRIPT_PATH:-/opt/local/etc/vpnc/vpnc-script}"

# MacPorts tools (libgcrypt-config) must be on PATH.
export PATH="/opt/local/bin:$PATH"

[ -f "$VPNC_DIR/Makefile" ] || { echo "error: $VPNC_DIR/Makefile not found (run from project root)" >&2; exit 1; }
if ! command -v libgcrypt-config >/dev/null 2>&1; then
    echo "error: libgcrypt-config not found. Install it:  sudo port install libgcrypt" >&2
    exit 1
fi

echo "Building vpnc (CRYPTO_NONE=yes, SCRIPT_PATH=$SCRIPT_PATH)…"
make -C "$VPNC_DIR" clean >/dev/null 2>&1 || true
make -C "$VPNC_DIR" CRYPTO_NONE=yes SCRIPT_PATH="$SCRIPT_PATH"

echo
echo "Built $(pwd)/$VPNC_DIR/bin/vpnc"
"$VPNC_DIR/bin/vpnc" --version | head -1
echo "Install over the system binary:  sudo $VPNC_DIR/install-utun-vpnc.sh"
