#!/bin/sh
# Build a fully self-contained, utun-capable vpnc for macOS — NO MacPorts needed
# at build OR run time. The static crypto libs (libgpg-error + libgcrypt) are
# produced by build-deps.sh; this script links them statically into vpnc, so only
# /usr/lib/libSystem stays dynamic. Produces ./vendor/vpnc/bin/{vpnc,cisco-decrypt}.
#
#   CRYPTO_NONE=yes   skip GnuTLS/OpenSSL cert code; core crypto via libgcrypt
#   SCRIPT_PATH=...   bake in the network-config script path
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"

VPNC_DIR="vendor/vpnc"
DEPS="$ROOT/vendor/deps"
SCRIPT_PATH="${SCRIPT_PATH:-/opt/vpncbar/vpnc-script}"

[ -f "$VPNC_DIR/Makefile" ] || { echo "error: $VPNC_DIR/Makefile not found (run from project root)" >&2; exit 1; }

# Ensure the static crypto deps exist; build-deps.sh builds them from source if not.
if [ ! -f "$DEPS/lib/libgcrypt.a" ] || [ ! -f "$DEPS/lib/libgpg-error.a" ]; then
    ./build-deps.sh
fi

# Our static libgcrypt-config wins on PATH; its lib dir holds only .a archives, so
# the `-lgcrypt -lgpg-error` link resolves to the static libs (no MacPorts).
export PATH="$DEPS/bin:$PATH"

echo "Building vpnc (static, CRYPTO_NONE=yes, SCRIPT_PATH=$SCRIPT_PATH)…"
make -C "$VPNC_DIR" clean >/dev/null 2>&1 || true
make -C "$VPNC_DIR" CRYPTO_NONE=yes SCRIPT_PATH="$SCRIPT_PATH"

echo
echo "Built $ROOT/$VPNC_DIR/bin/vpnc"
"$VPNC_DIR/bin/vpnc" --version | head -1
echo "Runtime deps (expect ONLY /usr/lib/libSystem):"
/usr/bin/otool -L "$VPNC_DIR/bin/vpnc" | sed -n '2,$p'
echo "Install everything:  ./install.sh"
