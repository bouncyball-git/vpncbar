#!/bin/sh
# Install the utun-capable vpnc + patched vpnc-disconnect to /opt/local/sbin.
# (No MacPorts vpnc remains, so nothing is backed up.)
# Run with sudo:  sudo ./install-utun-vpnc.sh
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_VPNC="$HERE/vendor/vpnc/bin/vpnc"
SRC_DISC="$HERE/vendor/vpnc/src/vpnc-disconnect"
SRC_SCRIPT="$HERE/vendor/vpnc-script"

[ -f "$SRC_VPNC" ]   || { echo "error: build first — missing $SRC_VPNC (run: ./build-vpnc.sh)"; exit 1; }
[ -f "$SRC_DISC" ]   || { echo "error: missing $SRC_DISC"; exit 1; }
[ -f "$SRC_SCRIPT" ] || { echo "error: missing $SRC_SCRIPT"; exit 1; }
[ "$(id -u)" = 0 ]   || { echo "error: run with sudo"; exit 1; }

install -d /opt/local/sbin
install -m 755 "$SRC_VPNC" /opt/local/sbin/vpnc            && echo "installed -> /opt/local/sbin/vpnc"
install -m 755 "$SRC_DISC" /opt/local/sbin/vpnc-disconnect && echo "installed -> /opt/local/sbin/vpnc-disconnect"

# Network-config script (our copy: never modifies the system default route).
install -d /opt/local/etc/vpnc
install -m 755 "$SRC_SCRIPT" /opt/local/etc/vpnc/vpnc-script && echo "installed -> /opt/local/etc/vpnc/vpnc-script"

/opt/local/sbin/vpnc --version | head -1
