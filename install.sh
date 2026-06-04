#!/bin/sh
# Build (if needed) and install VpncBar:
#   - VpncBar.app          -> /Applications
#   - vpnc, vpnc-disconnect, vpnc-script, cisco-decrypt -> /opt/vpncbar
#   - passwordless-sudo rule for vpnc/vpnc-disconnect    -> /etc/sudoers.d/vpncbar
#
# vpnc is statically linked (no MacPorts needed). Run as your normal user — the
# script uses `sudo` only for the privileged steps (so it captures the right
# username for the sudoers rule). Uninstall with ./uninstall.sh.
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"
USER_NAME="$(whoami)"
PKG="/opt/vpncbar"
APP="bin/VpncBar.app"

[ "$(id -u)" = 0 ] && { echo "Run as your normal user (NOT sudo); it will sudo the steps that need root." >&2; exit 1; }

# 1. Build the self-contained vpnc + the app if they're not already built.
[ -f vendor/vpnc/bin/vpnc ] && [ -f vendor/vpnc/bin/cisco-decrypt ] || ./build.sh vpnc
[ -d "$APP" ] || ./build.sh app

# 2. App -> /Applications
echo "Installing VpncBar.app -> /Applications…"
rm -rf /Applications/VpncBar.app
cp -R "$APP" /Applications/

# 3. vpnc package -> /opt/vpncbar (root-owned, self-contained)
echo "Installing vpnc package -> $PKG (sudo)…"
sudo install -d "$PKG"
sudo install -m 755 vendor/vpnc/bin/vpnc            "$PKG/vpnc"
sudo install -m 755 vendor/vpnc/bin/cisco-decrypt   "$PKG/cisco-decrypt"
sudo install -m 755 vendor/vpnc/src/vpnc-disconnect "$PKG/vpnc-disconnect"
sudo install -m 755 vendor/vpnc-script              "$PKG/vpnc-script"
sudo install -m 755 uninstall.sh                    "$PKG/uninstall.sh"

# 4. sudoers: let this user run vpnc/vpnc-disconnect (and a system openconnect, for
#    AnyConnect profiles) as root without a password. The openconnect paths may not
#    exist — listing them is harmless and covers Homebrew/MacPorts/local installs.
DEST="/etc/sudoers.d/vpncbar"
RULE="$USER_NAME ALL=(root) NOPASSWD: $PKG/vpnc, $PKG/vpnc-disconnect, /opt/homebrew/bin/openconnect, /opt/local/bin/openconnect, /opt/local/sbin/openconnect, /usr/local/bin/openconnect"
echo "Installing sudoers rule (sudo): $RULE"
printf '%s\n' "$RULE" | sudo tee "$DEST" >/dev/null
sudo chmod 440 "$DEST"
if ! sudo visudo -cf "$DEST" >/dev/null; then
    echo "INVALID sudoers rule — removing $DEST" >&2
    sudo rm -f "$DEST"
    exit 1
fi

echo
echo "Installed. vpnc: $("$PKG/vpnc" --version | head -1)"
echo "Runtime deps (expect ONLY /usr/lib/libSystem):"
/usr/bin/otool -L "$PKG/vpnc" | sed -n '2,$p'
echo "Launch:  open /Applications/VpncBar.app"
