#!/bin/sh
# Remove everything install.sh put on the system. Leaves your VPN profiles and
# Keychain secrets alone (see the note at the end). Run as your normal user.
set -e
cd "$(dirname "$0")"

[ "$(id -u)" = 0 ] && { echo "Run as your normal user (NOT sudo)." >&2; exit 1; }

echo "Quitting VpncBar (if running)…"
osascript -e 'quit app "VpncBar"' 2>/dev/null || true

echo "Removing /Applications/VpncBar.app…"
rm -rf /Applications/VpncBar.app

echo "Removing /opt/vpncbar and the sudoers rule (sudo)…"
sudo rm -rf /opt/vpncbar
sudo rm -f /etc/sudoers.d/vpncbar

echo "Removing transient runtime files…"
sudo rm -rf /var/run/vpncbar 2>/dev/null || true

echo
echo "Done. Your profiles and secrets were kept:"
echo "  profiles : ~/.config/vpncbar/"
echo "  secrets  : macOS login Keychain (items named vpnc-<uuid>-…)"
echo "Delete those manually if you want a full wipe."
