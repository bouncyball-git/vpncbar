#!/bin/sh
# One-time setup: allow the current user to run vpnc / vpnc-disconnect as root
# without a password, so VpncBar can toggle the VPN without prompting each time.
set -e

USER_NAME="$(whoami)"
RULE="$USER_NAME ALL=(root) NOPASSWD: /opt/local/sbin/vpnc, /opt/local/sbin/vpnc-disconnect"
DEST="/etc/sudoers.d/vpncbar"

echo "Installing sudoers rule for '$USER_NAME':"
echo "  $RULE"
printf '%s\n' "$RULE" | sudo tee "$DEST" >/dev/null
sudo chmod 440 "$DEST"

# Validate; remove the file if it doesn't parse so we never break sudo.
if sudo visudo -cf "$DEST" >/dev/null; then
    echo "OK: installed and validated $DEST"
else
    echo "INVALID rule — removing $DEST" >&2
    sudo rm -f "$DEST"
    exit 1
fi
