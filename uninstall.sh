#!/bin/sh
# Remove VpncBar: disconnect all tunnels, quit the app, then delete the app,
# /opt/vpncbar, the sudoers rule, and transient runtime files. Works whether
# installed via ./install.sh or the .pkg. Self-elevates with sudo, so just run:
#     ./uninstall.sh      (or  /opt/vpncbar/uninstall.sh)
#
# Your VPN profiles (~/.config/vpncbar) and Keychain secrets are KEPT — delete
# those by hand for a full wipe (see the note at the end).
[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"
cd /

echo "Quitting VpncBar app…"
pkill -x VpncBar 2>/dev/null || true

# Tear down any live tunnels BEFORE removing files: SIGTERM lets each vpnc run its
# disconnect script (restoring routes + scoped DNS) — which still exists right now.
echo "Disconnecting active vpnc tunnels…"
pkill -TERM -x vpnc 2>/dev/null || true
for _ in 1 2 3 4 5; do
    pgrep -x vpnc >/dev/null 2>&1 || break
    sleep 1
done
pkill -KILL -x vpnc 2>/dev/null || true   # force any straggler

echo "Removing files…"
rm -rf /Applications/VpncBar.app
rm -f  /etc/sudoers.d/vpncbar
rm -rf /var/run/vpncbar
rm -rf /opt/vpncbar          # last: this script lives here (already loaded, so fine)

echo
echo "Done. Kept your profiles (~/.config/vpncbar) and login-Keychain secrets"
echo "(items named vpnc-<uuid>-…). Delete those by hand for a full wipe."
