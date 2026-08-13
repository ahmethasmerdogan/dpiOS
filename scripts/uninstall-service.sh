#!/bin/bash
#
# Remove the dpiOS launchd daemon and make sure no pf rules are left behind.
#
set -euo pipefail

LABEL="com.dpios.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
ANCHOR="com.apple/dpios"

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root. Re-run with sudo." >&2
    exit 1
fi

echo "==> stopping the daemon"
launchctl bootout "system/${LABEL}" 2>/dev/null || true

if [[ -f "$PLIST" ]]; then
    echo "==> removing $PLIST"
    rm -f "$PLIST"
fi

# Belt and braces: even if the daemon crashed without cleaning up, this puts
# the packet filter back the way it was.
echo "==> flushing pf anchor ${ANCHOR}"
pfctl -a "$ANCHOR" -F all 2>/dev/null || true

# Remove the /etc/hosts entries the installer added for DNS-blocked names.
HOSTS_BEGIN="# BEGIN dpiOS"
HOSTS_END="# END dpiOS"
if grep -q "^${HOSTS_BEGIN}$" /etc/hosts 2>/dev/null; then
    echo "==> removing dpiOS entries from /etc/hosts"
    awk -v b="$HOSTS_BEGIN" -v e="$HOSTS_END" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip   { print }
    ' /etc/hosts > /tmp/dpios-hosts.new && cat /tmp/dpios-hosts.new > /etc/hosts
    rm -f /tmp/dpios-hosts.new
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
fi

# The installer turns IPv6 off only when the ISP was answering with a forged
# AAAA record. Put it back either way - it is harmless if it was never off.
DEV6="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
SVC6="$(networksetup -listnetworkserviceorder 2>/dev/null \
        | grep -B1 "Device: ${DEV6})" | head -1 | sed 's/^([0-9]*) //')"
if [[ -n "${SVC6:-}" ]]; then
    echo "==> restoring IPv6 on ${SVC6}"
    networksetup -setv6automatic "$SVC6" 2>/dev/null || true
fi

if [[ "${1:-}" == "--purge" ]]; then
    echo "==> removing /usr/local/bin/dpios"
    rm -f /usr/local/bin/dpios
    rm -f /var/log/dpios.log
fi

echo
echo "dpiOS service removed. Networking is back to normal."
echo "(pass --purge to also delete the binary and the log file)"
