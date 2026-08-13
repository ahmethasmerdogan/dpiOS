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

if [[ "${1:-}" == "--purge" ]]; then
    echo "==> removing /usr/local/bin/dpios"
    rm -f /usr/local/bin/dpios
    rm -f /var/log/dpios.log
fi

echo
echo "dpiOS service removed. Networking is back to normal."
echo "(pass --purge to also delete the binary and the log file)"
