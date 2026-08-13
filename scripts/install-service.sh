#!/bin/bash
#
# Install dpiOS as a launchd system daemon.
#
#   sudo ./scripts/install-service.sh            # uses preset -5
#   sudo ./scripts/install-service.sh -6 --frag-sni
#
set -euo pipefail

LABEL="com.dpios.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
BIN="/usr/local/bin/dpios"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root. Re-run with sudo." >&2
    exit 1
fi

if [[ ! -x "$BIN" ]]; then
    if [[ -x "$REPO_DIR/build/dpios" ]]; then
        echo "==> installing $BIN"
        install -d /usr/local/bin
        install -m 0755 "$REPO_DIR/build/dpios" "$BIN"
    else
        echo "$BIN not found and no build/dpios to install." >&2
        echo "Run 'make' first." >&2
        exit 1
    fi
fi

# Arguments after the script name become the daemon's arguments.
ARGS=("$@")
if [[ ${#ARGS[@]} -eq 0 ]]; then
    ARGS=("-5")
fi

echo "==> verifying this machine first"
if ! "$BIN" --check; then
    echo
    echo "Self-test reported failures. Fix them before installing the service." >&2
    exit 1
fi

echo "==> writing $PLIST"
{
    cat <<'HEADER'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dpios.daemon</string>

    <key>ProgramArguments</key>
    <array>
HEADER
    echo "        <string>${BIN}</string>"
    for a in "${ARGS[@]}"; do
        # escape XML metacharacters
        esc=$(printf '%s' "$a" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')
        echo "        <string>${esc}</string>"
    done
    echo "        <string>--syslog</string>"
    cat <<'FOOTER'
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>ProcessType</key>
    <string>Background</string>

    <key>StandardOutPath</key>
    <string>/var/log/dpios.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/dpios.log</string>
</dict>
</plist>
FOOTER
} > "$PLIST"

chown root:wheel "$PLIST"
chmod 0644 "$PLIST"

echo "==> (re)loading the daemon"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/${LABEL}"

sleep 1
echo
echo "Done. dpiOS is running with: ${ARGS[*]}"
echo
echo "  status : sudo launchctl print system/${LABEL} | head -20"
echo "  logs   : tail -f /var/log/dpios.log"
echo "  stop   : sudo launchctl bootout system/${LABEL}"
echo "  remove : sudo ./scripts/uninstall-service.sh"
