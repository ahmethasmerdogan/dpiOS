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
# --skip-check is ours, not the daemon's: install.sh has already run the
# self-test and there is no point paying for it twice.
SKIP_CHECK=0
ARGS=()
for a in "$@"; do
    if [[ "$a" == "--skip-check" ]]; then
        SKIP_CHECK=1
    else
        ARGS+=("$a")
    fi
done
if [[ ${#ARGS[@]} -eq 0 ]]; then
    ARGS=("-5")
fi

if [[ $SKIP_CHECK -eq 0 ]]; then
    echo "==> verifying this machine first"
    if ! "$BIN" --check; then
        echo
        echo "Self-test reported failures. Fix them before installing the service." >&2
        exit 1
    fi
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
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

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

# launchctl is the flakiest part of this script, so it gets handled by hand
# rather than under `set -e`: bootstrap fails with an unhelpful "Input/output
# error" if the label is still registered from a previous run, and the older
# load/unload verbs still work when bootstrap does not.
set +e

launchctl bootout "system/${LABEL}" >/dev/null 2>&1
launchctl bootout system "$PLIST"   >/dev/null 2>&1

# wait for the label to actually go away before bringing it back
for _ in 1 2 3 4 5 6 7 8 9 10; do
    launchctl print "system/${LABEL}" >/dev/null 2>&1 || break
    sleep 0.3
done

BOOT_ERR="$(launchctl bootstrap system "$PLIST" 2>&1)"
BOOT_RC=$?

if [[ $BOOT_RC -ne 0 ]]; then
    echo "    bootstrap başarısız (${BOOT_RC}): ${BOOT_ERR}"
    echo "    eski yöntem deneniyor: launchctl load"
    LOAD_ERR="$(launchctl load -w "$PLIST" 2>&1)"
    BOOT_RC=$?
    [[ $BOOT_RC -ne 0 ]] && echo "    load da başarısız: ${LOAD_ERR}"
fi

launchctl enable "system/${LABEL}" >/dev/null 2>&1
launchctl kickstart -k "system/${LABEL}" >/dev/null 2>&1

sleep 1

# Bootstrap can report success while the job dies immediately, so confirm the
# service really is registered and note its last exit status if it is not.
if ! launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    echo
    echo "Servis kaydedilemedi." >&2
    echo "Son loglar:" >&2
    tail -20 /var/log/dpios.log 2>/dev/null | sed 's/^/    /' >&2
    exit 1
fi

STATE="$(launchctl print "system/${LABEL}" 2>/dev/null \
         | awk -F'= ' '/last exit code|state/ {print "    " $0}' | head -3)"
[[ -n "$STATE" ]] && echo "$STATE"

set -e

echo
echo "Done. dpiOS is running with: ${ARGS[*]}"
echo
echo "  status : sudo launchctl print system/${LABEL} | head -20"
echo "  logs   : tail -f /var/log/dpios.log"
echo "  stop   : sudo launchctl bootout system/${LABEL}"
echo "  remove : sudo ./scripts/uninstall-service.sh"
