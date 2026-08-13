#!/bin/bash
#
# Build dpiOS for macOS from a non-macOS host.
#
# Zig ships a C compiler with Apple's libSystem stubs and most of the Darwin
# headers, so `zig cc -target aarch64-macos` produces a real Mach-O binary
# without Xcode. Three headers are missing from Zig's set; they are fetched
# from Apple's own open-source XNU tree.
#
# This exists to catch compile errors during development on a Linux box. The
# binary it produces is unsigned and untested on real hardware - on a Mac,
# just run `make`.
#
#   ./scripts/crossbuild.sh              # arm64
#   ./scripts/crossbuild.sh x86_64       # intel
#
set -euo pipefail

ARCH="${1:-aarch64}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${DPIOS_CROSS_DIR:-${TMPDIR:-/tmp}/dpios-cross}"
ZIG_VERSION="0.16.0"
XNU="https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd"

mkdir -p "$WORK"
cd "$WORK"

# --- toolchain -------------------------------------------------------------
if command -v zig >/dev/null 2>&1; then
    ZIG="$(command -v zig)"
else
    ZIG_DIR="$WORK/zig-x86_64-linux-${ZIG_VERSION}"
    if [[ ! -x "$ZIG_DIR/zig" ]]; then
        echo "==> downloading zig ${ZIG_VERSION}"
        curl -sSL -o zig.tar.xz \
            "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
        tar xf zig.tar.xz
    fi
    ZIG="$ZIG_DIR/zig"
fi
echo "==> using $($ZIG version) at $ZIG"

# --- the headers Zig does not bundle ---------------------------------------
SHIM="$WORK/sdkshim"
mkdir -p "$SHIM/net" "$SHIM/sys" "$SHIM/netinet"

fetch() {  # fetch <remote-path> <local-path>
    [[ -s "$SHIM/$2" ]] && return 0
    echo "==> fetching $2 from XNU"
    curl -sSfL -o "$SHIM/$2" "$XNU/$1"
}
fetch net/if_utun.h     net/if_utun.h
fetch net/bpf.h         net/bpf.h
fetch sys/sys_domain.h  sys/sys_domain.h
fetch netinet/ip6.h     netinet/ip6.h

# --- build -----------------------------------------------------------------
OUT="$REPO_DIR/build/dpios-${ARCH}-macos"
mkdir -p "$REPO_DIR/build"

echo "==> compiling for ${ARCH}-macos"
"$ZIG" cc -target "${ARCH}-macos" \
    -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter \
    -I"$REPO_DIR/src" -I"$SHIM" \
    -o "$OUT" "$REPO_DIR"/src/*.c

echo
file "$OUT" 2>/dev/null || ls -la "$OUT"
echo
echo "Built $OUT"
echo "Copy it to a Mac, chmod +x, then: sudo ./dpios --check"
