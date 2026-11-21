#!/bin/bash
# Integration test runner for cap-grantd.
#
# Runs a freshly built cap-grantd in a private mount namespace so its
# Varlink socket at /run/cap-grant/org.openSUSE.CapGrant never collides
# with a cap-grantd instance already running on the host. Everything
# this test writes under /run lives on a private tmpfs that vanishes
# when this script exits, so a host daemon (and the rest of the host's
# /run) is never touched.
#
# Must run as root: both the mount namespace setup and some of the
# behavior under test (lowering niceness, opening raw sockets) require
# real root privileges in the daemon.
#
# Creating a mount namespace needs CAP_SYS_ADMIN, which many CI/build
# containers drop even for root. Such containers normally already have
# their own private /run, separate from any real host, so when unshare
# is unavailable this script falls back to running without extra
# isolation -- but only if nothing is already listening on our socket
# path, to avoid ever clobbering a genuinely running cap-grantd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build}"

# Meson's convention: exit 77 means "skipped".
SKIP=77

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: must run as root (needs a private mount namespace for /run/cap-grant)" >&2
    exit $SKIP
fi

CAP_GRANTD="$BUILD_DIR/cap-grantd"
TEST_CLIENT="$BUILD_DIR/tests/test-cap-grant"

for f in "$CAP_GRANTD" "$TEST_CLIENT"; do
    if [ ! -x "$f" ]; then
        echo "ERROR: $f not found or not executable; build the project first" >&2
        exit 1
    fi
done

SOCKET_DIR=/run/cap-grant
SOCKET_PATH="$SOCKET_DIR/org.openSUSE.CapGrant"

# Re-exec ourselves inside a private mount namespace exactly once.
if [ "${CAP_GRANT_TEST_UNSHARED:-0}" != "1" ]; then
    if unshare --mount --propagation private -- true 2>/dev/null; then
        export CAP_GRANT_TEST_UNSHARED=1
        export BUILD_DIR
        exec unshare --mount --propagation private -- "$0" "$@"
    fi

    if [ -S "$SOCKET_PATH" ]; then
        echo "ERROR: cannot create a private mount namespace (unshare failed, likely missing CAP_SYS_ADMIN)" >&2
        echo "ERROR: and $SOCKET_PATH already exists; refusing to risk colliding with a running cap-grantd." >&2
        echo "ERROR: grant CAP_SYS_ADMIN to this container, or stop that instance first." >&2
        exit 1
    fi

    echo "WARNING: mount namespace isolation unavailable (no CAP_SYS_ADMIN); running without it" >&2
    export CAP_GRANT_TEST_UNSHARED=1
    export CAP_GRANT_TEST_NOT_ISOLATED=1
fi

# Overmount /run with a private tmpfs: nothing created below is visible
# outside this mount namespace, and it disappears automatically once
# this script (the last process using it) exits. Skipped in the
# unisolated fallback, where /run is whatever the container gave us.
if [ "${CAP_GRANT_TEST_NOT_ISOLATED:-0}" != "1" ]; then
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
fi
mkdir -p "$SOCKET_DIR"

"$CAP_GRANTD" &
DAEMON_PID=$!

cleanup() {
    local ec=$?
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    # Without namespace isolation we created real entries under the
    # container's /run; without it they'd otherwise outlive this script.
    if [ "${CAP_GRANT_TEST_NOT_ISOLATED:-0}" = "1" ]; then
        rm -f "$SOCKET_PATH"
        rmdir "$SOCKET_DIR" 2>/dev/null || true
    fi
    exit $ec
}
trap cleanup EXIT INT TERM

ready=0
for _ in $(seq 1 50); do
    if [ -S "$SOCKET_PATH" ]; then
        ready=1
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "ERROR: cap-grantd exited before creating its socket" >&2
        exit 1
    fi
    sleep 0.1
done

if [ "$ready" -ne 1 ]; then
    echo "ERROR: timed out waiting for $SOCKET_PATH" >&2
    exit 1
fi

"$TEST_CLIENT"
