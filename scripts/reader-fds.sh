#!/bin/sh
# Open only the Fold's fingerprint hidraw interface as root, then run the
# native diagnostic or registration command as the invoking user.
set -eu
if [ "$#" -lt 3 ] || [ "$(id -u)" -ne 0 ] || [ -z "${SUDO_UID:-}" ] || [ -z "${SUDO_GID:-}" ]; then
    echo 'Usage: sudo scripts/reader-fds.sh auto HOST-KEY-OR-- COMMAND [ARGS...]' >&2
    exit 2
fi
node=$1
key=$2
shift 2
if [ "$node" = auto ]; then
    count=0
    for candidate in /sys/class/hidraw/hidraw*; do
        [ -e "$candidate" ] || continue
        [ "$(cat "$candidate/device/../bInterfaceNumber" 2>/dev/null)" = 04 ] || continue
        [ "$(cat "$candidate/device/../../idVendor" 2>/dev/null)" = 17ef ] || continue
        [ "$(cat "$candidate/device/../../idProduct" 2>/dev/null)" = 6142 ] || continue
        node=/dev/${candidate##*/}
        count=$((count + 1))
    done
    if [ "$count" -ne 1 ]; then
        echo "Expected one Fold fingerprint interface, found $count" >&2
        exit 1
    fi
fi
case $node in
    /dev/hidraw[0-9]*) ;;
    *) echo 'Expected a /dev/hidraw node or auto' >&2; exit 2 ;;
esac
[ -c "$node" ] || { echo "Fingerprint node is missing: $node" >&2; exit 1; }
exec 3<> "$node"
if [ "$key" != - ]; then
    exec 4< "$key"
fi
exec setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --clear-groups "$@"
