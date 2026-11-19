#!/bin/sh
# The published installer stages only the native Linux runtime.
set -eu
cd "$(dirname "$0")/.."
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
build_dir=${BUILD_DIR:-"$PWD/build"}

BUILD_DIR="$build_dir" DESTDIR="$stage/native" ./install.sh
test -f "$stage/native/usr/local/libexec/x1fold-fingerprint/native-worker"
test -f "$stage/native/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so"
test -f "$stage/native/etc/systemd/system/x1fold-fingerprint.socket"
test -f "$stage/native/etc/systemd/system/x1fold-fingerprint@.service"
test "$(find "$stage/native" -type f | wc -l)" -eq 4

# Supply old binary inputs; rejection must occur before legacy source checks.
mkdir -p "$stage/inputs"
cp "$build_dir/libx1fold-hid.so" "$stage/inputs/libx1fold-hid.so"
printf 'retired worker\n' > "$stage/inputs/worker"
if output=$(BUILD_DIR="$stage/inputs" DESTDIR="$stage/legacy" ./install.sh --legacy 2>&1); then
    echo 'Legacy worker installation is still enabled' >&2
    exit 1
else
    status=$?
fi
test "$status" -eq 2
case "$output" in
    'Usage: ./install.sh '*) ;;
    *) echo "Unexpected legacy rejection: $output" >&2; exit 1 ;;
esac
test ! -e "$stage/legacy/usr/local/libexec/x1fold-fingerprint/worker"
echo 'Native-only installation staging passed'
