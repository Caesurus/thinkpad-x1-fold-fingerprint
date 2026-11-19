#!/bin/sh
# Stage with DESTDIR, or install and activate on the tested Ubuntu amd64 layout.
set -eu
cd "$(dirname "$0")"
build_dir=${BUILD_DIR:-"$PWD/build"}
root=${DESTDIR:-}
case "$#:${1:-}" in
    0:|1:--native) ;;
    *) echo "Usage: ./install.sh [--native]" >&2; exit 2 ;;
esac
if [ -n "$root" ]; then
    case "$root" in /*) ;; *) echo "DESTDIR must be absolute" >&2; exit 2 ;; esac
    mkdir -p "$root"
    root=$(realpath "$root")
    [ "$root" != / ] || { echo "Choose an empty staging directory, or unset DESTDIR for a live install" >&2; exit 2; }
else
    [ "$(id -u)" -eq 0 ] || { echo "Use sudo for a live install" >&2; exit 1; }
    [ "$(dpkg --print-architecture)" = amd64 ] || { echo "Ubuntu amd64 required" >&2; exit 1; }
fi

unit=service/native/x1fold-fingerprint@.service
for input in "$build_dir/native-worker" "$build_dir/libx1fold-hid.so" service/x1fold-fingerprint.socket "$unit"; do
    [ -s "$input" ] || { echo "Missing installation input: $input" >&2; exit 1; }
done

# Rename each completed file into place so active processes retain their mapped ELF.
copy_file() (
    dest=$root$3
    mkdir -p "$(dirname "$dest")"
    temporary=$(mktemp "$dest.XXXXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    install -m "$1" "$2" "$temporary"
    mv -T -- "$temporary" "$dest"
)

helper=/usr/local/libexec/x1fold-fingerprint
units=/etc/systemd/system
copy_file 0755 "$build_dir/native-worker" "$helper/native-worker"
copy_file 0644 "$unit" "$units/x1fold-fingerprint@.service"
copy_file 0644 service/x1fold-fingerprint.socket "$units/x1fold-fingerprint.socket"
copy_file 0644 "$build_dir/libx1fold-hid.so" /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so

if [ -z "$root" ]; then
    systemctl daemon-reload
    systemctl enable --now x1fold-fingerprint.socket
    systemctl try-restart fprintd.service
    rm -f -- "$helper/worker" "$helper/worker.py" "$helper/console_session.py"
fi
