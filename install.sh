#!/bin/sh
# Stage with DESTDIR, or install and activate on the tested Ubuntu amd64 layout.
set -eu
cd "$(dirname "$0")"
build_dir=${BUILD_DIR:-"$PWD/build"}
root=${DESTDIR:-}
case "$#:${1:-}" in
    0:|1:--native) backend=native ;;
    1:--legacy) backend=legacy ;;
    *) echo "Usage: ./install.sh [--native|--legacy]" >&2; exit 2 ;;
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

if [ "$backend" = native ]; then
    unit=service/native/x1fold-fingerprint@.service
    set -- "$build_dir/native-worker"
else
    unit=service/x1fold-fingerprint@.service
    set -- "$build_dir/worker" service/worker.py vendor-host/console_session.py
fi
for input in "$@" "$build_dir/libx1fold-hid.so" service/x1fold-fingerprint.socket "$unit"; do
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

if [ -z "$root" ] && [ "$backend" = native ]; then
    for name in sensor.cert host.cert host-key.pem; do
        credential=/etc/credstore.encrypted/x1fold-native/$name.cred
        [ -s "$credential" ] || { echo "Missing encrypted native pairing credential: $credential" >&2; exit 1; }
    done
elif [ -z "$root" ]; then
    credential=/etc/credstore.encrypted/x1fold-fingerprint.cred
    if [ ! -e "$credential" ]; then
        if [ -e /var/lib/x1fold-fingerprint-worker/.lock ]; then
            echo "Worker state exists without its machine credential. Restore the existing credential." >&2
            exit 1
        fi
        (
            umask 077
            mkdir -p /etc/credstore.encrypted
            work=$(mktemp -d /etc/credstore.encrypted/.x1fold-XXXXXXXX)
            trap 'rm -f -- "$work/encrypted"; rmdir -- "$work"' EXIT
            head -c 32 /dev/urandom | systemd-creds encrypt --with-key=host --name=x1fold-dpapi - "$work/encrypted"
            # A concurrent installer may have already created the same target.
            ln "$work/encrypted" "$credential" || [ -f "$credential" ]
        )
    fi
fi

helper=/usr/local/libexec/x1fold-fingerprint
units=/etc/systemd/system
if [ "$backend" = native ]; then
    copy_file 0755 "$build_dir/native-worker" "$helper/native-worker"
else
    copy_file 0755 "$build_dir/worker" "$helper/worker"
    copy_file 0644 service/worker.py "$helper/worker.py"
    copy_file 0644 vendor-host/console_session.py "$helper/console_session.py"
fi
copy_file 0644 "$unit" "$units/x1fold-fingerprint@.service"
copy_file 0644 service/x1fold-fingerprint.socket "$units/x1fold-fingerprint.socket"
copy_file 0644 "$build_dir/libx1fold-hid.so" /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so

if [ -z "$root" ]; then
    systemctl daemon-reload
    systemctl enable --now x1fold-fingerprint.socket
    systemctl try-restart fprintd.service
fi
