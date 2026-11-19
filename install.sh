#!/bin/sh
# Stage with DESTDIR, or install and activate on the tested Ubuntu amd64 layout.
set -eu
cd "$(dirname "$0")"
. ./scripts/install-state.sh
build_dir=${BUILD_DIR:-"$PWD/build"}
root=${DESTDIR:-}
case "$#:${1:-}" in
    0:|1:--native) action=install ;;
    1:--rollback) action=rollback ;;
    *) echo "Usage: ./install.sh [--native|--rollback]" >&2; exit 2 ;;
esac
if [ "$action" = rollback ] && [ -n "$root" ]; then
    echo 'DESTDIR cannot be used with --rollback' >&2
    exit 2
fi
if [ -n "$root" ]; then
    case "$root" in /*) ;; *) echo "DESTDIR must be absolute" >&2; exit 2 ;; esac
    mkdir -p "$root"
    root=$(realpath "$root")
    [ "$root" != / ] || { echo "Choose an empty staging directory, or unset DESTDIR for a live install" >&2; exit 2; }
elif [ "${X1FOLD_TEST_MODE:-}" = 1 ] && [ -n "${X1FOLD_TEST_ROOT:-}" ]; then
    case $X1FOLD_TEST_ROOT in /*) ;; *) echo 'Test root must be absolute' >&2; exit 2 ;; esac
    root=$(realpath "$X1FOLD_TEST_ROOT")
    [ "$root" != / ] || { echo 'Test root cannot be /' >&2; exit 2; }
else
    [ "$(id -u)" -eq 0 ] || { echo "Use sudo for a live install" >&2; exit 1; }
    [ "$(dpkg --print-architecture)" = amd64 ] || { echo "Ubuntu amd64 required" >&2; exit 1; }
fi

state_base=$root/var/lib/x1fold-fingerprint/install-backups

restore_snapshot() {
    saved=$1
    [ -d "$saved/files" ] || { echo 'Incomplete installation backup' >&2; return 1; }
    prior_enabled=$(cat "$saved/socket-enabled") || return 1
    prior_active=$(cat "$saved/socket-active") || return 1
    case $prior_enabled:$prior_active in
        0:0|0:1|1:0|1:1) ;;
        *) echo 'Invalid socket state in installation backup' >&2; return 1 ;;
    esac
    install_state_restore "$root" "$saved/files" || return 1
    systemctl daemon-reload || return 1
    if [ "$prior_enabled" = 1 ]; then
        systemctl enable x1fold-fingerprint.socket || return 1
    else
        systemctl disable x1fold-fingerprint.socket || return 1
    fi
    if [ "$prior_active" = 1 ]; then
        systemctl start x1fold-fingerprint.socket || return 1
    else
        systemctl stop x1fold-fingerprint.socket || return 1
    fi
    systemctl try-restart fprintd.service
}

if [ "$action" = rollback ]; then
    [ -L "$state_base/latest" ] || { echo 'No completed installation backup exists' >&2; exit 1; }
    saved_name=$(readlink "$state_base/latest")
    case $saved_name in
        install.*) ;;
        *) echo 'Invalid installation backup pointer' >&2; exit 1 ;;
    esac
    case $saved_name in
        */*|'') echo 'Invalid installation backup pointer' >&2; exit 1 ;;
    esac
    restore_snapshot "$state_base/$saved_name"
    echo 'Previous driver files and socket state restored; pairing credentials were not changed.'
    exit 0
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

publish_backup() (
    pointer=$(mktemp "$state_base/.latest.XXXXXXXX") || exit 1
    trap 'rm -f -- "$pointer"' EXIT
    rm -- "$pointer" || exit 1
    ln -s "$(basename "$backup")" "$pointer" || exit 1
    mv -Tf -- "$pointer" "$state_base/latest"
)

helper=/usr/local/libexec/x1fold-fingerprint
units=/etc/systemd/system
if [ -n "${DESTDIR:-}" ]; then
    copy_file 0755 "$build_dir/native-worker" "$helper/native-worker"
    copy_file 0644 "$unit" "$units/x1fold-fingerprint@.service"
    copy_file 0644 service/x1fold-fingerprint.socket "$units/x1fold-fingerprint.socket"
    copy_file 0644 "$build_dir/libx1fold-hid.so" /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so
    exit 0
fi

umask 077
install -d -m 0700 -- "$state_base"
backup=$(mktemp -d "$state_base/install.XXXXXXXX")
if systemctl is-enabled x1fold-fingerprint.socket >/dev/null 2>&1; then
    echo 1 > "$backup/socket-enabled"
else
    echo 0 > "$backup/socket-enabled"
fi
if systemctl is-active x1fold-fingerprint.socket >/dev/null 2>&1; then
    echo 1 > "$backup/socket-active"
else
    echo 0 > "$backup/socket-active"
fi
install_state_snapshot "$root" "$backup/files"

if copy_file 0755 "$build_dir/native-worker" "$helper/native-worker" &&
   copy_file 0644 "$unit" "$units/x1fold-fingerprint@.service" &&
   copy_file 0644 service/x1fold-fingerprint.socket "$units/x1fold-fingerprint.socket" &&
   copy_file 0644 "$build_dir/libx1fold-hid.so" /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so &&
   systemctl daemon-reload &&
   systemctl enable --now x1fold-fingerprint.socket &&
   systemctl try-restart fprintd.service &&
   rm -f -- "$helper/worker" "$helper/worker.py" "$helper/console_session.py" &&
   publish_backup; then
    echo "Installed native driver. Restore the previous files with: sudo ./install.sh --rollback"
else
    echo 'Installation failed; restoring previous files and socket state.' >&2
    if restore_snapshot "$backup"; then
        rm -rf -- "$backup"
    else
        echo "Automatic restoration failed; backup retained at $backup" >&2
    fi
    exit 1
fi
