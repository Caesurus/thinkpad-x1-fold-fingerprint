#!/bin/sh
# Sourced by install.sh. Snapshot only the files that its live path changes.

install_state_paths() {
    cat <<'EOF'
/usr/local/libexec/x1fold-fingerprint/native-worker
/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so
/etc/systemd/system/x1fold-fingerprint.socket
/etc/systemd/system/x1fold-fingerprint@.service
/usr/local/libexec/x1fold-fingerprint/worker
/usr/local/libexec/x1fold-fingerprint/worker.py
/usr/local/libexec/x1fold-fingerprint/console_session.py
EOF
}

install_state_snapshot() {
    snapshot_root=$1 snapshot_dir=$2
    (umask 077; mkdir -m 700 -- "$snapshot_dir") || return 1
    snapshot_index=0
    while IFS= read -r snapshot_path; do
        snapshot_index=$((snapshot_index + 1))
        snapshot_source=$snapshot_root$snapshot_path
        if [ -d "$snapshot_source" ] && [ ! -L "$snapshot_source" ]; then
            echo "Installation destination is a directory: $snapshot_path" >&2
            return 1
        fi
        if [ -e "$snapshot_source" ] || [ -L "$snapshot_source" ]; then
            if [ ! -f "$snapshot_source" ] && [ ! -L "$snapshot_source" ]; then
                echo "Installation destination is not a regular file or symlink: $snapshot_path" >&2
                return 1
            fi
            cp -a -- "$snapshot_source" "$snapshot_dir/$snapshot_index.entry" || return 1
            : > "$snapshot_dir/$snapshot_index.present" || return 1
        else
            : > "$snapshot_dir/$snapshot_index.absent" || return 1
        fi
    done <<EOF
$(install_state_paths)
EOF
}

install_state_validate() {
    restore_root=$1 restore_dir=$2
    [ -d "$restore_dir" ] && [ ! -L "$restore_dir" ] || return 1
    restore_index=0
    # Validate the whole snapshot and destination set before changing any file.
    while IFS= read -r restore_path; do
        restore_index=$((restore_index + 1))
        restore_dest=$restore_root$restore_path
        if [ -d "$restore_dest" ] && [ ! -L "$restore_dest" ]; then
            echo "Installation destination is a directory: $restore_path" >&2
            return 1
        fi
        if [ -f "$restore_dir/$restore_index.present" ]; then
            [ ! -e "$restore_dir/$restore_index.absent" ] || return 1
            [ -f "$restore_dir/$restore_index.entry" ] ||
                [ -L "$restore_dir/$restore_index.entry" ] || return 1
        elif [ -f "$restore_dir/$restore_index.absent" ]; then
            [ ! -e "$restore_dir/$restore_index.entry" ] || return 1
        else
            echo "Incomplete installation snapshot: $restore_index" >&2
            return 1
        fi
    done <<EOF
$(install_state_paths)
EOF
}

install_state_restore() {
    install_state_validate "$1" "$2" || return 1
    restore_root=$1 restore_dir=$2

    restore_index=0
    while IFS= read -r restore_path; do
        restore_index=$((restore_index + 1))
        restore_dest=$restore_root$restore_path
        if [ -f "$restore_dir/$restore_index.absent" ]; then
            rm -f -- "$restore_dest" || return 1
        else
            mkdir -p -- "$(dirname "$restore_dest")" || return 1
            restore_temp=$(mktemp "$restore_dest.XXXXXXXX") || return 1
            rm -- "$restore_temp" || return 1
            if ! cp -a -- "$restore_dir/$restore_index.entry" "$restore_temp" ||
               ! mv -Tf -- "$restore_temp" "$restore_dest"; then
                rm -f -- "$restore_temp"
                return 1
            fi
        fi
    done <<EOF
$(install_state_paths)
EOF
}
