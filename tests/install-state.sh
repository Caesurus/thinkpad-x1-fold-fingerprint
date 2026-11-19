#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/install-state.sh

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
root=$scratch/root
backup=$scratch/backup
mkdir -p "$root"

fail() { echo "install-state test: $*" >&2; exit 1; }
worker=$root/usr/local/libexec/x1fold-fingerprint/native-worker
plugin=$root/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so
legacy=$root/usr/local/libexec/x1fold-fingerprint/worker

# An initial install has no prior files. Rollback removes every managed file.
install_state_snapshot "$root" "$backup"
while IFS= read -r path; do
    dest=$root$path
    mkdir -p "$(dirname "$dest")"
    printf 'new\n' > "$dest"
done <<EOF
$(install_state_paths)
EOF
install_state_restore "$root" "$backup"
while IFS= read -r path; do
    test ! -e "$root$path" || fail "did not remove $path"
done <<EOF
$(install_state_paths)
EOF
install_state_restore "$root" "$backup"

# Preserve prior contents, mode and a legacy symlink through replacement.
rm -rf -- "$backup"
mkdir -p "$(dirname "$worker")" "$(dirname "$plugin")"
printf 'old worker\n' > "$worker"
chmod 0700 "$worker"
printf 'old plugin\n' > "$plugin"
ln -s native-worker "$legacy"
install_state_snapshot "$root" "$backup"
printf 'new worker\n' > "$worker"
chmod 0755 "$worker"
printf 'new plugin\n' > "$plugin"
rm -- "$legacy"
install_state_restore "$root" "$backup"
test "$(cat "$worker")" = 'old worker' || fail 'worker content changed'
test "$(stat -c %a "$worker")" = 700 || fail 'worker mode changed'
test "$(cat "$plugin")" = 'old plugin' || fail 'plugin content changed'
test "$(readlink "$legacy")" = native-worker || fail 'legacy link changed'
install_state_restore "$root" "$backup"

# A malformed backup must be rejected before any destination changes.
printf 'current worker\n' > "$worker"
rm -- "$backup/2.present"
if install_state_restore "$root" "$backup" 2>/dev/null; then
    fail 'accepted incomplete snapshot'
fi
test "$(cat "$worker")" = 'current worker' || fail 'partial restore on invalid snapshot'

echo 'Install snapshot and restore tests passed'
