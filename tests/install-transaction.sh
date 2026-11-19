#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test "$(id -u)" -ne 0 || { echo 'Run installer transaction tests unprivileged' >&2; exit 1; }
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
root=$scratch/root
state=$scratch/state
stub=$scratch/stub
mkdir -p "$root" "$state" "$stub"

cat > "$stub/systemctl" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$TEST_STATE_DIR/calls"
case $1 in
    is-enabled) cat "$TEST_STATE_DIR/enabled"; test "$(cat "$TEST_STATE_DIR/enabled")" = enabled ;;
    is-active) cat "$TEST_STATE_DIR/active"; test "$(cat "$TEST_STATE_DIR/active")" = active ;;
    enable) echo enabled > "$TEST_STATE_DIR/enabled"; test "${2:-}" != --now || echo active > "$TEST_STATE_DIR/active" ;;
    disable)
        test -e "$TEST_INSTALL_ROOT/etc/systemd/system/x1fold-fingerprint.socket" || exit 1
        echo disabled > "$TEST_STATE_DIR/enabled" ;;
    start) echo active > "$TEST_STATE_DIR/active" ;;
    stop)
        test -e "$TEST_INSTALL_ROOT/etc/systemd/system/x1fold-fingerprint.socket" || exit 1
        echo inactive > "$TEST_STATE_DIR/active" ;;
    daemon-reload) : ;;
    try-restart)
        if test -f "$TEST_STATE_DIR/fail-once"; then
            rm "$TEST_STATE_DIR/fail-once"
            exit 1
        fi ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$stub/systemctl"
echo disabled > "$state/enabled"
echo inactive > "$state/active"

worker=$root/usr/local/libexec/x1fold-fingerprint/native-worker
plugin=$root/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libx1fold-hid.so
credential=$root/etc/systemd/system/x1fold-fingerprint@.service.d/50-pairing.conf
mkdir -p "$(dirname "$worker")" "$(dirname "$plugin")" "$(dirname "$credential")"
printf 'previous worker\n' > "$worker"
printf 'previous plugin\n' > "$plugin"
printf 'encrypted pairing remains\n' > "$credential"

install_test() {
    TEST_STATE_DIR="$state" TEST_INSTALL_ROOT="$root" \
        X1FOLD_TEST_MODE=1 X1FOLD_TEST_ROOT="$root" \
        BUILD_DIR="$PWD/build" PATH="$stub:$PATH" ./install.sh "$@"
}
fail() { echo "install transaction test: $*" >&2; exit 1; }

install_test
test -L "$root/var/lib/x1fold-fingerprint/install-backups/latest" || fail 'no rollback pointer'
cmp "$worker" build/native-worker || fail 'worker was not installed'
cmp "$plugin" build/libx1fold-hid.so || fail 'plugin was not installed'
test "$(cat "$state/enabled")" = enabled || fail 'socket not enabled'
test "$(cat "$state/active")" = active || fail 'socket not active'
test "$(cat "$credential")" = 'encrypted pairing remains' || fail 'pairing changed'

backup_dir=$root/var/lib/x1fold-fingerprint/install-backups
snapshot=$backup_dir/$(readlink "$backup_dir/latest")
mv "$snapshot/files/1.present" "$snapshot/files/1.saved"
if install_test --rollback > "$scratch/corrupt-output" 2>&1; then
    fail 'rollback accepted incomplete snapshot'
fi
cmp "$worker" build/native-worker || fail 'corrupt rollback changed worker'
test "$(cat "$state/enabled")" = enabled || fail 'corrupt rollback disabled socket'
test "$(cat "$state/active")" = active || fail 'corrupt rollback stopped socket'
mv "$snapshot/files/1.saved" "$snapshot/files/1.present"

install_test --rollback
test "$(cat "$worker")" = 'previous worker' || fail 'worker not restored'
test "$(cat "$plugin")" = 'previous plugin' || fail 'plugin not restored'
test "$(cat "$state/enabled")" = disabled || fail 'socket enabled after rollback'
test "$(cat "$state/active")" = inactive || fail 'socket active after rollback'
test "$(cat "$credential")" = 'encrypted pairing remains' || fail 'pairing changed on rollback'
install_test --rollback

# A failed activation must undo the copied files and socket state.
touch "$state/fail-once"
if install_test > "$scratch/failed-output" 2>&1; then
    fail 'installation ignored activation failure'
fi
test "$(cat "$worker")" = 'previous worker' || fail 'worker left replaced after failure'
test "$(cat "$plugin")" = 'previous plugin' || fail 'plugin left replaced after failure'
test "$(cat "$state/enabled")" = disabled || fail 'socket enabled after failure'
test "$(cat "$state/active")" = inactive || fail 'socket active after failure'
test "$(cat "$credential")" = 'encrypted pairing remains' || fail 'pairing changed on failure'

# Publishing the rollback pointer is part of the transaction too.
rm "$root/var/lib/x1fold-fingerprint/install-backups/latest"
mkdir "$root/var/lib/x1fold-fingerprint/install-backups/latest"
if install_test > "$scratch/pointer-output" 2>&1; then
    fail 'installation ignored rollback-pointer failure'
fi
test "$(cat "$worker")" = 'previous worker' || fail 'worker left replaced after pointer failure'
test "$(cat "$plugin")" = 'previous plugin' || fail 'plugin left replaced after pointer failure'
test "$(cat "$state/enabled")" = disabled || fail 'socket enabled after pointer failure'
test "$(cat "$state/active")" = inactive || fail 'socket active after pointer failure'

# An upgrade over an already enabled service must restore that service.
rmdir "$root/var/lib/x1fold-fingerprint/install-backups/latest"
unit=$root/etc/systemd/system/x1fold-fingerprint.socket
printf 'previous socket\n' > "$unit"
echo enabled > "$state/enabled"
echo active > "$state/active"
install_test
install_test --rollback
test "$(cat "$unit")" = 'previous socket' || fail 'existing unit not restored'
test "$(cat "$state/enabled")" = enabled || fail 'existing socket disabled by rollback'
test "$(cat "$state/active")" = active || fail 'existing socket stopped by rollback'

# A late file-copy failure also restores the earlier files and service state.
cat > "$stub/install" <<'EOF'
#!/bin/sh
set -eu
case "$*" in
    *libx1fold-hid.so*)
        if test -f "$TEST_STATE_DIR/fail-copy-once"; then
            rm "$TEST_STATE_DIR/fail-copy-once"
            exit 1
        fi ;;
esac
exec /usr/bin/install "$@"
EOF
chmod +x "$stub/install"
touch "$state/fail-copy-once"
if install_test > "$scratch/copy-output" 2>&1; then
    fail 'installation ignored file-copy failure'
fi
test "$(cat "$worker")" = 'previous worker' || fail 'worker left replaced after copy failure'
test "$(cat "$plugin")" = 'previous plugin' || fail 'plugin left replaced after copy failure'
test "$(cat "$unit")" = 'previous socket' || fail 'unit left replaced after copy failure'
test "$(cat "$state/enabled")" = enabled || fail 'socket disabled after copy failure'
test "$(cat "$state/active")" = active || fail 'socket stopped after copy failure'

echo 'Installer transaction and rollback tests passed'
