# Install and recover the native Fold driver

This guide covers the tested ThinkPad X1 Fold 16 Gen 1 keyboard (`17ef:6142`, fingerprint HID interface 04) on Ubuntu 26.04 amd64. Installation replaces a local libfprint TOD module and installs a systemd socket and worker. The separate first-time pairing command below resets sensor storage when explicitly requested.

## Pairing credentials

The Fold v153 issuer derivation context is included in the native source. Each first-time setup creates a new host P-256 key and obtains two reader certificates. The installed service needs these three credentials to authenticate scans. Keep password unlock available until pairing and enrollment have been verified.

| Systemd credential name | Required value |
| --- | --- |
| `x1fold-native.sensor.cert` | Reader's signed 400-byte certificate |
| `x1fold-native.host.cert` | Host's 400-byte returned certificate |
| `x1fold-native.host-key.pem` | Matching host P-256 private key |

The built-in issuer is selected with `fold-v153:`. Its context is fixed across installations; formatting does not make a newly generated issuer trusted by this firmware. The native tool also accepts an OpenSSL issuer URI or a separately signed request. None of these paths executes Windows code. The built-in path was accepted on the tested Fold, while first-time provisioning on a second physical unit remains untested. See [pairing credentials and the hardware test](native-backend.md#pairing-credentials-and-the-hardware-test).

## Build and test

On the tested Ubuntu release, install the build and test packages:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends \
  build-essential pkg-config libfprint-2-tod-dev libfprint-2-dev \
  libgudev-1.0-dev libglib2.0-dev libssl-dev umockdev \
  gir1.2-umockdev-1.0 gir1.2-fprint-2.0 \
  python3-cryptography python3-gi
make
make check
```

The build and tests run without the reader. The installer checks for `build/native-worker` and `build/libx1fold-hid.so` before changing system files. For a harmless preview, run:

```sh
stage=$(mktemp -d)
DESTDIR="$stage" ./install.sh
find "$stage" -type f
```

## First-time pairing

Use this only when Linux has no usable pairing. `reset-register` formats SSFS and HOST, removing the existing pairing and enrolled fingerprints, including Windows Hello. The steps create a new host key and save the reader's response in a private directory. The tool refuses the wrong USB identity, serial, firmware profile, or an active session. Connect the keyboard by USB and complete the build above first.

```sh
umask 077
state="${XDG_STATE_HOME:-$HOME/.local/state}/x1fold-fingerprint"
mkdir -p -m 0700 "$state"
test ! -e "$state/host-key.pem" && test ! -e "$state/pair-response.bin"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
  -out "$state/host-key.pem"
sudo systemctl stop fprintd.service
serial=$(sudo scripts/reader-fds.sh auto - ./build/native-inspect --serial)
sudo scripts/reader-fds.sh auto "$state/host-key.pem" ./build/native-register \
  reset-register "$serial" fold-v153: "$state/pair-response.bin" --erase-enrollments
```

If registration fails, run `sudo systemctl start fprintd.service` and preserve the key, result file and error output for diagnosis. An `ffff` result marks an incomplete attempt; it cannot be used as a credential. Repeating setup requires a new output path and a check of the reader's current state.

On success, read the firmware security flags with `sudo scripts/reader-fds.sh auto - ./build/native-inspect`; the tested Fold reported `a10b`. In an administrative shell from the repository root, set `state` to the same absolute directory created above, then install the encrypted credentials:

```sh
umask 077
state=/home/USERNAME/.local/state/x1fold-fingerprint
dir=/etc/systemd/system/x1fold-fingerprint@.service.d
install -d -m 0700 "$dir"
config=$(mktemp "$dir/.pairing-XXXXXXXX")
./build/native-register service-config a10b "$state/pair-response.bin" \
  4<"$state/host-key.pem" >"$config"
mv -T -- "$config" "$dir/50-pairing.conf"
systemctl daemon-reload
systemctl start fprintd.service
```

Replace `USERNAME` and `a10b` with this installation's values. Run `sudo ./install.sh` if the driver is not installed, then use `fprintd-enroll -f right-index-finger` and `fprintd-verify -f right-index-finger`. Keep a protected backup of the original key and response for OS recovery. The native request paired the tested Fold and reconnected successfully; the exact reset-and-register command has passed a software-reader test but has not yet provisioned a second physical Fold.

## Install and verify

```sh
sudo ./install.sh
systemctl is-enabled x1fold-fingerprint.socket
systemctl is-active x1fold-fingerprint.socket
fprintd-list "$USER"
```

The installer takes a root-only snapshot under `/var/lib/x1fold-fingerprint/install-backups/` before changing its four runtime files or removing retired launchers. It records the socket's prior enabled and active state. If activation fails, it attempts to restore those files and states; if restoration also fails, it reports the retained snapshot path for recovery. The successful snapshot is selected by `latest`. The installer does not back up, replace or remove the pairing drop-in, encrypted credentials, PAM configuration, or on-sensor enrollments.

If `fprintd-list` shows an enrolled finger, verify it with `fprintd-verify -f right-index-finger` (replace the finger name as needed). Touch the reader after the command reports that verification started. A successful scan prints `verify-match`. To test KDE, lock the desktop only after password unlock is available, then use the enrolled finger.

## Roll back an installation

```sh
sudo ./install.sh --rollback
```

This restores the files and socket state from the most recent successful install. It can be run again without changing the result. If this was the first installation, rollback removes the newly installed module, worker and units. It does not undo sensor enrollment or pairing. Keep this repository checkout until you are satisfied that the upgrade works, because the rollback command is in `install.sh`.

On the tested Fold, a live install followed by `--rollback` completed successfully. The original worker hash matched after rollback, the socket was still enabled and active, and fprintd still listed the right index. This tests the upgrade-and-restore path on one already-paired machine; the temporary-root suite covers the first-install case without changing a reader.

## Preserve pairing for recovery

The installer preserves installed pairing credentials but does not make a portable backup of them. Before replacing the OS, save the original host private key and accepted 802-byte registration response in a protected, encrypted backup. They are needed to regenerate the machine-encrypted service configuration using `native-register service-config`. Never commit the owner key or pairing response to Git. The fixed issuer context is already in this repository's native source.

For recovery on the **same OS installation**, also copy the service's encrypted drop-ins into a root-only backup:

```sh
sudo install -d -m 0700 /root/fold-pairing-backup
sudo cp -a /etc/systemd/system/x1fold-fingerprint@.service.d /root/fold-pairing-backup/
```

If this installation uses named files in `/etc/credstore.encrypted/`, copy the three `x1fold-native.*` files as well. Store the backup on protected media. The installer does not modify either location. The encrypted drop-in by itself is not a portable substitute for the original host key and response: `native-register service-config` encrypts with systemd's host key, which can change on a new OS installation. See the [systemd-creds manual](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html) for host-bound credential behavior.

If verification fails, check `journalctl -b -u fprintd.service -u 'x1fold-fingerprint@*.service' --no-pager -n 100`. A missing credential and a missed 30-second touch window have different causes; do not reset the reader as a first troubleshooting step.
