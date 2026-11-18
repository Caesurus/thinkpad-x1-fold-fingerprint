# ThinkPad X1 Fold keyboard fingerprint reader for Linux

This driver lets KDE and `fprintd` enroll and verify fingers on the USB-connected detachable keyboard for the **ThinkPad X1 Fold 16 Gen 1**. The keyboard is USB `17ef:6142`. Its Synaptics fingerprint reader uses vendor HID interface 04. Lenovo also identifies its biometric child as `06cb:00dd`.

The tested system ran **Ubuntu 26.04.1 on x86-64**, Ubuntu's libfprint 1.95.1 TOD interface, and fprintd 1.94.5. On that system a right-index enrollment unlocked the KDE desktop twice. Password fallback also worked. Successive scans opened fresh workers using the same sensor pairing while the keyboard stayed connected.

Development of the independent Linux C backend is on the `native-backend` branch. `make native native-worker` builds its static library and experimental verification worker offline. The worker requires an existing pairing credential for the reader. Hardware acceptance is pending. The installed release uses the Lenovo worker for biometric operations. [Native implementation and verification status](docs/native-backend.md)

## Before building

The tested reader already had a working sensor pairing and firmware 10.1 build 3654703. Installation sets up the Linux authentication service. The test keyboard had undergone an earlier one-time provisioning step using Lenovo’s driver. Compatibility with an untouched or Windows-owned reader has not been established. This installer reuses a working pairing. Firmware flashing and partition formatting are unnecessary for this build. Keep access to your password and a Windows recovery option when experimenting with a differently provisioned reader.

Confirm the keyboard is connected over USB.

```sh
lsusb -d 17ef:6142
```

Install the build, test, and runtime dependencies on Ubuntu 26.04 amd64.

```sh
sudo apt install build-essential binutils git curl patch pkg-config innoextract python3 \
    libfprint-2-dev libfprint-2-tod-dev libgudev-1.0-dev libglib2.0-dev libgio-2.0-dev \
    libusb-1.0-0-dev libssl-dev umockdev python3-cryptography python3-gi gir1.2-umockdev-1.0 \
    gir1.2-fprint-2.0 fprintd libpam-fprintd
```

## Build

Run these commands from the root of this repository. The dependencies live under the Git-ignored `.deps/` directory. The builder extracts only the two required Windows DLLs into a temporary directory and checks the pinned revision, installer hash, and individual DLL hashes before linking.

```sh
mkdir -p .deps
git clone --no-checkout https://github.com/Popax21/synaTudor.git .deps/synaTudor
git -C .deps/synaTudor checkout --detach 31dfdb06107fd1c35c9f9ceae72617e98eccc43a
curl --fail --location --output .deps/n3lgf05w.exe https://download.lenovo.com/pccbbs/mobiles/n3lgf05w.exe
make
make check
```

For an offline build, supply a clean pinned source checkout and a previously downloaded installer with `make TUDOR=/path/to/synaTudor LENOVO=/path/to/n3lgf05w.exe`. The `LENOVO` argument also accepts a directory containing the two extracted DLLs. The build produces `build/libx1fold-hid.so` and `build/worker`. The worker embeds the proprietary DLLs for local use.

## Install and use

Finish any active fingerprint operation before installing. The installer copies the module and worker, creates the service's encrypted machine credential on first install, enables socket activation at boot, and reloads an active fprintd service. Reinstallation reuses the machine credential. KDE uses its existing fingerprint and password PAM services.

```sh
sudo ./install.sh
systemctl is-enabled x1fold-fingerprint.socket
fprintd-list "$USER"
```

If your preferred finger is already listed, go straight to verification. Otherwise enroll it once, lifting and replacing the same finger as prompted. KDE may request your password to authorize changes to enrollment.

```sh
fprintd-enroll -f right-index-finger
fprintd-verify -f right-index-finger
```

After `verify-match`, lock KDE in the usual way and touch the reader with that finger. Deletion, re-pairing, and power-cycling the keyboard are not part of normal unlock.

For a packaging check, stage the six runtime files under an empty directory without activating services or generating a credential.

```sh
stage=$(mktemp -d)
DESTDIR="$stage" ./install.sh
find "$stage" -type f
```

## How the pieces fit

| Component | Role |
| --- | --- |
| `libfprint/` | Native TOD module. It checks the USB interface and report descriptor, binds the print identity to the sensor serial and finger, and implements enrollment, verification, and individual deletion. |
| `service/` | Root-owned systemd socket, per-operation unprivileged worker service, and Python launcher. The system fingerprint daemon passes an open reader descriptor over the private socket. |
| `vendor-host/` | Worker build and Linux implementations of the Windows device, registry, and desktop-session interfaces used by Lenovo's WDF driver and WinBio adapter. |
| `vendor-compat/` | HID transport and compatibility patches for the pinned Windows runtime. |
| `vendor-protection/` | Implements the Windows protection and cryptography calls that the driver uses for Linux-side state. |

The sensor stores the biometric record. The fprintd enrollment identifies it by GUID, sensor serial, and finger. A successful verification requires a fresh WinBio match. Systemd supplies the worker with private state under `/var/lib/x1fold-fingerprint-worker` and a credential from `/etc/credstore.encrypted/x1fold-fingerprint.cred`. Both belong to the installed machine.

## Verification and limitations

Hardware testing covered enrollment, a correct-finger match, rejection of a different finger, removal of an individual print from both sensor and host, and KDE unlock with password fallback. Software recovery also reopened an abandoned sensor session while the keyboard stayed connected.

After a USB cable reconnect, fprintd recognized the reader and its saved enrollment. The subsequent scan timed out before a match was confirmed. Verification after suspend/resume and reboot is still outstanding. Canceling a capture can end a worker abnormally. A fresh worker recovered on the tested machine. For diagnostics, inspect `journalctl -b -u fprintd.service -u 'x1fold-fingerprint@*'`.

## Source provenance

The build uses Popax21's pinned synaTudor Windows runtime and Lenovo's N3LGF05W driver package. The supported files are `synaFpAdapter153.dll` and `synaWudfBioHid153.dll`. The exact SHA-256 values are in the worker builder. The upstream LGPL 2.1 license is in `LICENSES/`, and individual source files retain their SPDX notices. Lenovo supplies the proprietary components under its own terms. Publish the source tree and keep the installer, DLLs, linked worker, machine credentials, and enrollments local. [synaTudor source revision](https://github.com/Popax21/synaTudor/tree/31dfdb06107fd1c35c9f9ceae72617e98eccc43a) · [Lenovo package manifest](https://download.lenovo.com/pccbbs/mobiles/n3lgf05w_2_.xml)
