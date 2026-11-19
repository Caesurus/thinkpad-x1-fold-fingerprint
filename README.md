# ThinkPad X1 Fold keyboard fingerprint reader for Linux

This driver lets KDE and `fprintd` enroll and verify fingers on the USB-connected detachable keyboard for the **ThinkPad X1 Fold 16 Gen 1**. The keyboard is USB `17ef:6142`. Its Synaptics fingerprint reader uses vendor HID interface 04. Lenovo also identifies its biometric child as `06cb:00dd`.

The tested system ran **Ubuntu 26.04.1 on x86-64**, Ubuntu's libfprint 1.95.1 TOD interface, and fprintd 1.94.5.

The default build on `native-backend` produces a native Linux worker and libfprint plugin. On the physical Fold, this worker enrolled the right index, matched it, rejected a right-middle touch, recovered from cancellation without a keyboard reset, enrolled and deleted a temporary right-middle print, and matched the right index afterward. The owner confirmed a right-index KDE unlock. [Architecture diagrams and verification status](docs/native-backend.md)

## Native build and staged installation

On Ubuntu amd64 the build uses a C toolchain, pkg-config, Linux HID headers, OpenSSL 3, GLib/GIO, libgudev and the libfprint TOD development packages. The tests also use Python cryptography, PyGObject and umockdev. Run from the repository root with those dependencies installed.

```sh
make
make check
stage=$(mktemp -d)
DESTDIR="$stage" ./install.sh
```

To compare the native code directly with the extracted vendor DLLs without a reader, run `make check-dll DLL_DIR='/path/to/extracted/package'`. [Test dependencies and coverage](docs/native-backend.md#offline-dll-differential-tests)

The stage contains the TOD plugin, the native worker, the systemd socket and its service template. The static library is linked into the worker. These commands build and stage offline. A staged installation does not contact systemd or the keyboard.

To activate the native backend on the target machine, run `sudo ./install.sh`. It replaces the installed libfprint module and service, reloads systemd, and retires any legacy worker and Python launchers. It leaves PAM, fingerprint enrollments and credential stores in place. A desktop with password unlock can run this backend before the pairing credentials are available. Fingerprint operations then return an error until a usable pairing is present.

For fingerprint operations systemd loads these three credentials from the system credential store. Use the same name for the encrypted file and its bound credential name under `/etc/credstore.encrypted/`.

| Credential name | Contents |
| --- | --- |
| `x1fold-native.sensor.cert` | Reader's 400-byte signed sensor certificate |
| `x1fold-native.host.cert` | Reader's 400-byte returned host certificate |
| `x1fold-native.host-key.pem` | Corresponding host P-256 private key in PEM format |

For a completed native registration, `native-register service-config` converts the saved response and matching owner key into a single encrypted systemd drop-in for these three credentials. [Installing a completed native pairing](docs/native-backend.md#installing-a-completed-native-pairing)

The optional `make native-register` tool constructs and signs the host request locally through OpenSSL. It can also send a registration to an explicitly selected reader. On November 19, 2026, this Fold accepted a native request signed through the locally reconstructed Fold issuer path. The saved certificates and host key opened authenticated native sessions before and after a physical USB reconnect. The issuer profile is kept outside this repository, so this result does not yet provide a distributable setup procedure for other readers. The installed native service uses encrypted credentials, and right-index enrollment and KDE unlock have now passed on this Fold. [Pairing implementation and evidence](docs/native-backend.md#pairing-credentials-and-the-hardware-test)

## Components

| Path | Purpose |
| --- | --- |
| `libfprint/` | Native TOD plugin that discovers the reader and connects fprintd to the worker. |
| `native/` | Linux HID transport, pairing, encrypted session, capture, enrollment, verification, and deletion code. |
| `service/native/` | Per-operation systemd worker service. |
| `tests/` | DLL comparison and installation tests. |

The normal build and installed runtime use Linux ELF files and this repository's C sources. They do not load Windows DLLs or fetch synaTudor. The optional `make check-dll` target uses locally supplied DLLs as offline test inputs; they are not included in the repository or installed runtime. The LGPL 2.1 license is in `LICENSES/`, and source files retain their SPDX notices.

The local issuer profile used to pair this Fold is not distributed, so this repository does not yet provide a complete first-time provisioning procedure for other readers. Firmware update and recovery are separate maintenance work. [Hardware results and protocol analysis](docs/native-backend.md)
