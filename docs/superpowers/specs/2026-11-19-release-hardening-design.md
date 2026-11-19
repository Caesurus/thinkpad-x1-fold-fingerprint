# Release hardening design

## Intent

Make the native Fold driver safe to try on the tested Ubuntu 26.04 amd64 system and make its limits clear to a new user. The driver already performs enrollment and KDE unlock on one paired Fold after USB reconnect, suspend and reboot. Installation should be reversible without touching the sensor's stored prints or the Linux pairing credentials.

## Goals and constraints

- Provide a copyable build, test, install, verify and rollback path for the tested platform.
- Preserve the files that a live install replaces or removes, including retired worker launchers, and restore their prior presence, content and mode on rollback.
- Restore the previous socket enabled and active state on rollback. A failed installation should restore the prior files and service state automatically.
- Keep saved pairing credentials and sensor storage untouched by install and rollback. Document a separate root-only backup of the pairing drop-in and encrypted credentials for machine recovery.
- Exercise install and rollback file handling without root or a physical reader. Keep the existing four-file `DESTDIR` staging contract.
- Correct stale branch and hardware-test statements in the existing documentation.
- State that first-time pairing on another reader needs an issuer profile accepted by that reader. The private Fold profile and Windows binaries remain outside the repository and installed runtime.

This change does not format reader partitions, reset ownership, flash firmware, or promise provisioning on an untested second reader. It does not publish OEM signing material.

## Approach

The live installer creates a root-only snapshot in `/var/lib/x1fold-fingerprint/install-backups/` before replacing files. It records whether each managed file existed and the socket's enabled and active state. The snapshot is committed as `latest` only after successful activation. `sudo ./install.sh --rollback` restores that snapshot; a failed install restores it automatically. A small file-state helper takes an explicit root path so tests can run against a temporary tree. `DESTDIR` continues to stage only the four runtime files.

Alternatives considered: manual backup instructions alone leave upgrade failures partly installed; a distribution package would be a useful later delivery format but would add packaging and compatibility work before this installation path is proven.

## Acceptance

Temporary-tree tests cover first install, replacement of prior files, rollback to both present and absent states, symlinks, corrupt snapshots, and a failed copy. The existing `make check` suite remains green. The documentation names the tested hardware and OS, gives exact install and rollback commands, and describes the provisioning limit before any command that changes the machine.
