# Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make native driver installation reversible and document a truthful, copyable path for a Fold owner.

**Architecture:** Keep `install.sh` as the public entry point. Add a shell file-state helper for snapshot and restore, with a temporary-root test harness. Keep sensor and pairing credentials outside the install transaction.

**Tech Stack:** POSIX shell, systemd, Ubuntu 26.04 amd64, existing Makefile tests.

**Spec:** `docs/superpowers/specs/2026-11-19-release-hardening-design.md`

## Global Constraints

- Do not modify the sensor, its stored prints, or installed pairing credentials.
- Do not add Windows DLLs, a synaTudor dependency, or OEM private issuer material.
- Preserve the four-file `DESTDIR` staging contract.
- Keep the working native installation in place while developing and testing.

## Review Focus

- Existing destination symlink: snapshot and rollback must restore the link itself.
- Missing destination: rollback must remove the installed file.
- Corrupt or incomplete snapshot: refuse before changing installed files.
- Failed install: restore previous files and socket state.
- Repeated rollback: leave the machine in the same prior state.

---

### Task 1: Snapshot and restore installed files

**Files:** Create `scripts/install-state.sh`; create `tests/install-state.sh`; modify `Makefile`.

**Interfaces:** `install_state_snapshot ROOT BACKUP` and `install_state_restore ROOT BACKUP` operate on the fixed set of installed paths. They never touch pairing credentials.

- [ ] Write temporary-root tests for first install, existing files, absent files, symlink restoration, corrupt backup refusal, and repeat restore.
- [ ] Run `sh tests/install-state.sh` and observe failure because the helper is absent.
- [ ] Implement the smallest helper that passes the tests, using fixed paths, owner-only backup directory permissions, and prevalidation before restore.
- [ ] Run `sh tests/install-state.sh` and `make check`; both must pass.
- [ ] Commit the helper and tests.

### Task 2: Live backup and rollback entry point

**Files:** Modify `install.sh`; extend `tests/install-state.sh` and `tests/stage-install.sh` if needed.

**Interfaces:** `./install.sh` snapshots before the first write; `./install.sh --rollback` restores the last successful snapshot and prior socket state. `DESTDIR=... ./install.sh` still stages four files.

- [ ] Add tests using a temporary root and stubbed systemctl for successful install, rollback, activation failure, and repeat rollback; observe failure.
- [ ] Add the live transaction and rollback implementation. Do not read or rewrite the pairing drop-in or encrypted credentials.
- [ ] Run the focused tests and `make check`; both must pass.
- [ ] Commit the installer change.

### Task 3: User-facing setup and evidence

**Files:** Modify `README.md` and `docs/native-backend.md`; create `docs/install-and-recovery.md`.

**Interfaces:** A new owner can follow exact dependency, build, test, install, verify, rollback, and credential backup instructions, with the issuer prerequisite stated before installation.

- [ ] Correct stale branch, pairing-test and suspend/reboot statements.
- [ ] Document the supported platform, install and rollback commands, credential backup, and first-time pairing prerequisite without publishing private issuer material.
- [ ] Check commands against the code and run `git diff --check` plus `make check`.
- [ ] Commit documentation.

### Task 4: Final review

**Files:** Whole branch.

- [ ] Review the complete diff for credential exposure, accidental sensor writes, rollback integrity, and misleading setup claims.
- [ ] Run `make check`, focused shell tests, and staged install; record results.
- [ ] Prepare a pull request with the tested scope and the unresolved second-reader provisioning limitation.
