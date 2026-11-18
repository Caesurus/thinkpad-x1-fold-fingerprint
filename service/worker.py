"""Prepare read-only platform metadata and supervise one systemd-activated worker."""
import os
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_session import console_socket


def main():
    if os.geteuid() == 0:
        raise SystemExit("A dedicated unprivileged worker account is required")
    creds = Path(os.environ["CREDENTIALS_DIRECTORY"])
    entry = (creds / "smbios-entry").read_bytes()
    table = (creds / "smbios-table").read_bytes()
    if (len(entry) != 24 or entry[:5] != b"_SM3_" or entry[6] != len(entry)
            or sum(entry) % 256 or not 0 < len(table) <= min(1024 * 1024, int.from_bytes(entry[12:16], "little"))):
        raise SystemExit("Invalid SMBIOS 3 metadata")
    with TemporaryDirectory(dir=os.environ["RUNTIME_DIRECTORY"]) as work, console_socket(work, system_worker=True) as console:
        path = Path(work, "rsmb")
        path.write_bytes(struct.pack("<BBBBI", 0, *entry[7:10], len(table)) + table)
        path.chmod(0o400)
        env = dict(os.environ, FOLD_PLATFORM_DIRECTORY=work, FOLD_WTS_SOCKET=str(console),
                   FOLD_PROVIDER_STATE=str(Path(os.environ["STATE_DIRECTORY"]).resolve()))
        return subprocess.run([Path(__file__).with_name("worker")], env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
