"""Expose the local desktop's Win64 WTSINFOEXW snapshot to an isolated worker."""
import contextlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time


def bus_call(*args):
    command = ["/usr/bin/busctl", "--system", "--json=short", *args]
    output = subprocess.check_output(command, timeout=2, stderr=subprocess.DEVNULL)
    return json.loads(output)["data"]


def active_session():
    return bus_call("get-property", "org.freedesktop.login1",
                    "/org/freedesktop/login1/seat/seat0", "org.freedesktop.login1.Seat",
                    "ActiveSession")


def snapshot(*, system_worker=False):
    session, path = active_session()
    if not session:
        return b""
    properties, = bus_call("call", "org.freedesktop.login1", path,
                           "org.freedesktop.DBus.Properties", "GetAll", "s",
                           "org.freedesktop.login1.Session")
    fields = {key: prop["data"] for key, prop in properties.items()}
    if (fields["Seat"][0] != "seat0" or fields["Remote"] or not fields["Active"]
            or (not system_worker and fields["User"][0] != os.getuid()) or not fields["VTNr"]
            or active_session() != [session, path]):
        return b""
    # Use the active VT as the guest console identifier. The response contains
    # only fields for this local console. There are no RDP counters or domain.
    result = bytearray(232)
    struct.pack_into("<I4xIII", result, 0, 1, fields["VTNr"], 0, int(not fields["LockedHint"]))
    for start, limit, value in ((20, 32, "seat0"), (86, 20, fields["Name"])):
        encoded = value.encode("utf-16-le")[:2 * limit]
        encoded = encoded.decode("utf-16-le", errors="ignore").encode("utf-16-le")
        result[start:start + len(encoded)] = encoded
    def filetime(usec):
        return (usec + 11644473600000000) * 10 if usec else 0
    login = filetime(fields["Timestamp"])
    struct.pack_into("<5Q", result, 168, login, login, 0, 0, filetime(time.time_ns() // 1000))
    return bytes(result)


@contextlib.contextmanager
def console_socket(directory, *, system_worker=False):
    """Serve one read-only session snapshot per connection in a private directory."""
    path = Path(directory, "console.sock")
    stop = threading.Event()
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(4)
        listener.settimeout(0.2)
        def serve():
            while not stop.is_set():
                try:
                    peer, _ = listener.accept()
                except TimeoutError:
                    continue
                with peer:
                    try:
                        peer.send(snapshot(system_worker=system_worker))
                    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                        pass
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield path
        finally:
            stop.set()
            thread.join()
