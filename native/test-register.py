# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check the administrative CLI offline with two ephemeral test keys."""
import os
import hashlib
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def save_key(path, key):
    with path.open("xb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))


def run_request(program, host_file, issuer_file, dest):
    return subprocess.run(
        ["sh", "-c", 'exec 4<"$1"; exec "$2" request "$3" "$4"',
         "test-register", host_file, program, issuer_file.as_uri(), dest], capture_output=True)


def check_service_config(program, folder, host_file, body, sensor_file):
    result = folder / "response"

    def config(data):
        result.write_bytes(data)
        return subprocess.run(
            ["sh", "-c", 'exec 4<"$1"; exec "$2" service-config a10b "$3" --user',
             "test-register", host_file, program, result], capture_output=True)

    pending = config(bytes.fromhex("ffff") + bytes(800))
    assert pending.returncode != 0 and not pending.stdout
    if sensor_file is None:
        return

    # The synthetic host record belongs only to this systemd delivery test.
    host_record = body[:141] + bytes([2, 32, 0]) + bytes(256)
    sensor = Path(sensor_file).read_bytes()
    assert len(sensor) == 400
    accepted = bytes(2) + host_record + sensor
    for offset in (6, 402 + 144):
        bad = bytearray(accepted)
        bad[offset] ^= 1
        failed = config(bad)
        assert failed.returncode != 0 and not failed.stdout
    prepared = config(accepted)
    assert prepared.returncode == 0, prepared.stderr
    assert b"PRIVATE KEY" not in prepared.stdout
    lines = prepared.stdout.decode().replace("\\\n", "").splitlines()
    assert lines[:2] == ["[Service]", "LoadCredentialEncrypted="]
    directives = ["".join(line.split()) for line in lines if line.startswith("SetCredentialEncrypted=")]
    assert len(directives) == 3

    command = ["systemd-run", "--user", "--quiet", "--wait", "--collect", "--pipe"]
    for directive in directives:
        command.extend(["--property", directive])
    command.extend(["/usr/bin/python3", "-c",
                    "import hashlib, os, sys; from pathlib import Path\n"
                    "directory = Path(os.environ['CREDENTIALS_DIRECTORY'])\n"
                    "for name, digest in zip(sys.argv[1::2], sys.argv[2::2]):\n"
                    "    assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest"])
    for name, value in [("host.cert", host_record), ("sensor.cert", sensor), ("host-key.pem", host_file.read_bytes())]:
        command.extend(["x1fold-native." + name, hashlib.sha256(value).hexdigest()])
    subprocess.run(command, check=True)
    print("Encrypted pairing credentials delivered to the test service")


def main(program, sensor_file=None):
    host = ec.generate_private_key(ec.SECP256R1())
    issuer = ec.generate_private_key(ec.SECP256R1())
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        host_file, issuer_file = folder / "host", folder / "issuer"
        output = folder / "request"
        save_key(host_file, host)
        save_key(issuer_file, issuer)

        result = run_request(program, host_file, issuer_file, output)
        assert result.returncode == 0, result.stderr
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        request = output.read_bytes()
        point = host.public_key().public_numbers()
        body = bytes.fromhex("3f5f1700") + point.x.to_bytes(68, "little") + point.y.to_bytes(68, "little") + bytes(2)
        assert len(request) == 400 and request[:142] == body
        size = int.from_bytes(request[142:144], "little")
        issuer.public_key().verify(request[144:144 + size], body, ec.ECDSA(hashes.SHA256()))
        assert request[144 + size:] == bytes(256 - size)
        assert run_request(program, host_file, issuer_file, output).returncode != 0 and output.read_bytes() == request

        public_file = folder / "issuer-public"
        public_file.write_bytes(issuer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        second = folder / "second"
        assert run_request(program, host_file, public_file, second).returncode != 0 and not second.exists()
        assert run_request(program, host_file, folder / "missing", second).returncode != 0 and not second.exists()
        check_service_config(program, folder, host_file, body, sensor_file)
    print("Native offline request and signature verified")


if __name__ == "__main__":
    os.umask(0o077)
    main(*sys.argv[1:])
