# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check the administrative CLI offline with two ephemeral test keys."""
import os
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


def main(program):
    host = ec.generate_private_key(ec.SECP256R1())
    issuer = ec.generate_private_key(ec.SECP256R1())
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        host_file, issuer_file = folder / "host", folder / "issuer"
        output = folder / "request"
        save_key(host_file, host)
        save_key(issuer_file, issuer)

        def run(source, dest):
            return subprocess.run(
                ["sh", "-c", 'exec 4<"$1"; exec "$2" request "$3" "$4"',
                 "test-register", host_file, program, source.as_uri(), dest],
                capture_output=True, check=False)

        result = run(issuer_file, output)
        assert result.returncode == 0, result.stderr
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        request = output.read_bytes()
        point = host.public_key().public_numbers()
        body = bytes.fromhex("3f5f1700") + point.x.to_bytes(68, "little") + point.y.to_bytes(68, "little") + bytes(2)
        assert len(request) == 400 and request[:142] == body
        size = int.from_bytes(request[142:144], "little")
        issuer.public_key().verify(request[144:144 + size], body, ec.ECDSA(hashes.SHA256()))
        assert request[144 + size:] == bytes(256 - size)
        assert run(issuer_file, output).returncode != 0 and output.read_bytes() == request

        public_file = folder / "issuer-public"
        public_file.write_bytes(issuer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        second = folder / "second"
        assert run(public_file, second).returncode != 0 and not second.exists()
        assert run(folder / "missing", second).returncode != 0 and not second.exists()
    print("Native offline request and signature verified")


if __name__ == "__main__":
    os.umask(0o077)
    main(sys.argv[1])
