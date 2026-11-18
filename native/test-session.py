"""Independent test peer for the native client's full exchange on a packet socket."""
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def command(sock):
    payload = bytearray()
    while True:
        first = sock.recv(20)
        assert first[:9] == b"\x0esynaptic"
        size, seq = struct.unpack_from("<IH", first, 9)
        assert 2 <= size <= 250
        frag = bytearray(first[15:])
        while len(frag) < size - 2:
            packet = sock.recv(20)
            assert len(packet) == 20 and packet[0] == 14
            frag.extend(packet[1:])
        payload.extend(frag[:size - 2])
        if seq & 0x8000:
            return bytes(payload)


def respond(sock, data):
    # All replies in this profile fit the first Tudor envelope.
    assert len(data) <= 245
    message = b"synaptic" + struct.pack("<II", len(data) + 4, len(data)) + data
    for pos in range(0, len(message), 63):
        sock.sendall((b"\x0f" + message[pos:pos + 63]).ljust(64, b"\0"))


def prf(secret, label, seed, size):
    base = label + seed
    a = base
    out = b""
    while len(out) < size:
        a = hmac.digest(secret, a, "sha384")
        out += hmac.digest(secret, a + base, "sha384")
    return out[:size]


def record(kind, body):
    return struct.pack(">BHH", kind, 0x0303, len(body)) + body


def send_record(kind, body, key, salt, seq):
    explicit = os.urandom(8)
    aad = seq.to_bytes(8, "big") + record(kind, body)[:5]
    return record(kind, explicit + AESGCM(key).encrypt(salt + explicit, body, aad))


def open_record(wire, key, salt, seq, kind):
    assert wire[:3] == bytes([kind, 3, 3])
    assert int.from_bytes(wire[3:5], "big") == len(wire) - 5
    aad = struct.pack(">QBHH", seq, kind, 0x0303, len(wire) - 29)
    return AESGCM(key).decrypt(salt + wire[5:13], wire[13:], aad)


def reader(sock, mode):
    identity = ec.generate_private_key(ec.SECP256R1())
    sock.sendall(identity.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    host = serialization.load_der_public_key(sock.recv(128))
    if mode.startswith("open-"):
        assert sock.recv(20) == b""  # The client must close before its first HID command.
        return
    hello = command(sock)
    assert hello[:7] == b"D\0\0\0\x16\x03\x03"
    client_random = hello[15:47]
    random = os.urandom(32)
    server = bytes.fromhex("0200002d0383") + random + bytes.fromhex(
        "0701020304050607c02e000d000004014000000e000000")
    respond(sock, record(22, server))
    auth = command(sock)
    assert auth[:7] == b"D\0\0\0\x16\x03\x03"
    size = int.from_bytes(auth[7:9], "big")
    proof = auth[9:9 + size]
    assert proof[:12] == bytes.fromhex("0b0001980001900001900000")
    subject = host.public_numbers()
    assert int.from_bytes(proof[16:84], "little") == subject.x
    assert int.from_bytes(proof[84:152], "little") == subject.y
    assert proof[412:416] == bytes.fromhex("10000041")
    assert proof[481:484] == bytes.fromhex("0f0000") and proof[484] == len(proof) - 485
    host.verify(proof[485:], hello[9:] + server + proof[:481], ec.ECDSA(hashes.SHA256()))
    exchange = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), proof[416:481])
    master = prf(identity.exchange(ec.ECDH(), exchange), b"master secret", client_random + random, 48)
    keys = prf(master, b"key expansion", client_random + random, 72)
    digest = hashlib.sha256(hello[9:] + server + proof).digest()
    change = record(20, b"\x01")
    assert auth[9 + size:15 + size] == change
    finished = open_record(auth[15 + size:], keys[:32], keys[64:68], 0, 22)
    prefix = bytes.fromhex("1400000c")
    assert finished == prefix + prf(master, b"client finished", digest, 12)
    value = prf(master, b"server finished", digest, 12)
    if mode == "handshake-wrong-finished":
        value = bytes(12)
    sealed = send_record(22, prefix + value, keys[32:64], keys[68:], 0)
    if mode == "handshake-wrong-tag":
        sealed = sealed[:-1] + bytes([sealed[-1] ^ 1])
    respond(sock, (change if mode != "handshake-no-change" else b"") + sealed)
    if mode.startswith("handshake-"):
        return
    previous = None
    for seq in [1, 2]:
        assert open_record(command(sock), keys[:32], keys[64:68], seq, 23) == b"\x01"
        body = bytes(range(seq - 1, seq + 37))
        reply = send_record(23, body, keys[32:64], keys[68:], seq)
        if seq == 2 and mode == "record-replay":
            reply = previous
        if seq == 2 and mode == "record-wrong-tag":
            reply = reply[:-1] + bytes([reply[-1] ^ 1])
        respond(sock, reply)
        previous = reply
    if mode.startswith("record-"):
        return
    assert open_record(command(sock), keys[:32], keys[64:68], 3, 21) == b"\x01\x00"
    alert = b"\x02\x28" if mode == "close-invalid" else b"\x01\x00"
    respond(sock, send_record(21, alert, keys[32:64], keys[68:], 3))


def run(exe, mode):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with child, parent:
        parent.settimeout(4)
        with subprocess.Popen([exe, str(child.fileno()), mode], pass_fds=(child.fileno(),)) as proc:
            child.close()
            try:
                reader(parent, mode)
                assert proc.wait(timeout=4) == 0
            finally:
                if proc.poll() is None:
                    proc.kill()


if __name__ == "__main__":
    for case in ("valid", "open-busy", "open-wrong-host", "handshake-wrong-tag", "handshake-wrong-finished", "handshake-no-change",
                 "record-replay", "record-wrong-tag", "close-invalid"):
        run(sys.argv[1], case)
    print("9 native session scenarios passed")
