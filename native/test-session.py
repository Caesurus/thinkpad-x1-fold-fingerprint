"""Independent test peer for the native client's full exchange on a packet socket."""
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

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


def capture(sock, keys, mode, seq=1, client=None):
    notice = bytes([16]) + bytes(19)

    def exchange(expected, response, hint=False):
        nonlocal seq
        req = open_record(command(sock), keys[:32], keys[64:68], seq, 23)
        assert req == expected, (req.hex(), expected.hex())
        if hint:
            sock.sendall(notice)
        respond(sock, send_record(23, response, keys[32:64], keys[68:], seq))
        seq += 1

    def configure(mask, cursor):
        words = [mask, 0, 0, 0, mask, 0, 0, 0, 0 if mask else 4]
        exchange(b"\x86" + struct.pack("<9I", *words), bytes(64) + struct.pack("<H", cursor))

    def page(cursor, events, pending=0, legacy=False, hint=False):
        request = struct.pack("<BHH", 0x87, cursor, 32)
        if not legacy:
            request += struct.pack("<I", 1)
        body = struct.pack("<HHH", 0, len(events), pending)
        body += b"".join(bytes([kind]) + bytes(11) for kind in events)
        exchange(request, body, hint)

    configure(1 << 24, 65535)
    acquire = struct.pack("<BII", 0x80, 12 if mode == "capture-enroll" else 0x1014, 1)
    acquire += bytes.fromhex("0100000801010100")
    if mode == "capture-denied":
        exchange(acquire, bytes.fromhex("0104"))
        configure(0, 0)
        return seq
    if mode == "capture-busy":
        exchange(acquire, bytes.fromhex("ea06"))
    exchange(acquire, bytes(2))
    configure((1 << 24) | 2, 65535)
    assert sock.recv(20) == b"\x11wait event".ljust(20, b"\0")
    if mode == "capture-timeout":
        page(65535, [], hint=True)  # An untrusted wake-up alone cannot complete capture.
        page(65535, [1])            # Finger-down alone is also insufficient.
    elif mode == "capture-cancel-wait":
        page(65535, [])
        if client is not None:
            assert sock.recv(1) == b"W"
            client.shutdown(socket.SHUT_WR)
    elif mode == "capture-legacy":
        exchange(bytes.fromhex("87ffff200001000000"), bytes.fromhex("0504"))
        page(65535, [1], pending=2, legacy=True)
        page(0, [24], pending=1, legacy=True)
    elif mode == "capture-invalid-page":
        exchange(bytes.fromhex("87ffff200001000000"), bytes.fromhex("000002000000"))
    elif mode != "capture-cancel":
        page(65535, [24], hint=True)  # Interleaved notification arrives before the reply.
        page(0, [], hint=False)       # Must consume the latched hint, then wait again.
        sock.sendall(notice)
        page(0, [1])
    assert sock.recv(20) == b"\x11end event".ljust(20, b"\0")
    configure(0, 0)
    exchange(b"\x81", bytes(2))
    return seq


def print_operation(sock, keys, mode, client=None):
    seq = 1
    tuid = b"T" * 16
    child = b"P" * 16
    guid = bytes([0xb1]) + bytes(15)

    def exchange(expected, response):
        nonlocal seq
        assert open_record(command(sock), keys[:32], keys[64:68], seq, 23) == expected
        respond(sock, send_record(23, response, keys[32:64], keys[68:], seq))
        seq += 1

    def tags(template=tuid, user=guid, finger=2, subject_type=2):
        subject = struct.pack("<I", subject_type) + user + bytes(56)
        fields = [(1, subject), (0, template), (2, bytes([finger]))]
        return b"".join(struct.pack("<HI", tag, len(value)) + value for tag, value in fields)

    version = bytearray(38)
    version[18:24] = bytes([1, 2, 3, 4, 5, 6])
    if mode in ("verify-directory-serial", "delete-wrong-serial"):
        version[18] ^= 1
    exchange(b"\x01", version)
    if mode in ("verify-directory-serial", "delete-wrong-serial"):
        return seq

    def object_cmd(op, kind, obj):
        return struct.pack("<BI", op, kind) + obj

    def listing(ids):
        return struct.pack("<HH", 0, len(ids)) + b"".join(ids)

    if mode.startswith("enroll-"):
        old = b"A" * 16
        before = [] if mode == "enroll-empty" else [old]

        def directory(ids):
            exchange(object_cmd(0x9f, 2, bytes([255]) * 16), listing(ids))
            for template in sorted(ids):
                payload = child if template == tuid else b"R" * 16
                exchange(object_cmd(0x9f, 3, template), listing([payload]))
                target = template == tuid or mode == "enroll-existing-identity"
                data = tags(template=template, finger=2 if target else 3)
                exchange(object_cmd(0xa1, 3, payload), struct.pack("<II", 0, len(data)) + data)

        directory(before)
        if mode == "enroll-existing-identity":
            return seq
        start_reply = {"enroll-short-start": bytes(2), "enroll-start-denied": struct.pack("<H", 0x403)}
        exchange(struct.pack("<BIII", 0x96, 1, 0, 0), start_reply.get(mode, bytes(6)))
        finish = struct.pack("<BI", 0x96, 4)
        if mode == "enroll-short-start":
            exchange(finish, bytes(2))
            return seq
        if mode == "enroll-start-denied":
            return seq
        for pct, reject in [(35, 0), (35, 1), (100, 0)]:
            seq = capture(sock, keys, "capture-enroll", seq)
            if before:
                result = struct.pack("<H", 0x509)
                if mode == "enroll-duplicate":
                    result = bytes(2) + old + struct.pack("<IIII", 36, 0, 0, 100) + bytes(32)
                if mode == "enroll-missing-candidate":
                    result = struct.pack("<H", 0x683)
                exchange(struct.pack("<BIII", 0x99, 1, len(before) * 16, 0) + b"".join(before), result)
                if mode in ("enroll-duplicate", "enroll-missing-candidate"):
                    exchange(finish, bytes(2))
                    return seq
            stats = bytearray(60)
            struct.pack_into("<H", stats, 2, 101 if mode == "enroll-invalid-progress" else pct)
            struct.pack_into("<I", stats, 28, reject)
            if mode == "enroll-final-error" and pct == 100:
                struct.pack_into("<I", stats, 48, 1)
            new_id = old if mode == "enroll-collision" else tuid
            reply = bytes(2) + new_id + struct.pack("<I", len(stats)) + stats
            exchange(struct.pack("<BI", 0x96, 2), reply)
            if (mode in ("enroll-invalid-progress", "enroll-client-cancel") or
                    (pct == 100 and mode in ("enroll-collision", "enroll-final-error"))):
                exchange(finish, bytes(2))
                return seq
        subject = struct.pack("<I16s56x", 2, guid)
        metadata = (struct.pack("<HI16s", 0, 16, tuid) + struct.pack("<HI76s", 1, 76, subject)
                    + struct.pack("<HIB", 2, 1, 2))
        denial = struct.pack("<H", 0x403)
        exchange(struct.pack("<BIII", 0x96, 3, 0, len(metadata)) + metadata,
                 denial if mode == "enroll-commit-denied" else bytes(2))
        exchange(finish, denial if mode == "enroll-finish-denied" else bytes(2))
        if mode not in ("enroll-commit-denied", "enroll-finish-denied"):
            exchange(b"\x01", version)
            after = [tuid] if mode == "enroll-lost-other" else before + [tuid]
            directory(before if mode == "enroll-missing-readback" else after)
        return seq

    if mode.startswith("delete-"):
        other = b"A" * 16
        directory = object_cmd(0x9f, 2, b"\xff" * 16)
        ids = [other] if mode == "delete-absent" else [tuid, other]
        if mode == "delete-last":
            ids = [tuid]
        if mode == "delete-duplicate-id":
            exchange(directory, listing([tuid, tuid]))
            return seq
        exchange(directory, listing(ids))
        for template in sorted(ids):
            payload = child if template == tuid else b"R" * 16
            children = [payload, b"Q" * 16] if template == tuid and mode == "delete-shared" else [payload]
            exchange(object_cmd(0x9f, 3, template), listing(children))
            data = tags(template=template, finger=2 if template == tuid or mode == "delete-ambiguous" else 3)
            exchange(object_cmd(0xa1, 3, payload), struct.pack("<II", 0, len(data)) + data)
        if mode in ("delete-absent", "delete-shared", "delete-ambiguous"):
            return seq
        exchange(object_cmd(0xa3, 2, tuid), struct.pack("<HH", 0, 0 if mode == "delete-zero-count" else 1))
        if mode != "delete-zero-count":
            survivors = {"delete-one": [other], "delete-last": [], "delete-still-present": ids,
                         "delete-wrong-survivor": [tuid]}[mode]
            exchange(directory, listing(survivors))
        return seq

    exchange(object_cmd(0x9f, 2, bytes([255]) * 16), listing([tuid]))
    children = [child, b"Q" * 16] if mode == "verify-directory-ambiguous" else [child]
    exchange(object_cmd(0x9f, 3, tuid), listing(children))
    for obj in children:
        data = tags(finger=3) if mode == "verify-directory-missing" else tags()
        exchange(object_cmd(0xa1, 3, obj), struct.pack("<II", 0, len(data)) + data)
    if mode.startswith("verify-directory-"):
        return seq
    if mode == "verify-client-cancel":
        return capture(sock, keys, "capture-cancel-wait", seq, client)
    seq = capture(sock, keys, "capture-verify", seq)
    quality = 49 if mode == "verify-low-quality" else 50
    metric = 1 if mode == "verify-malformed-metric" else 0x10000
    exchange(struct.pack("<BI", 0x9d, 0x10000), struct.pack("<HIIII", 0, metric, 8, quality, 0))
    if mode in ("verify-low-quality", "verify-malformed-metric"):
        return seq
    header = b"Y" * 16 if mode == "verify-other-template" else tuid
    data = tags(template=header, finger=3 if mode == "verify-other-finger" else 2,
                user=b"A" * 16 if mode == "verify-other-account" else guid,
                subject_type=3 if mode == "verify-other-subject-type" else 2)
    if mode == "verify-malformed-dupe":
        data += struct.pack("<HIB", 2, 1, 2)
    if mode == "verify-malformed-truncated":
        data += struct.pack("<HI", 5, 8)
    if mode == "verify-malformed-id":
        header = b"Z" * 16
    score = 0 if mode == "verify-zero-score" else 100
    result = (bytes(2) + header + struct.pack("<IIII", 36, 0, len(data), score)
              + bytes(32) + data)
    if mode == "verify-rejected":
        result = struct.pack("<H", 0x509)
    exchange(struct.pack("<BIII", 0x99, 1, 16, 0) + tuid, result)
    return seq


def reader(sock, mode, worker_keys=None, client=None):
    if worker_keys is not None:
        identity, host = worker_keys
        assert command(sock) == b"\x01"
        version = bytearray(38)
        version[10:12] = bytes([10, 1])
        version[13] = 0x41
        version[18:24] = bytes(range(1, 7))
        respond(sock, version)
    else:
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
    start = capture(sock, keys, mode) if mode.startswith("capture-") else 1
    if mode.startswith(("verify-", "delete-", "enroll-")):
        start = print_operation(sock, keys, mode, client)
    previous = None
    probes = 0 if worker_keys else 2
    for i in range(probes):
        seq = start + i
        assert open_record(command(sock), keys[:32], keys[64:68], seq, 23) == b"\x01"
        body = bytes(range(i, i + 38))
        reply = send_record(23, body, keys[32:64], keys[68:], seq)
        if seq == 2 and mode == "record-replay":
            reply = previous
        if seq == 2 and mode == "record-wrong-tag":
            reply = reply[:-1] + bytes([reply[-1] ^ 1])
        respond(sock, reply)
        previous = reply
    if mode.startswith("record-"):
        return
    assert open_record(command(sock), keys[:32], keys[64:68], start + probes, 21) == b"\x01\x00"
    alert = b"\x02\x28" if mode in ("close-invalid", "verify-close-failed") else b"\x01\x00"
    respond(sock, send_record(21, alert, keys[32:64], keys[68:], start + probes))


def run_worker(exe, mode, expected_events):
    sensor = ec.generate_private_key(ec.SECP256R1())
    identity = ec.generate_private_key(ec.SECP256R1())
    host = identity.public_key()
    public = host.public_numbers()
    host_cert = (bytes.fromhex("3f5f1700") + public.x.to_bytes(68, "little")
                 + public.y.to_bytes(68, "little") + bytes.fromhex("00022000")).ljust(400, b"\0")
    sensor_cert = b"TEST" + sensor.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    op = {"enroll": 1, "verify": 2, "delete": 3}[mode.split("-")[0]]
    frame = (b"X1WB" + bytes([1, op, 0, 0]) + os.urandom(16) + b"\xb1".ljust(16, b"\0")
             + bytes([1, 2, 3, 4, 5, 6, 2, 0]))
    with tempfile.TemporaryDirectory() as directory:
        files = Path(directory)
        (files / "x1fold-native.sensor.cert").write_bytes(sensor_cert.ljust(400, b"\0"))
        (files / "x1fold-native.host.cert").write_bytes(host_cert)
        (files / "x1fold-native.host-key.pem").write_bytes(identity.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if mode == "verify-missing-credential":
            (files / "x1fold-native.host-key.pem").unlink()
        sensor_sock, hid = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client, channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with client, channel, sensor_sock, hid:
            client.settimeout(4)
            sensor_sock.settimeout(4)
            handles = (channel.fileno(), hid.fileno())
            with subprocess.Popen([exe, *map(str, handles), mode], pass_fds=handles,
                                  env=dict(os.environ, CREDENTIALS_DIRECTORY=directory)) as proc:
                channel.close()
                hid.close()
                try:
                    client.sendall(frame)
                    if mode != "verify-missing-credential":
                        reader(sensor_sock, mode, (sensor, host), client)
                    for event, stage in expected_events:
                        assert client.recv(64) == frame[:6] + bytes([event, stage]) + frame[8:]
                    assert client.recv(64) == b""
                    assert proc.wait(timeout=4) == int(expected_events[-1][0] == 6)
                finally:
                    if proc.poll() is None:
                        proc.kill()


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
    cases = ("valid", "open-busy", "open-wrong-host", "handshake-wrong-tag", "handshake-wrong-finished", "handshake-no-change",
                 "record-replay", "record-wrong-tag", "close-invalid", "capture-verify", "capture-enroll", "capture-busy",
                 "capture-legacy", "capture-cancel", "capture-timeout", "capture-invalid-page",
                 "capture-cancel-wait", "capture-denied", "capture-short-end", "verify-match",
                 "verify-directory-serial", "verify-directory-missing", "verify-directory-ambiguous",
                 "verify-other-finger", "verify-other-account", "verify-other-subject-type",
                 "verify-other-template", "verify-zero-score", "verify-rejected", "verify-malformed-id",
                 "verify-malformed-dupe", "verify-malformed-truncated", "verify-low-quality",
                 "verify-malformed-metric", "delete-one", "delete-absent", "delete-shared",
                 "delete-ambiguous", "delete-duplicate-id", "delete-wrong-serial", "delete-zero-count",
                 "delete-still-present", "delete-wrong-survivor", "delete-last",
                 "enroll-multiple", "enroll-empty", "enroll-existing-identity", "enroll-duplicate",
                 "enroll-missing-candidate", "enroll-invalid-progress", "enroll-final-error",
                 "enroll-collision", "enroll-client-cancel", "enroll-commit-denied",
                 "enroll-finish-denied", "enroll-missing-readback", "enroll-lost-other",
                 "enroll-short-start", "enroll-start-denied")
    for case in cases:
        run(sys.argv[1], case)
    print(f"{len(cases)} native session and biometric scenarios passed")
    if len(sys.argv) == 3:
        workers = {"verify-match": [(4, 0)], "verify-rejected": [(5, 0)],
                   "verify-missing-credential": [(6, 0)], "verify-close-failed": [(6, 0)],
                   "verify-client-cancel": [(7, 0)], "enroll-duplicate": [(9, 0)],
                   "enroll-multiple": [(1, 1), (2, 0), (1, 2), (3, 0)], "delete-one": [(8, 0)]}
        for mode, events in workers.items():
            run_worker(sys.argv[2], mode, events)
        print(f"{len(workers)} native worker transactions passed")
