# SPDX-License-Identifier: LGPL-2.1-or-later
"""Differential tests against selected machine-code routines in the exact v153 PE images."""
import argparse
import hashlib
import hmac
import runpy
import struct
import subprocess
import tempfile
from pathlib import Path

import pefile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_RSP)


NATIVE = Path(__file__).resolve().parents[1] / "native"
HID = "synaWudfBioHid153.dll"
ADAPTER = "synaFpAdapter153.dll"
DIGEST = {HID: "4c9e969eb6c26c0447fc4fb80a5258d19d5ee7785f19e1d0ae6de35fd176fe68",
          ADAPTER: "75d711603934527e1cf886fa153f202991a7158e27c8d1bf02f81835c72f1182"}
ARG_REGS = (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
SCRATCH = 0x100000
STOP = 0x200000


class Guest:
    """A fresh Windows x64 call frame. Only explicitly installed service doubles run."""
    def __init__(self, folder, name):
        data = (folder / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != DIGEST[name]:
            raise ValueError(f"Unexpected DLL version: {name}")
        pe = pefile.PE(data=data, fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.cpu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.cpu.mem_map(self.base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        self.cpu.mem_write(self.base, pe.get_memory_mapped_image())
        self.cpu.mem_map(SCRATCH, 0x20000)
        self.cpu.mem_map(STOP, 4096)
        self.next_addr = SCRATCH
        self.mock_calls = {}

    def alloc(self, data):
        addr = self.next_addr
        self.next_addr += (len(data) + 15) & ~15
        assert self.next_addr <= SCRATCH + 0x10000
        self.cpu.mem_write(addr, bytes(data))
        return addr

    def read(self, addr, size):
        return bytes(self.cpu.mem_read(addr, size))

    def u64(self, addr):
        return int.from_bytes(self.read(addr, 8), "little")

    def put64(self, addr, value):
        self.cpu.mem_write(addr, struct.pack("<Q", value))

    def service(self, rva, function):
        self.service_at(self.base + rva, function)

    def service_at(self, address, function):
        def handle(cpu, pc, size, userdata):
            self.mock_calls[address] = self.mock_calls.get(address, 0) + 1
            result = function(*(cpu.reg_read(reg) for reg in ARG_REGS))
            if result is not None:
                cpu.reg_write(UC_X86_REG_RAX, result)
            sp = cpu.reg_read(UC_X86_REG_RSP)
            cpu.reg_write(UC_X86_REG_RSP, sp + 8)
            cpu.reg_write(UC_X86_REG_RIP, self.u64(sp))

        self.cpu.hook_add(UC_HOOK_CODE, handle, begin=address, end=address)

    def call(self, rva, *args, stop_at=None):
        sp = SCRATCH + 0x1f008
        self.cpu.mem_write(sp, bytes(128))
        self.put64(sp, STOP)
        for reg, value in zip(ARG_REGS, args):
            self.cpu.reg_write(reg, value)
        for index, value in enumerate(args[4:]):
            self.put64(sp + 40 + index * 8, value)
        self.cpu.reg_write(UC_X86_REG_RSP, sp)
        end = STOP if stop_at is None else self.base + stop_at
        self.cpu.emu_start(self.base + rva, end, count=200000)
        assert self.cpu.reg_read(UC_X86_REG_RIP) == end, "DLL did not reach expected boundary"
        return self.cpu.reg_read(UC_X86_REG_RAX) & 0xffffffff


def hid_guest(folder):
    guest = Guest(folder, HID)
    # No Windows tracing provider is registered in this fixture.
    guest.put64(guest.base + 0x14fba0, 0)
    # The driver requests its small scratch allocations from the Windows heap.
    guest.service(0x61c50, lambda size, *_: guest.alloc(bytes(size)))
    return guest


def test_issuer_source(folder, build):
    # Replace the DLL's embedded issuer context with synthetic bytes. Observe
    # the derivation inputs without extracting or printing an OEM private key.
    for context in (bytes(range(32)), bytes(reversed(range(32)))):
        guest = hid_guest(folder)
        guest.put64(guest.base + 0x157a88, 0)
        guest.service(0x61c70, lambda *_: 0)
        guest.service(0x61c90, lambda dest, value, size, *_:
                      guest.cpu.mem_write(dest, bytes([value & 255]) * size))
        guest.service(0x61cd0, lambda dest, src, size, *_:
                      guest.cpu.mem_write(dest, guest.read(src, size)))
        guest.service(0x3a5b0, lambda *_: None)

        def supply_context(descriptor, *_):
            assert guest.read(descriptor, 4) == struct.pack("<I", 32)
            guest.cpu.mem_write(guest.u64(descriptor + 8), context)
            return 0

        expected = bytes(range(32, 64))

        def observe_derivation(secret, label, seed, output_size):
            assert guest.read(secret, 4) == struct.pack("<I", 16)
            assert guest.read(guest.u64(secret + 8), 16) == context[:16]
            assert guest.read(seed, 4) == struct.pack("<I", 18)
            assert guest.read(guest.u64(seed + 8), 18) == context[16:] + b"\xaa\xaa"
            assert label == guest.base + 0x155f98
            assert output_size == 32
            frame = guest.cpu.reg_read(UC_X86_REG_RSP)
            guest.cpu.mem_write(guest.u64(frame + 40), expected)
            return 0

        guest.service(0x6e4a0, supply_context)
        guest.service(0x73fa0, observe_derivation)
        output = guest.alloc(bytes(32))
        descriptor = guest.alloc(struct.pack("<IIQ", 32, 0, output))
        assert guest.call(0x6e6c0, descriptor) == 0
        assert guest.read(output, 32) == expected
        assert guest.mock_calls[guest.base + 0x6e4a0] == 1
        assert guest.mock_calls[guest.base + 0x73fa0] == 1
    print("2 synthetic issuer contexts followed the DLL's derivation input layout", flush=True)


def test_issuer_derivation(folder, build):
    for context in (bytes(range(32)), bytes(reversed(range(32))), bytes(32), bytes([255]) * 32):
        guest = hid_guest(folder)
        guest.put64(guest.base + 0x157a88, 0)
        guest.service(0x61c70, lambda *_: 0)
        guest.service(0x61c90, lambda dest, value, size, *_:
                      guest.cpu.mem_write(dest, bytes([value & 255]) * size))
        guest.service(0x61cd0, lambda dest, src, size, *_:
                      guest.cpu.mem_write(dest, guest.read(src, size)))
        guest.service(0x3a5b0, lambda *_: None)
        guest.service(0x639d0, lambda addr, *_: guest.read(addr, 80).index(0))

        def supply_context(descriptor, *_):
            guest.cpu.mem_write(guest.u64(descriptor + 8), context)
            return 0

        def hmac_sha256(data, length, secret, secret_length):
            frame = guest.cpu.reg_read(UC_X86_REG_RSP)
            assert guest.u64(frame + 48) == 32
            assert guest.u64(frame + 56) == 0
            digest = hmac.new(guest.read(secret, secret_length), guest.read(data, length), hashlib.sha256).digest()
            guest.cpu.mem_write(guest.u64(frame + 40), digest)
            return 0

        guest.service(0x6e4a0, supply_context)
        guest.service(0x74880, hmac_sha256)
        output = guest.alloc(bytes(32))
        descriptor = guest.alloc(struct.pack("<IIQ", 32, 0, output))
        assert guest.call(0x6e6c0, descriptor) == 0
        derived = guest.read(output, 32)
        assert guest.mock_calls[guest.base + 0x74880] == 2
        # Execute the driver's scalar import preparation too. The actual
        # property-store insertion receives big-endian coordinates and scalar.
        guest.service(0xbb260, lambda *_: guest.alloc(struct.pack("<III", 0, 256, 32)))
        captured = []
        def capture_import(kind, owner, size, data):
            assert kind == 0x139 and size == 96
            captured.append(guest.read(data, size))
            return 0
        guest.service(0xbbb90, capture_import)
        crypto_context = guest.alloc(struct.pack("<QQ", 0, guest.alloc(bytes(8))))
        imported = guest.alloc(bytes(8))
        assert guest.call(0xba520, crypto_context, 32, output, imported) == 0
        assert captured == [bytes(64) + derived[::-1]]
        point = ec.derive_private_key(int.from_bytes(derived, "little"), ec.SECP256R1()).public_key()
        expected = point.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        result = subprocess.run([build / "test-issuer"], input=context, capture_output=True, check=True)
        assert result.stdout == expected
    print("4 native issuer public keys matched the DLL's derivation with synthetic contexts", flush=True)


def test_pair_status(folder, build):
    # These are the two routines that the HID transport invokes on the first
    # reply word. 0x7fff exercises the default branch of the v153 converter.
    for raw, expected in ((0, 0), (0x403, 0x76), (0x404, 0x68), (0x44f, 0xca), (0x7fff, 0xca)):
        guest = hid_guest(folder)
        status = guest.call(0xb7440, raw)
        assert guest.call(0x8b560, status) == expected, hex(raw)
    print("Fold PAIR refusal maps to the HID DLL's generic error branch", flush=True)


def check_pair_command(folder, request, transport_status):
    guest = hid_guest(folder)
    unit = guest.alloc(bytes(32))
    # Distinct stand-ins make swapped or truncated certificate records visible.
    records = bytes([0x48]) * 400 + bytes([0x53]) * 400
    untouched = bytes([0xcd]) * len(records)
    output = guest.alloc(untouched)

    def exchange(context, opcode, outbound, inbound):
        assert context == unit and opcode == 0x93
        length, = struct.unpack("<I", guest.read(outbound, 4))
        assert guest.read(guest.u64(outbound + 8), length) == bytes([opcode]) + request
        assert guest.read(inbound, 4) == struct.pack("<I", 802)
        if transport_status == 0:
            guest.put64(inbound + 8, guest.alloc(bytes(2) + records))
        return transport_status

    guest.service(0x897d0, exchange)
    guest.service(0x61c70, lambda *_: 0)  # Guest arena owns the allocations.
    status = guest.call(0x90040, unit, guest.alloc(request), output)
    assert guest.mock_calls.get(guest.base + 0x897d0) == 1 and status == transport_status
    assert guest.read(output, len(records)) == (untouched if transport_status else records)


def check_signed_request(guest, context, request, issuer):
    # Exercise the public hash-and-pack block using the same test signature as
    # the native request. ECDSA can produce different signatures on separate calls.
    sp = SCRATCH + 0x1e000
    guest.cpu.reg_write(UC_X86_REG_RSP, sp)
    guest.put64(sp + 0x60, context + 8)
    signature_output = guest.alloc(bytes(145))
    guest.put64(sp + 0x40, signature_output)
    guest.cpu.mem_write(sp + 0x38, struct.pack("<I", 145))
    length, = struct.unpack_from("<H", request, 142)
    signature = request[144:144 + length]

    def hash_body(data, size, digest, algorithm):
        assert size == 142 and algorithm == 0
        guest.cpu.mem_write(digest, hashlib.sha256(guest.read(data, size)).digest())
        return 0

    def test_signature(_handle, _key, digest, size):
        assert size == 32
        issuer.verify(signature, guest.read(digest, size), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        frame = guest.cpu.reg_read(UC_X86_REG_RSP)
        assert guest.u64(frame + 40) == signature_output
        guest.cpu.mem_write(signature_output, signature)
        guest.cpu.mem_write(guest.u64(frame + 48), struct.pack("<I", length))
        return 0

    guest.service(0x74570, hash_body)
    guest.service(0xb8d60, test_signature)
    end = guest.base + 0x906a7
    guest.cpu.emu_start(guest.base + 0x905cc, end, count=10000)
    assert guest.cpu.reg_read(UC_X86_REG_RIP) == end
    assert guest.mock_calls.get(guest.base + 0xb8d60) == 1
    assert guest.read(guest.u64(context + 0x1b8), 400) == request


def test_request(folder, build):
    registration = runpy.run_path(str(NATIVE / "test-register.py"))
    issuer = ec.generate_private_key(ec.SECP256R1())
    # The latter two points require a leading zero in a 32-byte Y or X coordinate.
    for scalar in (1, 43, 379):
        host = ec.derive_private_key(scalar, ec.SECP256R1())
        point = host.public_key().public_numbers()
        guest = hid_guest(folder)
        coords = guest.alloc(point.x.to_bytes(68, "little") + point.y.to_bytes(68, "little"))
        ctx = guest.alloc(bytes(512))
        # First word of the public curve profile copied by tudorSecurityDoPair.
        curve, = struct.unpack("<I", guest.read(guest.base + 0x15ced0, 4))
        guest.cpu.mem_write(ctx, struct.pack("<III", 1, 0, curve))
        guest.put64(ctx + 0x1b0, coords)
        # Stop at the signing call. The subject, field order and length come from the DLL.
        guest.call(0x90740, ctx, stop_at=0x90310)
        dll_body = guest.read(guest.u64(ctx + 0x1b8), 142)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registration["save_key"](root / "host", host)
            registration["save_key"](root / "issuer", issuer)
            registration["run_request"](build / "native-register", root / "host", root / "issuer",
                                        root / "request").check_returncode()
            request = (root / "request").read_bytes()
            assert len(request) == 400 and request[:142] == dll_body
            check_signed_request(guest, ctx, request, issuer.public_key())
        for status in (0, 0x403):
            check_pair_command(folder, request, status)
    print("6 simulated PAIR transfers checked using native requests and the HID DLL", flush=True)
    print("3 full host requests matched the HID DLL with a test issuer signature", flush=True)


def record(tag, payload):
    return struct.pack("<HH", tag, len(payload)) + hashlib.sha256(payload).digest() + payload


def test_storage(folder, build):
    version = record(1, struct.pack("<I", 1))
    pairing = record(2, b"synthetic opaque owner record")
    unknown = record(7, b"test")
    damaged = pairing[:-1] + bytes([pairing[-1] ^ 1])
    exact_fit = record(7, bytes(4096 - len(version + pairing) - 36))
    corrupt_unknown = unknown[:-1] + bytes([unknown[-1] ^ 1])
    cases = [
        ("erased", b"", "absent"), ("version only", version, "absent"),
        ("owner", version + pairing, "present"), ("other tags", unknown + pairing + version, "present"),
        ("bad checksum", version + damaged, "invalid"),
        ("exact partition boundary", version + pairing + exact_fit, "present"),
        ("corrupt trailing tag", version + pairing + corrupt_unknown, "invalid"),
        ("empty unknown tag", record(7, b"") + version, "absent"),
    ]
    for name, entries, expected in cases:
        image = entries.ljust(4096, b"\xff")
        guest = hid_guest(folder)
        ctx = guest.alloc(bytes(512))
        guest.put64(ctx + 0x148, guest.alloc(image))
        guest.cpu.mem_write(ctx + 0x144, struct.pack("<I", len(image)))

        def sha256(value, length, output, algorithm):
            assert algorithm == 0
            guest.cpu.mem_write(output, hashlib.sha256(guest.read(value, length)).digest())
            return 0

        guest.service(0x74570, sha256)
        status = guest.call(0x94b60, ctx)
        if status:
            assert status == 0x72, (name, status)
            observed = "invalid"
        else:
            found = guest.call(0x95180, ctx, 2, 1, guest.alloc(bytes(16)))
            assert found in (0, 0x76), (name, found)
            observed = "absent" if found else "present"
        native = subprocess.check_output([build / "test-host-storage", "--image"], input=image)
        assert observed == expected == native.decode().strip(), (name, observed, native)
    print(f"{len(cases)} HOST images matched the HID DLL's validation and tag lookup", flush=True)


def dll_match(hid, reply, template):
    # The HID routine builds the command, calls its transport vtable, and decodes the reply.
    unit = hid.alloc(bytes(128))
    vtable = hid.alloc(bytes(176))
    hid.put64(unit + 0x68, vtable)
    hid.put64(unit + 0x70, unit)
    transport = STOP + 0x100
    hid.put64(vtable + 0xa0, transport)

    def exchange(context, transfer, operation, request):
        assert context == unit and operation == 3
        request_size = int.from_bytes(hid.read(request, 4), "little")
        cmd = hid.read(hid.u64(request + 8), request_size)
        assert cmd == struct.pack("<BIII", 0x99, 1, 16, 0) + template
        response = hid.u64(hid.cpu.reg_read(UC_X86_REG_RSP) + 40)
        assert int.from_bytes(hid.read(response, 4), "little") == 1602
        hid.cpu.mem_write(response, struct.pack("<I", len(reply)))
        hid.put64(response + 8, hid.alloc(reply))
        return 0

    hid.service_at(transport, exchange)
    hid.service(0x61c70, lambda *_: 0)  # Per-case guest arena owns all heap objects.
    stats = hid.alloc(bytes(36))
    record_id, identity, auxiliary = [hid.alloc(bytes(16)) for _ in range(3)]
    status = hid.call(0xa48f0, unit, hid.alloc(bytes(16)), 1, hid.alloc(template),
                      stats, record_id, identity, auxiliary, 0, 1)
    assert status == 0 and hid.mock_calls.get(transport) == 1

    def blob(descriptor):
        size = int.from_bytes(hid.read(descriptor, 4), "little")
        return hid.read(hid.u64(descriptor + 8), size) if size else b""

    return (int.from_bytes(hid.read(stats, 4), "little"), blob(record_id),
            blob(identity), blob(auxiliary))


def adapter_verdict(folder, score):
    adapter = Guest(folder, ADAPTER)
    pipeline = adapter.alloc(bytes(96))
    scratch = adapter.alloc(bytes(96))
    adapter.put64(pipeline + 0x38, scratch)

    def comparison(pipeline_ptr, subject, subfactor_ptr, match_ptr):
        adapter.cpu.mem_write(match_ptr, bytes([bool(score)]))
        return 0

    # Supply the underlying comparison result to the real WinBio wrapper.
    adapter.service(0x1150, comparison)
    status = adapter.call(0x28d0, pipeline, scratch, 2, scratch + 8,
                          scratch + 16, scratch + 24, scratch + 32, scratch + 40, scratch + 48)
    assert adapter.mock_calls.get(adapter.base + 0x1150) == 1 and status in (0, 0x80098005)
    return 4 if status == 0 else 5


def test_verify(folder, build):
    peer = runpy.run_path(str(NATIVE / "test-session.py"))
    template = peer["TEMPLATE_ID"]
    identity = peer["enrollment_tags"](order=(0, 1, 2))
    cases = [(49, 100, b""), (50, 0, b""), (50, 100, b""), (100, 100, b"aux"),
             (1, 100, b""), (75, 0, b"aux"), (51, 1, b"x")]
    for quality, score, extra in cases:
        reply = peer["match_result"](template, identity, score, extra)
        hid = hid_guest(folder)
        ctx = hid.alloc(bytes(32))
        config = hid.alloc(bytes(256))
        hid.put64(ctx + 8, config)
        # Report an unset configuration value; the DLL supplies the default threshold.
        hid.service(0x3d470, lambda *_: 0)
        status = hid.call(0x50d40, ctx, quality)
        assert status in (0, 0x194) and hid.mock_calls.get(hid.base + 0x3d470) == 1
        if status == 0x194:
            event, mode = 2, "verify-low-quality"
        else:
            observed, record_id, payload, auxiliary = dll_match(hid, reply, template)
            assert observed == score
            if observed:
                assert (record_id, payload, auxiliary) == (template, identity, extra)
            event = adapter_verdict(folder, observed)
            mode = "verify-match" if score else "verify-zero-score"
        peer["run_worker"](build / "test-worker", mode, [(event, 0)], quality=quality, match_reply=reply)
    print(f"{len(cases)} quality and verification outcomes matched the DLLs and the native worker",
          flush=True)

    # The HID DLL returns these fields. Binding the match to the requested Linux
    # enrollment is the worker's responsibility. A positive score alone is insufficient.
    mismatches = [
        ("wrong finger", template, peer["enrollment_tags"](finger=3)),
        ("wrong account", template, peer["enrollment_tags"](user=b"A" * 16)),
        ("other template", b"Y" * 16, peer["enrollment_tags"](template=b"Y" * 16)),
    ]
    for name, returned_id, other_identity in mismatches:
        reply = peer["match_result"](returned_id, other_identity, 100, extra=identity)
        observed = dll_match(hid_guest(folder), reply, template)
        assert observed == (100, returned_id, other_identity, identity), name
        peer["run_worker"](build / "test-worker", "verify-match", [(5, 0)], quality=50, match_reply=reply)
    print(f"{len(mismatches)} identity mismatches rejected by the native worker", flush=True)


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Run with Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll_directory", type=Path)
    parser.add_argument("build_directory", type=Path)
    args = parser.parse_args()
    for test in (test_issuer_source, test_issuer_derivation, test_request, test_pair_status, test_storage, test_verify):
        test(args.dll_directory, args.build_directory.resolve())
