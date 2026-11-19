# SPDX-License-Identifier: LGPL-2.1-or-later
"""Differential tests against selected machine-code routines in the exact v153 PE images."""
import argparse
import hashlib
import runpy
import struct
import subprocess
import tempfile
from pathlib import Path

import pefile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
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


def test_request(folder, build):
    save_key = runpy.run_path(str(NATIVE / "test-register.py"))["save_key"]
    issuer = ec.generate_private_key(ec.SECP256R1())
    # The latter two points require a leading zero in a 32-byte Y or X coordinate.
    for scalar in (1, 43, 379):
        host = ec.derive_private_key(scalar, ec.SECP256R1())
        point = host.public_key().public_numbers()
        guest = hid_guest(folder)
        coords = guest.alloc(point.x.to_bytes(68, "little") + point.y.to_bytes(68, "little"))
        ctx = guest.alloc(bytes(512))
        guest.cpu.mem_write(ctx, struct.pack("<III", 1, 0, 23))
        guest.put64(ctx + 0x1b0, coords)
        # Stop at the signing call. The subject, field order and length come from the DLL.
        guest.call(0x90740, ctx, stop_at=0x90310)
        dll_body = guest.read(guest.u64(ctx + 0x1b8), 142)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            save_key(root / "host", host)
            save_key(root / "issuer", issuer)
            subprocess.run(["sh", "-c", 'exec 4<"$1"; exec "$2" request "$3" "$4"',
                            "parity", root / "host", build / "native-register",
                            (root / "issuer").as_uri(), root / "request"], check=True)
            request = (root / "request").read_bytes()
            assert len(request) == 400 and request[:142] == dll_body
            n = int.from_bytes(request[142:144], "little")
            issuer.public_key().verify(request[144:144+n], dll_body, ec.ECDSA(hashes.SHA256()))
    print("3 host request bodies matched the HID DLL at its signing boundary", flush=True)


def record(tag, payload):
    return struct.pack("<HH", tag, len(payload)) + hashlib.sha256(payload).digest() + payload


def test_storage(folder, build):
    version = record(1, struct.pack("<I", 1))
    pairing = record(2, b"synthetic opaque owner record")
    unknown = record(7, b"test")
    damaged = pairing[:-1] + bytes([pairing[-1] ^ 1])
    for name, entries, expected in [
        ("erased", b"", "absent"), ("version only", version, "absent"),
        ("owner", version + pairing, "present"), ("other tags", unknown + pairing + version, "present"),
        ("bad checksum", version + damaged, "invalid"),
    ]:
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
    print("5 HOST images matched the HID DLL's validation and tag lookup", flush=True)


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


def test_verify(folder, build):
    run_worker = runpy.run_path(str(NATIVE / "test-session.py"))["run_worker"]
    for quality, score, extra in [(49, 100, b""), (50, 0, b""),
                                  (50, 100, b""), (100, 100, b"aux")]:
        template = b"T" * 16
        subject = struct.pack("<I", 2) + bytes([0xb1]) + bytes(71)
        identity = (struct.pack("<HI", 0, 16) + template + struct.pack("<HI", 1, 76) + subject
                    + struct.pack("<HIB", 2, 1, 2))
        reply = (bytes(2) + template + struct.pack("<IIII", 36, len(extra), len(identity), score)
                 + bytes(32) + extra + identity)
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
            adapter = Guest(folder, ADAPTER)
            pipeline = adapter.alloc(bytes(96))
            scratch = adapter.alloc(bytes(96))
            adapter.put64(pipeline + 0x38, scratch)

            def comparison(pipeline_ptr, subject, subfactor_ptr, match_ptr):
                adapter.cpu.mem_write(match_ptr, bytes([bool(observed)]))
                return 0

            # Supply the underlying comparison result to the real WinBio wrapper.
            adapter.service(0x1150, comparison)
            status = adapter.call(0x28d0, pipeline, scratch, 2, scratch + 8,
                                  scratch + 16, scratch + 24, scratch + 32, scratch + 40, scratch + 48)
            assert adapter.mock_calls.get(adapter.base + 0x1150) == 1 and status in (0, 0x80098005)
            event = 4 if status == 0 else 5
            mode = "verify-match" if score else "verify-zero-score"
        run_worker(build / "test-worker", mode, [(event, 0)], quality=quality, match_reply=reply)
    print("4 quality and verification outcomes matched the DLLs and the native worker", flush=True)


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Run with Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll_directory", type=Path)
    parser.add_argument("build_directory", type=Path)
    args = parser.parse_args()
    for test in (test_request, test_storage, test_verify):
        test(args.dll_directory, args.build_directory.resolve())
