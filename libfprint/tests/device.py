"""Exercise the private TOD module through FpContext in an isolated umockdev bed."""
import errno
import os
from pathlib import Path
import subprocess
import struct
import sys
import unittest

import gi

gi.require_version("FPrint", "2.0")
gi.require_version("UMockdev", "1.0")
from gi.repository import FPrint, GLib, UMockdev

DESCRIPTOR = bytes.fromhex(
    "0600ff0901a101850e0902150026ff00750895139102850f0906150026ff007508953f8102"
    "85100905150026ff0075089513810285110907150026ff0075089513b102c0"
)
REQUEST = bytes.fromhex("0e73796e617074696303000000ffc00100000000")

def version(serial=bytes(range(1, 7))):
    reply = bytearray(64)
    reply[:19] = b"\x0fsynaptic" + struct.pack("<IIH", 42, 38, 0)
    struct.pack_into("<IBBBB", reply, 23, 3654703, 10, 1, 0, 0x41)
    reply[35:41] = serial
    return reply


class HidIoctls(UMockdev.IoctlBase):
    def __init__(self, reports, descriptor=DESCRIPTOR):
        super().__init__()
        self.reports = iter(reports)
        self.descriptor = descriptor
        self.writes = []

    def do_handle_write(self, client):
        data = bytes(client.get_arg().retrieve())
        self.writes.append(data)
        client.complete(len(data), 0)
        return True

    def do_handle_read(self, client):
        report = next(self.reports, b"")
        client.get_arg().update(0, report)
        client.complete(len(report), 0)
        return True

    def do_handle_ioctl(self, client):
        responses = {
            0x80084803: struct.pack("=IHH", 3, 0x17ef, 0x6142),
            0x80044801: struct.pack("=I", len(self.descriptor)),
            0x90044802: struct.pack("=I", len(self.descriptor)) + self.descriptor,
        }
        request = client.get_request()
        if request not in responses:
            client.complete(-1, errno.ENOTTY)
            return True
        argument = client.get_arg().resolve(0, (request >> 16) & 0x3fff)
        argument.update(0, responses[request])
        client.complete(0, 0)
        return True


def add_keyboard(bed, interfaces, port=1, vid="17ef"):
    device = f"/devices/usb1/1-{port}"
    records = [f"""P: {device}
E: SUBSYSTEM=usb
E: DEVTYPE=usb_device
A: idVendor={vid}
A: idProduct=6142"""]
    seen_interfaces = set()
    for number, node, layout in interfaces:
        interface = f"{device}/1-{port}:1.{number}"
        hid = f"{interface}/0003:{vid.upper()}:6142.{node:04X}"
        if number not in seen_interfaces:
            seen_interfaces.add(number)
            records.append(f"""P: {interface}
E: SUBSYSTEM=usb
E: DEVTYPE=usb_interface
A: bInterfaceNumber={number:02x}""")
        records += [f"""P: {hid}
E: SUBSYSTEM=hid
E: HID_ID=0003:0000{vid.upper()}:00006142
H: report_descriptor={layout.hex()}""", f"""P: {hid}/hidraw/hidraw{node}
N: hidraw{node}=00
E: DEVNAME=/dev/hidraw{node}
E: SUBSYSTEM=hidraw
E: MAJOR=240
E: MINOR={node}
A: dev=240:{node}"""]
    bed.add_from_string("\n\n".join(records) + "\n")


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.bed = UMockdev.Testbed.new()
        self.assertTrue(UMockdev.in_mock_environment())

    def tearDown(self):
        self.context = None
        self.bed = None

    def discover(self):
        self.context = FPrint.Context.new()
        return self.context.get_devices()

    def test_keyboard_only(self):
        add_keyboard(self.bed, [(0, 20, b"keyboard")])
        self.assertEqual(self.discover(), [])

    def test_wrong_interface(self):
        add_keyboard(self.bed, [(1, 20, DESCRIPTOR)])
        self.assertEqual(self.discover(), [])

    def test_changed_descriptor(self):
        add_keyboard(self.bed, [(4, 20, bytes([0]) + DESCRIPTOR[1:])])
        self.assertEqual(self.discover(), [])

    def test_wrong_vendor(self):
        add_keyboard(self.bed, [(4, 20, DESCRIPTOR)], vid="1234")
        self.assertEqual(self.discover(), [])

    def test_two_matching_nodes(self):
        add_keyboard(self.bed, [(4, 20, DESCRIPTOR), (4, 21, DESCRIPTOR)])
        self.assertEqual(self.discover(), [])

    def test_sensor_on_different_keyboard(self):
        add_keyboard(self.bed, [(0, 20, b"keyboard")])
        add_keyboard(self.bed, [(4, 21, DESCRIPTOR)], port=2, vid="1234")
        self.assertEqual(self.discover(), [])

    def attach(self, mock):
        add_keyboard(self.bed, [(0, 20, b"keyboard"), (4, 21, DESCRIPTOR)])
        self.bed.attach_ioctl("/dev/hidraw21", mock)

    def sensor(self, mock):
        self.attach(mock)
        devices = self.discover()
        self.assertEqual(len(devices), 1)
        device = devices[0]
        self.assertEqual(device.get_driver(), "x1fold_hid")
        self.assertEqual(device.get_device_id(), "tudor-010203040506")
        self.assertTrue(device.has_feature(FPrint.DeviceFeature.VERIFY))
        self.assertTrue(device.has_feature(FPrint.DeviceFeature.STORAGE_DELETE))
        self.assertTrue(device.has_feature(FPrint.DeviceFeature.STORAGE))
        self.assertFalse(device.has_feature(FPrint.DeviceFeature.STORAGE_CLEAR))
        return device

    def test_native_open_and_rejected_biometrics(self):
        event = bytes([0x10]) + bytes(19)
        mock = HidIoctls([event, version(), version()])
        device = self.sensor(mock)
        device.open_sync()
        self.assertEqual(mock.writes, [REQUEST, REQUEST])
        try:
            template = FPrint.Print.new(device)
            for operation in (device.enroll_sync, device.verify_sync):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaises(GLib.Error) as caught:
                        operation(template)
                    self.assertTrue(caught.exception.matches(
                        FPrint.device_error_quark(), FPrint.DeviceError.DATA_INVALID
                    ))
        finally:
            device.close_sync()

    def test_malformed_reply_fails_open(self):
        mock = HidIoctls([version(), bytes(64)])
        device = self.sensor(mock)
        with self.assertRaises(GLib.Error) as caught:
            device.open_sync()
        self.assertEqual(mock.writes, [REQUEST, REQUEST])
        self.assertIn("Invalid Tudor GET_VERSION", str(caught.exception))

    def test_replaced_hid_fails_before_write(self):
        mock = HidIoctls([version()])
        device = self.sensor(mock)
        mock.descriptor = bytes([0]) + DESCRIPTOR[1:]
        with self.assertRaises(GLib.Error) as caught:
            device.open_sync()
        self.assertIn("does not match the fingerprint HID", str(caught.exception))
        self.assertEqual(mock.writes, [REQUEST])

    def test_different_physical_sensor_at_open(self):
        mock = HidIoctls([version(), version(b"second")])
        device = self.sensor(mock)
        with self.assertRaises(GLib.Error) as caught:
            device.open_sync()
        self.assertTrue(caught.exception.matches(FPrint.device_error_quark(), FPrint.DeviceError.REMOVED))
        self.assertEqual(mock.writes, [REQUEST, REQUEST])

    def run_codec(self, env):
        exe = Path(os.environ["FP_TOD_DRIVERS_DIR"]) / "test-print-identity"
        env["UMOCKDEV_DIR"] = self.bed.get_root_dir()
        subprocess.run([exe], env=env, check=True, timeout=10)

    def test_public_print_round_trip(self):
        mock = HidIoctls([version()])
        self.attach(mock)
        self.run_codec(os.environ.copy())
        self.assertEqual(mock.writes, [REQUEST])

    def test_passive_discovery_without_print_identity(self):
        mock = HidIoctls([])
        self.attach(mock)
        self.run_codec(dict(os.environ, X1FOLD_PASSIVE_DISCOVERY="1"))
        self.assertEqual(mock.writes, [])

    def test_blank_sensor_serial_has_no_print_identity(self):
        mock = HidIoctls([version(bytes(6)), version(bytes([255]) * 6)])
        self.attach(mock)
        self.run_codec(os.environ.copy())
        self.run_codec(os.environ.copy())
        self.assertEqual(mock.writes, [REQUEST, REQUEST])

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file mode restrictions")
    def test_unprivileged_discovery(self):
        mock = HidIoctls([])
        self.attach(mock)
        path = Path(self.bed.get_root_dir(), "dev/hidraw21")
        path.chmod(0)
        try:
            devices = self.discover()
            self.assertEqual([d.get_device_id() for d in devices], ["diagnostic-unidentified"])
            self.assertEqual(mock.writes, [])
        finally:
            path.chmod(0o600)


if __name__ == "__main__":
    if "umockdev" not in os.environ.get("LD_PRELOAD", "") or not os.environ.get("FP_TOD_DRIVERS_DIR"):
        sys.exit("Run through make check with an isolated TOD module directory and umockdev-wrapper")
    unittest.main()
