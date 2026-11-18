"""Verify the fields and offsets consumed by the Fold's session-information query."""
import os
import struct
import unittest
from unittest.mock import patch

import console_session as console


class ConsoleTests(unittest.TestCase):
    def read(self, *, seats=None, **changes):
        seat = ["3", "/session/3"]
        info = dict(Seat=["seat0", "/seat/0"], Remote=False, Active=True,
                    User=[os.getuid(), "/user"], VTNr=2, LockedHint=False,
                    Name="reader", Timestamp=1000000)
        info.update(changes)
        properties = {key: {"data": value} for key, value in info.items()}
        with patch.object(console, "active_session", side_effect=seats or [seat, seat]), \
                patch.object(console, "bus_call", return_value=[properties]):
            return console.snapshot()

    def test_infoex_layout_and_lock(self):
        for locked in (True, False):
            with self.subTest(locked=locked):
                data = self.read(LockedHint=locked)
                self.assertEqual(len(data), 232)
                self.assertEqual(struct.unpack_from("<I4xIII", data), (1, 2, 0, int(not locked)))
                self.assertEqual(data[86:100].decode("utf-16-le"), "reader\0")
                self.assertEqual(struct.unpack_from("<Q", data, 168)[0], 116444736010000000)

    def test_no_local_console(self):
        self.assertEqual(self.read(seats=[["", "/"]]), b"")
        self.assertEqual(self.read(Remote=True), b"")
        self.assertEqual(self.read(User=[os.getuid() + 1, "/other"]), b"")
        self.assertEqual(self.read(seats=[["3", "/3"], ["6", "/6"]]), b"")


if __name__ == "__main__":
    unittest.main()
