"""Drive cancellation through libfprint while the worker still holds the reader."""
import os
import socket
import unittest

import device as fixture
from gi.repository import Gio, GLib


class CancellationTests(fixture.DriverTests):
    def test_wait_for_worker(self):
        reader = self.sensor(fixture.HidIoctls([fixture.version(), fixture.version()]))
        reader.open_sync()
        result = []
        cancel = Gio.Cancellable()
        context = GLib.MainContext.default()

        def done(device, async_result, *unused):
            try:
                result.append(device.enroll_finish(async_result))
            except GLib.Error as error:
                result.append(error)

        def drain():
            while context.iteration(False):
                pass

        def start(client, worker, cancellable=None):
            os.environ["X1FOLD_TEST_CHANNEL"] = str(client.detach())
            template = fixture.FPrint.Print.new(reader)
            template.set_finger(fixture.FPrint.Finger.RIGHT_INDEX)
            reader.enroll(template, cancellable=cancellable, callback=done)
            drain()
            worker.settimeout(2)
            request = worker.recv(64)
            self.assertEqual(request[:4], b"X1WB")
            return request

        try:
            client, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with worker:
                request = start(client, worker, cancel)
                cancel.cancel()
                drain()
                self.assertEqual(worker.recv(64), b"")
                self.assertEqual(result, [], "libfprint finished before worker cleanup")
                worker.sendall(request[:6] + bytes([1, 1]) + request[8:])
                worker.sendall(request[:6] + bytes([3, 0]) + request[8:])
                drain()
                self.assertEqual(result, [], "late enrollment reply completed a cancelled scan")
            drain()
            self.assertEqual(len(result), 1)
            self.assertTrue(result.pop().matches(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED))

            client, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with worker:
                request = start(client, worker)
                worker.sendall(request[:6] + bytes([1, 1]) + request[8:])
                worker.sendall(request[:6] + bytes([3, 0]) + request[8:])
                drain()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].get_finger(), fixture.FPrint.Finger.RIGHT_INDEX)
        finally:
            drain()
            reader.close_sync()


if __name__ == "__main__":
    unittest.main(defaultTest="CancellationTests.test_wait_for_worker")
