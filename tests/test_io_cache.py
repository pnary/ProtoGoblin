"""Exercise the compiled cache against libc, including concurrent close/read."""

import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest


@unittest.skipUnless(shutil.which("g++"), "g++ is required for native cache tests")
class IoCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        subprocess.run([
            "g++", "-O2", "-fPIC", "-shared", "-std=c++17",
            "vklayers/io-cache/io_cache.cpp", "-o", str(cls.root / "cache.so"), "-ldl", "-pthread",
        ], check=True, capture_output=True)
        cls.old_enabled = os.environ.get("PROTOGOBLIN_IO_CACHE")
        os.environ["PROTOGOBLIN_IO_CACHE"] = "1"
        cls.lib = ctypes.CDLL(str(cls.root / "cache.so"))
        cls.lib.open64.argtypes = [ctypes.c_char_p, ctypes.c_int]
        cls.lib.open64.restype = ctypes.c_int
        cls.lib.pread64.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_longlong]
        cls.lib.pread64.restype = ctypes.c_ssize_t
        cls.lib.close.argtypes = [ctypes.c_int]
        cls.lib.close.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        if cls.old_enabled is None:
            os.environ.pop("PROTOGOBLIN_IO_CACHE", None)
        else:
            os.environ["PROTOGOBLIN_IO_CACHE"] = cls.old_enabled

    def setUp(self):
        self.path = self.root / (self._testMethodName + ".pak")
        self.contents = bytes(range(256)) * 4096
        self.path.write_bytes(self.contents)
        self.fd = self.lib.open64(os.fsencode(self.path), os.O_RDONLY)
        self.assertGreaterEqual(self.fd, 0)
        self.addCleanup(self.lib.close, self.fd)

    def read(self, count, offset):
        buffer = ctypes.create_string_buffer(count)
        result = self.lib.pread64(self.fd, buffer, count, offset)
        return result, buffer.raw[:max(0, result)]

    def test_window_boundary_is_not_eof(self):
        offset = 512 * 1024 - 16
        count, data = self.read(32, offset)
        self.assertEqual(count, 32)
        self.assertEqual(data, self.contents[offset:offset + 32])

    def test_eof_and_negative_offset_match_libc(self):
        self.assertEqual(self.read(32, len(self.contents) - 8), (8, self.contents[-8:]))
        self.assertEqual(self.read(32, len(self.contents)), (0, b""))
        self.assertEqual(self.read(32, -1)[0], -1)

    def test_external_same_size_write_invalidates_cache(self):
        self.read(32, 0)
        with self.path.open("r+b", buffering=0) as stream:
            stream.write(b"x" * 32)
            os.fsync(stream.fileno())
        self.assertEqual(self.read(32, 0), (32, b"x" * 32))

    def test_concurrent_close_keeps_slot_alive(self):
        failures = []
        def read_repeatedly():
            for _ in range(500):
                count, data = self.read(32, 0)
                if count not in (-1, 32) or (count == 32 and data != self.contents[:32]):
                    failures.append((count, data))
        thread = threading.Thread(target=read_repeatedly)
        thread.start()
        self.lib.close(self.fd)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
