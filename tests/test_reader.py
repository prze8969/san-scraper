"""Unit tests for BoundedBinaryReader and defensive parsing boundaries."""

import unittest
from src.reader import BoundedBinaryReader, BoundsError, TruncationError

class TestBoundedBinaryReader(unittest.TestCase):
    def test_empty_buffer(self):
        reader = BoundedBinaryReader(b"")
        self.assertEqual(reader.size, 0)
        self.assertEqual(reader.position, 0)
        self.assertTrue(reader.is_eof())
        with self.assertRaises(TruncationError):
            reader.read_bytes(1)

    def test_numeric_unpacking_little_endian(self):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        reader = BoundedBinaryReader(data)
        self.assertEqual(reader.read_u8(), 1)
        self.assertEqual(reader.read_u8(), 2)
        self.assertEqual(reader.read_u16_le(), 0x0403)
        self.assertEqual(reader.read_u32_le(), 0x08070605)
        self.assertTrue(reader.is_eof())

    def test_bounds_and_seek(self):
        data = b"ABCDEFGHIJ"
        reader = BoundedBinaryReader(data)
        reader.seek(5)
        self.assertEqual(reader.position, 5)
        self.assertEqual(reader.read_bytes(3), b"FGH")
        with self.assertRaises(BoundsError):
            reader.seek(20)
        with self.assertRaises(BoundsError):
            reader.seek(-1)

    def test_peek_and_slice(self):
        data = b"0123456789"
        reader = BoundedBinaryReader(data)
        self.assertEqual(reader.peek_bytes(4), b"0123")
        self.assertEqual(reader.position, 0)  # peek must not advance
        self.assertEqual(reader.read_exact(3, 5), b"567")
        self.assertEqual(reader.position, 0)
        with self.assertRaises(BoundsError):
            reader.read_exact(5, 8)

    def test_fixed_string_null_terminated(self):
        data = b"HELLO\x00\x00\x00WORLD\x00"
        reader = BoundedBinaryReader(data)
        self.assertEqual(reader.read_fixed_string(8), "HELLO")
        self.assertEqual(reader.read_fixed_string(6), "WORLD")

    def test_max_allocation_limit(self):
        data = b"\x00" * 100
        reader = BoundedBinaryReader(data, max_alloc=50)
        with self.assertRaises(BoundsError):
            reader.read_bytes(60)

if __name__ == "__main__":
    unittest.main()
