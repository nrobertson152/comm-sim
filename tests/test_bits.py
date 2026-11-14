"""Bit-level helpers: every CRC against its catalogue check value, checksums,
float packing and the line-code / stuffing helpers.

    python tests/test_bits.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from commsim import bits  # noqa: E402

CHECK = b"123456789"
n = 0
for name, p in bits.CRCS.items():
    w, poly, init, ri, ro, xo, chk, use = p
    got = bits.crcn(name, CHECK)
    assert 0 <= got < (1 << w), name
    if chk is not None:
        assert got == chk, "%s: 0x%X != 0x%X" % (name, got, chk)
        n += 1

# known vectors from real traffic
assert bits.crcn("CRC-16/MODBUS", bytes.fromhex("010300000002")) == 0x0BC4      # sent C4 0B
assert bits.crcn("CRC-32/ISO-HDLC", b"The quick brown fox jumps over the lazy dog") == 0x414FA339
assert bits.nmea_cs("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,") == 0x47
assert bits.lrc(bytes.fromhex("0103000A0001")) == 0xF1                              # Modbus ASCII example
assert bits.inet_cs(bytes.fromhex("45000073000040004011") + bytes(2) + bytes.fromhex("c0a80001c0a800c7")) == 0xB861

# floats: big- and little-endian byte order must really differ
assert bits.f32be(230.4) == struct.pack(">f", 230.4) == bytes.fromhex("43666666")
assert bits.f32le(230.4) == bytes.fromhex("66666643")
assert bits.f64be(1.0) == bytes.fromhex("3ff0000000000000")

# bit stuffing
assert bits.stuff([1, 1, 1, 1, 1, 1]) == ([1, 1, 1, 1, 1, 0, 1], {5})     # CAN: after 5 equal bits
assert bits.hdlc_stuff([1] * 6)[0] == [1, 1, 1, 1, 1, 0, 1]               # HDLC: a 0 after five 1s
assert bits.usb_stuff([1] * 7)[0] == [1, 1, 1, 1, 1, 1, 0, 1]             # USB: a 0 after six 1s
assert bits.lin_pid(0x10) == 0x50 and bits.lin_pid(0x3C) == 0x3C
assert bits.odd_parity(0b1011, 4) in (0, 1)
print("bits ok: %d CRC check values, checksums, floats, stuffing" % n)
