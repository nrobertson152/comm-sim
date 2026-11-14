"""Bit-level toolbox: CRCs, checksums, bit stuffing and line codes.

Every CRC used by the simulated protocols lives in CRCS with its
parameters in the usual Rocksoft/reveng form (width, poly, init, refin,
refout, xorout) and the standard check value (CRC of b"123456789"), so the
test-suite can prove each one is the real algorithm.
"""
import struct
import numpy as np

_tabs = {}


def reflect(v, n):
    r = 0
    for i in range(n):
        if v >> i & 1:
            r |= 1 << (n - 1 - i)
    return r


def _table(width, poly, refl):
    k = (width, poly, refl)
    t = _tabs.get(k)
    if t is None:
        t = []
        mask = (1 << width) - 1
        for i in range(256):
            if refl:
                c = i
                for _ in range(8):
                    c = (c >> 1) ^ poly if c & 1 else c >> 1
            else:
                c = i << (width - 8)
                for _ in range(8):
                    c = ((c << 1) ^ poly) & mask if c & (1 << (width - 1)) else (c << 1) & mask
            t.append(c)
        _tabs[k] = t
    return t


def crc(data, width, poly, init=0, refin=False, refout=False, xorout=0):
    """Generic CRC over bytes (any width >= 3)."""
    mask = (1 << width) - 1
    if width < 8:                                   # small CRCs: plain bit loop
        c = reflect(init, width) if refin else init
        rp = reflect(poly, width)
        for b in data:
            for i in range(8):
                if refin:
                    bit = (b >> i) & 1
                    fb = (c ^ bit) & 1
                    c >>= 1
                    if fb:
                        c ^= rp
                else:
                    bit = (b >> (7 - i)) & 1
                    fb = ((c >> (width - 1)) ^ bit) & 1
                    c = (c << 1) & mask
                    if fb:
                        c ^= poly
        if refin != refout:
            c = reflect(c, width)
        return (c ^ xorout) & mask
    if refin:
        tab = _table(width, reflect(poly, width), True)
        c = reflect(init, width)
        for b in data:
            c = (c >> 8) ^ tab[(c ^ b) & 0xFF]
        if not refout:
            c = reflect(c, width)
    else:
        tab = _table(width, poly, False)
        c = init
        sh = width - 8
        for b in data:
            c = ((c << 8) & mask) ^ tab[((c >> sh) ^ b) & 0xFF]
        if refout:
            c = reflect(c, width)
    return (c ^ xorout) & mask


def crc_bits(bits, width, poly, init=0, xorout=0):
    """Non-reflected CRC over a bit sequence in transmission order (CAN, Mode S...)."""
    mask = (1 << width) - 1
    c = init
    for b in bits:
        fb = ((c >> (width - 1)) & 1) ^ (b & 1)
        c = (c << 1) & mask
        if fb:
            c ^= poly
    return c ^ xorout


# name: (width, poly, init, refin, refout, xorout, check, used by)
CRCS = {
    "CRC-16/MODBUS": (16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37, "Modbus RTU, SunSpec over RTU"),
    "CRC-16/X-25": (16, 0x1021, 0xFFFF, True, True, 0xFFFF, 0x906E, "HDLC FCS: AIS, DLMS, BACnet MS/TP data, CC-Link"),
    "CRC-16/KERMIT": (16, 0x1021, 0x0000, True, True, 0x0000, 0x2189, "IEEE 802.15.4 FCS, Zigbee, Thread, ACARS BCS"),
    "CRC-16/CCITT-FALSE": (16, 0x1021, 0xFFFF, False, False, 0x0000, 0x29B1, "CCSDS TM/TC FECF, SpaceFibre"),
    "CRC-16/XMODEM": (16, 0x1021, 0x0000, False, False, 0x0000, 0x31C3, "LoRa PHY payload CRC, LonTalk"),
    "CRC-16/DNP": (16, 0x3D65, 0x0000, True, True, 0xFFFF, 0xEA82, "DNP3 link layer"),
    "CRC-16/EN-13757": (16, 0x3D65, 0x0000, False, False, 0xFFFF, 0xC2B7, "Wireless M-Bus"),
    "CRC-16/USB": (16, 0x8005, 0xFFFF, True, True, 0xFFFF, 0xB4C8, "USB data packets"),
    "CRC-32/ISO-HDLC": (32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xCBF43926, "Ethernet / Wi-Fi FCS, PROFINET, EtherCAT, AFDX, PNG, zip"),
    "CRC-8/SAE-J1850": (8, 0x1D, 0xFF, False, False, 0xFF, 0x4B, "SAE J1850, AUTOSAR E2E P1/P2"),
    "CRC-8/MAXIM-DOW": (8, 0x31, 0x00, True, True, 0x00, 0xA1, "1-Wire ROM and scratchpad"),
    "CRC-8/SMBUS": (8, 0x07, 0x00, False, False, 0x00, 0xF4, "SMBus PEC"),
    "CRC-8/ROHC": (8, 0x07, 0xFF, True, True, 0x00, 0xD0, "-"),
    "CRC-5/USB": (5, 0x05, 0x1F, True, True, 0x1F, 0x19, "USB token packets"),
    "CRC-24/BLE": (24, 0x00065B, 0x555555, True, True, 0x000000, 0xC25A56, "Bluetooth LE (advertising init)"),
    "CRC-24/FLEXRAY-A": (24, 0x5D6DCB, 0xFEDCBA, False, False, 0x000000, 0x7979BD, "FlexRay frame CRC, channel A"),
    "CRC-24/FLEXRAY-B": (24, 0x5D6DCB, 0xABCDEF, False, False, 0x000000, 0x1F23B8, "FlexRay frame CRC, channel B"),
    "CRC-11/FLEXRAY": (11, 0x385, 0x01A, False, False, 0x000, 0x5A3, "FlexRay header CRC"),
    "CRC-15/CAN": (15, 0x4599, 0x0000, False, False, 0x0000, 0x059E, "Classical CAN (computed over bits)"),
    "CRC-17/CAN-FD": (17, 0x1685B, 0x00000, False, False, 0x00000, 0x04F03, "CAN FD, payload <= 16 bytes"),
    "CRC-21/CAN-FD": (21, 0x102899, 0x000000, False, False, 0x000000, 0x0ED841, "CAN FD, payload > 16 bytes"),
    "CRC-24/MODE-S": (24, 0xFFF409, 0x000000, False, False, 0x000000, None, "Mode S / ADS-B parity (PI/AP)"),
    "CRC-16/IBM-SDLC": (16, 0x1021, 0xFFFF, True, True, 0xFFFF, 0x906E, "same as X-25"),
}


def crcn(name, data):
    w, p, i, ri, ro, x = CRCS[name][:6]
    return crc(data, w, p, i, ri, ro, x)


# ---------------------------------------------------------------- checksums
def sum8(data):
    return sum(data) & 0xFF


def lrc(data):
    """Modbus ASCII LRC: two's complement of the 8-bit sum."""
    return (-sum(data)) & 0xFF


def xor8(data):
    c = 0
    for b in data:
        c ^= b
    return c


def nmea_cs(body):
    """NMEA 0183 checksum: XOR of the characters between '$'/'!' and '*'."""
    return xor8(body.encode("ascii") if isinstance(body, str) else body)


def inet_cs(data):
    """RFC 1071 ones-complement 16-bit Internet checksum."""
    if len(data) % 2:
        data = bytes(data) + b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mstp_hcrc(data):
    """BACnet MS/TP header CRC (ASHRAE 135 Annex G), returned ready to send."""
    c = 0xFF
    for d in data:
        x = (c ^ d) & 0xFF
        x = x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4) ^ (x << 5) ^ (x << 6) ^ (x << 7)
        c = ((x & 0xFE) ^ ((x >> 8) & 1)) & 0xFF
    return (~c) & 0xFF


def lin_cs(data, pid=None):
    """LIN checksum: inverted 8-bit sum with carry (classic: data only;
    enhanced, LIN 2.x: protected identifier included)."""
    s = pid if pid is not None else 0
    for b in data:
        s += b
        if s > 255:
            s -= 255
    return (~s) & 0xFF


def lin_pid(fid):
    p0 = (fid ^ (fid >> 1) ^ (fid >> 2) ^ (fid >> 4)) & 1
    p1 = (~((fid >> 1) ^ (fid >> 3) ^ (fid >> 4) ^ (fid >> 5))) & 1
    return (fid & 0x3F) | (p0 << 6) | (p1 << 7)


def odd_parity(v, n):
    """Bit that makes the total number of ones (v + bit) odd."""
    return 1 - (bin(v & ((1 << n) - 1)).count("1") & 1)


def even_parity(v, n):
    return bin(v & ((1 << n) - 1)).count("1") & 1


# -------------------------------------------------------------- bit vectors
def msb(v, n):
    return [(v >> (n - 1 - i)) & 1 for i in range(n)]


def lsb(v, n):
    return [(v >> i) & 1 for i in range(n)]


def bytes_msb(data):
    out = []
    for b in data:
        out += msb(b, 8)
    return out


def bytes_lsb(data):
    out = []
    for b in data:
        out += lsb(b, 8)
    return out


def bits_to_int(bits):
    v = 0
    for b in bits:
        v = (v << 1) | (b & 1)
    return v


def pack_bits(bits):
    """MSB-first pack into bytes (last byte zero-padded)."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        out.append(bits_to_int(chunk + [0] * (8 - len(chunk))))
    return bytes(out)


def stuff(bits, run=5):
    """Insert a complementary bit after `run` identical bits (CAN style).
    Returns (stuffed bits, set of indices in the output that are stuff bits)."""
    out, pos = [], set()
    last, cnt = None, 0
    for b in bits:
        out.append(b)
        if b == last:
            cnt += 1
        else:
            last, cnt = b, 1
        if cnt == run:
            pos.add(len(out))
            out.append(1 - b)
            last, cnt = 1 - b, 1
    return out, pos


def hdlc_stuff(bits):
    """Zero insertion after five consecutive ones (HDLC, AIS, USB uses 6)."""
    out, pos, cnt = [], set(), 0
    for b in bits:
        out.append(b)
        cnt = cnt + 1 if b else 0
        if cnt == 5:
            pos.add(len(out))
            out.append(0)
            cnt = 0
    return out, pos


def usb_stuff(bits):
    out, pos, cnt = [], set(), 0
    for b in bits:
        out.append(b)
        cnt = cnt + 1 if b else 0
        if cnt == 6:
            pos.add(len(out))
            out.append(0)
            cnt = 0
    return out, pos


def nrzi(bits, start=1, zero_toggles=True):
    """NRZI: a 0 (USB, AIS) toggles the line, a 1 keeps it."""
    lvl, out = start, []
    for b in bits:
        if (b == 0) == zero_toggles:
            lvl ^= 1
        out.append(lvl)
    return out


def mlt3(bits):
    """MLT-3 (100BASE-TX): each 1 steps the cycle 0,+1,0,-1."""
    seq, i, out = (0, 1, 0, -1), 0, []
    for b in bits:
        if b:
            i = (i + 1) % 4
        out.append(seq[i])
    return out


B4B5 = [0b11110, 0b01001, 0b10100, 0b10101, 0b01010, 0b01011, 0b01110, 0b01111,
        0b10010, 0b10011, 0b10110, 0b10111, 0b11010, 0b11011, 0b11100, 0b11101]
B4B5_CTL = {"I": 0b11111, "J": 0b11000, "K": 0b10001, "T": 0b01101, "R": 0b00111, "H": 0b00100}


def enc4b5b(data, start=True, end=True):
    out = []
    if start:
        out += msb(B4B5_CTL["J"], 5) + msb(B4B5_CTL["K"], 5)
    for b in data:
        for nib in (b & 15, b >> 4):                 # low nibble first
            out += msb(B4B5[nib], 5)
    if end:
        out += msb(B4B5_CTL["T"], 5) + msb(B4B5_CTL["R"], 5)
    return out


def scramble100(bits, seed=0x7FF):
    """100BASE-TX side-stream scrambler, x^11 + x^9 + 1."""
    s, out = seed, []
    for b in bits:
        k = ((s >> 10) ^ (s >> 8)) & 1
        s = ((s << 1) | k) & 0x7FF
        out.append(b ^ k)
    return out


# 8b/10b (IEEE 802.3 clause 36 / ECSS SpaceFibre): 5b/6b and 3b/4b tables
_E6 = [  # (RD- code, RD+ code) written abcdei
    (0b100111, 0b011000), (0b011101, 0b100010), (0b101101, 0b010010), (0b110001, 0b110001),
    (0b110101, 0b001010), (0b101001, 0b101001), (0b011001, 0b011001), (0b111000, 0b000111),
    (0b111001, 0b000110), (0b100101, 0b100101), (0b010101, 0b010101), (0b110100, 0b110100),
    (0b001101, 0b001101), (0b101100, 0b101100), (0b011100, 0b011100), (0b010111, 0b101000),
    (0b011011, 0b100100), (0b100011, 0b100011), (0b010011, 0b010011), (0b110010, 0b110010),
    (0b001011, 0b001011), (0b101010, 0b101010), (0b011010, 0b011010), (0b111010, 0b000101),
    (0b110011, 0b001100), (0b100110, 0b100110), (0b010110, 0b010110), (0b110110, 0b001001),
    (0b001110, 0b001110), (0b101110, 0b010001), (0b011110, 0b100001), (0b101011, 0b010100)]
_E4 = [(0b1011, 0b0100), (0b1001, 0b1001), (0b0101, 0b0101), (0b1100, 0b0011),
       (0b1101, 0b0010), (0b1010, 0b1010), (0b0110, 0b0110), (0b1110, 0b0001)]


def _ones(v, n):
    return bin(v & ((1 << n) - 1)).count("1")


def enc8b10b(data, k=(), rd=-1):
    """Encode bytes to 10-bit symbols (bits in transmission order abcdei fghj).
    `k` = indices of bytes sent as K characters (K28.x). Returns (bits, rd)."""
    out = []
    for idx, byte in enumerate(data):
        x, y = byte & 31, byte >> 5
        if idx in k and x == 28:                         # K28.y
            c6 = 0b001111 if rd < 0 else 0b110000
        else:
            c6 = _E6[x][0 if rd < 0 else 1]
        d6 = _ones(c6, 6) - 3
        rd2 = rd if d6 == 0 else (1 if d6 > 0 else -1)
        if idx in k and x == 28:
            c4 = {0: (0b1011, 0b0100), 1: (0b0110, 0b1001), 2: (0b1010, 0b0101), 3: (0b1100, 0b0011),
                  4: (0b1101, 0b0010), 5: (0b0101, 0b1010), 6: (0b1001, 0b0110), 7: (0b0111, 0b1000)}[y][0 if rd2 < 0 else 1]
        elif y == 7 and ((rd2 < 0 and x in (17, 18, 20)) or (rd2 > 0 and x in (11, 13, 14))):
            c4 = 0b0111 if rd2 < 0 else 0b1000              # alternate D.x.A7
        else:
            c4 = _E4[y][0 if rd2 < 0 else 1]
        d4 = _ones(c4, 4) - 2
        rd = rd2 if d4 == 0 else (1 if d4 > 0 else -1)
        out += msb(c6, 6) + msb(c4, 4)
    return out, rd


# ---------------------------------------------------------- character sets
AIS6 = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"


def ais_armor(bits):
    """Pack an AIS bit string into NMEA 6-bit ASCII armour; returns (str, fill)."""
    fill = (-len(bits)) % 6
    bits = bits + [0] * fill
    out = []
    for i in range(0, len(bits), 6):
        v = bits_to_int(bits[i:i + 6])
        out.append(chr(v + 48 if v < 40 else v + 56))
    return "".join(out), fill


def six_text(s, n):
    """Text to AIS / Mode S 6-bit characters, padded with '@' (0)."""
    out = []
    for ch in (s.upper() + "@" * n)[:n]:
        out += msb(max(0, AIS6.find(ch)), 6)
    return out


def hexs(data, sep=" "):
    return sep.join("%02X" % b for b in data)


def bcd(v, ndig):
    out = 0
    for i in range(ndig):
        out |= (v % 10) << (4 * i)
        v //= 10
    return out


def f32be(v):
    return struct.pack(">f", float(v))


def f32le(v):
    return struct.pack("<f", float(v))


def f64be(v):
    return struct.pack(">d", float(v))


def be(v, n):
    return int(v & ((1 << (8 * n)) - 1)).to_bytes(n, "big")


def le(v, n):
    return int(v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
