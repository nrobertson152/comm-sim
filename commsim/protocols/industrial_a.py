"""Industrial automation, part A: Modbus RTU / ASCII / TCP, EtherNet/IP,
CIP, EtherCAT and PROFINET."""
import math
import struct
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, lrc, f32be
from .fam import serial_frame, char_time, IpNet, eth_pdu, udp_pdu, ipv4_pdu, macb

# ================================================================== Modbus
FC = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers", 5: "Write Single Coil",
      6: "Write Single Register", 8: "Diagnostics", 15: "Write Multiple Coils", 16: "Write Multiple Registers", 17: "Report Server ID",
      43: "Read Device Identification"}
EXC = {1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value", 4: "Server Device Failure", 5: "Acknowledge",
       6: "Server Device Busy", 10: "Gateway Path Unavailable", 11: "Gateway Target Device Failed to Respond"}


class MbServer:
    """A Modbus server (slave): coils, discrete inputs, input and holding registers."""

    def __init__(self, unit, name, hr=None, ir=None, coils=None, di=None, ident=("COMM-SIM", "GENERIC", "1.00"), names=None):
        self.unit, self.name = unit, name
        self.hr, self.ir = dict(hr or {}), dict(ir or {})
        self.coils, self.di = dict(coils or {}), dict(di or {})
        self.ident = ident
        self.names = names or {}

    def handle(self, pdu):
        fc = pdu[0]
        try:
            if fc in (1, 2):
                a, q = struct.unpack(">HH", pdu[1:5])
                src = self.coils if fc == 1 else self.di
                if not 1 <= q <= 2000:
                    return self.exc(fc, 3)
                if any((a + i) not in src for i in range(q)):
                    return self.exc(fc, 2)
                bits = [src[a + i] for i in range(q)]
                out = bytearray((q + 7) // 8)
                for i, b in enumerate(bits):
                    if b:
                        out[i // 8] |= 1 << (i % 8)
                return bytes([fc, len(out)]) + bytes(out)
            if fc in (3, 4):
                a, q = struct.unpack(">HH", pdu[1:5])
                src = self.hr if fc == 3 else self.ir
                if not 1 <= q <= 125:
                    return self.exc(fc, 3)
                if any((a + i) not in src for i in range(q)):
                    return self.exc(fc, 2)
                data = b"".join(struct.pack(">H", src[a + i] & 0xFFFF) for i in range(q))
                return bytes([fc, len(data)]) + data
            if fc == 5:
                a, v = struct.unpack(">HH", pdu[1:5])
                if a not in self.coils:
                    return self.exc(fc, 2)
                if v not in (0xFF00, 0x0000):
                    return self.exc(fc, 3)
                self.coils[a] = v == 0xFF00
                return pdu[:5]
            if fc == 6:
                a, v = struct.unpack(">HH", pdu[1:5])
                if a not in self.hr:
                    return self.exc(fc, 2)
                self.hr[a] = v
                return pdu[:5]
            if fc == 16:
                a, q, bc = struct.unpack(">HHB", pdu[1:6])
                if any((a + i) not in self.hr for i in range(q)):
                    return self.exc(fc, 2)
                for i in range(q):
                    self.hr[a + i] = struct.unpack(">H", pdu[6 + 2 * i:8 + 2 * i])[0]
                return pdu[:5]
            if fc == 15:
                a, q, bc = struct.unpack(">HHB", pdu[1:6])
                for i in range(q):
                    if (a + i) in self.coils:
                        self.coils[a + i] = bool(pdu[6 + i // 8] >> (i % 8) & 1)
                return pdu[:5]
            if fc == 8:
                return pdu
            if fc == 17:
                s = (self.name + " " + self.ident[1]).encode()
                return bytes([fc, len(s) + 1]) + s + b"\xff"
            if fc == 43 and len(pdu) > 1 and pdu[1] == 0x0E:
                objs = b"".join(bytes([i, len(v)]) + v.encode() for i, v in enumerate(self.ident))
                return bytes([43, 0x0E, 0x01, 0x01, 0x00, 0x00, len(self.ident)]) + objs
        except struct.error:
            return self.exc(fc, 3)
        return self.exc(fc, 1)

    @staticmethod
    def exc(fc, code):
        return bytes([fc | 0x80, code])


def mb_req(fc, a=0, q=1, vals=None):
    if fc in (1, 2, 3, 4):
        return struct.pack(">BHH", fc, a, q)
    if fc == 5:
        return struct.pack(">BHH", fc, a, 0xFF00 if vals else 0)
    if fc == 6:
        return struct.pack(">BHH", fc, a, vals & 0xFFFF)
    if fc == 16:
        vals = list(vals)
        return struct.pack(">BHHB", fc, a, len(vals), 2 * len(vals)) + b"".join(struct.pack(">H", v & 0xFFFF) for v in vals)
    if fc == 15:
        vals = list(vals)
        out = bytearray((len(vals) + 7) // 8)
        for i, b in enumerate(vals):
            if b:
                out[i // 8] |= 1 << (i % 8)
        return struct.pack(">BHHB", fc, a, len(vals), len(out)) + bytes(out)
    if fc == 8:
        return struct.pack(">BHH", 8, 0, 0xA537)
    if fc == 17:
        return bytes([17])
    if fc == 43:
        return bytes([43, 0x0E, 0x01, 0x00])
    return bytes([fc])


def mb_dissect(b, pdu, req=None, names=None, d=1, base=0):
    """Add Modbus PDU rows (function code + fields) to builder b; the PDU
    bytes are already in b starting at offset `base`."""
    names = names or {}
    fc = pdu[0]
    if fc & 0x80:
        b.rows.append([d, "Function Code: %d + 0x80 = exception response to %s" % (fc & 0x7F, FC.get(fc & 0x7F, "?")), base, 1,
                       "High bit set: the server could not perform the request."])
        code = pdu[1] if len(pdu) > 1 else 0
        b.rows.append([d, "Exception Code: %d (%s)" % (code, EXC.get(code, "?")), base + 1, 1,
                       {1: "Function not supported by this server.", 2: "Address range does not exist in this server.", 3: "Bad quantity or value.",
                        4: "Unrecoverable error while performing the action.", 6: "Server busy with a long command.",
                        10: "Gateway could not route to the target unit.", 11: "Gateway got no answer from the target."}.get(code, "")])
        return
    b.rows.append([d, "Function Code: %s (%d)" % (FC.get(fc, "?"), fc), base, 1, "What the server should do. 1-4 read, 5/6/15/16 write, 8 diagnostics, 43 device ID."])
    is_req = req is None
    if fc in (1, 2, 3, 4) and is_req and len(pdu) >= 5:
        a, q = struct.unpack(">HH", pdu[1:5])
        ref = {1: 0, 2: 10000, 3: 40000, 4: 30000}[fc]
        b.rows.append([d, "Starting Address: %d (0x%04X)  [classic %d]" % (a, a, ref + a + 1), base + 1, 2,
                       "Zero-based protocol address. Documentation often uses 1-based '4xxxx'/'3xxxx' numbering - the source of many off-by-one bugs."])
        b.rows.append([d, "Quantity: %d" % q, base + 3, 2, "Number of coils (max 2000) or registers (max 125) to read."])
    elif fc in (3, 4) and len(pdu) >= 2:
        bc = pdu[1]
        b.rows.append([d, "Byte Count: %d" % bc, base + 1, 1, "Bytes of register data that follow (2 per register)."])
        a0 = struct.unpack(">H", req[1:3])[0] if req and len(req) >= 3 else 0
        for i in range(bc // 2):
            v = struct.unpack(">H", pdu[2 + 2 * i:4 + 2 * i])[0]
            nm = names.get((fc, a0 + i), "")
            b.rows.append([d + 1, "Register %d: %d (0x%04X)%s" % (a0 + i, v, v, ("  " + nm) if nm else ""), base + 2 + 2 * i, 2,
                           "16-bit big-endian register. " + (nm or "")])
    elif fc in (1, 2) and not is_req:
        b.rows.append([d, "Byte Count: %d" % pdu[1], base + 1, 1, "Coil/input states packed 8 per byte, first coil in the LSB."])
        b.rows.append([d, "Status bits: %s" % " ".join(format(x, "08b")[::-1] for x in pdu[2:]), base + 2, len(pdu) - 2, "Bit order shown first coil first."])
    elif fc in (5, 6) and len(pdu) >= 5:
        a, v = struct.unpack(">HH", pdu[1:5])
        b.rows.append([d, "%s Address: %d" % ("Coil" if fc == 5 else "Register", a), base + 1, 2, ""])
        b.rows.append([d, "Value: 0x%04X%s" % (v, (" (ON)" if v == 0xFF00 else " (OFF)") if fc == 5 else " (%d)" % v), base + 3, 2,
                       "Coils use 0xFF00 = ON and 0x0000 = OFF. The server echoes the request when done."])
    elif fc in (15, 16) and len(pdu) >= 5:
        a, q = struct.unpack(">HH", pdu[1:5])
        b.rows.append([d, "Starting Address: %d" % a, base + 1, 2, ""])
        b.rows.append([d, "Quantity: %d" % q, base + 3, 2, ""])
        if is_req and len(pdu) > 6:
            b.rows.append([d, "Byte Count: %d" % pdu[5], base + 5, 1, ""])
            b.rows.append([d, "Values: %s" % pdu[6:].hex(" ").upper(), base + 6, len(pdu) - 6, ""])
    elif fc == 8 and len(pdu) >= 5:
        b.rows.append([d, "Sub-function: 0x%04X (Return Query Data)" % struct.unpack(">H", pdu[1:3])[0], base + 1, 2, "Loop-back test: the server echoes the data."])
        b.rows.append([d, "Data: 0x%04X" % struct.unpack(">H", pdu[3:5])[0], base + 3, 2, ""])
    elif fc == 43 and len(pdu) > 3:
        b.rows.append([d, "MEI type 0x0E (Read Device Identification), code %d" % pdu[2], base + 1, 2, "Basic objects: VendorName, ProductCode, MajorMinorRevision."])
        if not is_req and len(pdu) > 7:
            k = 7
            while k + 2 <= len(pdu):
                oid, ln = pdu[k], pdu[k + 1]
                b.rows.append([d + 1, "Object %d: %s" % (oid, pdu[k + 2:k + 2 + ln].decode("latin-1")), base + k, 2 + ln, ""])
                k += 2 + ln
    elif len(pdu) > 1:
        b.rows.append([d, "Data: %s" % pdu[1:].hex(" ").upper(), base + 1, len(pdu) - 1, ""])


def mb_info(pdu, req=None):
    fc = pdu[0]
    if fc & 0x80:
        return "Exception %d %s (fc %d)" % (pdu[1] if len(pdu) > 1 else 0, EXC.get(pdu[1] if len(pdu) > 1 else 0, "?"), fc & 0x7F)
    if req is None:
        if fc in (1, 2, 3, 4):
            a, q = struct.unpack(">HH", pdu[1:5])
            return "%s addr %d qty %d" % (FC[fc], a, q)
        if fc in (5, 6):
            a, v = struct.unpack(">HH", pdu[1:5])
            return "%s addr %d = 0x%04X" % (FC[fc], a, v)
        return FC.get(fc, "fc %d" % fc)
    if fc in (3, 4):
        regs = [struct.unpack(">H", pdu[2 + 2 * i:4 + 2 * i])[0] for i in range(pdu[1] // 2)]
        return "%s reply: %s" % (FC[fc].replace("Read ", ""), " ".join(str(r) for r in regs[:8]) + (" ..." if len(regs) > 8 else ""))
    return "%s reply" % FC.get(fc, "fc %d" % fc)


def f32regs(v, swap=False):
    hi, lo = struct.unpack(">HH", f32be(v))
    return (lo, hi) if swap else (hi, lo)


def regs_f32(hi, lo):
    return struct.unpack(">f", struct.pack(">HH", hi, lo))[0]


class ModbusSerial(Scenario):
    """Shared Modbus master + three slaves on RS-485 (RTU or ASCII)."""
    cat = "ind"
    phy = "rs485"
    ascii = False
    nets = [("A", "RS-485 A"), ("B", "RS-485 B"), ("VDIFF", "B - A")]
    lines = ["D", "DE"]

    def build(self):
        self.baud = 9600 if self.ascii else 19200
        m = self.node("m", "HMI / MASTER", "hmi", 30, 40, "client", "polls every 100 ms")
        s1 = self.node("s1", "VFD", "drive", 230, 260, "slave 1", "pump drive")
        s2 = self.node("s2", "POWER METER", "meter", 470, 260, "slave 2", "3-phase")
        s3 = self.node("s3", "TEMP CONTROLLER", "tstat", 700, 260, "slave 3", "PID")
        for n in (s1, s2, s3):
            n.at_top()
        self.trunk(180, 60, 850, [m, s1, s2, s3], "rs485", net="VDIFF", label="RS-485 2-wire, %d %s" % (self.baud, "7E1" if self.ascii else "8E1"), t0=True, t1=True)
        self.user = "m"
        self.srv = {
            1: MbServer(1, "VFD", hr={0: 0x047F, 1: 4500}, ir={0: 4498, 1: 112, 2: 565, 3: 0x0003},
                        ident=("COMM-SIM DRIVES", "VFD-22", "2.10"), names={(3, 0): "control word", (3, 1): "speed ref 0.01 Hz", (4, 0): "output freq 0.01 Hz",
                                                                              (4, 1): "motor current 0.1 A", (4, 2): "DC bus V", (4, 3): "status word"}),
            2: MbServer(2, "METER", ir={i: 0 for i in range(12)}, hr={100: 1, 101: 5},
                        ident=("COMM-SIM METERING", "PM-3300", "1.4"), names={(4, 0): "V L-N float hi", (4, 1): "V L-N float lo", (4, 2): "I avg float hi",
                                                                               (4, 3): "I avg float lo", (4, 4): "kW float hi", (4, 5): "kW float lo",
                                                                               (4, 6): "kWh float hi", (4, 7): "kWh float lo", (4, 8): "Hz float hi", (4, 9): "Hz float lo"}),
            3: MbServer(3, "TEMP", hr={0: 652, 1: 650, 2: 37}, coils={0: True, 1: False},
                        ident=("COMM-SIM CONTROLS", "TC-48", "3.0"), names={(3, 0): "PV x0.1 degC", (3, 1): "SP x0.1 degC", (3, 2): "output %"}),
        }
        s1.vars.update({"Speed ref Hz": 45.0})
        s1.ctl = [("Speed ref Hz", "SPEED REF", 0.0, 60.0, 0, lambda v: "%.1f Hz" % v)]
        s2.vars.update({"Load kW": 18.5})
        s2.ctl = [("Load kW", "LOAD", 0.0, 60.0, 0, lambda v: "%.1f kW" % v)]
        s3.vars.update({"Temperature C": 65.2})
        s3.ctl = [("Temperature C", "TEMP", 0.0, 150.0, 0, lambda v: "%.1f" % v)]
        m.vars.update({"VFD freq": "-", "Meter V": "-", "Meter kW": "-", "TC PV": "-", "Timeouts": 0, "CRC/LRC errors": 0, "Exceptions": 0})
        self.kwh = 1523.0
        self.k = 0
        self.pending = None
        self.every(0.1, self.poll, 0.01)
        self.every(0.1, self.physics, 0.05)

    def physics(self):
        s1 = self.srv[1]
        ref = self.by["s1"].vars["Speed ref Hz"]
        s1.hr[1] = int(ref * 100)
        out = s1.ir[0] / 100.0
        out += (ref - out) * 0.2
        s1.ir[0] = int(out * 100)
        s1.ir[1] = int(10 + out * 2.2)
        kw = self.by["s2"].vars["Load kW"]
        self.kwh += kw * 0.1 / 3600
        v = 230.4 + float(self.rng.normal(0, 0.3))
        regs = f32regs(v) + f32regs(kw * 1000 / (3 * v)) + f32regs(kw) + f32regs(self.kwh) + f32regs(50.0 + float(self.rng.normal(0, 0.01)))
        for i, r in enumerate(regs):
            self.srv[2].ir[i] = r
        self.srv[3].hr[0] = int(self.by["s3"].vars["Temperature C"] * 10)

    # framing --------------------------------------------------------------
    def adu(self, unit, pdu, req=None, info=None, names=None):
        if self.ascii:
            body = bytes([unit]) + pdu
        """Return (Pdu, info)."""
        names = names or (self.srv[unit].names if unit in self.srv else {})
        if self.ascii:
            body = bytes([unit]) + pdu
            l_ = lrc(body)
            txt = ":" + (body + bytes([l_])).hex().upper() + "\r\n"
            b = Bld("Modbus ASCII", "Each byte sent as two hexadecimal ASCII characters, framed by ':' and CR LF, checked by an LRC.")
            b.text("Start", ":", "Colon starts every ASCII frame (resynchronises receivers).")
            b.text("Address", txt[1:3], "Slave address %d as two hex characters." % unit)
            b.text("PDU (hex text)", txt[3:-4], "Function code and data as hex characters.")
            o = len(b.b) - len(txt[3:-4])
            del o
            b.text("LRC", txt[-4:-2], "Longitudinal Redundancy Check 0x%02X: two's complement of the 8-bit sum of address + PDU bytes." % l_)
            b.text("End", "\r\n", "CR LF ends the frame.")
            inner = Bld("Modbus PDU (decoded from the hex text)", "")
            inner.raw("Address", bytes([unit]), str(unit), "")
            for r in []:
                pass
            p = b.done()
            p.rows.append([0, "Modbus PDU (decoded from the hex)", None, 0, "The bytes the hex characters stand for."])
            dec = Bld()
            dec.raw("", pdu, "")
            sub = Bld()
            sub.b = bytearray(pdu)
            mb_dissect(sub, pdu, req, names, d=1, base=0)
            for r in sub.rows:
                p.rows.append([r[0], r[1], None, 0, r[4]])
            return p
        crc = crcn("CRC-16/MODBUS", bytes([unit]) + pdu)
        b = Bld("Modbus RTU", "Binary Modbus framing for serial lines; frames are separated by >= 3.5 character times of silence.")
        b.u8("Slave Address", unit, "%d" % unit, "1-247 = one slave, 0 = broadcast (no reply). The reply carries the same address.")
        base = len(b.b)
        b.b += pdu
        mb_dissect(b, pdu, req, names, d=1, base=base)
        b.u16("CRC", crc, "0x%04X [correct], sent low byte first" % crc, "CRC-16/MODBUS (poly 0xA001 reflected, init 0xFFFF) over address + PDU.", little=True)
        return b.done()

    def mkframe(self, src, dst, unit, pdu, req=None, kind="cmd", err=None, corrupt=False):
        p = self.adu(unit, pdu, req)
        info = mb_info(pdu, req)
        if self.ascii:
            fr = serial_frame(self, src, dst, "Modbus ASCII", info, p, self.baud, 7, "E", 1, rs485=2, kind=kind, err=err,
                              key=("Q%d fc%d" % (unit, pdu[0])) if req is None else ("R%d fc%d" % (unit, pdu[0] & 0x7F)))
        else:
            gap = (2.0 * char_time(self.baud, 8, "E")) if (self.fault.get("gap") and src == "s2") else 0.0
            fr = serial_frame(self, src, dst, "Modbus RTU", info, p, self.baud, 8, "E", 1, rs485=2, kind=kind, err=err, gap=gap if gap else 0.0,
                              key=("Q%d fc%d" % (unit, pdu[0])) if req is None else ("R%d fc%d" % (unit, pdu[0] & 0x7F)))
        fr.meta.update(unit=unit, pdu=pdu, req=req)
        return fr

    def poll(self):
        if not self.by["m"].on:
            return
        self.k = self.k % 3 + 1
        unit, pdu = {1: (1, mb_req(4, 0, 4)), 2: (2, mb_req(4, 0, 10)), 3: (3, mb_req(3, 0, 3))}[self.k]
        if self.fault.get("wrongaddr") and unit == 3:
            unit = 4
        self.request(unit, pdu)

    def request(self, unit, pdu):
        dst = "s%d" % unit if unit in (1, 2, 3) else None
        fr = self.mkframe("m", dst, unit, pdu)
        self.tx(fr)
        tok = object()
        self.pending = tok
        self.at(self.t + 0.09, self.timeout, tok, unit)
        return fr

    def timeout(self, tok, unit):
        if self.pending is tok:
            self.by["m"].vars["Timeouts"] += 1
            self.log("Timeout: no reply from unit %d" % unit)
            self.pending = None

    def rx(self, fr):
        unit = fr.meta.get("unit")
        if fr.src == "m":
            srv = self.srv.get(unit)
            n = self.by.get("s%d" % unit)
            if srv is None or n is None or not n.on or fr.err:
                return
            if self.fault.get("offline") and unit == 3:
                return
            rsp = srv.handle(fr.meta["pdu"])
            err = None
            if self.fault.get("noise") and self.rng.random() < 0.3:
                err = ("LRC" if self.ascii else "CRC") + " mismatch: reply corrupted by noise"
            if self.fault.get("gap") and unit == 2:
                err = "Inter-character gap > 1.5 chars: master saw two broken frames"
            if self.fault.get("fast") and self.rng.random() < 0.4:
                err = "Reply collided with the next poll (no 3.5-char silence)"
            r = self.mkframe("s%d" % unit, "m", unit, rsp, fr.meta["pdu"], "resp" if not rsp[0] & 0x80 else "err", err)
            r.t = self.t + (0.0004 if self.fault.get("fast") else 0.004)
            self.tx(r)
        elif fr.dst == "m":
            m = self.by["m"]
            self.pending = None
            if fr.err:
                m.vars["CRC/LRC errors"] += 1
                return
            pdu = fr.meta["pdu"]
            if pdu[0] & 0x80:
                m.vars["Exceptions"] += 1
                return
            req = fr.meta["req"]
            if pdu[0] in (3, 4):
                regs = [struct.unpack(">H", pdu[2 + 2 * i:4 + 2 * i])[0] for i in range(pdu[1] // 2)]
                if unit == 1 and pdu[0] == 4:
                    m.vars["VFD freq"] = "%.2f Hz" % (regs[0] / 100.0)
                elif unit == 2 and len(regs) >= 6:
                    sw = self.fault.get("swap")
                    v = regs_f32(regs[1], regs[0]) if sw else regs_f32(regs[0], regs[1])
                    kw = regs_f32(regs[5], regs[4]) if sw else regs_f32(regs[4], regs[5])
                    m.vars["Meter V"] = "%.4g V" % v + ("  (word order wrong!)" if sw else "")
                    m.vars["Meter kW"] = "%.4g kW" % kw
                elif unit == 3:
                    m.vars["TC PV"] = "%.1f degC" % (regs[0] / 10.0)

    def tpls(self):
        units = [1, 2, 3]
        return [Tpl("Read registers (03/04)", [P("u", "Slave", 1, 1, 247), P("fc", "Function", 3, opts=[3, 4]), P("a", "Start address", 0, 0, 65535), P("q", "Quantity", 4, 1, 125)],
                    lambda s, v, send: self._q(v["u"], mb_req(v["fc"], v["a"], v["q"]), send), "FC03 holding registers / FC04 input registers. Try address 500 for an Illegal Data Address exception."),
                Tpl("Write single register (06)", [P("u", "Slave", 1, 1, 247), P("a", "Address", 1, 0, 65535), P("v", "Value", 3000, 0, 65535)],
                    lambda s, v, send: self._q(v["u"], mb_req(6, v["a"], 0, v["v"]), send), "Slave 1 register 1 is the drive speed reference in 0.01 Hz."),
                Tpl("Write multiple registers (16)", [P("u", "Slave", 3, 1, 247), P("a", "Start", 1, 0, 65535), P("v1", "Value 1", 700, 0, 65535), P("v2", "Value 2", 40, 0, 65535)],
                    lambda s, v, send: self._q(v["u"], mb_req(16, v["a"], 0, [v["v1"], v["v2"]]), send), "Slave 3: register 1 setpoint (x0.1 degC), register 2 output %."),
                Tpl("Write single coil (05)", [P("u", "Slave", 3, 1, 247), P("a", "Coil", 0, 0, 65535), P("on", "State", "ON", opts=["ON", "OFF"])],
                    lambda s, v, send: self._q(v["u"], mb_req(5, v["a"], 0, v["on"] == "ON"), send), "Coil 0 on slave 3 = controller run/stop."),
                Tpl("Read device identification (43/14)", [P("u", "Slave", 1, 1, 247)], lambda s, v, send: self._q(v["u"], mb_req(43), send), "Vendor, product code and revision strings."),
                Tpl("Diagnostics echo (08)", [P("u", "Slave", 2, 1, 247)], lambda s, v, send: self._q(v["u"], mb_req(8), send), "Return Query Data: proves the link end to end."),
                Tpl("Illegal function (fc 0x41)", [P("u", "Slave", 1, 1, 247)], lambda s, v, send: self._q(v["u"], bytes([0x41, 0, 0]), send), "Provokes exception 01.")]

    def _q(self, unit, pdu, send):
        if send:
            return self.request(unit, pdu)
        return self.mkframe("m", None, unit, pdu)

    def inspect(self, n):
        rows = list(n.vars.items())
        if n.id.startswith("s"):
            srv = self.srv[int(n.id[1])]
            for (fc, a), nm in list(srv.names.items())[:8]:
                src = srv.hr if fc == 3 else srv.ir
                rows.append(("%s %d %s" % ("HR" if fc == 3 else "IR", a, nm), src.get(a, "-")))
        return rows


class ModbusRTU(ModbusSerial):
    key, name = "modbus_rtu", "Modbus RTU"
    blurb = "Serial PLCs, sensors, meters"
    rate = 19200
    medium = "Modbus RTU over RS-485 2-wire, 19200 bit/s 8E1, master + 3 slaves"
    faults = [("noise", "Electrical noise on the bus", "Some replies arrive with a bad CRC; the master must discard them and retry."),
              ("offline", "Temperature controller (slave 3) offline", "No reply: the master times out after its response timeout."),
              ("wrongaddr", "Master configured to poll slave 4 instead of 3", "Nobody has address 4 - permanent timeouts."),
              ("gap", "Meter pauses > 1.5 char inside its replies", "RTU uses silence to find frame boundaries; a long gap splits the reply into two invalid frames."),
              ("fast", "Master polls without the 3.5-char gap", "Frames run into each other, so receivers cannot find the boundaries."),
              ("swap", "Master decodes floats with the wrong word order", "Modbus has no float type: 32-bit values span two registers and vendors disagree on which comes first.")]
    spec = [("Standard", "Modbus Application Protocol V1.1b3 + Modbus over Serial Line V1.02 (modbus.org)"), ("Transport", "RS-485 (or RS-232), 8 data bits, even parity by default"),
            ("Model", "Single master (client) polls up to 247 slaves (servers); slaves never speak unasked"),
            ("Data", "Coils (1-bit RW), discrete inputs (1-bit RO), input registers (16-bit RO), holding registers (16-bit RW)"),
            ("Framing", "Address + PDU + CRC-16; frames delimited by >= 3.5 character times of silence"),
            ("Limits", "PDU <= 253 bytes: 125 registers or 2000 coils per read"), ("Exceptions", "Function code | 0x80 + exception code")]
    frame = [["RTU ADU", ("Address", 8), ("Function", 8), ("Data", "0-252 B"), ("CRC lo", 8), ("CRC hi", 8)],
             ["FC03 request", ("Addr", 8), ("03", 8), ("Start", 16), ("Quantity", 16), ("CRC", 16)]]
    about = ("Modbus RTU is the lingua franca of industrial devices: a master asks, a slave answers, and every message carries the slave address, a "
             "function code, the data and a CRC. There are no data types beyond 16-bit registers and bits, so a device's register map (in its manual) "
             "says what each register means - including how 32-bit floats are split across two registers.")
    guide = ["Select a FC04 reply from the power meter: registers 0-1 are a 32-bit float (voltage).",
             "Inject the word-order fault and read the meter values in the HMI's DEVICE panel.",
             "COMPOSE: read 2 registers from address 500 on slave 1 - Illegal Data Address exception.",
             "Watch the gap between frames in LOGIC: at 19200 bit/s, 3.5 characters = 2 ms of silence.",
             "Inject the >1.5 char gap fault and read the error."]


class ModbusASCII(ModbusSerial):
    key, name = "modbus_ascii", "Modbus ASCII"
    blurb = "Legacy serial industrial equipment"
    ascii = True
    rate = 9600
    medium = "Modbus ASCII over RS-485, 9600 bit/s 7E1, hex characters, ':' ... CR LF, LRC"
    faults = [("noise", "Electrical noise on the bus", "A flipped bit changes a hex character; the LRC check fails."),
              ("offline", "Temperature controller (slave 3) offline", "Timeouts on every poll of slave 3."),
              ("wrongaddr", "Master polls slave 4", "No such slave."),
              ("swap", "Master decodes floats with the wrong word order", "Same pitfall as RTU.")]
    spec = [("Standard", "Modbus over Serial Line V1.02, ASCII mode"), ("Characters", "7 data bits, even parity, 1 stop (7E1) typical"),
            ("Framing", "':' + address + function + data as hex characters + LRC + CR LF"), ("Check", "LRC: two's complement of the 8-bit sum"),
            ("Timing", "Up to 1 s between characters allowed - works over modems and slow links"), ("Cost", "Twice the characters of RTU for the same data")]
    frame = [["ASCII ADU", (":", 8), ("Address 2 ch", 16), ("Function 2 ch", 16), ("Data 2n ch", "2n x 8"), ("LRC 2 ch", 16), ("CR LF", 16)]]
    about = ("Modbus ASCII sends the same messages as RTU but writes every byte as two printable hex characters. Frames start with ':' and end "
             "with CR LF, so timing gaps do not matter and you can read the traffic in a terminal. The price is double the size and a weaker LRC check.")
    guide = ["Look at the hex dump: the bytes are ASCII digits and letters - readable text.",
             "Verify the LRC by hand: add the address and PDU bytes, negate the 8-bit result.",
             "Compare frame durations with Modbus RTU in the ANALYZER."]


class ModbusTCP(IpNet):
    key, name, cat = "modbus_tcp", "Modbus TCP", "ind"
    blurb = "Ethernet-based industrial communication"
    medium = "Modbus TCP on port 502: SCADA client, native Modbus TCP PLC, and a TCP/RTU gateway to RS-485 slaves"
    faults = [("gwtimeout", "RTU slave behind the gateway silent", "The gateway answers for it with exception 0x0B 'Gateway Target Device Failed to Respond'."),
              ("unit", "SCADA uses unit ID 9 (not configured in the gateway)", "The gateway has no route: exception 0x0A 'Gateway Path Unavailable'."),
              ("refused", "PLC port 502 closed (service disabled)", "The TCP SYN is answered with RST: connection refused."),
              ("txid", "Client reuses transaction IDs", "With several requests in flight the client cannot match replies to requests (MBAP transaction ID).")]
    spec = [("Standard", "Modbus Messaging on TCP/IP Implementation Guide V1.0b"), ("Port", "TCP 502 (802 for Modbus/TCP Security with TLS)"),
            ("Header", "MBAP: transaction ID, protocol ID (0), length, unit ID - replaces address + CRC (TCP already checks integrity)"),
            ("Unit ID", "Selects a slave behind a gateway; 0xFF / 0 for a native device"), ("Concurrency", "Several transactions may be in flight, matched by transaction ID")]
    frame = [["Modbus TCP ADU", ("Transaction ID", 16), ("Protocol ID 0", 16), ("Length", 16), ("Unit ID", 8), ("Function", 8), ("Data", "n x 8")]]
    about = ("Modbus TCP wraps the same PDU in a 7-byte MBAP header and sends it over a TCP connection to port 502. The CRC disappears because "
             "TCP and Ethernet already check integrity. The unit ID lets a gateway forward requests to serial slaves - so one SCADA client can reach "
             "an old RS-485 network across the plant LAN.")
    guide = ["Watch the TCP three-way handshake in FLOW before the first Modbus request.",
             "Select a request: Ethernet > IPv4 > TCP > Modbus/TCP. Click 'Transaction Identifier' and match it to the reply.",
             "Inject 'RTU slave silent' and see the gateway answer with exception 11 on behalf of the slave.",
             "Close port 502 on the PLC: SYN, then RST."]

    def setup(self):
        hosts = [("scada", "SCADA", "scada", 40, 40, "10.0.0.10", "00:0c:29:10:00:10"), ("plc", "PLC (native)", "plc", 700, 40, "10.0.0.20", "00:1d:9c:00:00:20"),
                 ("gw", "TCP/RTU GATEWAY", "gw", 700, 290, "10.0.0.30", "00:30:de:00:00:30")]
        self.star(hosts)
        rtu = self.node("rtu", "RTU SLAVE 7", "meter", 380, 300, "RS-485 slave", "behind gateway")
        rtu.at_right()
        self.seg([rtu.port, (self.by["gw"].x, rtu.port[1])], "rs485", net=None, label="RS-485", c0="screw", c1="screw")
        rtu.extra["can"] = False
        self.user = "scada"
        self.plc = MbServer(255, "PLC", hr={i: 100 + i for i in range(20)}, ir={i: i * 3 for i in range(10)}, ident=("COMM-SIM PLC", "CPU-1215", "4.5"))
        self.slave = MbServer(7, "RTU7", hr={0: 412, 1: 55}, ir={0: 2301, 1: 18})
        self.txid = 0
        self.c1 = self.c2 = None
        self.by["scada"].vars.update({"Connections": 0, "Last": "-"})
        self.at(0.05, self.connect)
        self.every(0.25, self.cycle, 0.3)

    def connect(self):
        self.c1 = self.tcp("scada", "plc", 50211, 502, "Modbus/TCP")
        self.c2 = self.tcp("scada", "gw", 50212, 502, "Modbus/TCP")
        if self.fault["refused"]:
            c1 = self.c1
            c1.seg("scada", 0x02)
            self.at(self.t + 0.0002, lambda: c1.reset("plc"))
            self.c1 = None
        else:
            self.c1.connect()
        self.c2.connect()
        self.by["scada"].vars["Connections"] = 2 if self.c1 else 1

    def mbap(self, tid, unit, pdu, req=None):
        b = Bld("Modbus/TCP", "MBAP header + Modbus PDU.")
        b.u16("Transaction Identifier", tid, None, "Chosen by the client; the server copies it into the reply so requests and replies can be paired.")
        b.u16("Protocol Identifier", 0, "0 (Modbus)", "Always 0.")
        b.u16("Length", len(pdu) + 1, None, "Bytes that follow: unit ID + PDU.")
        b.u8("Unit Identifier", unit, "%d%s" % (unit, " (native device)" if unit == 255 else " (serial slave behind gateway)"), "Addresses a slave behind a gateway.")
        base = len(b.b)
        b.b += pdu
        mb_dissect(b, pdu, req, {}, 1, base)
        return b.done()

    def cycle(self):
        if not self.by["scada"].on:
            return
        if self.c1 and self.c1.open:
            self.ask(self.c1, 255, mb_req(3, 0, 10))
        if self.c2 and self.c2.open:
            self.ask(self.c2, 9 if self.fault["unit"] else 7, mb_req(4, 0, 2))

    def ask(self, conn, unit, pdu):
        self.txid = (self.txid + (0 if self.fault["txid"] else 1)) & 0xFFFF
        tid = self.txid
        fr = conn.send("scada", self.mbap(tid, unit, pdu), "Query TID %d unit %d: %s" % (tid, unit, mb_info(pdu)), "Modbus/TCP", "cmd", auto_ack=False)
        dev = conn.srv

        def reply():
            if not self.by[dev].on:
                return
            if dev == "plc":
                rsp = self.plc.handle(pdu)
                lat = 0.0008
            else:
                if unit != 7:
                    rsp = bytes([pdu[0] | 0x80, 10])
                    lat = 0.0005
                elif self.fault["gwtimeout"]:
                    rsp = bytes([pdu[0] | 0x80, 11])
                    lat = 0.08
                else:
                    rsp = self.slave.handle(pdu)
                    lat = 0.012
            self.at(self.t + lat, lambda: self._rsp(conn, tid, unit, rsp, pdu))
        self.at(self.t + 0.0003, reply)
        return fr

    def _rsp(self, conn, tid, unit, rsp, req):
        if not conn.open:
            return
        k = "err" if rsp[0] & 0x80 else "resp"
        conn.send(conn.srv, self.mbap(tid, unit, rsp, req), "Response TID %d unit %d: %s" % (tid, unit, mb_info(rsp, req)), "Modbus/TCP", k)
        self.by["scada"].vars["Last"] = mb_info(rsp, req)

    def on_fault(self, key, on):
        if key == "refused":
            self.at(self.t + 0.01, self.connect)

    def tpls(self):
        return [Tpl("Read holding registers", [P("dev", "Target", "plc", opts=["plc", "gw"]), P("u", "Unit ID", 255, 0, 255), P("a", "Start", 0, 0, 65535), P("q", "Quantity", 5, 1, 125)],
                    lambda s, v, send: self._ask(v, mb_req(3, v["a"], v["q"]), send), "Unit 255 = the PLC itself; via the gateway use unit 7."),
                Tpl("Write single register", [P("dev", "Target", "plc", opts=["plc", "gw"]), P("u", "Unit ID", 255, 0, 255), P("a", "Address", 2, 0, 65535), P("v", "Value", 1234, 0, 65535)],
                    lambda s, v, send: self._ask(v, mb_req(6, v["a"], 0, v["v"]), send), "FC06 write.")]

    def _ask(self, v, pdu, send):
        conn = self.c1 if v["dev"] == "plc" else self.c2
        if send and conn and conn.open:
            return self.ask(conn, v["u"], pdu)
        return Frame(self.t, 0.0001, "scada", v["dev"], "Modbus/TCP", mb_info(pdu), pdu=self.mbap(self.txid + 1, v["u"], pdu))


# ============================================================ EtherNet/IP
ENC_CMD = {0x0063: "ListIdentity", 0x0065: "RegisterSession", 0x0066: "UnRegisterSession", 0x006F: "SendRRData", 0x0070: "SendUnitData", 0x0004: "ListServices"}
CIP_SVC = {0x01: "Get_Attributes_All", 0x0E: "Get_Attribute_Single", 0x10: "Set_Attribute_Single", 0x4C: "Read_Tag", 0x4D: "Write_Tag",
           0x52: "Unconnected_Send", 0x54: "Forward_Open", 0x4E: "Forward_Close", 0x05: "Reset"}
CIP_CLASS = {0x01: "Identity", 0x02: "Message Router", 0x04: "Assembly", 0x06: "Connection Manager", 0xF5: "TCP/IP Interface", 0xF6: "Ethernet Link", 0x0F: "Parameter"}
CIP_STATUS = {0x00: "Success", 0x01: "Connection failure", 0x04: "Path segment error", 0x05: "Path destination unknown", 0x08: "Service not supported",
              0x0E: "Attribute not settable", 0x14: "Attribute not supported", 0x16: "Object does not exist", 0x0C: "Object state conflict"}


def cip_path(cls, inst, attr=None):
    p = bytes([0x20, cls, 0x24, inst]) + (bytes([0x30, attr]) if attr is not None else b"")
    return p


def cip_req_pdu(svc, path, data=b""):
    b = Bld("Common Industrial Protocol", "CIP explicit request: service code + EPATH (class / instance / attribute) + data.")
    b.u8("Service", svc, "%s (0x%02X)" % (CIP_SVC.get(svc, "?"), svc), "What to do with the addressed object.")
    b.u8("Request Path Size", len(path) // 2, "%d words" % (len(path) // 2), "EPATH length in 16-bit words.")
    o = b.f("Request Path", path, " ".join("%02X" % x for x in path), "Logical segments: 0x20 class, 0x24 instance, 0x30 attribute (8-bit forms).")
    segs = []
    for i in range(0, len(path) - 1, 2):
        t, v = path[i], path[i + 1]
        nm = {0x20: "Class", 0x24: "Instance", 0x30: "Attribute", 0x01: "Port"}.get(t, "seg 0x%02X" % t)
        segs.append("%s 0x%02X%s" % (nm, v, (" (%s)" % CIP_CLASS.get(v, "")) if t == 0x20 and v in CIP_CLASS else ""))
    b.note(" / ".join(segs), "", d=2, off=o, n=len(path))
    if data:
        b.raw("Request Data", data, None, "")
    return b.done()


def cip_rsp_pdu(svc, status, data=b"", desc=""):
    b = Bld("Common Industrial Protocol (response)", "")
    b.u8("Service", svc | 0x80, "%s reply (0x%02X)" % (CIP_SVC.get(svc, "?"), svc | 0x80), "Request service code with bit 7 set.")
    b.u8("Reserved", 0, None, "")
    b.u8("General Status", status, "0x%02X %s" % (status, CIP_STATUS.get(status, "")), "0 = success. Non-zero codes are the CIP general status table.")
    b.u8("Additional Status Size", 0, None, "")
    if data:
        b.raw("Response Data", data, desc or None, desc)
    return b.done()


def enc_pdu(cmd, session, inner_items, context=b"COMMSIM\0", status=0):
    """EtherNet/IP encapsulation header + Common Packet Format items."""
    body = Bld()
    if inner_items is not None:
        body.u32("Interface Handle", 0, None, "0 = CIP", little=True)
        body.u16("Timeout", 0, None, "", little=True)
        body.u16("Item Count", len(inner_items), None, "Common Packet Format items", little=True)
        for tid, payload, name in inner_items:
            body.u16("Type ID", tid, "0x%04X (%s)" % (tid, name), {0x0000: "Null address item (unconnected)", 0x00B2: "Unconnected data item",
                                                                0x00A1: "Connected address item", 0x00B1: "Connected data item", 0x8002: "Sequenced address item"}.get(tid, ""), little=True)
            body.u16("Length", len(payload.b) if isinstance(payload, Pdu) else len(payload), None, "", little=True)
            if isinstance(payload, Pdu):
                body.sub(payload, 0)
            elif payload:
                body.raw("Data", payload, None, "")
    inner = body.done()
    b = Bld("EtherNet/IP (Industrial Protocol), Session: 0x%08X, %s" % (session, ENC_CMD.get(cmd, "?")), "ODVA encapsulation header (24 bytes, little-endian) over TCP or UDP 44818.")
    b.u16("Command", cmd, "%s (0x%04X)" % (ENC_CMD.get(cmd, "?"), cmd), "Encapsulation command.", little=True)
    b.u16("Length", len(inner.b), None, "Bytes after the 24-byte header.", little=True)
    b.u32("Session Handle", session, "0x%08X" % session, "Returned by RegisterSession; required on every later explicit message.", little=True)
    b.u32("Status", status, "Success" if status == 0 else "0x%X" % status, "", little=True)
    b.f("Sender Context", context, context.hex(" "), "Echoed back by the target to pair replies.")
    b.u32("Options", 0, None, "", little=True)
    b.sub(inner, 0)
    return b.done()


class EtherNetIP(IpNet):
    key, name, cat = "ethernetip", "EtherNet/IP", "ind"
    blurb = "PLCs and industrial automation"
    medium = "ODVA EtherNet/IP: scanner PLC, I/O adapter and drive; explicit TCP 44818, implicit UDP 2222 at the RPI"
    faults = [("rpi", "RPI set to 1 ms for the slow I/O adapter", "The adapter cannot produce that fast; packets go missing and after 4 x RPI the connection times out (I/O fault)."),
              ("off", "I/O adapter powered down", "The scanner's connection timeout fires and it retries Forward_Open."),
              ("mcast", "T->O multicast without IGMP snooping", "Multicast I/O floods every switch port: the HMI receives all the cyclic data it never asked for."),
              ("conflict", "Duplicate IP on the drive", "ARP conflict: two devices answer for the same address.")]
    spec = [("Standard", "ODVA CIP Networks Library Vol. 1 (CIP) + Vol. 2 (EtherNet/IP adaptation)"), ("Explicit", "TCP 44818: RegisterSession, SendRRData / SendUnitData carrying CIP services"),
            ("Implicit (I/O)", "UDP 2222: cyclic connected data at the Requested Packet Interval (RPI)"), ("Connections", "Forward_Open to the Connection Manager establishes O->T and T->O connection IDs"),
            ("Timeout", "Connection timeout = RPI x timeout multiplier (typically 4x)"), ("Discovery", "ListIdentity broadcast on UDP 44818")]
    frame = [["Encapsulation header", ("Command", 16), ("Length", 16), ("Session", 32), ("Status", 32), ("Context", 64), ("Options", 32)],
             ["Implicit I/O (UDP 2222)", ("Seq addr item: conn ID + seq", 96), ("Connected data: seq count", 16), ("Run/Idle", 32), ("I/O data", "n x 8")]]
    about = ("EtherNet/IP carries CIP over standard Ethernet. Configuration and on-demand data use explicit messages over TCP: the scanner "
             "registers a session and sends CIP services. Real-time I/O uses implicit connections: a Forward_Open request agrees connection IDs and "
             "a Requested Packet Interval, then both ends send UDP packets on that period without any request/response.")
    guide = ["Watch the start-up in FLOW: ListIdentity, RegisterSession, Forward_Open, then cyclic UDP I/O.",
             "Select an I/O packet and find the sequence count and the 32-bit run/idle header.",
             "STATS: the I/O packets appear at exactly the RPI.",
             "Set the RPI fault and watch the connection time out after four missed intervals."]

    def setup(self):
        hosts = [("plc", "SCANNER PLC", "plc", 40, 40, "192.168.1.1", "00:00:bc:01:01:01"), ("hmi", "HMI", "hmi", 700, 40, "192.168.1.50", "00:0e:c6:50:50:50"),
                 ("io", "I/O ADAPTER", "io", 40, 290, "192.168.1.20", "00:00:bc:20:20:20"), ("vfd", "VFD", "drive", 700, 290, "192.168.1.30", "00:00:bc:30:30:30")]
        self.star(hosts)
        self.user = "plc"
        self.sess = {}
        self.conn = {}
        self.seq = {}
        self.by["io"].vars.update({"Inputs": 0x00A5, "Outputs": 0, "RPI": "10 ms", "Connection": "closed"})
        self.by["io"].ctl = [("Inputs", "INPUT WORD", 0, 255, 1, lambda v: "0x%02X" % int(v))]
        self.by["vfd"].vars.update({"Speed ref": 1500, "Speed fbk": 0, "RPI": "20 ms", "Connection": "closed"})
        self.by["plc"].vars.update({"I/O faults": 0})
        self.at(0.02, self.discover)
        self.at(0.05, self.open_all)
        self.every(0.5, self.hmi_read, 0.6)

    def discover(self):
        self.lan.udp("plc", None, 44818, 44818, enc_pdu(0x0063, 0, None), "ListIdentity (broadcast)", "ENIP", "bcast", dip="255.255.255.255", dmac="ff:ff:ff:ff:ff:ff")
        for d in ("io", "vfd"):
            ident = Bld("CIP Identity item", "")
            ident.u16("Vendor ID", 1 if d == "io" else 2, None, "", little=True)
            ident.u16("Device Type", 12 if d == "io" else 2, "%s" % ("Communications adapter" if d == "io" else "AC drive"), "", little=True)
            ident.text("Product Name", "COMM-SIM %s" % ("1734-AENT" if d == "io" else "PF525"), "")
            self.at(self.t + 0.001 + (0.0003 if d == "vfd" else 0), lambda d=d, ident=ident: self.lan.udp(d, "plc", 44818, 44818, enc_pdu(0x0063, 0, [(0x000C, ident.done(), "CIP Identity")]),
                                                                                                         "ListIdentity reply: %s" % d.upper(), "ENIP", "resp"))

    def open_all(self):
        for d, rpi in (("io", 0.010), ("vfd", 0.020)):
            self.open(d, rpi)

    def open(self, d, rpi):
        if not self.by[d].on:
            self.at(self.t + 1.0, self.open, d, rpi)
            return
        c = self.tcp("plc", d, 50000 + len(self.sess), 44818, "ENIP")
        self.sess[d] = c

        def reg():
            h = 0x10000 + int(self.rng.integers(1, 0xFFFF))
            c.send("plc", enc_pdu(0x0065, 0, None), "RegisterSession", "ENIP", "cmd", auto_ack=False)
            self.at(self.t + 0.0005, lambda: c.send(d, enc_pdu(0x0065, h, None), "RegisterSession reply: handle 0x%08X" % h, "ENIP", "resp", auto_ack=False))
            self.at(self.t + 0.001, lambda: fo(h))

        def fo(h):
            rpi_us = int((0.001 if (self.fault.get("rpi") and d == "io") else rpi) * 1e6)
            data = bytes([0x0A, 0x0E]) + (0).to_bytes(4, "little") + (0x2A000000 + len(self.conn)).to_bytes(4, "little") + bytes([0x34, 0x12, 1, 0, 0x42, 0x42, 0x42, 0x42, 3, 0, 0, 0]) + \
                rpi_us.to_bytes(4, "little") + bytes([0x08, 0x43]) + rpi_us.to_bytes(4, "little") + bytes([0x08, 0x43, 0x01, 3, 0x20, 0x04, 0x24, 0x01, 0x2C, 0x96, 0x2C, 0x64])
            req = cip_req_pdu(0x54, cip_path(0x06, 1), data)
            c.send("plc", enc_pdu(0x006F, h, [(0x0000, b"", "Null Address"), (0x00B2, req, "Unconnected Data")]), "SendRRData: Forward_Open RPI %d us" % rpi_us, "ENIP/CIP", "cmd", auto_ack=False)
            cid = 0x2A000000 + len(self.conn)
            self.conn[d] = dict(cid=cid, rpi=rpi, last=self.t, open=True, h=h, miss=0)
            self.seq[d] = 0

            def ok():
                rsp = cip_rsp_pdu(0x54, 0, cid.to_bytes(4, "little") + (cid + 1).to_bytes(4, "little"), "O->T 0x%08X, T->O 0x%08X" % (cid, cid + 1))
                c.send(d, enc_pdu(0x006F, h, [(0x0000, b"", "Null Address"), (0x00B2, rsp, "Unconnected Data")]), "Forward_Open success", "ENIP/CIP", "resp")
                self.by[d].vars["Connection"] = "open (Exclusive Owner)"
                self.by[d].state = "RUN"
                self.cyc(d)
            self.at(self.t + 0.002, ok)
        c.connect(on_open=reg)

    def io_pkt(self, frm, to, cid, seq, data, run=True):
        b = Bld("EtherNet/IP implicit I/O (CPF)", "Class 1 connected data on UDP 2222.")
        b.u16("Item Count", 2, None, "", little=True)
        b.u16("Type ID", 0x8002, "0x8002 Sequenced Address Item", "", little=True)
        b.u16("Length", 8, None, "", little=True)
        b.u32("Connection ID", cid, "0x%08X" % cid, "From Forward_Open", little=True)
        b.u32("Encapsulation Sequence", seq, None, "Increments every packet", little=True)
        b.u16("Type ID", 0x00B1, "0x00B1 Connected Data Item", "", little=True)
        b.u16("Length", len(data) + 2 + (4 if frm == "plc" else 0), None, "", little=True)
        b.u16("CIP Sequence Count", seq & 0xFFFF, None, "Lets the consumer detect duplicates", little=True)
        if frm == "plc":
            b.u32("Run/Idle Header", 1 if run else 0, "RUN" if run else "IDLE", "O->T data carries the scanner's run/program mode", little=True)
        b.raw("I/O Data", data, None, "Assembly data")
        return b.done()

    def cyc(self, d):
        c = self.conn.get(d)
        if not c or not c["open"]:
            return
        self.seq[d] += 1
        s = self.seq[d]
        outw = (int(self.t * 10) & 0xFF)
        self.lan.udp("plc", d, 2222, 2222, self.io_pkt("plc", d, c["cid"], s, bytes([outw, 0])), "I/O O->T 0x%08X seq %d" % (c["cid"], s), "ENIP I/O", "data")
        dev = self.by[d]
        slow = self.fault.get("rpi") and d == "io"
        if dev.on and not (slow and self.rng.random() < 0.7):
            data = bytes([int(dev.vars.get("Inputs", 0)) & 255, 0]) if d == "io" else (1500).to_bytes(2, "little")
            mc = self.fault.get("mcast")
            self.lan.udp(d, None if mc else "plc", 2222, 2222, self.io_pkt(d, "plc", c["cid"] + 1, s, data), "I/O T->O 0x%08X seq %d%s" % (c["cid"] + 1, s, " (multicast)" if mc else ""),
                         "ENIP I/O", "data", dip="239.192.1.%d" % (1 if d == "io" else 2) if mc else None, dmac="01:00:5e:40:01:01" if mc else None)
            c["last"] = self.t
        if self.t - c["last"] > 4 * c["rpi"]:
            c["open"] = False
            self.by["plc"].vars["I/O faults"] += 1
            dev.vars["Connection"] = "TIMED OUT"
            dev.state = "I/O FAULT"
            self.log("Connection timeout to %s (4 x RPI without data)" % d)
            self.at(self.t + 1.0, self.open, d, c["rpi"])
            return
        self.at(self.t + c["rpi"], self.cyc, d)

    def hmi_read(self):
        b = cip_req_pdu(0x4C, bytes([0x91, 9]) + b"PumpSpeed" + b"\0", (1).to_bytes(2, "little"))
        c = getattr(self, "_hmic", None)
        if c is None:
            c = self._hmic = self.tcp("hmi", "plc", 51000, 44818, "ENIP")
            c.connect()
            return
        if not c.open:
            return
        c.send("hmi", enc_pdu(0x006F, 0x1001, [(0x0000, b"", "Null Address"), (0x00B2, b, "Unconnected Data")]), "Read_Tag 'PumpSpeed'", "ENIP/CIP", "cmd", auto_ack=False)
        self.at(self.t + 0.002, lambda: c.send("plc", enc_pdu(0x006F, 0x1001, [(0x0000, b"", "Null Address"), (0x00B2, cip_rsp_pdu(0x4C, 0, bytes([0xC4, 0]) + (1500).to_bytes(4, "little"), "DINT 1500"), "Unconnected Data")]),
                                               "Read_Tag reply: DINT 1500", "ENIP/CIP", "resp"))

    def on_power(self, n):
        pass

    def on_fault(self, key, on):
        if key == "off":
            self.by["io"].on = not on

    def tpls(self):
        return [Tpl("Get_Attribute_Single", [P("dev", "Target", "io", opts=["io", "vfd"]), P("cls", "Class", 0x01, 0, 255), P("inst", "Instance", 1, 0, 255), P("attr", "Attribute", 7, 0, 255)],
                    lambda s, v, send: self._gas(v, send), "Identity object (class 1): attr 1 vendor, 2 device type, 3 product code, 4 revision, 6 serial, 7 product name."),
                Tpl("ListIdentity broadcast", [], lambda s, v, send: self.discover() if send else Frame(self.t, 1e-5, "plc", None, "ENIP", "ListIdentity", pdu=enc_pdu(0x63, 0, None)), "Discover every EtherNet/IP device on the subnet.")]

    def _gas(self, v, send):
        req = cip_req_pdu(0x0E, cip_path(v["cls"], v["inst"], v["attr"]))
        c = self.sess.get(v["dev"])
        if not send or not c or not c.open:
            return Frame(self.t, 1e-5, "plc", v["dev"], "ENIP/CIP", "Get_Attribute_Single", pdu=enc_pdu(0x6F, 0, [(0, b"", "Null Address"), (0xB2, req, "Unconnected Data")]))
        h = self.conn.get(v["dev"], {}).get("h", 0)
        fr = c.send("plc", enc_pdu(0x006F, h, [(0x0000, b"", "Null Address"), (0x00B2, req, "Unconnected Data")]),
                    "Get_Attribute_Single class 0x%02X inst %d attr %d" % (v["cls"], v["inst"], v["attr"]), "ENIP/CIP", "cmd", auto_ack=False)
        name = ("COMM-SIM 1734-AENT" if v["dev"] == "io" else "COMM-SIM PF525").encode()
        vals = {1: (1).to_bytes(2, "little"), 2: (12).to_bytes(2, "little"), 3: (55).to_bytes(2, "little"), 4: bytes([3, 1]), 6: (0x00C0FFEE).to_bytes(4, "little"), 7: bytes([len(name)]) + name}
        if v["cls"] == 1 and v["attr"] in vals:
            rsp = cip_rsp_pdu(0x0E, 0, vals[v["attr"]])
        elif v["cls"] in CIP_CLASS:
            rsp = cip_rsp_pdu(0x0E, 0x14)
        else:
            rsp = cip_rsp_pdu(0x0E, 0x05)
        self.at(self.t + 0.002, lambda: c.send(v["dev"], enc_pdu(0x006F, h, [(0x0000, b"", "Null Address"), (0x00B2, rsp, "Unconnected Data")]),
                                               "Get_Attribute_Single reply status 0x%02X" % rsp.b[2], "ENIP/CIP", "resp" if rsp.b[2] == 0 else "err"))
        return fr


class CIP(EtherNetIP):
    key, name = "cip", "CIP"
    blurb = "Common Industrial Protocol used by several industrial networks"
    medium = "CIP object model and routing: EtherNet/IP -> PLC backplane -> DeviceNet module -> device (one protocol across three networks)"
    faults = [("path", "Wrong slot in the route path", "The PLC backplane has no module in slot 5: general status 0x05 (path destination unknown)."),
              ("attr", "Requesting an unsupported attribute", "General status 0x14 (attribute not supported)."),
              ("svc", "Set on a read-only attribute", "General status 0x0E (attribute not settable).")]
    spec = [("Standard", "ODVA CIP Networks Library Vol. 1; adapted to EtherNet/IP, DeviceNet, ControlNet, CompoNet"), ("Object model", "Class / instance / attribute, accessed by services"),
            ("Core objects", "Identity (0x01), Message Router (0x02), Assembly (0x04), Connection Manager (0x06), TCP/IP (0xF5), Ethernet Link (0xF6)"),
            ("Messaging", "Explicit (request/response) and implicit (cyclic I/O) connections"), ("Routing", "Unconnected_Send with port segments hops across networks transparently"),
            ("Addressing", "EPATH: logical segments (class/instance/attribute) and port segments (port/link)")]
    frame = [["Explicit request", ("Service", 8), ("Path size", 8), ("EPATH", "n x 16"), ("Data", "n x 8")],
             ["Explicit response", ("Service|0x80", 8), ("Reserved", 8), ("General status", 8), ("Ext size", 8), ("Data", "n x 8")]]
    about = ("CIP is the application layer shared by EtherNet/IP, DeviceNet and ControlNet. Every device is a set of objects, each with numbered "
             "attributes and services such as Get_Attribute_Single. Because the object model is identical on every network, a message can be routed "
             "from Ethernet through a PLC backplane onto DeviceNet just by adding port segments to the path.")
    guide = ["In COMPOSE build Get_Attribute_Single class 1 instance 1 attribute 7: the product name comes back.",
             "Try attribute 99: general status 0x14.",
             "Send the routed request: find the port segments (backplane slot, DeviceNet MAC ID) in the tree.",
             "Compare CIP status codes with Modbus exception codes - same idea, different numbers."]

    def setup(self):
        super().setup()
        dn = self.node("dn", "DeviceNet DEVICE", "sensor", 380, 300, "MAC 12", "photo-eye")
        dn.at_right()
        dn.extra["can"] = False
        self.seg([dn.port, (self.by["io"].x + self.by["io"].w + 160, dn.port[1])], "devnet", label="DeviceNet (via PLC backplane module)")

    def tpls(self):
        base = super().tpls()
        return base + [Tpl("Routed Unconnected_Send", [P("slot", "Backplane slot", 3, 0, 16), P("mac", "DeviceNet MAC", 12, 0, 63), P("attr", "Identity attribute", 7, 1, 20)],
                           lambda s, v, send: self._route(v, send), "Path: port 1 (backplane) link = slot, then port 2 (DeviceNet) link = MAC ID, then the Identity object.")]

    def _route(self, v, send):
        inner = cip_req_pdu(0x0E, cip_path(0x01, 1, v["attr"]))
        route = bytes([0x01, v["slot"], 0x02, v["mac"]])
        data = bytes([0x07, 0xE9]) + len(inner.b).to_bytes(2, "little") + inner.b + bytes([len(route) // 2, 0]) + route
        req = cip_req_pdu(0x52, cip_path(0x06, 1), data)
        pdu = enc_pdu(0x006F, 0x1001, [(0x0000, b"", "Null Address"), (0x00B2, req, "Unconnected Data")])
        if not send:
            return Frame(self.t, 1e-5, "plc", "dn", "ENIP/CIP", "Unconnected_Send via slot %d to MAC %d" % (v["slot"], v["mac"]), pdu=pdu)
        c = self.sess.get("io")
        if not c or not c.open:
            return None
        fr = c.send("plc", pdu, "Unconnected_Send -> backplane slot %d -> DeviceNet MAC %d: Get attr %d" % (v["slot"], v["mac"], v["attr"]), "ENIP/CIP", "cmd", auto_ack=False)
        ok = v["slot"] == 3 and not self.fault.get("path") and v["mac"] == 12
        st = 0 if ok and v["attr"] in (1, 2, 3, 7) and not self.fault.get("attr") else (0x05 if not ok else 0x14)
        rsp = cip_rsp_pdu(0x52, st, b"\x0bPHOTO-EYE 9" if st == 0 else b"")
        self.at(self.t + 0.006, lambda: c.send("io", enc_pdu(0x006F, 0x1001, [(0x0000, b"", "Null Address"), (0x00B2, rsp, "Unconnected Data")]),
                                               "Routed reply status 0x%02X %s" % (st, CIP_STATUS.get(st, "")), "ENIP/CIP", "resp" if st == 0 else "err"))
        return fr


# ================================================================ EtherCAT
ECAT_CMD = {0: "NOP", 1: "APRD", 2: "APWR", 3: "APRW", 4: "FPRD", 5: "FPWR", 6: "FPRW", 7: "BRD", 8: "BWR", 9: "BRW", 10: "LRD", 11: "LWR", 12: "LRW", 13: "ARMW", 14: "FRMW"}
AL = {1: "INIT", 2: "PRE-OP", 4: "SAFE-OP", 8: "OP"}


class EtherCAT(Scenario):
    key, name, cat = "ethercat", "EtherCAT", "ind"
    blurb = "Real-time servo and motion control"
    phy, rate = "eth100", 100e6
    medium = "IEC 61158 Type 12, 100BASE-TX line: master -> coupler -> 8 DI -> 8 DO -> servo drive, 1 ms cycle, distributed clocks"
    nets = [("TX", "100BASE-TX (MLT-3)")]
    lines = ["M"]
    faults = [("break", "Cable break between DO terminal and servo", "The DO terminal closes its port and sends the frame back: the servo is no longer reached, WKC drops from 6 to 3."),
              ("safeop", "Servo refuses OP (bad PDO mapping)", "The drive stays in SAFE-OP and reports an AL status code; the master's state machine stalls."),
              ("loss", "Noise on the master link (lost frames)", "Some frames never come back: the master counts lost frames and outputs go stale for that cycle."),
              ("dc", "Servo distributed-clock sync lost", "Sync manager watchdog: the drive's SYNC0 jitter exceeds its limit and it drops to SAFE-OP with an error.")]
    spec = [("Standard", "IEC 61158 / IEC 61784 Type 12, ETG.1000 (EtherCAT Technology Group)"), ("Principle", "One frame passes through every slave; each reads and writes its data 'on the fly' in hardware"),
            ("Frame", "EtherType 0x88A4; datagrams with command, address, length, data and Working Counter (WKC)"),
            ("Addressing", "Position (auto-increment), configured station address, or logical (FMMU-mapped process image)"),
            ("Topology", "Line, tree, ring; the last slave closes the loop automatically"), ("Timing", "Cycle times down to 31.25 us; distributed clocks synchronise slaves to < 1 us"),
            ("States", "INIT -> PRE-OP (mailbox) -> SAFE-OP (inputs) -> OP (outputs)")]
    frame = [["EtherCAT frame", ("Ethernet hdr", 112), ("ECAT hdr: len/type", 16), ("Datagram 1", "n"), ("Datagram 2", "n"), ("FCS", 32)],
             ["Datagram", ("Cmd", 8), ("Idx", 8), ("Address", 32), ("Len/R/C/M", 16), ("IRQ", 16), ("Data", "n x 8"), ("WKC", 16)]]
    about = ("EtherCAT treats the whole network as one distributed shift register. The master sends a single frame; as it passes through each "
             "slave, the slave's ESC chip copies its outputs out and inserts its inputs within nanoseconds, then increments the Working Counter. "
             "The last slave sends the frame back. The master checks the WKC: if it is lower than expected, some slave did not take part.")
    guide = ["Select a cyclic frame: two datagrams, LRW (process data) and ARMW (distributed clock).",
             "Click 'Working Counter': 6 = DI read (+1) + DO write (+2) + servo read/write (+3).",
             "Break the cable before the servo: WKC 3, and the servo's DEVICE panel shows it lost.",
             "Watch the start-up sequence in FLOW: BRD slave count, station addresses, INIT -> PRE-OP -> SAFE-OP -> OP."]

    def build(self):
        m = self.node("m", "ECAT MASTER", "pc", 30, 150, "TwinCAT-like", "1 ms cycle").at_right()
        sl = [("cpl", "COUPLER", "coupler", 200, "EK1100", 0), ("di", "8 DI TERMINAL", "io", 380, "EL1008", 1), ("do", "8 DO TERMINAL", "io", 560, "EL2008", 2),
              ("srv", "SERVO DRIVE", "servo", 740, "CiA 402", 3)]
        prev = m.port
        for nid, lab, kind, x, sub, wk in sl:
            n = self.node(nid, lab, kind, x, 140, "addr 0x%04X" % (0x1001 + len(self.nodes) - 1), sub)
            n.at_left()
            n.vars.update({"AL state": "INIT", "WKC part": wk})
            self.seg([prev, n.port], "cat5", net="TX", c0="rj45", c1="rj45", label="IN->OUT" if nid == "cpl" else "")
            prev = (n.x + n.w, n.port[1] + 10)
        self.by["srv"].vars.update({"Target pos": 0, "Actual pos": 0, "Statusword": "0x0237"})
        self.by["di"].vars["Inputs"] = 0x5A
        self.by["di"].ctl = [("Inputs", "INPUTS", 0, 255, 1, lambda v: "0x%02X" % int(v))]
        self.user = "m"
        self.state = 1
        self.cycle_n = 0
        self.lost = 0
        self.wkc_err = 0
        self.by["m"].vars.update({"Expected WKC": 6, "Last WKC": "-", "Lost frames": 0, "WKC errors": 0, "Network state": "INIT"})
        self.at(0.005, self.startup)

    def dgram(self, b, cmd, idx, addr, data, wkc, more, desc):
        b.u8("Cmd", cmd, "%s (%d)" % (ECAT_CMD[cmd], cmd), {12: "Logical Read-Write: read and write the mapped process image in one pass.",
                                                             13: "Auto-increment Read Multiple Write: first slave's register is written to all others (used for DC time).",
                                                             7: "Broadcast Read: every slave participates (WKC = number of slaves).",
                                                             2: "Auto-increment Physical Write", 4: "Configured-address Physical Read", 5: "Configured-address Physical Write"}.get(cmd, ""), d=2)
        b.u8("Index", idx, None, "Master's datagram index", d=2)
        b.u32("Address", addr, "0x%08X" % addr, "Logical address, or ADP (position/station) + ADO (register offset)", d=2, little=True)
        b.u16("Len / flags", len(data) | (0x8000 if more else 0), "%d bytes%s" % (len(data), ", more datagrams follow" if more else ""), "11-bit length, circulating and more-follows flags", d=2, little=True)
        b.u16("IRQ", 0, None, "Event request bits", d=2, little=True)
        b.raw("Data", data, None, desc, d=2)
        b.u16("Working Counter", wkc, str(wkc), "Incremented by each slave that processed the datagram: +1 read, +2 write, +3 read and write.", d=2, little=True)

    def ecat(self, dgrams, info, kind="data", err=None):
        b = Bld("EtherCAT frame", "EtherType 0x88A4, processed on the fly by every slave.")
        total = sum(10 + len(d[3]) + 2 for d in dgrams)
        b.u16("EtherCAT header", total | 0x1000, "length %d, type 1 (commands)" % total, "11-bit length + type (1 = EtherCAT commands)", little=True)
        for i, (cmd, idx, addr, data, wkc, desc) in enumerate(dgrams):
            b.note("Datagram %d: %s" % (i + 1, ECAT_CMD[cmd]), "", d=1)
            self.dgram(b, cmd, idx, addr, data, wkc, i < len(dgrams) - 1, desc)
        pdu = eth_pdu("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x88A4, b.done())
        dur = (len(pdu.b) + 8) * 8 / 100e6
        from .fam import eth_wire
        fr = Frame(self.t, dur, "m", ["cpl", "di", "do", "srv"], "EtherCAT", info, pdu=pdu, kind=kind, err=err,
                   wirefn=lambda fr: eth_wire("eth100", pdu.b, 100e6), key=info.split(" ")[0])
        fr.meta["lat"] = dur + 4 * 1e-6
        return fr

    def reach(self):
        return ["cpl", "di", "do"] if self.fault["break"] else ["cpl", "di", "do", "srv"]

    def startup(self):
        n = len([x for x in self.reach() if self.by[x].on])
        self.tx(self.ecat([(7, 0, 0x0000, bytes(2), n, "Register 0x0000 type")], "BRD 0x0000: %d slaves answered (WKC)" % n, "ctl"))
        for i, nid in enumerate(self.reach()):
            self.at(self.t + 0.0002 * (i + 1), lambda i=i: self.tx(self.ecat([(2, 1, ((-i) & 0xFFFF) | (0x0010 << 16), (0x1001 + i).to_bytes(2, "little"), 1, "Configured station address")],
                                                                                "APWR pos %d: station address 0x%04X" % (-i, 0x1001 + i), "ctl")))
        for k, st in enumerate((2, 4, 8)):
            self.at(self.t + 0.01 * (k + 1), self.request_state, st)
        self.every(0.001, self.cycle, 0.05)

    def request_state(self, st):
        reach = [x for x in self.reach() if self.by[x].on]
        self.tx(self.ecat([(8, 2, 0x01200000, bytes([st, 0]), len(reach), "AL Control register 0x0120: requested state")], "BWR AL Control = %s" % AL[st], "ctl"))
        for nid in reach:
            ok = not ((self.fault["safeop"] or self.fault["dc"]) and nid == "srv" and st == 8)
            self.by[nid].vars["AL state"] = AL[st] if ok else "SAFE-OP + ERR (AL status 0x%04X)" % (0x001D if self.fault["safeop"] else 0x002C)
            self.by[nid].state = self.by[nid].vars["AL state"]
        self.state = st
        self.by["m"].vars["Network state"] = AL[st]

    def cycle(self):
        if not self.by["m"].on:
            return
        self.cycle_n += 1
        reach = [x for x in self.reach() if self.by[x].on]
        wk = {"di": 1, "do": 2, "srv": 3}
        wkc = sum(wk.get(x, 0) for x in reach if self.state >= 4 and (x != "srv" or not (self.fault["safeop"] or self.fault["dc"]) or self.state < 8))
        exp = 6 if self.state >= 8 else (6 if self.state >= 4 else 0)
        srv = self.by["srv"]
        tgt = int(10000 * math.sin(self.t * 2))
        srv.vars["Target pos"] = tgt
        if "srv" in reach and self.state >= 8 and not (self.fault["safeop"] or self.fault["dc"]):
            srv.vars["Actual pos"] = int(srv.vars["Actual pos"] + (tgt - srv.vars["Actual pos"]) * 0.3)
        img = bytes([self.cycle_n & 0xFF]) + bytes([int(self.by["di"].vars["Inputs"]) & 255]) + tgt.to_bytes(4, "little", signed=True) + int(srv.vars["Actual pos"]).to_bytes(4, "little", signed=True)
        err = None
        if self.fault["loss"] and self.rng.random() < 0.08:
            self.lost += 1
            self.by["m"].vars["Lost frames"] = self.lost
            err = "Frame lost on the wire: not returned to the master"
        elif wkc != exp and self.state >= 4:
            self.wkc_err += 1
            self.by["m"].vars["WKC errors"] = self.wkc_err
            err = "Working Counter %d, expected %d" % (wkc, exp)
        self.by["m"].vars["Last WKC"] = wkc
        dt = (int(self.t * 1e9)).to_bytes(8, "little")
        fr = self.ecat([(12, 0x10, 0x00010000, img, wkc, "Process image: DO byte, DI byte, servo target and actual position"),
                         (13, 0x11, 0x09100000 | ((0x1001) & 0xFFFF), dt[:8], len(reach), "DC system time (register 0x0910) distributed from the reference clock")],
                        "LRW+ARMW cycle %d WKC %d/%d" % (self.cycle_n, wkc, exp), "data", err)
        self.tx(fr)

    def on_fault(self, key, on):
        if key == "break":
            self.segs[-1].broken = on
            self._paths.clear()
            self.by["srv"].state = "NOT REACHED" if on else self.by["srv"].vars["AL state"]
        if key in ("safeop", "dc") and self.state >= 4:
            self.request_state(8)

    def tpls(self):
        return [Tpl("Request network state", [P("st", "State", "OP", opts=["INIT", "PRE-OP", "SAFE-OP", "OP"])],
                    lambda s, v, send: self.request_state({"INIT": 1, "PRE-OP": 2, "SAFE-OP": 4, "OP": 8}[v["st"]]) if send else
                    self.ecat([(8, 2, 0x01200000, bytes([1, 0]), 4, "AL Control")], "BWR AL Control", "ctl"), "Writes the AL Control register (0x0120) of all slaves."),
                Tpl("Read slave register (FPRD)", [P("st", "Station", 0x1004, 0x1001, 0x1004), P("reg", "Register", 0x0130, 0, 0xFFFF)],
                    lambda s, v, send: (self.tx if send else (lambda f: f))(self.ecat([(4, 3, v["st"] | (v["reg"] << 16), bytes(2), 1, "Register contents")],
                                                                                       "FPRD station 0x%04X reg 0x%04X" % (v["st"], v["reg"]), "cmd")),
                    "0x0130 = AL Status, 0x0134 = AL Status Code, 0x0000 = type.")]


# =============================================================== PROFINET
class PROFINET(IpNet):
    key, name, cat = "profinet", "PROFINET", "ind"
    blurb = "Siemens and other industrial systems"
    medium = "PROFINET IO RT (class 1) on switched 100 Mbit/s: IO controller + 3 IO devices, send clock 1 ms, reduction ratio 4 (4 ms cycle)"
    nets = [("TX", "100BASE-TX (MLT-3)")]
    faults = [("name", "Device renamed 'iodevice1' (expected 'io-device-1')", "PROFINET finds devices by NameOfStation via DCP. With a mismatch the controller never connects."),
              ("wd", "Drive stops sending (watchdog 3 x 4 ms)", "Missing cyclic frames trip the watchdog: the AR is aborted and a station failure is reported."),
              ("prio", "Switch without 802.1p priority under heavy load", "RT frames queue behind bulk traffic: jitter and late frames."),
              ("dupip", "Duplicate IP address on the valve terminal", "DCP/ARP detects the conflict; the device refuses to start.")]
    spec = [("Standard", "IEC 61158 / 61784 Type 10 (PROFIBUS & PROFINET International)"), ("RT", "Cyclic real-time frames directly on Ethernet, EtherType 0x8892, VLAN priority 6"),
            ("IRT", "Isochronous RT with scheduled time slots (< 1 µs jitter) for motion"), ("Discovery", "DCP: Identify, Set NameOfStation / IP, by multicast"),
            ("Connection", "Application Relationship (AR) set up with DCE/RPC over UDP 34964"), ("Watchdog", "Data hold time = send clock x reduction ratio x factor (typ. 3)"),
            ("Status", "Every frame ends with cycle counter, data status and transfer status")]
    frame = [["RT cyclic frame", ("VLAN prio 6", 32), ("Type 0x8892", 16), ("FrameID", 16), ("IO data + IOPS", "n x 8"), ("Cycle counter", 16), ("Data status", 8), ("Transfer status", 8)]]
    about = ("PROFINET IO exchanges cyclic data directly in Ethernet frames for speed while keeping configuration on UDP/IP. Devices are identified "
             "by a name (NameOfStation) that the controller sets or verifies with DCP, then an Application Relationship is opened and both sides send "
             "RT frames every send-clock x reduction-ratio. Each data item carries a provider status byte (IOPS) that says whether the value is good.")
    guide = ["Watch the DCP Identify multicast and the replies at start-up in FLOW.",
             "Select an RT frame: find the FrameID, IOPS bytes, cycle counter and data status (0x35 = primary, valid, run, no problem).",
             "Rename the IO device (fault) and see DCP find 'iodevice1' - no connection.",
             "Stop the drive and watch the watchdog abort the AR after three missed cycles."]

    def setup(self):
        hosts = [("ioc", "IO CONTROLLER", "plc", 40, 40, "192.168.0.1", "00:1b:1b:01:00:01"), ("io1", "IO-DEVICE-1", "io", 40, 290, "192.168.0.11", "00:1b:1b:11:00:11"),
                 ("drv", "G120-DRIVE", "drive", 380, 300, "192.168.0.12", "00:1b:1b:12:00:12"), ("vt", "VALVE-TERMINAL", "valve", 700, 290, "192.168.0.13", "00:1b:1b:13:00:13"),
                 ("eng", "ENGINEERING PC", "pc", 700, 40, "192.168.0.100", "00:0c:29:00:01:00")]
        self.star(hosts, style="profinet")
        self.user = "ioc"
        self.names = {"io1": "io-device-1", "drv": "g120-drive", "vt": "valve-terminal"}
        self.fid = {"io1": 0x8001, "drv": 0x8002, "vt": 0x8003}
        self.cc = 0
        self.ar = {}
        self.last = {}
        for d in self.names:
            self.by[d].vars.update({"NameOfStation": self.names[d], "AR": "none", "IOPS": "-"})
        self.by["io1"].vars["Inputs"] = 0x0F
        self.by["io1"].ctl = [("Inputs", "INPUTS", 0, 255, 1, lambda v: "0x%02X" % int(v))]
        self.at(0.02, self.dcp_identify)
        self.every(0.004, self.rt_cycle, 0.08)
        self.every(0.05, self.background, 0.01)

    def dcp(self, frm, to, sid, info, blocks, resp=False):
        b = Bld("PROFINET DCP", "Discovery and Configuration Protocol, directly on Ethernet.")
        b.u16("FrameID", 0xFEFF if resp else 0xFEFE, "0x%04X (%s)" % (0xFEFF if resp else 0xFEFE, "Identify response" if resp else "Identify multicast request"), "")
        b.u8("ServiceID", 5, "Identify (5)", "")
        b.u8("ServiceType", 1 if resp else 0, "Response success" if resp else "Request", "")
        b.u32("Xid", 0x1234, None, "Transaction ID")
        b.u16("Response delay / reserved", 1, None, "Devices spread their replies to avoid a burst")
        body = b"".join(bytes([o, s]) + len(v).to_bytes(2, "big") + v for o, s, v in blocks)
        b.u16("DCPDataLength", len(body), None, "")
        for o, s, v in blocks:
            nm = {(2, 2): "NameOfStation", (1, 2): "IP parameter", (2, 3): "Device ID", (0xFF, 0xFF): "All selector"}.get((o, s), "%d/%d" % (o, s))
            b.raw("Block %s" % nm, bytes([o, s]) + len(v).to_bytes(2, "big") + v, v.decode("latin-1") if (o, s) == (2, 2) else v.hex(" "), "")
        dmac = "01:0e:cf:00:00:00" if not resp else self.lan.mac[to]
        return self.lan.l2(frm, to, 0x8892, b.done(), info, "PN-DCP", "bcast" if not resp else "resp", dmac=dmac)

    def dcp_identify(self):
        self.dcp("ioc", None, 0, "DCP Identify All (multicast)", [(0xFF, 0xFF, b"")])
        for i, d in enumerate(self.names):
            nm = ("iodevice1" if (d == "io1" and self.fault["name"]) else self.names[d]).encode()
            self.at(self.t + 0.002 + i * 0.0004, lambda d=d, nm=nm: self.dcp(d, "ioc", 0, "DCP Identify OK: %s" % nm.decode(), [(2, 2, nm), (1, 2, bytes(map(int, self.lan.ip[d].split("."))) + bytes([255, 255, 255, 0]) + bytes(4))], True))
        self.at(self.t + 0.01, self.connect_all)

    def connect_all(self):
        for d in self.names:
            if d == "io1" and self.fault["name"]:
                self.log("No device named 'io-device-1' found (DCP)")
                self.by[d].vars["AR"] = "none - name mismatch"
                self.by[d].state = "BF (bus fault) LED"
                continue
            if d == "vt" and self.fault["dupip"]:
                self.by[d].vars["AR"] = "none - IP conflict"
                self.by[d].state = "IP CONFLICT"
                continue
            b = Bld("PNIO-CM Connect.req (DCE/RPC)", "Context management: opens an Application Relationship with IOCR (cyclic) and alarm CR.")
            b.raw("AR UUID", bytes(range(16)), "random", "Identifies the AR")
            b.u16("Session key", 1, None, "")
            b.u16("IOCR send clock factor", 32, "32 (1 ms)", "Send clock in 31.25 us units")
            b.u16("Reduction ratio", 4, None, "Frame every 4 send clocks = 4 ms")
            b.u16("Data hold factor", 3, None, "Watchdog = 3 x 4 ms")
            from .fam import udp_pdu
            self.lan.udp("ioc", d, 49152, 34964, b.done(), "Connect.req to %s" % self.names[d], "PNIO-CM", "cmd")
            self.ar[d] = True
            self.last[d] = self.t
            self.by[d].vars["AR"] = "established"
            self.by[d].state = "RUN"
            self.at(self.t + 0.001, lambda d=d: self.lan.udp(d, "ioc", 34964, 49152, Pdu(b"\x00" * 20, [[0, "PNIO-CM Connect.res (OK)", 0, 20, ""]]), "Connect.res OK from %s" % self.names[d], "PNIO-CM", "resp"))

    def rt(self, frm, to, fid, data, info, err=None):
        self.cc = (self.cc + 64) & 0xFFFF
        b = Bld("PROFINET IO cyclic data (RT class 1)", "")
        b.u16("FrameID", fid, "0x%04X (RT cyclic)" % fid, "0x8000-0xBFFF: RT class 1 unicast cyclic data; identifies the IOCR.")
        o = b.raw("IO data", data, None, "Submodule data followed by its IOPS (provider status 0x80 = good)")
        del o
        b.u16("CycleCounter", self.cc, None, "Increments by send-clock units each cycle; consumers detect duplicates and gaps")
        b.u8("DataStatus", 0x35, "0x35 (primary, valid, run, station OK)", "State, redundancy, data valid, provider run, station problem indicator")
        b.u8("TransferStatus", 0, "OK", "")
        return self.lan.l2(frm, to, 0x8892, b.done(), info, "PN-RT", "data", vlan=(0 if self.fault["prio"] else 6, 0), err=err)

    def rt_cycle(self):
        for d in self.names:
            if not self.ar.get(d):
                continue
            outd = bytes([int(self.t * 50) & 255, 0x80])
            self.rt("ioc", d, self.fid[d] + 0x100, outd, "RT out -> %s" % self.names[d])
            dev = self.by[d]
            stop = self.fault["wd"] and d == "drv"
            if dev.on and not stop:
                late = self.fault["prio"] and self.rng.random() < 0.2
                ind = bytes([int(dev.vars.get("Inputs", 0x11)) & 255, 0x80])
                self.rt(d, "ioc", self.fid[d], ind, "RT in <- %s" % self.names[d], err="Late frame: queued behind bulk traffic (no priority)" if late else None)
                self.last[d] = self.t
                dev.vars["IOPS"] = "0x80 GOOD"
            if self.t - self.last.get(d, self.t) > 0.012:
                self.ar[d] = False
                dev.vars["AR"] = "ABORTED (watchdog)"
                dev.state = "STATION FAILURE"
                self.log("Watchdog expired for %s: AR aborted, alarm raised" % self.names[d])
                self.lan.l2("ioc", d, 0x8892, Pdu(b"\xfc\x01" + bytes(10), [[0, "PROFINET RTA alarm (FrameID 0xFC01)", 0, 12, "Acyclic real-time alarm channel"]]),
                            "Alarm: station %s failed" % self.names[d], "PN-RTA", "evt")
                self.at(self.t + 1.0, self.reconnect, d)

    def reconnect(self, d):
        if self.fault["wd"] and d == "drv":
            self.at(self.t + 1.0, self.reconnect, d)
            return
        self.connect_all()

    def background(self):
        if self.fault["prio"]:
            for _ in range(6):
                b = Bld("Bulk TCP (file copy)", "")
                b.raw("Data", bytes(1400), "1400 bytes", "")
                self.lan.l2("eng", "ioc", 0x0800, b.done(), "Bulk file transfer 1400 B", "TCP", "data")

    def on_fault(self, key, on):
        if key in ("name", "dupip") and not on:
            self.at(self.t + 0.01, self.dcp_identify)
        if key == "name" and on:
            self.by["io1"].vars["NameOfStation"] = "iodevice1"
        elif key == "name":
            self.by["io1"].vars["NameOfStation"] = "io-device-1"

    def tpls(self):
        return [Tpl("DCP Identify All", [], lambda s, v, send: self.dcp_identify() if send else None, "Multicast identify; every device answers with its name and IP."),
                Tpl("DCP Set NameOfStation", [P("dev", "Device", "io1", opts=["io1", "drv", "vt"]), P("nm", "Name", "io-device-1")], lambda s, v, send: self._set(v, send),
                    "Assigns the name the controller expects (what the engineering tool does when you 'assign device name').")]

    def _set(self, v, send):
        if not send:
            return None
        self.dcp("eng", v["dev"], 0, "DCP Set NameOfStation '%s'" % v["nm"], [(2, 2, v["nm"].encode())])
        if v["dev"] == "io1" and v["nm"] == "io-device-1" and self.fault["name"]:
            self.set_fault("name", False)
        return None
