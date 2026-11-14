"""Power utility automation, part A: DNP3, IEC 61850 (GOOSE, MMS, Sampled
Values), IEC 60870-5-101 and IEC 60870-5-104."""
import math
import struct
from datetime import datetime, timezone, timedelta
from ..engine import Scenario, Bld, Frame, Tpl, P, Pdu
from ..bits import crcn, f32be
from .fam import serial_frame, IpNet

T0 = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)


def epoch_ms(t):
    return int((T0.timestamp() + t) * 1000)


def utc(t):
    return T0 + timedelta(seconds=t)


# ===================================================================== BER
def tlv_len(n):
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 255])


def ber_int(v):
    n = 1
    while not -(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1)):
        n += 1
    return int(v).to_bytes(n, "big", signed=True)


class T:
    """BER TLV node: primitive (bytes value) or constructed (list of T)."""

    def __init__(self, tag, label, val, txt=None, desc=""):
        self.tag, self.label, self.val, self.txt, self.desc = tag, label, val, txt, desc

    def body(self):
        return b"".join(c.enc() for c in self.val) if isinstance(self.val, list) else bytes(self.val)

    def enc(self):
        bd = self.body()
        return bytes([self.tag]) + tlv_len(len(bd)) + bd

    def put(self, b, d=1):
        off = len(b.b)
        e = self.enc()
        if isinstance(self.val, list):
            bl = len(self.body())
            b.b += e[:len(e) - bl]
            b.rows.append([d, "%s (tag 0x%02X, length %d)" % (self.label, self.tag, bl), off, len(e), self.desc])
            for c in self.val:
                c.put(b, d + 1)
        else:
            b.b += e
            b.rows.append([d, "%s: %s" % (self.label, self.txt if self.txt is not None else bytes(self.val).hex(" ").upper()), off, len(e),
                           (self.desc + " " if self.desc else "") + "[BER tag 0x%02X, length %d]" % (self.tag, len(self.val))])
        return b


def Tstr(tag, label, s, desc=""):
    return T(tag, label, s.encode(), '"%s"' % s, desc)


def Tint(tag, label, v, desc="", txt=None):
    return T(tag, label, ber_int(v), txt or str(v), desc)


def Tbool(tag, label, v, desc=""):
    return T(tag, label, b"\xff" if v else b"\x00", "TRUE" if v else "FALSE", desc)


def Tf32(tag, label, v, desc=""):
    return T(tag, label, b"\x08" + f32be(v), "%.4g" % v, (desc + " " if desc else "") + "MMS floating-point: exponent width 8 + IEEE 754 single")


def Tutc(tag, label, t, desc=""):
    s = T0.timestamp() + t
    sec = int(s)
    frac = int((s - sec) * (1 << 24))
    return T(tag, label, struct.pack(">I", sec) + frac.to_bytes(3, "big") + b"\x0a", utc(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC",
             (desc + " " if desc else "") + "UtcTime: 32-bit seconds since 1970, 24-bit fraction, quality (10 bits accuracy)")


# ==================================================================== DNP3
DNP_FC = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE", 13: "COLD_RESTART", 20: "ENABLE_UNSOLICITED",
          21: "DISABLE_UNSOLICITED", 23: "DELAY_MEASURE", 129: "RESPONSE", 130: "UNSOLICITED_RESPONSE"}
IIN_BITS = ["BROADCAST", "CLASS_1_EVENTS", "CLASS_2_EVENTS", "CLASS_3_EVENTS", "NEED_TIME", "LOCAL_CONTROL", "DEVICE_TROUBLE", "DEVICE_RESTART",
            "NO_FUNC_CODE_SUPPORT", "OBJECT_UNKNOWN", "PARAMETER_ERROR", "EVENT_BUFFER_OVERFLOW", "ALREADY_EXECUTING", "CONFIG_CORRUPT", "RESERVED_2", "RESERVED_1"]
CROB_ST = {0: "SUCCESS", 1: "TIMEOUT", 2: "NO_SELECT", 3: "FORMAT_ERROR", 4: "NOT_SUPPORTED", 5: "ALREADY_ACTIVE", 6: "HARDWARE_ERROR", 7: "LOCAL",
           8: "TOO_MANY_OBJS", 9: "NOT_AUTHORIZED"}
G_NAMES = {(1, 2): "Binary Input - with flags", (2, 2): "Binary Input Event - with absolute time", (12, 1): "Control Relay Output Block (CROB)",
           (20, 1): "Counter - 32-bit with flag", (30, 1): "Analog Input - 32-bit with flag", (32, 1): "Analog Input Event - 32-bit without time",
           (50, 1): "Time and Date - absolute time", (52, 2): "Time Delay - fine", (60, 1): "Class 0 data", (60, 2): "Class 1 data",
           (60, 3): "Class 2 data", (60, 4): "Class 3 data", (80, 1): "Internal Indications - packed format"}
QUAL = {0x00: "0x00: 8-bit start and stop indices", 0x01: "0x01: 16-bit start and stop indices", 0x06: "0x06: no range field (all objects)",
        0x07: "0x07: 8-bit count", 0x28: "0x28: 16-bit count, 16-bit index prefix"}


def iin_text(iin):
    on = [IIN_BITS[i] for i in range(16) if iin >> i & 1]
    return ", ".join(on) if on else "none set"


def dnp_time(t):
    return epoch_ms(t).to_bytes(6, "little")


class DnpApp:
    """Application layer builder (objects with dissection)."""

    def __init__(self, fc, seq, rsp=False, iin=0, con=False, uns=False):
        self.b = Bld("DNP3 Application Layer", "Function code, then object headers (group, variation, qualifier, range) and objects.")
        ac = 0xC0 | (0x20 if con else 0) | (0x10 if uns else 0) | (seq & 15)
        self.b.u8("Application control", ac, "FIR 1, FIN 1, CON %d, UNS %d, SEQ %d" % (con, uns, seq & 15),
                  "CON = the master must CONFIRM this fragment; UNS = unsolicited; SEQ pairs requests and responses (0-15).")
        self.b.u8("Function code", fc, "%d %s" % (fc, DNP_FC.get(fc, "?")), "What to do: READ, WRITE, SELECT / OPERATE, ... or 129 RESPONSE / 130 UNSOLICITED.")
        if rsp:
            self.b.u16("Internal Indications (IIN)", ((iin & 0xFF) << 8) | (iin >> 8), "0x%02X%02X: %s" % (iin & 0xFF, iin >> 8, iin_text(iin)),
                       "Two status bytes in every response: events waiting per class, device restart, need time, local control, errors.")
        self.fc = fc
        self.parts = []

    def hdr(self, g, v, q, rng=b""):
        b = self.b
        b.raw("Object header", bytes([g, v, q]) + rng, "Group %d Var %d (%s), qualifier %s" % (g, v, G_NAMES.get((g, v), "?"), QUAL.get(q, "0x%02X" % q)),
              "Group = object type, variation = encoding, qualifier = how the points are addressed.")
        self.parts.append(G_NAMES.get((g, v), "g%dv%d" % (g, v)))

    def classes(self, cls):
        for c in cls:
            self.hdr(60, c + 1, 0x06)

    def bi(self, start, states, names):
        self.hdr(1, 2, 0x00, bytes([start, start + len(states) - 1]))
        for i, st in enumerate(states):
            f = 0x01 | (0x80 if st else 0)
            self.b.u8("BI %d %s" % (start + i, names.get(start + i, "")), f, "flags 0x%02X: ONLINE, state %d" % (f, st), "Bit 7 = point state, bit 0 = ONLINE.", d=2)

    def ai(self, start, vals, names):
        self.hdr(30, 1, 0x00, bytes([start, start + len(vals) - 1]))
        for i, v in enumerate(vals):
            self.b.raw("AI %d %s" % (start + i, names.get(start + i, "")), bytes([0x01]) + struct.pack("<i", int(v)), "%d (flag ONLINE)" % int(v),
                       "Flag byte + 32-bit signed value, little-endian. Engineering units come from the point list, not the protocol.", d=2)

    def ctr(self, start, vals, names):
        self.hdr(20, 1, 0x00, bytes([start, start + len(vals) - 1]))
        for i, v in enumerate(vals):
            self.b.raw("Counter %d %s" % (start + i, names.get(start + i, "")), bytes([0x01]) + struct.pack("<I", int(v) & 0xFFFFFFFF), "%d" % int(v), "", d=2)

    def bi_events(self, evs, names):
        self.hdr(2, 2, 0x28, struct.pack("<H", len(evs)))
        for idx, st, t in evs:
            self.b.raw("BI event: point %d %s" % (idx, names.get(idx, "")), struct.pack("<HB", idx, 0x01 | (0x80 if st else 0)) + dnp_time(t),
                       "%s at %s" % ("ON / closed" if st else "OFF / open", utc(t).strftime("%H:%M:%S.%f")[:-3]),
                       "Index (16-bit), flags with state, 48-bit time in ms since 1970 UTC.", d=2)

    def ai_events(self, evs, names):
        self.hdr(32, 1, 0x28, struct.pack("<H", len(evs)))
        for idx, v in evs:
            self.b.raw("AI event: point %d %s" % (idx, names.get(idx, "")), struct.pack("<HBi", idx, 0x01, int(v)), "%d" % int(v),
                       "Reported because the value moved more than the deadband.", d=2)

    def crob(self, idx, code, on_ms=1000, status=0):
        self.hdr(12, 1, 0x28, struct.pack("<H", 1))
        op = {1: "PULSE_ON", 2: "PULSE_OFF", 3: "LATCH_ON", 4: "LATCH_OFF"}.get(code & 15, "NUL")
        tcc = {0: "", 1: " CLOSE", 2: " TRIP"}[code >> 6]
        self.b.raw("CROB point %d" % idx, struct.pack("<HBBIIB", idx, code, 1, on_ms, 0, status),
                   "code 0x%02X (%s%s), count 1, on %d ms, status %d %s" % (code, op, tcc, on_ms, status, CROB_ST.get(status, "")),
                   "Control code (operation type + trip/close code), count, on-time, off-time, status (0 in requests).", d=2)

    def time(self, t):
        self.hdr(50, 1, 0x07, b"\x01")
        self.b.raw("Time", dnp_time(t), utc(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC", "48-bit ms since 1970-01-01 UTC.", d=2)

    def iin_clear(self):
        self.hdr(80, 1, 0x00, bytes([7, 7]))
        self.b.u8("IIN1.7 DEVICE_RESTART", 0, "write 0 (clear)", "The master acknowledges the restart by clearing the bit.", d=2)

    def delay(self, ms):
        self.hdr(52, 2, 0x07, b"\x01")
        self.b.u16("Time delay", ms, "%d ms" % ms, "How long the master should wait before talking to the restarting outstation.", d=2, little=True)

    def done(self):
        return self.b.done()


def dnp_frame(dst, src, from_master, tseq, app):
    """Link layer (with a CRC after the header and after every 16-byte block) + transport header + application fragment."""
    user = bytes([0xC0 | (tseq & 63)]) + app.b
    ctrl = (0x80 if from_master else 0) | 0x40 | 0x04
    hdr = bytes([0x05, 0x64, 5 + len(user), ctrl]) + struct.pack("<HH", dst, src)
    hc = crcn("CRC-16/DNP", hdr)
    out = bytearray(hdr + struct.pack("<H", hc))
    rows = [[0, "DNP3 Data Link Layer", 0, 10, "IEEE 1815: start bytes, length, control, addresses and a CRC; user data follows in 16-byte blocks, each with its own CRC."],
            [1, "Start: 0x05 0x64", 0, 2, "Sync pattern that starts every link frame."],
            [1, "Length: %d" % (5 + len(user)), 2, 1, "Octets of control + addresses + user data, not counting CRCs (max 255)."],
            [1, "Control: 0x%02X (DIR %d, PRM 1, func 4 UNCONFIRMED_USER_DATA)" % (ctrl, 1 if from_master else 0), 3, 1,
             "DIR = sent by the master; PRM = primary (initiating) station; function 4 = user data without link confirm."],
            [1, "Destination: %d" % dst, 4, 2, "Outstation / master address (16-bit, little-endian). Frames for other addresses are ignored."],
            [1, "Source: %d" % src, 6, 2, ""],
            [1, "Header CRC: 0x%04X [correct]" % hc, 8, 2, "CRC-16/DNP (poly 0x3D65) over the 8 header bytes."]]
    crc_rows = []
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk
        c = crcn("CRC-16/DNP", blk)
        crc_rows.append([1, "Block %d CRC: 0x%04X [correct]" % (i // 16, c), len(out), 2, "Every block of up to 16 user-data bytes carries its own CRC."])
        out += struct.pack("<H", c)

    def m(o):
        return 10 + o + 2 * (o // 16)
    rows.append([0, "DNP3 Transport Function", m(0), 1, "One byte per link frame: FIN, FIR and a 6-bit sequence; splits large fragments over several frames."])
    rows.append([1, "Transport header: 0x%02X (FIN 1, FIR 1, SEQ %d)" % (user[0], tseq & 63), m(0), 1, ""])
    for r in app.rows:
        if r[2] is None:
            rows.append(list(r))
            continue
        a = m(r[2] + 1)
        n = r[3] if r[3] not in (-1, None) else 0
        e = (m(r[2] + 1 + n - 1) + 1) if n > 0 else a
        rows.append([r[0], r[1], a, e - a, r[4]])
    rows.append([0, "DNP3 link-layer block CRCs", None, 0, "Interleaved after every 16 user-data bytes."])
    rows += crc_rows
    return Pdu(bytes(out), rows)


class DNP3(IpNet):
    key, name, cat = "dnp3", "DNP3", "power"
    blurb = "Electric utilities, water systems, SCADA"
    medium = "DNP3 (IEEE 1815) over TCP port 20000: SCADA master polls a substation RTU (events by class) and a pole-top recloser that reports unsolicited"
    faults = [("restart", "Substation RTU restarts", "The next response has IIN1.7 DEVICE_RESTART and IIN1.4 NEED_TIME: the master clears the bit, syncs the clock and does an integrity poll."),
              ("local", "RTU switched to LOCAL control", "IIN1.5 LOCAL_CONTROL is set and control requests are rejected with CROB status 7 (LOCAL)."),
              ("sbo", "SELECT -> OPERATE takes too long", "The OPERATE arrives after the outstation's select timeout: status 1 (TIMEOUT), nothing operates."),
              ("feeder", "Permanent fault on the recloser's feeder", "The recloser trips, recloses, trips again and locks out; each change is sent as an unsolicited response."),
              ("addr", "Master configured with RTU address 11 (is 10)", "The RTU ignores link frames for other addresses: every poll times out.")]
    spec = [("Standard", "IEEE 1815-2012 (DNP3), DNP Users Group; Secure Authentication v5/v6; IEC 62351 for TLS"),
            ("Transport", "Serial (RS-232 / RS-485 / radio) or TCP / UDP port 20000"),
            ("Layers", "Data link (0x0564, addresses, CRC per 16 bytes), pseudo-transport (FIR / FIN / SEQ), application (fragments up to 2048 bytes)"),
            ("Data", "Binary inputs, analog inputs, counters, binary / analog outputs; static values and time-stamped events in classes 1, 2, 3"),
            ("Polling", "Integrity poll (class 0 + events), event polls (classes 1-3), unsolicited responses from the outstation, report by exception"),
            ("Controls", "CROB with SELECT-before-OPERATE or DIRECT_OPERATE; trip / close codes, pulse times"),
            ("IIN", "Two status bytes in every response: events available, restart, need time, local control, errors")]
    frame = [["Link header", ("0x05 0x64", 16), ("LEN", 8), ("CTRL", 8), ("DEST", 16), ("SRC", 16), ("CRC", 16)],
             ["User data", ("Transport", 8), ("App control", 8), ("Function", 8), ("[IIN]", 16), ("Objects ...", "n x 8"), ("CRC every 16 B", 16)]]
    about = ("DNP3 is how most North American utilities - and many water and gas systems - read their remote terminal units. The outstation "
             "keeps a time-stamped event log sorted into classes; the master asks for 'class 1, 2, 3 events' every few seconds and only "
             "occasionally reads everything (an integrity poll). Every response carries the Internal Indications that tell the master when to "
             "act: events waiting, the RTU restarted, it needs the time. Breakers are operated with a SELECT followed by an OPERATE.")
    guide = ["Watch the integrity poll (class 0,1,2,3) after connecting and the class 1-3 event polls every 2 s.",
             "Select a response: decode the IIN bits, then the object headers (group, variation, qualifier) and the points.",
             "COMPOSE an SBO trip of CB 1: SELECT, the echo, OPERATE, then a binary-input event in the next poll.",
             "Restart the RTU: follow IIN1.7 -> WRITE g80v1 -> time sync -> integrity poll.",
             "Inject the feeder fault: unsolicited responses from the recloser, each confirmed by the master."]

    BI_NAMES = {0: "CB1 closed", 1: "CB2 closed", 2: "Earth switch", 3: "Protection trip", 4: "Door open"}
    AI_NAMES = {0: "Bus voltage (V)", 1: "Feeder 1 current (A)", 2: "Active power (kW)", 3: "Reactive power (kvar)", 4: "Transformer temp (degC)"}
    CT_NAMES = {0: "Energy (kWh)", 1: "CB1 operations"}
    RB_NAMES = {0: "Recloser closed", 1: "Lockout"}
    RA_NAMES = {0: "Line current (A)"}

    def setup(self):
        hosts = [("m", "SCADA MASTER", "scada", 40, 40, "10.10.0.1", "00:50:56:0a:00:01", "DNP3 addr 1"),
                 ("rtu", "SUBSTATION RTU", "rtu", 700, 40, "10.10.0.10", "00:1b:7a:00:00:10", "DNP3 addr 10"),
                 ("rc", "RECLOSER CONTROL", "ied", 700, 290, "10.10.0.20", "00:1b:7a:00:00:20", "DNP3 addr 20")]
        self.star(hosts, sw=("sw", "UTILITY WAN ROUTER", 380, 160))
        self.user = "m"
        self.out = {"rtu": dict(addr=10, bi=[1, 1, 0, 0, 0], ai=[11020, 182, 3410, 620, 58], ctr=[1520330, 312], ev1=[], ev2=[], iin=0x0090, tseq=0, useq=0, sel=None),
                    "rc": dict(addr=20, bi=[1, 0], ai=[96], ctr=[], ev1=[], ev2=[], iin=0x0090, tseq=0, useq=0, sel=None, unsol=False)}
        self.mseq = {"rtu": 0, "rc": 0}
        self.mtseq = {"rtu": 0, "rc": 0}
        self.clr = {}
        self.pending = {}
        self.conns = {}
        m = self.by["m"]
        m.vars.update({"RTU CB1 / CB2": "-", "RTU V / I": "-", "Recloser": "-", "Last IIN (RTU)": "-", "Timeouts": 0})
        self.by["rtu"].vars.update({"Events queued": 0, "Mode": "REMOTE"})
        self.by["rc"].vars.update({"State": "CLOSED", "Shots": 0})
        self.at(0.05, self.connect)
        self.every(2.0, self.event_poll, 3.0)
        self.every(20.0, lambda: self.read("rtu", [0, 1, 2, 3], "Integrity poll"), 21.0)
        self.every(0.5, self.physics, 0.25)

    def connect(self):
        for k in ("rtu", "rc"):
            c = self.tcp("m", k, 49152 + len(self.conns), 20000, "DNP3")
            self.conns[k] = c
            c.connect(on_open=(lambda k=k: self.at(self.t + 0.01, self.read, k, [0, 1, 2, 3], "Integrity poll")))
        self.at(1.5, self.enable_unsol)

    # ------------------------------------------------------------ master
    def next_seq(self, k):
        self.mseq[k] = (self.mseq[k] + 1) & 15
        return self.mseq[k]

    def request(self, k, app, info, kind="cmd", on_rsp=None):
        c = self.conns.get(k)
        if not c or not c.open or not self.by["m"].on:
            return None
        o = self.out[k]
        dst = 11 if (self.fault["addr"] and k == "rtu") else o["addr"]
        self.mtseq[k] = (self.mtseq[k] + 1) & 63
        p = dnp_frame(dst, 1, True, self.mtseq[k], app)
        fr = c.send("m", p, info, "DNP3", kind)
        tok = object()
        self.pending[k] = (tok, on_rsp)
        self.at(self.t + 1.5, self._timeout, k, tok)
        if dst == o["addr"] and self.by[k].on:
            self.at(self.t + 0.004, self.outstation, k, app, dst)
        return fr

    def _timeout(self, k, tok):
        if self.pending.get(k, (None,))[0] is tok:
            self.pending.pop(k, None)
            self.by["m"].vars["Timeouts"] += 1
            self.log("Master: no response from %s (response timeout 1.5 s)" % self.by[k].label)

    def read(self, k, classes, what):
        a = DnpApp(1, self.next_seq(k))
        a.classes(classes)
        return self.request(k, a.done(), "%s: READ class %s -> addr %d" % (what, ",".join(str(c) for c in classes), self.out[k]["addr"]), "cmd")

    def event_poll(self):
        self.read("rtu", [1, 2, 3], "Event poll")

    def enable_unsol(self):
        a = DnpApp(20, self.next_seq("rc"))
        a.classes([1, 2, 3])
        self.request("rc", a.done(), "ENABLE_UNSOLICITED class 1,2,3 -> recloser addr 20", "ctl")

    def operate(self, k, idx, trip, mode="sbo", send=True):
        code = 0x81 if trip else 0x41
        if not send:
            a = DnpApp(3 if mode == "sbo" else 5, self.mseq[k])
            a.crob(idx, code)
            return Frame(self.t, 0.0001, "m", k, "DNP3", "preview", pdu=dnp_frame(self.out[k]["addr"], 1, True, self.mtseq[k], a.done()))
        what = "%s CB%d" % ("TRIP" if trip else "CLOSE", idx + 1)
        if mode == "direct":
            a = DnpApp(5, self.next_seq(k))
            a.crob(idx, code)
            return self.request(k, a.done(), "DIRECT_OPERATE %s (CROB g12v1 index %d)" % (what, idx), "cmd")
        a = DnpApp(3, self.next_seq(k))
        a.crob(idx, code)

        def selected(app_rsp_status):
            if app_rsp_status != 0:
                return
            delay = 12.0 if self.fault["sbo"] else 0.4
            a2 = DnpApp(4, self.next_seq(k))
            a2.crob(idx, code)
            self.at(self.t + delay, self.request, k, a2.done(), "OPERATE %s (same CROB as the SELECT)" % what, "cmd")
        return self.request(k, a.done(), "SELECT %s (CROB g12v1 index %d)" % (what, idx), "cmd", on_rsp=selected)

    def time_sync(self, k):
        a = DnpApp(2, self.next_seq(k))
        a.time(self.t + 0.005)
        self.request(k, a.done(), "WRITE time and date (g50v1) -> addr %d" % self.out[k]["addr"], "ctl")

    def clear_restart(self, k):
        a = DnpApp(2, self.next_seq(k))
        a.iin_clear()
        self.request(k, a.done(), "WRITE g80v1 index 7 = 0: clear DEVICE_RESTART", "ctl")

    def master_rx(self, k, fc, iin, status, info):
        m = self.by["m"]
        tok = self.pending.pop(k, None)
        if k == "rtu":
            m.vars["Last IIN (RTU)"] = iin_text(iin)
            o = self.out["rtu"]
            m.vars["RTU CB1 / CB2"] = "%s / %s" % ("CLOSED" if o["bi"][0] else "OPEN", "CLOSED" if o["bi"][1] else "OPEN")
            m.vars["RTU V / I"] = "%d V / %d A" % (o["ai"][0], o["ai"][1])
        else:
            o = self.out["rc"]
            m.vars["Recloser"] = "LOCKOUT" if o["bi"][1] else ("CLOSED" if o["bi"][0] else "OPEN")
        if tok and tok[1]:
            tok[1](status)
        if iin & 0x80 and self.t - self.clr.get(k, -9.0) > 3.0:
            self.clr[k] = self.t
            self.at(self.t + 0.05, self.clear_restart, k)
            self.at(self.t + 0.3, self.time_sync, k)
            self.at(self.t + 0.6, self.read, k, [0, 1, 2, 3], "Integrity poll after restart")
        elif iin & 0x10 and self.t - self.clr.get(k, -9.0) > 3.0:
            self.clr[k] = self.t
            self.at(self.t + 0.05, self.time_sync, k)

    # -------------------------------------------------------- outstation
    def iin(self, k):
        o = self.out[k]
        v = o["iin"] & ~0x0E
        if o["ev1"]:
            v |= 0x02
        if o["ev2"]:
            v |= 0x04
        if k == "rtu" and self.fault["local"]:
            v |= 0x20
        return v

    def respond(self, k, app, info, kind="resp", uns=False, con=False):
        c = self.conns[k]
        o = self.out[k]
        o["tseq"] = (o["tseq"] + 1) & 63
        c.send(k, dnp_frame(1, o["addr"], False, o["tseq"], app), info, "DNP3", kind)

    def outstation(self, k, req, dst):
        o = self.out[k]
        names_bi = self.BI_NAMES if k == "rtu" else self.RB_NAMES
        names_ai = self.AI_NAMES if k == "rtu" else self.RA_NAMES
        fc, seq = req.b[1], req.b[0] & 15
        hdrs = []
        i = 2
        while i + 2 < len(req.b):
            g, v, q = req.b[i], req.b[i + 1], req.b[i + 2]
            hdrs.append((g, v, q))
            i += 3 + {0x00: 2, 0x06: 0, 0x07: 1, 0x28: 2}.get(q, 0)
            if g == 12:
                idx, code = struct.unpack("<HB", req.b[i:i + 3])
                hdrs[-1] = (g, v, q, idx, code)
                i += 13
            elif g == 50:
                i += 6
            elif g == 80:
                i += 1
        status = 0
        if fc == 1:
            cls = [h[1] - 1 for h in hdrs if h[0] == 60]
            a = DnpApp(129, seq, True, self.iin(k), con=bool((1 in cls and o["ev1"]) or (2 in cls and o["ev2"])))
            if 0 in cls:
                a.bi(0, o["bi"], names_bi)
                a.ai(0, o["ai"], names_ai)
                if o["ctr"]:
                    a.ctr(0, o["ctr"], self.CT_NAMES)
            n1 = n2 = 0
            if 1 in cls and o["ev1"]:
                n1 = len(o["ev1"])
                a.bi_events(o["ev1"], names_bi)
                o["ev1"] = []
            if 2 in cls and o["ev2"]:
                n2 = len(o["ev2"])
                a.ai_events(o["ev2"], names_ai)
                o["ev2"] = []
            iin = self.iin(k)
            p = a.done()
            p.b = p.b[:2] + bytes([iin & 0xFF, iin >> 8]) + p.b[4:]
            for r in p.rows:
                if r[1].startswith("Internal Indications"):
                    r[1] = "Internal Indications (IIN): 0x%02X%02X: %s" % (iin & 0xFF, iin >> 8, iin_text(iin))
            parts = (["static data"] if 0 in cls else []) + (["%d BI + %d AI events" % (n1, n2)] if (n1 or n2) else [])
            what = ", ".join(parts) or "no events"
            self.respond(k, p, "RESPONSE seq %d: %s; IIN %s" % (seq, what, iin_text(iin)), "resp")
            if n1 or n2:
                self.at(self.t + 0.02, self.confirm, k, seq)
            self.at(self.t + 0.01, self.master_rx, k, 129, iin, 0, "")
        elif fc in (3, 4, 5):
            h = [x for x in hdrs if x[0] == 12][0]
            idx, code = h[3], h[4]
            if k == "rtu" and self.fault["local"]:
                status = 7
            elif fc == 3:
                o["sel"] = (idx, code, self.t)
            elif fc == 4:
                s = o.get("sel")
                if not s or s[0] != idx or s[1] != code:
                    status = 2
                elif self.t - s[2] > 10.0:
                    status = 1
                o["sel"] = None
            if idx > 1 or (k == "rc" and idx > 0):
                status = 4
            a = DnpApp(129, seq, True, self.iin(k))
            a.crob(idx, code, 1000, status)
            word = {3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE"}[fc]
            self.respond(k, a.done(), "RESPONSE to %s: CROB echo, status %d %s" % (word, status, CROB_ST[status]), "resp" if status == 0 else "err")
            if status == 0 and fc in (4, 5):
                self.at(self.t + 0.06, self.switch, k, idx, (code >> 6) == 1)
            self.at(self.t + 0.01, self.master_rx, k, 129, self.iin(k), status, "")
        elif fc == 2:
            for h in hdrs:
                if h[0] == 80:
                    o["iin"] &= ~0x0080
                if h[0] == 50:
                    o["iin"] &= ~0x0010
            a = DnpApp(129, seq, True, self.iin(k))
            self.respond(k, a.done(), "RESPONSE to WRITE: null response, IIN %s" % iin_text(self.iin(k)), "ack")
            self.at(self.t + 0.01, self.master_rx, k, 129, self.iin(k), 0, "")
        elif fc in (20, 21):
            o["unsol"] = fc == 20
            a = DnpApp(129, seq, True, self.iin(k))
            self.respond(k, a.done(), "RESPONSE to %s: null response" % DNP_FC[fc], "ack")
            self.at(self.t + 0.01, self.master_rx, k, 129, self.iin(k), 0, "")
        elif fc == 13:
            a = DnpApp(129, seq, True, self.iin(k))
            a.delay(2000)
            self.respond(k, a.done(), "RESPONSE to COLD_RESTART: time delay 2000 ms", "resp")
            self.at(self.t + 2.0, self.restart, k)
        elif fc == 0:
            return
        else:
            a = DnpApp(129, seq, True, self.iin(k) | 0x0100)
            self.respond(k, a.done(), "RESPONSE: IIN2.0 NO_FUNC_CODE_SUPPORT", "err")

    def confirm(self, k, seq, uns=False):
        a = DnpApp(0, seq, uns=uns)
        c = self.conns.get(k)
        if c and c.open:
            self.mtseq[k] = (self.mtseq[k] + 1) & 63
            c.send("m", dnp_frame(self.out[k]["addr"], 1, True, self.mtseq[k], a.done()), "CONFIRM %s seq %d" % ("unsolicited" if uns else "response", seq), "DNP3", "ack")

    def switch(self, k, idx, close):
        o = self.out[k]
        if o["bi"][idx] != int(close):
            o["bi"][idx] = int(close)
            o["ev1"].append((idx, int(close), self.t))
            if k == "rtu" and idx == 0:
                o["ctr"][1] += 1
            self.log("%s: %s %s" % (self.by[k].label, "CB%d" % (idx + 1) if k == "rtu" else "recloser", "CLOSED" if close else "OPENED"))
        if k == "rc":
            if close and o["bi"][1]:
                o["bi"][1] = 0
                o["ev1"].append((1, 0, self.t))
            self.by["rc"].vars["State"] = "CLOSED" if close else "OPEN (SCADA)"
            self.by["rc"].vars["Shots"] = 0
            self.unsol("%s by SCADA command" % ("CLOSED" if close else "OPENED"))

    def restart(self, k):
        o = self.out[k]
        o["iin"] |= 0x0090
        o["ev1"], o["ev2"] = [], []
        o["tseq"] = 0
        self.log("%s restarted: DEVICE_RESTART and NEED_TIME set, event buffer lost" % self.by[k].label)

    def physics(self):
        o = self.out["rtu"]
        base = 182 if o["bi"][0] else 0
        cur = max(0, int(base + 6 * math.sin(self.t / 7.0) + self.rng.normal(0, 2)))
        if abs(cur - o["ai"][1]) > 8:
            o["ai"][1] = cur
            o["ev2"].append((1, cur))
        o["ai"][0] = int(11020 + self.rng.normal(0, 15))
        o["ai"][2] = int(o["ai"][1] * o["ai"][0] * 1.732 * 0.98 / 1000)
        o["ctr"][0] += int(o["ai"][2] * 0.5 / 3600 + 0.5)
        self.by["rtu"].vars["Events queued"] = len(o["ev1"]) + len(o["ev2"])
        self.by["rtu"].vars["Mode"] = "LOCAL" if self.fault["local"] else "REMOTE"
        rc = self.out["rc"]
        rc["ai"][0] = int(96 + self.rng.normal(0, 2)) if rc["bi"][0] else 0

    def unsol(self, why):
        rc = self.out["rc"]
        if not rc.get("unsol") or not self.conns["rc"].open:
            return
        rc["useq"] = (rc["useq"] + 1) & 15
        a = DnpApp(130, rc["useq"], True, self.iin("rc"), con=True, uns=True)
        a.bi_events(rc["ev1"], self.RB_NAMES)
        a.ai_events([(0, rc["ai"][0])], self.RA_NAMES)
        rc["ev1"] = []
        self.respond("rc", a.done(), "UNSOLICITED_RESPONSE seq %d: %s" % (rc["useq"], why), "data")
        self.at(self.t + 0.03, self.confirm, "rc", rc["useq"], True)
        self.at(self.t + 0.03, self.master_rx, "rc", 130, 0, 0, "")

    def recloser_fault(self, shot):
        rc = self.out["rc"]
        if not self.fault["feeder"]:
            return
        rc["bi"][0] = 0
        rc["ai"][0] = 0
        rc["ev1"].append((0, 0, self.t))
        self.by["rc"].vars["Shots"] = shot
        if shot >= 2:
            rc["bi"][1] = 1
            rc["ev1"].append((1, 1, self.t))
            self.by["rc"].vars["State"] = "LOCKOUT"
            self.unsol("TRIP %d - LOCKOUT" % shot)
            return
        self.by["rc"].vars["State"] = "OPEN (reclose in 2 s)"
        self.unsol("TRIP %d (overcurrent)" % shot)
        self.at(self.t + 2.0, self.reclose, shot)

    def reclose(self, shot):
        rc = self.out["rc"]
        rc["bi"][0] = 1
        rc["ev1"].append((0, 1, self.t))
        self.by["rc"].vars["State"] = "CLOSED (reclose attempt)"
        self.unsol("RECLOSE %d" % shot)
        self.at(self.t + 0.4, self.recloser_fault, shot + 1)

    def on_fault(self, key, on):
        if key == "restart" and on:
            self.restart("rtu")
        if key == "feeder":
            if on:
                self.at(self.t + 0.2, self.recloser_fault, 1)
            else:
                rc = self.out["rc"]
                if rc["bi"][1]:
                    self.by["rc"].vars["State"] = "LOCKOUT (close it from SCADA)"

    def tpls(self):
        tg = lambda v: "%s (addr %d)" % (self.by[v].label, self.out[v]["addr"])
        return [Tpl("Integrity poll", [P("k", "Outstation", "rtu", opts=["rtu", "rc"], fmt=tg)],
                    lambda s, v, send: self._read(v["k"], [0, 1, 2, 3], send), "READ class 0, 1, 2, 3: all static data plus all events."),
                Tpl("Event poll", [P("k", "Outstation", "rtu", opts=["rtu", "rc"], fmt=tg)],
                    lambda s, v, send: self._read(v["k"], [1, 2, 3], send), "READ class 1, 2, 3: only what changed since the last poll."),
                Tpl("Control: select before operate", [P("k", "Outstation", "rtu", opts=["rtu", "rc"], fmt=tg), P("i", "Point (CB index)", 0, 0, 3),
                                                       P("op", "Command", "TRIP", opts=["TRIP", "CLOSE"])],
                    lambda s, v, send: self.operate(v["k"], v["i"], v["op"] == "TRIP", "sbo", send), "SELECT then OPERATE a CROB. Point 0 on the recloser closes it after a lockout."),
                Tpl("Control: direct operate", [P("k", "Outstation", "rtu", opts=["rtu", "rc"], fmt=tg), P("i", "Point (CB index)", 1, 0, 3),
                                                P("op", "Command", "TRIP", opts=["TRIP", "CLOSE"])],
                    lambda s, v, send: self.operate(v["k"], v["i"], v["op"] == "TRIP", "direct", send), "One message, no select step."),
                Tpl("Time synchronisation", [P("k", "Outstation", "rtu", opts=["rtu", "rc"], fmt=tg)], lambda s, v, send: self._ts(v["k"], send), "WRITE g50v1 absolute time."),
                Tpl("Cold restart", [P("k", "Outstation", "rtu", opts=["rtu", "rc"], fmt=tg)], lambda s, v, send: self._cold(v["k"], send),
                    "FC 13: the outstation answers with a time delay and restarts.")]

    def _read(self, k, cls, send):
        if send:
            return self.read(k, cls, "Integrity poll" if 0 in cls else "Event poll")
        a = DnpApp(1, self.mseq[k])
        a.classes(cls)
        return Frame(self.t, 0.0001, "m", k, "DNP3", "preview", pdu=dnp_frame(self.out[k]["addr"], 1, True, self.mtseq[k], a.done()))

    def _ts(self, k, send):
        if send:
            return self.time_sync(k)
        a = DnpApp(2, self.mseq[k])
        a.time(self.t)
        return Frame(self.t, 0.0001, "m", k, "DNP3", "preview", pdu=dnp_frame(self.out[k]["addr"], 1, True, self.mtseq[k], a.done()))

    def _cold(self, k, send):
        a = DnpApp(13, self.mseq[k] if not send else self.next_seq(k))
        if send:
            return self.request(k, a.done(), "COLD_RESTART -> addr %d" % self.out[k]["addr"], "ctl")
        return Frame(self.t, 0.0001, "m", k, "DNP3", "preview", pdu=dnp_frame(self.out[k]["addr"], 1, True, self.mtseq[k], a.done()))


# =============================================================== IEC 61850
def goose_pdu(appid, gocb, dataset, goid, tchg, st, sq, conf, ttl, values, sim=False):
    entries = []
    for kind, label, v in values:
        if kind == "bool":
            entries.append(Tbool(0x83, label, v))
        elif kind == "dbpos":
            entries.append(T(0x84, label, bytes([6, 0x80 if v else 0x40]), "%s" % ("on / closed (bits 10)" if v else "off / open (bits 01)"),
                             "Dbpos: 2-bit string, 00 intermediate, 01 off, 10 on, 11 bad"))
        elif kind == "q":
            entries.append(T(0x84, label, bytes([3, 0, 0]), "0x0000 good", "13-bit quality (validity, detail quality, source, test, operator blocked)"))
    pdu = T(0x61, "goosePdu", [
        Tstr(0x80, "gocbRef", gocb, "GOOSE control block that publishes this message"),
        Tint(0x81, "timeAllowedtoLive", ttl, "A subscriber that hears nothing for this long declares the message invalid", "%d ms" % ttl),
        Tstr(0x82, "datSet", dataset, "Dataset whose members follow in allData"),
        Tstr(0x83, "goID", goid),
        Tutc(0x84, "t", tchg, "Time of the last state change"),
        Tint(0x85, "stNum", st, "State number: +1 on every change of the data"),
        Tint(0x86, "sqNum", sq, "Sequence number: +1 on every retransmission, back to 0 after a change"),
        Tbool(0x87, "simulation", sim, "Edition 2 simulation (test) flag"),
        Tint(0x88, "confRev", conf, "Configuration revision: subscribers check it against the SCL file"),
        Tbool(0x89, "ndsCom", False, "Needs commissioning"),
        Tint(0x8A, "numDatSetEntries", len(entries)),
        T(0xAB, "allData", entries, desc="Dataset values in order")])
    body = pdu.enc()
    b = Bld("IEC 61850-8-1 GOOSE", "Generic Object Oriented Substation Event: Ethernet multicast straight from the MAC layer (no IP), repeated with growing gaps.")
    b.u16("APPID", appid, "0x%04X" % appid, "Application identifier (0x0000-0x3FFF for GOOSE).")
    b.u16("Length", 8 + len(body), None, "From APPID to the end of the APDU.")
    b.u16("Reserved 1", 0x8000 if sim else 0, "simulation bit %d" % sim, "Edition 2 uses the top bit for simulation.")
    b.u16("Reserved 2", 0, None, "")
    pdu.put(b, 1)
    return b.done()


def sv_pdu(svid, smp, conf, sync, vals):
    seq = b"".join(struct.pack(">iI", int(v), 0) for v in vals)
    asdu = T(0x30, "ASDU 1", [Tstr(0x80, "svID", svid), T(0x82, "smpCnt", struct.pack(">H", smp), str(smp), "Sample counter 0..3999 (4000 samples/s at 50 Hz), wraps every second"),
                             T(0x83, "confRev", struct.pack(">I", conf), str(conf)),
                             T(0x85, "smpSynch", bytes([sync]), {0: "0 not synchronised", 1: "1 local clock", 2: "2 global (PTP / GPS)"}[sync],
                               "Protection must not use samples that are not time-aligned"),
                             T(0x87, "seqData", seq, "Ia %.0f A, Ib %.0f A, Ic %.0f A, In %.0f A | Va %.0f V, Vb %.0f V, Vc %.0f V" % (
                                 vals[0] / 1000.0, vals[1] / 1000.0, vals[2] / 1000.0, vals[3] / 1000.0, vals[4] / 100.0, vals[5] / 100.0, vals[6] / 100.0),
                               "8 x (INT32 value + 32-bit quality): currents in mA, voltages in 10 mV (9-2LE)")])
    pdu = T(0x60, "savPdu", [T(0x80, "noASDU", b"\x01", "1"), T(0xA2, "seqASDU", [asdu])])
    body = pdu.enc()
    b = Bld("IEC 61850-9-2 Sampled Values", "Merging unit streams digitised CT/VT samples: 80 per cycle (9-2LE).")
    b.u16("APPID", 0x4000, "0x4000", "0x4000-0x7FFF for SV.")
    b.u16("Length", 8 + len(body), None, "")
    b.u16("Reserved 1", 0, None, "")
    b.u16("Reserved 2", 0, None, "")
    pdu.put(b, 1)
    return b.done()


def mms_tpkt(mms, title):
    ppdu = T(0x61, "Presentation: fully-encoded-data", [T(0x30, "PDV-list", [Tint(0x02, "presentation-context-identifier", 3, "3 = MMS abstract syntax"),
                                                                             T(0xA0, "single-ASN1-type", [mms])])])
    body = ppdu.enc()
    b = Bld("TPKT (RFC 1006)", "ISO transport service on top of TCP port 102.")
    b.u8("Version", 3, None, "")
    b.u8("Reserved", 0, None, "")
    b.u16("Length", 4 + 3 + 4 + len(body), None, "Whole TPKT including this header.")
    b.layer("ISO 8073 COTP", "Connection-oriented transport protocol class 0.")
    b.u8("Length indicator", 2, None, "")
    b.u8("PDU type", 0xF0, "0xF0 DT (data)", "")
    b.u8("TPDU number / EOT", 0x80, "EOT (last data unit)", "")
    b.layer("ISO 8327 session", "Give-tokens + data-transfer SPDUs.")
    b.raw("SPDUs", bytes([0x01, 0x00, 0x01, 0x00]), "Give Tokens, Data Transfer", "")
    b.layer("ISO 8823 presentation + MMS (ISO 9506): " + title, "Manufacturing Message Specification, BER encoded.")
    ppdu.put(b, 1)
    return b.done()


def mms_name(dom, item):
    return T(0xA0, "variableSpecification: name", [T(0xA1, "domain-specific", [Tstr(0x1A, "domainId", dom, "Logical device"), Tstr(0x1A, "itemId", item, "LN$FC$DO$DA path")])])


class IEC61850(IpNet):
    key, name, cat = "iec61850", "IEC 61850", "power"
    blurb = "Substation automation"
    medium = "IEC 61850 station bus: GOOSE (layer-2 multicast) between IEDs, MMS (TCP 102) to the station HMI, Sampled Values from a merging unit (shown 1 in 200)"
    faults = [("fault", "Short circuit on feeder 1", "Currents jump in the SV stream; the protection IED trips by GOOSE in milliseconds; the bay controller opens the breaker."),
              ("link", "Protection IED Ethernet link lost", "Its GOOSE stops: the subscriber's timeAllowedtoLive expires and it raises a GOOSE supervision alarm."),
              ("confrev", "Protection IED dataset changed (confRev 2)", "The subscriber still expects confRev 1 and rejects the messages."),
              ("sim", "Protection IED left in simulation mode", "GOOSE carries simulation = TRUE; a subscriber not in test mode ignores it - a trip would be lost."),
              ("sync", "Merging unit loses time synchronisation", "smpSynch = 0: the protection blocks sample-based functions.")]
    spec = [("Standard", "IEC 61850 (parts 6 SCL, 7-x data model, 8-1 MMS / GOOSE, 9-2 SV, 90-x extensions)"),
            ("Model", "Logical devices > logical nodes (XCBR, CSWI, PTOC, MMXU ...) > data objects > attributes, with functional constraints (ST, MX, CO, CF)"),
            ("MMS", "Client / server over TCP 102 (TPKT, COTP, session, presentation, ACSE): read, write, reports, control (SBOw / Oper)"),
            ("GOOSE", "Ethertype 0x88B8, multicast 01:0C:CD:01:xx:xx, VLAN priority 4; stNum / sqNum; repeated 2, 4, 8 ... ms after a change, then every T0"),
            ("SV", "Ethertype 0x88BA, 4000 (50 Hz) or 4800 (60 Hz) samples/s, 8 values per ASDU (9-2LE), PTP time-synchronised"),
            ("Configuration", "SCL files: SSD, SCD, ICD / CID describe the substation, IEDs and data flows")]
    frame = [["GOOSE frame", ("Dst MAC 01:0C:CD:01", 48), ("Src MAC", 48), ("802.1Q", 32), ("0x88B8", 16), ("APPID", 16), ("Length", 16), ("Reserved", 32), ("goosePdu (BER)", "n x 8")]]
    about = ("IEC 61850 describes a whole substation as a data model - breakers (XCBR), switch controllers (CSWI), protection functions (PTOC), "
             "measurements (MMXU) - and maps it to three kinds of traffic: MMS for client/server access from the HMI, GOOSE for fast peer-to-peer "
             "events such as trip signals, and Sampled Values that replace copper wires from instrument transformers. A GOOSE message is "
             "repeated with growing gaps after every change, so a lost frame is recovered within milliseconds.")
    guide = ["Select a GOOSE heartbeat: gocbRef, timeAllowedtoLive, stNum and sqNum. Watch sqNum count up between changes.",
             "Inject the short circuit: SV currents jump, the trip GOOSE bursts (stNum + 1, sqNum 0, 1, 2 ...), the breaker opens.",
             "COMPOSE an MMS operate to close the breaker again: SBOw then Oper, then the report and the new GOOSE state.",
             "Pull the protection IED's link and watch the bay controller's GOOSE supervision alarm after timeAllowedtoLive."]

    def setup(self):
        hosts = [("hmi", "STATION HMI / GATEWAY", "scada", 40, 40, "10.0.61.1", "00:30:a7:00:61:01", "MMS client"),
                 ("prot", "FEEDER PROTECTION IED", "ied", 700, 40, "10.0.61.11", "00:30:a7:00:61:11", "FDR1PROT"),
                 ("bcu", "BAY CONTROLLER IED", "ied", 700, 290, "10.0.61.12", "00:30:a7:00:61:12", "FDR1CTRL"),
                 ("mu", "MERGING UNIT", "ied", 40, 290, "10.0.61.21", "00:30:a7:00:61:21", "MU01 9-2LE")]
        self.star(hosts, sw=("sw", "STATION BUS SWITCH", 380, 160), style="fiber", conn="lc")
        cb = self.node("cb", "CIRCUIT BREAKER", "box", 520, 300, "", "52-1, closed", w=128)
        ct = self.node("ct", "CT / VT", "sensor", 205, 300, "", "600/1 A, 11 kV", w=110)
        self.seg([(700, 326), (648, 326)], "wire", c0="screw", c1="screw")
        self.seg([(158, 326), (205, 326)], "wire", c0="screw", c1="screw")
        for n in (cb, ct):
            n.extra["can"] = False
        self.user = "hmi"
        self.cb_closed = True
        self.trip = False
        self.pub = {"prot": dict(st=1, sq=0, gen=0, tchg=0.0, appid=0x0001, gocb="FDR1PROT/LLN0$GO$gcbTrip", ds="FDR1PROT/LLN0$dsTrip", goid="FDR1_TRIP",
                                 mac="01:0c:cd:01:00:01"),
                    "bcu": dict(st=1, sq=0, gen=0, tchg=0.0, appid=0x0002, gocb="FDR1CTRL/LLN0$GO$gcbPos", ds="FDR1CTRL/LLN0$dsPos", goid="FDR1_CB_POS",
                                mac="01:0c:cd:01:00:02")}
        self.last_rx = 0.0
        self.tripping = False
        self.bcu_st = 1
        self.smp = 0
        self.inv = 0
        self.rpt_seq = 0
        self.ctl_num = 0
        self.conns = {}
        self.by["bcu"].vars.update({"Breaker": "CLOSED", "GOOSE from protection": "OK"})
        self.by["prot"].vars.update({"PTOC1 trip": "no", "Ia": "-"})
        self.by["mu"].vars.update({"smpSynch": "2 (global)", "Ia": "-"})
        self.by["hmi"].vars.update({"Feeder MW": "-", "Breaker (report)": "CLOSED", "Alarms": "-"})
        for k in ("prot", "bcu"):
            self.at(0.02 + 0.05 * (k == "bcu"), self.gpub_tick, k, 0)
        self.every(0.05, self.sv, 0.01)
        self.every(0.25, self.supervise, 0.5)
        self.at(0.1, self.mms_connect)
        self.every(2.0, self.mms_poll, 1.0)

    # ---------------------------------------------------------- GOOSE
    def values(self, k):
        if k == "prot":
            return [("bool", "PTOC1.Op.general (trip)", self.trip), ("q", "PTOC1.Op.q", 0)]
        return [("dbpos", "XCBR1.Pos.stVal", self.cb_closed), ("q", "XCBR1.Pos.q", 0)]

    def gpub_tick(self, k, gen, iv=1.0):
        p = self.pub[k]
        if gen != p["gen"]:
            return
        self.goose(k)
        p["sq"] += 1
        nxt = min(1.0, iv * 2) if iv < 1.0 else 1.0
        self.at(self.t + iv, self.gpub_tick, k, gen, nxt)

    def change(self, k):
        p = self.pub[k]
        p["st"] += 1
        p["sq"] = 0
        p["gen"] += 1
        p["tchg"] = self.t
        self.gpub_tick(k, p["gen"], 0.002)

    def goose(self, k):
        p = self.pub[k]
        if k == "prot" and self.fault["link"]:
            return
        sim = k == "prot" and self.fault["sim"]
        conf = 2 if (k == "prot" and self.fault["confrev"]) else 1
        vals = self.values(k)
        st, sq = p["st"], p["sq"]
        txt = ("trip = %s" % ("TRUE" if self.trip else "false")) if k == "prot" else ("XCBR1.Pos = %s" % ("on" if self.cb_closed else "off"))
        info = "GOOSE %s stNum %d sqNum %d: %s%s%s" % (p["goid"], st, sq, txt, " [simulation]" if sim else "", " confRev 2" if conf == 2 else "")
        pdu = goose_pdu(p["appid"], p["gocb"], p["ds"], p["goid"], p["tchg"], st, sq, conf, 2000, vals, sim)
        fr = self.lan.l2(k, None, 0x88B8, pdu, info, "GOOSE", "ctl" if sq else "data", key="GOOSE %s" % p["goid"], vlan=(4, 0), dmac=p["mac"])
        fr.dd = p["mac"]
        if k == "prot":
            self.at(self.t + 0.0002, self.bcu_rx, st, sq, self.trip, sim, conf)

    def bcu_rx(self, st, sq, trip, sim, conf):
        b = self.by["bcu"]
        if not b.on:
            return
        if conf != 1:
            b.vars["GOOSE from protection"] = "REJECTED (confRev 2, expected 1)"
            return
        if sim:
            b.vars["GOOSE from protection"] = "ignored (simulation flag, IED not in test mode)"
            return
        self.last_rx = self.t
        b.vars["GOOSE from protection"] = "OK (stNum %d)" % st
        new = st != self.bcu_st
        self.bcu_st = st
        if trip and self.cb_closed and new:
            self.log("Bay controller: trip GOOSE received, opening breaker")
            self.at(self.t + 0.045, self.cb_move, False, "protection trip")

    def supervise(self):
        b = self.by["bcu"]
        if self.fault["confrev"] or self.fault["sim"]:
            return
        if self.t - self.last_rx > 2.0 and self.t > 3.0:
            if "ALARM" not in str(b.vars["GOOSE from protection"]):
                self.log("Bay controller: GOOSE from FDR1PROT missing for > timeAllowedtoLive (2000 ms): LGOS supervision alarm")
            b.vars["GOOSE from protection"] = "ALARM: timeAllowedtoLive expired"
            self.by["hmi"].vars["Alarms"] = "GOOSE supervision FDR1CTRL"
        elif self.by["hmi"].vars["Alarms"] != "-" and self.t - self.last_rx < 1.2:
            self.by["hmi"].vars["Alarms"] = "-"

    def cb_move(self, close, why):
        if self.cb_closed == close:
            return
        self.cb_closed = close
        self.by["cb"].sub = "52-1, %s" % ("closed" if close else "OPEN")
        self.by["bcu"].vars["Breaker"] = "CLOSED" if close else "OPEN (%s)" % why
        self.change("bcu")
        self.at(self.t + 0.01, self.report, close)

    # ------------------------------------------------------------- SV
    def currents(self):
        if not self.cb_closed:
            return 0.0
        return 8200.0 if self.fault["fault"] else 310.0 + 8 * math.sin(self.t / 5.0)

    def sv(self):
        self.smp = (self.smp + 200) % 4000
        ia = self.currents()
        sync = 0 if self.fault["sync"] else 2
        ph = 2 * math.pi * 50 * (self.smp / 4000.0)
        vals = [ia * 1000 * math.sin(ph), ia * 1000 * math.sin(ph - 2.094), ia * 1000 * math.sin(ph + 2.094), 0,
                6350 * 100 * math.sin(ph + 0.3) * (0.4 if self.fault["fault"] and self.cb_closed else 1), 6350 * 100 * math.sin(ph - 1.794), 6350 * 100 * math.sin(ph + 2.394), 0]
        info = "SV MU01 smpCnt %d: Ia %.0f A rms, smpSynch %d" % (self.smp, ia, sync)
        fr = self.lan.l2("mu", None, 0x88BA, sv_pdu("MU01", self.smp, 1, sync, vals), info, "SV", "sync", key="SV MU01", vlan=(4, 0), dmac="01:0c:cd:04:00:01")
        fr.dd = "01:0c:cd:04:00:01"
        self.by["mu"].vars.update({"smpSynch": "%d (%s)" % (sync, "none" if sync == 0 else "global"), "Ia": "%.0f A" % ia})
        pr = self.by["prot"]
        pr.vars["Ia"] = "%.0f A" % ia
        if sync == 0:
            pr.vars["PTOC1 trip"] = "BLOCKED (SV not synchronised)"
            return
        if ia > 2000 and not self.trip and not self.tripping:
            self.tripping = True
            self.log("Protection: overcurrent %.0f A > 2000 A, PTOC operates after 30 ms" % ia)
            self.at(self.t + 0.03, self.do_trip)
        elif ia < 100 and self.trip and not self.fault["fault"]:
            self.trip = False
            pr.vars["PTOC1 trip"] = "reset"
            self.change("prot")
        elif ia < 100 and self.trip and not self.cb_closed:
            self.trip = False
            pr.vars["PTOC1 trip"] = "reset (breaker open)"
            self.change("prot")

    def do_trip(self):
        self.tripping = False
        self.trip = True
        self.by["prot"].vars["PTOC1 trip"] = "TRIP (I > 2000 A)"
        self.change("prot")

    # ------------------------------------------------------------ MMS
    def mms_connect(self):
        for k, port in (("prot", 49301), ("bcu", 49302)):
            c = self.tcp("hmi", k, port, 102, "MMS")
            self.conns[k] = c
            c.connect(on_open=lambda k=k: self.at(self.t + 0.005, self.initiate, k))

    def initiate(self, k):
        c = self.conns[k]
        req = T(0xA8, "initiate-RequestPDU", [Tint(0x80, "localDetailCalling", 65000), Tint(0x81, "proposedMaxServOutstandingCalling", 5),
                                               Tint(0x82, "proposedMaxServOutstandingCalled", 5), Tint(0x83, "proposedDataStructureNestingLevel", 10),
                                               T(0xA4, "mmsInitRequestDetail", [Tint(0x80, "proposedVersionNumber", 1),
                                                                                T(0x81, "proposedParameterCBB", bytes([0x03, 0x05, 0xF1, 0x00]), "str1 str2 vnam valt vlis"),
                                                                                T(0x82, "servicesSupportedCalling", bytes([0x03, 0xEE, 0x1C, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18]),
                                                                                  "read, write, getNameList, informationReport ...")])])
        c.send("hmi", mms_tpkt(req, "Initiate-Request"), "MMS Initiate-Request (association, after COTP CR/CC and ACSE AARQ)", "MMS", "ctl")

        def rsp():
            r = T(0xA9, "initiate-ResponsePDU", [Tint(0x80, "localDetailCalled", 65000), Tint(0x81, "negotiatedMaxServOutstandingCalling", 5),
                                                  Tint(0x82, "negotiatedMaxServOutstandingCalled", 5), Tint(0x83, "negotiatedDataStructureNestingLevel", 10),
                                                  T(0xA4, "mmsInitResponseDetail", [Tint(0x80, "negotiatedVersionNumber", 1)])])
            c.send(k, mms_tpkt(r, "Initiate-Response"), "MMS Initiate-Response from %s" % self.by[k].sub, "MMS", "resp")
        self.at(self.t + 0.002, rsp)

    def mms_read(self, k, dom, item, send=True):
        self.inv += 1
        req = T(0xA0, "confirmed-RequestPDU", [Tint(0x02, "invokeID", self.inv), T(0xA4, "read", [T(0xA1, "variableAccessSpecification", [
            T(0xA0, "listOfVariable", [T(0x30, "SEQUENCE", [mms_name(dom, item)])])])])])
        p = mms_tpkt(req, "Read-Request")
        if not send:
            return Frame(self.t, 0.0001, "hmi", k, "MMS", "preview", pdu=p)
        c = self.conns.get(k)
        if not c or not c.open:
            return None
        c.send("hmi", p, "MMS Read-Request %s/%s (invokeID %d)" % (dom, item, self.inv), "MMS", "cmd")
        inv = self.inv
        if self.fault["link"] and k == "prot":
            return None

        def rsp():
            ia = self.currents()
            flt = self.fault["fault"] and self.cb_closed
            val = (ia * 11000 * (0.4 if flt else 1.0) * 1.732 * (0.2 if flt else 0.95) / 1e6) if "TotW" in item else ia
            r = T(0xA1, "confirmed-ResponsePDU", [Tint(0x02, "invokeID", inv), T(0xA4, "read", [T(0xA1, "listOfAccessResult", [Tf32(0x87, "success: floating-point", val)])])])
            c.send(k, mms_tpkt(r, "Read-Response"), "MMS Read-Response invokeID %d: %.4g" % (inv, val), "MMS", "resp")
            if "TotW" in item:
                self.by["hmi"].vars["Feeder MW"] = "%.2f MW" % val
        self.at(self.t + 0.003, rsp)
        return None

    def mms_poll(self):
        self.mms_read("prot", "FDR1PROT", "MMXU1$MX$TotW$mag$f")

    def report(self, closed):
        c = self.conns.get("bcu")
        if not c or not c.open:
            return
        self.rpt_seq += 1
        val = T(0xA2, "XCBR1.Pos (structure)", [T(0x84, "stVal", bytes([6, 0x80 if closed else 0x40]), "on" if closed else "off"),
                                                 T(0x84, "q", bytes([3, 0, 0]), "good"), Tutc(0x91, "t", self.t)])
        r = T(0xA3, "unconfirmed-PDU", [T(0xA0, "informationReport", [
            T(0xA1, "variableListName", [Tstr(0x80, "vmd-specific", "RPT")]),
            T(0xA0, "listOfAccessResult", [Tstr(0x8A, "RptID", "FDR1CTRL/LLN0$BR$brcbPos01"), T(0x84, "OptFlds", bytes([6, 0x7A, 0x00]), "seqNum, time, reason, dataset, entryID"),
                                            T(0x86, "SeqNum", bytes([self.rpt_seq & 0xFF]), str(self.rpt_seq)), Tstr(0x8A, "DatSet", "FDR1CTRL/LLN0$dsPos"),
                                            T(0x84, "Inclusion", bytes([7, 0x80]), "member 1"), val,
                                            T(0x84, "ReasonCode", bytes([1, 0x40]), "data-change")])])])
        c.send("bcu", mms_tpkt(r, "InformationReport"), "MMS InformationReport brcbPos01 seq %d: XCBR1.Pos = %s (data-change)" % (self.rpt_seq, "on" if closed else "off"),
               "MMS", "data")
        self.by["hmi"].vars["Breaker (report)"] = "CLOSED" if closed else "OPEN"

    def operate(self, close, send=True):
        self.ctl_num = (self.ctl_num + 1) & 255

        def wr(item, inv):
            data = T(0xA2, "Oper structure", [Tbool(0x83, "ctlVal", close, "TRUE = close / on"),
                                               T(0xA2, "origin", [Tint(0x85, "orCat", 2, "", "2 station-control"), T(0x89, "orIdent", b"HMI1", '"HMI1"')]),
                                               T(0x86, "ctlNum", bytes([self.ctl_num]), str(self.ctl_num)), Tutc(0x91, "T", self.t),
                                               Tbool(0x83, "Test", False), T(0x84, "Check", bytes([6, 0x00]), "no checks")])
            return T(0xA0, "confirmed-RequestPDU", [Tint(0x02, "invokeID", inv), T(0xA5, "write", [
                T(0xA0, "variableAccessSpecification: listOfVariable", [T(0x30, "SEQUENCE", [mms_name("FDR1CTRL", item)])]),
                T(0xA0, "listOfData", [data])])])
        if not send:
            return Frame(self.t, 0.0001, "hmi", "bcu", "MMS", "preview", pdu=mms_tpkt(wr("CSWI1$CO$Pos$Oper", self.inv + 1), "Write-Request (Oper)"))
        c = self.conns.get("bcu")
        if not c or not c.open:
            return None
        verb = "close" if close else "open"
        self.inv += 1
        c.send("hmi", mms_tpkt(wr("CSWI1$CO$Pos$SBOw", self.inv), "Write-Request (SBOw)"), "MMS Write CSWI1.Pos.SBOw: select %s (invokeID %d)" % (verb, self.inv), "MMS", "cmd")
        inv1 = self.inv
        ok = T(0xA1, "confirmed-ResponsePDU", [Tint(0x02, "invokeID", inv1), T(0xA5, "write", [T(0x81, "success", b"", "NULL")])])
        self.at(self.t + 0.003, lambda: c.send("bcu", mms_tpkt(ok, "Write-Response"), "MMS Write-Response invokeID %d: success (selected)" % inv1, "MMS", "resp"))
        self.inv += 1
        inv2 = self.inv
        self.at(self.t + 0.2, lambda: c.send("hmi", mms_tpkt(wr("CSWI1$CO$Pos$Oper", inv2), "Write-Request (Oper)"),
                                             "MMS Write CSWI1.Pos.Oper: %s (invokeID %d)" % (verb, inv2), "MMS", "cmd"))
        ok2 = T(0xA1, "confirmed-ResponsePDU", [Tint(0x02, "invokeID", inv2), T(0xA5, "write", [T(0x81, "success", b"", "NULL")])])
        self.at(self.t + 0.204, lambda: c.send("bcu", mms_tpkt(ok2, "Write-Response"), "MMS Write-Response invokeID %d: success" % inv2, "MMS", "resp"))
        self.at(self.t + 0.26, self.cb_move, close, "operator")
        return None

    def on_fault(self, key, on):
        if key == "fault" and not on and not self.cb_closed:
            self.log("Fault cleared; breaker stays open until the operator closes it (MMS operate)")

    def tpls(self):
        return [Tpl("Operate breaker (MMS SBOw + Oper)", [P("op", "Command", "close", opts=["close", "open"])], lambda s, v, send: self.operate(v["op"] == "close", send),
                    "Select-before-operate with enhanced security on CSWI1.Pos; the bay controller then drives XCBR1."),
                Tpl("MMS read", [P("k", "Server", "prot", opts=["prot", "bcu"], fmt=lambda v: self.by[v].sub),
                                 P("item", "Item", "MMXU1$MX$TotW$mag$f", opts=["MMXU1$MX$TotW$mag$f", "MMXU1$MX$A$phsA$cVal$mag$f"])],
                    lambda s, v, send: self.mms_read(v["k"], self.by[v["k"]].sub, v["item"], send), "Read one attribute: domain = logical device, item = LN$FC$DO$DA.")]


# ========================================================= IEC 60870-5
I870_T = {1: ("M_SP_NA_1", "single-point information"), 3: ("M_DP_NA_1", "double-point information"), 11: ("M_ME_NB_1", "measured value, scaled"),
          13: ("M_ME_NC_1", "measured value, short float"), 30: ("M_SP_TB_1", "single-point with time tag CP56Time2a"),
          31: ("M_DP_TB_1", "double-point with time tag CP56Time2a"), 36: ("M_ME_TF_1", "short float with time tag CP56Time2a"),
          45: ("C_SC_NA_1", "single command"), 46: ("C_DC_NA_1", "double command"), 50: ("C_SE_NC_1", "set-point command, short float"),
          70: ("M_EI_NA_1", "end of initialization"), 100: ("C_IC_NA_1", "interrogation command"), 103: ("C_CS_NA_1", "clock synchronization command"),
          104: ("C_TS_NA_1", "test command")}
I870_COT = {1: "periodic", 2: "background", 3: "spontaneous", 4: "initialized", 5: "request", 6: "activation", 7: "activation confirmation",
            8: "deactivation", 9: "deactivation confirmation", 10: "activation termination", 20: "interrogated by station", 44: "unknown type",
            45: "unknown cause", 46: "unknown common address", 47: "unknown information object address"}


def cp56(t):
    d = utc(t)
    ms = d.second * 1000 + d.microsecond // 1000
    return struct.pack("<H", ms) + bytes([d.minute, d.hour, d.day | (d.isoweekday() << 5), d.month, d.year % 100])


def el_sp(v):
    return bytes([1 if v else 0]), "SPI %s, quality good" % ("ON" if v else "OFF")


def el_dp(v):
    return bytes([2 if v else 1]), "DPI %d = %s, quality good" % (2 if v else 1, "ON / closed" if v else "OFF / open")


def el_float(v):
    return struct.pack("<f", v) + b"\x00", "%.4g (IEEE 754 float) + QDS 0x00" % v


def el_scaled(v):
    return struct.pack("<h", int(v)) + b"\x00", "%d (scaled) + QDS 0x00" % int(v)


def el_time(t):
    return cp56(t), utc(t).strftime("%d.%m.%y %H:%M:%S.%f")[:-3]


def asdu(typ, cot, ca, objs, neg=False, sq=False, cot_len=2, ca_len=2, ioa_len=3, part="104"):
    """objs: [(ioa, [(label, bytes, text), ...])]."""
    b = Bld("IEC 60870-5-%s ASDU: %s %s" % (part, I870_T.get(typ, ("?",))[0], I870_COT.get(cot, "")),
            "Application service data unit: type, structure qualifier, cause, common address, then information objects.")
    b.u8("Type identification", typ, "%d %s (%s)" % (typ, *I870_T.get(typ, ("?", "?"))), "What the information objects contain.")
    b.u8("Variable structure qualifier", (0x80 if sq else 0) | len(objs), "SQ %d, %d object(s)" % (sq, len(objs)),
         "SQ = 1: one address followed by consecutive elements; SQ = 0: every object has its own address.")
    cv = cot | (0x40 if neg else 0)
    ctxt = "%d %s%s" % (cot, I870_COT.get(cot, "?"), " NEGATIVE" if neg else "")
    if cot_len == 2:
        b.raw("Cause of transmission", bytes([cv, 0]), ctxt + ", originator 0", "Why it was sent (T test bit, P/N negative confirm, cause), then the originator address.")
    else:
        b.u8("Cause of transmission", cv, ctxt, "Why it was sent: periodic, spontaneous, activation, interrogated ...")
    if ca_len == 2:
        b.u16("Common address (ASDU address)", ca, str(ca), "Station / sector address, little-endian.", little=True)
    else:
        b.u8("Common address (ASDU address)", ca, str(ca), "Station address.")
    for ioa, els in objs:
        b.raw("Information object address", ioa.to_bytes(ioa_len, "little"), str(ioa), "Point address (%d bytes)." % ioa_len)
        for lab, data, txt in els:
            b.raw(lab, data, txt, "", d=2)
    return b.done()


def obj(ioa, *els):
    return (ioa, list(els))


class I870Data:
    """Process image of a controlled station (RTU / gateway)."""

    def __init__(self, ca, name):
        self.ca, self.name = ca, name
        self.dp = {1001: True, 1002: True, 1003: False}
        self.sp = {2001: False, 2002: False}
        self.me = {3001: 11.02, 3002: 182.0, 3003: 3.41}
        self.dp_names = {1001: "CB Q1 position", 1002: "CB Q2 position", 1003: "Earth switch"}
        self.sp_names = {2001: "Protection trip", 2002: "Gas alarm"}
        self.me_names = {3001: "Busbar voltage (kV)", 3002: "Feeder current (A)", 3003: "Active power (MW)"}

    def gi_asdus(self, cot_len, ca_len, ioa_len, part):
        el = dict(cot_len=cot_len, ca_len=ca_len, ioa_len=ioa_len, part=part)
        return [asdu(3, 20, self.ca, [obj(a, ("DIQ " + self.dp_names[a], *el_dp(v))) for a, v in self.dp.items()], **el),
                asdu(1, 20, self.ca, [obj(a, ("SIQ " + self.sp_names[a], *el_sp(v))) for a, v in self.sp.items()], **el),
                asdu(13, 20, self.ca, [obj(a, ("Value " + self.me_names[a], *el_float(v))) for a, v in self.me.items()], **el)]


class IEC101(Scenario):
    key, name, cat = "iec101", "IEC 60870-5-101", "power"
    blurb = "Telecontrol over serial links"
    phy, rate = "rs485", 9600
    medium = "IEC 60870-5-101 unbalanced mode over a multidrop serial line (RS-485, 9600 bit/s 8E1): the master polls two RTUs for class 1 / class 2 data"
    nets = [("A", "RS-485 A"), ("B", "RS-485 B"), ("VDIFF", "B - A")]
    lines = ["D", "DE"]
    faults = [("trip", "Feeder breaker trips at RTU 1", "RTU 1 sets ACD (class 1 data waiting) in its next reply; the master fetches the spontaneous M_DP_TB_1."),
              ("noise", "Noise on the line", "Some frames fail the checksum or parity: the master repeats the request with the same FCB."),
              ("rtu2", "RTU 2 offline", "No answer: after the retries the master marks the link down and keeps trying 'request status of link'."),
              ("fcb", "Master forgets to toggle FCB", "The RTU sees an unchanged FCB, assumes its last reply was lost and repeats it instead of sending new data.")]
    spec = [("Standard", "IEC 60870-5-101 (companion standard), -1 FT1.2 frame format, -2 link procedures, -3 / -4 / -5 ASDU structure and application functions"),
            ("Link", "FT1.2: fixed frame 10h C A CS 16h, variable frame 68h L L 68h C A ASDU CS 16h, single character E5h; 8 data bits, even parity"),
            ("Modes", "Unbalanced (master polls, multidrop) or balanced (both may initiate, point-to-point)"),
            ("Control field", "PRM, FCB / FCV (frame count bit toggles per new request), ACD (class 1 data waiting), DFC, function code"),
            ("ASDU", "Type ID, VSQ, cause of transmission, common address, IOA + elements (sizes are project parameters: here COT 1, CA 1, IOA 2 bytes)"),
            ("Typical", "General interrogation (C_IC_NA_1), spontaneous events with CP56Time2a, commands with select / execute")]
    frame = [["Fixed frame", ("10h", 8), ("C", 8), ("A", 8), ("CS", 8), ("16h", 8)],
             ["Variable frame", ("68h", 8), ("L", 8), ("L", 8), ("68h", 8), ("C", 8), ("A", 8), ("ASDU", "L-2 x 8"), ("CS", 8), ("16h", 8)]]
    about = ("IEC 60870-5-101 is the European telecontrol protocol for serial lines - leased lines, radio and multidrop RS-485. In unbalanced mode "
             "the master owns the line and polls each RTU in turn; an RTU flags urgent (class 1) data with the ACD bit so the master comes back "
             "for it. The frame count bit lets the RTU tell a new request from a repetition after a lost reply.")
    guide = ["Watch the link start-up: request status of link, reset of remote link, then the end-of-initialization ASDU.",
             "Follow the general interrogation: activation, confirmation, the inrogen data, termination.",
             "Look at FCB in successive class 2 polls: it toggles for every new request.",
             "Trip the breaker at RTU 1: ACD in its reply, then the class 1 poll that fetches the time-tagged event."]

    def build(self):
        m = self.node("m", "CONTROL CENTRE FEP", "scada", 30, 40, "master", "unbalanced")
        r1 = self.node("r1", "RTU 1 - SUBSTATION A", "rtu", 330, 260, "link 1", "CA 1", w=132)
        r2 = self.node("r2", "RTU 2 - SUBSTATION B", "rtu", 640, 260, "link 2", "CA 2", w=132)
        for n in (r1, r2):
            n.at_top()
        self.trunk(180, 60, 850, [m, r1, r2], "rs485", net="VDIFF", label="RS-485 multidrop, 9600 8E1", t0=True, t1=True)
        self.user = "m"
        self.st = {1: dict(d=I870Data(1, "RTU1"), up=False, fcb=None, last=None, c1=[], c2=[], init=True, gi=False),
                   2: dict(d=I870Data(2, "RTU2"), up=False, fcb=None, last=None, c1=[], c2=[], init=True, gi=False)}
        self.st[2]["d"].me = {3001: 33.1, 3002: 95.0, 3003: 4.9}
        self.fcb = {1: 0, 2: 0}
        self.k = 0
        self.busy = False
        m.vars.update({"Link RTU1": "down", "Link RTU2": "down", "Q1 @RTU1": "-", "Retries": 0})
        r1.vars.update({"Class 1 queue": 0, "Class 2 queue": 0})
        r2.vars.update({"Class 1 queue": 0, "Class 2 queue": 0})
        self.every(0.25, self.cycle, 0.05)
        self.every(5.0, self.cyclic, 4.0)
        self.retry = None

    # framing ----------------------------------------------------------
    def fixed(self, c, a):
        cs = (c + a) & 0xFF
        b = Bld("IEC 60870-5-101 FT1.2 fixed-length frame", "Start 10h, control, link address, checksum, end 16h.")
        b.u8("Start", 0x10, "10h", "Fixed-length frame.")
        self._ctl(b, c)
        b.u8("Link address", a, str(a), "Which station on the multidrop line.")
        b.u8("Checksum", cs, "0x%02X [correct]" % cs, "Arithmetic sum of control + address, modulo 256.")
        b.u8("End", 0x16, "16h", "")
        return b.done()

    def variable(self, c, a, ap):
        cs = (c + a + sum(ap.b)) & 0xFF
        b = Bld("IEC 60870-5-101 FT1.2 variable-length frame", "Start 68h, length twice, 68h, control, address, ASDU, checksum, 16h.")
        b.u8("Start", 0x68, "68h", "")
        b.u8("Length L", len(ap.b) + 2, str(len(ap.b) + 2), "Bytes of control + address + ASDU.")
        b.u8("Length L (repeated)", len(ap.b) + 2, str(len(ap.b) + 2), "Sent twice for safety.")
        b.u8("Start (repeated)", 0x68, "68h", "")
        self._ctl(b, c)
        b.u8("Link address", a, str(a), "")
        b.sub(ap)
        b.u8("Checksum", cs, "0x%02X [correct]" % cs, "Arithmetic sum of all user data bytes (control, address, ASDU), modulo 256.")
        b.u8("End", 0x16, "16h", "")
        return b.done()

    @staticmethod
    def _ctl(b, c):
        prm = c >> 6 & 1
        fn = c & 15
        if prm:
            names = {0: "reset of remote link", 3: "user data, confirm expected", 4: "user data, no reply", 9: "request status of link",
                     10: "request user data class 1", 11: "request user data class 2"}
            txt = "PRM 1, FCB %d, FCV %d, function %d (%s)" % (c >> 5 & 1, c >> 4 & 1, fn, names.get(fn, "?"))
        else:
            names = {0: "ACK", 1: "NACK", 8: "user data (RESPOND)", 9: "NACK: requested data not available", 11: "status of link"}
            txt = "PRM 0, ACD %d, DFC %d, function %d (%s)" % (c >> 5 & 1, c >> 4 & 1, fn, names.get(fn, "?"))
        b.u8("Control field", c, txt, "PRM = from the primary (master); FCB toggles per new request; ACD = class 1 data waiting at the RTU.")

    def send(self, src, dst, pdu, info, kind):
        err = None
        if self.fault["noise"] and self.rng.random() < 0.15:
            err = "Checksum / parity error: frame discarded by the receiver"
        fr = serial_frame(self, src, dst, "IEC 101", info, pdu, 9600, 8, "E", 1, rs485=2, kind=kind, err=err)
        self.tx(fr, ifs=0.004)
        return fr

    # master -----------------------------------------------------------
    def cycle(self):
        if self.busy or not self.by["m"].on:
            return
        self.k = self.k % 2 + 1
        a = self.k
        s = self.st[a]
        if not s["up"]:
            self.request(a, 9, False, "Request status of link")
        elif s.get("acd"):
            self.request(a, 10, True, "Request class 1 data")
        else:
            self.request(a, 11, True, "Request class 2 data")

    def request(self, a, fn, fcv, what, ap=None, repeat=False):
        if fcv and not repeat and not self.fault["fcb"]:
            self.fcb[a] ^= 1
        c = 0x40 | (self.fcb[a] << 5 if fcv else 0) | (0x10 if fcv else 0) | fn
        p = self.fixed(c, a) if ap is None else self.variable(c, a, ap)
        fr = self.send("m", "r%d" % a, p, "%s -> link %d (FCB %d)%s" % (what, a, self.fcb[a] if fcv else 0, " [repeat]" if repeat else ""), "cmd")
        self.busy = True
        tok = (a, fn, fcv, what, ap, self.t)
        self.retry = tok
        self.at(fr.t + fr.dur + 0.15, self.timeout, tok, repeat)
        if not fr.err:
            self.at(fr.t + fr.dur + 0.008, self.rtu, a, c, ap, tok)
        return fr

    def timeout(self, tok, was_repeat):
        if self.retry is not tok:
            return
        a, fn, fcv, what, ap, _ = tok
        self.busy = False
        self.retry = None
        if not was_repeat and self.st[a]["up"]:
            self.by["m"].vars["Retries"] += 1
            self.request(a, fn, fcv, what, ap, repeat=True)
            return
        if self.st[a]["up"]:
            self.log("Master: link %d lost (no reply after retry)" % a)
        self.st[a]["up"] = False
        self.by["m"].vars["Link RTU%d" % a] = "down"

    def master_rx(self, a, c, ap, tok, err):
        if self.retry is not tok:
            return
        self.retry = None
        self.busy = False
        if err:
            self.request(tok[0], tok[1], tok[2], tok[3], tok[4], repeat=True)
            return
        s = self.st[a]
        s["acd"] = bool(c >> 5 & 1)
        fn = c & 15
        if tok[1] == 9 and fn == 11:
            self.request(a, 0, False, "Reset of remote link")
        elif tok[1] == 0 and fn == 0:
            s["up"] = True
            self.fcb[a] = 0
            self.by["m"].vars["Link RTU%d" % a] = "up"
            self.log("Master: link %d up" % a)
        elif ap is not None and ap.b[0] == 70:
            self.at(self.t + 0.05, self.gi, a)
        elif ap is not None and ap.b[0] in (3, 31) and a == 1:
            self.by["m"].vars["Q1 @RTU1"] = "CLOSED" if self.st[1]["d"].dp[1001] else "OPEN"

    def gi(self, a, send=True):
        ap = asdu(100, 6, a, [obj(0, ("QOI", bytes([20]), "20 station interrogation (global)"))], cot_len=1, ca_len=1, ioa_len=2, part="101")
        if not send:
            return Frame(self.t, 0.02, "m", "r%d" % a, "IEC 101", "preview", pdu=self.variable(0x73, a, ap))
        self.at_free(lambda: self.request(a, 3, True, "General interrogation C_IC_NA_1 act", ap))
        return None

    def command(self, a, ioa, on, send=True):
        ap1 = asdu(46, 6, a, [obj(ioa, ("DCO", bytes([0x80 | (2 if on else 1)]), "S/E 1 (select), DCS %d %s" % (2 if on else 1, "ON" if on else "OFF")))],
                   cot_len=1, ca_len=1, ioa_len=2, part="101")
        if not send:
            return Frame(self.t, 0.02, "m", "r%d" % a, "IEC 101", "preview", pdu=self.variable(0x73, a, ap1))
        ap2 = asdu(46, 6, a, [obj(ioa, ("DCO", bytes([2 if on else 1]), "S/E 0 (execute), DCS %d %s" % (2 if on else 1, "ON" if on else "OFF")))],
                   cot_len=1, ca_len=1, ioa_len=2, part="101")
        self.at_free(lambda: self.request(a, 3, True, "Double command SELECT IOA %d %s" % (ioa, "ON" if on else "OFF"), ap1))
        self.at(self.t + 1.6, lambda: self.at_free(lambda: self.request(a, 3, True, "Double command EXECUTE IOA %d %s" % (ioa, "ON" if on else "OFF"), ap2)))
        return None

    def clock(self, a, send=True):
        ap = asdu(103, 6, a, [obj(0, ("CP56Time2a", *el_time(self.t)))], cot_len=1, ca_len=1, ioa_len=2, part="101")
        if not send:
            return Frame(self.t, 0.02, "m", "r%d" % a, "IEC 101", "preview", pdu=self.variable(0x73, a, ap))
        self.at_free(lambda: self.request(a, 3, True, "Clock synchronization C_CS_NA_1", ap))
        return None

    def at_free(self, fn):
        if self.busy:
            self.at(self.t + 0.05, self.at_free, fn)
        else:
            fn()

    # RTU --------------------------------------------------------------
    def rtu(self, a, c, ap, tok):
        n = self.by["r%d" % a]
        if not n.on or (a == 2 and self.fault["rtu2"]):
            return
        s = self.st[a]
        fn = c & 15
        fcv, fcb = c >> 4 & 1, c >> 5 & 1
        if fcv and s["fcb"] == fcb and s["last"] is not None:
            rc, rap, rinfo = s["last"]
            self._reply(a, rc, rap, rinfo + " [REPEATED: FCB unchanged]", tok)
            return
        if fcv:
            s["fcb"] = fcb
        acd = lambda: 0x20 if s["c1"] else 0
        if fn == 9:
            self._reply(a, 0x0B | acd(), None, "Status of link (RTU %d)" % a, tok, store=False)
        elif fn == 0:
            s["fcb"] = None
            s["last"] = None
            if s["init"]:
                s["c1"].append(asdu(70, 4, a, [obj(0, ("COI", bytes([0]), "0 local power switch on"))], cot_len=1, ca_len=1, ioa_len=2, part="101"))
                s["init"] = False
            self._reply(a, 0x00 | acd(), None, "ACK (link reset, FCB expected 1)", tok, store=False)
        elif fn == 3:
            typ = ap.b[0]
            if typ == 100:
                s["c1"].append(asdu(100, 7, a, [obj(0, ("QOI", bytes([20]), "20 station"))], cot_len=1, ca_len=1, ioa_len=2, part="101"))
                s["c1"] += s["d"].gi_asdus(1, 1, 2, "101")
                s["c1"].append(asdu(100, 10, a, [obj(0, ("QOI", bytes([20]), "20 station"))], cot_len=1, ca_len=1, ioa_len=2, part="101"))
            elif typ == 46:
                ioa = ap.b[4] | ap.b[5] << 8
                dco = ap.b[6]
                s["c1"].append(asdu(46, 7, a, [obj(ioa, ("DCO", bytes([dco]), "confirmed %s" % ("select" if dco & 0x80 else "execute")))], cot_len=1, ca_len=1, ioa_len=2, part="101"))
                if not dco & 0x80:
                    on = (dco & 3) == 2
                    self.at(self.t + 0.3, self.change, a, ioa, on)
                    s["c1"].append(asdu(46, 10, a, [obj(ioa, ("DCO", bytes([dco]), "terminated"))], cot_len=1, ca_len=1, ioa_len=2, part="101"))
            elif typ == 103:
                s["c1"].append(asdu(103, 7, a, [obj(0, ("CP56Time2a", *el_time(self.t)))], cot_len=1, ca_len=1, ioa_len=2, part="101"))
            self._reply(a, 0x00 | acd(), None, "ACK (user data accepted)%s" % (", ACD = 1" if s["c1"] else ""), tok)
        elif fn in (10, 11):
            q = s["c1"] if fn == 10 else (s["c2"] or s["c1"])
            if q:
                ap2 = q.pop(0)
                typ, cot = ap2.b[0], ap2.b[2] & 0x3F
                self._reply(a, 0x08 | acd(), ap2, "RESPOND class %d: %s %s, %d object(s)" % (1 if q is s["c1"] else 2, I870_T[typ][0], I870_COT.get(cot, ""), ap2.b[1] & 0x7F), tok)
            else:
                self._reply(a, 0x09 | acd(), None, "NACK: no %s data available" % ("class 1" if fn == 10 else "class 2"), tok)
        n.vars["Class 1 queue"] = len(s["c1"])
        n.vars["Class 2 queue"] = len(s["c2"])

    def _reply(self, a, c, ap, info, tok, store=True):
        p = self.fixed(c, a) if ap is None else self.variable(c, a, ap)
        if store:
            self.st[a]["last"] = (c, ap, info)
        kind = "resp" if ap is not None else ("ack" if (c & 15) in (0, 11) else "ctl")
        fr = self.send("r%d" % a, "m", p, info + (" [ACD]" if c & 0x20 else ""), kind)
        self.at(fr.t + fr.dur + 0.002, self.master_rx, a, c, ap, tok, fr.err)

    def change(self, a, ioa, on):
        s = self.st[a]
        d = s["d"]
        if ioa in d.dp:
            d.dp[ioa] = on
            s["c1"].append(asdu(31, 3, a, [obj(ioa, ("DIQ " + d.dp_names[ioa], *el_dp(on)), ("CP56Time2a", *el_time(self.t)))], cot_len=1, ca_len=1, ioa_len=2, part="101"))
            self.log("RTU %d: %s -> %s (spontaneous, class 1)" % (a, d.dp_names[ioa], "ON" if on else "OFF"))
        elif ioa in d.sp:
            d.sp[ioa] = on
            s["c1"].append(asdu(30, 3, a, [obj(ioa, ("SIQ " + d.sp_names[ioa], *el_sp(on)), ("CP56Time2a", *el_time(self.t)))], cot_len=1, ca_len=1, ioa_len=2, part="101"))

    def cyclic(self):
        for a, s in self.st.items():
            if not s["up"]:
                continue
            d = s["d"]
            d.me[3002] = max(0.0, (182.0 if a == 1 else 95.0) * (1 if d.dp[1001] else 0) + float(self.rng.normal(0, 2)))
            d.me[3003] = d.me[3001] * d.me[3002] * 1.732 * 0.95 / 1000
            s["c2"] = [asdu(13, 1, a, [obj(k, ("Value " + d.me_names[k], *el_float(v))) for k, v in d.me.items()], cot_len=1, ca_len=1, ioa_len=2, part="101")]

    def on_fault(self, key, on):
        if key == "trip" and on:
            self.change(1, 2001, True)
            self.change(1, 1001, False)
        if key == "rtu2" and not on:
            self.st[2]["init"] = True

    def tpls(self):
        rt = lambda v: "RTU %d (link %d)" % (v, v)
        return [Tpl("General interrogation", [P("a", "Station", 1, opts=[1, 2], fmt=rt)], lambda s, v, send: self.gi(v["a"], send),
                    "C_IC_NA_1 with QOI 20; the replies come back through class 1 polls."),
                Tpl("Double command (select + execute)", [P("a", "Station", 1, opts=[1, 2], fmt=rt), P("ioa", "IOA", 1001, opts=[1001, 1002]),
                                                          P("on", "State", "ON", opts=["ON", "OFF"])],
                    lambda s, v, send: self.command(v["a"], v["ioa"], v["on"] == "ON", send), "C_DC_NA_1: select (S/E = 1), then execute (S/E = 0)."),
                Tpl("Clock synchronization", [P("a", "Station", 1, opts=[1, 2], fmt=rt)], lambda s, v, send: self.clock(v["a"], send), "C_CS_NA_1 with CP56Time2a.")]


U_NAMES = {0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act", 0x23: "STOPDT con", 0x43: "TESTFR act", 0x83: "TESTFR con"}


def apci(fmt, ns=0, nr=0, u=0, ap=None):
    b = Bld("IEC 60870-5-104 APCI (%s-format)" % fmt, "Start 68h, APDU length, four control octets. I = numbered information, S = supervisory ack, U = unnumbered control.")
    b.u8("Start", 0x68, "68h", "")
    b.u8("APDU length", 4 + (len(ap.b) if ap else 0), None, "Control octets + ASDU (max 253).")
    if fmt == "I":
        b.u16("Send sequence number N(S)", ns << 1, "%d (bit 0 = 0: I-format)" % ns, "Counts I-frames sent on this connection (15 bits).", little=True)
        b.u16("Receive sequence number N(R)", nr << 1, "%d" % nr, "Acknowledges all I-frames up to N(R) - 1 from the other side.", little=True)
        b.sub(ap)
    elif fmt == "S":
        b.u16("Control 1-2", 0x0001, "0x01 0x00 (S-format)", "", little=True)
        b.u16("Receive sequence number N(R)", nr << 1, "%d" % nr, "Pure acknowledgement, sent after w I-frames or timeout t2.", little=True)
    else:
        b.u8("Control 1", u, "0x%02X %s" % (u, U_NAMES.get(u, "?")), "U-format function: start / stop data transfer or test the link.")
        b.raw("Control 2-4", b"\x00\x00\x00", None, "")
    return b.done()


class IEC104(IpNet):
    key, name, cat = "iec104", "IEC 60870-5-104", "power"
    blurb = "Telecontrol over TCP/IP"
    medium = "IEC 60870-5-104 over TCP port 2404: SCADA (controlling station) connected to two substation gateways (controlled stations, CA 1 and 2)"
    faults = [("trip", "Breaker trip at substation 1", "Spontaneous M_SP_TB_1 + M_DP_TB_1 with CP56Time2a time tags."),
              ("noack", "SCADA stops sending S-frames", "The gateway reaches k = 12 unacknowledged I-frames and stops; after t1 = 15 s it closes the connection."),
              ("ca", "SCADA commands use common address 3", "The gateway answers with a negative confirmation, cause 46 (unknown common address)."),
              ("link", "Substation 2 network cable unplugged", "Silence: after t3 = 20 s the SCADA sends TESTFR act, gets no TESTFR con within t1 and drops the link.")]
    spec = [("Standard", "IEC 60870-5-104 (network access for IEC 60870-5-101 using standard transport profiles); IEC 62351-3 for TLS"),
            ("Transport", "TCP port 2404 (19998 with TLS); the controlled station listens"),
            ("APCI", "68h, length, 4 control octets: I-format (N(S), N(R)), S-format (N(R)), U-format (STARTDT, STOPDT, TESTFR)"),
            ("ASDU", "Like 101 but fixed sizes: COT 2 bytes (with originator), CA 2 bytes, IOA 3 bytes"),
            ("Timers", "t0 30 s connect, t1 15 s ack timeout, t2 10 s (< t1) delayed S-ack, t3 20 s idle test; k = 12 unacked I-frames, w = 8 ack after"),
            ("Redundancy", "Several connections per station, only one STARTDT active")]
    frame = [["I-format APDU", ("68h", 8), ("Length", 8), ("N(S) << 1", 16), ("N(R) << 1", 16), ("ASDU: type", 8), ("VSQ", 8), ("COT + OA", 16), ("CA", 16),
              ("IOA", 24), ("elements", "n x 8")]]
    about = ("IEC 60870-5-104 carries the 101 application layer over TCP/IP. The data part is the same ASDU, but the serial link layer is replaced "
             "by a small APCI with its own sequence numbers and acknowledgements on top of TCP. Data only flows after the SCADA sends STARTDT; "
             "an idle link is tested with TESTFR, and if acknowledgements stop coming the connection is closed and rebuilt.")
    guide = ["Follow the start: TCP handshake, STARTDT act / con, general interrogation (act, actcon, inrogen data, actterm).",
             "Compare N(S) / N(R) in the I-frames with the S-frames the SCADA sends after w = 8 frames.",
             "COMPOSE a double command select + execute on IOA 1001 and watch actcon, actterm and the spontaneous position change.",
             "Stop the S-frames and watch k = 12 and t1 close the connection."]

    def setup(self):
        hosts = [("sc", "SCADA (CONTROLLING)", "scada", 40, 40, "10.20.0.1", "00:50:56:14:00:01", "client"),
                 ("g1", "SUBSTATION 1 GATEWAY", "rtu", 700, 40, "10.20.0.11", "00:1b:7a:14:00:11", "CA 1"),
                 ("g2", "SUBSTATION 2 GATEWAY", "rtu", 700, 290, "10.20.0.12", "00:1b:7a:14:00:12", "CA 2")]
        self.star(hosts, sw=("sw", "WAN ROUTER", 380, 160))
        self.user = "sc"
        self.L = {}
        self.data = {"g1": I870Data(1, "S1"), "g2": I870Data(2, "S2")}
        self.data["g2"].me = {3001: 33.1, 3002: 95.0, 3003: 4.9}
        self.by["sc"].vars.update({"Link S1": "-", "Link S2": "-", "Q1 @S1": "-"})
        for g in ("g1", "g2"):
            self.by[g].vars.update({"V(S) / V(R)": "-", "Unacked I-frames": 0, "STARTDT": "no"})
        self.at(0.05, self.connect, "g1")
        self.at(0.08, self.connect, "g2")
        self.every(1.0, self.timers, 1.0)
        self.every(2.0, self.spont_measure, 3.0)
        self.port = 50000

    def connect(self, g):
        if self.fault["link"] and g == "g2":
            self.at(self.t + 5.0, self.connect, g)
            return
        self.port += 1
        c = self.tcp("sc", g, self.port, 2404, "IEC 104")
        self.L[g] = dict(c=c, vs=0, vr=0, svs=0, svr=0, unack=[], q=[], cnt=0, first=None, started=False, lr_sc=self.t, lr_st=self.t, test=None)
        c.connect(on_open=lambda: self.at(self.t + 0.01, self.startdt, g))

    def startdt(self, g):
        L = self.L[g]
        L["c"].send("sc", apci("U", u=0x07), "U STARTDT act", "IEC 104", "ctl")
        self.at(self.t + 0.004, self._u_con, g, 0x0B)

    def _u_con(self, g, u):
        L = self.L.get(g)
        if not L or not L["c"].open or (self.fault["link"] and g == "g2"):
            return
        L["c"].send(g, apci("U", u=u), "U %s" % U_NAMES[u], "IEC 104", "ack")
        L["lr_sc"] = self.t
        if u == 0x0B:
            L["started"] = True
            self.by[g].vars["STARTDT"] = "yes"
            self.by["sc"].vars["Link S%s" % g[1]] = "STARTDT, data transfer"
            self.at(self.t + 0.02, self.gi, g)
        if u == 0x83:
            L["test"] = None

    # ------------------------------------------------------- I / S frames
    def st_send(self, g, ap, info, kind="data"):
        L = self.L.get(g)
        if not L or not L["c"].open or not L["started"]:
            return
        if len(L["unack"]) >= 12:
            L["q"].append((ap, info, kind))
            self.by[g].vars["Unacked I-frames"] = "%d (k reached, queue %d)" % (len(L["unack"]), len(L["q"]))
            return
        if self.fault["link"] and g == "g2":
            return
        L["c"].send(g, apci("I", L["vs"], L["vr"], ap=ap), "I(%d,%d) %s" % (L["vs"], L["vr"], info), "IEC 104", kind)
        L["vs"] = (L["vs"] + 1) & 0x7FFF
        L["unack"].append(self.t)
        self.by[g].vars["V(S) / V(R)"] = "%d / %d" % (L["vs"], L["vr"])
        self.by[g].vars["Unacked I-frames"] = len(L["unack"])
        self.at(self.t + 0.002, self.sc_rx_i, g, ap)

    def sc_rx_i(self, g, ap):
        L = self.L[g]
        L["svr"] = (L["svr"] + 1) & 0x7FFF
        L["lr_sc"] = self.t
        L["cnt"] += 1
        if L["first"] is None:
            L["first"] = self.t
        if ap.b[0] in (3, 31) and g == "g1":
            self.by["sc"].vars["Q1 @S1"] = "CLOSED" if self.data["g1"].dp[1001] else "OPEN"
        if L["cnt"] >= 8 and not self.fault["noack"]:
            self.sc_ack(g)

    def sc_ack(self, g):
        L = self.L[g]
        L["c"].send("sc", apci("S", nr=L["svr"]), "S(%d) acknowledges %d I-frame(s)" % (L["svr"], L["cnt"]), "IEC 104", "ack")
        L["cnt"] = 0
        L["first"] = None
        self.at(self.t + 0.002, self.st_acked, g)

    def st_acked(self, g):
        L = self.L[g]
        L["unack"] = []
        L["lr_st"] = self.t
        self.by[g].vars["Unacked I-frames"] = 0
        q, L["q"] = L["q"], []
        for ap, info, kind in q:
            self.st_send(g, ap, info, kind)

    def sc_send(self, g, ap, info, kind="cmd", send=True):
        L = self.L.get(g)
        if not send:
            return Frame(self.t, 0.0001, "sc", g, "IEC 104", "preview", pdu=apci("I", L["svs"] if L else 0, L["svr"] if L else 0, ap=ap))
        if not L or not L["c"].open or not L["started"]:
            return None
        L["c"].send("sc", apci("I", L["svs"], L["svr"], ap=ap), "I(%d,%d) %s" % (L["svs"], L["svr"], info), "IEC 104", kind)
        L["svs"] = (L["svs"] + 1) & 0x7FFF
        L["cnt"] = 0
        L["first"] = None
        L["unack"] = []
        if not (self.fault["link"] and g == "g2"):
            self.at(self.t + 0.003, self.station_cmd, g, ap)
        return None

    # ------------------------------------------------------- station side
    def gi(self, g, send=True):
        ca = 3 if self.fault["ca"] else self.data[g].ca
        ap = asdu(100, 6, ca, [obj(0, ("QOI", bytes([20]), "20 station interrogation"))])
        return self.sc_send(g, ap, "C_IC_NA_1 act (general interrogation) CA %d" % ca, "cmd", send)

    def station_cmd(self, g, ap):
        L = self.L[g]
        L["vr"] = (L["vr"] + 1) & 0x7FFF
        L["lr_st"] = self.t
        d = self.data[g]
        typ = ap.b[0]
        ca = ap.b[4] | ap.b[5] << 8
        body = ap.b[6:]
        if ca != d.ca:
            neg = asdu(typ, 46, ca, [obj(int.from_bytes(body[:3], "little"), ("Element (echo)", body[3:], "echo"))], neg=True)
            self.st_send(g, neg, "%s actcon NEGATIVE: cause 46 unknown common address %d" % (I870_T[typ][0], ca), "err")
            return
        if typ == 100:
            self.st_send(g, asdu(100, 7, d.ca, [obj(0, ("QOI", bytes([20]), "20 station"))]), "C_IC_NA_1 actcon", "resp")
            for a in d.gi_asdus(2, 2, 3, "104"):
                self.st_send(g, a, "%s inrogen (%d objects)" % (I870_T[a.b[0]][0], a.b[1] & 0x7F), "data")
            self.st_send(g, asdu(100, 10, d.ca, [obj(0, ("QOI", bytes([20]), "20 station"))]), "C_IC_NA_1 actterm", "resp")
        elif typ in (46, 50, 103):
            ioa = int.from_bytes(body[:3], "little")
            if typ == 46 and ioa not in d.dp:
                self.st_send(g, asdu(46, 47, d.ca, [obj(ioa, ("DCO", body[3:4], "echo"))], neg=True), "C_DC_NA_1 actcon NEGATIVE: cause 47 unknown IOA %d" % ioa, "err")
                return
            self.st_send(g, asdu(typ, 7, d.ca, [obj(ioa, ("Element (echo)", body[3:], "echo"))]), "%s actcon%s" % (
                I870_T[typ][0], (" (select)" if body[3] & 0x80 else " (execute)") if typ == 46 else ""), "resp")
            if typ == 46 and not body[3] & 0x80:
                on = (body[3] & 3) == 2
                self.st_send(g, asdu(46, 10, d.ca, [obj(ioa, ("DCO", body[3:4], "terminated"))]), "C_DC_NA_1 actterm", "resp")
                self.at(self.t + 0.25, self.spont_dp, g, ioa, on)
            if typ == 50:
                v = struct.unpack("<f", body[3:7])[0]
                self.log("Gateway %s: set-point IOA %d = %.3f" % (g[1], ioa, v))

    def spont_dp(self, g, ioa, on):
        d = self.data[g]
        d.dp[ioa] = on
        self.st_send(g, asdu(31, 3, d.ca, [obj(ioa, ("DIQ " + d.dp_names[ioa], *el_dp(on)), ("CP56Time2a", *el_time(self.t)))]),
                     "M_DP_TB_1 spont: %s %s" % (d.dp_names[ioa], "ON" if on else "OFF"), "data")

    def spont_measure(self):
        d = self.data["g1"]
        new = (182.0 if d.dp[1001] else 0.0) + float(self.rng.normal(0, 4))
        if abs(new - d.me[3002]) > 5:
            d.me[3002] = max(0.0, new)
            self.st_send("g1", asdu(36, 3, 1, [obj(3002, ("Value " + d.me_names[3002], *el_float(d.me[3002])), ("CP56Time2a", *el_time(self.t)))]),
                         "M_ME_TF_1 spont: feeder current %.1f A (deadband exceeded)" % d.me[3002], "data")

    def timers(self):
        for g, L in list(self.L.items()):
            if not L["c"].open:
                continue
            if L["first"] is not None and self.t - L["first"] > 10.0 and not self.fault["noack"]:
                self.sc_ack(g)
            if L["unack"] and self.t - L["unack"][0] > 15.0:
                self.log("Gateway %s: t1 expired (no acknowledgement for 15 s): closing the connection" % g[1])
                self.drop(g, g)
                continue
            if L["test"] is not None and self.t - L["test"] > 15.0:
                self.log("SCADA: no TESTFR con within t1: closing the connection to S%s" % g[1])
                self.drop(g, "sc")
                continue
            if L["test"] is None and self.t - L["lr_sc"] > 20.0:
                L["test"] = self.t
                L["c"].send("sc", apci("U", u=0x43), "U TESTFR act (t3 idle timer)", "IEC 104", "ctl")
                self.at(self.t + 0.004, self._u_con, g, 0x83)

    def drop(self, g, who):
        L = self.L[g]
        if who == "sc" and self.fault["link"] and g == "g2":
            L["c"].open = False
            L["c"].state = {k: "CLOSED" for k in L["c"].state}
        else:
            L["c"].close(who)
        L["started"] = False
        self.by[g].vars["STARTDT"] = "no"
        self.by["sc"].vars["Link S%s" % g[1]] = "closed, reconnecting"
        self.at(self.t + 5.0, self.connect, g)

    def on_fault(self, key, on):
        if key == "trip" and on:
            d = self.data["g1"]
            d.sp[2001] = True
            self.st_send("g1", asdu(30, 3, 1, [obj(2001, ("SIQ " + d.sp_names[2001], *el_sp(True)), ("CP56Time2a", *el_time(self.t)))]), "M_SP_TB_1 spont: protection trip ON", "data")
            self.at(self.t + 0.06, self.spont_dp, "g1", 1001, False)
        if key == "noack" and not on:
            for g in self.L:
                if self.L[g]["c"].open and self.L[g]["cnt"]:
                    self.sc_ack(g)

    def tpls(self):
        st = lambda v: "Substation %s (CA %d)" % (v[1], self.data[v].ca)
        return [Tpl("General interrogation", [P("g", "Station", "g1", opts=["g1", "g2"], fmt=st)], lambda s, v, send: self.gi(v["g"], send),
                    "C_IC_NA_1: actcon, all points with cause 20, actterm."),
                Tpl("Double command", [P("g", "Station", "g1", opts=["g1", "g2"], fmt=st), P("ioa", "IOA", 1001, 1, 99999),
                                       P("se", "Step", "select", opts=["select", "execute"]), P("on", "State", "ON", opts=["ON", "OFF"])],
                    lambda s, v, send: self._dc(v, send), "C_DC_NA_1: send 'select' then 'execute'. IOA 1001 / 1002 are breakers; others give cause 47."),
                Tpl("Set-point (short float)", [P("g", "Station", "g1", opts=["g1", "g2"], fmt=st), P("ioa", "IOA", 5001, 1, 99999), P("v", "Value", 10.5, -1000.0, 1000.0, 0.5)],
                    lambda s, v, send: self.sc_send(v["g"], asdu(50, 6, self._ca(v["g"]), [obj(v["ioa"], ("Value + QOS", struct.pack("<f", v["v"]) + b"\x00", "%.3f, QOS 0 (execute)" % v["v"]))]),
                                                    "C_SE_NC_1 act IOA %d = %.3f" % (v["ioa"], v["v"]), "cmd", send), "Set-point command, e.g. a tap-changer or power limit."),
                Tpl("Clock synchronization", [P("g", "Station", "g1", opts=["g1", "g2"], fmt=st)],
                    lambda s, v, send: self.sc_send(v["g"], asdu(103, 6, self._ca(v["g"]), [obj(0, ("CP56Time2a", *el_time(self.t)))]), "C_CS_NA_1 act", "cmd", send),
                    "Sets the station clock (CP56Time2a)."),
                Tpl("TESTFR act", [P("g", "Station", "g1", opts=["g1", "g2"], fmt=st)], lambda s, v, send: self._test(v["g"], send), "U-format link test.")]

    def _ca(self, g):
        return 3 if self.fault["ca"] else self.data[g].ca

    def _dc(self, v, send):
        sel = v["se"] == "select"
        dco = (0x80 if sel else 0) | (2 if v["on"] == "ON" else 1)
        ap = asdu(46, 6, self._ca(v["g"]), [obj(v["ioa"], ("DCO", bytes([dco]), "S/E %d (%s), DCS %d %s" % (sel, v["se"], dco & 3, v["on"])))])
        return self.sc_send(v["g"], ap, "C_DC_NA_1 act %s IOA %d %s" % (v["se"], v["ioa"], v["on"]), "cmd", send)

    def _test(self, g, send):
        if not send:
            return Frame(self.t, 0.0001, "sc", g, "IEC 104", "preview", pdu=apci("U", u=0x43))
        L = self.L.get(g)
        if L and L["c"].open:
            L["c"].send("sc", apci("U", u=0x43), "U TESTFR act", "IEC 104", "ctl")
            self.at(self.t + 0.004, self._u_con, g, 0x83)
        return None
