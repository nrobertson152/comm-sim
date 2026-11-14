"""Aviation and aerospace, part A: avionics buses - ARINC 429, 629, 664 (AFDX),
825, 717, MIL-STD-1553, MIL-STD-1760 (concept level), CANaerospace, ASCB
and TTP/C."""
import math
import struct
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, msb, lsb, crc
from .fam import Lan, eth_pdu, ipv4_pdu, udp_pdu, IpNet
from .phys_b import CanNet, hexdata

# =============================================================== ARINC 429
A429_LABELS = {  # octal label: (name, kind, range, sig bits, unit)
    0o203: ("Pressure altitude", "bnr", 131072.0, 17, "ft"), 0o205: ("Mach", "bnr", 4.096, 16, ""), 0o206: ("Computed airspeed", "bnr", 1024.0, 14, "kt"),
    0o210: ("True airspeed", "bnr", 2048.0, 15, "kt"), 0o212: ("Altitude rate", "bnr", 32768.0, 11, "ft/min"), 0o312: ("Ground speed", "bnr", 4096.0, 15, "kt"),
    0o314: ("True heading", "bnr", 180.0, 15, "deg"), 0o320: ("Magnetic heading", "bnr", 180.0, 15, "deg"), 0o324: ("Pitch angle", "bnr", 180.0, 14, "deg"),
    0o325: ("Roll angle", "bnr", 180.0, 14, "deg"), 0o365: ("Inertial vertical speed", "bnr", 32768.0, 15, "ft/min"), 0o125: ("UTC (hours, minutes)", "bcd", 0, 0, "hh:mm.m"),
}
SSM_BNR = {0: "failure warning", 1: "no computed data", 2: "functional test", 3: "normal operation"}
SSM_BCD = {0: "plus / north / east", 1: "no computed data", 2: "functional test", 3: "minus / south / west"}


def a429_word(label, data19, sdi=0, ssm=3):
    """32-bit word with bit 1 = LSB of the integer. The label is stored with its MSB in bit 1 (as transmitted)."""
    lab = int("{:08b}".format(label)[::-1], 2)
    w = lab | (sdi & 3) << 8 | (data19 & 0x7FFFF) << 10 | (ssm & 3) << 29
    par = 1 - (bin(w).count("1") & 1)
    return w | par << 31


def a429_bnr(label, value):
    name, kind, rng, sig, unit = A429_LABELS[label]
    res = rng / (1 << sig)
    raw = int(round(value / res))
    raw = max(-(1 << sig), min((1 << sig) - 1, raw))
    field = raw & ((1 << (sig + 1)) - 1)
    return (field << (18 - sig)) & 0x7FFFF


def a429_bcd(digits):
    """5 BCD digits into bits 11-29 (most significant digit 3 bits)."""
    v = 0
    for i, d in enumerate(reversed(digits)):
        v |= (d & (7 if i == 4 else 15)) << (4 * i)
    return v & 0x7FFFF


def a429_decode(w):
    lab = int("{:08b}".format(w & 0xFF)[::-1], 2)
    sdi = (w >> 8) & 3
    data = (w >> 10) & 0x7FFFF
    ssm = (w >> 29) & 3
    par = w >> 31
    ok = bin(w).count("1") % 2 == 1
    return lab, sdi, data, ssm, par, ok


def a429_value(lab, data):
    ent = A429_LABELS.get(lab)
    if ent is None:
        return None, ""
    name, kind, rng, sig, unit = ent
    if kind == "bnr":
        raw = data >> (18 - sig)
        if raw & (1 << sig):
            raw -= 1 << (sig + 1)
        return raw * rng / (1 << sig), unit
    d = [(data >> (4 * i)) & 15 for i in range(5)][::-1]
    return "%d%d:%d%d:%d" % tuple(d), ""


def a429_pdu(w, note=None):
    lab, sdi, data, ssm, par, ok = a429_decode(w)
    ent = A429_LABELS.get(lab, ("unknown label", "bnr", 0, 0, ""))
    val, unit = a429_value(lab, data)
    b = Bld("ARINC 429 word: label %03o %s" % (lab, ent[0]), "32-bit word, bipolar return-to-zero, one transmitter to up to 20 receivers")
    b.b += w.to_bytes(4, "little")
    b.rows.append([1, "Label (bits 1-8): %03o octal - %s" % (lab, ent[0]), 0, 1, "Identifies the parameter. Sent MSB first, the rest of the word LSB first."])
    b.rows.append([1, "SDI (bits 9-10): %d" % sdi, 1, 1, "Source/destination identifier (e.g. which of several identical systems)"])
    if ent[1] == "bnr" and val is not None:
        b.rows.append([1, "Data (bits 11-29, BNR): %s %s" % (("%.4f" % val).rstrip("0").rstrip("."), unit), 1, 3,
                       "Two's complement, MSB at bit 28, sign bit 29; %d significant bits over range %g %s" % (ent[3], ent[2], unit)])
    elif ent[1] == "bcd" and val is not None:
        b.rows.append([1, "Data (bits 11-29, BCD): %s" % val, 1, 3, "Binary-coded decimal digits"])
    else:
        b.rows.append([1, "Data (bits 11-29): 0x%05X" % data, 1, 3, ""])
    b.rows.append([1, "SSM (bits 30-31): %d%d %s" % (ssm >> 1, ssm & 1, (SSM_BCD if ent[1] == "bcd" else SSM_BNR)[ssm]), 3, 1, "Sign/status matrix: validity of the data"])
    b.rows.append([1, "Parity (bit 32): %d [%s]" % (par, "odd parity OK" if ok else "PARITY ERROR"), 3, 1, "Odd parity over all 32 bits"])
    if note:
        b.rows.append([0, note, None, 0, ""])
    return b.done()


def a429_wire(words, bit=10e-6, gap=4, invert=False):
    w = Wire(bit=bit)
    w.set("W", 0.0, 0)
    t = 2 * bit
    for k, word in enumerate(words):
        t0 = t
        for i in range(32):
            b = (word >> i) & 1
            lvl = (1 if b else -1) * (-1 if invert else 1)
            w.set("W", t, lvl)
            w.set("W", t + bit / 2, 0)
            t += bit
        lab = int("{:08b}".format(word & 0xFF)[::-1], 2)
        w.seg(t0, t0 + 8 * bit, "LABEL %03o" % lab, 2, 1)
        w.seg(t0 + 8 * bit, t0 + 10 * bit, "SDI", 4, 1)
        w.seg(t0 + 10 * bit, t0 + 29 * bit, "DATA", 1, 1)
        w.seg(t0 + 29 * bit, t0 + 31 * bit, "SSM", 5, 1)
        w.seg(t0 + 31 * bit, t0 + 32 * bit, "P", 7, 1)
        t += gap * bit
    w.end(t)
    return w


class ARINC429(Scenario):
    key, name, cat = "a429", "ARINC 429", "aero"
    blurb = "Commercial aircraft avionics"
    phy, rate = "a429", 100000
    medium = "ARINC 429 (Mark 33 DITS): one transmitter (ADIRU) per twisted shielded pair, receivers in parallel (FMS, EFIS, autopilot); 100 kbit/s bipolar RZ"
    nets = [("VDIFF", "A - B (bipolar RZ, +/-10 V)"), ("A", "line A"), ("B", "line B")]
    lines = ["W"]
    faults = [("swap", "EFIS input wired with A and B swapped", "Every bit inverts. Parity cannot catch it: inverting all 32 bits of an odd-parity word keeps odd parity, so the EFIS sees wrong labels."),
              ("speed", "Autopilot receiver set to low speed (12.5 kbit/s)", "The receiver times 80 us bits on a 10 us signal: no valid words at all."),
              ("ssm", "Air data module failure", "The ADIRU keeps sending air data words with SSM 00 = failure warning: displays show red flags."),
              ("gap", "Word gap reduced below 4 bit times", "Receivers resynchronise on the NULL gap between words; without it they lose word framing.")]
    spec = [("Standard", "ARINC Specification 429 (Mark 33 Digital Information Transfer System), since 1977"),
            ("Topology", "Simplex: one transmitter per bus, up to 20 receivers; bidirectional data needs two buses"),
            ("Electrical", "Twisted shielded pair, bipolar return-to-zero: HI +10 V, NULL 0 V, LO -10 V (differential)"),
            ("Speed", "High speed 100 kbit/s, low speed 12.5-14.5 kbit/s (never mixed on one bus); at least 4 NULL bit times between words"),
            ("Word", "32 bits: label (8, octal), SDI (2), data (19: BNR, BCD or discrete), SSM (2), odd parity"),
            ("Labels", "Standardised per equipment: 203 pressure altitude, 206 CAS, 314 true heading, 324 pitch, 325 roll ...")]
    frame = [["ARINC 429 word", ("Label", 8), ("SDI", 2), ("Data (BNR / BCD)", 19), ("SSM", 2), ("P", 1)]]
    about = ("ARINC 429 has carried avionics data in airliners for decades. Each transmitter owns its own wire pair and broadcasts a stream of "
             "32-bit words; any number of receivers (up to 20) listen. The 8-bit label - written in octal - says what the word is, so a receiver simply "
             "picks the labels it needs. Bits are bipolar return-to-zero, so every bit carries its own clock edge and the 4-bit null gap marks word "
             "boundaries.")
    guide = ["Select label 203 (pressure altitude): read SDI, the BNR data, SSM 11 = normal and the parity.",
             "SCOPE the differential signal: +10 V for a 1, -10 V for a 0, back to 0 V in the middle of every bit.",
             "Note that the label is sent MSB first while the data field is sent LSB first.",
             "Swap A/B at the EFIS: why does parity not catch it?",
             "COMPOSE your own label with a value and watch the BNR encoding."]

    def build(self):
        tx = self.node("adiru", "ADIRU 1", "box", 30, 150, "TX", "air data + inertial").at_right()
        rxs = [self.node("fms", "FMS 1", "ecu", 640, 30, "RX"), self.node("efis", "EFIS / PFD", "display", 640, 150, "RX"), self.node("fcc", "AUTOPILOT FCC", "pilot", 640, 270, "RX")]
        x = 420
        self.seg([tx.port, (x, tx.port[1])], "tsp", net="VDIFF", label="78 Ω shielded twisted pair", c0="arinc600", col=(210, 210, 210))
        for r in rxs:
            r.at_left()
            self.seg([(x, tx.port[1]), (x, r.port[1]), r.port], "tsp", net="VDIFF", c1="arinc600", col=(210, 210, 210))
        self.user = "adiru"
        self.alt, self.cas, self.hdg = 35000.0, 280.0, 72.0
        self.pitch, self.roll = 2.5, 0.0
        self.by["adiru"].ctl = [("Altitude ft", "ALT", 0.0, 45000.0, 100.0, lambda v: "%.0f" % v)]
        self.by["adiru"].vars.update({"Altitude ft": 35000.0})
        for r in rxs:
            r.vars.update({"Altitude": "-", "CAS": "-", "Heading": "-", "Status": "-"})
        self.sched = [(0o203, 0.0625), (0o206, 0.0625), (0o314, 0.05), (0o324, 0.025), (0o325, 0.025), (0o125, 1.0)]
        for i, (lab, per) in enumerate(self.sched):
            self.every(per, self.send_label, 0.003 * i, 0.0, lab)

    def value(self, lab):
        self.alt = self.by["adiru"].vars["Altitude ft"]
        return {0o203: self.alt + 3 * math.sin(self.t), 0o206: self.cas + math.sin(self.t / 3), 0o314: self.hdg + 0.2 * math.sin(self.t / 5),
                0o324: self.pitch + 0.3 * math.sin(self.t * 1.3), 0o325: self.roll + 2 * math.sin(self.t / 4)}.get(lab)

    def word_for(self, lab, ssm=None):
        if A429_LABELS[lab][1] == "bcd":
            u = __import__("datetime").datetime(2026, 11, 14, 12, 0, 0) + __import__("datetime").timedelta(seconds=self.t)
            d = [u.hour // 10, u.hour % 10, u.minute // 10, u.minute % 10, u.second // 6]
            return a429_word(lab, a429_bcd(d), 0, 0 if ssm is None else ssm)
        v = self.value(lab)
        if ssm is None:
            ssm = 0 if (self.fault["ssm"] and lab in (0o203, 0o206)) else 3
        return a429_word(lab, a429_bnr(lab, v), 0, ssm)

    def send_label(self, lab, word=None, kind="data"):
        if not self.by["adiru"].on:
            return
        w = word if word is not None else self.word_for(lab)
        lab2, sdi, data, ssm, par, ok = a429_decode(w)
        val, unit = a429_value(lab2, data)
        gap = 1 if self.fault["gap"] else 4
        err = "Word gap 1 bit: receivers lose word synchronisation" if self.fault["gap"] and self.rng.random() < 0.3 else None
        info = "%03o %s = %s%s" % (lab2, A429_LABELS.get(lab2, ("?",))[0], (("%.2f" % val) if isinstance(val, float) else val), (" " + unit) if unit else "")
        if ssm == 0 and A429_LABELS.get(lab2, ("", "bnr"))[1] == "bnr":
            info += "  [SSM failure warning]"
        fr = Frame(self.t, (32 + gap) * 10e-6, "adiru", ["fms", "efis", "fcc"], "ARINC 429", info, pdu=a429_pdu(w), kind=kind, err=err,
                   wirefn=lambda f, w=w, gap=gap: a429_wire([w], gap=gap), key="label %03o" % lab2)
        self.tx(fr)
        self.receive(w, err)

    def receive(self, w, err):
        lab, sdi, data, ssm, par, ok = a429_decode(w)
        val, unit = a429_value(lab, data)
        for rid in ("fms", "efis", "fcc"):
            n = self.by[rid]
            if not n.on:
                continue
            if rid == "fcc" and self.fault["speed"]:
                n.vars["Status"] = "NO VALID WORDS (receiver at 12.5 kbit/s)"
                continue
            ww = w
            if rid == "efis" and self.fault["swap"]:
                ww = (~w) & 0xFFFFFFFF
                l2, _, d2, s2, _, ok2 = a429_decode(ww)
                n.vars["Status"] = "receiving label %03o instead of %03o (parity %s!)" % (l2, lab, "OK" if ok2 else "bad")
                n.vars["Altitude"] = n.vars["CAS"] = n.vars["Heading"] = "--- (no label 203/206/314)"
                continue
            if err:
                continue
            n.vars["Status"] = "receiving OK"
            if val is None:
                continue
            txt = ("%.0f %s" % (val, unit)) if isinstance(val, float) else str(val)
            if ssm == 0:
                txt = "FAIL FLAG"
            if lab == 0o203:
                n.vars["Altitude"] = txt
            elif lab == 0o206:
                n.vars["CAS"] = txt
            elif lab == 0o314:
                n.vars["Heading"] = txt

    def cond(self, net):
        c = super().cond(net)
        return c

    def tpls(self):
        labs = sorted(k for k, v in A429_LABELS.items() if v[1] == "bnr")
        return [Tpl("BNR word", [P("lab", "Label", 0o203, opts=labs, fmt=lambda v: "%03o %s" % (v, A429_LABELS[v][0])), P("v", "Value", 12500.0, -200000.0, 200000.0, 1.0),
                                 P("ssm", "SSM", 3, opts=[3, 0, 1, 2], fmt=lambda v: "%d%d %s" % (v >> 1, v & 1, SSM_BNR[v]))],
                    lambda s, v, send: self._bnr(v, send), "Encode a value with the label's range and resolution."),
                Tpl("Raw 32-bit word (hex)", [P("w", "Word", "60000183")], lambda s, v, send: self._raw(v, send), "Any 32 bits (bit 1 = LSB).")]

    def _bnr(self, v, send):
        w = a429_word(v["lab"], a429_bnr(v["lab"], v["v"]), 0, v["ssm"])
        if not send:
            return Frame(self.t, 360e-6, "adiru", None, "ARINC 429", "preview", pdu=a429_pdu(w), wirefn=lambda f: a429_wire([w]))
        self.send_label(v["lab"], w, "cmd")
        return None

    def _raw(self, v, send):
        try:
            w = int(v["w"], 16) & 0xFFFFFFFF
        except ValueError:
            w = 0
        if not send:
            return Frame(self.t, 360e-6, "adiru", None, "ARINC 429", "preview", pdu=a429_pdu(w), wirefn=lambda f: a429_wire([w]))
        lab = a429_decode(w)[0]
        self.send_label(lab, w, "cmd")
        return None


# ============================================================ MIL-STD-1553
def m1553_bits(v16):
    return msb(v16 & 0xFFFF, 16) + [1 - (bin(v16 & 0xFFFF).count("1") & 1)]


def cmd_word(rt, tr, sa, wc):
    return (rt & 31) << 11 | (tr & 1) << 10 | (sa & 31) << 5 | (wc & 31)


def m1553_wire(words, line="A", gaps=None):
    """words: list of (kind 'cmd'|'stat'|'data', value16, label). gaps: idle time (s) before each word."""
    tb = 1e-6
    w = Wire(bit=tb)
    w.set(line, 0.0, 2)
    t = 1e-6
    for i, (kind, v, lab) in enumerate(words):
        if gaps and gaps[i]:
            w.set(line, t, 2)
            t += gaps[i]
        t0 = t
        first = 1 if kind in ("cmd", "stat") else 0
        w.set(line, t, first)
        w.set(line, t + 1.5 * tb, 1 - first)
        t += 3 * tb
        for b in m1553_bits(v):
            w.set(line, t, 1 if b else 0)
            w.set(line, t + tb / 2, 0 if b else 1)
            t += tb
        w.seg(t0, t0 + 3 * tb, "SYNC", 7, 0)
        w.seg(t0, t, lab, {"cmd": 2, "stat": 5, "data": 1}[kind], 1)
        w.seg(t0 + 3 * tb, t, "%04X" % v, i % 2, 0)
    w.set(line, t, 2)
    w.end(t + 2e-6)
    return w


MODE_CODES = {0: "Dynamic bus control", 1: "Synchronize", 2: "Transmit status word", 3: "Initiate self test", 4: "Transmitter shutdown", 5: "Override transmitter shutdown",
              8: "Reset remote terminal", 17: "Synchronize (with data word)", 18: "Transmit last command", 19: "Transmit BIT word"}


def m1553_rows(b, words):
    for i, (kind, v, lab) in enumerate(words):
        o = 2 * i
        if kind == "cmd":
            rt, tr, sa, wc = v >> 11, (v >> 10) & 1, (v >> 5) & 31, v & 31
            mode = sa in (0, 31)
            b.rows.append([0, "Command word: RT %d, %s, %s %d, %s %d" % (rt, "transmit" if tr else "receive", "mode" if mode else "subaddress", sa,
                                                                      "mode code" if mode else "word count", wc if (wc or mode) else 32), o, 2,
                           "Sync (+ then -), RT address 5 bits, T/R, subaddress/mode 5 bits, word count/mode code 5 bits, odd parity"])
            b.rows.append([1, "RT address %d%s" % (rt, " (broadcast)" if rt == 31 else ""), o, 1, ""])
            b.rows.append([1, "T/R %d: RT will %s" % (tr, "transmit" if tr else "receive"), o, 1, ""])
            b.rows.append([1, ("Mode code %d: %s" % (wc, MODE_CODES.get(wc, "?"))) if mode else ("Subaddress %d, word count %d" % (sa, wc or 32)), o + 1, 1, ""])
        elif kind == "stat":
            bits = [(10, "message error"), (9, "instrumentation"), (8, "service request"), (4, "broadcast command received"), (3, "busy"), (2, "subsystem flag"),
                    (1, "dynamic bus control acceptance"), (0, "terminal flag")]
            st = ", ".join(n for k, n in bits if v & (1 << k)) or "all clear"
            b.rows.append([0, "Status word: RT %d - %s" % (v >> 11, st), o, 2, "RT address + status bits; sent 4-12 us after the command (or the last data word)"])
        else:
            b.rows.append([1 if i else 0, "Data word %s: 0x%04X" % (lab, v), o, 2, "Sync (- then +), 16 data bits MSB first, odd parity"])


class MIL1553(Scenario):
    key, name, cat = "m1553", "MIL-STD-1553", "aero"
    blurb = "Military avionics data bus"
    phy, rate = "m1553", 1000000
    medium = "MIL-STD-1553B: dual-redundant 1 Mbit/s Manchester bus (A and B), transformer-coupled stubs, mission computer = bus controller, 4 remote terminals + bus monitor"
    nets = [("BUS A", "bus A (twinax, transformer coupled)"), ("BUS B", "bus B")]
    lines = ["A", "Bb"]
    faults = [("rt_dead", "Air data computer (RT 2) stops responding", "No status word within 14 us: the BC retries on bus B, then marks the RT failed."),
              ("bus_a", "Bus A stub shorted", "Every transfer on bus A fails; the BC switches the whole schedule to bus B."),
              ("wc", "Display processor rejects word count 18", "An invalid message: the RT suppresses its status word and sets the message error bit, reported on the next Transmit Status mode code."),
              ("busy", "INS (RT 1) busy", "The RT answers with the busy bit set and no data words."),
              ("no_termA1", "Bus A terminator missing", "78 Ω termination removed: reflections distort the Manchester waveform.")]
    spec = [("Standard", "MIL-STD-1553B (1978) with Notices 1-4; SAE AS15531 commercial equivalent"),
            ("Physical", "Twinax 70-85 Ω, Manchester II bi-phase at 1 Mbit/s, transformer-coupled stubs up to 6 m, terminated both ends; dual-redundant buses A and B"),
            ("Roles", "One bus controller (BC) commands everything; up to 31 remote terminals (RT 0-30, 31 = broadcast); bus monitors listen"),
            ("Words", "20 bit times: 3-bit sync, 16 data bits, odd parity. Command and status words share the +/- sync, data words use -/+"),
            ("Transfers", "BC->RT, RT->BC, RT->RT, mode codes, broadcast; RT response 4-12 us, no-response timeout 14 us"),
            ("Scheduling", "Major / minor frames (e.g. 20 ms) with messages at fixed rates")]
    frame = [["Command word", ("Sync", 3), ("RT addr", 5), ("T/R", 1), ("Subaddr / mode", 5), ("Word count / mode code", 5), ("P", 1)],
             ["Status word", ("Sync", 3), ("RT addr", 5), ("ME", 1), ("Instr", 1), ("SR", 1), ("Res", 3), ("BCR", 1), ("Busy", 1), ("SF", 1), ("DBCA", 1), ("TF", 1), ("P", 1)]]
    about = ("MIL-STD-1553 is the command/response bus of military aircraft, helicopters and spacecraft. One bus controller owns the bus: it "
             "sends a command word, the addressed remote terminal answers with a status word (and data words) within microseconds, and nothing "
             "else may talk. Every message runs on one of two independent buses, so a damaged cable or connector does not stop the system.")
    guide = ["Follow one BC->RT transfer: command word, data words, then the RT's status word.",
             "Follow an RT->BC transfer: command word with T/R = 1, status word, then the data.",
             "LOGIC: command and data words differ only by the sync polarity.",
             "Make RT 2 stop responding: watch the 14 us timeout and the retry on bus B.",
             "COMPOSE a 'Transmit status word' mode code to any RT."]

    def build(self):
        bc = self.node("bc", "MISSION COMPUTER (BC)", "ecu", 30, 40, "BC", "bus controller")
        rts = [self.node("rt1", "INS", "compass", 250, 40, "RT 1"), self.node("rt2", "AIR DATA COMPUTER", "box", 470, 40, "RT 2"),
               self.node("rt3", "DISPLAY PROCESSOR", "display", 690, 40, "RT 3"), self.node("rt4", "RADAR ALTIMETER", "radar", 250, 290, "RT 4"),
               self.node("bm", "BUS MONITOR", "scope", 600, 290, "BM", "records all")]
        nodes = [bc] + rts
        for n in nodes[4:]:
            n.at_top()
        self.trunk(180, 30, 860, nodes, "twinax", net="BUS A", label="Bus A (twinax, couplers + stubs)", drop_conn="twinax", t0=True, t1=True, tlabel="78 Ω", tkey="termA")
        self.trunk(220, 30, 860, [], "twinax", net="BUS B", label="Bus B (redundant)", t0=True, t1=True, tlabel="78 Ω", tkey="termB")
        for n in nodes:
            x = n.port[0]
            self.seg([(x - 6, 180 + (0 if n.y < 180 else 0)), (x - 6, 220)], "twinax", net="BUS B", w=3, col=(80, 80, 96))
        self.user = "bc"
        self.rt_fail = set()
        self.me = set()
        self.minor = 0
        for n in rts:
            n.vars.update({"Last message": "-", "Status": "OK"})
        self.by["bc"].vars.update({"Bus in use": "A", "Retries": 0, "Failed RTs": "-"})
        self.every(0.02, self.minor_frame, 0.005)

    def addr(self, nid):
        return int(self.by[nid].addr.split()[-1])

    def bus(self):
        return "B" if self.fault.get("bus_a") else "A"

    def transfer(self, words, info, kind="data", err=None, bus=None, dst=None, src="bc"):
        bus = bus or self.bus()
        line = "A" if bus == "A" else "Bb"
        b = Bld()
        b.b += b"".join(v.to_bytes(2, "big") for _, v, _ in words)
        m1553_rows(b, words)
        p = Pdu(bytes(b.b), b.rows)
        dur = 1e-6 + len(words) * 20e-6 + 10e-6
        fr = Frame(self.t, dur, src, dst, "MIL-STD-1553", "[bus %s] %s" % (bus, info), pdu=p, kind=kind, err=err, wirefn=lambda f, w=words, ln=line: m1553_wire(w, ln),
                   key=info.split(":")[0])
        return self.tx(fr, bus="1553", ifs=4e-6)

    def bc_rt(self, rt, sa, data, info, bus=None):
        nid = "rt%d" % rt
        n = self.by.get(nid)
        cw = cmd_word(rt, 0, sa, len(data) % 32)
        words = [("cmd", cw, "CMD")] + [("data", d, "D%d" % (i + 1)) for i, d in enumerate(data)]
        dead = n is None or not n.on or nid in self.rt_fail or (rt == 2 and self.fault.get("rt_dead"))
        wc_bad = rt == 3 and self.fault.get("wc") and len(data) == 18
        if dead or wc_bad or (self.fault.get("bus_a") and (bus or self.bus()) == "A"):
            why = "no status word within 14 us" if not wc_bad else "RT 3 rejected word count %d: status suppressed, message error bit set" % len(data)
            self.transfer(words, "BC->RT %d SA %d: %s - TIMEOUT (%s)" % (rt, sa, info, why), "err", err="No response", bus=bus, dst=nid)
            if wc_bad:
                self.me.add(rt)
            return False
        st = (rt << 11) | ((1 << 10) if rt in self.me else 0)
        self.transfer(words + [("stat", st, "STATUS")], "BC->RT %d SA %d: %s" % (rt, sa, info), "cmd", bus=bus, dst=nid)
        n.vars["Last message"] = "received SA %d (%d words)" % (sa, len(data))
        return True

    def rt_bc(self, rt, sa, data, info, bus=None):
        nid = "rt%d" % rt
        n = self.by.get(nid)
        cw = cmd_word(rt, 1, sa, len(data) % 32)
        dead = n is None or not n.on or nid in self.rt_fail or (rt == 2 and self.fault.get("rt_dead")) or (self.fault.get("bus_a") and (bus or self.bus()) == "A")
        if dead:
            self.transfer([("cmd", cw, "CMD")], "RT %d->BC SA %d: %s - TIMEOUT" % (rt, sa, info), "err", err="No response", bus=bus, dst=nid)
            return False
        busy = rt == 1 and self.fault.get("busy")
        st = (rt << 11) | ((1 << 3) if busy else 0) | ((1 << 10) if rt in self.me else 0)
        words = [("cmd", cw, "CMD"), ("stat", st, "STATUS")] + ([] if busy else [("data", d, "D%d" % (i + 1)) for i, d in enumerate(data)])
        self.transfer(words, "RT %d->BC SA %d: %s%s" % (rt, sa, info, " - BUSY, no data" if busy else ""), "resp" if not busy else "evt", bus=bus, dst=nid)
        n.vars["Last message"] = "transmitted SA %d" % sa
        n.vars["Status"] = "BUSY" if busy else ("message error" if rt in self.me else "OK")
        return True

    def mode(self, rt, code, bus=None):
        nid = "rt%d" % rt
        cw = cmd_word(rt, 1, 31, code)
        n = self.by.get(nid)
        if n is None or not n.on or (rt == 2 and self.fault.get("rt_dead")):
            self.transfer([("cmd", cw, "MODE CMD")], "Mode code %d (%s) to RT %d - TIMEOUT" % (code, MODE_CODES.get(code, ""), rt), "err", err="No response", bus=bus, dst=nid)
            return
        st = (rt << 11) | ((1 << 10) if rt in self.me else 0)
        words = [("cmd", cw, "MODE CMD"), ("stat", st, "STATUS")]
        if code == 19:
            words.append(("data", 0x0000, "BIT WORD"))
        self.transfer(words, "Mode code %d %s to RT %d%s" % (code, MODE_CODES.get(code, ""), rt, " (message error reported)" if rt in self.me else ""), "ctl", bus=bus, dst=nid)
        if code == 2:
            self.me.discard(rt)

    def minor_frame(self):
        if not self.by["bc"].on:
            return
        self.minor = (self.minor + 1) % 50
        bc = self.by["bc"]
        bc.vars["Bus in use"] = self.bus()
        att = [int(1000 * math.sin(self.t + i)) & 0xFFFF for i in range(6)]
        if not self.rt_bc(1, 2, att, "INS attitude/rates (6 words)"):
            self.retry(lambda b: self.rt_bc(1, 2, att, "INS attitude/rates (retry)", bus=b))
        if self.minor % 2 == 0:
            ad = [int(35000 + 10 * math.sin(self.t)) & 0xFFFF, 2800, 7800, 0x0122]
            if not self.rt_bc(2, 3, ad, "air data: altitude, CAS, Mach, temp"):
                self.retry(lambda b: self.rt_bc(2, 3, ad, "air data (retry)", bus=b), "rt2")
        if self.minor % 5 == 0:
            wc = 18 if self.fault.get("wc") else 16
            self.bc_rt(3, 1, [(0x1000 + i) & 0xFFFF for i in range(wc)], "display page update (%d words)" % wc)
        if self.minor % 10 == 0:
            self.rt_bc(4, 1, [int(2500 + 50 * math.sin(self.t)) & 0xFFFF], "radar altitude")
        if self.minor % 25 == 0 and self.me:
            for rt in list(self.me):
                self.mode(rt, 2)

    def retry(self, fn, nid=None):
        b = "B" if self.bus() == "A" else "A"
        bc = self.by["bc"]
        bc.vars["Retries"] += 1
        if not fn(b) and nid:
            self.rt_fail.add(nid)
            bc.vars["Failed RTs"] = ", ".join(sorted(self.by[x].addr for x in self.rt_fail))
            self.by[nid].state = "FAILED"

    def on_fault(self, key, on):
        if key == "rt_dead" and not on:
            self.rt_fail.discard("rt2")
            self.by["rt2"].state = ""
            self.by["bc"].vars["Failed RTs"] = "-"

    def cond(self, net):
        c = super().cond(net)
        if net == "BUS A" and self.fault.get("no_termA1"):
            c.update(refl=0.35, ringf=6e6, ringd=0.25e-6)
        if net == "BUS A" and self.fault.get("bus_a"):
            c["atten"] = 0.05
        return c

    def tpls(self):
        rts = [1, 2, 3, 4]
        return [Tpl("Mode code to an RT", [P("rt", "RT", 1, opts=rts), P("mc", "Mode code", 2, opts=[2, 1, 19, 8], fmt=lambda v: "%d %s" % (v, MODE_CODES[v]))],
                    lambda s, v, send: self._mode(v, send), "Mode codes use subaddress 31 (or 0)."),
                Tpl("BC->RT receive command", [P("rt", "RT", 3, opts=rts), P("sa", "Subaddress", 5, 1, 30), P("wc", "Word count", 4, 1, 32)],
                    lambda s, v, send: self._rx(v, send), "Bus controller sends data words to an RT subaddress.")]

    def _mode(self, v, send):
        if not send:
            words = [("cmd", cmd_word(v["rt"], 1, 31, v["mc"]), "MODE CMD")]
            b = Bld()
            m1553_rows(b, words)
            return Frame(self.t, 22e-6, "bc", "rt%d" % v["rt"], "MIL-STD-1553", "preview", pdu=Pdu(cmd_word(v["rt"], 1, 31, v["mc"]).to_bytes(2, "big"), b.rows),
                         wirefn=lambda f: m1553_wire(words))
        self.mode(v["rt"], v["mc"])
        return None

    def _rx(self, v, send):
        data = [(0xA000 + i) for i in range(v["wc"])]
        if not send:
            words = [("cmd", cmd_word(v["rt"], 0, v["sa"], v["wc"] % 32), "CMD")] + [("data", d, "D%d" % (i + 1)) for i, d in enumerate(data)]
            b = Bld()
            m1553_rows(b, words)
            return Frame(self.t, 1e-4, "bc", None, "MIL-STD-1553", "preview", pdu=Pdu(b"".join(x[1].to_bytes(2, "big") for x in words), b.rows), wirefn=lambda f: m1553_wire(words))
        self.bc_rt(v["rt"], v["sa"], data, "user data (%d words)" % v["wc"])
        return None


class MIL1760(MIL1553):
    key, name, cat = "m1760", "MIL-STD-1760", "aero"
    blurb = "Aircraft-store electrical interface"
    medium = "MIL-STD-1760 (concept level): the standard aircraft-to-store electrical interface; its data interface is a MIL-STD-1553 bus. Only generic bus traffic is simulated here."
    faults = [("rt_dead", "Store not responding on the data bus", "The bus controller times out (14 us) and retries on the second bus."),
              ("bus_a", "Bus A path open at the station connector", "Transfers move to bus B (the interface carries both buses).")]
    spec = [("Standard", "MIL-STD-1760 (Aircraft/Store Electrical Interconnection System)"),
            ("Purpose", "One standard electrical interface so different stores can be carried on different aircraft without unique wiring"),
            ("Signal sets", "Dual-redundant MIL-STD-1553 data bus, high-bandwidth signal paths, power (DC and AC), discrete and address signals"),
            ("Connectors", "Standardised station and store connector classes"),
            ("Data", "Messages use normal MIL-STD-1553 command / status / data words"),
            ("Scope here", "Concept level only: this simulator shows the generic data-bus exchange and does not model store-specific functions")]
    about = ("MIL-STD-1760 defines a common electrical interface between an aircraft and the equipment it carries on its stations, so that "
             "integration does not need custom wiring for every combination. Its digital data path is a dual-redundant MIL-STD-1553 bus, which "
             "is what you can watch here; the other signal sets (power, discretes, high-bandwidth paths) are described in SPEC. Store-specific "
             "functions are intentionally not simulated.")
    guide = ["See that the data exchange is ordinary MIL-STD-1553: command, status and data words.",
             "Compare with the MIL-STD-1553 scenario: same words, same timing.",
             "Open the bus A path and watch the bus controller move to bus B."]

    def build(self):
        bc = self.node("bc", "AIRCRAFT COMPUTER (BC)", "ecu", 40, 60, "BC")
        st = self.node("rt1", "STATION INTERFACE", "box", 380, 60, "RT 1", "station connector")
        dev = self.node("rt2", "CARRIED EQUIPMENT", "box", 700, 60, "RT 2", "generic RT")
        self.trunk(200, 30, 860, [bc, st, dev], "twinax", net="BUS A", label="Bus A", drop_conn="mil", t0=True, t1=True, tlabel="78 Ω", tkey="termA")
        self.trunk(240, 30, 860, [], "twinax", net="BUS B", label="Bus B", t0=True, t1=True, tlabel="78 Ω", tkey="termB")
        for n in (bc, st, dev):
            self.seg([(n.port[0] - 6, 200), (n.port[0] - 6, 240)], "twinax", net="BUS B", w=3, col=(80, 80, 96))
        self.user = "bc"
        self.rt_fail, self.me, self.minor = set(), set(), 0
        self.by["bc"].vars.update({"Bus in use": "A", "Retries": 0, "Failed RTs": "-"})
        for n in (st, dev):
            n.vars.update({"Last message": "-", "Status": "OK"})
        self.every(0.05, self.cycle, 0.01)

    def cycle(self):
        self.minor += 1
        if not self.rt_bc(2, 1, [0x0000, 0x0001], "generic status data (2 words)"):
            self.retry(lambda b: self.rt_bc(2, 1, [0x0000, 0x0001], "generic status data (retry)", bus=b), "rt2")
        if self.minor % 4 == 0:
            self.bc_rt(1, 1, [0x1111, 0x2222], "generic data (2 words)")
        if self.minor % 20 == 0:
            self.mode(2, 2)

    def tpls(self):
        return [Tpl("Transmit status word (mode code 2)", [P("rt", "RT", 2, opts=[1, 2])], lambda s, v, send: self._mode({"rt": v["rt"], "mc": 2}, send),
                    "A generic MIL-STD-1553 mode code.")]


# =============================================================== ARINC 717
A717_SYNC = [0o1107, 0o2670, 0o5107, 0o6670]


class ARINC717(Scenario):
    key, name, cat = "a717", "ARINC 717", "aero"
    blurb = "Flight data recording"
    phy, rate = "a717", 768
    medium = "ARINC 717: flight data acquisition unit -> crash-protected flight data recorder and quick access recorder; 12-bit words, Harvard bi-phase, 64 words/s"
    nets = [("HBP", "Harvard bi-phase data pair")]
    lines = ["H"]
    faults = [("wps", "Recorder configured for 256 words/s", "The FDR looks for sync words 4 times faster than they come: it never achieves frame lock."),
              ("sync", "Corrupted sync word in subframe 3", "The recorder loses frame synchronisation until it finds the sync pattern again."),
              ("fdr", "FDR input connector loose", "The FDR stops recording; the maintenance status reports it.")]
    spec = [("Standard", "ARINC 717 (Flight Data Acquisition and Recording System), with ARINC 573 heritage"),
            ("Coding", "Harvard bi-phase (transition every bit, extra mid-bit transition for a 1) or bipolar RZ"),
            ("Words", "12-bit words, LSB first; 64, 128, 256, 512 or 1024 words per second"),
            ("Frame", "4 subframes of 1 s each, each starting with a sync word: 1107, 2670, 5107, 6670 (octal); superframes for slow parameters"),
            ("Content", "Parameter positions defined by the aircraft's data frame layout (e.g. word 2 = altitude)"),
            ("Recording", "FDR (crash protected, 25 h) and QAR / DFDAU outputs for flight data monitoring")]
    frame = [["Subframe (1 s at 64 wps)", ("Sync word", 12), ("Word 2", 12), ("Word 3", 12), ("...", 24), ("Word 64", 12)]]
    about = ("ARINC 717 is how flight data reaches the 'black box'. The acquisition unit samples hundreds of parameters and lays them into a fixed "
             "frame of 12-bit words: every second a subframe starts with a sync word, and each parameter always sits in the same word position. The "
             "recorder only has to find the sync words to know where everything is.")
    guide = ["LOGIC: find the 12-bit sync word at the start of each subframe (1107, 2670, 5107, 6670 octal).",
             "Decode the Harvard bi-phase: every bit cell starts with a transition, a 1 adds one in the middle.",
             "Read the parameters of a subframe in the tree: altitude, airspeed, heading, pitch, roll.",
             "Set the FDR to 256 words/s and watch it fail to lock."]

    def build(self):
        f = self.node("fdau", "FDAU", "box", 40, 150, "", "acquisition unit").at_right()
        r1 = self.node("fdr", "FLIGHT DATA RECORDER", "store", 640, 60, "", "crash protected").at_left()
        r2 = self.node("qar", "QUICK ACCESS RECORDER", "store", 640, 260, "", "flight data monitoring").at_left()
        self.seg([f.port, (420, f.port[1])], "tsp", net="HBP", label="HBP twisted pair", c0="arinc600", col=(210, 210, 210))
        for r in (r1, r2):
            self.seg([(420, f.port[1]), (420, r.port[1]), r.port], "tsp", net="HBP", c1="arinc600", col=(210, 210, 210))
        self.sf = 0
        self.user = None
        r1.vars.update({"Frame lock": "searching", "Recorded subframes": 0})
        r2.vars.update({"Frame lock": "searching", "Recorded subframes": 0})
        self.every(1.0, self.subframe, 0.05)

    def subframe(self):
        if not self.by["fdau"].on:
            return
        sync = A717_SYNC[self.sf]
        if self.fault["sync"] and self.sf == 2:
            sync ^= 0o0040
        alt = int(35000 + 20 * math.sin(self.t / 10)) // 4
        words = [sync, alt & 0xFFF, int(280 * 4) & 0xFFF, int(72 / 360 * 4096) & 0xFFF, int((2.5 + 180) / 360 * 4096) & 0xFFF, int((self.t % 30 - 15 + 180) / 360 * 4096) & 0xFFF]
        words += [(0x100 + i * 37 + int(self.t)) & 0xFFF for i in range(58)]
        b = Bld("ARINC 717 subframe %d" % (self.sf + 1), "64 words of 12 bits")
        names = ["Sync word %d (octal %04o)" % (self.sf + 1, sync), "Word 2: pressure altitude %d ft" % (alt * 4), "Word 3: computed airspeed 280.0 kt", "Word 4: heading 72.0 deg",
                 "Word 5: pitch +2.5 deg", "Word 6: roll %+.1f deg" % (self.t % 30 - 15)]
        for i, wv in enumerate(words):
            b.u16(names[i] if i < len(names) else "Word %d" % (i + 1), wv, "%04o octal (0x%03X)" % (wv, wv), "12-bit word in a 16-bit container" if i else "Marks the start of the subframe")
        tb = 1 / 768.0

        def wf(fr, words=words):
            w = Wire(bit=tb)
            lvl = 0
            w.set("H", 0.0, lvl)
            t = 0.0
            for i, wv in enumerate(words[:8]):
                t0 = t
                for k in range(12):
                    bit = (wv >> k) & 1
                    lvl ^= 1
                    w.set("H", t, lvl)
                    if bit:
                        lvl ^= 1
                        w.set("H", t + tb / 2, lvl)
                    t += tb
                w.seg(t0, t, ("SYNC %04o" % wv) if i == 0 else "W%d %04o" % (i + 1, wv), 7 if i == 0 else i % 2, 1)
            w.end(t)
            return w
        err = None
        for rid in ("fdr", "qar"):
            n = self.by[rid]
            if rid == "fdr" and (self.fault["fdr"] or self.fault["wps"]):
                n.vars["Frame lock"] = "NO INPUT" if self.fault["fdr"] else "NO LOCK (expects 256 wps)"
                continue
            if self.fault["sync"] and self.sf == 2:
                n.vars["Frame lock"] = "LOST (bad sync word)"
                err = "Sync word corrupted: recorders lose frame lock"
                continue
            n.vars["Frame lock"] = "locked"
            n.vars["Recorded subframes"] += 1
        self.tx(Frame(self.t, 1.0, "fdau", ["fdr", "qar"], "ARINC 717", "Subframe %d: sync %04o, alt %d ft" % (self.sf + 1, sync, alt * 4), pdu=b.done(), kind="data", err=err,
                      wirefn=wf, key="subframe %d" % (self.sf + 1)))
        self.sf = (self.sf + 1) % 4


# =============================================================== CANaerospace / ARINC 825
CA_IDS = {300: "Body longitudinal acceleration", 301: "Body lateral acceleration", 302: "Body normal acceleration", 303: "Body pitch rate", 304: "Body roll rate",
          305: "Body yaw rate", 311: "Body pitch angle", 312: "Body roll angle", 315: "Indicated airspeed", 316: "True airspeed", 321: "Heading angle", 322: "Standard altitude",
          500: "Engine #1 N1", 502: "Engine #1 EGT"}
CA_TYPES = {0: "NODATA", 1: "ERROR", 2: "FLOAT", 3: "LONG", 4: "ULONG", 5: "BLONG", 6: "SHORT", 7: "USHORT"}


class CANaerospace(CanNet):
    key, name, cat = "canaerospace", "CAN Aerospace", "aero"
    blurb = "Aircraft and UAV systems"
    rate = 500000
    can_proto = "CANaerospace"
    medium = "CANaerospace (Stock Flight Systems, open standard): 11-bit identifiers by data meaning, 8-byte payload = node ID, data type, service code, message code, 4 data bytes"
    faults = [("type", "AHRS firmware sends heading as LONG", "Receivers expect FLOAT for identifier 321: the display rejects the data type."),
              ("node", "Two nodes configured with node ID 2", "Node-service replies collide and identification becomes ambiguous."),
              ("adc", "Air data computer fails", "No more airspeed/altitude; the display flags the missing identifiers after its timeout.")]
    spec = [("Origin", "CANaerospace (Stock Flight Systems, 1998), open; widely used in small aircraft, UAVs and simulators; NASA AGATE adopted it"),
            ("Identifiers", "By meaning: 0-127 emergency events, 128-199 high-priority node service, 200-299 high-priority user, 300-1799 normal operation data, "
                            "1800-1899 low-priority user, 1900-2031 low-priority node service"),
            ("Payload", "Byte 0 node ID, byte 1 data type (FLOAT, LONG...), byte 2 service code, byte 3 message code (rolling counter), bytes 4-7 data"),
            ("Services", "Node service protocol: identification, time stamp, module configuration ... request/response on channel pairs"),
            ("Relation", "ARINC 825 extends the same ideas for transport aircraft")]
    frame = [["CANaerospace message", ("Node ID", 8), ("Data type", 8), ("Service code", 8), ("Message code", 8), ("Data (4 bytes)", 32)]]
    about = ("CANaerospace puts flight data on CAN in a self-describing way: the identifier says what the data is (e.g. 321 = heading angle), "
             "and every message carries the sender's node ID, the data type and a rolling message code, so receivers can detect missing or stale "
             "data. A node service protocol on separate identifiers lets you ask any node who it is.")
    guide = ["Select identifier 321: data type 2 = FLOAT, the heading in bytes 4-7.",
             "Watch the message code count up in each message (detects lost or repeated frames).",
             "COMPOSE an identification service request to node 2.",
             "Inject the LONG data type and see the display reject it."]

    def setup(self):
        nodes = [self.node("adc", "AIR DATA COMPUTER", "box", 30, 60, "node 1"), self.node("ahrs", "AHRS", "compass", 280, 60, "node 2"),
                 self.node("eng", "ENGINE MONITOR", "engine", 530, 60, "node 3"), self.node("efis", "EFIS DISPLAY", "display", 400, 290, "node 4")]
        nodes[3].at_top()
        self.can_trunk(nodes, 200, conn="dt")
        self.mc = {}
        self.user = "efis"
        self.by["efis"].vars.update({"IAS": "-", "Altitude": "-", "Heading": "-", "Rejected": 0})
        self.every(0.05, self.fast, 0.01)
        self.every(0.25, self.slow, 0.07)

    def ca_send(self, node, cid, val, dtype=2, svc=0, info=None, kind="data"):
        nid = int(self.by[node].addr.split()[-1])
        k = (node, cid)
        self.mc[k] = (self.mc.get(k, -1) + 1) & 0xFF
        data = bytes([nid, dtype, svc, self.mc[k]]) + (struct.pack(">f", val) if dtype == 2 else struct.pack(">i", int(val)))

        def dis(b, o, d=data, cid=cid):
            b.rows.append([0, "CANaerospace: %d %s" % (cid, CA_IDS.get(cid, "")), o, 8, ""])
            b.rows.append([1, "Node ID %d" % d[0], o, 1, "Sender"])
            b.rows.append([1, "Data type %d (%s)" % (d[1], CA_TYPES.get(d[1], "?")), o + 1, 1, "How to read bytes 4-7"])
            b.rows.append([1, "Service code %d" % d[2], o + 2, 1, "Normal operation data: application-defined (often 0)"])
            b.rows.append([1, "Message code %d" % d[3], o + 3, 1, "Rolling counter: detects lost or repeated messages"])
            v = struct.unpack(">f", d[4:8])[0] if d[1] == 2 else struct.unpack(">i", d[4:8])[0]
            b.rows.append([1, "Data: %s" % (("%.3f" % v) if d[1] == 2 else str(v)), o + 4, 4, "Big-endian"])
        self.bus.send(node, cid, data, info=info or "%d %s = %.2f" % (cid, CA_IDS.get(cid, ""), val), kind=kind, dissect=dis, key="ID %d" % cid)

    def fast(self):
        if self.by["adc"].on and not self.fault["adc"]:
            self.ca_send("adc", 315, 112.0 + math.sin(self.t))
            self.by["efis"].vars["IAS"] = "%.1f kt" % (112.0 + math.sin(self.t))
        elif self.fault["adc"]:
            self.by["efis"].vars["IAS"] = "FLAG (no ID 315)"
        if self.by["ahrs"].on:
            h = (95.0 + 3 * math.sin(self.t / 4)) % 360
            if self.fault["type"]:
                self.ca_send("ahrs", 321, h, dtype=3, info="321 Heading angle sent as LONG = %d (wrong data type)" % int(h))
                self.by["efis"].vars["Heading"] = "REJECTED (type LONG, expected FLOAT)"
                self.by["efis"].vars["Rejected"] += 1
            else:
                self.ca_send("ahrs", 321, h)
                self.by["efis"].vars["Heading"] = "%.1f deg" % h
            self.ca_send("ahrs", 311, 2.0 * math.sin(self.t))
            self.ca_send("ahrs", 312, 10.0 * math.sin(self.t / 3))

    def slow(self):
        if self.by["adc"].on and not self.fault["adc"]:
            alt = 4500.0 + 50 * math.sin(self.t / 10)
            self.ca_send("adc", 322, alt)
            self.by["efis"].vars["Altitude"] = "%.0f ft" % alt
        elif self.fault["adc"]:
            self.by["efis"].vars["Altitude"] = "FLAG (no ID 322)"
        if self.by["eng"].on:
            self.ca_send("eng", 500, 92.5 + math.sin(self.t))
            self.ca_send("eng", 502, 640.0 + 5 * math.sin(self.t / 2))

    def ids(self, node_id, send=True):
        cid = 128
        data = bytes([node_id, 0, 0, 0, 0, 0, 0, 0])
        if not send:
            return self.preview_can("efis", cid, data)
        self.bus.send("efis", cid, data, info="Node service: identification request to node %d (IDS, service code 0)" % node_id, kind="cmd", key="NSH 128")
        targets = [k for k in ("adc", "ahrs", "eng") if int(self.by[k].addr.split()[-1]) == node_id or (self.fault["node"] and node_id == 2 and k == "eng")]
        for i, k in enumerate(targets):
            self.at(self.t + 0.001 + 0.0002 * i, lambda k=k: self.bus.send(k, 129, bytes([node_id, 0, 0, 0, 1, 0, 0, 0]),
                                                                            info="IDS response from %s: hardware 1, software 0%s" % (self.by[k].label, " (DUPLICATE NODE ID)" if self.fault["node"] and k == "eng" else ""),
                                                                            kind="resp", key="NSH 129"))
        return None

    def tpls(self):
        return [Tpl("Identification service request", [P("n", "Node ID", 2, 1, 255)], lambda s, v, send: self.ids(v["n"], send), "Node service channel 0: request on ID 128, response on 129.")] + \
            self.generic_tpls("efis")


A825_LCC = {0: "EEC emergency event", 2: "NOC normal operation", 4: "NSC node service", 6: "UDC user-defined", 7: "TMC test and maintenance"}


def a825_id(lcc, fid, doc, rci=0, lcl=0, pvt=0, fsb=0):
    return (lcc & 7) << 26 | (fid & 0x7F) << 19 | (fsb & 1) << 18 | (lcl & 1) << 17 | (pvt & 1) << 16 | (doc & 0x3FFF) << 2 | (rci & 3)


class ARINC825(CanNet):
    key, name, cat = "a825", "ARINC 825", "aero"
    blurb = "CAN for avionics systems"
    rate = 500000
    can_proto = "ARINC 825"
    medium = "ARINC 825: CAN 2.0B with 29-bit identifiers structured as LCC + function ID + data object code, redundancy channels; cabin and utility systems on a transport aircraft"
    faults = [("fid", "Replacement unit configured with the wrong function ID", "Receivers filter on the source function ID: the unit's data is ignored."),
              ("rci", "Redundant sensor B lost", "Only redundancy channel A remains: consumers switch to single-source mode."),
              ("no_term1", "Terminator missing", "Bus reflections; error counters rise.")]
    spec = [("Standard", "ARINC Specification 825 (General Standardization of CAN Bus Protocol for Airborne Use), based on CANaerospace ideas"),
            ("Physical", "CAN 2.0B, typically 125, 250, 500 kbit/s or 1 Mbit/s; bit timing and stub lengths specified"),
            ("Identifier", "LCC (3) | source FID (7) | FSB | LCL | PVT | DOC (14) | RCI (2) for one-to-many; client/server form for peer-to-peer"),
            ("LCC", "0 emergency event, 2 normal operation, 4 node service, 6 user-defined, 7 test and maintenance"),
            ("Redundancy", "RCI distinguishes up to 4 redundant sources of the same data"),
            ("Use", "Cabin systems, lighting, fuel, flap/slat, engine data concentrators (A380, A350, B787)")]
    frame = [["29-bit identifier (one-to-many)", ("LCC", 3), ("Source FID", 7), ("FSB", 1), ("LCL", 1), ("PVT", 1), ("DOC", 14), ("RCI", 2)]]
    about = ("ARINC 825 standardises how airliners use CAN. The 29-bit identifier is split into fields: a logical communication channel (emergency, "
             "normal operation, node service...), the function ID of the sender, a data object code that says what the data is, and a redundancy "
             "channel identifier so identical redundant sensors can share a bus.")
    guide = ["Decode an identifier: LCC 2 (normal operation), source FID, DOC and RCI.",
             "Find the two redundant fuel quantity sensors (RCI 0 and RCI 1).",
             "Inject the wrong function ID and see the consumer ignore the unit."]

    def setup(self):
        nodes = [self.node("fq1", "FUEL QTY SENSOR A", "sensor", 30, 60, "FID 0x21", "RCI 0"), self.node("fq2", "FUEL QTY SENSOR B", "sensor", 250, 60, "FID 0x21", "RCI 1"),
                 self.node("light", "CABIN LIGHTING CTRL", "lamp", 470, 60, "FID 0x30"), self.node("fqms", "FUEL MGMT COMPUTER", "ecu", 690, 60, "FID 0x20"),
                 self.node("cms", "CABIN MGMT SYSTEM", "server", 400, 290, "FID 0x31")]
        nodes[4].at_top()
        self.can_trunk(nodes, 200, conn="mil")
        self.user = "cms"
        self.by["fqms"].vars.update({"Fuel qty": "-", "Sources": "-"})
        self.every(0.1, self.cycle, 0.02)

    def dis825(self, cid, data, what):
        def dis(b, o):
            lcc, fid, doc, rci = cid >> 26, (cid >> 19) & 0x7F, (cid >> 2) & 0x3FFF, cid & 3
            b.rows.append([0, "ARINC 825 (%s): %s" % (A825_LCC.get(lcc, "?"), what), o, len(data), ""])
            b.rows.append([1, "LCC %d %s, source FID 0x%02X, DOC %d, RCI %d" % (lcc, A825_LCC.get(lcc, ""), fid, doc, rci), None, 0, "Identifier fields"])
            if len(data) >= 4:
                b.rows.append([1, "Value: %.2f" % struct.unpack(">f", data[:4])[0], o, 4, "IEEE 754 float"])
        return dis

    def cycle(self):
        q = 18450.0 - self.t * 0.5
        srcs = []
        for k, rci, fid in (("fq1", 0, 0x21), ("fq2", 1, 0x21)):
            if not self.by[k].on or (k == "fq2" and self.fault["rci"]):
                continue
            if k == "fq1" and self.fault["fid"]:
                fid = 0x22
            cid = a825_id(2, fid, 1200, rci)
            d = struct.pack(">f", q + rci * 3)
            self.bus.send(k, cid, d, ext=True, info="NOC FID 0x%02X DOC 1200 RCI %d: fuel quantity %.0f kg" % (fid, rci, q + rci * 3), dissect=self.dis825(cid, d, "fuel quantity"),
                          key="DOC 1200 RCI %d" % rci)
            if fid == 0x21:
                srcs.append("RCI %d" % rci)
        f = self.by["fqms"]
        f.vars["Fuel qty"] = "%.0f kg" % q if srcs else "NO DATA"
        f.vars["Sources"] = ", ".join(srcs) + (" (single source!)" if len(srcs) == 1 else "")
        if int(self.t * 10) % 10 == 0:
            cid = a825_id(2, 0x30, 2100)
            d = struct.pack(">f", 0.7)
            self.bus.send("light", cid, d, ext=True, info="NOC FID 0x30 DOC 2100: cabin light level 70 %", dissect=self.dis825(cid, d, "cabin light level"), key="DOC 2100")

    def tpls(self):
        return [Tpl("Set cabin light scene", [P("lvl", "Level %", 40, 0, 100)], lambda s, v, send: self._light(v, send), "CMS sends a normal-operation message to the lighting controller.")]

    def _light(self, v, send):
        cid = a825_id(2, 0x31, 2101)
        d = struct.pack(">f", v["lvl"] / 100.0)
        if not send:
            return self.preview_can("cms", cid, d, ext=True, dissect=self.dis825(cid, d, "light scene command"))
        self.bus.send("cms", cid, d, ext=True, info="NOC FID 0x31 DOC 2101: light scene %d %%" % v["lvl"], kind="cmd", dissect=self.dis825(cid, d, "light scene command"), key="DOC 2101")
        return None


# =============================================================== ARINC 629
class ARINC629(Scenario):
    key, name, cat = "a629", "ARINC 629", "aero"
    blurb = "Boeing 777 data bus"
    phy, rate = "manch", 2000000
    medium = "ARINC 629: 2 Mbit/s multi-transmitter bus, current-mode couplers clamped onto an unterminated twisted-pair bus cable; access by bus quiet time (no bus controller)"
    nets = [("BUS", "stub signal at a terminal (Manchester)")]
    lines = ["M"]
    faults = [("tg", "Two terminals configured with the same terminal gap", "They start transmitting at the same instant: collision, both wordstrings lost."),
              ("stub", "Coupler stub cable to the flap computer cut", "The terminal no longer appears on the bus; its periodic data stops."),
              ("ti", "Air data terminal transmit interval too short", "It would transmit more often than allowed; the protocol forces it to wait for TI and SG.")]
    spec = [("Standard", "ARINC 629 (Multi-Transmitter Data Bus), Boeing 777 (DATAC heritage)"),
            ("Physical", "2 Mbit/s Manchester, inductive current-mode couplers on the bus cable, up to 120 terminals"),
            ("Access", "No master: each terminal waits for its transmit interval (TI), the synchronisation gap (SG) and its unique terminal gap (TG)"),
            ("Words", "20 bit times: 3-bit sync, 16 data bits, parity; label word starts each wordstring, then up to 256 data words"),
            ("Modes", "Basic protocol (periodic / aperiodic) and combined protocol")]
    frame = [["Wordstring", ("Label word", 20), ("Data word 1", 20), ("...", 40), ("Data word n", 20)]]
    about = ("ARINC 629 lets many terminals share one bus without a controller. Each terminal has three timers: a transmit interval (how often it "
             "may send), a synchronisation gap (bus must have been quiet this long) and a unique terminal gap - the bus quiet time after which this "
             "terminal, and only this one, may start. Because every terminal's gap is different, the bus is shared deterministically.")
    guide = ["Watch the order of transmissions: terminals take turns according to their terminal gaps.",
             "LOGIC: label word sync vs data word sync.",
             "Give two terminals the same TG and see the collision."]

    def build(self):
        terms = [("adc", "AIR DATA (TG 8 us)", 8), ("fcc", "FLIGHT CONTROL (TG 12 us)", 12), ("eicas", "EICAS (TG 16 us)", 16), ("flap", "FLAP/SLAT (TG 20 us)", 20)]
        nodes = []
        for i, (nid, lab, tg) in enumerate(terms):
            n = self.node(nid, lab, "ecu", 40 + 210 * i, 60, "TG %d" % tg, "terminal + coupler")
            n.vars.update({"Wordstrings": 0})
            n.extra["tg"] = tg
            nodes.append(n)
        self.trunk(220, 30, 860, nodes, "twinax", net="BUS", label="ARINC 629 bus cable (current-mode couplers)", drop_conn="coupler")
        self.k = 0
        self.every(0.025, self.round, 0.01)

    def ws(self, nid, label, nwords, err=None):
        n = self.by[nid]
        words = [("cmd", label, "LABEL %03X" % label)] + [("data", (label * 7 + i * 113) & 0xFFFF, "D%d" % (i + 1)) for i in range(nwords)]
        b = Bld("ARINC 629 wordstring from %s" % n.label, "")
        b.b += b"".join(v.to_bytes(2, "big") for _, v, _ in words)
        b.rows.append([1, "Label word 0x%03X (channel / label)" % label, 0, 2, "Identifies the wordstring"])
        b.rows.append([1, "%d data words" % nwords, 2, 2 * nwords, ""])
        dur = len(words) * 10e-6 + 4e-6
        tg = 8e-6 if (self.fault["tg"] and nid == "fcc") else n.extra["tg"] * 1e-6

        def wf(f, words=words):
            w = m1553_wire([(k, v, l) for k, v, l in words], line="M")
            return w
        fr = Frame(self.t, dur, nid, None, "ARINC 629", "%s: label 0x%03X + %d words (after TG %.0f us)" % (n.label.split(" (")[0], label, nwords, tg * 1e6), pdu=b.done(), kind="data", err=err,
                   wirefn=wf, key=nid)
        return fr, tg

    def round(self):
        t = self.t
        coll = self.fault["tg"]
        for nid, lab, nw in (("adc", 0x210, 6), ("fcc", 0x330, 8), ("eicas", 0x400, 4), ("flap", 0x520, 2)):
            n = self.by[nid]
            if not n.on or (nid == "flap" and self.fault["stub"]):
                continue
            err = "Collision: AIR DATA and FLIGHT CONTROL share terminal gap 8 us" if coll and nid in ("adc", "fcc") else None
            fr, tg = self.ws(nid, lab, nw, err)
            start = max(t, self.free.get("bus", 0.0)) + tg + (2e-6 if not (coll and nid == "fcc") else 0)
            if coll and nid == "fcc":
                start = self.prev_start
            fr.t = start
            self.prev_start = start
            self.tx(fr, bus="coll" if (coll and nid == "fcc") else "bus", start=start)
            if not err:
                n.vars["Wordstrings"] += 1


# =============================================================== AFDX
class AFDX(Scenario):
    key, name, cat = "afdx", "ARINC 664 / AFDX", "aero"
    blurb = "Avionics Ethernet networks"
    phy, rate = "eth100", 100e6
    medium = "ARINC 664 Part 7 (AFDX): full-duplex switched Ethernet, two independent networks A and B, virtual links with bandwidth allocation gaps, first-valid-wins redundancy"
    nets = [("TX", "100BASE-TX pair")]
    lines = ["M"]
    faults = [("swa", "Switch A fails", "Every frame still arrives via network B: redundancy management keeps the first valid copy."),
              ("bag", "ADIRU end system transmits VL 101 too often (2 ms instead of BAG 8 ms)", "The switch polices each virtual link: frames that break the BAG are dropped."),
              ("sn", "FMS end system skips sequence numbers", "Receivers' integrity checking rejects frames whose sequence number is outside the window.")]
    spec = [("Standard", "ARINC 664 Part 7 (Avionics Full-Duplex Switched Ethernet); AFDX is Airbus' trademark (A380, A350, B787 uses a similar CDN)"),
            ("Physical", "IEEE 802.3 10/100 Mbit/s full duplex, twisted pair or fibre; every end system on two networks"),
            ("Virtual link", "Unidirectional, one source, multicast destinations, identified by the MAC destination 03:00:00:00:VL-ID; BAG 1-128 ms, Lmax"),
            ("Determinism", "End systems shape traffic per VL; switches police it (token bucket) and have static forwarding tables"),
            ("Redundancy", "Each frame sent on A and B with a sequence number byte; receivers keep the first valid copy"),
            ("Stack", "IP / UDP; sampling and queuing ports (ARINC 653 partitions)")]
    frame = [["AFDX frame", ("MAC dst 03:00:00:00:VL", 48), ("MAC src (net A/B)", 48), ("IPv4", 160), ("UDP", 64), ("Payload", "n x 8"), ("SN", 8), ("FCS", 32)]]
    about = ("AFDX makes Ethernet deterministic enough for flight-critical data. Every flow is a virtual link with a guaranteed bandwidth: the "
             "sender may transmit at most one frame per bandwidth allocation gap, and switches police that rule. Every frame travels twice, on two "
             "independent networks, and the receiver keeps whichever valid copy arrives first.")
    guide = ["Select a frame: MAC destination = virtual link ID, MAC source says network A or B.",
             "Find the same sequence number on network A and network B.",
             "Fail switch A: nothing is lost.",
             "Make the ADIRU violate its BAG: watch the switch drop frames."]

    def build(self):
        self.lan = Lan(self, 100e6, "eth100", 20e-6)
        es = [("adiru", "ADIRU (ES 1)", "box", 40, 40, "10.1.33.1"), ("fms", "FMS (ES 2)", "ecu", 40, 300, "10.1.33.2"), ("cds", "DISPLAYS (ES 3)", "display", 720, 40, "10.1.33.3"),
              ("fwc", "FLIGHT WARNING (ES 4)", "server", 720, 300, "10.1.33.4")]
        sa = self.node("swa", "AFDX SWITCH A", "switch", 380, 110, "", "policing + static tables", w=130)
        sb = self.node("swb", "AFDX SWITCH B", "switch", 380, 230, "", "independent network", w=130)
        for n in (sa, sb):
            n.extra["can"] = False
        for i, (nid, lab, kind, x, y, ip) in enumerate(es):
            n = self.node(nid, lab, kind, x, y, ip)
            self.lan.host(nid, "02:00:00:00:%02x:20" % (i + 1), ip)
            px = x + (n.w if x < 380 else 0)
            n.port = (px, y + 26)
            mx = (px + 380) / 2 if x < 380 else (px + 510) / 2
            self.seg([n.port, (mx, y + 26), (mx, 136), (380 if x < 380 else 510, 136)], "cat6", net="TX", c0="rj45", label="net A" if i == 0 else "")
            self.seg([(mx, y + 26), (mx + (8 if x < 380 else -8), y + 26), (mx + (8 if x < 380 else -8), 256), (380 if x < 380 else 510, 256)], "cat6", net="TX", col=(200, 120, 60),
                     label="net B" if i == 0 else "")
        for nid, c in (("swa", (445, 136)), ("swb", (445, 256))):
            self.by[nid].port = c
            self.seg([(380, 136 if nid == "swa" else 256), c], "cat6", w=1, col=(30, 30, 34))
            self.seg([(510, 136 if nid == "swa" else 256), c], "cat6", w=1, col=(30, 30, 34))
        self.sn = {}
        self.vls = {101: ("adiru", ["fms", "cds", "fwc"], 0.008, "air data + attitude"), 102: ("fms", ["cds"], 0.032, "flight plan / guidance"), 103: ("fwc", ["cds"], 0.064, "warnings")}
        self.user = "fms"
        self.by["swa"].vars.update({"Policed drops": 0})
        self.by["cds"].vars.update({"Accepted": 0, "Duplicates discarded": 0, "Rejected (SN)": 0})
        for vl, (src, dsts, bag, what) in self.vls.items():
            self.every(bag, self.vl_tx, 0.001 * vl % 0.007, 0.0, vl)
        self.every(0.002, self.babble, 0.0005)

    def frame_pdu(self, vl, src, net, payload, sn):
        dmac = "03:00:00:00:%02x:%02x" % (vl >> 8, vl & 255)
        smac = self.lan.mac[src][:-2] + ("20" if net == "A" else "40")
        inner = Bld("Application payload (AFDX port)", "")
        inner.raw("Data", payload, "%d bytes" % len(payload), "")
        inner.u8("Sequence number", sn, None, "AFDX SN (0 after reset, then 1..255): redundancy and integrity management")
        ip = ipv4_pdu(self.lan.ip[src], "224.224.%d.%d" % (vl >> 8, vl & 255), 17, udp_pdu(10000 + vl, 10000 + vl, inner.done(), self.lan.ip[src], "224.224.%d.%d" % (vl >> 8, vl & 255)))
        return eth_pdu(dmac, smac, 0x0800, ip, title="AFDX frame, network %s, virtual link %d" % (net, vl))

    def vl_tx(self, vl, forced=False):
        src, dsts, bag, what = self.vls[vl]
        if not self.by[src].on:
            return
        sn = self.sn.get(vl, 0) % 255 + 1
        if self.fault["sn"] and src == "fms":
            sn = (sn + 3) % 255 + 1
        self.sn[vl] = sn
        payload = bytes((vl + i * 7 + int(self.t * 100)) & 255 for i in range(64 if vl == 101 else 200))
        cds = self.by["cds"]
        for net in ("A", "B"):
            err = None
            if net == "A" and self.fault["swa"]:
                err = "Switch A failed: frame lost on network A"
            elif forced:
                err = "Switch policing: VL %d exceeded its BAG (%g ms), frame dropped" % (vl, bag * 1000)
            elif self.fault["sn"] and src == "fms":
                err = "Integrity check: sequence number out of window, rejected"
            p = self.frame_pdu(vl, src, net, payload, sn)
            fr = self.lan.frame(src, dsts, p, "VL %d net %s SN %d: %s (BAG %g ms)" % (vl, net, sn, what, bag * 1000), "AFDX", "data" if net == "A" else "sync", err=err,
                                meta={"bus": "%s:%s" % (net, src)}, key="VL %d %s" % (vl, net))
            self.lan.send(fr)
            if "cds" in dsts:
                if err is None:
                    if net == "A" or self.fault["swa"]:
                        cds.vars["Accepted"] += 1
                    else:
                        cds.vars["Duplicates discarded"] += 1
                elif self.fault["sn"] and src == "fms":
                    cds.vars["Rejected (SN)"] += 1
            if forced:
                self.by["swa"].vars["Policed drops"] += 1

    def babble(self):
        if self.fault["bag"] and int(self.t * 500) % 4 != 0:
            self.vl_tx(101, forced=True)

    def tpls(self):
        return [Tpl("Send on VL 102 now", [], lambda s, v, send: (self.vl_tx(102) if send else None), "One extra frame from the FMS end system (still within its BAG budget).")]


# =============================================================== ASCB-D
class ASCB(Scenario):
    key, name, cat = "ascb", "ASCB", "aero"
    blurb = "Business jet avionics"
    phy, rate = "eth10", 10e6
    medium = "ASCB-D (Honeywell Primus Epic): four Ethernet-based buses, two per side, time-synchronous frames controlled by time servers; modular avionics units, displays, radios"
    nets = [("TD", "10 Mbit/s Manchester (10BASE-T style) bus")]
    lines = ["TD"]
    faults = [("ts", "Left time server fails", "Another time server takes over the master role; frames continue on schedule."),
              ("bus1", "Left bus 1 fails", "Modules keep using left bus 2: every message is sent on both buses of its side."),
              ("slot", "Display unit transmits outside its slot", "The bus schedule is violated: the frame collides with the next scheduled message.")]
    spec = [("Origin", "Avionics Standard Communications Bus, Honeywell proprietary; versions A-D; ASCB-D in Primus Epic (business and regional aircraft)"),
            ("Architecture", "Four Ethernet buses (two per side of the aircraft), bridged between sides"),
            ("Timing", "Periodic, time-synchronous frames; time servers (masters) keep the schedule; deterministic slots per module"),
            ("Fault tolerance", "Duplicated buses, master selection among time servers, clock synchronisation and reintegration")]
    frame = [["ASCB frame (illustrative)", ("Sync / time message", "n"), ("Slot 1", "n"), ("Slot 2", "n"), ("...", "n")]]
    about = ("ASCB is Honeywell's avionics bus for business jets and regional aircraft. In its D version, four Ethernet-based buses - two for each "
             "side of the aircraft - carry periodic data in a fixed schedule. Time servers start every frame and keep all modules synchronised; if "
             "one fails, another takes over. (Details beyond the published architecture are proprietary; message contents here are illustrative.)")
    guide = ["Watch the frame start message from the time server, then each module in its slot.",
             "Fail the left time server: the right one becomes master.",
             "Fail left bus 1: traffic continues on bus 2."]

    def build(self):
        self.lan = Lan(self, 10e6, "eth10", 5e-6)
        mods = [("mau1", "MAU LEFT (time server)", "server", 40, 40), ("mau2", "MAU RIGHT (time server)", "server", 700, 40), ("du1", "DISPLAY 1", "display", 40, 300),
                ("du2", "DISPLAY 2", "display", 260, 300), ("du3", "DISPLAY 3", "display", 480, 300), ("rad", "RADIO / NAV UNIT", "radio", 700, 300)]
        for i, (nid, lab, kind, x, y) in enumerate(mods):
            n = self.node(nid, lab, kind, x, y, "", "")
            self.lan.host(nid, "00:11:22:00:00:%02x" % (i + 1), "10.0.0.%d" % (i + 1))
            n.at_top() if y > 150 else None
        self.trunk(190, 30, 860, [self.by[k] for k, *_ in mods], "twinax", net="TD", label="ASCB-D left/right buses 1 and 2 (shown combined)", drop_conn="mil")
        self.master = "mau1"
        self.k = 0
        self.by["mau1"].vars.update({"Role": "MASTER time server"})
        self.by["mau2"].vars.update({"Role": "backup time server"})
        self.every(0.0125, self.frame_tick, 0.002)

    def msg(self, src, info, kind, err=None, size=200):
        b = Bld("ASCB message (illustrative content)", "Layout simplified: real ASCB formats are proprietary")
        b.u16("Frame number", self.k & 0xFFFF, None, "")
        b.u8("Slot", hash(src) & 15, None, "")
        b.raw("Periodic data", bytes((i * 13 + self.k) & 255 for i in range(min(size, 64))), "%d bytes" % size, "")
        for bus in ("1", "2"):
            if bus == "1" and self.fault["bus1"]:
                continue
            fr = self.lan.frame(src, None, eth_pdu("01:00:5e:00:00:01", self.lan.mac[src], 0x88B5, b.done(), title="ASCB-D on bus %s" % bus), "[bus %s] %s" % (bus, info), "ASCB",
                                kind, err=err, meta={"bus": "bus" + bus}, key=info.split(" ")[0] + bus)
            self.lan.send(fr)

    def frame_tick(self):
        self.k += 1
        if self.fault["ts"] and self.master == "mau1":
            self.master = "mau2"
            self.by["mau1"].vars["Role"] = "FAILED"
            self.by["mau2"].vars["Role"] = "MASTER time server (took over)"
            self.log("Left time server failed: right time server is now master")
        if not self.fault["ts"] and self.master == "mau2":
            self.master = "mau1"
            self.by["mau1"].vars["Role"] = "MASTER time server"
            self.by["mau2"].vars["Role"] = "backup time server"
        self.msg(self.master, "Frame %d start (time server %s)" % (self.k, "L" if self.master == "mau1" else "R"), "sync", size=32)
        if self.k % 2 == 0:
            self.msg("mau1" if not self.fault["ts"] else "mau2", "MAU periodic data: air data, attitude, nav", "data")
        if self.k % 4 == 1:
            self.msg("rad", "Radio/nav unit: VOR/ILS deviations", "data", size=80)
        if self.k % 8 == 3:
            err = "Outside its slot: collides with the next scheduled transmission" if self.fault["slot"] else None
            self.msg("du1", "Display 1 status", "data", err=err, size=40)


# =============================================================== TTP/C
class TTPC(Scenario):
    key, name, cat = "ttpc", "TTP/C", "aero"
    blurb = "Time-triggered safety-critical systems"
    phy, rate = "rs485", 5000000
    medium = "TTP/C (SAE AS6003): time-triggered TDMA on two replicated channels; static schedule (MEDL), membership and fault-tolerant clock sync; 4 nodes of a power/cabin-pressure controller"
    nets = [("A", "channel A line A"), ("B", "channel A line B"), ("VDIFF", "channel A differential")]
    lines = ["D"]
    faults = [("crash", "Node 3 crashes", "Its slot stays empty: every other node removes it from the membership vector in the next round."),
              ("babble", "Node 2 controller babbles", "The bus guardian only opens node 2's transmitter in its own slot: the babbling is blocked."),
              ("clock", "Node 4 oscillator drifts", "Fault-tolerant clock synchronisation corrects it until the drift is too large; then it loses sync and must reintegrate.")]
    spec = [("Standard", "SAE AS6003 (TTP), TTTech; used in A380 cabin pressure control, B787 power systems, space"),
            ("Access", "TDMA: every node owns slots in a round; the message descriptor list (MEDL) fixes the whole schedule at design time"),
            ("Services", "Fault-tolerant clock synchronisation, group membership (who is alive), clique avoidance, bus guardians"),
            ("Frames", "I-frames carry the controller state (C-state) for (re)integration; N-frames carry data with the C-state folded into the CRC"),
            ("Physical", "Two replicated channels; e.g. RS-485 / MFM at up to 5 Mbit/s or Ethernet PHY at 25 Mbit/s")]
    frame = [["N-frame", ("Header (type, mode)", 4), ("Data", "n x 8"), ("CRC-24 (incl. C-state)", 24)]]
    about = ("TTP/C is a time-triggered protocol: nothing happens on the bus unless the schedule says so. Every node knows the global time and the "
             "static message schedule, so it knows exactly when every other node must send. A missing frame therefore tells everyone that the "
             "sender has failed, which gives a consistent membership view; bus guardians stop a faulty node from talking outside its slot.")
    guide = ["Watch the TDMA round: nodes 1-4 send in their fixed slots on channels A and B.",
             "Crash node 3: see the membership vector change in the next frames.",
             "Make node 2 babble: the guardian blocks it."]

    def build(self):
        nodes = [self.node("n%d" % i, lab, "ecu", 40 + 210 * (i - 1), 60, "node %d" % i, "slot %d" % i) for i, lab in
                 ((1, "CABIN PRESSURE CTRL A"), (2, "CABIN PRESSURE CTRL B"), (3, "OUTFLOW VALVE"), (4, "SAFETY VALVE MONITOR"))]
        self.trunk(200, 30, 860, nodes, "rs485", net="VDIFF", label="channel A", drop_conn="mil", t0=True, t1=True)
        self.trunk(240, 30, 860, [], "rs485", net="VDIFF", label="channel B (replicated)")
        for n in nodes:
            self.seg([(n.port[0] - 6, 200), (n.port[0] - 6, 240)], "rs485", w=3, col=(80, 80, 120))
            n.vars.update({"Membership": "1111", "Sync": "in sync"})
        self.round_no = 0
        self.member = [1, 1, 1, 1]
        self.every(0.02, self.tdma_round, 0.0005)

    def tdma_round(self):
        self.round_no += 1
        slot = 0.005
        for i in range(4):
            nid = "n%d" % (i + 1)
            n = self.by[nid]
            t = self.t + i * slot
            alive = n.on and not (self.fault["crash"] and i == 2)
            if self.fault["clock"] and i == 3 and self.round_no % 50 == 25:
                alive = False
                n.vars["Sync"] = "lost sync - reintegrating"
            if not alive:
                self.member[i] = 0
                continue
            self.member[i] = 1
            iframe = self.round_no % 10 == 0
            b = Bld("TTP/C %s from node %d (round %d)" % ("I-frame" if iframe else "N-frame", i + 1, self.round_no), "")
            b.u8("Header", 0x80 if iframe else 0x00, "%s, no mode change" % ("I-frame (explicit C-state)" if iframe else "N-frame"), "")
            if iframe:
                b.u32("C-state: global time", self.round_no * 2000, "%d us" % (self.round_no * 2000), "")
                b.u8("C-state: membership", int("".join(map(str, self.member)), 2), "".join(map(str, self.member)), "Who sent correctly in the last round")
            b.raw("Data", bytes([(self.round_no + i * 17) & 255] * 8), None, "Application data (state messages)")
            crcv = crc(bytes(b.b) + bytes([int("".join(map(str, self.member)), 2)]), 24, 0x5D6DCB, 0xFEDCBA)
            b.u24("CRC-24", crcv, "0x%06X (includes the receiver's C-state)" % crcv, "A node with a different view of the C-state sees a CRC error")
            p = b.done()

            def wf(fr, d=p.b):
                w = Wire(bit=0.2e-6)
                w.set("D", 0.0, 1)
                return _manch_bytes(w, "D", d, 0.2e-6)
            fr = Frame(t, 30e-6 + len(p.b) * 8 * 0.2e-6, nid, None, "TTP/C", "Round %d slot %d: node %d %s, membership %s" % (self.round_no, i + 1, i + 1, "I-frame" if iframe else "N-frame",
                                                                                                                       "".join(map(str, self.member))),
                       pdu=p, kind="sync" if iframe else "data", wirefn=wf, key="slot %d" % (i + 1))
            self.tx(fr, start=t)
        if self.fault["babble"]:
            self.log("Bus guardian blocked node 2 outside its slot") if self.round_no % 100 == 0 else None
            self.by["n2"].vars["Sync"] = "babbling - blocked by bus guardian"
        mv = "".join(map(str, self.member))
        for n in self.nodes:
            n.vars["Membership"] = mv


def _manch_bytes(w, line, data, tb):
    t = 1e-6
    for i, byte in enumerate(data[:24]):
        t0 = t
        for k in range(8):
            bit = (byte >> (7 - k)) & 1
            w.set(line, t, 1 if bit else 0)
            w.set(line, t + tb / 2, 0 if bit else 1)
            t += tb
        w.seg(t0, t, "%02X" % byte, i % 2, 0)
    w.set(line, t, 1)
    w.end(t + 1e-6)
    return w
