"""Automotive and heavy equipment, part A: SAE J1939, J1708, J1587,
CANopen for mobile machinery (with safety SRDOs), CAN FD with AUTOSAR E2E
protection, LIN and FlexRay."""
import math
import struct
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, crc_bits, msb, lsb, bytes_msb, lin_cs, lin_pid, sum8
from .fam import serial_frame, CanBus
from .phys_b import CanNet, CANFD, hexdata

# ==================================================================== J1939
# PGN: (name, priority, [(spn, name, start byte 1-based, start bit 1-based, bits, scale, offset, unit)])
PGNS = {
    61444: ("EEC1 Electronic Engine Controller 1", 3, [(899, "Engine torque mode", 1, 1, 4, 1, 0, ""), (512, "Driver's demand torque", 2, 1, 8, 1, -125, "%"),
                                                     (513, "Actual engine torque", 3, 1, 8, 1, -125, "%"), (190, "Engine speed", 4, 1, 16, 0.125, 0, "rpm"),
                                                     (1483, "Source address of controlling device", 6, 1, 8, 1, 0, "")]),
    61443: ("EEC2 Electronic Engine Controller 2", 3, [(91, "Accelerator pedal position 1", 2, 1, 8, 0.4, 0, "%"), (92, "Engine percent load at current speed", 3, 1, 8, 1, 0, "%")]),
    65262: ("ET1 Engine Temperature 1", 6, [(110, "Engine coolant temperature", 1, 1, 8, 1, -40, "degC"), (174, "Fuel temperature", 2, 1, 8, 1, -40, "degC"),
                                           (175, "Engine oil temperature 1", 3, 1, 16, 0.03125, -273, "degC")]),
    65263: ("EFL/P1 Engine Fluid Level/Pressure 1", 6, [(100, "Engine oil pressure", 4, 1, 8, 4, 0, "kPa"), (111, "Coolant level", 8, 1, 8, 0.4, 0, "%")]),
    65265: ("CCVS1 Cruise Control/Vehicle Speed 1", 6, [(84, "Wheel-based vehicle speed", 2, 1, 16, 1 / 256.0, 0, "km/h"), (597, "Brake switch", 4, 5, 2, 1, 0, "")]),
    65266: ("LFE1 Fuel Economy (Liquid)", 6, [(183, "Engine fuel rate", 1, 1, 16, 0.05, 0, "L/h"), (184, "Instantaneous fuel economy", 3, 1, 16, 1 / 512.0, 0, "km/L")]),
    61445: ("ETC2 Electronic Transmission Controller 2", 6, [(524, "Selected gear", 1, 1, 8, 1, -125, ""), (523, "Current gear", 4, 1, 8, 1, -125, "")]),
    61441: ("EBC1 Electronic Brake Controller 1", 6, [(521, "Brake pedal position", 2, 1, 8, 0.4, 0, "%")]),
    65226: ("DM1 Active Diagnostic Trouble Codes", 6, []), 59904: ("Request", 6, []), 60928: ("Address Claimed", 6, []),
    60416: ("TP.CM Transport Protocol - Connection Management", 7, []), 60160: ("TP.DT Transport Protocol - Data Transfer", 7, []),
    65260: ("VI Vehicle Identification", 6, []), 65242: ("SOFT Software Identification", 6, []), 65235: ("DM11 Diagnostic Data Clear/Reset for Active DTCs", 6, []),
}
SA_NAMES = {0x00: "Engine #1", 0x03: "Transmission #1", 0x0B: "Brakes - System Controller", 0x17: "Instrument Cluster #1", 0x21: "Body Controller", 0xF9: "Off-board Diagnostic-Service Tool #1",
            0xFE: "Null (cannot claim)", 0xFF: "Global"}


def j1939_id(prio, pgn, sa, da=0xFF):
    pf = (pgn >> 8) & 0xFF
    ps = da if pf < 240 else pgn & 0xFF
    return (prio << 26) | ((pgn >> 16) & 3) << 24 | pf << 16 | ps << 8 | sa


def j1939_split(cid):
    prio = cid >> 26
    dp = (cid >> 24) & 3
    pf = (cid >> 16) & 0xFF
    ps = (cid >> 8) & 0xFF
    sa = cid & 0xFF
    pgn = (dp << 16) | (pf << 8) | (ps if pf >= 240 else 0)
    da = ps if pf < 240 else 0xFF
    return prio, pgn, sa, da, pf, ps


def spn_get(data, sb, bb, bits):
    v = int.from_bytes(bytes(data[sb - 1:sb - 1 + (bits + bb - 2) // 8 + 1]), "little")
    return (v >> (bb - 1)) & ((1 << bits) - 1)


def spn_put(data, sb, bb, bits, raw):
    n = (bits + bb - 2) // 8 + 1
    v = int.from_bytes(bytes(data[sb - 1:sb - 1 + n]), "little")
    m = ((1 << bits) - 1) << (bb - 1)
    v = (v & ~m) | ((int(raw) << (bb - 1)) & m)
    data[sb - 1:sb - 1 + n] = v.to_bytes(n, "little")


def encode_pgn(pgn, vals):
    d = bytearray([0xFF] * 8)
    for spn, nm, sb, bb, bits, sc, off, unit in PGNS[pgn][2]:
        if spn in vals:
            spn_put(d, sb, bb, bits, max(0, min((1 << bits) - 1, round((vals[spn] - off) / sc))))
    return bytes(d)


def j1939_idrows(b, o, cid):
    prio, pgn, sa, da, pf, ps = j1939_split(cid)
    b.note("Priority: %d" % prio, "3 most significant bits: 0 highest .. 7 lowest (control messages 3, info 6)", d=1)
    b.note("PGN: %d (0x%05X) %s" % (pgn, pgn, PGNS.get(pgn, ("proprietary / unknown",))[0]), "Parameter Group Number = data page + PDU format + (PDU specific if PF >= 240)", d=1)
    b.note("PDU format %d -> %s" % (pf, "PDU1: PS is destination address 0x%02X" % ps if pf < 240 else "PDU2: PS is group extension 0x%02X (broadcast)" % ps),
           "PF < 240 = PDU1, addressed (peer-to-peer); PF >= 240 = PDU2, broadcast", d=1)
    b.note("Source address: 0x%02X (%d) %s" % (sa, sa, SA_NAMES.get(sa, "")), "Each ECU claims an address 0-253 with the address-claim procedure", d=1)


def j1939_dissect(b, off, cid, data):
    prio, pgn, sa, da, pf, ps = j1939_split(cid)
    name = PGNS.get(pgn, ("PGN %d" % pgn, 0, []))[0]
    b.rows.append([0, "SAE J1939: %s" % name, off, len(data), "Parameters (SPNs) packed little-endian with scale and offset from J1939-71"])
    for spn, nm, sb, bb, bits, sc, ofs, unit in PGNS.get(pgn, ("", 0, []))[2]:
        if sb - 1 >= len(data):
            continue
        raw = spn_get(data, sb, bb, bits)
        na = raw >= (1 << bits) - (1 if bits <= 4 else (1 << max(0, bits - 8)) * 1) if False else raw == (1 << bits) - 1
        val = "not available" if na else "%g %s" % (round(raw * sc + ofs, 3), unit)
        b.rows.append([1, "SPN %d %s: %s (raw %d)" % (spn, nm, val, raw), off + sb - 1, max(1, (bits + bb - 2) // 8 + 1),
                       "Byte %d, bit %d, %d bits, %g/bit, offset %g. All-ones = 'not available'." % (sb, bb, bits, sc, ofs)])
    if pgn == 65226 and len(data) >= 6:
        lamp = data[0]
        b.rows.append([1, "Lamps: MIL %d, Red stop %d, Amber warning %d, Protect %d" % ((lamp >> 6) & 3, (lamp >> 4) & 3, (lamp >> 2) & 3, lamp & 3), off, 2, "2 bits each: 00 off, 01 on"])
        for k in range(2, len(data) - 3, 4):
            spn = data[k] | (data[k + 1] << 8) | ((data[k + 2] >> 5) << 16)
            fmi = data[k + 2] & 0x1F
            oc = data[k + 3] & 0x7F
            if spn == 0 and fmi == 0:
                continue
            b.rows.append([1, "DTC: SPN %d FMI %d (%s) OC %d" % (spn, fmi, {0: "data valid but above normal range - most severe", 1: "below normal - most severe", 3: "voltage above normal",
                                                                                4: "voltage below normal", 2: "erratic", 5: "current below normal", 31: "condition exists"}.get(fmi, ""), oc), off + k, 4,
                           "19-bit Suspect Parameter Number + 5-bit Failure Mode Identifier + occurrence count (version 4 conversion)"])
    if pgn == 59904 and len(data) >= 3:
        rq = data[0] | data[1] << 8 | data[2] << 16
        b.rows.append([1, "Requested PGN: %d (%s)" % (rq, PGNS.get(rq, ("?",))[0]), off, 3, "The destination answers with that PGN (or a NACK)"])
    if pgn == 60928 and len(data) == 8:
        nm = int.from_bytes(bytes(data), "little")
        b.rows.append([1, "NAME: 0x%016X" % nm, off, 8, "64-bit NAME: lower value wins an address conflict"])
        b.rows.append([2, "Identity %d, manufacturer %d, function %d, vehicle system %d, industry group %d, arbitrary address capable %d" %
                       (nm & 0x1FFFFF, (nm >> 21) & 0x7FF, (nm >> 40) & 0xFF, (nm >> 49) & 0x7F, (nm >> 60) & 7, nm >> 63), off, 8, ""])
    if pgn == 60416 and len(data) == 8:
        b.rows.append([1, "Control byte: %d (%s)" % (data[0], {32: "BAM broadcast announce", 16: "RTS", 17: "CTS", 19: "EndOfMsgAck", 255: "Abort"}.get(data[0], "")), off, 1, ""])
        b.rows.append([1, "Message size %d bytes in %d packets, PGN %d" % (data[1] | data[2] << 8, data[3], data[5] | data[6] << 8 | data[7] << 16), off + 1, 7, ""])
    if pgn == 60160 and len(data) == 8:
        b.rows.append([1, "Sequence number %d + 7 data bytes" % data[0], off, 8, "Packets of a multi-packet message, 50-200 ms apart for BAM"])


class J1939(CanNet):
    key, name, cat = "j1939", "SAE J1939", "auto"
    blurb = "Heavy-duty vehicles and equipment"
    rate = 250000
    can_proto = "J1939"
    medium = "SAE J1939 on 250 kbit/s CAN (J1939-11 shielded twisted pair, 9-pin Deutsch diagnostic connector), 6 ECUs + service tool"
    faults = [("conflict", "Body controller tries to claim 0x00 (engine's address)", "Address claim: the ECU with the lower NAME keeps 0x00, the other must claim another address or send 'Cannot Claim' from 0xFE."),
              ("hot", "Engine coolant overheating", "SPN 110 rises past the limit: the ECM sets DTC SPN 110 FMI 0, lights the red stop lamp and DM1 grows beyond 8 bytes (sent with BAM)."),
              ("tool500", "Service tool connected at 500 kbit/s", "J1939-14 is 500 kbit/s; on a 250 kbit/s network the tool destroys frames until it goes error passive."),
              ("no_term1", "Terminator missing (right end)", "Termination fault, as on any CAN bus.")]
    spec = [("Standard", "SAE J1939 (-21 data link, -71 application, -73 diagnostics, -81 network management); ISO 11783 is derived from it"),
            ("Physical", "CAN 2.0B 29-bit at 250 kbit/s (J1939-11/-15) or 500 kbit/s (J1939-14)"),
            ("Identifier", "Priority (3) + data page + PDU format (8) + PDU specific (8) + source address (8)"),
            ("Data", "PGNs (parameter groups) containing SPNs (suspect parameters) with fixed scaling"), ("Multi-packet", "Transport protocol: BAM (broadcast) or RTS/CTS, up to 1785 bytes"),
            ("Addressing", "Dynamic address claim with a 64-bit NAME"), ("Diagnostics", "DM1 active DTCs (SPN + FMI + occurrence count), DM2, DM11 clear...")]
    frame = [["29-bit identifier", ("Priority", 3), ("EDP", 1), ("DP", 1), ("PDU format", 8), ("PDU specific / DA", 8), ("Source address", 8)],
             ["DM1 DTC (4 bytes)", ("SPN low 16", 16), ("SPN hi 3", 3), ("FMI", 5), ("CM", 1), ("OC", 7)]]
    about = ("J1939 is how trucks, buses, tractors and construction machines talk. Each CAN identifier encodes a priority, a Parameter Group Number "
             "(what the data is) and the sender's address. The PGN's 8 bytes hold SPNs with standard scaling - engine speed is always bytes 4-5 of "
             "EEC1 at 0.125 rpm/bit - so any tool can read any truck. Faults are broadcast in DM1 as SPN + FMI codes.")
    guide = ["Select an EEC1 frame (PGN 61444): read engine speed from SPN 190 in the tree.",
             "Raise the throttle on the engine (DEVICE) and watch SPN 190 and the fuel rate follow.",
             "Inject the coolant overheat: DM1 becomes multi-packet - find the TP.CM BAM and TP.DT frames.",
             "COMPOSE a Request for PGN 65260 (VIN) addressed to the engine.",
             "Watch the address-claim battle with the conflict fault."]

    def setup(self):
        nodes = [self.node("ecm", "ENGINE ECM", "ecu", 30, 60, "SA 0x00"), self.node("tcm", "TRANSMISSION", "ecu", 230, 60, "SA 0x03"), self.node("abs", "ABS / EBS", "ecu", 430, 60, "SA 0x0B"),
                 self.node("ic", "INSTRUMENT CLUSTER", "display", 640, 60, "SA 0x17"), self.node("bcm", "BODY CONTROLLER", "ecu", 230, 290, "SA 0x21"),
                 self.node("tool", "SERVICE TOOL", "tool", 560, 290, "SA 0xF9", "via 9-pin Deutsch")]
        for n in nodes[4:]:
            n.at_top()
        self.can_trunk(nodes, 200, label="J1939-15 unshielded twisted pair, 250 kbit/s", conn="deutsch")
        self.sa = {"ecm": 0x00, "tcm": 0x03, "abs": 0x0B, "ic": 0x17, "bcm": 0x21, "tool": 0xF9}
        self.names = {"ecm": 0x0000000000014001, "bcm": 0x8000200000A12345}
        self.user = "tool"
        e = self.by["ecm"]
        e.vars.update({"Throttle %": 12.0, "RPM": 750.0, "Coolant C": 88.0, "Oil kPa": 380.0, "Fuel L/h": 4.1})
        e.ctl = [("Throttle %", "THROTTLE", 0.0, 100.0, 0, lambda v: "%.0f%%" % v), ("Coolant C", "COOLANT", 40.0, 130.0, 0, lambda v: "%.0f C" % v)]
        self.by["abs"].vars.update({"Speed km/h": 0.0, "Brake %": 0.0})
        self.by["abs"].ctl = [("Brake %", "BRAKE", 0.0, 100.0, 0, lambda v: "%.0f%%" % v)]
        self.by["tcm"].vars.update({"Gear": 1})
        self.by["ic"].vars.update({"Tacho": "-", "Speedo": "-", "Coolant gauge": "-", "Lamps": "off"})
        self.dtcs = []
        self.oc = 0
        self.at(0.01, self.claims)
        self.every(0.020, self.eec1, 0.1)
        self.every(0.050, self.eec2, 0.11)
        self.every(0.100, self.ccvs, 0.12)
        self.every(0.100, self.lfe, 0.13)
        self.every(0.100, self.etc2, 0.14)
        self.every(0.5, self.eflp, 0.15)
        self.every(1.0, self.et1, 0.16)
        self.every(1.0, self.dm1, 0.5)

    def jsend(self, node, pgn, data, da=0xFF, prio=None, info=None, kind="data"):
        sa = self.sa.get(node, 0xFE)
        cid = j1939_id(PGNS.get(pgn, ("", 6))[1] if prio is None else prio, pgn, sa, da)
        self.bus.send(node, cid, data, ext=True, info=info or "%s SA 0x%02X" % (PGNS.get(pgn, ("PGN %d" % pgn,))[0].split(" ")[0], sa), kind=kind,
                      key="PGN %d %s" % (pgn, PGNS.get(pgn, ("",))[0].split(" ")[0]), dissect=lambda b, o, cid=cid, d=bytes(data): j1939_dissect(b, o, cid, d),
                      idrows=lambda b, o, cid=cid: j1939_idrows(b, o, cid))

    def claims(self):
        for node in ("ecm", "tcm", "abs", "ic", "bcm", "tool"):
            nm = self.names.get(node, 0x8000000000000000 | (self.sa[node] << 3) | 0x123)
            self.jsend(node, 60928, nm.to_bytes(8, "little"), 0xFF, 6, "Address Claimed SA 0x%02X" % self.sa[node], "ctl")

    def eng(self):
        e = self.by["ecm"]
        thr = e.vars["Throttle %"]
        e.vars["RPM"] = round(e.vars["RPM"] + ((650 + thr * 15) - e.vars["RPM"]) * 0.05, 1)
        e.vars["Fuel L/h"] = round(2.5 + thr * 0.6, 2)
        if self.fault["hot"]:
            e.vars["Coolant C"] = min(118.0, e.vars["Coolant C"] + 0.05)
        return e

    def eec1(self):
        if not self.by["ecm"].on:
            return
        e = self.eng()
        thr = e.vars["Throttle %"]
        self.jsend("ecm", 61444, encode_pgn(61444, {899: 0, 512: thr * 0.8, 513: thr * 0.75, 190: e.vars["RPM"], 1483: 0}), info="EEC1 engine speed %.0f rpm" % e.vars["RPM"])

    def eec2(self):
        e = self.by["ecm"]
        if e.on:
            self.jsend("ecm", 61443, encode_pgn(61443, {91: e.vars["Throttle %"], 92: e.vars["Throttle %"] * 0.9}), info="EEC2 pedal %.0f%%" % e.vars["Throttle %"])

    def ccvs(self):
        a = self.by["abs"]
        thr = self.by["ecm"].vars["Throttle %"]
        a.vars["Speed km/h"] = round(max(0.0, min(110.0, a.vars["Speed km/h"] + thr * 0.004 - a.vars["Brake %"] * 0.01 - 0.01)), 2)
        if a.on:
            self.jsend("abs", 65265, encode_pgn(65265, {84: a.vars["Speed km/h"], 597: 1 if a.vars["Brake %"] > 1 else 0}), info="CCVS1 speed %.1f km/h" % a.vars["Speed km/h"])
            self.jsend("abs", 61441, encode_pgn(61441, {521: a.vars["Brake %"]}), info="EBC1 brake pedal %.0f%%" % a.vars["Brake %"])

    def lfe(self):
        e = self.by["ecm"]
        if e.on:
            self.jsend("ecm", 65266, encode_pgn(65266, {183: e.vars["Fuel L/h"], 184: 3.2}), info="LFE1 fuel rate %.1f L/h" % e.vars["Fuel L/h"])

    def etc2(self):
        t = self.by["tcm"]
        spd = self.by["abs"].vars["Speed km/h"]
        t.vars["Gear"] = max(1, min(12, int(spd / 9) + 1))
        if t.on:
            self.jsend("tcm", 61445, encode_pgn(61445, {524: t.vars["Gear"], 523: t.vars["Gear"]}), info="ETC2 gear %d" % t.vars["Gear"])

    def eflp(self):
        e = self.by["ecm"]
        if e.on:
            self.jsend("ecm", 65263, encode_pgn(65263, {100: e.vars["Oil kPa"], 111: 92}), info="EFL/P1 oil pressure %.0f kPa" % e.vars["Oil kPa"])

    def et1(self):
        e = self.by["ecm"]
        if e.on:
            self.jsend("ecm", 65262, encode_pgn(65262, {110: e.vars["Coolant C"], 174: 38, 175: 95}), info="ET1 coolant %.0f C" % e.vars["Coolant C"])

    def dm1(self):
        e = self.by["ecm"]
        if not e.on:
            return
        dt = [(110, 0)] if e.vars["Coolant C"] > 108 else []
        if self.fault["hot"] and e.vars["Coolant C"] > 108:
            dt.append((111, 1))
        lamp = 0x00 if not dt else 0x14
        body = bytearray([lamp, 0xFF])
        for spn, fmi in dt:
            self.oc = min(126, self.oc + 1)
            body += bytes([spn & 255, (spn >> 8) & 255, ((spn >> 16) << 5) | fmi, self.oc & 0x7F])
        if not dt:
            body += bytes([0, 0, 0, 0, 0xFF, 0xFF])
        self.by["ic"].vars["Lamps"] = "RED STOP + AMBER" if dt else "off"
        if len(body) <= 8:
            self.jsend("ecm", 65226, bytes(body), info="DM1 %s" % ("no active DTCs" if not dt else "SPN %d FMI %d" % dt[0]), kind="evt" if dt else "data")
        else:
            npk = (len(body) + 6) // 7
            self.jsend("ecm", 60416, bytes([32, len(body), 0, npk, 0xFF, 0xCA, 0xFE, 0x00]), info="TP.CM BAM: DM1 %d bytes in %d packets" % (len(body), npk), kind="ctl")
            for i in range(npk):
                chunk = bytes(body[i * 7:i * 7 + 7]).ljust(7, b"\xff")
                self.at(self.t + 0.05 * (i + 1), lambda i=i, chunk=chunk: self.jsend("ecm", 60160, bytes([i + 1]) + chunk, info="TP.DT #%d (DM1 part)" % (i + 1), kind="evt"))

    def can_fault(self, key, on):
        if key == "tool500":
            (self.bus.bad_rate.add if on else self.bus.bad_rate.discard)("tool")
        if key == "conflict" and on:
            self.jsend("bcm", 60928, self.names["bcm"].to_bytes(8, "little"), 0xFF, 6, "Address Claimed: BCM wants SA 0x00!", "ctl")
            self.sa["bcm"] = 0x00
            self.at(self.t + 0.001, lambda: self.jsend("ecm", 60928, self.names["ecm"].to_bytes(8, "little"), 0xFF, 6, "Address Claimed: ECM defends 0x00 (lower NAME wins)", "ctl"))

            def lose():
                self.sa["bcm"] = 0xFE
                self.by["bcm"].addr = "SA 0xFE (cannot claim)"
                self.jsend("bcm", 60928, self.names["bcm"].to_bytes(8, "little"), 0xFF, 6, "Cannot Claim Address (from SA 0xFE)", "err")
            self.at(self.t + 0.25, lose)
        if key == "conflict" and not on:
            self.sa["bcm"] = 0x21
            self.by["bcm"].addr = "SA 0x21"
        if key == "hot" and not on:
            self.by["ecm"].vars["Coolant C"] = 88.0

    def rx(self, fr):
        if fr.err or not fr.meta.get("lost") is None and False:
            return
        ic = self.by["ic"]
        e = self.by["ecm"]
        ic.vars["Tacho"] = "%.0f rpm" % e.vars["RPM"]
        ic.vars["Speedo"] = "%.1f km/h" % self.by["abs"].vars["Speed km/h"]
        ic.vars["Coolant gauge"] = "%.0f C" % e.vars["Coolant C"]

    def request(self, pgn, da, send=True):
        data = bytes([pgn & 255, (pgn >> 8) & 255, pgn >> 16])
        if not send:
            cid = j1939_id(6, 59904, 0xF9, da)
            return self.preview_can("tool", cid, data, ext=True, dissect=lambda b, o: j1939_dissect(b, o, cid, data), idrows=lambda b, o: j1939_idrows(b, o, cid))
        self.jsend("tool", 59904, data, da, 6, "Request PGN %d -> SA 0x%02X" % (pgn, da), "cmd")
        node = {0: "ecm", 3: "tcm", 0x0B: "abs", 0x17: "ic"}.get(da)
        if node and self.by[node].on:
            if pgn == 65260:
                vin = b"1XKAD49X0NJ123456*"
                self.at(self.t + 0.01, lambda: self.jsend(node, 60416, bytes([32, len(vin), 0, 3, 0xFF, 0xEC, 0xFE, 0]), info="TP.CM BAM: VI %d bytes" % len(vin), kind="ctl"))
                for i in range(3):
                    self.at(self.t + 0.06 + 0.05 * i, lambda i=i: self.jsend(node, 60160, bytes([i + 1]) + vin[i * 7:i * 7 + 7].ljust(7, b"\xff"), info="TP.DT #%d VIN part" % (i + 1), kind="resp"))
            elif pgn == 65235:
                self.dtcs.clear()
                self.oc = 0
                self.at(self.t + 0.005, lambda: self.jsend(node, 59392, bytes([0, 0xFF, 0xFF, 0xFF, 0xF9, 0xD3, 0xFE, 0]), 0xF9, 6, "Acknowledgment: DM11 done", "resp"))
            elif pgn in PGNS and PGNS[pgn][2]:
                self.at(self.t + 0.005, lambda: self.jsend(node, pgn, encode_pgn(pgn, {}), info="%s (on request)" % PGNS[pgn][0].split(" ")[0], kind="resp"))
            else:
                self.at(self.t + 0.005, lambda: self.jsend(node, 59392, bytes([1, 0xFF, 0xFF, 0xFF, 0xF9, pgn & 255, (pgn >> 8) & 255, pgn >> 16]), 0xF9, 6, "NACK: PGN %d not supported" % pgn, "err"))
        return None

    def tpls(self):
        return [Tpl("Request PGN (59904)", [P("pgn", "PGN", 65260, opts=[65260, 65242, 65262, 65235, 61444, 65259], fmt=lambda v: "%d %s" % (v, PGNS.get(v, ("Component ID",))[0][:22])),
                                            P("da", "Destination SA", 0x00, 0, 0xFF, fmt=lambda v: "0x%02X %s" % (v, SA_NAMES.get(v, "")))],
                    lambda s, v, send: self.request(v["pgn"], v["da"], send), "65260 VIN (multi-packet), 65242 software ID, 65235 DM11 clears active DTCs.")] + self.generic_tpls("tool")


# ================================================================= J1708
MID = {128: "Engine #1", 130: "Transmission", 136: "Brakes, tractor", 140: "Instrument cluster", 172: "Off-board diagnostics #1", 142: "Vehicle management"}
PID = {84: ("Road speed", 1, 0.5, "mph"), 190: ("Engine speed", 2, 0.25, "rpm"), 110: ("Engine coolant temperature", 1, 1, "degF"), 100: ("Engine oil pressure", 1, 0.5, "psi"),
       168: ("Battery potential", 2, 0.05, "V"), 102: ("Boost pressure", 1, 0.125, "psi"), 245: ("Total vehicle distance", 4, 0.1, "mi"), 247: ("Total engine hours", 4, 0.05, "h"),
       194: ("Transmitter system diagnostic code", -1, 1, ""), 0: ("Request parameter", 1, 1, ""), 237: ("Vehicle identification number", -1, 1, ""), 243: ("Component identification", -1, 1, "")}


def j1587_dissect(b, msg):
    b.rows.append([0, "SAE J1587 application layer", 1, len(msg) - 2, "PIDs (parameter IDs) each followed by their data; the PID number defines the length"])
    k = 1
    while k < len(msg) - 1:
        pid = msg[k]
        nm, ln, sc, unit = PID.get(pid, ("PID %d" % pid, 1 if pid < 128 else (2 if pid < 192 else -1), 1, ""))
        if ln == -1:
            ln = msg[k + 1] + 1 if k + 1 < len(msg) - 1 else 1
            raw = bytes(msg[k + 1:k + 1 + ln])
            txt = raw[1:].decode("latin-1") if pid in (237, 243) else raw.hex(" ")
            if pid == 194 and len(raw) >= 2:
                txt = "PID/SID %d FMI %d" % (raw[1], raw[2] & 0x0F if len(raw) > 2 else 0)
        else:
            raw = bytes(msg[k + 1:k + 1 + ln])
            txt = "%g %s (raw %d)" % (int.from_bytes(raw, "little") * sc, unit, int.from_bytes(raw, "little"))
        b.rows.append([1, "PID %d %s: %s" % (pid, nm, txt), k, 1 + ln, "PIDs 0-127: 1 data byte, 128-191: 2 bytes, 192-253: length byte + data"])
        k += 1 + ln


class J17xx(Scenario):
    cat = "auto"
    phy, rate = "rs485", 9600
    medium = "SAE J1708 bus (RS-485-like transceivers, 9600 bit/s 8N1), MIDs 128 engine, 130 transmission, 136 brakes, 140 cluster + tool"
    nets = [("A", "J1708 + (A)"), ("B", "J1708 - (B)"), ("VDIFF", "differential")]
    lines = ["D", "DE"]

    def build(self):
        nodes = [self.node("eng", "ENGINE ECM", "ecu", 30, 40, "MID 128"), self.node("trn", "TRANSMISSION", "ecu", 300, 40, "MID 130"),
                 self.node("brk", "ABS", "ecu", 570, 40, "MID 136"), self.node("ic", "CLUSTER", "display", 220, 280, "MID 140"), self.node("tool", "DIAG TOOL", "tool", 560, 280, "MID 172")]
        for n in nodes[3:]:
            n.at_top()
        self.trunk(190, 30, 860, nodes, "can", net="VDIFF", label="J1708 twisted pair (18 AWG), 40 m", drop_conn="deutsch")
        self.mid = {"eng": 128, "trn": 130, "brk": 136, "ic": 140, "tool": 172}
        self.user = "tool"
        e = self.by["eng"]
        e.vars.update({"RPM": 1100.0, "Coolant F": 190, "Oil psi": 45.0, "Battery V": 13.9, "Throttle %": 20.0})
        e.ctl = [("Throttle %", "THROTTLE", 0.0, 100.0, 0, lambda v: "%.0f%%" % v)]
        self.by["brk"].vars["Speed mph"] = 0.0
        self.by["ic"].vars.update({"Tacho": "-", "Speedo": "-"})
        self.every(0.1, self.eng_msg, 0.01)
        self.every(0.1, self.brk_msg, 0.03)
        self.every(1.0, self.trn_msg, 0.05)
        self.every(1.0, self.dtc_msg, 0.4)

    def msg(self, node, body, info, kind="data", err=None, prio=8):
        mid = self.mid[node]
        raw = bytes([mid]) + body
        cs = (-sum(raw)) & 0xFF
        msg = raw + bytes([cs])
        b = Bld("SAE J1708 message", "MID + data + checksum, max 21 bytes, characters 8N1 at 9600 bit/s")
        b.u8("MID", mid, "%d %s" % (mid, MID.get(mid, "")), "Message identifier = sending module")
        b.raw("Data", body, None, "")
        b.u8("Checksum", cs, "0x%02X [correct]" % cs, "Two's complement of the sum of MID and data bytes: all bytes sum to 0 mod 256")
        p = b.done()
        j1587_dissect(p, list(msg)) if self.dissect_pids else None
        if len(msg) > 21:
            err = err or "Message longer than 21 bytes"
        fr = serial_frame(self, node, None, "J1708" if not self.dissect_pids else "J1587", info, p, 9600, 8, "N", 1, rs485=2, kind=kind, err=err, key="MID %d" % mid,
                          lead=10 + 2 * prio)
        return self.tx(fr, ifs=(10 + 2 * prio) / 9600.0)

    def eng_msg(self):
        e = self.by["eng"]
        if not e.on:
            return
        e.vars["RPM"] = round(e.vars["RPM"] + ((650 + e.vars["Throttle %"] * 15) - e.vars["RPM"]) * 0.1, 1)
        rpm = int(e.vars["RPM"] / 0.25)
        body = bytes([190]) + rpm.to_bytes(2, "little") + bytes([110, int(e.vars["Coolant F"]), 100, int(e.vars["Oil psi"] / 0.5)])
        err = None
        if self.fault.get("cksum") and self.rng.random() < 0.3:
            err = "Checksum error: receivers discard the message"
        if self.fault.get("collide") and self.rng.random() < 0.2:
            err = "Collision: two MIDs started together, both back off"
        self.msg("eng", body, "MID 128: RPM %.0f, coolant %d F, oil %.0f psi" % (e.vars["RPM"], e.vars["Coolant F"], e.vars["Oil psi"]), err=err, prio=1)
        self.by["ic"].vars["Tacho"] = "%.0f rpm" % e.vars["RPM"]

    def brk_msg(self):
        b_ = self.by["brk"]
        b_.vars["Speed mph"] = round(min(70.0, b_.vars["Speed mph"] + self.by["eng"].vars["Throttle %"] * 0.003 - 0.01), 1)
        b_.vars["Speed mph"] = max(0.0, b_.vars["Speed mph"])
        if b_.on:
            self.msg("brk", bytes([84, int(b_.vars["Speed mph"] / 0.5)]), "MID 136: road speed %.1f mph" % b_.vars["Speed mph"], prio=2)
            self.by["ic"].vars["Speedo"] = "%.1f mph" % b_.vars["Speed mph"]

    def trn_msg(self):
        if self.by["trn"].on:
            self.msg("trn", bytes([168]) + int(13.9 / 0.05).to_bytes(2, "little"), "MID 130: battery 13.9 V", prio=4)

    def dtc_msg(self):
        if self.fault.get("dtc"):
            self.msg("eng", bytes([194, 2, 110, 0x80 | 0]), "MID 128: PID 194 fault code PID 110 FMI 0 (coolant high)", "evt", prio=3)

    def tpls(self):
        return [Tpl("Request parameter (PID 0)", [P("mid", "To MID", 128, opts=[128, 130, 136]), P("pid", "PID wanted", 245, opts=[245, 247, 237, 243, 168, 110])],
                    lambda s, v, send: self.req(v, send), "PID 0 asks a module to send one parameter. 245 odometer, 247 engine hours, 237 VIN, 243 component ID.")]

    def req(self, v, send):
        if not send:
            raw = bytes([172, 0, v["pid"], v["mid"]])
            return Frame(self.t, 0.005, "tool", None, "J1587", "Request", pdu=Pdu(raw + bytes([(-sum(raw)) & 255]), [[0, "J1708 request", 0, 5, ""]]))
        self.msg("tool", bytes([0, v["pid"], v["mid"]]), "MID 172: request PID %d from MID %d" % (v["pid"], v["mid"]), "cmd", prio=8)
        node = {128: "eng", 130: "trn", 136: "brk"}[v["mid"]]
        p = v["pid"]
        if p == 245:
            body = bytes([245, 4]) + int(412345.6 / 0.1).to_bytes(4, "little")
        elif p == 247:
            body = bytes([247, 4]) + int(12034.5 / 0.05).to_bytes(4, "little")
        elif p == 237:
            vin = b"1XKAD49X0NJ123456"
            body = bytes([237, len(vin)]) + vin
        elif p == 243:
            s_ = b"COMMSIM*ECM-X15*SN4711*"
            body = bytes([243, len(s_)]) + s_
        elif p == 168:
            body = bytes([168]) + int(13.9 / 0.05).to_bytes(2, "little")
        else:
            body = bytes([110, 190])
        self.at(self.t + 0.03, lambda: self.msg(node, body[:20], "MID %d: PID %d response" % (v["mid"], p), "resp", prio=8))
        return None


class J1708(J17xx):
    key, name = "j1708", "SAE J1708"
    blurb = "Older heavy-duty vehicle networks"
    dissect_pids = False
    faults = [("cksum", "Corrupted messages from the engine (bad checksum)", "Each J1708 message ends with a checksum byte that makes the sum of all bytes zero; receivers drop messages that fail."),
              ("collide", "Two modules start transmitting together", "J1708 access: wait for an idle line of (10 + 2 x priority) bit times, listen while sending; on a collision both stop and retry."),
              ("dtc", "Engine reports a fault code", "Diagnostic code broadcast in PID 194 (see the J1587 view for decoding).")]
    spec = [("Standard", "SAE J1708 (physical + data link), used with J1587 (application) - pre-2007 trucks and buses"),
            ("Physical", "RS-485 style transceivers with RC filtering, 9600 bit/s, 8N1"), ("Message", "MID (sender) + data + checksum, max 21 bytes"),
            ("Access", "Idle time = 10 + 2 x priority bit times before transmitting; collision detection by reading back"),
            ("Checksum", "Two's complement of the sum of all other bytes"), ("Successor", "J1939 (CAN) replaced J1708/J1587")]
    frame = [["J1708 message", ("MID", 8), ("Data (PIDs)", "n x 8"), ("Checksum", 8)]]
    about = ("J1708 was the first common truck network: a slow RS-485-like bus where any module may talk after the line has been idle for a time "
             "that depends on its priority. Every message starts with the sender's MID and ends with a checksum. J1587 defines what the bytes in "
             "between mean.")
    guide = ["In LOGIC, see the idle gap before each message (priority) and the 10-bit characters.",
             "Check the checksum: add all bytes of a message, the low byte is 0.",
             "Inject corrupted messages and filter on 'err'."]


class J1587(J17xx):
    key, name = "j1587", "SAE J1587"
    blurb = "Vehicle diagnostic messaging over J1708"
    dissect_pids = True
    medium = "SAE J1587 parameters (PIDs) and diagnostics carried in J1708 messages, 9600 bit/s"
    faults = [("dtc", "Engine sets a coolant fault code", "PID 194 diagnostic code: PID 110 (coolant temperature) with FMI 0 (above normal)."),
              ("cksum", "Corrupted messages (checksum errors)", "Receivers silently discard them."),
              ("collide", "Collisions between modules", "Back-off and retry per J1708.")]
    spec = [("Standard", "SAE J1587 (application layer over J1708); diagnostics J2497 PLC4TRUCKS for trailers"), ("PIDs", "0-127: 1 byte, 128-191: 2 bytes, 192-253: variable (length byte); 255 = page 2"),
            ("Examples", "PID 84 road speed (0.5 mph), 190 engine speed (0.25 rpm), 110 coolant (1 degF), 245 odometer (0.1 mi)"),
            ("Diagnostics", "PID 194: SID/PID + FMI (+ count); PID 195/196 request/response for codes"), ("Requests", "PID 0 requests a single parameter from a MID")]
    frame = [["J1587 data", ("MID", 8), ("PID", 8), ("value", "1-2 B"), ("PID", 8), ("value", "..."), ("Checksum", 8)]]
    about = ("J1587 gives meaning to J1708 bytes: each value is a PID number followed by its data, whose length and scaling are fixed by the PID. "
             "A single message can carry several parameters. Fault codes are reported in PID 194 with an FMI (failure mode identifier) - the same "
             "idea J1939 later reused with SPNs.")
    guide = ["Select an engine message and read each PID in the tree (engine speed, coolant, oil pressure).",
             "COMPOSE a request for PID 245 (odometer) or 237 (VIN) from MID 128.",
             "Inject the fault code and decode PID 194."]


# ======================================================== CANopen (mobile)
class CANopenMobile(CanNet):
    key, name, cat = "canopen_mobile", "CANopen (mobile machinery)", "auto"
    blurb = "Mobile machinery and embedded systems"
    rate = 250000
    can_proto = "CANopen"
    medium = "CANopen + CANopen Safety (EN 50325-5) on an aerial work platform: joystick, inclinometer, proportional valve controller, safety controller, 250 kbit/s"
    faults = [("hb", "Joystick heartbeat lost", "The valve controller's heartbeat consumer times out: valves go to the safe (closed) state."),
              ("srdo", "SRDO inverted copy corrupted", "Safety data is sent twice, the second copy bit-inverted; any mismatch is treated as a safety fault."),
              ("srvt", "Second SRDO copy arrives late (SRVT exceeded)", "Safety-Related Validation Time: both copies must arrive within e.g. 20 ms."),
              ("tilt", "Platform tilted beyond 5 degrees", "The inclinometer sends EMCY and the safety controller locks out lifting.")]
    spec = [("Standards", "CiA 301, EN 50325-5 (CANopen Safety / SRDO), CiA 410 inclinometer, CiA 408 hydraulic valves, CiA 4xx application profiles"),
            ("Bus", "CAN 250 kbit/s typical in mobile machines (EN ISO 13849 safety)"), ("SRDO", "Two CAN frames per safety object: normal data and bit-inverted data, COB-IDs 0x101+2n and 0x102+2n"),
            ("Timers", "SCT (safeguard cycle time) and SRVT (validation time between the two copies)"), ("Liveness", "Heartbeat producer/consumer with fail-safe reaction")]
    frame = [["SRDO pair", ("Normal: data", "n x 8"), ("Inverted: ~data", "n x 8")]]
    about = ("Mobile machines use CANopen like factories but must also be safe: an aerial platform must never move if the joystick signal is wrong. "
             "CANopen Safety sends each safety-relevant object twice, the second copy bit-inverted, within a short validation time, and every node "
             "watches its partners' heartbeats so that a broken cable leads to a safe stop.")
    guide = ["Find the two SRDO frames (0x101 normal, 0x102 inverted) and check that the bytes are complements.",
             "Corrupt the inverted copy and watch the safety controller stop the valves.",
             "Pull the joystick heartbeat."]

    def setup(self):
        nodes = [self.node("safe", "SAFETY CONTROLLER", "plc", 30, 60, "node 1", "NMT master"), self.node("joy", "JOYSTICK", "button", 280, 60, "node 16", "CiA 401 + SRDO"),
                 self.node("inc", "INCLINOMETER", "sensor", 530, 60, "node 32", "CiA 410"), self.node("valve", "VALVE CONTROLLER", "valve", 280, 290, "node 48", "CiA 408"),
                 self.node("disp", "DISPLAY", "display", 600, 290, "node 5", "")]
        for n in nodes[3:]:
            n.at_top()
        self.can_trunk(nodes, 200, conn="deutsch")
        self.user = "safe"
        j = self.by["joy"]
        j.vars.update({"Lever %": 0.0})
        j.ctl = [("Lever %", "LEVER", -100.0, 100.0, 0, lambda v: "%+.0f%%" % v)]
        self.by["inc"].vars.update({"Tilt deg": 1.2})
        self.by["inc"].ctl = [("Tilt deg", "TILT", -10.0, 10.0, 0, lambda v: "%+.1f" % v)]
        self.by["valve"].vars.update({"Spool %": 0.0, "State": "ENABLED"})
        self.every(0.02, self.cycle, 0.05)
        self.every(0.1, self.hb, 0.07)
        self.last_joy = 0.0

    def cycle(self):
        j = self.by["joy"]
        if j.on and not self.fault["hb"]:
            lever = int(j.vars["Lever %"])
            d = struct.pack("<h", lever * 100) + b"\x01\x00"
            inv = bytes(x ^ 0xFF for x in d)
            if self.fault["srdo"]:
                inv = bytes([inv[0] ^ 0x10]) + inv[1:]
            self.bus.send("joy", 0x101, d, info="SRDO1 normal: lever %+d%%" % lever, kind="data", key="SRDO1 normal")
            self.bus.send("joy", 0x102, inv, t=self.t + (0.03 if self.fault["srvt"] else 0.0005), info="SRDO1 inverted", kind="data", key="SRDO1 inverted")
        tilt = self.by["inc"].vars["Tilt deg"]
        self.bus.send("inc", 0x180 + 32, struct.pack("<hh", int(tilt * 100), 0), info="TPDO1 inclinometer X %+.2f deg" % tilt)
        v = self.by["valve"]
        ok = True
        why = ""
        if self.fault["hb"] or not j.on:
            ok, why = False, "joystick heartbeat lost"
        elif self.fault["srdo"]:
            ok, why = False, "SRDO copy mismatch"
        elif self.fault["srvt"]:
            ok, why = False, "SRVT exceeded"
        elif abs(tilt) > 5 or self.fault["tilt"]:
            ok, why = False, "tilt beyond 5 deg"
        if ok:
            v.vars["Spool %"] = round(j.vars["Lever %"], 1)
            v.vars["State"] = "ENABLED"
            v.state = ""
        else:
            if v.vars["State"] == "ENABLED":
                self.log("SAFE STATE: %s - valves closed" % why)
                if "tilt" in why:
                    self.bus.send("inc", 0x80 + 32, bytes([0x00, 0xFF, 0x01, 0, 0, 0, 0, 0]), info="EMCY node 32: inclination limit", kind="evt")
            v.vars["Spool %"] = 0.0
            v.vars["State"] = "SAFE STATE (%s)" % why
            v.state = "SAFE STATE"
        self.bus.send("safe", 0x200 + 48, struct.pack("<h", int(v.vars["Spool %"] * 100)), info="RPDO1 valve: spool %+.0f%%" % v.vars["Spool %"], kind="cmd")

    def hb(self):
        for d, nid in (("joy", 16), ("inc", 32), ("valve", 48), ("safe", 1)):
            if self.by[d].on and not (d == "joy" and self.fault["hb"]):
                self.bus.send(d, 0x700 + nid, b"\x05", info="Heartbeat node %d: operational" % nid, kind="sync")

    def can_fault(self, key, on):
        if key == "tilt":
            self.by["inc"].vars["Tilt deg"] = 6.5 if on else 1.2

    def tpls(self):
        return self.generic_tpls("disp")


# ======================================================= CAN FD automotive
class CANFDAuto(CANFD):
    key, name, cat = "canfd_auto", "CAN FD (vehicle E2E)", "auto"
    blurb = "Modern vehicle networking"
    medium = "CAN FD 500k/2M powertrain/ADAS bus with AUTOSAR E2E protection (CRC-8 J1850 + alive counter) on every safety signal"
    faults = [("flip", "Gateway corrupts a byte while routing", "CAN's own CRC is recomputed by the gateway, so only the end-to-end CRC (E2E) reveals the corruption."),
              ("stuck", "Steering ECU software hangs (counter frozen)", "The alive counter stops changing: the receiver's E2E check reports REPEATED and then no new data."),
              ("loss", "Every 5th steering frame lost", "The counter jumps by 2: E2E status WRONGSEQUENCE."),
              ("classic", "Classical CAN node attached", "Form errors on every FD frame.")]
    spec = [("Standards", "ISO 11898-1:2015 CAN FD; AUTOSAR E2E protection profiles (P1/P2: CRC-8 SAE J1850 + 4-bit counter; P5/P11...)"),
            ("Why E2E", "CAN's CRC protects one hop; E2E protects sender-to-receiver through gateways and software"),
            ("Checks", "CRC over data ID + payload, alive counter sequence, timeout"), ("Results", "OK, REPEATED, WRONGSEQUENCE, ERROR (CRC), NODATA (timeout)"),
            ("Security", "AUTOSAR SecOC adds a truncated MAC + freshness value for authenticity")]
    frame = [["E2E-protected PDU", ("CRC-8", 8), ("Counter", 4), ("Data ID nibble", 4), ("Signals", "n x 8")]]
    about = ("Inside a car a steering-angle signal may cross two CAN buses and a gateway before it reaches the ESP. Each hop has its own CRC, but a "
             "fault inside the gateway would be invisible. AUTOSAR end-to-end protection adds a CRC-8 and a rolling counter computed by the sending "
             "application and checked by the receiving application, so corruption, repetition and loss are all detected.")
    guide = ["Select a steering frame: E2E CRC and counter in the tree, then the signals.",
             "Inject the gateway corruption: the CAN frame is valid but the E2E check fails at the ESP.",
             "Freeze the counter and watch the E2E status in the ESP's DEVICE panel."]

    def setup(self):
        nodes = [self.node("str", "STEERING ECU", "ecu", 40, 60, "0x0C2 / 10 ms"), self.node("gw", "CENTRAL GATEWAY", "gw", 300, 60, "routing"),
                 self.node("esp", "ESP / ABS", "ecu", 560, 60, "E2E receiver"), self.node("tool", "CAN FD TOOL", "tool", 300, 290, ""),
                 self.node("old", "LEGACY ECU", "ecu", 600, 290, "classical CAN 2.0")]
        nodes[3].at_top()
        nodes[4].at_top()
        nodes[4].on = False
        nodes[4].sub = "unplugged"
        self.can_trunk(nodes, 200)
        self.user = "tool"
        self.n = 0
        self.ctr = 0
        self.last_ctr = None
        self.by["str"].vars.update({"Angle deg": 0.0})
        self.by["str"].ctl = [("Angle deg", "ANGLE", -540.0, 540.0, 0, lambda v: "%+.0f" % v)]
        self.by["esp"].vars.update({"E2E status": "-", "E2E errors": 0, "Last angle": "-"})
        self.every(0.010, self.steer, 0.002)
        self.every(0.033, self.cam, 0.001)

    def e2e(self, data_id, payload, ctr):
        hdr = bytes([0, (ctr & 15) | ((data_id >> 8) & 15) << 4])
        c = crcn("CRC-8/SAE-J1850", bytes([data_id & 255]) + hdr[1:] + payload)
        return bytes([c]) + hdr[1:] + payload

    def steer(self):
        if not self.by["str"].on:
            return
        self.n += 1
        if not self.fault["stuck"]:
            self.ctr = (self.ctr + 1) % 15
        ang = self.by["str"].vars["Angle deg"]
        body = self.e2e(0x2C2, struct.pack("<hhH", int(ang * 10), 0, 0x0001) + bytes(10), self.ctr)
        if self.fault["loss"] and self.n % 5 == 0:
            return
        raw = bytearray(body)
        if self.fault["flip"]:
            raw[3] ^= 0x04

        def dis(b, off, d=bytes(raw)):
            b.rows.append([0, "AUTOSAR E2E Profile 1 protected PDU", off, len(d), "End-to-end protection added by the sending application"])
            b.rows.append([1, "CRC-8 (SAE J1850): 0x%02X" % d[0], off, 1, "Over the data ID, counter byte and payload"])
            b.rows.append([1, "Alive counter: %d" % (d[1] & 15), off + 1, 1, "Increments 0..14 each transmission"])
            b.rows.append([1, "Steering angle: %+.1f deg" % (struct.unpack("<h", d[2:4])[0] / 10.0), off + 2, 2, ""])
        self.bus.send("str", 0x0C2, bytes(raw), fd=True, brs=True, info="SteeringAngle %+.0f deg ctr %d" % (ang, self.ctr), dissect=dis, meta={"e2e": bytes(raw), "ctr": self.ctr})

    def rx(self, fr):
        if fr.err or "e2e" not in fr.meta:
            return
        d = fr.meta["e2e"]
        esp = self.by["esp"]
        ok_crc = crcn("CRC-8/SAE-J1850", bytes([0xC2]) + d[1:2] + d[2:]) == d[0]
        ctr = d[1] & 15
        if not ok_crc:
            st = "ERROR (E2E CRC mismatch)"
        elif self.last_ctr is None:
            st = "INITIAL"
        elif ctr == self.last_ctr:
            st = "REPEATED"
        elif (ctr - self.last_ctr) % 15 == 1:
            st = "OK"
        else:
            st = "WRONGSEQUENCE (lost %d)" % ((ctr - self.last_ctr) % 15 - 1)
        self.last_ctr = ctr
        esp.vars["E2E status"] = st
        if st != "OK" and st != "INITIAL":
            esp.vars["E2E errors"] += 1
            esp.state = "E2E " + st.split(" ")[0]
        else:
            esp.state = ""
            esp.vars["Last angle"] = "%+.1f deg" % (struct.unpack("<h", d[2:4])[0] / 10.0)

    def cam(self):
        data = bytes((i * 37 + self.n) & 255 for i in range(64))
        self.bus.send("gw", 0x320, data, fd=True, brs=True, info="ADAS object list (64 B, routed)")


# ===================================================================== LIN
LIN_FR = {0x10: ("Window_Cmd", "master", 2), 0x11: ("Window_Status", "win", 2), 0x20: ("Mirror_Cmd", "master", 2), 0x30: ("RLS_Data", "rls", 4), 0x3C: ("MasterReq", "master", 8), 0x3D: ("SlaveResp", "win", 8)}


class LIN(Scenario):
    key, name, cat = "lin", "LIN Bus", "auto"
    blurb = "Low-cost vehicle electronics"
    phy, rate = "lin", 19200
    medium = "ISO 17987 / LIN 2.2A at 19.2 kbit/s: body controller master, door window lift, mirror and rain/light sensor slaves, 10 ms slots"
    nets = [("LIN", "LIN line (single wire, 12 V)"), ("VBAT", "battery")]
    lines = ["B"]
    faults = [("noresp", "Window-lift slave not responding", "The master sends the header for 0x11 but no response follows: 'no response' error for that frame."),
              ("cks", "Rain sensor uses the classic checksum", "LIN 2.x uses the enhanced checksum (PID included); a mismatch causes checksum errors."),
              ("drift", "Mirror slave RC oscillator 16 % off", "Slaves re-synchronise on the 0x55 sync field (+/-14 % tolerated); beyond that they misread headers."),
              ("short", "LIN wire shorted to ground", "The bus is permanently dominant: every frame fails (bus error).")]
    spec = [("Standard", "ISO 17987 (LIN 2.2A), SAE J2602"), ("Physical", "Single wire, 12 V, open-collector with 1 kΩ master pull-up, max 20 kbit/s, 40 m, 16 nodes"),
            ("Access", "One master runs a schedule table; slaves only answer headers"), ("Frame", "Break (>= 13 bits dominant), sync 0x55, protected ID (6 bits + 2 parity), 1-8 data bytes, checksum"),
            ("Checksum", "Classic (data only, LIN 1.x) or enhanced (PID + data, LIN 2.x): inverted sum with carry"), ("Diagnostics", "0x3C master request / 0x3D slave response, sleep / wake-up")]
    frame = [["LIN frame", ("Break", 13), ("Del", 1), ("Sync 0x55", 10), ("PID", 10), ("Data 1-8", "n x 10"), ("Checksum", 10)]]
    about = ("LIN is the low-cost sub-bus under CAN for windows, mirrors, seats and sensors. The master owns the time: it walks a schedule table and "
             "sends a header (break, sync, protected identifier) for each slot; whichever node publishes that identifier fills in the response. Slaves "
             "can use cheap RC oscillators because they measure the 0x55 sync byte and adjust their bit timing every frame.")
    guide = ["In LOGIC, find the break, the 0x55 sync field (alternating bits) and the PID with its two parity bits.",
             "Compare a master-published frame (0x10) with a slave-published one (0x11).",
             "Switch the rain sensor to the classic checksum and read the error.",
             "COMPOSE 'Go to sleep' then watch the bus fall silent."]

    def build(self):
        m = self.node("master", "BODY CONTROLLER", "ecu", 30, 40, "LIN master", "1 kΩ pull-up")
        win = self.node("win", "WINDOW LIFT", "motor", 260, 260, "slave", "NAD 0x02")
        mir = self.node("mir", "MIRROR", "ecu", 480, 260, "slave", "NAD 0x03")
        rls = self.node("rls", "RAIN/LIGHT SENSOR", "sensor", 700, 260, "slave", "NAD 0x04")
        for n in (win, mir, rls):
            n.at_top()
        self.trunk(180, 60, 860, [m, win, mir, rls], "wire", net="LIN", label="LIN single wire (+ ground, battery)", drop_conn="dt")
        self.user = "master"
        self.sched = [0x10, 0x11, 0x20, 0x30]
        self.k = 0
        self.asleep = False
        win.vars.update({"Position %": 40, "Command": "stop"})
        rls.vars.update({"Rain": 0, "Light lux": 800})
        rls.ctl = [("Rain", "RAIN", 0, 15, 1, lambda v: "%d" % v)]
        m.vars.update({"No response errors": 0, "Checksum errors": 0, "Schedule": "Normal (10 ms slots)"})
        self.every(0.010, self.lin_slot, 0.005)

    def lin_frame(self, fid, data, info, kind, err=None, classic=False, resp=True, src="master"):
        pid = lin_pid(fid)
        cs = lin_cs(data, None if classic or fid >= 0x3C else pid)
        b = Bld("LIN frame ID 0x%02X (%s)" % (fid, LIN_FR.get(fid, ("?",))[0]), "")
        b.u8("Sync", 0x55, "0x55", "Alternating 0101... lets slaves measure the bit time")
        b.u8("Protected ID", pid, "0x%02X (ID 0x%02X, P0 %d, P1 %d)" % (pid, fid, (pid >> 6) & 1, pid >> 7), "6-bit frame identifier + 2 parity bits")
        if resp:
            b.raw("Data", data, None, "Response published by %s" % LIN_FR.get(fid, ("", "?"))[1])
            b.u8("Checksum", cs, "0x%02X (%s)" % (cs, "classic" if classic or fid >= 0x3C else "enhanced"), "Inverted 8-bit sum with carry; enhanced includes the PID")
        p = b.done()
        tb = 1 / 19200.0
        nbytes = 2 + (len(data) + 1 if resp else 0)
        dur = (14 + nbytes * 10 + 2) * tb
        short = self.fault["short"]

        def wf(fr):
            w = Wire(bit=tb)
            w.set("B", 0.0, 1)
            w.set("B", tb, 0)
            w.set("B", 14 * tb, 1)
            w.seg(tb, 14 * tb, "BREAK", 8, 1)
            w.seg(14 * tb, 15 * tb, "DEL", 7, 1)
            bts = [0x55, pid] + (list(data) + [cs] if resp else [])
            labs = ["SYNC 55", "PID %02X" % pid] + ["%02X" % x for x in data] + (["CS %02X" % cs] if resp else [])
            spans = w.uart("B", bytes(bts), 19200, 15 * tb, 8, "N", 1, labels=labs)
            if len(spans) > 2 and resp:
                w.seg(spans[2][0], spans[-1][1], "RESPONSE (%s)" % LIN_FR.get(fid, ("", "?"))[1], 1, 1)
            w.seg(spans[0][0], spans[1][1], "HEADER (master)", 0, 1)
            if short:
                w.L["B"] = ([0.0], [0])
            w.end(dur)
            return w
        return Frame(self.t, dur, src, LIN_FR.get(fid, ("", "?"))[1] if src == "master" else "master", "LIN", info, pdu=p, kind=kind, err=err, wirefn=wf, key="ID 0x%02X" % fid)

    def lin_slot(self):
        if self.asleep or not self.by["master"].on:
            return
        fid = self.sched[self.k % len(self.sched)]
        self.k += 1
        name, pub, n = LIN_FR[fid]
        err = None
        resp = True
        m = self.by["master"]
        if self.fault["short"]:
            err = "Bus error: LIN line stuck dominant"
        if fid == 0x10:
            win = self.by["win"]
            data = bytes([1 if win.vars["Command"] == "up" else (2 if win.vars["Command"] == "down" else 0), 0])
            info = "Window_Cmd %s" % win.vars["Command"]
        elif fid == 0x11:
            win = self.by["win"]
            if win.vars["Command"] == "up":
                win.vars["Position %"] = min(100, win.vars["Position %"] + 1)
            elif win.vars["Command"] == "down":
                win.vars["Position %"] = max(0, win.vars["Position %"] - 1)
            data = bytes([win.vars["Position %"], 0x01])
            info = "Window_Status pos %d%%" % win.vars["Position %"]
            if self.fault["noresp"] or not win.on:
                resp, err = False, err or "No response: slave silent after header"
                m.vars["No response errors"] += 1
        elif fid == 0x20:
            data = bytes([0x00, 0x00])
            info = "Mirror_Cmd"
            if self.fault["drift"]:
                err = err or "Mirror slave misread the header (clock 16 % off)"
        else:
            r = self.by["rls"]
            data = bytes([int(r.vars["Rain"]), (int(r.vars["Light lux"]) >> 8) & 255, int(r.vars["Light lux"]) & 255, 0])
            info = "RLS_Data rain %d light %d lx" % (r.vars["Rain"], r.vars["Light lux"])
            if self.fault["cks"]:
                err = err or "Checksum error: slave used the classic checksum"
                m.vars["Checksum errors"] += 1
        fr = self.lin_frame(fid, data, info, "data" if pub != "master" else "cmd", err, classic=self.fault["cks"] and fid == 0x30, resp=resp)
        fr.src = "master"
        self.tx(fr)

    def tpls(self):
        return [Tpl("Window command", [P("c", "Command", "up", opts=["up", "down", "stop"])], lambda s, v, send: self._win(v, send), "Changes the data the master publishes in frame 0x10."),
                Tpl("Go to sleep (0x3C, D0 = 0)", [], lambda s, v, send: self._sleep(send), "Diagnostic master request with first byte 0x00 puts the cluster to sleep."),
                Tpl("Wake up", [], lambda s, v, send: self._wake(send), "Dominant pulse 250 us - 5 ms, then the master restarts its schedule.")]

    def _win(self, v, send):
        if send:
            self.by["win"].vars["Command"] = v["c"]
        return self.lin_frame(0x10, bytes([{"up": 1, "down": 2, "stop": 0}[v["c"]], 0]), "Window_Cmd", "cmd")

    def _sleep(self, send):
        fr = self.lin_frame(0x3C, bytes([0x00] + [0xFF] * 7), "MasterReq: GO TO SLEEP", "ctl")
        if send:
            self.tx(fr)
            self.asleep = True
            for n in self.nodes:
                n.state = "SLEEP"
        return fr

    def _wake(self, send):
        if send and self.asleep:
            self.asleep = False
            for n in self.nodes:
                n.state = ""
            b = Bld("LIN wake-up", "")

            def wf(fr):
                w = Wire(bit=1 / 19200.0)
                w.set("B", 0.0, 1)
                w.set("B", 0.0002, 0)
                w.set("B", 0.0012, 1)
                w.seg(0.0002, 0.0012, "WAKE-UP 1 ms dominant", 7, 1)
                w.end(0.002)
                return w
            self.tx(Frame(self.t, 0.002, "master", None, "LIN", "Wake-up pulse", pdu=b.done(), kind="ctl", wirefn=wf))
        return None


# ================================================================= FlexRay
class FlexRay(Scenario):
    key, name, cat = "flexray", "FlexRay", "auto"
    blurb = "Deterministic automotive communication"
    phy, rate = "flexray", 10e6
    medium = "ISO 17458 FlexRay, 10 Mbit/s dual channel A/B, 5 ms cycle: static segment 40 slots + dynamic segment, 4 nodes (2 cold-start)"
    nets = [("VDIFF", "channel A BP - BM"), ("BP", "channel A BP"), ("BM", "channel A BM"), ("VDIFF B", "channel B")]
    lines = ["F", "G"]
    faults = [("chB", "Channel B open circuit", "Dual channels: frames still arrive on channel A, the cluster keeps running."),
              ("drift", "Damper ECU clock out of tolerance", "Clock synchronisation cannot correct it: the node falls to POC passive and stops sending."),
              ("slot", "Two ECUs configured on static slot 5", "Both transmit in the same slot: the frames collide and receivers flag syntax/CRC errors."),
              ("cold", "Steering ECU (2nd cold-start node) unplugged", "At least two cold-start nodes are needed to start the cluster; after a restart it cannot integrate.")]
    spec = [("Standard", "ISO 17458 (FlexRay Consortium V2.1/V3.0)"), ("Physical", "Differential, 10 Mbit/s, two independent channels (A, B), bus or active star"),
            ("Access", "TDMA static segment (fixed slots) + FTDMA dynamic segment (minislots), repeating communication cycles 0-63"),
            ("Frame", "5-byte header (IDs, flags, length, header CRC-11, cycle count) + 0-254 byte payload + CRC-24"),
            ("Coding", "TSS, FSS, then each byte preceded by a byte start sequence (BSS); FES at the end"), ("Sync", "Distributed fault-tolerant clock synchronisation from sync frames")]
    frame = [["FlexRay frame", ("Flags", 5), ("Frame ID", 11), ("Payload len", 7), ("Header CRC", 11), ("Cycle", 6), ("Payload", "0-254 B"), ("CRC-24", 24)]]
    about = ("FlexRay was built for x-by-wire: every node owns fixed time slots in the static segment, so latency never varies, and everything can be "
             "sent on two channels for redundancy. Event-driven traffic uses the dynamic segment, where lower IDs get earlier minislots. A distributed "
             "clock synchronisation keeps all nodes aligned to the microtick.")
    guide = ["In FLOW, see the static slots repeat every 5 ms in the same order.",
             "Select a frame: header CRC-11, cycle count and payload length in 16-bit words.",
             "In LOGIC look for TSS, FSS and the BSS (1-0) before every byte.",
             "Open channel B and verify channel A still delivers."]

    def build(self):
        nodes = [self.node("brk", "BRAKE CTRL", "ecu", 40, 40, "slots 1, 21", "cold-start"), self.node("str", "STEERING", "ecu", 300, 40, "slots 2, 22", "cold-start"),
                 self.node("dmp", "DAMPER CTRL", "ecu", 560, 40, "slot 5"), self.node("gw", "GATEWAY", "gw", 300, 290, "slot 10 + dynamic")]
        nodes[3].at_top()
        self.trunk(190, 40, 860, nodes, "can", net="VDIFF", label="channel A (B runs in parallel)", t0=True, t1=True, drop_conn="dt", tlabel="100 Ω")
        self.seg([(40, 204), (860, 204)], "can", label="channel B", w=4, net="VDIFF B")
        self.user = "gw"
        self.cyc = 0
        self.slots = [(1, "brk", 16), (2, "str", 16), (5, "dmp", 8), (10, "gw", 32), (21, "brk", 16), (22, "str", 16)]
        self.by["brk"].vars.update({"Wheel torque Nm": 0})
        self.by["dmp"].vars.update({"POC state": "NORMAL ACTIVE"})
        self.every(0.005, self.cycle, 0.002)

    def hdr(self, fid, plen_words, cyc, sync, startup):
        bits = [0, 0, 0, 1 if sync else 0, 1 if startup else 0] + msb(fid, 11) + msb(plen_words, 7)
        hcrc = crc_bits(bits[3:5] + bits[5:23], 11, 0x385, 0x01A)
        return bits + msb(hcrc, 11) + msb(cyc, 6), hcrc

    def fr_frame(self, fid, node, payload, info, ch="AB", err=None, kind="data"):
        sync = fid in (1, 2)
        bits, hcrc = self.hdr(fid, len(payload) // 2, self.cyc, sync, sync)
        hb = bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, 40, 8))
        crcv = crcn("CRC-24/FLEXRAY-A", hb + payload)
        b = Bld("FlexRay frame (slot %d)" % fid, "")
        b.f("Header", hb, hb.hex(" "), "Indicators (reserved, payload preamble, null frame, sync, startup), frame ID, payload length, header CRC, cycle")
        b.note("Frame ID %d, payload %d words, sync %d, startup %d" % (fid, len(payload) // 2, sync, sync), "Frame ID = slot number in the static segment", d=2)
        b.note("Header CRC-11: 0x%03X, cycle count %d" % (hcrc, self.cyc), "CRC-11 over sync, startup, frame ID and length", d=2)
        b.raw("Payload", payload, None, "Signals (2-byte words)")
        b.u24("Frame CRC-24", crcv, "0x%06X (channel A init 0xFEDCBA)" % crcv, "CRC-24 over header and payload; the init value differs per channel")
        p = b.done()
        tb = 1e-7
        allb = hb + payload + crcv.to_bytes(3, "big")
        nbit = 6 + 1 + len(allb) * 10 + 2
        chB = self.fault["chB"]

        def wf(fr):
            w = Wire(bit=tb)
            for ln, on in (("F", "A" in ch), ("G", "B" in ch and not chB)):
                w.set(ln, 0.0, 2)
                if not on:
                    continue
                t = tb
                w.set(ln, t, 0)
                t += 6 * tb
                w.set(ln, t, 1)
                t += tb
                for i, byte in enumerate(allb):
                    t0 = t
                    w.set(ln, t, 1)
                    w.set(ln, t + tb, 0)
                    t += 2 * tb
                    for k_ in range(8):
                        w.set(ln, t, (byte >> (7 - k_)) & 1)
                        t += tb
                    if ln == "F":
                        w.seg(t0, t, "%02X" % byte, i % 2, 0)
                w.set(ln, t, 0)
                w.set(ln, t + tb, 1)
                w.set(ln, t + 2 * tb, 2)
            w.seg(tb, 7 * tb, "TSS", 8, 1)
            w.seg(8 * tb, (8 + 50) * tb, "HEADER id %d" % fid, 0, 1)
            w.seg((8 + 50) * tb, (8 + 50 + 10 * len(payload)) * tb, "PAYLOAD", 1, 1)
            w.seg((8 + 50 + 10 * len(payload)) * tb, (8 + 80 + 10 * len(payload)) * tb, "CRC-24", 2, 1)
            w.end((nbit + 3) * tb)
            return w
        return Frame(self.t, nbit * tb, node, None, "FlexRay", info, pdu=p, err=err, kind=kind, wirefn=wf, key="slot %d" % fid)

    def cycle(self):
        self.cyc = (self.cyc + 1) % 64
        t0 = self.t
        for slot, node, plen in self.slots:
            n = self.by[node]
            if not n.on:
                continue
            if node == "dmp" and self.fault["drift"]:
                n.vars["POC state"] = "NORMAL PASSIVE (clock out of tolerance)"
                n.state = "PASSIVE"
                continue
            if self.fault["cold"] and node == "str":
                continue
            payload = bytes((slot * 13 + self.cyc + i) & 255 for i in range(plen))
            err = "Slot collision: two transmitters in slot 5" if (slot == 5 and self.fault["slot"]) else None
            fr = self.fr_frame(slot, node, payload, "Static slot %d %s (cycle %d)%s" % (slot, n.label, self.cyc, "  [A only]" if self.fault["chB"] else ""), err=err)
            self.tx(fr, start=t0 + (slot - 1) * 50e-6)
        if self.cyc % 4 == 0:
            fr = self.fr_frame(60, "gw", b"\x01\x02\x03\x04", "Dynamic segment ID 60: diagnostics (cycle %d)" % self.cyc, ch="A", kind="ctl")
            self.tx(fr, start=t0 + 40 * 50e-6 + 0.0002)
        if not self.fault["drift"]:
            self.by["dmp"].vars["POC state"] = "NORMAL ACTIVE"
            self.by["dmp"].state = ""

    def on_fault(self, key, on):
        if key == "chB":
            self.segs[-1].broken = on
        if key == "cold":
            self.by["str"].on = not on

    def tpls(self):
        return [Tpl("Dynamic segment frame", [P("id", "Frame ID (> 40)", 50, 41, 2047), P("data", "Payload (hex)", "11 22 33 44")],
                    lambda s, v, send: (self.tx if send else (lambda f: f))(self.fr_frame(v["id"], "gw", hexdata(v["data"], 254).ljust(2 * ((len(hexdata(v["data"], 254)) + 1) // 2), b"\0"), "Dynamic ID %d" % v["id"], ch="A", kind="cmd")),
                    "Event-triggered message in the dynamic segment; lower IDs get earlier minislots.")]
