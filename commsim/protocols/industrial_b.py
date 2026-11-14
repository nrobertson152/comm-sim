"""Industrial automation, part B: PROFIBUS DP / PA, CANopen, DeviceNet,
ControlNet, IO-Link, AS-Interface and HART."""
import math
import struct
import numpy as np
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import sum8, xor8, crcn, lsb, msb, bytes_lsb, even_parity
from .fam import serial_frame, char_time
from .phys_b import CanNet, hexdata
from .. import phy

# ============================================================ PROFIBUS DP
SAP = {54: "Master-Master", 55: "Set_Slave_Add", 56: "Rd_Inp", 57: "Rd_Outp", 58: "Global_Control", 59: "Get_Cfg", 60: "Slave_Diag", 61: "Set_Prm", 62: "Chk_Cfg"}


def pb_telegram(da, sa, fc, data=b"", dsap=None, ssap=None, sd=None):
    """PROFIBUS FDL telegram bytes + dissection."""
    b = Bld("PROFIBUS FDL (IEC 61158 Type 3)", "Fieldbus Data Link: start delimiter, addresses, function code, data, FCS, end delimiter.")
    body = bytes([da | (0x80 if dsap is not None else 0), sa | (0x80 if ssap is not None else 0), fc]) + \
        (bytes([dsap]) if dsap is not None else b"") + (bytes([ssap]) if ssap is not None else b"") + data
    if sd is None:
        sd = 0x68 if (data or dsap is not None) and len(body) - 3 != 8 else (0xA2 if len(body) - 3 == 8 else 0x10)
    if sd == 0xDC:
        b.u8("SD4", 0xDC, "0xDC (token)", "Token frame: passes the right to send to the next master.")
        b.u8("DA", da, "%d" % da, "Next master (receives the token)")
        b.u8("SA", sa, "%d" % sa, "Current token holder")
        return b.done()
    if sd == 0xE5:
        b.u8("SC", 0xE5, "0xE5 (short acknowledgement)", "One-byte acknowledgement with no data.")
        return b.done()
    if sd == 0x68:
        b.u8("SD2", 0x68, "0x68 (variable length)", "Variable-length data telegram.")
        b.u8("LE", len(body), None, "Length of DA..data")
        b.u8("LEr", len(body), None, "Length repeated (protects the length field)")
        b.u8("SD2", 0x68, "0x68", "Start delimiter repeated")
    elif sd == 0xA2:
        b.u8("SD3", 0xA2, "0xA2 (8 data bytes)", "Fixed length telegram with 8 data bytes.")
    else:
        b.u8("SD1", 0x10, "0x10 (no data)", "Fixed length telegram without data.")
    b.u8("DA", body[0], "%d%s" % (da, " + SAP ext" if dsap is not None else ""), "Destination address; bit 7 set = a destination SAP byte follows.")
    b.u8("SA", body[1], "%d%s" % (sa, " + SAP ext" if ssap is not None else ""), "Source address; bit 7 set = a source SAP byte follows.")
    req = fc & 0x40
    fname = ({0x0C: "SRD low", 0x0D: "SRD high", 0x09: "Request FDL status", 0x03: "SDA low", 0x04: "SDN low", 0x06: "SDN high"}.get(fc & 0x0F, "%X" % (fc & 15))
             if req else {0x00: "ACK positive (OK)", 0x08: "DL (data low)", 0x0A: "DH (data high)", 0x02: "RR (no resources)", 0x01: "UE (user error)"}.get(fc & 0x0F, "%X" % (fc & 15)))
    b.u8("FC", fc, "0x%02X %s %s%s" % (fc, "request" if req else "response", fname, (" FCB=%d FCV=%d" % ((fc >> 5) & 1, (fc >> 4) & 1)) if req else ""),
         "Function code. Requests carry the frame count bit (FCB) toggled per new message so repeats can be detected.")
    if dsap is not None:
        b.u8("DSAP", dsap, "%d (%s)" % (dsap, SAP.get(dsap, "?")), "Destination service access point = which DP service.")
    if ssap is not None:
        b.u8("SSAP", ssap, "%d" % ssap, "Source SAP (62 for a class-1 master)")
    if data:
        b.raw("Data", data, None, "Service data / process image bytes")
    fcs = sum8(body)
    b.u8("FCS", fcs, "0x%02X [correct]" % fcs, "Frame check sequence: arithmetic sum of DA..data, modulo 256.")
    b.u8("ED", 0x16, "0x16", "End delimiter")
    return b.done()


class ProfibusDP(Scenario):
    key, name, cat = "profibus_dp", "PROFIBUS DP", "ind"
    blurb = "Distributed industrial I/O"
    phy, rate = "rs485", 1500000
    medium = "PROFIBUS DP-V0 on RS-485, 1.5 Mbit/s, purple cable, DB9 connectors with switchable termination, 1 master + 4 slaves, 4 ms constant bus cycle"
    nets = [("A", "line A (green)"), ("B", "line B (red)"), ("VDIFF", "B - A")]
    lines = ["D", "DE"]
    faults = [("no_term1", "Termination switch OFF in the last connector", "At 1.5 Mbit/s the unterminated end reflects strongly: telegram errors and retries."),
              ("ident", "Slave 6 has the wrong ident number (GSD mismatch)", "Set_Prm carries the configured ident number; the slave rejects it and reports Prm_Fault in its diagnosis."),
              ("cfg", "Slave 5 I/O configuration differs from the GSD", "Chk_Cfg is refused: Cfg_Fault, the slave never enters Data_Exchange."),
              ("off", "Slave 4 powered off", "No response: the master repeats (max_retry_limit) and marks the station as missing."),
              ("swap", "A/B swapped at slave 7", "That station receives inverted data and never answers.")]
    spec = [("Standard", "IEC 61158 / 61784 Type 3, EN 50170"), ("Physical", "RS-485, 9.6 kbit/s - 12 Mbit/s, max 32 stations per segment (126 with repeaters)"),
            ("Distance", "1200 m at <= 93.75 kbit/s, 200 m at 1.5 Mbit/s, 100 m at 12 Mbit/s"), ("Access", "Token passing between masters + master/slave polling"),
            ("Characters", "11-bit UART: start, 8 data, even parity, stop"), ("Telegrams", "SD1 0x10, SD2 0x68 (variable), SD3 0xA2, SD4 0xDC (token), SC 0xE5"),
            ("Start-up", "Slave_Diag -> Set_Prm -> Chk_Cfg -> Slave_Diag -> Data_Exchange"), ("Termination", "220 Ω across A-B + 390 Ω bias resistors to VP / DGND in the connector")]
    frame = [["SD2 telegram", ("SD2 68", 8), ("LE", 8), ("LEr", 8), ("SD2 68", 8), ("DA", 8), ("SA", 8), ("FC", 8), ("DSAP", 8), ("SSAP", 8), ("Data", "n x 8"), ("FCS", 8), ("ED 16", 8)]]
    about = ("PROFIBUS DP polls remote I/O at high speed on RS-485. The master first configures every slave: it reads the diagnosis, sends the "
             "parameters (with the device's ident number from its GSD file) and the expected I/O configuration; only when the slave accepts both does "
             "cyclic Data_Exchange start, writing outputs and reading inputs in one telegram pair. Masters share the bus by passing a token.")
    guide = ["Watch slave start-up in FLOW: Slave_Diag, Set_Prm, Chk_Cfg, Slave_Diag, then Data_Exchange.",
             "Select a Set_Prm telegram and find the ident number bytes.",
             "Inject the ident number fault: slave 6's diagnosis shows Prm_Fault.",
             "Turn the termination switch off and read the error count in STATS."]

    def build(self):
        m = self.node("m", "DP MASTER", "plc", 30, 40, "addr 2", "class 1")
        sl = [(4, "ET 200 I/O", "io", 200), (5, "VALVE ISLAND", "valve", 380), (6, "DRIVE", "drive", 560), (7, "HMI PANEL", "hmi", 740)]
        nodes = [m]
        for a, lab, kind, x in sl:
            n = self.node("s%d" % a, lab, kind, x - 30, 260, "addr %d" % a, "")
            n.at_top()
            n.vars.update({"State": "WAIT_PRM", "Ident": "0x%04X" % (0x8000 + a), "Diag": "-"})
            n.extra["addr"] = a
            nodes.append(n)
        self.trunk(180, 60, 850, nodes, "profibus", net="VDIFF", label="PROFIBUS cable 6XV1830 (purple), 1.5 Mbit/s", t0=True, t1=True, drop_conn="db9", tlabel="220 Ω + bias")
        self.user = "m"
        self.fcb = {}
        self.queue = []
        self.st = {a: "WAIT_PRM" for a, *_ in sl}
        self.by["s4"].vars["Inputs"] = 0x3C
        self.by["s4"].ctl = [("Inputs", "INPUTS", 0, 255, 1, lambda v: "0x%02X" % int(v))]
        self.by["m"].vars.update({"Stations OK": 0, "Retries": 0, "Bus cycle": "-"})
        self.every(0.004, self.cycle, 0.01)
        self.k = 0

    def cond(self, net):
        c = super().cond(net)
        if c["nterm"] < 2:
            c.update(refl=0.4, ringf=9e6, ringd=0.35e-6)
        return c

    def tel(self, src, dst, da, sa, fc, data=b"", dsap=None, ssap=None, sd=None, info="", kind="cmd", err=None):
        p = pb_telegram(da, sa, fc, data, dsap, ssap, sd)
        return serial_frame(self, src, dst, "PROFIBUS DP", info, p, 1500000, 8, "E", 1, rs485=2, kind=kind, err=err, key=info.split(" ")[0])

    def fc(self, a, high=True):
        self.fcb[a] = not self.fcb.get(a, False)
        return 0x40 | (0x20 if self.fcb[a] else 0) | 0x10 | (0x0D if high else 0x0C)

    def cycle(self):
        m = self.by["m"]
        if not m.on:
            return
        t0 = self.t
        self.tx(self.tel("m", None, 2, 2, 0, sd=0xDC, info="Token 2 -> 2 (single master)", kind="sync"))
        ok = 0
        for a in (4, 5, 6, 7):
            n = self.by["s%d" % a]
            st = self.st[a]
            dead = (not n.on) or (a == 7 and self.fault["swap"])
            err = "Telegram corrupted by reflections" if self.fault["no_term1"] and self.rng.random() < 0.25 else None
            if st == "WAIT_PRM":
                req = self.tel("m", n.id, a, 2, self.fc(a), b"", 60, 62, info="Slave_Diag req -> %d" % a, err=err)
                self.tx(req)
                if dead:
                    m.vars["Retries"] += 1
                    continue
                diag = bytes([0x02, 0x05, 0x00, 0xFF, 0x80, a])
                self.tx(self.tel(n.id, "m", 2, a, 0x08, diag, 62, 60, info="Slave_Diag res from %d: Prm_Req" % a, kind="resp"))
                prm = bytes([0x88, 0x01, 0x14, 0x0B]) + struct.pack(">H", 0x8000 + a) + bytes([0x00])
                self.tx(self.tel("m", n.id, a, 2, self.fc(a), prm, 61, 62, info="Set_Prm -> %d ident 0x%04X" % (a, 0x8000 + a)))
                if a == 6 and self.fault["ident"]:
                    self.tx(self.tel(n.id, "m", 2, a, 0x01, b"", sd=0xE5, info="SC from %d" % a, kind="ack"))
                    n.vars["Diag"] = "Prm_Fault (ident number mismatch)"
                    n.state = "PRM FAULT"
                    continue
                self.tx(self.tel(n.id, "m", 2, a, 0, sd=0xE5, info="SC (ack) from %d" % a, kind="ack"))
                cfg = bytes([0x31 if a == 4 else 0x20])
                self.tx(self.tel("m", n.id, a, 2, self.fc(a), cfg, 62, 62, info="Chk_Cfg -> %d cfg 0x%02X" % (a, cfg[0])))
                if a == 5 and self.fault["cfg"]:
                    n.vars["Diag"] = "Cfg_Fault (configuration differs from GSD)"
                    n.state = "CFG FAULT"
                    continue
                self.tx(self.tel(n.id, "m", 2, a, 0, sd=0xE5, info="SC (ack) from %d" % a, kind="ack"))
                self.st[a] = "DATA_EXCH"
                n.vars["State"] = "DATA_EXCH"
                n.vars["Diag"] = "OK"
                n.state = "DATA_EXCH"
            else:
                outs = bytes([int(self.t * 20) & 255])
                self.tx(self.tel("m", n.id, a, 2, self.fc(a), outs, info="Data_Exchange -> %d out %s" % (a, outs.hex().upper()), err=err))
                if dead:
                    m.vars["Retries"] += 1
                    self.st[a] = "WAIT_PRM"
                    n.vars["State"] = "MISSING"
                    n.state = "NO RESPONSE"
                    continue
                ins = bytes([int(n.vars.get("Inputs", a * 3)) & 255, a])
                self.tx(self.tel(n.id, "m", 2, a, 0x08, ins, info="Data_Exchange res %d in %s" % (a, ins.hex().upper()), kind="resp", err=err))
                ok += 1
        m.vars["Stations OK"] = ok
        m.vars["Bus cycle"] = "%.2f ms" % ((self.free.get("bus", self.t) - t0) * 1000)

    def on_fault(self, key, on):
        if key == "off":
            self.by["s4"].on = not on
        if not on:
            for a in self.st:
                if self.st[a] != "DATA_EXCH":
                    self.st[a] = "WAIT_PRM"

    def tpls(self):
        return [Tpl("Slave_Diag request", [P("a", "Slave address", 5, 1, 125)], lambda s, v, send: (self.tx if send else (lambda f: f))(
            self.tel("m", "s%d" % v["a"] if "s%d" % v["a"] in self.by else None, v["a"], 2, 0x5D, b"", 60, 62, info="Slave_Diag req -> %d" % v["a"])),
            "SAP 60: read the station's diagnosis (6 standard bytes + extended)."),
                Tpl("Request FDL status", [P("a", "Address", 3, 1, 126)], lambda s, v, send: (self.tx if send else (lambda f: f))(
                    self.tel("m", None, v["a"], 2, 0x49, info="FDL status? -> %d" % v["a"])), "Used by masters to find other masters in the GAP range.")]


# ============================================================ PROFIBUS PA
class ProfibusPA(Scenario):
    key, name, cat = "profibus_pa", "PROFIBUS PA", "ind"
    blurb = "Process instrumentation"
    phy, rate = "ffpa", 31250
    medium = "MBP (IEC 61158-2): 31.25 kbit/s Manchester, bus-powered, DP/PA coupler, 3 instruments on a trunk with spurs"
    nets = [("BUS AC", "bus signal (AC coupled)"), ("BUS DC", "bus voltage")]
    lines = ["M"]
    faults = [("budget", "Six more devices added to the segment", "Each device draws ~12-15 mA from the coupler; beyond its output current the voltage collapses."),
              ("short", "Short circuit on the level transmitter spur", "The junction box short-circuit protection isolates that spur; the device disappears from the segment."),
              ("no_term1", "Terminator missing at the field end", "MBP needs RC terminators (100 Ω + 1 µF) at both trunk ends: without one the signal amplitude doubles and reflects."),
              ("water", "Water in a junction box", "Leakage and noise add jitter: CRC-equivalent FCS errors.")]
    spec = [("Standard", "IEC 61158-2 MBP (Manchester Bus Powered), PROFIBUS PA profile 3.02"), ("Signalling", "31.25 kbit/s Manchester as +/-9 mA current modulation on the DC supply"),
            ("Power", "Devices powered over the two signal wires (typ. 10-20 mA each)"), ("Intrinsic safety", "FISCO / Ex ia for hazardous areas"),
            ("Length", "Up to 1900 m trunk + spurs (less in Ex zones)"), ("Coupling", "DP/PA coupler or link converts to PROFIBUS DP"),
            ("Data", "Each AI value = IEEE float + status byte (0x80 = good)")]
    frame = [["MBP frame", ("Preamble 55", 8), ("Start delim (N+ N-)", 8), ("FDL telegram", "n x 8"), ("End delim", 8)], ["AI value", ("Value IEEE float", 32), ("Status", 8)]]
    about = ("PROFIBUS PA runs the PROFIBUS protocol over a slow, robust physical layer that also powers the instruments: each device draws a "
             "constant current and signals by modulating it +/-9 mA. Manchester coding keeps the average current constant so the data never disturbs "
             "the supply. A coupler joins the PA segment to the fast DP network; each measured value travels with a status byte.")
    guide = ["Probe BUS DC: about 19 V with a small Manchester ripple; BUS AC shows the +/-0.45 V signal.",
             "Select a Data_Exchange response: 4-byte float + status 0x80 (good).",
             "Add the six extra devices and read the current budget in the coupler's DEVICE panel.",
             "Short the level transmitter spur and see it vanish."]

    def build(self):
        cp = self.node("cp", "DP/PA COUPLER", "coupler", 30, 40, "DP 45.45k / PA 31.25k", "100 mA out")
        devs = [(21, "PRESSURE XMTR", "pressure", 230), (22, "LEVEL XMTR", "sensor", 470), (23, "VALVE POSITIONER", "valve", 700)]
        nodes = [cp]
        for a, lab, kind, x in devs:
            n = self.node("d%d" % a, lab, kind, x - 30, 260, "addr %d" % a, "PA profile 3.02")
            n.at_top()
            n.vars.update({"PV": {21: 4.52, 22: 1.83, 23: 37.0}[a], "Units": {21: "bar", 22: "m", 23: "%"}[a], "Status": "0x80 GOOD", "Current": "13 mA"})
            n.ctl = [("PV", "PV", 0.0, 100.0 if a == 23 else 10.0, 0, lambda v: "%.2f" % v)]
            nodes.append(n)
        self.trunk(180, 60, 850, nodes, "profibus", net="BUS AC", label="PA trunk (blue Ex cable), 31.25 kbit/s", t0=True, t1=True, drop_conn="m12", tlabel="RC 100Ω+1µF")
        self.user = "cp"
        self.every(0.12, self.cycle, 0.01)

    def budget(self):
        n = sum(1 for d in ("d21", "d22", "d23") if self.by[d].on and not (d == "d22" and self.fault["short"])) + (6 if self.fault["budget"] else 0)
        return n, n * 13.0

    def inspect(self, n):
        rows = list(n.vars.items())
        if n.id == "cp":
            k, ma = self.budget()
            rows = [("Devices on segment", k), ("Current demand", "%.0f mA of 100 mA" % ma), ("Bus voltage", "%.1f V" % (19.0 if ma <= 100 else 19.0 - (ma - 100) * 0.12)),
                    ("Segment", "OK" if ma <= 100 else "OVERLOAD - voltage collapsed")]
        return rows

    def pa(self, src, dst, tel, info, kind, err=None):
        data = tel.b
        tb = 1.0 / 31250
        n = 8 + 8 + 8 * len(data) + 8
        b = Bld("MBP physical frame", "IEC 61158-2 Manchester frame wrapping the PROFIBUS telegram.")
        b.u8("Preamble", 0x55, "0x55", "Lets receivers synchronise")
        b.u8("Start delimiter", 0x00, "N+ N- code violations", "Manchester code violations mark the start")
        b.sub(tel)
        b.u8("End delimiter", 0x00, "N- N+", "")

        def wf(fr):
            w = Wire(bit=tb)
            w.set("M", 0.0, 2)
            t = tb
            t = w.manch("M", [0, 1, 0, 1, 0, 1, 0, 1], t, tb, 1)
            w.seg(tb, t, "PREAMBLE", 7, 1)
            t0 = t
            for lvl in (1, 1, 0, 1, 0, 0, 1, 0):
                w.set("M", t, lvl)
                t += tb / 2
                w.set("M", t, lvl)
                t += tb / 2
            w.seg(t0, t, "START (N+N-)", 2, 1)
            for i, byte in enumerate(data):
                a = t
                t = w.manch("M", lsb(byte, 8), t, tb, 1)
                w.seg(a, t, "%02X" % byte, i % 2, 0)
            w.seg(t0 + 8 * tb, t, info.split(":")[0], 1, 1)
            w.set("M", t, 2)
            w.end(t + 2 * tb)
            return w
        return Frame(self.t, n * tb, src, dst, "PROFIBUS PA", info, pdu=b.done(), kind=kind, err=err, wirefn=wf, key=info.split(" ")[0])

    def cycle(self):
        k, ma = self.budget()
        for a in (21, 22, 23):
            d = self.by["d%d" % a]
            err = None
            if ma > 100:
                err = "Segment overload: bus voltage below device minimum"
            elif self.fault["water"] and self.rng.random() < 0.3:
                err = "FCS error: jitter from water ingress"
            elif self.fault["no_term1"] and self.rng.random() < 0.2:
                err = "FCS error: reflections (terminator missing)"
            self.tx(self.pa("cp", d.id, pb_telegram(a, 2, 0x7D, b"\x00"), "Data_Exchange -> %d" % a, "cmd", err))
            if not d.on or (a == 22 and self.fault["short"]) or ma > 100:
                d.state = "NOT ON SEGMENT"
                continue
            d.state = "OK"
            val = struct.pack(">f", d.vars["PV"]) + b"\x80"
            self.tx(self.pa(d.id, "cp", pb_telegram(2, a, 0x08, val), "Data_Exchange res %d: %.3f %s status 0x80" % (a, d.vars["PV"], d.vars["Units"]), "resp", err))
            self.at(self.t, lambda: None)

    def cond(self, net):
        c = super().cond(net)
        if c["nterm"] < 2:
            c.update(atten=1.9, refl=0.3, ringf=4e5, ringd=6e-6)
        if self.fault["water"]:
            c["noise"] = 0.05
        return c

    def tpls(self):
        return [Tpl("Read AI OUT", [P("a", "Device", 21, opts=[21, 22, 23])], lambda s, v, send: (self.tx if send else (lambda f: f))(
            self.pa("cp", "d%d" % v["a"], pb_telegram(v["a"], 2, 0x7D, b"\x00"), "Data_Exchange -> %d" % v["a"], "cmd")), "Cyclic read of the AI block output (float + status).")]


# ================================================================ CANopen
NMT_CMD = {0x01: "Start remote node", 0x02: "Stop remote node", 0x80: "Enter pre-operational", 0x81: "Reset node", 0x82: "Reset communication"}
HB_ST = {0x00: "Boot-up", 0x04: "Stopped", 0x05: "Operational", 0x7F: "Pre-operational"}
SDO_ABORT = {0x06020000: "Object does not exist in the object dictionary", 0x06090011: "Sub-index does not exist", 0x06010002: "Attempt to write a read only object",
             0x05040001: "Client/server command specifier not valid", 0x08000020: "Data cannot be transferred or stored to the application"}


def cob_name(cid):
    fn, nid = cid & 0x780, cid & 0x7F
    if cid == 0:
        return "NMT"
    if cid == 0x80:
        return "SYNC"
    return {0x080: "EMCY", 0x180: "TPDO1", 0x200: "RPDO1", 0x280: "TPDO2", 0x300: "RPDO2", 0x380: "TPDO3", 0x400: "RPDO3", 0x580: "SDO tx",
            0x600: "SDO rx", 0x700: "NMT EC (heartbeat)"}.get(fn, "COB 0x%03X" % cid) + (" node %d" % nid if nid else "")


class CANopen(CanNet):
    key, name, cat = "canopen", "CANopen", "ind"
    blurb = "Industrial CAN-based devices"
    rate = 500000
    can_proto = "CANopen"
    medium = "CiA 301 CANopen at 500 kbit/s: NMT master, I/O module (CiA 401), servo drive (CiA 402), encoder (CiA 406)"
    faults = [("dupid", "Encoder also set to node-ID 3", "Two devices with one node-ID send identical COB-IDs with different data: error frames, broken SDO replies."),
              ("hb", "Encoder heartbeat lost (cable pulled)", "The master's heartbeat consumer times out (1.5 x producer time) and reacts (here: logs and sets the drive to quick stop)."),
              ("oc", "Drive overcurrent", "The drive sends an EMCY (0x2310) and enters FAULT; statusword 0x0218."),
              ("pdo", "RPDO1 to the drive one byte short", "Length mismatch: the drive ignores the PDO and sends EMCY 0x8210 (PDO not processed due to length error)."),
              ("no_term1", "Terminator missing (right end)", "Termination fault, as for any CAN network.")]
    spec = [("Standard", "CiA 301 (application layer), CiA 401/402/406... device profiles, EN 50325-4"), ("Bus", "Classical CAN, 10 kbit/s - 1 Mbit/s, 127 nodes"),
            ("COB-ID", "Function code (4 bits) + node-ID (7 bits) = 11-bit CAN identifier"), ("Services", "NMT, SYNC, EMCY, PDO (real-time), SDO (object dictionary access), heartbeat"),
            ("Object dictionary", "16-bit index + 8-bit sub-index; 0x1000-0x1FFF communication, 0x6000+ device profile"),
            ("States", "Initialisation -> Pre-operational -> Operational / Stopped")]
    frame = [["COB-ID", ("Function code", 4), ("Node-ID", 7)], ["Expedited SDO", ("Command", 8), ("Index LE", 16), ("Sub", 8), ("Data", 32)],
             ["Heartbeat", ("State", 8)]]
    about = ("CANopen gives CAN a standard application layer. Every device has an object dictionary of numbered parameters; SDOs read and write it "
             "with a confirmed request/response, while PDOs carry live process data with no overhead, triggered by the SYNC message. The NMT master starts "
             "and stops nodes, and every node proves it is alive with a heartbeat. Device profiles such as CiA 402 define what the drive objects mean.")
    guide = ["Watch the boot-up messages (0x700 + node) and the NMT start command in FLOW.",
             "Select an SDO reply: index 0x1000 device type, expedited 4 bytes, little-endian.",
             "Use COMPOSE to walk the drive state machine: controlword 0x06, 0x07, 0x0F; watch the statusword.",
             "Pull the encoder's heartbeat and see the master react.",
             "Try an SDO upload of index 0x2FFF: SDO abort 0x06020000."]

    def setup(self):
        nodes = [self.node("m", "NMT MASTER", "plc", 40, 60, "node 1", "PLC"), self.node("io", "I/O MODULE", "io", 300, 60, "node 2", "CiA 401"),
                 self.node("drv", "SERVO DRIVE", "servo", 560, 60, "node 3", "CiA 402"), self.node("enc", "ENCODER", "sensor", 300, 290, "node 4", "CiA 406"),
                 self.node("tool", "CAN TOOL", "tool", 600, 290, "PC")]
        for n in nodes[3:]:
            n.at_top()
        self.can_trunk(nodes, 200)
        self.user = "m"
        self.nid = {"m": 1, "io": 2, "drv": 3, "enc": 4}
        self.nmt = {"io": 0, "drv": 0, "enc": 0}
        self.od = {
            "io": {(0x1000, 0): 0x00030191, (0x1001, 0): 0, (0x1008, 0): "IO-16DI16DO", (0x1017, 0): 100, (0x1018, 1): 0x0000ABCD, (0x6000, 1): 0x5A, (0x6200, 1): 0x00},
            "drv": {(0x1000, 0): 0x00020192, (0x1001, 0): 0, (0x1008, 0): "SERVO-402", (0x1017, 0): 100, (0x1018, 1): 0x0000ABCD, (0x6040, 0): 0, (0x6041, 0): 0x0240,
                    (0x6060, 0): 3, (0x6064, 0): 0, (0x606C, 0): 0, (0x60FF, 0): 0},
            "enc": {(0x1000, 0): 0x00010196, (0x1001, 0): 0, (0x1008, 0): "ENC-406", (0x1017, 0): 100, (0x1018, 1): 0x0000ABCD, (0x6004, 0): 0}}
        self.ro = {(0x1000, 0), (0x1008, 0), (0x1018, 1), (0x6041, 0), (0x6064, 0), (0x606C, 0), (0x6004, 0), (0x6000, 1)}
        self.by["drv"].vars.update({"State": "SWITCH ON DISABLED", "Statusword": "0x0240", "Velocity": 0})
        self.by["enc"].vars.update({"Position": 0})
        self.by["io"].vars.update({"Inputs": 0x5A, "Outputs": 0})
        self.by["io"].ctl = [("Inputs", "INPUTS", 0, 255, 1, lambda v: "0x%02X" % int(v))]
        self.last_hb = {"io": 0.0, "drv": 0.0, "enc": 0.0}
        self.at(0.01, self.boot)
        self.every(0.1, self.heartbeats, 0.2)
        self.every(0.01, self.sync, 0.3)

    def send(self, src, cid, data, info=None, kind="data", on_tx=None):
        nm = cob_name(cid)

        def dis(b, off, cid=cid, data=bytes(data)):
            self.dissect(b, off, cid, data)
        self.bus.send(src, cid, data, info=info or nm, kind=kind, key=nm.split(" node")[0] + (" %d" % (cid & 0x7F) if cid & 0x7F else ""), on_tx=on_tx,
                      dissect=dis, idrows=lambda b, o, cid=cid: b.note("COB-ID 0x%03X = function code 0x%X (%s), node-ID %d" % (cid, cid >> 7, cob_name(cid).split(" node")[0], cid & 0x7F),
                                                                       "Predefined connection set: COB-ID = function code x 128 + node-ID.", d=1))

    def dissect(self, b, off, cid, data):
        fn = cid & 0x780
        L = len(data)
        if cid == 0 and L >= 2:
            b.rows.append([0, "CANopen NMT", off, 2, "Network management command from the master"])
            b.rows.append([1, "Command: 0x%02X %s" % (data[0], NMT_CMD.get(data[0], "?")), off, 1, ""])
            b.rows.append([1, "Node: %d%s" % (data[1], " (all nodes)" if data[1] == 0 else ""), off + 1, 1, ""])
        elif fn == 0x700:
            b.rows.append([0, "CANopen NMT error control (heartbeat)", off, L, "Producer heartbeat: proves the node is alive and shows its NMT state"])
            if L:
                b.rows.append([1, "State: 0x%02X %s" % (data[0], HB_ST.get(data[0] & 0x7F, "?")), off, 1, ""])
        elif fn in (0x580, 0x600) and L == 8:
            cs = data[0]
            idx = data[1] | (data[2] << 8)
            b.rows.append([0, "CANopen SDO %s" % ("request (client -> server)" if fn == 0x600 else "response"), off, 8, "Service Data Object: confirmed access to the object dictionary"])
            nm = {0x40: "Initiate upload (read) request", 0x43: "Upload response, expedited 4 bytes", 0x47: "Upload response, 3 bytes", 0x4B: "Upload response, expedited 2 bytes",
                  0x4F: "Upload response, expedited 1 byte", 0x23: "Download (write) expedited 4 bytes", 0x2B: "Download expedited 2 bytes", 0x2F: "Download expedited 1 byte",
                  0x60: "Download response (OK)", 0x80: "ABORT", 0x41: "Upload response, segmented (size indicated)"}.get(cs, "cs 0x%02X" % cs)
            b.rows.append([1, "Command specifier: 0x%02X %s" % (cs, nm), off, 1, "ccs/scs + e (expedited) + s (size) + n (unused bytes)"])
            b.rows.append([1, "Index: 0x%04X  Sub-index: %d" % (idx, data[3]), off + 1, 3, "Object dictionary address, index little-endian"])
            val = struct.unpack("<I", bytes(data[4:8]))[0]
            if cs == 0x80:
                b.rows.append([1, "Abort code: 0x%08X %s" % (val, SDO_ABORT.get(val, "")), off + 4, 4, ""])
            else:
                b.rows.append([1, "Data: 0x%08X (%d)" % (val, val), off + 4, 4, "Little-endian value"])
        elif fn == 0x080 and cid != 0x80 and L:
            code = data[0] | (data[1] << 8)
            b.rows.append([0, "CANopen EMCY", off, L, "Emergency object: sent once when an error occurs (and again with code 0 when cleared)"])
            b.rows.append([1, "Error code: 0x%04X %s" % (code, {0x2310: "current at outputs too high", 0x8210: "PDO not processed due to length error", 0x0000: "error reset / no error",
                                                               0x8130: "life guard / heartbeat error", 0x4210: "temperature too high"}.get(code, "")), off, 2, ""])
            if L > 2:
                b.rows.append([1, "Error register (0x1001): 0x%02X" % data[2], off + 2, 1, "bit0 generic, bit1 current, bit2 voltage, bit3 temperature, bit4 communication"])
        elif cid == 0x80:
            b.rows.append([0, "CANopen SYNC", off, L, "Synchronisation: synchronous PDOs are sampled / applied when SYNC arrives"])
        elif fn in (0x180, 0x200, 0x280, 0x300):
            b.rows.append([0, "CANopen %s" % cob_name(cid), off, L, "Process Data Object: no protocol overhead, content defined by the PDO mapping parameters"])
            node = {2: "io", 3: "drv", 4: "enc"}.get(cid & 0x7F)
            if node == "drv" and fn == 0x180 and L >= 6:
                b.rows.append([1, "Statusword (0x6041): 0x%04X" % (data[0] | data[1] << 8), off, 2, "CiA 402 state bits"])
                b.rows.append([1, "Velocity actual (0x606C): %d" % struct.unpack("<i", bytes(data[2:6]))[0], off + 2, 4, ""])
            elif node == "drv" and fn == 0x200 and L >= 2:
                b.rows.append([1, "Controlword (0x6040): 0x%04X" % (data[0] | data[1] << 8), off, 2, "0x06 shutdown, 0x07 switch on, 0x0F enable operation, 0x80 fault reset"])
                if L >= 6:
                    b.rows.append([1, "Target velocity (0x60FF): %d" % struct.unpack("<i", bytes(data[2:6]))[0], off + 2, 4, ""])
            elif node == "enc" and L >= 4:
                b.rows.append([1, "Position value (0x6004): %d" % struct.unpack("<I", bytes(data[0:4]))[0], off, 4, ""])
            elif node == "io" and L >= 1:
                b.rows.append([1, "Digital %s (0x%04X): 0x%02X" % ("inputs" if fn == 0x180 else "outputs", 0x6000 if fn == 0x180 else 0x6200, data[0]), off, 1, ""])

    def boot(self):
        self.send("m", 0x000, bytes([0x82, 0]), "NMT Reset communication (all)", "cmd")
        for i, d in enumerate(("io", "drv", "enc")):
            self.at(self.t + 0.002 + i * 0.0005, lambda d=d: self.boot_msg(d))
        for i, d in enumerate(("io", "drv", "enc")):
            self.at(self.t + 0.01 + i * 0.002, lambda d=d: self.sdo_read(d, 0x1000, 0))
        self.at(self.t + 0.03, lambda: self.nmt_cmd(0x01, 0))

    def boot_msg(self, d):
        if not self.by[d].on:
            return
        self.nmt[d] = 0x7F
        self.send(d, 0x700 + self.nid[d], b"\x00", "Boot-up node %d" % self.nid[d], "evt")
        if d == "enc" and self.fault["dupid"]:
            self.send(d, 0x700 + 3, b"\x00", "Boot-up node 3 (duplicate!)", "evt")

    def nmt_cmd(self, cmd, node):
        self.send("m", 0x000, bytes([cmd, node]), "NMT %s node %s" % (NMT_CMD.get(cmd, "?"), node or "all"), "cmd")
        for d, nid in self.nid.items():
            if d == "m" or (node and node != nid):
                continue
            self.nmt[d] = {0x01: 0x05, 0x02: 0x04, 0x80: 0x7F}.get(cmd, self.nmt[d])
            if cmd in (0x81, 0x82):
                self.at(self.t + 0.002, self.boot_msg, d)
            self.by[d].state = HB_ST.get(self.nmt[d], "")

    def sdo_read(self, d, idx, sub):
        nid = self.nid.get(d, 0)
        self.send("m", 0x600 + nid, bytes([0x40, idx & 255, idx >> 8, sub, 0, 0, 0, 0]), "SDO upload req node %d 0x%04X:%d" % (nid, idx, sub), "cmd",
                  on_tx=lambda fr: self.at(fr.t + fr.dur + 0.0004, self.sdo_reply, d, idx, sub, None))

    def sdo_write(self, d, idx, sub, val, size=4):
        nid = self.nid.get(d, 0)
        cs = {4: 0x23, 2: 0x2B, 1: 0x2F}[size]
        self.send("m", 0x600 + nid, bytes([cs, idx & 255, idx >> 8, sub]) + struct.pack("<I", val & 0xFFFFFFFF), "SDO download req node %d 0x%04X:%d = %d" % (nid, idx, sub, val), "cmd",
                  on_tx=lambda fr: self.at(fr.t + fr.dur + 0.0004, self.sdo_reply, d, idx, sub, val))

    def sdo_reply(self, d, idx, sub, val):
        if d not in self.od or not self.by[d].on:
            return
        od = self.od[d]
        nid = self.nid[d]
        if (idx, sub) not in od:
            ab = 0x06020000 if not any(k[0] == idx for k in od) else 0x06090011
            self.send(d, 0x580 + nid, bytes([0x80, idx & 255, idx >> 8, sub]) + struct.pack("<I", ab), "SDO ABORT 0x%08X" % ab, "err")
            return
        if val is None:
            v = od[(idx, sub)]
            if isinstance(v, str):
                raw = v.encode()[:4]
                self.send(d, 0x580 + nid, bytes([0x43, idx & 255, idx >> 8, sub]) + raw.ljust(4, b"\0"), "SDO upload res 0x%04X '%s...'" % (idx, v[:4]), "resp")
            else:
                self.send(d, 0x580 + nid, bytes([0x43, idx & 255, idx >> 8, sub]) + struct.pack("<I", int(v) & 0xFFFFFFFF), "SDO upload res 0x%04X:%d = 0x%X" % (idx, sub, int(v)), "resp")
        else:
            if (idx, sub) in self.ro:
                self.send(d, 0x580 + nid, bytes([0x80, idx & 255, idx >> 8, sub]) + struct.pack("<I", 0x06010002), "SDO ABORT read-only", "err")
                return
            od[(idx, sub)] = val
            if d == "drv" and idx == 0x6040:
                self.cw(val)
            self.send(d, 0x580 + nid, bytes([0x60, idx & 255, idx >> 8, sub, 0, 0, 0, 0]), "SDO download res OK", "resp")

    def cw(self, cw):
        od = self.od["drv"]
        sw = od[(0x6041, 0)]
        st = self.by["drv"].vars["State"]
        if self.fault["oc"] and st != "FAULT":
            pass
        if cw & 0x80:
            st, sw = "SWITCH ON DISABLED", 0x0240
        elif st == "FAULT":
            pass
        elif cw & 0x0F == 0x06:
            st, sw = "READY TO SWITCH ON", 0x0221
        elif cw & 0x0F == 0x07 and st in ("READY TO SWITCH ON", "OPERATION ENABLED"):
            st, sw = "SWITCHED ON", 0x0233
        elif cw & 0x0F == 0x0F and st in ("SWITCHED ON", "OPERATION ENABLED"):
            st, sw = "OPERATION ENABLED", 0x0237
        od[(0x6041, 0)] = sw
        self.by["drv"].vars.update({"State": st, "Statusword": "0x%04X" % sw})

    def heartbeats(self):
        for d in ("io", "drv", "enc"):
            n = self.by[d]
            if not n.on or (d == "enc" and self.fault["hb"]):
                if self.t - self.last_hb[d] > 0.15 and self.nmt.get(d) != -1:
                    self.log("Heartbeat timeout node %d" % self.nid[d])
                    n.state = "HEARTBEAT LOST"
                    self.nmt[d] = -1
                continue
            if self.nmt.get(d, 0) == -1:
                self.nmt[d] = 0x7F
            self.send(d, 0x700 + self.nid[d], bytes([self.nmt.get(d, 0x7F) & 0x7F]), "Heartbeat node %d: %s" % (self.nid[d], HB_ST.get(self.nmt.get(d, 0x7F) & 0x7F, "?")), "sync")
            self.last_hb[d] = self.t
            if d == "enc" and self.fault["dupid"]:
                self.send(d, 0x703, b"\x05", "Heartbeat node 3 (duplicate ID!)", "err")

    def sync(self):
        if not self.by["m"].on:
            return
        self.send("m", 0x080, b"", "SYNC", "sync")
        od = self.od["drv"]
        if self.nmt.get("drv") == 0x05:
            st = self.by["drv"].vars["State"]
            if self.fault["oc"] and st != "FAULT":
                self.by["drv"].vars.update({"State": "FAULT", "Statusword": "0x0218"})
                od[(0x6041, 0)] = 0x0218
                self.send("drv", 0x083, bytes([0x10, 0x23, 0x03, 0, 0, 0, 0, 0]), "EMCY node 3: 0x2310 overcurrent", "evt")
            tv = int(1000 * math.sin(self.t)) if st == "OPERATION ENABLED" else 0
            data = struct.pack("<Hi", od[(0x6040, 0)] | (0x000F if st == "OPERATION ENABLED" else 0), tv)
            if self.fault["pdo"]:
                data = data[:5]
            self.send("m", 0x203, data, "RPDO1 node 3: controlword + target velocity", "cmd")
            if self.fault["pdo"] and self.rng.random() < 0.1:
                self.send("drv", 0x083, bytes([0x10, 0x82, 0x10, 0, 0, 0, 0, 0]), "EMCY node 3: 0x8210 PDO length error", "evt")
            if st == "OPERATION ENABLED" and not self.fault["pdo"]:
                od[(0x606C, 0)] = int(od[(0x606C, 0)] + (tv - od[(0x606C, 0)]) * 0.3)
            self.by["drv"].vars["Velocity"] = od[(0x606C, 0)]
            self.send("drv", 0x183, struct.pack("<Hi", od[(0x6041, 0)], od[(0x606C, 0)]), "TPDO1 node 3: statusword 0x%04X vel %d" % (od[(0x6041, 0)], od[(0x606C, 0)]))
        if self.nmt.get("enc") == 0x05 and self.by["enc"].on and not self.fault["hb"]:
            self.od["enc"][(0x6004, 0)] = (self.od["enc"][(0x6004, 0)] + 37) & 0xFFFFFF
            self.by["enc"].vars["Position"] = self.od["enc"][(0x6004, 0)]
            self.send("enc", 0x184, struct.pack("<I", self.od["enc"][(0x6004, 0)]), "TPDO1 node 4: position %d" % self.od["enc"][(0x6004, 0)])
        if self.nmt.get("io") == 0x05 and int(self.t * 100) % 5 == 0:
            self.send("io", 0x182, bytes([int(self.by["io"].vars["Inputs"]) & 255]), "TPDO1 node 2: inputs 0x%02X" % int(self.by["io"].vars["Inputs"]))

    def can_fault(self, key, on):
        if key == "dupid":
            self.by["enc"].addr = "node 3 (!)" if on else "node 4"
        if key == "oc" and not on:
            self.cw(0x80)

    def tpls(self):
        devs = ["io", "drv", "enc"]
        return [Tpl("NMT command", [P("cmd", "Command", 0x01, opts=[0x01, 0x02, 0x80, 0x81, 0x82], fmt=lambda v: "0x%02X %s" % (v, NMT_CMD[v])), P("node", "Node (0 = all)", 0, 0, 127)],
                    lambda s, v, send: self.nmt_cmd(v["cmd"], v["node"]) if send else self.preview_can("m", 0, bytes([v["cmd"], v["node"]])), "Start, stop, pre-operational or reset nodes."),
                Tpl("SDO upload (read)", [P("d", "Node", "drv", opts=devs), P("idx", "Index", 0x1008, 0, 0xFFFF, fmt=lambda v: "0x%04X" % v), P("sub", "Sub-index", 0, 0, 255)],
                    lambda s, v, send: self.sdo_read(v["d"], v["idx"], v["sub"]) if send else self.preview_can("m", 0x600 + self.nid[v["d"]], bytes([0x40, v["idx"] & 255, v["idx"] >> 8, v["sub"], 0, 0, 0, 0])),
                    "0x1000 device type, 0x1008 name, 0x1017 heartbeat time, 0x1018:1 vendor ID, 0x6041 statusword."),
                Tpl("SDO download (write)", [P("d", "Node", "drv", opts=devs), P("idx", "Index", 0x6040, 0, 0xFFFF, fmt=lambda v: "0x%04X" % v), P("sub", "Sub-index", 0, 0, 255),
                                             P("val", "Value", 6, 0, 0xFFFFFFFF), P("sz", "Size", 2, opts=[1, 2, 4])],
                    lambda s, v, send: self.sdo_write(v["d"], v["idx"], v["sub"], v["val"], v["sz"]) if send else self.preview_can("m", 0x600 + self.nid[v["d"]], bytes([0x2B, v["idx"] & 255, v["idx"] >> 8, v["sub"]]) + struct.pack("<I", v["val"])),
                    "Drive controlword 0x6040: 6 shutdown, 7 switch on, 15 enable operation, 128 fault reset.")]


# ================================================================ DeviceNet
class DeviceNet(CanNet):
    key, name, cat = "devicenet", "DeviceNet", "ind"
    blurb = "CAN-based industrial networking"
    rate = 500000
    can_proto = "DeviceNet"
    medium = "ODVA DeviceNet at 500 kbit/s: trunk + drop cable carrying CAN and 24 V, scanner + 3 devices, polled I/O"
    faults = [("dup", "Starter set to MAC ID 20 (same as the VFD)", "At power-up each device sends Duplicate MAC ID checks; the second device sees a reply and goes off-line (NS LED solid red)."),
              ("volts", "Long thin trunk: 24 V drops below 11 V at the VFD", "DeviceNet needs 11-25 V at every node; brown-outs make the device reset."),
              ("no_term1", "121 Ω terminator missing", "As for any CAN network."),
              ("off", "Photo-eye unplugged", "The scanner's polled connection times out (expected packet rate x 4).")]
    spec = [("Standard", "ODVA DeviceNet (CIP over CAN), IEC 62026-3"), ("Bit rates", "125 kbit/s (500 m), 250 kbit/s (250 m), 500 kbit/s (100 m)"),
            ("Cable", "Thick/thin trunk and drops: 2 CAN wires + 24 V power pair + shield (5-pin connectors)"), ("Nodes", "64 MAC IDs (0-63)"),
            ("Identifiers", "Message groups 1-4: e.g. group 2 = 0x400 | MAC << 3 | message ID"), ("I/O", "Polled, bit-strobe, change-of-state, cyclic connections"),
            ("Start-up", "Duplicate MAC ID check, then the scanner allocates the master/slave connection set")]
    frame = [["Group 2 identifier", ("1 0", 2), ("MAC ID", 6), ("Msg ID", 3)], ["Explicit message", ("Hdr: frag XID MAC", 8), ("Service", 8), ("Class", 8), ("Instance", 8), ("Attr", 8)]]
    about = ("DeviceNet is CIP running over CAN. The 11-bit identifier is split into message groups that encode the device's MAC ID and the message type, "
             "so the CAN arbitration priority follows the message role. The cable carries 24 V for the devices alongside CAN. At power-up every device "
             "checks that nobody else uses its MAC ID; the scanner then allocates connections and polls each device every scan cycle.")
    guide = ["Watch the Duplicate MAC ID check messages (group 2, message ID 7) at start-up.",
             "Select a poll command: identifier 0x400 | MAC << 3 | 5.",
             "Set the duplicate MAC fault and power-cycle the starter: it goes off-line.",
             "COMPOSE an explicit Get_Attribute_Single of the Identity object (class 1, attr 7)."]

    def setup(self):
        nodes = [self.node("sc", "SCANNER", "plc", 40, 60, "MAC 0", "1756-DNB"), self.node("pe", "PHOTO-EYE", "sensor", 300, 60, "MAC 5", "42EF"),
                 self.node("ms", "MOTOR STARTER", "drive", 560, 60, "MAC 10", "E3 overload"), self.node("vfd", "VFD", "drive", 300, 290, "MAC 20", "PowerFlex"),
                 self.node("ps", "24 V SUPPLY", "battery", 600, 290, "8 A", "network power")]
        for n in nodes[3:]:
            n.at_top()
        nodes[4].extra["can"] = False
        self.can_trunk(nodes, 200, label="DeviceNet thick trunk (CAN + 24 V)", style="devnet", conn="m12")
        self.user = "sc"
        self.mac = {"sc": 0, "pe": 5, "ms": 10, "vfd": 20}
        self.alloc = set()
        for d in ("pe", "ms", "vfd"):
            self.by[d].vars.update({"Network status": "flashing green", "Connection": "none"})
        self.by["pe"].vars["Target present"] = 1
        self.by["pe"].ctl = [("Target present", "TARGET", 0, 1, 1, lambda v: "YES" if v else "NO")]
        self.at(0.01, self.startup)
        self.every(0.01, self.scan, 0.2)

    def g2(self, mac, mid):
        return 0x400 | (mac << 3) | mid

    def send(self, src, cid, data, info, kind="data"):
        grp = "Group 1" if cid < 0x400 else ("Group 2" if cid < 0x600 else "Group 3/4")

        def idr(b, o, cid=cid):
            if 0x400 <= cid < 0x600:
                b.note("Group 2: MAC ID %d, message ID %d (%s)" % ((cid >> 3) & 63, cid & 7, {4: "master explicit request", 3: "slave explicit response", 5: "master I/O poll command",
                                                                                         6: "unconnected explicit request", 7: "duplicate MAC ID check", 2: "COS ack"}.get(cid & 7, "")),
                       "Group 2 identifier = 10 + MAC ID (6 bits) + message ID (3 bits).", d=1)
            elif cid < 0x400:
                b.note("Group 1: message ID %d, source MAC %d (%s)" % ((cid >> 6) & 15, cid & 63, {15: "slave I/O poll response", 14: "slave COS/cyclic", 13: "bit-strobe response"}.get((cid >> 6) & 15, "")),
                       "Group 1 identifier = 0 + message ID (4 bits) + source MAC ID (6 bits).", d=1)
        self.bus.send(src, cid, data, info=info, kind=kind, key="%s 0x%03X" % (grp, cid), idrows=idr)

    def startup(self):
        for i, d in enumerate(("pe", "ms", "vfd")):
            self.at(self.t + 0.003 * i, self.dup_check, d)
        self.at(self.t + 0.05, self.allocate)

    def dup_check(self, d):
        if not self.by[d].on:
            return
        mac = self.mac[d]
        data = bytes([0x00, 0x01, 0x00]) + (0xC0DE00 + mac).to_bytes(4, "little")
        self.send(d, self.g2(mac, 7), data, "Duplicate MAC ID check MAC %d" % mac, "ctl")
        if self.fault["dup"] and d == "ms":
            self.send("vfd", self.g2(20, 7), bytes([0x80, 0x01, 0x00]) + (0xC0DE14).to_bytes(4, "little"), "Duplicate MAC ID RESPONSE (MAC 20 already in use)", "err")
            self.by["ms"].vars["Network status"] = "SOLID RED (duplicate MAC)"
            self.by["ms"].state = "OFF-LINE"

    def allocate(self):
        for d in ("pe", "ms", "vfd"):
            mac = self.mac[d]
            if not self.by[d].on or (self.fault["dup"] and d == "ms"):
                continue
            self.send("sc", self.g2(mac, 6), bytes([0x00, 0x4B, 0x03, 0x01, 0x03, 0x00]), "Allocate M/S connection set -> MAC %d (explicit+poll)" % mac, "cmd")
            self.at(self.t + 0.001, lambda d=d, mac=mac: self.send(d, self.g2(mac, 3), bytes([0x00, 0xCB, 0x00]), "Allocate response MAC %d" % mac, "resp"))
            self.alloc.add(d)
            self.by[d].vars.update({"Network status": "solid green", "Connection": "polled I/O"})
            self.by[d].state = "ON-LINE"

    def scan(self):
        if not self.by["sc"].on:
            return
        for d in ("pe", "ms", "vfd"):
            if d not in self.alloc:
                continue
            mac = self.mac[d]
            self.send("sc", self.g2(mac, 5), bytes([int(self.t * 10) & 3]), "Poll command -> MAC %d" % mac, "cmd")
            n = self.by[d]
            if not n.on or (d == "vfd" and self.fault["volts"] and self.rng.random() < 0.3):
                if d == "vfd" and self.fault["volts"]:
                    n.state = "BROWN-OUT RESET"
                continue
            data = bytes([int(n.vars.get("Target present", 1)) & 1]) if d == "pe" else (bytes([0x05, 0x00, 0xDC, 0x05]) if d == "vfd" else bytes([0x21]))
            self.send(d, (15 << 6) | mac, data, "Poll response MAC %d: %s" % (mac, data.hex().upper()), "resp")

    def can_fault(self, key, on):
        if key == "off":
            self.by["pe"].on = not on
        if key == "dup":
            self.alloc.discard("ms")
            self.by["ms"].addr = "MAC 20 (!)" if on else "MAC 10"
            self.mac["ms"] = 20 if on else 10
            self.at(self.t + 0.01, self.startup)
        if key == "volts":
            self.by["vfd"].vars["Supply at node"] = "10.2 V (min 11 V)" if on else "23.1 V"

    def tpls(self):
        return [Tpl("Explicit Get_Attribute_Single", [P("mac", "MAC ID", 20, 0, 63), P("cls", "Class", 1, 0, 255), P("inst", "Instance", 1, 0, 255), P("attr", "Attribute", 7, 0, 255)],
                    lambda s, v, send: self._ex(v, send), "Group 2 message 4 request; the device answers on message 3.")] + self.generic_tpls("sc")

    def _ex(self, v, send):
        data = bytes([0x00, 0x0E, v["cls"], v["inst"], v["attr"]])
        if not send:
            return self.preview_can("sc", self.g2(v["mac"], 4), data)
        self.send("sc", self.g2(v["mac"], 4), data, "Explicit Get_Attribute_Single MAC %d %d/%d/%d" % (v["mac"], v["cls"], v["inst"], v["attr"]), "cmd")
        d = {5: "pe", 10: "ms", 20: "vfd"}.get(v["mac"])
        if d and self.by[d].on:
            rsp = bytes([0x00, 0x8E]) + (b"PHOTO" if v["attr"] == 7 else b"\x01\x00")
            self.at(self.t + 0.001, lambda: self.send(d, self.g2(v["mac"], 3), rsp[:8], "Explicit response MAC %d" % v["mac"], "resp"))
        return None


# ============================================================== ControlNet
class ControlNet(Scenario):
    key, name, cat = "controlnet", "ControlNet", "ind"
    blurb = "Deterministic industrial networking"
    phy, rate = "manch", 5e6
    medium = "ControlNet 5 Mbit/s Manchester on RG-6 coax with taps, redundant media A/B, NUT 5 ms, SMAX 3, UMAX 10"
    nets = [("BUS", "coax trunk (channel A)")]
    lines = ["M"]
    faults = [("cableA", "Channel A cable damaged", "Redundant media: every node keeps receiving on channel B; the A channel status shows a fault."),
              ("no_term0", "75 Ω terminator missing", "Reflections on the coax corrupt frames on that channel."),
              ("umax", "HMI configured as node 12 (UMAX is 10)", "Nodes above UMAX never get an unscheduled turn: the HMI cannot communicate."),
              ("nut", "NUT shortened to 1 ms", "The scheduled data no longer fits: insufficient bandwidth for the configured connections.")]
    spec = [("Standard", "ODVA ControlNet (CIP), IEC 61158 Type 2"), ("Physical", "5 Mbit/s Manchester, RG-6 75 Ω coax with taps, fibre options; redundant A/B media"),
            ("Access", "CTDMA: each Network Update Time (NUT) has a scheduled part, an unscheduled part and a guardband"),
            ("Scheduled", "Nodes 1..SMAX transmit once per NUT in address order: deterministic I/O"),
            ("Unscheduled", "Round robin, starting node advances each NUT, up to UMAX: explicit messages"), ("Moderator", "Lowest-addressed node sends the moderator frame in the guardband")]
    frame = [["MAC frame", ("Preamble", 16), ("Start delim", 8), ("Source MAC", 8), ("Lpacket(s)", "n x 8"), ("CRC-16", 16), ("End delim", 8)]]
    about = ("ControlNet makes CIP deterministic by dividing time into repeating Network Update Times. In the scheduled part every node up to SMAX "
             "gets exactly one transmission opportunity per NUT, so I/O timing never varies. In the unscheduled part the remaining time is shared round "
             "robin for messaging. Everything is sent on two redundant cables.")
    guide = ["In FLOW, count the scheduled transmissions per NUT (nodes 1-3) followed by one unscheduled turn and the moderator frame.",
             "Damage cable A: data keeps flowing on B.",
             "Move the HMI above UMAX and watch it go silent."]

    def build(self):
        devs = [("plc", "PLC (keeper)", "plc", 30, 40, 1), ("io", "I/O RACK", "io", 300, 40, 2), ("drv", "DRIVE", "drive", 560, 40, 3), ("hmi", "HMI", "hmi", 300, 290, 10)]
        nodes = []
        for nid, lab, kind, x, y, a in devs:
            n = self.node(nid, lab, kind, x, y, "node %d" % a, "")
            n.extra["mac"] = a
            if y > 200:
                n.at_top()
            nodes.append(n)
        self.trunk(200, 30, 850, nodes, "coax", net="BUS", label="RG-6 trunk A (B runs alongside)", t0=True, t1=True, drop_conn="bnc", tlabel="75 Ω")
        self.seg([(30, 214), (850, 214)], "coax", label="trunk B", w=4)
        self.user = "plc"
        self.nut = 0
        self.urr = 1
        self.every(0.005, self.nut_cycle, 0.01)
        for n in nodes:
            n.vars.update({"Channel A": "OK", "Channel B": "OK"})

    def mac(self, src, lp, info, kind, err=None):
        b = Bld("ControlNet MAC frame", "")
        b.u8("Source MAC ID", self.by[src].extra["mac"], None, "Transmitting node")
        b.raw("Lpacket", lp, None, "Link packets: size, control, tag (connection ID) and data")
        crc = crcn("CRC-16/CCITT-FALSE", bytes([self.by[src].extra["mac"]]) + lp)
        b.u16("CRC", crc, "0x%04X" % crc, "CRC-16")
        p = b.done()
        tb = 1.0 / 5e6
        bits = msb(0xFF00, 16) + bytes_lsb(p.b)

        def wf(fr):
            w = Wire(bit=tb)
            w.set("M", 0.0, 2)
            t = w.manch("M", bits, tb, tb, 1)
            w.seg(tb, tb * 17, "PREAMBLE", 7, 1)
            w.seg(tb * 17, t, info.split(":")[0], 1, 1)
            w.set("M", t, 2)
            w.end(t + tb)
            return w
        return Frame(self.t, (len(bits) + 4) * tb, src, None, "ControlNet", info, pdu=p, kind=kind, err=err, wirefn=wf, key=info.split(" ")[0] + " " + info.split(" ")[1])

    def nut_cycle(self):
        self.nut += 1
        t0 = self.t
        span = 0.001 if self.fault["nut"] else 0.005
        err_ch = "Received on channel B only (A faulted)" if self.fault["cableA"] else None
        sched = [n for n in self.nodes if n.extra["mac"] <= 3 and n.on]
        for n in sched:
            err = None
            if self.fault["no_term0"] and self.rng.random() < 0.15:
                err = "CRC error on channel A (reflections)"
            if self.fault["nut"] and n.extra["mac"] == 3:
                err = "Insufficient bandwidth: scheduled data does not fit the NUT"
            fr = self.mac(n.id, bytes([6, 0x01, n.extra["mac"], 0x10]) + bytes([int(self.t * 100) & 255] * 4), "Scheduled node %d (NUT %d)" % (n.extra["mac"], self.nut), "data", err)
            self.tx(fr)
            if err_ch:
                n.vars["Channel A"] = "FAULT"
        hmi_mac = 12 if self.fault["umax"] else 10
        self.by["hmi"].extra["mac"] = hmi_mac
        self.by["hmi"].addr = "node %d%s" % (hmi_mac, " (> UMAX!)" if hmi_mac > 10 else "")
        cand = [n for n in self.nodes if n.on and n.extra["mac"] <= 10]
        if cand:
            self.urr = self.urr % 10 + 1
            pick = min(cand, key=lambda n: (n.extra["mac"] - self.urr) % 10)
            if pick.id == "hmi" or self.urr % 3 == 0:
                who = pick if pick.id == "hmi" else self.by["plc"]
                self.tx(self.mac(who.id, bytes([8, 0x02, 0x00, 0x0E, 0x20, 0x01, 0x24, 0x01]), "Unscheduled node %d: explicit message" % who.extra["mac"], "cmd"))
        self.tx(self.mac("plc", bytes([10, 0x7F]) + bytes(8), "Moderator frame (NUT %d, SMAX 3, UMAX 10)" % self.nut, "sync"))
        del t0, span

    def on_fault(self, key, on):
        if key == "cableA":
            self.segs[-2].broken = on if len(self.segs) > 2 else False
            for n in self.nodes:
                n.vars["Channel A"] = "FAULT" if on else "OK"
            self._paths.clear()

    def cond(self, net):
        c = super().cond(net)
        if self.fault["no_term0"]:
            c.update(refl=0.35, ringf=12e6, ringd=0.15e-6)
        if self.fault["cableA"]:
            c.update(atten=0.15, noise=0.08)
        return c


# ================================================================== IO-Link
class IOLink(Scenario):
    key, name, cat = "iolink", "IO-Link", "ind"
    blurb = "Smart sensors and actuators"
    phy, rate = "iolink", 38400
    medium = "IEC 61131-9 IO-Link: master port class A (M12), COM2 38.4 kbit/s on C/Q, distance sensor, 2.3 ms cycle"
    nets = [("C/Q", "pin 4: switching / communication line"), ("L+", "pin 1: 24 V")]
    lines = ["B"]
    faults = [("wrong", "Device replaced by a different model", "Port validation compares Vendor ID / Device ID with the configuration: mismatch, the port refuses to operate."),
              ("long", "25 m cable (spec: max 20 m)", "Signal degradation: communication errors and retries."),
              ("short", "Short circuit on C/Q", "The master port detects over-current and switches off the line."),
              ("sio", "Device fails to answer the wake-up", "The port falls back to SIO: the C/Q pin works as a plain switching input (standard I/O).")]
    spec = [("Standard", "IEC 61131-9 (SDCI), IO-Link Interface Spec 1.1"), ("Wiring", "Unshielded 3-wire, M12/M8, max 20 m; point-to-point (not a bus)"),
            ("Speeds", "COM1 4.8, COM2 38.4, COM3 230.4 kbit/s"), ("Start-up", "Wake-up request (80 us current pulse), then the master finds the device's COM speed"),
            ("Data", "Cyclic process data (1-32 bytes) + acyclic ISDU parameters (index/sub-index) + events"), ("Fallback", "SIO: behaves as a standard 24 V switching sensor"),
            ("Description", "IODD (XML) file describes the device's parameters")]
    frame = [["Master message", ("MC: R/W, channel, address", 8), ("CKT: type + checksum", 8), ("OD (write)", "0-2 x 8")], ["Device message", ("PD in", "n x 8"), ("OD", "n x 8"), ("CKS: event, PD valid, checksum", 8)]]
    about = ("IO-Link turns the third wire of an ordinary 24 V sensor cable into a serial link. After a wake-up pulse the master and the smart "
             "sensor exchange short M-sequences every cycle: the device returns its process data (here a distance) and, on request, parameters "
             "identified by index, such as its name or switching point. Unplug it and plug in a plain switch, and the port still works in SIO mode.")
    guide = ["Look at the wake-up pulse then the COM2 M-sequences in LOGIC.",
             "Select an M-sequence reply: find the process data and the checksum/status byte.",
             "COMPOSE an ISDU read of index 0x0010 (vendor name).",
             "Plug in the wrong device model and read the port status in the master's DEVICE panel."]

    def build(self):
        m = self.node("m", "IO-LINK MASTER", "io", 60, 150, "port 1 (class A)", "8 ports").at_right()
        d = self.node("dev", "DISTANCE SENSOR", "sensor", 680, 150, "COM2", "VendorID 0x0310").at_left()
        self.seg([m.port, d.port], "wire", net="C/Q", label="M12 4-pin, 5 m", c0="m12", c1="m12", col=(40, 40, 46), w=6)
        self.user = "m"
        self.n = 0
        d.vars.update({"Distance mm": 412, "Switch point mm": 500, "Output": "OFF"})
        d.ctl = [("Distance mm", "TARGET", 50, 2000, 1, lambda v: "%d mm" % v)]
        m.vars.update({"Port mode": "IO-Link OPERATE", "Validation": "OK (VendorID 0x0310, DeviceID 0x00A1)", "Cycle": "2.3 ms"})
        self.mode = "STARTUP"
        self.at(0.01, self.wake)
        self.every(0.0023, self.cycle, 0.05)

    def wake(self):
        b = Bld("IO-Link wake-up request (WURQ)", "The master drives C/Q against the device's level for 80 us, then expects a reply within TREN.")
        b.note("80 us current pulse", "", d=1)

        def wf(fr):
            w = Wire(bit=26e-6)
            w.set("B", 0.0, 1)
            w.set("B", 20e-6, 0)
            w.set("B", 100e-6, 1)
            w.seg(20e-6, 100e-6, "WURQ 80 us", 7, 1)
            w.end(160e-6)
            return w
        self.tx(Frame(self.t, 160e-6, "m", "dev", "IO-Link", "Wake-up request (WURQ)", pdu=b.done(), kind="ctl", wirefn=wf, key="WURQ"))
        if self.fault["sio"] or self.fault["short"]:
            self.mode = "SIO"
            self.by["m"].vars["Port mode"] = "SIO (standard input)" if self.fault["sio"] else "OFF - short circuit on C/Q"
            return
        if self.fault["wrong"]:
            self.mode = "FAULT"
            self.by["m"].vars["Port mode"] = "VALIDATION ERROR"
            self.by["m"].vars["Validation"] = "FAILED: found DeviceID 0x00B7, expected 0x00A1"
            self.by["dev"].state = "WRONG DEVICE"
            return
        self.mode = "OPERATE"
        self.by["m"].vars["Port mode"] = "IO-Link OPERATE"
        self.by["m"].vars["Validation"] = "OK (VendorID 0x0310, DeviceID 0x00A1)"
        self.by["dev"].state = "OPERATE"

    @staticmethod
    def ckt(data, seed=0x52):
        x = seed
        for b_ in data:
            x ^= b_
        c = (((x >> 7) ^ (x >> 5) ^ (x >> 3) ^ (x >> 1)) & 1) << 5 | (((x >> 6) ^ (x >> 4) ^ (x >> 2) ^ x) & 1) << 4 | \
            (((x >> 7) ^ (x >> 6)) & 1) << 3 | (((x >> 5) ^ (x >> 4)) & 1) << 2 | (((x >> 3) ^ (x >> 2)) & 1) << 1 | ((x >> 1) ^ x) & 1
        return c

    def mseq(self, src, data, info, kind, desc_rows, err=None):
        b = Bld("IO-Link M-sequence (%s)" % ("master" if src == "m" else "device"), "")
        for label, v, desc in desc_rows:
            b.u8(label, v, None, desc)
        p = b.done()
        return serial_frame(self, src, "dev" if src == "m" else "m", "IO-Link", info, p, 38400, 8, "E", 1, line="B", kind=kind, err=err, key=info.split(":")[0])

    def cycle(self):
        if self.mode != "OPERATE" or not self.by["m"].on:
            return
        self.n += 1
        mc = 0x80 | 0x00
        ck = 0x80 | self.ckt(bytes([mc, 0x80]))
        err = "Checksum error (cable too long)" if self.fault["long"] and self.rng.random() < 0.15 else None
        self.tx(self.mseq("m", None, "M-seq TYPE_2_2 read PD", "cmd", [("MC", mc, "Read, process channel"), ("CKT", ck, "M-sequence type 2 + 6-bit checksum")], err), bus="cq")
        dev = self.by["dev"]
        mm = int(dev.vars["Distance mm"])
        dev.vars["Output"] = "ON" if mm < dev.vars["Switch point mm"] else "OFF"
        pd = struct.pack(">H", mm << 2 | (1 if mm < dev.vars["Switch point mm"] else 0))
        cks = 0x40 | self.ckt(pd + bytes([0x40]))
        r = self.mseq("dev", None, "Device PD: %d mm, Q1 %s" % (mm, dev.vars["Output"]), "resp",
                      [("PD byte 1", pd[0], "Distance (14 bits) + switching bit"), ("PD byte 2", pd[1], ""), ("CKS", cks, "Event flag, PD valid flag, 6-bit checksum")], err)
        r.t = self.t + 0.0006
        self.tx(r, bus="cq")

    def isdu(self, idx, send=True):
        vals = {0x0010: b"COMM-SIM SENSORS", 0x0012: b"O5D150 distance", 0x0015: b"000123456", 0x003C: struct.pack(">H", self.by["dev"].vars["Switch point mm"])}
        v = vals.get(idx, None)
        req = self.mseq("m", None, "ISDU read index 0x%04X" % idx, "cmd", [("MC", 0xF0, "Read, ISDU channel"), ("I-Service", 0x93, "Read request, index 8-bit"), ("Index", idx & 255, ""), ("CHKPDU", 0x5A, "")])
        if not send:
            return req
        self.tx(req, bus="cq")
        if v is None:
            rsp = self.mseq("dev", None, "ISDU error: index not available (0x8011)", "err", [("I-Service", 0xC4, "Read response, error"), ("ErrorCode", 0x80, ""), ("AdditionalCode", 0x11, "")])
        else:
            rsp = self.mseq("dev", None, "ISDU response: %s" % (v.decode("latin-1") if idx != 0x003C else str(self.by["dev"].vars["Switch point mm"])), "resp",
                            [("I-Service", 0xD0 | min(15, len(v) + 2), "Read response, length")] + [("Data[%d]" % i, x, "") for i, x in enumerate(v[:12])])
        rsp.t = self.t + 0.003
        return self.tx(rsp, bus="cq")

    def on_fault(self, key, on):
        self.at(self.t + 0.005, self.wake)

    def cond(self, net):
        c = super().cond(net)
        if self.fault["long"]:
            c["rise"] = 6.0
        if self.fault["short"] and net == "C/Q":
            c["atten"] = 0.02
        return c

    def tpls(self):
        return [Tpl("ISDU read", [P("idx", "Index", 0x0010, 0, 0xFFFF, fmt=lambda v: "0x%04X" % v)], lambda s, v, send: self.isdu(v["idx"], send),
                    "0x0010 vendor name, 0x0012 product name, 0x0015 serial number, 0x003C switch point SP1."),
                Tpl("ISDU write switch point", [P("sp", "SP1 mm", 300, 50, 2000)], lambda s, v, send: self._sp(v, send), "Changes when the switching output Q1 turns on.")]

    def _sp(self, v, send):
        f = self.mseq("m", None, "ISDU write index 0x003C = %d" % v["sp"], "cmd", [("MC", 0x70, "Write, ISDU channel"), ("I-Service", 0x15, "Write request"), ("Index", 0x3C, ""),
                                                                                  ("Data hi", v["sp"] >> 8, ""), ("Data lo", v["sp"] & 255, "")])
        if send:
            self.by["dev"].vars["Switch point mm"] = v["sp"]
            return self.tx(f, bus="cq")
        return f


# ============================================================ AS-Interface
class ASi(Scenario):
    key, name, cat = "asi", "AS-Interface (AS-i)", "ind"
    blurb = "Simple sensors and actuators"
    phy, rate = "asi", 166667
    medium = "AS-i on yellow flat cable: 30 V power + data, APM modulation, master + 4 slaves, cycle ~0.7 ms"
    nets = [("AS-i +/-", "AS-i voltage (AC part)")]
    lines = ["M"]
    faults = [("addr0", "Two new slaves both at address 0", "Factory-new slaves have address 0; with two of them the master cannot address either - assign addresses one at a time."),
              ("missing", "Valve slave (address 2) missing", "Configuration error: the slave is in the projected list (LPS) but not detected (LDS). CONFIG ERR LED."),
              ("earth", "Earth fault on AS-i +", "The supply's earth fault detection reports it; communication may become unreliable."),
              ("ps", "AS-i power supply overloaded", "Voltage drops toward the 26.5 V minimum: slaves reset.")]
    spec = [("Standard", "IEC 62026-2 / EN 50295 (AS-International)"), ("Cable", "Yellow 2-wire flat cable, insulation-piercing (vampire) connections, no polarity issues"),
            ("Power + data", "30 V DC power and data on the same two wires; data decoupled by inductors in the supply"),
            ("Modulation", "Manchester code shaped as sin² voltage pulses (Alternating Pulse Modulation), 167 kbit/s"),
            ("Nodes", "31 standard or 62 A/B slaves, 4 in / 4 out bits each"), ("Cycle", "~150 us per slave: 5 ms for 31 slaves"),
            ("Frames", "Master request 14 bits, slave response 7 bits, both with parity")]
    frame = [["Master request", ("ST", 1), ("SB", 1), ("A4..A0", 5), ("I4..I0", 5), ("PB", 1), ("EB", 1)], ["Slave response", ("ST", 1), ("I3..I0", 4), ("PB", 1), ("EB", 1)]]
    about = ("AS-i is the simplest fieldbus: one unshielded yellow cable carries power and data to binary sensors and actuators, clamped on anywhere. "
             "The master polls each slave in turn with a 14-bit request that also carries the slave's 4 output bits, and the slave answers with "
             "its 4 inputs in 7 bits. The signal is encoded as gentle sine-squared pulses so it can share the cable with the power.")
    guide = ["In LOGIC, decode a master request: start, control bit, 5 address bits, 5 info bits, parity, end.",
             "On the SCOPE, see the APM pulses: each Manchester transition becomes a sin² pulse.",
             "Add two new slaves at address 0 and use COMPOSE 'Change address' to fix one."]

    def build(self):
        m = self.node("m", "AS-i MASTER", "plc", 30, 40, "in PLC", "")
        sl = [(1, "PUSHBUTTONS", "button", 230), (2, "VALVE", "valve", 430), (3, "PROX SENSOR", "sensor", 630), (4, "STACK LIGHT", "lamp", 760)]
        nodes = [m]
        for a, lab, kind, x in sl:
            n = self.node("s%d" % a, lab, kind, x - 50, 260, "addr %d" % a, "4I/4O", w=112)
            n.at_top()
            n.extra["a"] = a
            n.vars.update({"Inputs": a & 15, "Outputs": 0})
            nodes.append(n)
        ps = self.node("ps", "AS-i POWER", "battery", 380, 40, "30 V / 4 A", "with decoupling")
        ps.at_top() if False else None
        ps.port = (ps.x + ps.w / 2, ps.y + ps.h)
        nodes.append(ps)
        self.trunk(180, 40, 860, nodes, "flat", net="AS-i +/-", label="AS-i yellow flat cable", drop_conn="tap")
        self.user = "m"
        self.by["s1"].ctl = [("Inputs", "BUTTONS", 0, 15, 1, lambda v: format(int(v), "04b"))]
        self.every(0.001, self.cycle, 0.01)
        self.k = 0

    def req_bits(self, a, info, ctl=0):
        bits = [ctl] + msb(a, 5) + msb(info, 5)
        return [0] + bits + [even_parity(int("".join(map(str, bits)), 2), 11)] + [1]

    def asi_wire(self, bits, label):
        tb = 6e-6
        w = Wire(bit=tb)
        w.set("M", 0.0, 1)
        t = tb
        t = w.manch("M", bits, t, tb, 1)
        w.set("M", t, 1)
        w.end(t + tb)
        tl, vl = w.L["M"]
        edges = [(tl[i], vl[i] - vl[i - 1]) for i in range(1, len(tl))]

        def ana(ts):
            y = np.zeros_like(ts)
            for te, d in edges:
                m_ = (ts >= te) & (ts < te + 3e-6)
                y[m_] += -2.0 * d * np.sin(math.pi * (ts[m_] - te) / 3e-6) ** 2
            return y
        w.ana["ASI"] = ana
        w.seg(tb, t, label, 1, 1)
        return w

    def mk(self, src, a, bits, info, kind, rows, err=None):
        b = Bld("AS-i %s" % ("master request" if src == "m" else "slave response"), "")
        b.note("Bits: %s" % "".join(map(str, bits)), "Transmitted MSB first after the start bit", d=1)
        for r in rows:
            b.note(r, "", d=1)
        return Frame(self.t, (len(bits) + 2) * 6e-6, src, "s%d" % a if src == "m" else "m", "AS-i", info, pdu=b.done(), kind=kind, err=err,
                     wirefn=lambda fr: self.asi_wire(bits, info.split(":")[0]), key=info.split(" ")[0] + " %d" % a)

    def cycle(self):
        if not self.by["m"].on:
            return
        self.k = self.k % 4 + 1
        a = self.k
        n = self.by["s%d" % a]
        out = (int(self.t * 4) & 15) if a in (2, 4) else 0
        n.vars["Outputs"] = out
        bits = self.req_bits(a, out)
        err = "Earth fault: unreliable communication" if self.fault["earth"] and self.rng.random() < 0.2 else None
        self.tx(self.mk("m", a, bits, "Data_Exchange slave %d out %s" % (a, format(out, "04b")), "cmd", ["Address %d, info %s, parity ok" % (a, format(out, "05b"))], err))
        missing = (a == 2 and self.fault["missing"]) or not n.on or (self.fault["ps"] and self.rng.random() < 0.3)
        if missing:
            n.state = "NOT DETECTED (LDS)" if a == 2 and self.fault["missing"] else ("RESET (low voltage)" if self.fault["ps"] else "OFF")
            return
        n.state = ""
        inp = int(n.vars["Inputs"]) & 15
        rb = [0] + msb(inp, 4) + [even_parity(inp, 4)] + [1]
        r = self.mk("s%d" % a, a, rb, "Response slave %d in %s" % (a, format(inp, "04b")), "resp", ["Inputs %s" % format(inp, "04b")], err)
        r.t = self.t + 18 * 6e-6 + 30e-6
        self.tx(r)
        if self.fault["addr0"] and a == 4:
            self.tx(self.mk("m", 0, self.req_bits(0, 0), "Data_Exchange slave 0: TWO slaves at 0 answer", "err", ["Address conflict"], "Address 0 conflict: response collision"))

    def tpls(self):
        return [Tpl("Change slave address", [P("old", "Old address", 0, 0, 31), P("new", "New address", 5, 1, 31)], lambda s, v, send: self._addr(v, send),
                    "'Delete address' (to 0) then 'Set address' - how a new slave is commissioned with a hand-held addressing unit or the master."),
                Tpl("Read status", [P("a", "Slave", 1, 1, 31)], lambda s, v, send: (self.tx if send else (lambda f: f))(self.mk("m", v["a"], self.req_bits(v["a"], 0b11110, 1), "Read_Status slave %d" % v["a"], "cmd", ["Command frame (SB = 1)"])),
                    "Command frame with the control bit set.")]

    def _addr(self, v, send):
        f = self.mk("m", v["old"], self.req_bits(v["old"], v["new"], 0), "Set_Address %d -> %d" % (v["old"], v["new"]), "cmd", ["Set address command"])
        if send:
            if v["old"] == 0 and self.fault["addr0"]:
                self.set_fault("addr0", False)
            return self.tx(f)
        return f


# ===================================================================== HART
HART_CMD = {0: "Read Unique Identifier", 1: "Read Primary Variable", 2: "Read Loop Current and Percent of Range", 3: "Read Dynamic Variables and Loop Current",
            6: "Write Polling Address", 12: "Read Message", 13: "Read Tag, Descriptor, Date", 40: "Enter/Exit Fixed Current Mode", 48: "Read Additional Device Status"}


class HART(Scenario):
    key, name, cat = "hart", "HART", "ind"
    blurb = "Digital communications over 4-20 mA instrumentation"
    phy, rate = "hart", 1200
    medium = "HART 7 on a 4-20 mA loop: Bell 202 FSK (1200 Hz = 1, 2200 Hz = 0) at 1200 bit/s, 250 Ω loop resistor, DCS + handheld"
    nets = [("LOOP", "loop current (mA)"), ("VR250", "voltage across the 250 Ω resistor")]
    lines = ["D"]
    faults = [("res", "250 Ω loop resistor missing", "HART needs 230-1100 Ω in the loop to turn the +/-0.5 mA FSK into a readable voltage. Without it, no communication."),
              ("noise", "VFD cable in the same tray", "Noise in the HART band (500-10 kHz) corrupts characters: checksum and parity errors."),
              ("fixed", "Transmitter left in fixed-current mode", "Someone ran command 40 for a loop test: the 4-20 mA output is frozen at 12 mA while the process changes. Status bit 'loop current fixed'."),
              ("cfg", "Configuration changed by the handheld", "Field device status shows 'configuration changed' until a master resets the flag (command 38).")]
    spec = [("Standard", "FieldComm Group HART 7 (IEC 62591 for WirelessHART)"), ("Physical", "Bell 202 FSK, 1200 bit/s, +/-0.5 mA superimposed on the 4-20 mA signal"),
            ("Characters", "8 data bits, odd parity, 1 stop (11 bits)"), ("Masters", "Primary (DCS) and secondary (handheld); field devices answer only when asked (or burst mode)"),
            ("Addressing", "Short (polling address 0-63) or long 38-bit unique ID"), ("Commands", "Universal (0-30), common practice (32-126), device specific"),
            ("Analogue", "Average FSK value is zero: the 4-20 mA signal is undisturbed")]
    frame = [["HART long frame", ("Preamble FF x5+", 40), ("Delimiter", 8), ("Address 5 B", 40), ("Command", 8), ("Byte count", 8), ("Status 2 B (reply)", 16), ("Data", "n x 8"), ("Checksum", 8)]]
    about = ("HART adds a digital conversation to an ordinary 4-20 mA instrument loop without disturbing it: a modem superimposes a +/-0.5 mA tone - "
             "1200 Hz for a one, 2200 Hz for a zero - whose average is zero. The control system keeps reading the analogue current while a handheld "
             "or the DCS asks the transmitter for its tag, units, digital PV and diagnostics. You can hear the FSK through the speaker at real-time speed.")
    guide = ["Probe LOOP and AUTOSET: the 4-20 mA level with the FSK riding on it.",
             "Turn on sound at real-time speed and listen: HART's warble.",
             "Select a command 3 reply: units codes, IEEE floats, field device status.",
             "Put the transmitter into fixed-current mode (fault) and compare the analogue loop current with the digital PV.",
             "Remove the 250 Ω resistor."]

    def build(self):
        dcs = self.node("dcs", "DCS AI CARD", "plc", 40, 40, "primary master", "with HART modem")
        hh = self.node("hh", "HANDHELD", "tool", 40, 290, "secondary master", "475 communicator")
        tx = self.node("tx", "PRESSURE XMTR", "pressure", 700, 160, "poll addr 0", "0-10 bar").at_left()
        ps = self.node("ps", "24 V LOOP SUPPLY", "battery", 380, 40, "", "")
        ps.extra["power"] = False
        y = tx.port[1]
        dcs.at_right()
        self.seg([dcs.port, (300, dcs.port[1]), (300, y), tx.port], "loop", net="LOOP", label="2-wire twisted pair", c1="screw")
        self.seg([(hh.x + hh.w, hh.y + 26), (520, hh.y + 26), (520, y)], "wire", label="handheld clips", col=(200, 50, 40), w=2)
        hh.port = (hh.x + hh.w, hh.y + 26)
        self.seg([(ps.x + ps.w / 2, ps.y + ps.h), (ps.x + ps.w / 2, y)], "loop")
        self.term(300, 110, "250 Ω", True, "res", vert=True)
        self.user = "hh"
        tx.vars.update({"PV bar": 4.20, "URV bar": 10.0, "LRV bar": 0.0, "Tag": "PT-101", "Loop mA": 0.0, "Status": "0x00"})
        tx.ctl = [("PV bar", "PRESSURE", 0.0, 10.0, 0, lambda v: "%.2f bar" % v)]
        dcs.vars.update({"Analogue reading": "-", "HART PV": "-", "Comm errors": 0})
        self.every(1.0, self.poll, 0.2)
        self._audio_fr = None

    def ma(self):
        t = self.by["tx"]
        if self.fault["fixed"]:
            return 12.0
        pv = t.vars["PV bar"]
        return 4.0 + 16.0 * max(0, min(1, (pv - t.vars["LRV bar"]) / (t.vars["URV bar"] - t.vars["LRV bar"])))

    def frame_bytes(self, master, cmd, data=b"", reply=False, status=(0x00, 0x00)):
        addr = bytes([(0x80 if master == "dcs" else 0x00) | 0x26, 0x0B, 0x00, 0x12, 0x34])
        delim = 0x86 if reply else 0x82
        body = bytes([delim]) + addr + bytes([cmd]) + bytes([len(data) + (2 if reply else 0)]) + (bytes(status) if reply else b"") + data
        return bytes([0xFF] * 5) + body + bytes([xor8(body)])

    def mkpdu(self, raw, reply, cmd, data_rows):
        b = Bld("HART %s" % ("response (ACK)" if reply else "request (STX)"), "")
        b.raw("Preamble", raw[:5], "5 x 0xFF", "Lets the receiving modem lock onto the carrier")
        b.u8("Delimiter", raw[5], "0x%02X (%s, long address)" % (raw[5], "ACK slave-to-master" if reply else "STX master-to-slave"), "Frame type and address size")
        a = raw[6:11]
        b.raw("Address", a, "%s master, mfr 0x%02X, dev type 0x%02X, ID 0x%s" % ("primary" if a[0] & 0x80 else "secondary", a[0] & 0x3F, a[1], a[2:].hex().upper()),
              "38-bit unique address: master bit, burst bit, manufacturer ID, device type, device ID")
        b.u8("Command", cmd, "%d %s" % (cmd, HART_CMD.get(cmd, "")), "")
        b.u8("Byte count", raw[12], None, "Bytes of status + data")
        k = 13
        if reply:
            b.u8("Response code", raw[13], "0x%02X %s" % (raw[13], "success" if raw[13] == 0 else ""), "Communication status / command response code")
            b.u8("Field device status", raw[14], "0x%02X%s" % (raw[14], (" " + ", ".join(n for m_, n in ((0x08, "loop current fixed"), (0x40, "configuration changed"), (0x10, "more status available")) if raw[14] & m_)) if raw[14] else ""),
                 "Bits: device malfunction, config changed, cold start, more status, loop current fixed, saturated, non-PV out of limits, PV out of limits")
            k = 15
        for label, n, txt, desc in data_rows:
            b.raw(label, raw[k:k + n], txt, desc)
            k += n
        b.u8("Checksum", raw[-1], "0x%02X [correct]" % raw[-1], "XOR (longitudinal parity) of every byte from the delimiter")
        return b.done()

    def fsk_frame(self, src, dst, raw, pdu, info, kind, err=None):
        baud = 1200
        nb = 11
        dur = (len(raw) * nb + 4) / baud
        lvl = self.ma()

        def wf(fr):
            w = Wire(bit=1.0 / baud)
            w.set("D", 0.0, 1)
            spans = w.uart("D", raw, baud, 2.0 / baud, 8, "O", 1)
            w.field_segs(pdu, spans)
            tl, vl = w.L["D"]
            fsk = phy.fsk(w.T, (tl, vl), 1200.0, 2200.0, 0.5)
            amp = 0.05 if self.fault["res"] else 1.0

            def loop(ts):
                y = lvl + fsk(ts) * amp
                if self.fault["noise"]:
                    y = y + 0.12 * np.sin(2 * math.pi * 3150 * ts) + np.random.default_rng(1).normal(0, 0.05, len(ts))
                return y
            w.ana["LOOP"] = loop
            w.end(dur)
            return w
        fr = Frame(self.t, dur, src, dst, "HART", info, pdu=pdu, kind=kind, err=err, wirefn=wf, key="cmd %d %s" % (raw[11], "rsp" if raw[5] == 0x86 else "req"))
        return fr

    def poll(self):
        if self.by["dcs"].on:
            self.command("dcs", 3)

    def command(self, master, cmd, data=b""):
        raw = self.frame_bytes(master, cmd, data)
        pdu = self.mkpdu(raw, False, cmd, [("Data", len(data), data.hex(" ") if data else "", "")] if data else [])
        err = None
        if self.fault["res"]:
            err = "No reply possible: FSK amplitude too small without the 250 Ω resistor"
        fr = self.fsk_frame(master, "tx", raw, pdu, "%s -> PT-101: cmd %d %s" % (master.upper(), cmd, HART_CMD.get(cmd, "")), "cmd", err)
        self.tx(fr)
        if err or not self.by["tx"].on:
            if master == "dcs":
                self.by["dcs"].vars["Comm errors"] += 1
            return fr
        self.at(fr.t + fr.dur + 0.05, self.reply, master, cmd, data)
        return fr

    def reply(self, master, cmd, data):
        t = self.by["tx"]
        pv = t.vars["PV bar"]
        ma = self.ma()
        pct = (ma - 4) / 16 * 100
        st = (0x08 if self.fault["fixed"] else 0) | (0x40 if self.fault["cfg"] else 0)
        if cmd == 0:
            d = bytes([254, 0x26, 0x0B, 5, 7, 3, 2, 0x01, 0x00, 0x12, 0x34])
            rows = [("Device data", len(d), "254, mfr 0x26, type 0x0B, 5 preambles, HART rev 7", "Expanded device type, preambles, revisions, flags, device ID")]
        elif cmd == 1:
            d = bytes([7]) + struct.pack(">f", pv)
            rows = [("PV units", 1, "7 (bar)", "HART units code table: 7 bar, 12 kPa, 6 psi, 32 degC"), ("PV", 4, "%.3f" % pv, "IEEE 754 float")]
        elif cmd == 2:
            d = struct.pack(">ff", ma, pct)
            rows = [("Loop current", 4, "%.3f mA" % ma, ""), ("Percent of range", 4, "%.2f %%" % pct, "")]
        elif cmd == 3:
            d = struct.pack(">f", ma) + bytes([7]) + struct.pack(">f", pv) + bytes([32]) + struct.pack(">f", 24.1)
            rows = [("Loop current", 4, "%.3f mA" % ma, "What the analogue output is driving"), ("PV units", 1, "7 (bar)", ""), ("PV", 4, "%.3f" % pv, ""),
                    ("SV units", 1, "32 (degC)", ""), ("SV", 4, "24.10", "Secondary variable: sensor temperature")]
        elif cmd == 13:
            d = bytes(6) + b"PRESSURE IN" + bytes(5) + bytes([14, 11, 126])
            rows = [("Tag (packed ASCII)", 6, "PT-101", "8 characters packed into 6 bytes"), ("Descriptor", 16, "PRESSURE IN", ""), ("Date", 3, "14.11.2026", "")]
        elif cmd == 40:
            d = data[:4] if data else struct.pack(">f", 0.0)
            rows = [("Fixed current", 4, "%.2f mA" % struct.unpack(">f", d)[0], "0 = exit fixed current mode")]
            fixed = struct.unpack(">f", d)[0] != 0
            if fixed != self.fault["fixed"]:
                self.set_fault("fixed", fixed)
        elif cmd == 48:
            d = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            rows = [("Device-specific status", 6, "000000000000", "")]
        else:
            d = b""
            rows = []
        raw = self.frame_bytes(master, cmd, d, True, (0x00, st))
        err = "Checksum error (noise)" if self.fault["noise"] and self.rng.random() < 0.5 else None
        fr = self.fsk_frame("tx", master, raw, self.mkpdu(raw, True, cmd, rows), "PT-101 -> %s: cmd %d reply" % (master.upper(), cmd), "resp", err)
        self.tx(fr)
        if master == "dcs" and not err:
            dv = self.by["dcs"]
            dv.vars["Analogue reading"] = "%.2f mA = %.2f bar" % (ma, (ma - 4) / 16 * 10)
            dv.vars["HART PV"] = "%.2f bar" % pv
        t.vars["Loop mA"] = round(ma, 3)
        t.vars["Status"] = "0x%02X" % st

    def audio(self, syn, n):
        if not self.cap:
            return None
        from ..audio import SR
        ts = self.t - n / float(SR) + np.arange(n) / float(SR)
        out = np.zeros(n)
        for fr in list(self.cap)[-3:]:
            if fr.t + fr.dur < ts[0] or fr.t > ts[-1]:
                continue
            w = fr.wire
            if w is None or "LOOP" not in w.ana:
                continue
            m = (ts >= fr.t) & (ts <= fr.t + fr.dur)
            out[m] += (w.ana["LOOP"](ts[m] - fr.t) - self.ma()) * 0.25
        return out if np.any(out) else None

    def tpls(self):
        return [Tpl("HART command", [P("cmd", "Command", 1, opts=[0, 1, 2, 3, 13, 48], fmt=lambda v: "%d %s" % (v, HART_CMD[v]))],
                    lambda s, v, send: self.command("hh", v["cmd"]) if send else self.fsk_frame("hh", "tx", self.frame_bytes("hh", v["cmd"]), self.mkpdu(self.frame_bytes("hh", v["cmd"]), False, v["cmd"], []), "preview", "cmd"),
                    "Universal commands every HART device supports."),
                Tpl("Fixed current mode (cmd 40)", [P("ma", "Current mA (0 = exit)", 12.0, 0.0, 22.0, 0.5)], lambda s, v, send: self.command("hh", 40, struct.pack(">f", v["ma"])) if send else None,
                    "Loop test: freeze the output current. Remember to exit (0 mA) afterwards!")]
