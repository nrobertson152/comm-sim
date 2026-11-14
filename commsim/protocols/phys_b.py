"""Physical interfaces, part B: CAN, CAN FD, Ethernet, SPI, I2C, 1-Wire,
USB, LVDS and fibre-optic Ethernet. Also CanNet, the base class every
CAN-based protocol scenario builds on."""
import math
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, crc, msb, lsb, bytes_lsb, usb_stuff, nrzi, bits_to_int
from .fam import (CanBus, FD_DLC, Lan, eth_pdu, ipv4_pdu, macb, flag_names)
from .. import bits as B


def hexdata(s, n=64):
    try:
        return bytes.fromhex(s.replace(" ", "").replace(",", ""))[:n]
    except ValueError:
        return s.encode()[:n]


# ================================================================ CAN base
class CanNet(Scenario):
    """Common wiring, analogue conditions, fault handling and inspection
    for every CAN-based network."""
    phy = "can"
    rate = 500000
    drate = None
    nets = [("CANH", "CAN_H"), ("CANL", "CAN_L"), ("VDIFF", "CAN_H - CAN_L"), ("RXD", "transceiver RXD (logic)")]
    lines = ["B", "T"]
    can_proto = "CAN"

    def build(self):
        self.bus = CanBus(self, self.rate, self.drate, proto=self.can_proto)
        self.setup()
        self._p_err()

    def setup(self):
        pass

    def can_trunk(self, nodes, y=200, x0=30, x1=850, label="twisted pair, 120 Ω", style="can", conn="dt"):
        self.trunk(y, x0, x1, nodes, style, net="VDIFF", label=label, t0=True, t1=True, drop_conn=conn)

    def _p_err(self):
        nt = sum(1 for t in self.terms if t.on)
        base = {2: 0.0, 1: 0.004 if self.rate <= 250000 else 0.02, 0: 0.55 if self.rate >= 250000 else 0.2}.get(nt, 0.0)
        if self.fault.get("stub"):
            base = max(base, 0.05)
        self.bus.p_err = base

    def on_fault(self, key, on):
        self._p_err()
        self.can_fault(key, on)

    def can_fault(self, key, on):
        pass

    def cond(self, net):
        c = super().cond(net)
        nt = c["nterm"]
        if nt == 1:
            c.update(slow_up=2.0, refl=0.06, ringf=self.rate * 6, ringd=0.12 / self.rate)
        elif nt == 0 and self.terms:
            c.update(slow_up=30.0 * self.rate / 500000.0, refl=0.25, ringf=self.rate * 5, ringd=0.2 / self.rate)
        if self.fault.get("stub"):
            c.update(refl=max(c.get("refl", 0), 0.2), ringf=self.rate * 8, ringd=0.15 / self.rate)
        if self.fault.get("short") and net in ("CANH", "CANL", "VDIFF"):
            c["atten"] = 0.05
        return c

    def inspect(self, n):
        rows = list(n.vars.items())
        if n.extra.get("can", True):
            rows += [("TEC / REC", "%d / %d" % (self.bus.tec.get(n.id, 0), self.bus.rec.get(n.id, 0))),
                     ("Fault confinement", self.bus.state(n.id))]
        return rows

    def draw_stats(self, s, r):
        from .. import ui
        ui.text(s, "CAN ERROR COUNTERS (TEC: transmit, REC: receive)", (r.x, r.y), 11, (200, 220, 230), bold=True)
        y = r.y + 22
        for n in self.nodes:
            if not n.extra.get("can", True):
                continue
            tec, rec = self.bus.tec.get(n.id, 0), self.bus.rec.get(n.id, 0)
            ui.text(s, ui.clip_text(n.label, 10, 120), (r.x, y), 10, (200, 200, 190))
            ui.bar(s, (r.x + 128, y, 200, 10), tec / 256.0, "amber", 32, peak=0.5)
            ui.bar(s, (r.x + 128, y + 11, 200, 6), rec / 256.0, "cyan", 32, peak=0.5)
            ui.text(s, "%3d/%3d %s" % (tec, rec, self.bus.state(n.id)), (r.x + 336, y), 9, (230, 200, 120))
            y += 24
        ui.text(s, "Arbitration losses: %d" % self.bus.lost, (r.x, y + 6), 10, (180, 200, 190))
        ui.text_block(s, "TEC +8 per transmit error, -1 per success; >=128 error passive, >=256 bus off.", (r.x, y + 24, r.w, 40), 9, (150, 160, 150), mono=False)
        return True

    def generic_tpls(self, src):
        return [Tpl("CAN data frame", [P("id", "Identifier", 0x123, 0, 0x7FF, kind="int"), P("data", "Data (hex)", "11 22 33 44")],
                    lambda s, v, send: self._gen(src, v, False, send), "Classical 11-bit data frame with 0-8 bytes."),
                Tpl("Extended frame", [P("id", "Identifier", 0x18FF5021, 0, 0x1FFFFFFF, kind="int"), P("data", "Data (hex)", "01 02 03")],
                    lambda s, v, send: self._gen(src, v, True, send), "29-bit identifier (CAN 2.0B)."),
                Tpl("Remote frame", [P("id", "Identifier", 0x3E0, 0, 0x7FF, kind="int"), P("dlc", "DLC", 8, 0, 8)],
                    lambda s, v, send: self._rtr(src, v, send), "Ask the owner of an identifier to send it (rarely used in practice).")]

    def _gen(self, src, v, ext, send):
        data = hexdata(v["data"], 8)
        if send:
            self.bus.send(src, v["id"], data, ext=ext, info="ID 0x%X [%d] %s" % (v["id"], len(data), data.hex(" ").upper()), kind="cmd")
            return None
        return self.preview_can(src, v["id"], data, ext)

    def _rtr(self, src, v, send):
        if send:
            self.bus.send(src, v["id"], bytes(v["dlc"]), rtr=True, info="REMOTE 0x%03X" % v["id"], kind="cmd")
            return None
        return self.preview_can(src, v["id"], bytes(v["dlc"]), rtr=True)

    def preview_can(self, src, cid, data, ext=False, rtr=False, fd=False, brs=False, dissect=None, idrows=None, info=None):
        from .fam import can_layout, can_dur, can_pdu
        lay = can_layout(cid, data, ext, rtr, fd, brs)
        return Frame(self.t, can_dur(lay, self.rate, self.drate if brs else None), src, None, self.can_proto, info or "ID 0x%X" % cid,
                     pdu=can_pdu(cid, lay, ext, rtr, fd, brs, idrows, dissect))


# ===================================================================== CAN
class CAN(CanNet):
    key, name, cat = "can", "CAN Bus (ISO 11898)", "phys"
    blurb = "Vehicles, machinery, embedded controllers"
    rate = 500000
    medium = "ISO 11898-2 high-speed CAN, 500 kbit/s, 40 m twisted pair, 120 Ω at both ends"
    faults = [("no_term0", "Terminator missing (left end)", "One 120 Ω left: bus impedance 120 Ω instead of 60 Ω. Slower recessive edges, a little ringing - usually still works."),
              ("no_term1", "Terminator missing (right end)", "With both missing, the recessive edge relies on the transceivers' ~20 kΩ: the bus cannot return to recessive within a bit - errors everywhere."),
              ("short", "CAN_H shorted to CAN_L", "No differential voltage possible: every transmitter sees bit errors, error counters climb to BUS OFF."),
              ("rate", "Body ECU configured for 250 kbit/s", "It misreads every frame and destroys them with error flags until it goes error-passive."),
              ("babble", "Brake ECU babbling on ID 0x000", "A stuck node flooding the highest priority ID starves every other message (the 'babbling idiot')."),
              ("stub", "3 m stub to the dashboard", "Stubs longer than ~0.3 m at 500 kbit/s reflect: ringing and occasional CRC errors.")]
    spec = [("Standard", "ISO 11898-1 (data link), ISO 11898-2 (high-speed PHY)"), ("Signalling", "Differential: recessive 0 V (both 2.5 V), dominant 2 V (CAN_H 3.5 V, CAN_L 1.5 V)"),
            ("Rate / length", "1 Mbit/s at 40 m, 500 kbit/s at 100 m, 125 kbit/s at 500 m"), ("Access", "CSMA/CR: bitwise arbitration on the identifier, dominant (0) wins, no frame lost"),
            ("Error handling", "CRC-15, bit, stuff, form and ACK checks; error frames; TEC/REC fault confinement"),
            ("Termination", "120 Ω at each end (60 Ω measured across CAN_H/CAN_L with power off)"), ("Connector", "No single standard: DB9 (CiA 106: pin 7 CAN_H, 2 CAN_L), M12, Deutsch, OBD")]
    frame = [["Classical CAN data frame", ("SOF", 1), ("Identifier", 11), ("RTR", 1), ("IDE", 1), ("r0", 1), ("DLC", 4), ("Data", "0-64"), ("CRC", 15), ("DEL", 1), ("ACK", 1), ("DEL", 1), ("EOF", 7)]]
    about = ("CAN is a multi-master bus in which every frame is a broadcast and the identifier doubles as its priority. All nodes send their identifiers "
             "bit by bit; a 0 (dominant) overwrites a 1 (recessive), and a node that reads back a 0 while sending a 1 drops out of arbitration "
             "without destroying the winning frame. Every receiver checks the frame and the first error it sees is announced with an error flag that "
             "makes everybody discard the frame; error counters isolate a faulty node so it cannot drag the bus down.")
    guide = ["Probe CAN_H (CH1) and CAN_L (CH2), MATH on: recessive both 2.5 V, dominant 3.5 / 1.5 V.",
             "Set speed to 1/1000x and watch frames queue. The STATS tab counts arbitration losses.",
             "In LOGIC look for the red 'S' markers: stuff bits after five equal bits.",
             "Pull one terminator: almost nothing changes. Pull the second: the recessive edges crawl back and frames turn red.",
             "Power off every node except one: the lone transmitter gets ACK errors and its TEC climbs (STATS chart).",
             "Inject the 250 kbit/s fault and watch the Body ECU's REC rise to error passive, after which the bus heals."]

    def setup(self):
        nodes = [self.node("eng", "ENGINE ECU", "ecu", 40, 60, "0x0C0 10 ms"), self.node("brk", "BRAKE ECU", "ecu", 270, 60, "0x1A0 20 ms"),
                 self.node("body", "BODY ECU", "ecu", 500, 60, "0x3E0 100 ms"), self.node("dash", "INSTRUMENT", "display", 160, 290, "0x500 1 s"),
                 self.node("tool", "CAN INTERFACE", "tool", 620, 290, "PC tool")]
        for n in nodes[3:]:
            n.at_top()
        self.can_trunk(nodes, 200, 30, 850, "CAN twisted pair 40 m, 120 Ω Zc")
        self.user = "tool"
        self.rpm, self.spd = 820.0, 0.0
        self.by["eng"].vars.update({"RPM": 820.0, "Throttle %": 4.0, "Coolant C": 86.0})
        self.by["eng"].ctl = [("Throttle %", "THROTTLE", 0.0, 100.0, 0, lambda v: "%.0f%%" % v)]
        self.by["brk"].vars.update({"Wheel speed km/h": 0.0, "Brake pressure bar": 0.0})
        self.by["brk"].ctl = [("Brake pressure bar", "BRAKE", 0.0, 150.0, 0, lambda v: "%.0f" % v)]
        self.by["body"].vars.update({"Doors": "closed", "Lights": "off"})
        self.by["dash"].vars.update({"Shown RPM": 0, "Shown speed": 0})
        self.every(0.010, self.eng_tx, 0.001)
        self.every(0.020, self.brk_tx, 0.003)
        self.every(0.100, self.body_tx, 0.007)
        self.every(1.0, self.dash_tx, 0.02)

    def eng_tx(self):
        e = self.by["eng"]
        thr = e.vars["Throttle %"]
        self.rpm += ((800 + thr * 55) - self.rpm) * 0.05
        e.vars["RPM"] = round(self.rpm, 1)
        raw = int(self.rpm * 4)
        data = bytes([raw >> 8, raw & 255, int(thr * 2.55), int(e.vars["Coolant C"] + 40), 0, 0, 0, 0])

        def dis(b, off, raw=raw):
            b.rows.append([0, "Engine status (vendor DBC)", off, 8, "Signals decoded with the network database (DBC)."])
            b.rows.append([1, "EngineSpeed: %.1f rpm (raw %d x 0.25)" % (raw / 4.0, raw), off, 2, "16-bit big-endian, 0.25 rpm/bit"])
            b.rows.append([1, "Throttle: %.0f %%" % (data[2] / 2.55), off + 2, 1, "0.392 %/bit"])
            b.rows.append([1, "Coolant: %d degC" % (data[3] - 40), off + 3, 1, "1 degC/bit, offset -40"])
        self.bus.send("eng", 0x0C0, data, info="EngineStatus rpm=%.0f thr=%.0f%%" % (self.rpm, thr), dissect=dis)

    def brk_tx(self):
        b_ = self.by["brk"]
        thr = self.by["eng"].vars["Throttle %"]
        p = b_.vars["Brake pressure bar"]
        self.spd = max(0.0, min(180.0, self.spd + (thr * 0.002 - p * 0.004 - 0.002)))
        b_.vars["Wheel speed km/h"] = round(self.spd, 1)
        v = int(self.spd * 100)
        data = bytes([v >> 8, v & 255, v >> 8, v & 255, int(min(255, p)), 0])
        if self.fault["babble"]:
            return
        self.bus.send("brk", 0x1A0, data, info="WheelSpeeds %.1f km/h p=%d bar" % (self.spd, p))

    def body_tx(self):
        self.bus.send("body", 0x3E0, bytes([0x00, 0x00, 0x10, 0x00]), info="BodyStatus doors closed")

    def dash_tx(self):
        self.bus.send("dash", 0x500, bytes([0x01]), info="Heartbeat instrument cluster", kind="sync")

    def babble(self):
        if self.fault["babble"] and self.by["brk"].on:
            self.bus.send("brk", 0x000, bytes([0xFF] * 8), info="BABBLE ID 0x000", kind="err")
            self.at(self.t + 0.00026, self.babble)

    def can_fault(self, key, on):
        if key == "rate":
            (self.bus.bad_rate.add if on else self.bus.bad_rate.discard)("body")
        if key == "short":
            self.bus.shorted = on
        if key == "babble" and on:
            self.babble()

    def rx(self, fr):
        if fr.err:
            return
        d = self.by["dash"]
        if fr.key == "0xC0":
            d.vars["Shown RPM"] = int(self.rpm)
        if fr.key == "0x1A0":
            d.vars["Shown speed"] = int(self.spd)

    def tpls(self):
        return self.generic_tpls("tool")


# ================================================================== CAN FD
class CANFD(CanNet):
    key, name, cat = "canfd", "CAN FD", "phys"
    blurb = "Higher-capacity CAN communication"
    rate, drate = 500000, 2000000
    can_proto = "CAN FD"
    medium = "ISO 11898-1:2015 CAN FD, 500 kbit/s arbitration / 2 Mbit/s data phase, up to 64 data bytes"
    faults = [("classic", "Classical CAN node attached", "A pre-FD controller sees the FDF bit as a reserved bit, flags a form error and destroys every FD frame (use 'FD-tolerant' or FD-capable controllers)."),
              ("rate", "Radar ECU data phase set to 5 Mbit/s", "The data-phase bit rates disagree: CRC / stuff errors on the radar's frames."),
              ("no_term0", "Terminator missing (left end)", "At 2 Mbit/s in the data phase reflections matter much more than in classical CAN."),
              ("no_term1", "Terminator missing (right end)", "Both missing: the fast data phase fails first.")]
    spec = [("Standard", "ISO 11898-1:2015 (ISO CAN FD), ISO 11898-2:2016"), ("Payload", "0-8, 12, 16, 20, 24, 32, 48 or 64 bytes"),
            ("Bit rates", "Arbitration phase like classical CAN (<= 1 Mbit/s); data phase 2, 5 or 8 Mbit/s"),
            ("New bits", "FDF (FD format), BRS (bit-rate switch), ESI (error state), stuff count"), ("CRC", "CRC-17 (<= 16 bytes) or CRC-21, includes stuff bits; fixed stuff bits in the CRC field"),
            ("Compatibility", "Classical CAN controllers cannot coexist on an FD bus unless FD-tolerant")]
    frame = [["CAN FD frame", ("SOF", 1), ("ID", 11), ("RRS", 1), ("IDE", 1), ("FDF", 1), ("res", 1), ("BRS", 1), ("ESI", 1), ("DLC", 4), ("Data", "0-512"), ("Stuff cnt", 4), ("CRC", "17/21"), ("ACK..EOF", 10)]]
    about = ("CAN FD keeps CAN's arbitration but, once arbitration is won, switches to a faster bit rate for the data and allows up to 64 bytes per frame. "
             "Effective throughput rises 5-8x. The CRC was strengthened (17 or 21 bits) and the number of stuff bits is now transmitted so a "
             "lost stuff bit cannot slip through. Here a camera and a radar stream object lists to the central computer.")
    guide = ["Select an FD frame and look at the SCOPE: bits are 2 us wide in the header, then 0.5 us wide in the data phase.",
             "Compare the ANALYZER 'Len' column with classical CAN: 64-byte frames.",
             "Attach a classical node: every FD frame becomes an error frame.",
             "In LOGIC note the fixed stuff bits ('S') every four bits in the CRC field."]

    def setup(self):
        nodes = [self.node("cam", "CAMERA ECU", "camera", 40, 60, "0x120 64 B / 33 ms"), self.node("rad", "RADAR ECU", "radar", 300, 60, "0x121 48 B / 50 ms"),
                 self.node("cc", "CENTRAL COMPUTER", "ecu", 560, 60, "receiver"), self.node("tool", "CAN FD TOOL", "tool", 300, 290, "PC tool"),
                 self.node("old", "LEGACY ECU", "ecu", 600, 290, "classical CAN 2.0")]
        nodes[3].at_top()
        nodes[4].at_top()
        nodes[4].on = False
        nodes[4].sub = "unplugged"
        self.can_trunk(nodes, 200)
        self.user = "tool"
        self.n = 0
        self.by["cam"].vars.update({"Objects": 6})
        self.by["cam"].ctl = [("Objects", "OBJECTS", 0, 10, 1, lambda v: "%d" % v)]
        self.every(0.033, self.cam, 0.001)
        self.every(0.050, self.radar, 0.004)

    def cam(self):
        self.n += 1
        nobj = int(self.by["cam"].vars["Objects"])
        data = bytes([self.n & 255, nobj]) + bytes((i * 37 + self.n) & 255 for i in range(62))
        self.bus.send("cam", 0x120, data, fd=True, brs=True, info="ObjectList #%d %d objects (64 B)" % (self.n, nobj))

    def radar(self):
        data = bytes((i * 11 + self.n) & 255 for i in range(48))
        self.bus.send("rad", 0x121, data, fd=True, brs=True, info="RadarTargets (48 B)")

    def can_fault(self, key, on):
        if key == "classic":
            o = self.by["old"]
            o.on = on
            o.sub = "classical CAN 2.0" if on else "unplugged"
            (self.bus.classic.add if on else self.bus.classic.discard)("old")
        if key == "rate":
            (self.bus.bad_rate.add if on else self.bus.bad_rate.discard)("rad")

    def tpls(self):
        return [Tpl("CAN FD frame", [P("id", "Identifier", 0x200, 0, 0x7FF), P("len", "Length", 64, 0, 64), P("brs", "Bit-rate switch", "on", opts=["on", "off"])],
                    lambda s, v, send: self._fd(v, send), "Lengths are rounded up to the next valid FD size (12, 16, 20, 24, 32, 48, 64).")] + self.generic_tpls("tool")

    def _fd(self, v, send):
        data = bytes(range(v["len"]))
        brs = v["brs"] == "on"
        if send:
            self.bus.send("tool", v["id"], data, fd=True, brs=brs, info="FD 0x%03X len %d %s" % (v["id"], len(data), "BRS" if brs else ""), kind="cmd")
            return None
        return self.preview_can("tool", v["id"], data, fd=True, brs=brs)


# ================================================================ Ethernet
def icmp_pdu(typ, code, ident, seq, data):
    body = bytes([typ, code, 0, 0]) + ident.to_bytes(2, "big") + seq.to_bytes(2, "big") + data
    cs = B.inet_cs(body)
    b = Bld("Internet Control Message Protocol", "RFC 792: diagnostics and error reports for IP (ping, unreachable, time exceeded).")
    b.u8("Type", typ, {8: "8 (Echo request)", 0: "0 (Echo reply)", 3: "3 (Destination unreachable)", 11: "11 (Time exceeded)"}.get(typ, str(typ)), "")
    b.u8("Code", code, None, "")
    b.u16("Checksum", cs, "0x%04X [correct]" % cs, "Internet checksum over the ICMP message")
    b.u16("Identifier", ident, None, "Matches replies to the pinging process")
    b.u16("Sequence", seq, None, "Increments per ping")
    b.raw("Data", data, "%d bytes" % len(data), "Echo payload, returned unchanged")
    return b.done()


def arp_pdu(op, smac, sip, tmac, tip):
    b = Bld("Address Resolution Protocol (%s)" % ("request" if op == 1 else "reply"), "RFC 826: finds the MAC address that owns an IPv4 address on the local link.")
    b.u16("Hardware type", 1, "Ethernet (1)", "")
    b.u16("Protocol type", 0x0800, "IPv4 (0x0800)", "")
    b.u8("Hardware size", 6, None, "")
    b.u8("Protocol size", 4, None, "")
    b.u16("Opcode", op, "request (1)" if op == 1 else "reply (2)", "")
    b.f("Sender MAC", macb(smac), smac, "")
    b.f("Sender IP", B.be(int.from_bytes(bytes(map(int, sip.split("."))), "big"), 4), sip, "")
    b.f("Target MAC", macb(tmac), tmac, "Unknown (zero) in a request")
    b.f("Target IP", bytes(map(int, tip.split("."))), tip, "")
    return b.done()


class Ethernet(Scenario):
    key, name, cat = "ethernet", "Ethernet (IEEE 802.3)", "phys"
    blurb = "Industrial and computer networks"
    phy, rate = "eth100", 100e6
    medium = "IEEE 802.3 100BASE-TX / 1000BASE-T switched LAN, Cat5e/Cat6, full duplex"
    nets = [("TX", "100BASE-TX pair 1-2 (MLT-3 after 4B/5B and scrambling)")]
    lines = ["M"]
    faults = [("duplex", "Duplex mismatch on the server port", "The server is forced to 100 full, the switch auto-negotiates and falls back to half duplex: late collisions and FCS errors, terrible throughput."),
              ("pair", "Broken pair in the PC's cable", "Gigabit needs all four pairs; with one broken, autonegotiation drops to 100 Mbit/s (or the link flaps)."),
              ("noise", "Damaged cable near a VFD (noise)", "Bit errors corrupt frames; receivers drop them silently on a bad FCS."),
              ("loop", "Patch cable loops two switch ports (no STP)", "Broadcasts circulate forever and multiply: a broadcast storm saturates the network.")]
    spec = [("Standard", "IEEE 802.3 (10BASE-T, 100BASE-TX, 1000BASE-T, 10GBASE-T...)"), ("Media", "Cat5e/Cat6 UTP/STP, 100 m per segment, RJ45 (8P8C)"),
            ("Line codes", "10BASE-T Manchester; 100BASE-TX 4B/5B + MLT-3; 1000BASE-T PAM-5 on 4 pairs, full duplex with echo cancellation"),
            ("Frame", "Preamble 7 x 55, SFD D5, MAC dst/src, (802.1Q tag), EtherType, 46-1500 bytes, CRC-32 FCS"),
            ("Access", "Switched full duplex (no collisions); CSMA/CD only on hubs / half duplex"), ("Gap", "96 bit times minimum inter-frame gap")]
    frame = [["Ethernet II frame", ("Preamble", 56), ("SFD", 8), ("Dst MAC", 48), ("Src MAC", 48), ("802.1Q", "opt 32"), ("Type", 16), ("Payload", "46-1500 B"), ("FCS", 32)]]
    about = ("Ethernet frames carry 48-bit MAC addresses and an EtherType that says what is inside. A switch learns which port each MAC lives on and "
             "forwards frames only there; broadcasts go everywhere. Every link is full duplex, so there are no collisions - unless a duplex mismatch "
             "or a hub brings CSMA/CD back. On the wire, 100BASE-TX encodes each 4 bits as 5, scrambles them and sends them as three-level MLT-3.")
    guide = ["Select a ping frame: Ethernet II > IPv4 > ICMP in the tree; click the FCS row to see its 4 bytes.",
             "Open SCOPE + AUTOSET on a short frame: MLT-3 steps between -1, 0 and +1 V.",
             "Open SPECTRUM: MLT-3 concentrates energy below about 31 MHz although the symbol rate is 125 Mbaud - that is why it was chosen.",
             "Inject the duplex mismatch and filter on 'err'.",
             "Inject the loop fault and watch the bus load meter in STATS hit the stops."]

    def build(self):
        self.lan = Lan(self, 100e6, "eth100")
        sw = self.node("sw", "SWITCH", "switch", 380, 160, "24-port L2", "", w=130, h=52)
        hosts = [("pc", "WORKSTATION", "pc", 60, 40, "192.168.1.10", "00:1b:21:3a:4f:01"), ("srv", "FILE SERVER", "server", 700, 40, "192.168.1.20", "00:25:90:aa:10:02"),
                 ("cam", "IP CAMERA", "camera", 60, 300, "192.168.1.40", "ac:cc:8e:11:22:03"), ("prn", "PRINTER", "box", 700, 300, "192.168.1.30", "00:80:77:3c:9d:04")]
        for nid, lab, kind, x, y, ip, mac in hosts:
            n = self.node(nid, lab, kind, x, y, ip, mac[-8:])
            self.lan.host(nid, mac, ip)
            n.vars.update({"IP": ip, "MAC": mac, "Link": "1000 Mbit/s full" if nid != "cam" else "100 Mbit/s full"})
            top = y < 160
            n.port = (x + n.w / 2, y + n.h) if top else (x + n.w / 2, y)
            yy = 176 if top else 196
            ex = sw.x if x < 380 else sw.x + sw.w
            self.seg([n.port, (n.port[0], yy), (ex, yy)], "cat6" if nid != "cam" else "cat5", net="TX", c0="rj45", c1="rj45",
                     label="Cat6 15 m" if nid == "pc" else "")
        bp = (40, 40, 44)
        self.seg([(sw.x, 176), (sw.x, 196)], "cat6", w=1, col=bp)
        self.seg([(sw.x, 196), (sw.x + sw.w, 196)], "cat6", w=1, col=bp)
        self.seg([(sw.x + sw.w, 196), (sw.x + sw.w, 176)], "cat6", w=1, col=bp)
        sw.port = (sw.x, 176)
        self.lan.mac["sw"] = "00:1a:2b:00:00:ff"
        self.user = "pc"
        self.ping_seq = 0
        self.arp_done = set()
        self.by["srv"].vars["Pings answered"] = 0
        self.by["pc"].vars["Ping RTT"] = "-"
        self.every(1.0, self.ping, 0.2)
        self.every(0.020, self.video, 0.01)
        self.every(7.0, self.bcast, 3.0)

    def eth(self, src, dst, et, inner, info, proto, kind="data", err=None, dmac=None, vlan=None):
        if err is None:
            if self.fault["noise"] and self.rng.random() < 0.15:
                err = "FCS error: frame corrupted by noise, dropped by receiver"
            elif self.fault["duplex"] and "srv" in (src, dst) and self.rng.random() < 0.35:
                err = "Late collision / FCS error (duplex mismatch)"
        return self.lan.l2(src, dst, et, inner, info, proto, kind, err=err, dmac=dmac, vlan=vlan)

    def arp(self, src, dst):
        sip, tip = self.lan.ip[src], self.lan.ip[dst]
        self.eth(src, None, 0x0806, arp_pdu(1, self.lan.mac[src], sip, "00:00:00:00:00:00", tip), "Who has %s? Tell %s" % (tip, sip), "ARP", "bcast",
                 dmac="ff:ff:ff:ff:ff:ff")

        def rep():
            self.eth(dst, src, 0x0806, arp_pdu(2, self.lan.mac[dst], tip, self.lan.mac[src], sip), "%s is at %s" % (tip, self.lan.mac[dst]), "ARP", "resp")
        self.at(self.t + 0.0002, rep)

    def ping(self, dst="srv", size=56):
        if not self.by["pc"].on:
            return
        if dst not in self.arp_done:
            self.arp("pc", dst)
            self.arp_done.add(dst)
            self.at(self.t + 0.001, self.ping, dst, size)
            return
        self.ping_seq += 1
        data = bytes((0x10 + i) & 255 for i in range(size))
        sip, tip = self.lan.ip["pc"], self.lan.ip[dst]
        fr = self.eth("pc", dst, 0x0800, ipv4_pdu(sip, tip, 1, icmp_pdu(8, 0, 0x1F2E, self.ping_seq, data), ident=self.ping_seq),
                      "Echo (ping) request id=0x1f2e seq=%d" % self.ping_seq, "ICMP", "cmd")
        fr.meta["seq"] = self.ping_seq
        fr.meta["data"] = data
        fr.meta["dst"] = dst
        return fr

    def video(self):
        if not self.by["cam"].on:
            return
        b = Bld("RTP video (H.264 slice)", "Real-time Transport Protocol carrying a video slice.")
        b.raw("RTP payload", bytes(200), "200 bytes", "Compressed video data")
        from .fam import udp_pdu
        sip, tip = self.lan.ip["cam"], self.lan.ip["srv"]
        self.eth("cam", "srv", 0x0800, ipv4_pdu(sip, tip, 17, udp_pdu(5004, 5004, b.done(), sip, tip)), "RTP video 5004 → 5004 len 200", "UDP", "data")

    def bcast(self):
        self.arp("prn", "srv")
        if self.fault["loop"]:
            for k in range(60):
                self.at(self.t + 0.0003 * (k + 1), self.storm)

    def storm(self):
        if not self.fault["loop"]:
            return
        self.eth("prn", None, 0x0806, arp_pdu(1, self.lan.mac["prn"], "192.168.1.30", "00:00:00:00:00:00", "192.168.1.20"),
                 "Who has 192.168.1.20? (looping copy)", "ARP", "err", err="Broadcast storm: frame looped back by the switch", dmac="ff:ff:ff:ff:ff:ff")
        self.at(self.t + 0.0004, self.storm)

    def on_fault(self, key, on):
        if key == "pair":
            self.by["pc"].vars["Link"] = "100 Mbit/s full (downshift: pair 3/6 broken)" if on else "1000 Mbit/s full"
        if key == "duplex":
            self.by["srv"].vars["Link"] = "100 Mbit/s FULL (forced) vs switch HALF" if on else "1000 Mbit/s full"
        if key == "loop" and on:
            self.storm()

    def rx(self, fr):
        if fr.proto == "ICMP" and fr.kind == "cmd" and not fr.err:
            dst = fr.meta["dst"]
            if not self.by[dst].on:
                return
            sip, tip = self.lan.ip[dst], self.lan.ip["pc"]
            self.by[dst].vars["Pings answered"] = self.by[dst].vars.get("Pings answered", 0) + 1
            r = self.eth(dst, "pc", 0x0800, ipv4_pdu(sip, tip, 1, icmp_pdu(0, 0, 0x1F2E, fr.meta["seq"], fr.meta["data"]), ident=fr.meta["seq"] + 1000),
                         "Echo (ping) reply id=0x1f2e seq=%d" % fr.meta["seq"], "ICMP", "resp")
            r.meta["req_t"] = fr.t
        elif fr.proto == "ICMP" and fr.kind == "resp" and not fr.err:
            self.by["pc"].vars["Ping RTT"] = "%.3f ms" % ((self.t - fr.meta.get("req_t", self.t)) * 1000)

    def tpls(self):
        hosts = ["srv", "cam", "prn"]
        return [Tpl("Ping (ICMP echo)", [P("dst", "Destination", "srv", opts=hosts), P("size", "Data bytes", 56, 0, 1472)],
                    lambda s, v, send: self.ping(v["dst"], v["size"]) if send else self._pv(v), "ICMP echo request; the target answers with an echo reply. 1472 bytes fills a 1500-byte MTU."),
                Tpl("ARP request", [P("dst", "Target", "prn", opts=hosts)], lambda s, v, send: self.arp("pc", v["dst"]) if send else
                    self.lan.frame("pc", None, eth_pdu("ff:ff:ff:ff:ff:ff", self.lan.mac["pc"], 0x0806, arp_pdu(1, self.lan.mac["pc"], "192.168.1.10", "00:00:00:00:00:00", self.lan.ip[v["dst"]])), "ARP", "ARP"),
                    "Broadcast 'who has' query."),
                Tpl("Raw frame with VLAN tag", [P("vid", "VLAN ID", 10, 1, 4094), P("pcp", "Priority (PCP)", 5, 0, 7), P("et", "EtherType", 0x88B5, 0x0600, 0xFFFF), P("data", "Payload (hex)", "DE AD BE EF")],
                    lambda s, v, send: self._raw(v, send), "Hand-built 802.1Q-tagged frame; 0x88B5 is the IEEE 'local experimental' EtherType.")]

    def _pv(self, v):
        sip, tip = self.lan.ip["pc"], self.lan.ip[v["dst"]]
        return self.lan.frame("pc", v["dst"], eth_pdu(self.lan.mac[v["dst"]], self.lan.mac["pc"], 0x0800,
                              ipv4_pdu(sip, tip, 1, icmp_pdu(8, 0, 0x1F2E, self.ping_seq + 1, bytes(v["size"])))), "Echo request", "ICMP")

    def _raw(self, v, send):
        b = Bld("Data", "Raw payload")
        b.raw("Payload", hexdata(v["data"], 1500), None, "")
        if send:
            return self.eth("pc", None, v["et"], b.done(), "Raw 802.1Q VID %d PCP %d type 0x%04X" % (v["vid"], v["pcp"], v["et"]), "Ethernet", "cmd",
                            dmac="ff:ff:ff:ff:ff:ff", vlan=(v["pcp"], v["vid"]))
        return self.lan.frame("pc", None, eth_pdu("ff:ff:ff:ff:ff:ff", self.lan.mac["pc"], v["et"], b.done(), (v["pcp"], v["vid"])), "Raw", "Ethernet")


# ===================================================================== SPI
FLASH = b"COMM-SIM SPI NOR FLASH. Sector 0 holds this text; read it with command 0x03. " * 3


class SPI(Scenario):
    key, name, cat = "spi", "SPI", "phys"
    blurb = "High-speed, short-distance chip communication"
    phy, rate = "spi", 8e6
    medium = "4-wire SPI on a PCB: SCLK, MOSI, MISO, one chip select per slave, mode 0 (CPOL 0, CPHA 0)"
    nets = [("SCLK", "serial clock"), ("MOSI", "master out, slave in"), ("MISO", "master in, slave out"), ("CS0", "flash chip select (active low)"), ("CS1", "ADC chip select")]
    lines = ["CS0", "CS1", "SCLK", "MOSI", "MISO"]
    faults = [("mode", "MCU set to SPI mode 1 (CPHA = 1)", "The master samples MISO on the opposite clock edge from where the slave changes it: every byte comes back shifted by one bit."),
              ("miso", "MISO trace open", "Nothing drives the master's input; with its pull-up it reads 0xFF."),
              ("cs", "Both chip selects asserted together", "Two slaves drive MISO at once: contention, garbage data and extra supply current."),
              ("fast", "ADC clocked at 8 MHz (max 1.35 MHz at 2.7 V)", "The ADC cannot settle its output in time: conversion bits arrive wrong.")]
    spec = [("Signals", "SCLK, MOSI, MISO, /CS per slave (active low)"), ("Modes", "CPOL (clock idle level) x CPHA (sample on 1st or 2nd edge) = modes 0-3"),
            ("Speed", "Tens of MHz typical, >100 MHz for flash in quad mode"), ("Distance", "Same board / short cable"), ("Framing", "None: chip select brackets a transaction; MSB first usually"),
            ("Duplex", "Full duplex: one bit out and one bit in on every clock")]
    frame = [["Flash read (0x03)", ("CMD 03", 8), ("ADDR A23-A0", 24), ("DATA ...", "n x 8")], ["MCP3008 conversion", ("start 01", 8), ("SGL+CH", 8), ("don't care", 8)]]
    about = ("SPI is a synchronous shift register shared between a master and a slave: on every clock edge one bit leaves on MOSI and one arrives on MISO. "
             "There is no addressing - the master lowers the chip select of the slave it wants. The clock polarity and phase (the 'mode') must match "
             "the slave's datasheet or every byte is misread.")
    guide = ["In LOGIC, read the JEDEC ID transaction: MOSI 9F then MISO EF 40 16 (Winbond, SPI flash, 32 Mbit).",
             "Change to SPI mode 1 (fault): the ID comes back as F7 A0 0B - each byte shifted.",
             "Probe SCLK and MOSI on the SCOPE; data changes on the falling edge and is stable on the rising edge (mode 0).",
             "Use COMPOSE to read flash memory or an ADC channel."]

    def build(self):
        m = self.node("mcu", "MCU", "mcu", 60, 150, "SPI master", "8 MHz").at_right()
        f = self.node("flash", "SPI FLASH", "flash", 650, 40, "W25Q32 (CS0)", "32 Mbit").at_left()
        a = self.node("adc", "ADC", "adc", 650, 270, "MCP3008 (CS1)", "10-bit, 8 ch").at_left()
        self.seg([m.port, (420, m.port[1]), (420, f.port[1]), f.port], "trace", net="MOSI", label="PCB traces 4 cm")
        self.seg([(420, m.port[1]), (420, a.port[1]), a.port], "trace", net="MISO")
        self.user = "mcu"
        a.vars.update({"CH0 V": 1.65, "CH1 V": 0.42})
        a.ctl = [("CH0 V", "CH0", 0.0, 3.3, 0, lambda v: "%.3f V" % v), ("CH1 V", "CH1", 0.0, 3.3, 0, lambda v: "%.3f V" % v)]
        f.vars.update({"JEDEC ID": "EF 40 16", "Status reg": "0x00"})
        m.vars.update({"Last result": "-"})
        self.every(0.25, lambda: self.jedec(), 0.02)
        self.every(0.1, lambda: self.adc(0), 0.05)

    def xfer(self, cs, mosi, miso, info, clk, err=None):
        """Mode-0 SPI transaction waveform."""
        tb = 1.0 / clk
        shift = self.fault["mode"]
        rd = list(miso)
        if self.fault["miso"]:
            rd = [0xFF] * len(rd)
        elif self.fault["cs"]:
            rd = [(x ^ 0x5A) & 0xFF for x in rd]
        shown = list(rd)
        if shift:
            allb = []
            for x in rd:
                allb += msb(x, 8)
            allb = allb[1:] + [1]
            shown = [bits_to_int(allb[i:i + 8]) for i in range(0, len(allb), 8)]
        b = Bld("SPI transaction (%s)" % ("CS0 flash" if cs == "CS0" else "CS1 ADC"), "Full-duplex shift: one MOSI byte out, one MISO byte in per 8 clocks.")
        b.raw("MOSI", bytes(mosi), None, "Bytes from master to slave (command, address, dummy)")
        b.raw("MISO", bytes(shown), None, "Bytes from slave to master as the master sampled them")
        pdu = b.done()
        n = len(mosi)
        dur = (n * 8 + 4) * tb

        def wf(fr):
            w = Wire(bit=tb)
            for ln in ("SCLK", "MOSI", "MISO", "CS0", "CS1"):
                w.set(ln, 0.0, 0 if ln == "SCLK" else 1)
            t = tb
            w.set(cs, t, 0)
            if self.fault["cs"]:
                w.set("CS1" if cs == "CS0" else "CS0", t, 0)
            t += tb
            for i in range(n):
                t0 = t
                for k in range(8):
                    w.set("MOSI", t, (mosi[i] >> (7 - k)) & 1)
                    w.set("MISO", t, (rd[i] >> (7 - k)) & 1)
                    w.set("SCLK", t + tb / 2, 1)
                    w.set("SCLK", t + tb, 0)
                    w.marks.append((t + (tb if shift else tb / 2), ""))
                    t += tb
                w.seg(t0, t, "%02X" % mosi[i], 0, 1)
                w.seg(t0, t, "%02X" % shown[i], 1, 0)
            w.set(cs, t + tb / 2, 1)
            w.set("CS1" if cs == "CS0" else "CS0", t + tb / 2, 1)
            w.end(t + tb)
            return w
        return Frame(self.t, dur, "mcu", "flash" if cs == "CS0" else "adc", "SPI", info, pdu=pdu, err=err, kind="cmd", wirefn=wf, key=info.split(":")[0])

    def jedec(self, send=True):
        fr = self.xfer("CS0", [0x9F, 0, 0, 0], [0xFF, 0xEF, 0x40, 0x16], "JEDEC ID: EF 40 16", 8e6,
                       err="Wrong SPI mode: data shifted one bit" if self.fault["mode"] else ("MISO floating" if self.fault["miso"] else None))
        if self.fault["mode"]:
            fr.info = "JEDEC ID: F7 A0 0B (expected EF 40 16)"
        return self.tx(fr) if send else fr

    def adc(self, ch, send=True):
        a = self.by["adc"]
        v = a.vars.get("CH%d V" % ch, 0.0)
        code = max(0, min(1023, int(v / 3.3 * 1023)))
        err = None
        if self.fault["fast"]:
            code ^= 0x0A5
            err = "ADC clocked beyond its rating: wrong conversion bits"
        fr = self.xfer("CS1", [0x01, 0x80 | (ch << 4), 0x00], [0xFF, (code >> 8) & 3, code & 255], "ADC CH%d: %d (%.3f V)" % (ch, code, code * 3.3 / 1023),
                       8e6 if self.fault["fast"] else 1e6, err)
        if send:
            self.by["mcu"].vars["Last result"] = fr.info
            return self.tx(fr)
        return fr

    def read(self, addr, n, send=True):
        data = (FLASH * 4)[addr:addr + n]
        fr = self.xfer("CS0", [0x03, (addr >> 16) & 255, (addr >> 8) & 255, addr & 255] + [0] * n, [0xFF] * 4 + list(data),
                       "READ 0x%06X: %s" % (addr, data[:16].decode("ascii", "replace")), 8e6)
        return self.tx(fr) if send else fr

    def tpls(self):
        return [Tpl("Read JEDEC ID (0x9F)", [], lambda s, v, send: self.jedec(send), "Manufacturer, memory type and capacity bytes."),
                Tpl("Read data (0x03)", [P("a", "Address", 0, 0, 0xFFFFFF), P("n", "Bytes", 16, 1, 64)], lambda s, v, send: self.read(v["a"], v["n"], send),
                    "Command 0x03 + 24-bit address, then the flash streams bytes while CS stays low."),
                Tpl("Read status (0x05)", [], lambda s, v, send: (self.tx if send else (lambda f: f))(self.xfer("CS0", [0x05, 0], [0xFF, 0x00], "STATUS: 0x00 (not busy, unprotected)", 8e6)), "Status register 1: BUSY, WEL, block protect bits."),
                Tpl("ADC conversion", [P("ch", "Channel", 0, 0, 7)], lambda s, v, send: self.adc(v["ch"], send), "Start bit, single-ended + channel, then 10 result bits.")]


# ===================================================================== I2C
class I2C(Scenario):
    key, name, cat = "i2c", "I²C", "phys"
    blurb = "Sensors and integrated circuits"
    phy, rate = "i2c", 100000
    medium = "I²C at 100 kHz, open-drain SDA/SCL with 4.7 kΩ pull-ups to 3.3 V, ~150 pF bus"
    nets = [("SCL", "serial clock"), ("SDA", "serial data")]
    lines = ["SCL", "SDA"]
    faults = [("nopull", "Pull-up resistors missing", "Open-drain outputs can only pull low: with nothing pulling high the bus never leaves 0 V. Every transfer fails."),
              ("weak", "47 kΩ pull-ups at 400 kHz", "Rise time = R x C: 47 kΩ x 150 pF = 7 µs. At 400 kHz a bit lasts 2.5 µs: the lines never reach a valid high."),
              ("dup", "Second TMP102 also at 0x48", "Both ACK and both drive data: the wired-AND mixes their bits into nonsense."),
              ("stuck", "RTC holding SDA low after a reset", "A slave interrupted mid-byte keeps SDA low; the master must clock SCL up to 9 times until it lets go."),
              ("stretch", "RTC clock stretching", "A slow slave holds SCL low to make the master wait - legal, but it slows the bus.")]
    spec = [("Standard", "NXP UM10204 I²C-bus specification (SMBus / PMBus are close relatives)"), ("Signals", "SDA, SCL - open drain with pull-up resistors"),
            ("Speed", "100 kHz standard, 400 kHz fast, 1 MHz fast-plus, 3.4 MHz high-speed"), ("Addressing", "7-bit (or 10-bit) address + R/W bit after START"),
            ("Bus capacitance", "Max 400 pF; rise time limit 1000 ns (100 kHz) / 300 ns (400 kHz)"), ("Handshake", "Receiver pulls SDA low in the 9th clock = ACK; high = NACK"),
            ("Conditions", "START: SDA falls while SCL high. STOP: SDA rises while SCL high.")]
    frame = [["Write pointer + read (repeated START)", ("S", 1), ("ADDR 7", 7), ("W", 1), ("A", 1), ("REG", 8), ("A", 1), ("Sr", 1), ("ADDR", 7), ("R", 1), ("A", 1), ("DATA", 8), ("A", 1), ("DATA", 8), ("N", 1), ("P", 1)]]
    about = ("I²C uses two open-drain wires shared by every chip. Nobody drives a line high - resistors pull it up and devices only pull it low, so "
             "conflicts are harmless (wired AND). Each transfer starts with a START condition and the 7-bit address of a chip; the addressed chip "
             "acknowledges by pulling SDA low in the ninth clock. Because rising edges come from resistors, bus capacitance limits the speed.")
    guide = ["On the SCOPE, compare rising edges (slow, RC curve from the pull-up) with falling edges (fast, transistor).",
             "In LOGIC, decode a temperature read: START, 0x48+W, ACK, 0x00, ACK, repeated START, 0x48+R, two data bytes.",
             "Inject the 47 kΩ / 400 kHz fault and look at the shark-fin edges.",
             "Use 'Scan bus' in COMPOSE: only addresses with a device return ACK.",
             "Inject the stuck-SDA fault, then send 'Bus recovery (9 clocks)'."]

    def build(self):
        m = self.node("mcu", "MCU", "mcu", 40, 150, "I2C master", "100 kHz").at_right()
        devs = [("tmp", "TEMP SENSOR", "temp", "0x48 TMP102", 290), ("rtc", "REAL-TIME CLOCK", "rtc", "0x68 DS1307", 500), ("eep", "EEPROM", "eeprom", "0x50 24C02", 700)]
        y = m.port[1]
        self.seg([m.port, (860, y)], "trace", net="SDA", label="SDA / SCL")
        for nid, lab, kind, addr, x in devs:
            n = self.node(nid, lab, kind, x - 30, 260, addr, "")
            n.at_top()
            self.seg([n.port, (n.port[0], y)], "trace", net="SDA")
        self.term(150, y - 40, "4k7 Ω x2", True, "pull", vert=True)
        self.user = "mcu"
        self.by["tmp"].vars.update({"Temperature C": 23.5})
        self.by["tmp"].ctl = [("Temperature C", "TEMP", -40.0, 125.0, 0, lambda v: "%.2f" % v)]
        self.by["rtc"].vars.update({"Time": "12:00:00"})
        self.eep = bytearray(b"COMM-SIM EEPROM 24C02 " + bytes(234))
        self.by["eep"].vars.update({"Byte 0..15": self.eep[:16].decode("ascii", "replace")})
        self.by["mcu"].vars.update({"Last read": "-", "NACKs": 0})
        self.every(0.25, self.read_temp, 0.02)
        self.every(1.0, self.read_rtc, 0.11)

    def cond(self, net):
        c = super().cond(net)
        if self.fault["weak"]:
            c["rise"] = 10.0
        return c

    def bus_hz(self):
        return 400000 if self.fault["weak"] else 100000

    def txn(self, parts, info, err=None, kind="cmd", dst=None):
        """parts: list of ('S'|'Sr'|'P') or (byte, ack_bit, who) where who = 'm' or 's'."""
        tb = 1.0 / self.bus_hz()
        stretch = self.fault["stretch"]
        b = Bld("I²C transfer", "START, address + R/W, data bytes each followed by ACK (0) or NACK (1), STOP.")
        for p in parts:
            if isinstance(p, tuple):
                byte, ack, who = p
                b.u8("Address" if who == "a" else ("Data (slave)" if who == "s" else "Data (master)"), byte,
                     ("0x%02X %s" % (byte >> 1, "Read" if byte & 1 else "Write")) if who == "a" else "0x%02X" % byte,
                     "7-bit address in the upper bits, R/W in bit 0" if who == "a" else "")
                b.note("%s" % ("ACK" if ack == 0 else "NACK"), "Ninth clock: receiver pulls SDA low to acknowledge", d=2)
        pdu = b.done()
        nbits = sum(9 if isinstance(p, tuple) else 1.5 for p in parts)
        dur = (nbits + 2) * tb * (1.3 if stretch else 1.0)
        nopull = self.fault["nopull"]

        def wf(fr):
            w = Wire(bit=tb)
            w.set("SCL", 0.0, 0 if nopull else 1)
            w.set("SDA", 0.0, 0 if nopull else 1)
            if nopull:
                w.seg(0, dur, "bus stuck at 0 V: no pull-ups", 8, 1)
                w.end(dur)
                return w
            t = tb
            for p in parts:
                if p in ("S", "Sr"):
                    if p == "Sr":
                        w.set("SDA", t, 1)
                        w.set("SCL", t + tb * 0.25, 1)
                        t += tb * 0.5
                    w.set("SDA", t, 0)
                    w.seg(t - tb * 0.2, t + tb * 0.4, p, 7, 1)
                    w.set("SCL", t + tb * 0.5, 0)
                    t += tb * 0.75
                elif p == "P":
                    w.set("SDA", t, 0)
                    w.set("SCL", t + tb * 0.3, 1)
                    w.set("SDA", t + tb * 0.7, 1)
                    w.seg(t + tb * 0.3, t + tb, "P", 7, 1)
                    t += tb
                else:
                    byte, ack, who = p
                    t0 = t
                    for k in range(9):
                        bit = (byte >> (7 - k)) & 1 if k < 8 else ack
                        w.set("SDA", t + tb * 0.1, bit)
                        w.set("SCL", t + tb * 0.5, 1)
                        hold = tb * (0.6 if stretch and who == "s" and k == 8 else 0.0)
                        w.set("SCL", t + tb + hold, 0)
                        t += tb + hold
                    lab = ("0x%02X %s" % (byte >> 1, "R" if byte & 1 else "W")) if who == "a" else "%02X" % byte
                    w.seg(t0, t - tb, lab, 0 if who == "a" else 1, 1)
                    w.seg(t - tb, t, "ACK" if ack == 0 else "NACK", 2 if ack == 0 else 8, 0)
            w.end(t + tb)
            return w
        return Frame(self.t, dur, "mcu", dst, "I2C", info, pdu=pdu, err=err, kind=kind, wirefn=wf, key=info.split(" ")[0] + " " + info.split(" ")[1] if " " in info else info)

    def read_temp(self, send=True):
        t = self.by["tmp"].vars["Temperature C"]
        raw = int(round(t * 16)) & 0xFFF
        hi, lo = raw >> 4, (raw & 15) << 4
        err = None
        if self.fault["nopull"]:
            err = "Bus stuck low: no pull-ups"
        elif self.fault["stuck"]:
            err = "Arbitration lost / bus busy: SDA held low by a slave"
        elif self.fault["weak"] and self.rng.random() < 0.6:
            err = "Bits misread: edges too slow for 400 kHz"
        elif self.fault["dup"]:
            hi, lo = hi & 0x3C, lo & 0x90
            err = "Two devices answered: data mixed by wired-AND"
        parts = ["S", (0x90, 0, "a"), (0x00, 0, "m"), "Sr", (0x91, 0, "a"), (hi, 0, "s"), (lo, 1, "s"), "P"]
        fr = self.txn(parts, "TMP102 read: %.4f degC" % (((hi << 4) | (lo >> 4)) / 16.0), err, dst="tmp")
        if send:
            self.by["mcu"].vars["Last read"] = fr.info
            return self.tx(fr)
        return fr

    def read_rtc(self):
        s = int(self.t) % 60
        bcd = lambda v: ((v // 10) << 4) | (v % 10)
        parts = ["S", (0xD0, 0, "a"), (0x00, 0, "m"), "Sr", (0xD1, 0, "a"), (bcd(s), 0, "s"), (bcd(0), 0, "s"), (bcd(12), 1, "s"), "P"]
        self.by["rtc"].vars["Time"] = "12:00:%02d" % s
        err = "Bus stuck low" if self.fault["nopull"] or self.fault["stuck"] else None
        self.tx(self.txn(parts, "DS1307 read: 12:00:%02d" % s, err, dst="rtc"))

    def scan(self, send=True):
        frs = []
        present = {0x48: "tmp", 0x68: "rtc", 0x50: "eep"}
        for a in (0x08, 0x20, 0x48, 0x50, 0x57, 0x68, 0x70):
            ack = 0 if a in present and not self.fault["nopull"] else 1
            fr = self.txn(["S", (a << 1, ack, "a"), "P"], "PROBE 0x%02X %s" % (a, "ACK" if ack == 0 else "NACK"), kind="cmd" if ack == 0 else "err",
                          dst=present.get(a))
            if send:
                self.tx(fr)
            frs.append(fr)
        return frs[2]

    def recover(self, send=True):
        tb = 1.0 / self.bus_hz()

        def wf(fr):
            w = Wire(bit=tb)
            w.set("SDA", 0.0, 0)
            w.set("SCL", 0.0, 1)
            t = tb
            for k in range(9):
                w.set("SCL", t, 0)
                w.set("SCL", t + tb / 2, 1)
                if k == 6:
                    w.set("SDA", t + tb * 0.7, 1)
                    w.marks.append((t + tb * 0.7, "SDA released"))
                t += tb
            w.set("SDA", t, 0)
            w.set("SDA", t + tb / 2, 1)
            w.seg(tb, t, "9 recovery clocks", 7, 1)
            w.seg(t, t + tb, "STOP", 2, 1)
            w.end(t + 2 * tb)
            return w
        b = Bld("I²C bus recovery", "Master toggles SCL until the stuck slave finishes its byte and releases SDA, then sends STOP.")
        fr = Frame(self.t, 11 * tb, "mcu", None, "I2C", "Bus recovery: 9 clocks + STOP", pdu=b.done(), kind="ctl", wirefn=wf)
        if send:
            if self.fault["stuck"]:
                self.set_fault("stuck", False)
            return self.tx(fr)
        return fr

    def tpls(self):
        return [Tpl("Read temperature", [], lambda s, v, send: self.read_temp(send), "Write pointer register 0x00, repeated START, read two bytes (12-bit, 0.0625 degC/LSB)."),
                Tpl("Scan bus", [], lambda s, v, send: self.scan(send), "Address probe: START + address + W, then STOP. Present chips ACK."),
                Tpl("EEPROM write byte", [P("a", "Memory address", 0, 0, 255), P("d", "Data", 0x41, 0, 255)], lambda s, v, send: self._ew(v, send),
                    "24C02: device address 0x50, word address, data. The chip then needs ~5 ms to program (it NACKs meanwhile)."),
                Tpl("Bus recovery (9 clocks)", [], lambda s, v, send: self.recover(send), "Clears a slave that holds SDA low.")]

    def _ew(self, v, send):
        fr = self.txn(["S", (0xA0, 0, "a"), (v["a"], 0, "m"), (v["d"], 0, "m"), "P"], "EEPROM write [0x%02X] = 0x%02X" % (v["a"], v["d"]), dst="eep")
        if send:
            self.eep[v["a"]] = v["d"]
            self.by["eep"].vars["Byte 0..15"] = self.eep[:16].decode("ascii", "replace")
            return self.tx(fr)
        return fr


# ================================================================== 1-Wire
def ds_rom(serial):
    body = bytes([0x28]) + serial.to_bytes(6, "little")
    return body + bytes([crcn("CRC-8/MAXIM-DOW", body)])


class OneWire(Scenario):
    key, name, cat = "onewire", "1-Wire", "phys"
    blurb = "Simple sensors and identification devices"
    phy, rate = "onewire", 15400
    medium = "1-Wire bus: one data line + ground, 4.7 kΩ pull-up to 3.3 V, 30 m of cable, 3 x DS18B20"
    nets = [("DQ", "data / power line")]
    lines = ["DQ"]
    faults = [("weak", "Long cable with a weak 10 kΩ pull-up", "The line recovers too slowly between time slots; some 1s read as 0s and the CRC catches them."),
              ("gone", "Sensor #2 disconnected", "No presence pulse from it, and a Match ROM to its code reads all 1s: CRC error."),
              ("para", "Parasite power without a strong pull-up", "A parasitically powered DS18B20 cannot finish its conversion: it reports the 85.0 degC power-on value."),
              ("short", "DQ shorted to ground", "No presence pulse at all - the master reports 'no devices'.")]
    spec = [("Origin", "Dallas Semiconductor (now Analog Devices / Maxim)"), ("Signals", "One open-drain data line (DQ) + ground; devices can be parasite powered from DQ"),
            ("Timing", "Reset 480 µs low; presence 60-240 µs; 60 µs time slots (~15.4 kbit/s standard speed)"),
            ("Addressing", "Unique 64-bit ROM: family code, 48-bit serial, CRC-8"), ("Commands", "ROM: 0x33 Read, 0x55 Match, 0xCC Skip, 0xF0 Search. DS18B20: 0x44 Convert T, 0xBE Read scratchpad"),
            ("Error check", "CRC-8 (x^8+x^5+x^4+1, Maxim) on ROM and scratchpad")]
    frame = [["Temperature read", ("RESET", "480 µs"), ("PRESENCE", "60-240 µs"), ("55 Match ROM", 8), ("ROM 64-bit", 64), ("BE", 8), ("Scratchpad 9 B", 72)],
             ["DS18B20 scratchpad", ("T LSB", 8), ("T MSB", 8), ("TH", 8), ("TL", 8), ("CONFIG", 8), ("FF", 8), ("0C", 8), ("10", 8), ("CRC", 8)]]
    about = ("1-Wire runs a whole network over one wire plus ground. The master starts every bit by pulling the line low; to write a 1 it lets go "
             "after a few microseconds, to write a 0 it holds the line low for the whole 60 µs slot. To read, it pulls low briefly and samples "
             "~15 µs later - a device holds the line low to answer 0. Each device has a laser-etched 64-bit ROM code; the clever Search ROM "
             "algorithm discovers all of them one bit position at a time.")
    guide = ["In LOGIC, FIT a temperature read: the long 480 µs reset, the device's presence pulse, then the bit slots.",
             "Zoom on a few slots: short low = 1, long low = 0.",
             "Check the scratchpad in the ANALYZER: 0x0170 = 23.0 degC (1/16 degC per LSB).",
             "Inject the parasite power fault: the sensors report 85.0 degC.",
             "Run 'Search ROM' in COMPOSE and read the discovered ROM codes."]

    def build(self):
        m = self.node("m", "MASTER", "mcu", 40, 150, "1-Wire master", "4k7 pull-up").at_right()
        y = m.port[1]
        self.seg([m.port, (860, y)], "wire", net="DQ", label="DQ + GND (30 m Cat5 pair)")
        self.sens = []
        for i, x in enumerate((250, 450, 650)):
            n = self.node("s%d" % (i + 1), "DS18B20 #%d" % (i + 1), "temp", x, 260, "", "")
            rom = ds_rom(0x0000B1A20000 + 0x1F3 * (i + 1))
            n.addr = "28-%s" % rom[1:7][::-1].hex()
            n.vars.update({"ROM": rom.hex(" ").upper(), "Temperature C": 21.0 + i * 1.5})
            n.ctl = [("Temperature C", "TEMP", -55.0, 125.0, 0, lambda v: "%.2f" % v)]
            n.extra["rom"] = rom
            n.at_top()
            self.seg([n.port, (n.port[0], y)], "wire", net="DQ")
            self.sens.append(n)
        self.term(140, y - 36, "4k7", True, "pull", vert=True)
        self.user = "m"
        self.k = 0
        self.by["m"].vars.update({"Devices found": 3, "CRC errors": 0})
        self.every(1.0, self.convert, 0.05)

    def cond(self, net):
        c = super().cond(net)
        if self.fault["weak"]:
            c["rise"] = 3.5
        if self.fault["short"]:
            c["atten"] = 0.01
        return c

    def slots(self, items):
        """items: ('R') reset+presence, or (byte, 'w'|'r', present?)"""
        w = Wire(bit=70e-6)
        t = 10e-6
        w.set("DQ", 0.0, 1)
        short = self.fault["short"]
        if short:
            w.set("DQ", 0.0, 0)
        for it in items:
            if it == "R":
                w.set("DQ", t, 0)
                w.set("DQ", t + 480e-6, 0 if short else 1)
                pres = not short
                if pres:
                    w.set("DQ", t + 480e-6 + 35e-6, 0)
                    w.set("DQ", t + 480e-6 + 35e-6 + 110e-6, 1)
                w.seg(t, t + 480e-6, "RESET", 7, 1)
                w.seg(t + 480e-6, t + 960e-6, "PRESENCE" if pres else "no presence", 2 if pres else 8, 1)
                t += 960e-6
                continue
            byte, mode, lab = it
            t0 = t
            for k in range(8):
                bit = (byte >> k) & 1
                w.set("DQ", t, 0)
                if mode == "w":
                    w.set("DQ", t + (6e-6 if bit else 60e-6), 0 if short else 1)
                else:
                    w.set("DQ", t + (6e-6 if bit else 32e-6), 0 if short else 1)
                    w.marks.append((t + 15e-6, ""))
                t += 70e-6
            w.seg(t0, t, lab or "%02X" % byte, 0 if mode == "w" else 1, 0)
        w.end(t + 20e-6)
        return w

    def convert(self):
        if not self.by["m"].on:
            return
        items = ["R", (0xCC, "w", "CC Skip ROM"), (0x44, "w", "44 Convert T")]
        b = Bld("1-Wire: Skip ROM + Convert T", "Addresses every device at once and starts a temperature conversion (750 ms at 12-bit resolution).")
        b.u8("ROM command", 0xCC, "0xCC Skip ROM", "Talk to all devices")
        b.u8("Function", 0x44, "0x44 Convert T", "Start conversion")
        fr = Frame(self.t, 0.0012 + 16 * 70e-6, "m", None, "1-Wire", "Skip ROM, Convert T (all sensors)", pdu=b.done(), kind="cmd",
                   wirefn=lambda fr, it=items: self.slots(it), key="Convert T",
                   err="No presence pulse: DQ shorted" if self.fault["short"] else None)
        self.tx(fr)
        self.k = 0
        self.at(self.t + 0.75, self.read_next)

    def scratch(self, n):
        t = n.vars["Temperature C"]
        if self.fault["para"]:
            t = 85.0
        raw = int(round(t * 16)) & 0xFFFF
        body = bytes([raw & 255, raw >> 8, 0x4B, 0x46, 0x7F, 0xFF, 0x0C, 0x10])
        return body + bytes([crcn("CRC-8/MAXIM-DOW", body)]), t

    def read_next(self, k=None, send=True):
        if k is None:
            if self.k >= len(self.sens):
                return
            k = self.k
            self.k += 1
            self.at(self.t + 0.03, self.read_next)
        n = self.sens[k]
        rom = n.extra["rom"]
        sp, t = self.scratch(n)
        err = None
        if self.fault["short"]:
            err, sp = "No presence: DQ shorted to ground", bytes(9)
        elif self.fault["gone"] and k == 1:
            err, sp = "CRC error: device absent, read all 1s", bytes([0xFF] * 9)
        elif self.fault["weak"] and self.rng.random() < 0.35:
            sp = bytes([sp[0] & 0xF7]) + sp[1:]
            err = "CRC-8 mismatch: a 1 read as 0 (slow recovery)"
        items = ["R", (0x55, "w", "55 Match ROM")] + [(x, "w", None) for x in rom] + [(0xBE, "w", "BE Read")] + [(x, "r", None) for x in sp]
        b = Bld("1-Wire: Match ROM + Read Scratchpad", "Select one device by its 64-bit ROM, then read its 9-byte scratchpad.")
        b.u8("ROM command", 0x55, "0x55 Match ROM", "Followed by the 8-byte ROM code of the target")
        b.raw("ROM code", rom, "family 0x28 (DS18B20) serial %s CRC 0x%02X" % (rom[1:7][::-1].hex(), rom[7]), "Family code, 48-bit serial number (LSB first), CRC-8")
        b.u8("Function", 0xBE, "0xBE Read Scratchpad", "")
        raw = sp[0] | (sp[1] << 8)
        if raw & 0x8000:
            raw -= 65536
        o = b.f("Scratchpad", sp, None, "9 bytes sent LSB first")
        b.note("Temperature: %.4f degC (raw 0x%04X / 16)" % (raw / 16.0, raw & 0xFFFF), "12-bit two's complement, 0.0625 degC per LSB", d=2, off=o, n=2)
        b.note("TH/TL alarm: %d / %d degC, config 0x%02X (12-bit)" % (sp[2], sp[3], sp[4]), "", d=2, off=o + 2, n=3)
        ok = crcn("CRC-8/MAXIM-DOW", sp[:8]) == sp[8]
        b.note("CRC-8: 0x%02X [%s]" % (sp[8], "correct" if ok else "INCORRECT"), "Maxim CRC-8 over bytes 0-7", d=2, off=o + 8, n=1)
        info = "Sensor #%d: %.2f degC" % (k + 1, raw / 16.0) if not err else "Sensor #%d read" % (k + 1)
        fr = Frame(self.t, 0.00096 + (19) * 8 * 70e-6, "m", n.id, "1-Wire", info, pdu=b.done(), kind="resp", err=err,
                   wirefn=lambda fr, it=items: self.slots(it), key="Read #%d" % (k + 1))
        if err:
            self.by["m"].vars["CRC errors"] += 1
        return self.tx(fr) if send else fr

    def search(self, send=True):
        roms = sorted([s.extra["rom"] for i, s in enumerate(self.sens) if not (self.fault["gone"] and i == 1)], key=lambda r: int.from_bytes(r, "little"))
        last = None
        for rom in roms[:3]:
            items = ["R", (0xF0, "w", "F0 Search ROM")]
            b = Bld("1-Wire Search ROM pass", "For each of the 64 bit positions every device sends its bit and its complement; the master picks a branch and writes it back.")
            b.u8("ROM command", 0xF0, "0xF0 Search ROM", "")
            b.raw("ROM found", rom, rom.hex(" ").upper(), "Discovered device code")
            w_items = list(items)
            for byte in rom:
                w_items.append((byte, "r", None))
            fr = Frame(self.t, 0.00096 + 64 * 3 * 70e-6, "m", None, "1-Wire", "Search ROM: found %s" % rom.hex(" ").upper(), pdu=b.done(), kind="ctl",
                       wirefn=lambda fr, it=w_items: self.slots(it), key="Search")
            if send:
                self.tx(fr)
            last = fr
        self.by["m"].vars["Devices found"] = len(roms)
        return last

    def tpls(self):
        return [Tpl("Read sensor", [P("k", "Sensor #", 1, 1, 3)], lambda s, v, send: self.read_next(v["k"] - 1, send), "Reset, Match ROM, Read Scratchpad."),
                Tpl("Search ROM (discover all)", [], lambda s, v, send: self.search(send), "Binary-tree search across all ROM codes on the bus."),
                Tpl("Convert T (all)", [], lambda s, v, send: self.convert() if send else None, "Skip ROM + Convert T.")]


# ===================================================================== USB
PIDS = {0xE1: "OUT", 0x69: "IN", 0xA5: "SOF", 0x2D: "SETUP", 0xC3: "DATA0", 0x4B: "DATA1", 0xD2: "ACK", 0x5A: "NAK", 0x1E: "STALL"}
DEV_DESC = bytes([18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x6D, 0x04, 0x1D, 0xC3, 0x00, 0x01, 1, 2, 0, 1])


class USB(Scenario):
    key, name, cat = "usb", "USB", "phys"
    blurb = "Peripheral communication"
    phy, rate = "usb", 12e6
    medium = "USB 2.0 full speed (12 Mbit/s), NRZI + bit stuffing on D+/D-, HID keyboard on a 1.5 m cable"
    nets = [("D+", "data plus"), ("D-", "data minus"), ("VDIFF", "D+ minus D-")]
    lines = ["DP", "DM"]
    faults = [("swap", "D+ and D- swapped in the cable", "The host sees inverted J/K states and an apparent low-speed attach; enumeration never succeeds."),
              ("cable", "Poor-quality 5 m extension", "Signal integrity errors corrupt packets: CRC failures and retries."),
              ("stall", "Device firmware lacks string descriptors", "Unsupported requests are answered with a STALL handshake - normal behaviour, but noisy."),
              ("power", "Port current limit too low (bus-powered hub)", "The device browns out during enumeration and re-attaches over and over.")]
    spec = [("Standard", "USB 2.0 (USB-IF); low 1.5, full 12, high 480 Mbit/s"), ("Signalling", "Differential D+/D-: J and K states, SE0 = both low (reset / end of packet)"),
            ("Encoding", "NRZI (a 0 toggles the line) with a stuffed 0 after six 1s"), ("Packets", "SYNC, PID (4 bits + complement), fields, CRC5 or CRC16, EOP"),
            ("Transfers", "Control, interrupt, bulk, isochronous; every frame (1 ms) starts with SOF"), ("Attach", "Device pulls D+ (full speed) or D- (low speed) up to 3.3 V with 1.5 kΩ"),
            ("Enumeration", "Reset, GET_DESCRIPTOR, SET_ADDRESS, GET_DESCRIPTOR(config), SET_CONFIGURATION")]
    frame = [["Token packet", ("SYNC", 8), ("PID", 8), ("ADDR", 7), ("ENDP", 4), ("CRC5", 5), ("EOP", 3)],
             ["Data packet", ("SYNC", 8), ("PID", 8), ("DATA", "0-1023 B"), ("CRC16", 16), ("EOP", 3)], ["Handshake", ("SYNC", 8), ("PID", 8), ("EOP", 3)]]
    about = ("USB is host-centric: the device speaks only when the host sends it a token. Each transaction is a token packet (IN, OUT, SETUP), "
             "an optional data packet and a handshake (ACK, NAK, STALL). At attach the host resets the device, reads its descriptors at address 0, "
             "gives it an address and selects a configuration. A keyboard is then polled with IN tokens every 10 ms; it NAKs until a key changes.")
    guide = ["Watch the enumeration in FLOW right after start (or toggle the keyboard's POWER).",
             "Select a SETUP DATA0 packet: decode bmRequestType, bRequest, wValue in the tree.",
             "In LOGIC, the SYNC field appears as KJKJKJKK; 'S' markers show stuffed bits.",
             "Press a key with the device action button and see the IN poll return a DATA packet instead of NAK."]

    def build(self):
        h = self.node("host", "PC HOST", "pc", 60, 150, "root hub", "xHCI").at_right()
        d = self.node("kbd", "USB KEYBOARD", "keypad", 680, 150, "HID boot", "full speed").at_left()
        self.seg([h.port, d.port], "usb", net="VDIFF", label="USB 2.0 cable 1.5 m", c0="usba", c1="usbb")
        self.user = "host"
        self.addr = 0
        self.frame_no = 0
        self.key_q = []
        d.vars.update({"Address": 0, "Configured": "no", "Last report": "-"})
        d.acts = [("PRESS 'A'", lambda: self.key_q.append(0x04)), ("PRESS ENTER", lambda: self.key_q.append(0x28))]
        self.at(0.01, self.enumerate)
        self.every(0.001, self.sof, 0.0005)
        self.every(0.010, self.poll, 0.004)
        self.toggle = 0

    def on_power(self, n):
        if n.id == "kbd" and n.on:
            self.addr = 0
            n.vars.update({"Address": 0, "Configured": "no"})
            self.at(self.t + 0.1, self.enumerate)

    def pkt(self, pid, body, info, src, dst, kind, crc5=False, err=None):
        name = PIDS.get(pid, "?")
        b = Bld("USB %s packet" % name, "")
        b.u8("SYNC", 0x80, "KJKJKJKK", "Lets the receiver lock onto the bit timing")
        b.u8("PID", pid, "%s (0x%02X)" % (name, pid), "Packet identifier: 4 bits plus their complement")
        if crc5:
            v = body[0] | (body[1] << 8)
            b.raw("ADDR/ENDP", body, "addr %d endp %d" % (v & 0x7F, (v >> 7) & 15), "7-bit device address, 4-bit endpoint")
            c = crc(bytes(body), 5, 0x05, 0x1F, True, True, 0x1F)
            b.note("CRC5: 0x%02X" % c, "CRC-5 over address and endpoint", d=1)
        elif body:
            b.raw("Data", body, None, "")
            c = crcn("CRC-16/USB", bytes(body))
            b.u16("CRC16", c, "0x%04X" % c, "CRC-16 over the data", little=True)
        pdu = b.done()
        raw = bytes([pid]) + bytes(body)
        bits = [0, 0, 0, 0, 0, 0, 0, 1] + bytes_lsb(raw)
        stf, pos = usb_stuff(bits)
        lv = nrzi(stf)
        tb = 1.0 / 12e6
        dur = (len(lv) + 3) * tb
        swap = self.fault["swap"]

        def wf(fr, lv=lv, pos=pos):
            w = Wire(bit=tb)
            j = (1, 0) if not swap else (0, 1)
            w.set("DP", 0.0, j[0])
            w.set("DM", 0.0, j[1])
            t = tb
            for i, v in enumerate(lv):
                dp = (v if not swap else 1 - v)
                w.set("DP", t, dp)
                w.set("DM", t, 1 - dp)
                if i in pos:
                    w.marks.append((t + tb / 2, "S"))
                t += tb
            w.set("DP", t, 0)
            w.set("DM", t, 0)
            w.seg(t, t + 2 * tb, "EOP SE0", 7, 1)
            w.set("DP", t + 2 * tb, j[0])
            w.set("DM", t + 2 * tb, j[1])
            w.seg(tb, 9 * tb, "SYNC", 7, 1)
            w.seg(9 * tb, 17 * tb, name, 0, 1)
            if len(lv) > 17:
                w.seg(17 * tb, (len(lv) + 1) * tb, "payload + CRC", 1, 1)
            w.end(t + 3 * tb)
            return w
        return Frame(self.t, dur, src, dst, "USB", info, pdu=pdu, kind=kind, wirefn=wf, err=err, key=name)

    def token(self, pid, addr, endp, info):
        v = addr | (endp << 7)
        return self.pkt(pid, bytes([v & 255, v >> 8]), info, "host", "kbd", "cmd", crc5=True)

    def seq(self, items, t0=None):
        t = self.t if t0 is None else t0
        for fr in items:
            fr.t = t
            self.tx(fr)
            t = fr.t + fr.dur + 1.2e-6
        return t

    def setup_xfer(self, req, info, reply=None, t=None):
        if not self.by["kbd"].on or self.fault["swap"]:
            fr = self.token(0x2D, self.addr, 0, "SETUP addr %d (no response)" % self.addr)
            fr.err = "No handshake: device not attached / D+ D- swapped" if self.fault["swap"] else "No handshake: device off"
            return self.seq([fr], t)
        err = "CRC16 error, host retries" if self.fault["cable"] and self.rng.random() < 0.4 else None
        items = [self.token(0x2D, self.addr, 0, "SETUP addr %d ep0" % self.addr),
                 self.pkt(0xC3, req, info, "host", "kbd", "cmd", err=err), self.pkt(0xD2 if not err else 0x5A, b"", "ACK" if not err else "(no ACK: bad CRC)", "kbd", "host", "ack")]
        if reply is not None:
            if reply == "STALL":
                items += [self.token(0x69, self.addr, 0, "IN addr %d ep0" % self.addr), self.pkt(0x1E, b"", "STALL (request not supported)", "kbd", "host", "err")]
            else:
                items += [self.token(0x69, self.addr, 0, "IN addr %d ep0" % self.addr), self.pkt(0x4B, reply, "DATA1 %d bytes" % len(reply), "kbd", "host", "resp"),
                          self.pkt(0xD2, b"", "ACK", "host", "kbd", "ack")]
        items += [self.token(0xE1 if reply is not None else 0x69, self.addr, 0, "STATUS stage"), self.pkt(0x4B, b"", "DATA1 zero-length (status)", "host" if reply is not None else "kbd", "kbd" if reply is not None else "host", "ack")]
        return self.seq(items, t)

    def enumerate(self):
        d = self.by["kbd"]
        if self.fault["power"]:
            self.log("Device browned out during enumeration (port current limit)")
            self.at(self.t + 0.3, self.enumerate)
        t = self.setup_xfer(bytes([0x80, 6, 0, 1, 0, 0, 64, 0]), "GET_DESCRIPTOR Device (64)", DEV_DESC[:8])
        if self.fault["swap"] or not d.on or self.fault["power"]:
            return

        def step2():
            self.setup_xfer(bytes([0x00, 5, 7, 0, 0, 0, 0, 0]), "SET_ADDRESS 7")
            self.addr = 7
            d.vars["Address"] = 7
            d.addr = "addr 7"
            self.at(self.t + 0.002, step3)

        def step3():
            self.setup_xfer(bytes([0x80, 6, 0, 1, 0, 0, 18, 0]), "GET_DESCRIPTOR Device (18)", DEV_DESC)
            self.at(self.t + 0.002, step4)

        def step4():
            cfg = bytes([9, 2, 34, 0, 1, 1, 0, 0xA0, 50])
            self.setup_xfer(bytes([0x80, 6, 0, 2, 0, 0, 9, 0]), "GET_DESCRIPTOR Configuration (9)", cfg)
            self.at(self.t + 0.002, step5)

        def step5():
            if self.fault["stall"]:
                self.setup_xfer(bytes([0x80, 6, 2, 3, 9, 4, 255, 0]), "GET_DESCRIPTOR String 2", "STALL")
            self.setup_xfer(bytes([0x00, 9, 1, 0, 0, 0, 0, 0]), "SET_CONFIGURATION 1")
            d.vars["Configured"] = "yes (config 1)"
            d.state = "CONFIGURED"
        self.at(t + 0.002, step2)

    def sof(self):
        if not self.by["host"].on:
            return
        self.frame_no = (self.frame_no + 1) & 0x7FF
        fn = self.frame_no
        fr = self.pkt(0xA5, bytes([fn & 255, fn >> 8]), "SOF frame %d" % fn, "host", None, "sync", crc5=True)
        self.tx(fr)

    def poll(self):
        d = self.by["kbd"]
        if not d.on or d.vars["Configured"] == "no":
            return
        items = [self.token(0x69, self.addr, 1, "IN addr %d ep1 (interrupt)" % self.addr)]
        if self.key_q:
            k = self.key_q.pop(0)
            self.toggle ^= 1
            rep = bytes([0, 0, k, 0, 0, 0, 0, 0])
            items += [self.pkt(0x4B if self.toggle else 0xC3, rep, "HID report: key 0x%02X (%s)" % (k, {0: "all released", 4: "A", 0x28: "ENTER"}.get(k, "usage")), "kbd", "host", "data"),
                      self.pkt(0xD2, b"", "ACK", "host", "kbd", "ack")]
            d.vars["Last report"] = rep.hex(" ")
            self.key_q.insert(0, 0) if k else None
        else:
            items += [self.pkt(0x5A, b"", "NAK (no new key)", "kbd", "host", "ack")]
        self.seq(items)

    def tpls(self):
        return [Tpl("GET_DESCRIPTOR", [P("t", "Type", "Device", opts=["Device", "Configuration", "String"]), P("i", "Index", 0, 0, 5), P("n", "wLength", 18, 0, 255)],
                    lambda s, v, send: self._gd(v, send), "Standard request 6. Device = 1, Configuration = 2, String = 3."),
                Tpl("GET_STATUS", [], lambda s, v, send: self.setup_xfer(bytes([0x80, 0, 0, 0, 0, 0, 2, 0]), "GET_STATUS", bytes([0, 0])) if send else self.pkt(0xC3, bytes([0x80, 0, 0, 0, 0, 0, 2, 0]), "GET_STATUS", "host", "kbd", "cmd"), "Self-powered / remote-wakeup bits."),
                Tpl("Press a key", [P("k", "HID usage", 0x04, 0x04, 0x65)], lambda s, v, send: self.key_q.append(v["k"]) if send else None, "Queue a keypress; it is delivered at the next IN poll.")]

    def _gd(self, v, send):
        t = {"Device": 1, "Configuration": 2, "String": 3}[v["t"]]
        req = bytes([0x80, 6, v["i"], t, 0, 0, v["n"], 0])
        if not send:
            return self.pkt(0xC3, req, "SETUP data", "host", "kbd", "cmd")
        rep = DEV_DESC[:v["n"]] if t == 1 else (bytes([9, 2, 34, 0, 1, 1, 0, 0xA0, 50])[:v["n"]] if t == 2 else ("STALL" if self.fault["stall"] else "COMM-SIM".encode("utf-16-le")))
        return self.setup_xfer(req, "GET_DESCRIPTOR %s %d" % (v["t"], v["i"]), rep)


# ==================================================================== LVDS
class LVDS(Scenario):
    key, name, cat = "lvds", "LVDS", "phys"
    blurb = "High-speed differential signalling"
    phy, rate = "lvds", 280e6
    medium = "TIA-644-A LVDS, 7:1 serialised video link (camera to display), 280 Mbit/s per pair, 100 Ω at the receiver"
    nets = [("VDIFF", "data pair 0 (P - N)"), ("P", "data pair P"), ("N", "data pair N"), ("CLK", "clock pair")]
    lines = ["D", "C"]
    eye_ok = True
    faults = [("noterm", "100 Ω receiver termination missing", "The ~3.5 mA current loop has nothing to develop 350 mV across, and every edge reflects: the eye closes."),
              ("long", "10 m cable instead of 2 m", "Cable loss and inter-symbol interference smear the bits (watch the eye diagram)."),
              ("skew", "300 ps clock-to-data skew", "Data is sampled off-centre by the deserialiser: errors at the eye edges."),
              ("open", "N leg of pair 0 open", "Only half the swing reaches the receiver and the common mode shifts.")]
    spec = [("Standard", "TIA/EIA-644-A (LVDS); also inside FPD-Link, Camera Link, display panels"), ("Signalling", "Current-mode differential: 3.5 mA into 100 Ω = 350 mV swing around 1.2 V common mode"),
            ("Speed", "Hundreds of Mbit/s to ~3 Gbit/s per pair"), ("Power / EMI", "Low swing -> low power and low emissions; tight coupling cancels radiation"),
            ("Topology", "Point-to-point (M-LVDS for multipoint)"), ("Termination", "100 Ω differential at the receiver")]
    frame = [["7:1 serialisation per pixel clock (one pair)", ("b0", 1), ("b1", 1), ("b2", 1), ("b3", 1), ("b4", 1), ("b5", 1), ("b6", 1)]]
    about = ("LVDS steers a small constant current through a termination resistor: the direction sets the logic level, the 100 Ω turns it into "
             "a 350 mV differential signal. The small swing allows very fast edges with little power and EMI. Video links pack 7 bits per pair into "
             "each pixel clock cycle and send the clock on its own pair - the receiver multiplies it up to find the bit centres.")
    guide = ["SCOPE: P and N each swing only 350 mV around 1.2 V; MATH shows the differential signal.",
             "Press EYE on the SCOPE: a wide-open eye.",
             "Remove the termination and look at the eye again, then try the 10 m cable.",
             "Open SPECTRUM to see the bit-rate harmonics of a 280 Mbit/s stream."]

    def build(self):
        a = self.node("ser", "CAMERA SERIALISER", "camera", 60, 150, "4 pairs + clock").at_right()
        b = self.node("des", "DISPLAY DESERIALISER", "display", 640, 150, "100 Ω per pair").at_left()
        self.seg([a.port, b.port], "lvds", net="VDIFF", label="shielded twisted pairs, 2 m", c0="header", c1="header")
        self.term(630, 150, "100 Ω", True, "term0", vert=True)
        self.user = "ser"
        self.line_no = 0
        self.pattern = "PRBS7"
        b.vars.update({"Lines OK": 0, "Bit errors": 0, "Pattern": self.pattern})
        self.every(0.004, self.vline, 0.001)

    def cond(self, net):
        c = super().cond(net)
        if self.fault["noterm"]:
            c.update(refl=0.55, ringf=1.1e9, ringd=1.6e-9, atten=1.6)
        if self.fault["long"]:
            c.update(rise=9.0, atten=0.7)
        if self.fault["open"] and net in ("VDIFF", "N"):
            c.update(atten=0.5, off=0.17)
        return c

    def bits(self, n):
        out = []
        if self.pattern == "PRBS7":
            s = 0x5A
            for _ in range(n):
                nb = ((s >> 6) ^ (s >> 5)) & 1
                s = ((s << 1) | nb) & 0x7F
                out.append(nb)
        elif self.pattern == "CHECKER":
            out = [i & 1 for i in range(n)]
        else:
            out = [1 if (i // 56) % 2 == 0 else 0 for i in range(n)]
        return out

    def vline(self):
        self.line_no += 1
        n = 7 * 80
        bits = self.bits(n)
        tb = 1.0 / 280e6
        err = None
        if (self.fault["noterm"] or self.fault["skew"] or self.fault["long"]) and self.rng.random() < (0.6 if self.fault["noterm"] else 0.3):
            err = "Deserialiser bit errors (eye closed / sampling off centre)"
        b = Bld("LVDS video line (pair 0)", "80 pixel clocks x 7 bits on one data pair.")
        b.raw("Bits (packed)", B.pack_bits(bits), "%d bits" % n, "Serialised RGB/sync bits")
        sk = 300e-12 if self.fault["skew"] else 0.0

        def wf(fr, bits=bits):
            w = Wire(bit=tb)
            t = 0.0
            for i, x in enumerate(bits):
                w.set("D", t, x)
                if i % 7 == 0:
                    w.set("C", t + sk, 1)
                if i % 7 == 4:
                    w.set("C", t + sk, 0)
                if i % 7 == 6:
                    w.seg(t - 6 * tb, t + tb, "px %d" % (i // 7), (i // 7) % 2, 0)
                t += tb
            w.end(t)
            return w
        fr = Frame(self.t, n * tb, "ser", "des", "LVDS", "Video line %d (%s)" % (self.line_no % 1080, self.pattern), pdu=b.done(), err=err, kind="data", wirefn=wf, key="line")
        self.tx(fr)
        d = self.by["des"]
        d.vars["Lines OK" if not err else "Bit errors"] += 1

    def tpls(self):
        return [Tpl("Test pattern", [P("p", "Pattern", "PRBS7", opts=["PRBS7", "CHECKER", "BARS"])], lambda s, v, send: self._pat(v, send), "PRBS7 exercises every short run length - best for eye diagrams.")]

    def _pat(self, v, send):
        if send:
            self.pattern = v["p"]
            self.by["des"].vars["Pattern"] = self.pattern
        return None


# =================================================================== fibre
OPTICS = {"1000BASE-SX": (850, -5.0, -17.0, "OM2 MMF", 3.5, 550), "1000BASE-LX": (1310, -6.0, -19.0, "OS2 SMF", 0.4, 10000)}


class Fiber(Scenario):
    key, name, cat = "fiber", "Fiber-optic Ethernet", "phys"
    blurb = "Long-distance and noise-resistant networks"
    phy, rate = "fiber", 1.25e9
    medium = "1000BASE-SX on OM2 multimode, LC duplex, two patch panels, 8B/10B at 1.25 GBd"
    nets = [("OPTICAL", "optical power at the receiver"), ("ELEC", "SFP receiver output")]
    lines = ["O"]
    eye_ok = True
    faults = [("dirty", "Dirty LC connector (+3 dB)", "A fingerprint or dust on the ferrule scatters light. Inspect and clean before blaming the optic!"),
              ("bend", "Fibre bent tighter than its radius (+5 dB)", "Light escapes the core at tight bends (macrobend loss)."),
              ("cross", "TX and RX crossed (polarity A-to-A)", "Each transmitter faces the other transmitter: no light at either receiver, link down."),
              ("smf", "SX optic patched onto single-mode fibre", "850 nm multimode light cannot couple into a 9 µm core: massive loss.")]
    spec = [("Standards", "IEEE 802.3z 1000BASE-SX (850 nm, MMF, 550 m OM2) / LX (1310 nm, SMF, 10 km); 10GBASE-SR/LR"),
            ("Coding", "8B/10B (1000BASE-X): 1.25 GBd, DC balanced, K28.5 comma for alignment"), ("Connectors", "LC duplex (SFP), SC, MPO for parallel optics"),
            ("Loss budget", "TX power - RX sensitivity, minus fibre (dB/km), connector (~0.5 dB) and splice (~0.1 dB) losses = margin"),
            ("Monitoring", "Digital Optical Monitoring (SFF-8472): temperature, Vcc, bias, TX and RX power"), ("Immunity", "No EMI pickup, no ground loops, galvanic isolation")]
    frame = [["1000BASE-X stream", ("/I/ K28.5 D16.2", 20), ("/S/ K27.7", 10), ("frame bytes (8B/10B)", "n x 10"), ("/T/R/", 20)]]
    about = ("Fibre links replace the copper pair with light. Over a fibre link the only question is power: does enough light reach the receiver after "
             "every metre of fibre, every connector and every splice? The panel draws the loss budget. On the wire, 1000BASE-X uses 8B/10B so the "
             "light is DC-balanced and the receiver can find symbol boundaries with the K28.5 comma.")
    guide = ["Look at the loss budget bar in the wiring view; change the fibre length with the knob on SWITCH B.",
             "Inject the dirty connector, then the bend: watch the margin and the DOM RX power fall.",
             "Cross the fibres: link down, frames stop.",
             "SCOPE + EYE on OPTICAL: the eye shrinks as received power drops."]

    def build(self):
        a = self.node("swa", "SWITCH A", "switch", 40, 140, "SFP 1000BASE-SX").at_right()
        p1 = self.node("pp1", "PATCH PANEL", "box", 270, 140, "LC/LC", w=96, h=46)
        p2 = self.node("pp2", "PATCH PANEL", "box", 520, 140, "LC/LC", w=96, h=46)
        b = self.node("swb", "SWITCH B", "switch", 730, 140, "SFP 1000BASE-SX").at_left()
        for p in (p1, p2):
            p.extra["power"] = False
            p.port = (p.x + p.w / 2, p.y + p.h / 2)
        y = a.port[1]
        self.seg([a.port, (p1.x, y)], "fiber", net="OPTICAL", label="OM2 patch 3 m", c0="lcmm", c1="lcmm")
        self.seg([(p1.x + p1.w, y), (p2.x, y)], "fiber", net="OPTICAL", label="OM2 trunk", c0="lcmm", c1="lcmm")
        self.seg([(p2.x + p2.w, y), b.port], "fiber", net="OPTICAL", label="OM2 patch 3 m", c0="lcmm", c1="lcmm")
        self.seg([(p1.x, y), (p1.x + p1.w, y)], "fiber", w=1)
        self.seg([(p2.x, y), (p2.x + p2.w, y)], "fiber", w=1)
        self.user = "swa"
        b.vars["Fibre length m"] = 300.0
        b.ctl = [("Fibre length m", "LENGTH", 10.0, 2000.0, 10.0, lambda v: "%.0f m" % v)]
        self.n = 0
        self.every(0.01, self.traffic, 0.002)

    def budget(self):
        wl, ptx, sens, fib, att, reach = OPTICS["1000BASE-SX"]
        L = self.by["swb"].vars["Fibre length m"] / 1000.0
        loss = L * att + 4 * 0.5 + (3.0 if self.fault["dirty"] else 0) + (5.0 if self.fault["bend"] else 0) + (18.0 if self.fault["smf"] else 0)
        if L * 1000 > reach:
            loss += (L * 1000 - reach) / 100.0
        prx = ptx - loss
        if self.fault["cross"]:
            prx = -40.0
        return ptx, prx, sens, loss

    def cond(self, net):
        c = super().cond(net)
        ptx, prx, sens, loss = self.budget()
        k = 10 ** (prx / 10.0) / 0.5
        if net == "OPTICAL":
            c.update(atten=min(1.0, k * 1.0), noise=0.004 + max(0, (sens + 3 - prx)) * 0.002)
        else:
            c.update(noise=0.02 + max(0, (sens + 3 - prx)) * 0.03)
        return c

    def inspect(self, n):
        ptx, prx, sens, loss = self.budget()
        if n.id in ("swa", "swb"):
            return [("Optic", "1000BASE-SX 850 nm"), ("DOM temperature", "38.2 degC"), ("DOM Vcc", "3.31 V"), ("DOM TX bias", "6.8 mA"),
                    ("DOM TX power", "%.1f dBm" % ptx), ("DOM RX power", "%.1f dBm" % prx if prx > -39 else "LOS"), ("RX sensitivity", "%.1f dBm" % sens),
                    ("Link", "UP 1000 full" if prx > sens else "DOWN (LOS)")] + list(n.vars.items())
        return [("Insertion loss", "0.5 dB per mated pair")]

    def traffic(self):
        ptx, prx, sens, loss = self.budget()
        if prx < sens:
            if int(self.t * 100) % 50 == 0:
                self.log("Link down: RX power %.1f dBm below sensitivity" % prx)
            return
        self.n += 1
        b = Bld("Ethernet over 1000BASE-SX", "Normal Ethernet frames; the fibre PHY adds 8B/10B coding.")
        b.raw("Frame", bytes((i * 7 + self.n) & 255 for i in range(64)), "64 bytes", "")
        err = None
        if prx < sens + 2 and self.rng.random() < 0.3:
            err = "Code violation / FCS error: receive power near sensitivity"
        from .fam import eth_wire
        data = bytes([0x55] * 7 + [0xD5]) + bytes((i * 7 + self.n) & 255 for i in range(64))
        fr = Frame(self.t, 84 * 8 / 1e9, "swa", "swb", "1000BASE-X", "Frame %d (64 B) RX %.1f dBm" % (self.n, prx), pdu=b.done(), err=err, kind="data",
                   wirefn=lambda fr, d=data: eth_wire("fiber", d, 1e9), key="data")
        self.tx(fr)

    def draw_extra(self, s, r):
        from .. import ui
        import pygame
        ptx, prx, sens, loss = self.budget()
        x, y, w = r.x + 120, r.y + 270, 640
        ui.text(s, "OPTICAL LOSS BUDGET", (x, y - 18), 10, (220, 200, 150), bold=True)

        def X(db):
            return x + (db + 30) / 30.0 * w
        pygame.draw.rect(s, (20, 22, 26), (x, y, w, 26))
        pygame.draw.rect(s, (60, 160, 90) if prx > sens + 3 else (220, 170, 40) if prx > sens else (220, 60, 50), (X(max(-30, prx)), y + 3, X(ptx) - X(max(-30, prx)), 20))
        pygame.draw.line(s, (255, 80, 60), (X(sens), y - 4), (X(sens), y + 30), 2)
        ui.text(s, "TX %.1f dBm" % ptx, (X(ptx), y + 30), 9, (200, 220, 200), align="c")
        ui.text(s, "RX %.1f" % prx, (X(max(-30, prx)), y + 30), 9, (200, 220, 200), align="c")
        ui.text(s, "sens %.0f" % sens, (X(sens), y - 16), 9, (255, 120, 100), align="c")
        ui.text(s, "loss %.1f dB, margin %+.1f dB" % (loss, prx - sens), (x + w, y - 18), 10, (200, 220, 200), align="r")
