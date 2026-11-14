"""Industrial automation, part C: WirelessHART, FOUNDATION Fieldbus H1,
CC-Link, CC-Link IE Field, SERCOS III, POWERLINK, OPC UA, MQTT (with the
shared MQTT codec) and DDS / RTPS."""
import math
import struct
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, lsb, msb, bytes_lsb, xor8
from .fam import IpNet, RfNet, rf_frame, burst_wire, serial_frame, eth_pdu, udp_pdu
from .industrial_b import pb_telegram

WH_CH = [(11 + i, 2405.0 + 5 * i) for i in range(15)]


def mac154(seq, pan, dst, src, payload, ack_req=True, ftype=1, title=None):
    """IEEE 802.15.4 MAC frame (short addresses, PAN ID compression) + FCS."""
    fc = ftype | (0x20 if ack_req else 0) | 0x40 | (2 << 10) | (2 << 14)
    b = Bld(title or "IEEE 802.15.4 MAC", "Low-rate wireless PAN MAC frame (2.4 GHz O-QPSK PHY, 250 kbit/s).")
    b.u16("Frame Control", fc, "0x%04X (%s, ack req %d, PAN ID compression, short addr)" % (fc, {0: "Beacon", 1: "Data", 2: "Ack", 3: "MAC command"}[ftype], 1 if ack_req else 0),
          "Frame type, security, pending, ack request, PAN ID compression, addressing modes.", little=True)
    b.u8("Sequence Number", seq & 255, None, "Matches the acknowledgment to this frame.")
    b.u16("Destination PAN", pan, "0x%04X" % pan, "", little=True)
    b.u16("Destination", dst, "0x%04X%s" % (dst, " (broadcast)" if dst == 0xFFFF else ""), "Short (16-bit) address", little=True)
    b.u16("Source", src, "0x%04X" % src, "", little=True)
    b.sub(payload)
    fcs = crcn("CRC-16/KERMIT", bytes(b.b))
    b.u16("FCS", fcs, "0x%04X [correct]" % fcs, "CRC-16/ITU-T (KERMIT) over the MAC header and payload.", little=True)
    return b.done()


# ============================================================ WirelessHART
class WirelessHART(RfNet):
    key, name, cat = "wirelesshart", "WirelessHART", "ind"
    blurb = "Wireless process instrumentation"
    f_mhz, ptx, sens, n_exp = 2440.0, 10.0, -90.0, 2.6
    map_size = 260.0
    band = {"f0": 2400.0, "f1": 2483.5, "unit": "MHz", "chans": [("ch%d" % c, f, 2.0) for c, f in WH_CH]}
    medium = "IEC 62591 WirelessHART: 802.15.4 2.4 GHz, TDMA 10 ms slots, channel hopping over 15 channels, graph-routed mesh"
    faults = [("wifi", "Wi-Fi access point on channel 1 nearby", "Wi-Fi channel 1 covers 802.15.4 channels 11-14: packets in those slots fail until the network manager blacklists them."),
              ("router", "Level transmitter (a routing node) fails", "Devices that used it as a parent switch to their second parent - graph routing keeps the data flowing."),
              ("battery", "Temperature transmitter battery low", "The device reports low battery in its status; the network manager lengthens its update period."),
              ("ant", "Gateway antenna cable disconnected", "Only the closest devices are heard at all.")]
    spec = [("Standard", "IEC 62591 (HART 7 wireless), FieldComm Group"), ("Radio", "IEEE 802.15.4-2006 PHY, 2.4 GHz, 250 kbit/s, 15 channels"),
            ("Access", "TDMA: 10 ms time slots, superframes, scheduled by the network manager"), ("Hopping", "Every slot on a different channel; bad channels blacklisted"),
            ("Mesh", "Every device can route; graph routing with at least two parents"), ("Security", "AES-128 CCM* at network and data-link layers (MIC on every packet)"),
            ("Application", "Same HART commands as wired HART (e.g. command 9 publishing device variables)")]
    frame = [["Packet", ("802.15.4 MAC hdr", 72), ("DLPDU: ASN, prio, MIC", "n"), ("NPDU: graph ID, TTL", "n"), ("TPDU", 8), ("HART cmd 9 + data", "n x 8"), ("FCS", 16)]]
    about = ("WirelessHART puts HART instruments on a self-healing radio mesh. Time is cut into 10 ms slots and every transmission is scheduled "
             "by the network manager on a channel that changes from slot to slot, so interference on one channel only costs a retry. Each device keeps "
             "at least two parents, and the gateway translates the data back into ordinary HART commands for the control system.")
    guide = ["Open SPECTRUM: transmissions hop across the 15 channels.",
             "Turn on the Wi-Fi fault: the lower four channels go red until they are blacklisted.",
             "Fail the level transmitter: routes via the second parent take over (watch the links on the map).",
             "Drag a device far from everyone and see its links turn red."]

    def setup(self):
        g = self.rnode("gw", "GATEWAY", "gateway", 30, 120, "0x0001", "+ net manager")
        devs = [("pt", "PRESSURE PT-201", "pressure", 90, 40), ("tt", "TEMP TT-202", "temp", 120, 200), ("lt", "LEVEL LT-203", "sensor", 170, 110),
                ("vt", "VIBRATION VT-204", "sensor", 225, 40), ("pv", "VALVE FB ZT-205", "valve", 235, 190)]
        for i, (nid, lab, kind, x, y) in enumerate(devs):
            n = self.rnode(nid, lab, kind, x, y, "0x%04X" % (0x10 + i), "burst 1 s")
            n.vars.update({"PV": 10.0 + i * 3.3, "Battery": "OK", "Parents": "-"})
        self.parents = {"pt": ["gw", "lt"], "tt": ["gw", "lt"], "lt": ["gw", "pt"], "vt": ["lt", "pt"], "pv": ["lt", "tt"]}
        self.pairs = [(d, p) for d, ps in self.parents.items() for p in ps]
        self.user = "gw"
        self.asn = 0
        self.blk = set()
        self.seq = 0
        self.every(1.0, self.publish_all, 0.1)
        self.every(5.0, self.manager, 2.0)

    def chan(self):
        allowed = [c for c in WH_CH if c[0] not in self.blk]
        return allowed[self.asn % len(allowed)]

    def hop_ok(self, a, b, ch):
        if self.fault["wifi"] and ch[0] <= 14:
            return False
        if self.fault["ant"] and "gw" in (a, b):
            return self.radio_model.margin(a, b) > 25
        return self.radio_model.ok(a, b)

    def pkt(self, src, dst, final, payload, info, kind):
        self.asn += 1
        self.seq += 1
        ch = self.chan()
        b = Bld("WirelessHART DLPDU", "")
        b.u8("ASN snippet", self.asn & 255, None, "Absolute Slot Number: every device knows the network time in slots")
        b.u8("DLPDU spec", 0x31, "priority normal, data, keyed MIC", "")
        b.u16("Graph ID", 0x0100, None, "Route the packet follows through the mesh")
        b.u8("TTL", 8, None, "Hop limit")
        b.u16("Final destination", final, "0x%04X" % final, "")
        b.sub(payload)
        b.u32("MIC", (self.asn * 2654435761) & 0xFFFFFFFF, "0x%08X (AES-CCM*, simulated)" % ((self.asn * 2654435761) & 0xFFFFFFFF), "Message integrity code")
        ok = self.hop_ok(src, dst, ch)
        pdu = mac154(self.seq, 0x1A2B, int(self.by[dst].addr, 16) if self.by[dst].addr else 0xFFFF, int(self.by[src].addr, 16), b.done(), title="IEEE 802.15.4 MAC (WirelessHART)")
        dur = (len(pdu.b) + 6) * 8 / 250e3
        rssi = int(self.radio_model.rssi(src, dst))
        fr = rf_frame(self, src, dst, "WirelessHART", "%s  [ch %d, ASN %d]" % (info, ch[0], self.asn), pdu, dur, ch[1], 2.0, kind,
                      err=None if ok else "Lost: no ACK (channel %d interference / range)" % ch[0], rssi=rssi,
                      wirefn=lambda fr, d=dur: burst_wire(d, seed=self.asn, label="O-QPSK DSSS burst"), key=info.split(" ")[0] + " " + src)
        return fr, ok

    def route(self, d):
        ps = [p for p in self.parents[d] if self.by[p].on and not (self.fault["router"] and p == "lt")]
        return ps

    def publish_all(self):
        for d in ("pt", "tt", "lt", "vt", "pv"):
            n = self.by[d]
            if not n.on or (self.fault["router"] and d == "lt"):
                continue
            n.vars["PV"] = round(n.vars["PV"] + float(self.rng.normal(0, 0.05)), 2)
            pl = Bld("HART command 9 (burst)", "Read device variables with status")
            pl.u8("Command", 9, None, "")
            pl.raw("PV", struct.pack(">f", n.vars["PV"]), "%.2f" % n.vars["PV"], "")
            pl.u8("PV status", 0xC0, "good", "")
            pl.u8("Battery", 0x0C if self.fault["battery"] and d == "tt" else 0x00, "LOW" if self.fault["battery"] and d == "tt" else "OK", "")
            self.forward(d, pl.done(), 0)

    def forward(self, cur, payload, hops):
        if cur == "gw" or hops > 4:
            return
        ps = self.route(cur)
        n = self.by[cur]
        n.vars["Parents"] = ", ".join(self.by[p].label.split(" ")[0] for p in ps) or "NONE"
        for p in ps:
            fr, ok = self.pkt(cur, p, 0x0001, payload, "Publish %s via %s" % (cur.upper(), p.upper()), "data")
            fr.t = self.t + hops * 0.01 + 0.0001 * len(self.cap) % 0.005
            self.tx(fr, bus="air")
            if ok:
                self.at(fr.t + 0.01, self.forward, p, payload, hops + 1)
                break

    def manager(self):
        if self.fault["wifi"] and not self.blk:
            self.blk = {11, 12, 13, 14}
            self.log("Network manager blacklists channels 11-14 (Wi-Fi)")
            pl = Bld("Network manager command", "")
            pl.raw("Channel blacklist", b"\x0f\x00", "channels 11-14 disabled", "")
            fr, ok = self.pkt("gw", "lt", 0xFFFF, pl.done(), "Blacklist update", "ctl")
            self.tx(fr, bus="air")
        if not self.fault["wifi"]:
            self.blk = set()

    def on_fault(self, key, on):
        if key == "router":
            self.by["lt"].on = not on
        if key == "battery":
            self.by["tt"].vars["Battery"] = "LOW (update period 16 s)" if on else "OK"


# ============================================================= FOUNDATION Fieldbus
class FFH1(Scenario):
    key, name, cat = "ff", "FOUNDATION Fieldbus", "ind"
    blurb = "Process automation"
    phy, rate = "ffpa", 31250
    medium = "FOUNDATION Fieldbus H1: 31.25 kbit/s (IEC 61158-2), LAS schedule with 1 s macrocycle, AI -> PID -> AO control in the field"
    nets = [("BUS AC", "H1 signal"), ("BUS DC", "segment voltage")]
    lines = ["M"]
    faults = [("las", "Host (primary LAS) disconnected", "The backup Link Master in the valve takes over the schedule after missing the LAS's traffic; control in the field continues."),
              ("short", "Macrocycle cut to 150 ms", "The scheduled function blocks no longer fit: execution overruns and stale data."),
              ("addr", "Two devices at address 0x20", "Address conflict: one of them stays off the live list."),
              ("no_term1", "Terminator missing", "Reflections on the H1 segment.")]
    spec = [("Standard", "IEC 61158 Type 1 / IEC 61784, FieldComm Group"), ("Physical", "31.25 kbit/s Manchester, bus-powered, same as PROFIBUS PA (IEC 61158-2)"),
            ("Scheduler", "Link Active Scheduler (LAS): CD (compel data) for scheduled publishing, PT (pass token) for unscheduled traffic"),
            ("Model", "Function blocks (AI, PID, AO...) inside the devices, linked into control loops that run in the field"),
            ("Communication", "Publisher/subscriber (scheduled), client/server and report distribution (unscheduled)"),
            ("Housekeeping", "TD (time distribution), PN (probe node) for the live list, Link Masters as backup LAS")]
    frame = [["DLL PDU", ("Preamble", 8), ("Start delim", 8), ("FC", 8), ("Dest addr", "8-32"), ("Src addr", "0-32"), ("Data", "n x 8"), ("FCS-16", 16), ("End delim", 8)]]
    about = ("In FOUNDATION Fieldbus the control loop lives in the instruments: the transmitter's AI block publishes its output, the valve's PID "
             "block subscribes to it and drives the AO block, all on a schedule repeated every macrocycle. The Link Active Scheduler compels each "
             "publisher at exactly its time, and hands out the token for configuration traffic in the gaps.")
    guide = ["In FLOW, follow one macrocycle: CD to the transmitter, its AI publication, CD to the valve, PID publication, then PT tokens.",
             "Disconnect the host: the valve's backup LAS takes over.",
             "Change the PID setpoint with COMPOSE and watch the valve output move."]

    def build(self):
        h = self.node("host", "HOST / LAS", "server", 30, 40, "0x10 (LAS)", "DCS H1 card")
        tx = self.node("ft", "FLOW XMTR FT-101", "xmtr", 260, 260, "0x20", "AI block")
        vl = self.node("fv", "VALVE FV-101", "valve", 520, 260, "0x21", "PID + AO, link master")
        tt = self.node("tt", "TEMP TT-102", "temp", 740, 260, "0x22", "AI block")
        for n in (tx, vl, tt):
            n.at_top()
        self.trunk(180, 60, 860, [h, tx, vl, tt], "profibus", net="BUS AC", label="FF H1 segment (orange cable)", t0=True, t1=True, drop_conn="m12", tlabel="RC 100Ω+1µF")
        self.user = "host"
        tx.vars.update({"AI OUT m3/h": 42.0})
        tx.ctl = [("AI OUT m3/h", "FLOW", 0.0, 100.0, 0, lambda v: "%.1f" % v)]
        vl.vars.update({"PID SP": 50.0, "PID mode": "AUTO", "AO OUT %": 40.0})
        self.las = "host"
        self.every(1.0, self.macro, 0.05)

    def dll(self, src, dst, fc, data, info, kind, err=None):
        b = Bld("FF H1 Data Link (IEC 61158-4 Type 1)", "")
        b.u8("Frame control", fc, "0x%02X %s" % (fc, {0x01: "CD compel data", 0x02: "DT data transfer", 0x03: "PT pass token", 0x04: "TD time distribution", 0x05: "PN probe node", 0x06: "RT return token"}.get(fc, "")), "")
        b.u8("Destination", int(self.by[dst].addr.split(" ")[0], 16) if dst else 0xFF, None, "")
        if data:
            b.raw("Data", data, None, "")
        p = b.done()
        tb = 1.0 / 31250
        bits = msb(0x55, 8) + bytes_lsb(p.b) + msb(0x00, 16)

        def wf(fr):
            w = Wire(bit=tb)
            w.set("M", 0.0, 2)
            t = w.manch("M", bits, tb, tb, 1)
            w.seg(tb, 9 * tb, "PRE", 7, 1)
            w.seg(9 * tb, t, info.split(" (")[0], 1, 1)
            w.set("M", t, 2)
            w.end(t + tb)
            return w
        return Frame(self.t, (len(bits) + 2) * tb, src, dst, "FF H1", info, pdu=p, kind=kind, err=err, wirefn=wf, key=info.split(" ")[0] + " " + info.split(" ")[1])

    def macro(self):
        las = "fv" if (self.fault["las"] or not self.by["host"].on) else "host"
        if las != self.las:
            self.log("LAS role moved to %s" % las.upper())
            self.las = las
        self.by[las].state = "LAS"
        other = "host" if las == "fv" else "fv"
        self.by[other].state = "" if self.by[other].on else "OFF"
        t = self.by["ft"]
        err = "Schedule overrun: blocks do not fit the macrocycle" if self.fault["short"] else None
        self.tx(self.dll(las, "ft", 0x01, b"", "CD -> FT-101 (publish AI OUT)", "cmd"))
        self.tx(self.dll("ft", None, 0x02, struct.pack(">f", t.vars["AI OUT m3/h"]) + b"\x80", "DT FT-101 AI OUT %.2f good (published)" % t.vars["AI OUT m3/h"], "data", err))
        v = self.by["fv"]
        e = v.vars["PID SP"] - t.vars["AI OUT m3/h"]
        if v.vars["PID mode"] == "AUTO":
            v.vars["AO OUT %"] = max(0.0, min(100.0, round(v.vars["AO OUT %"] + 0.3 * e, 2)))
        self.tx(self.dll(las, "fv", 0x01, b"", "CD -> FV-101 (publish PID OUT)", "cmd"))
        self.tx(self.dll("fv", None, 0x02, struct.pack(">f", v.vars["AO OUT %"]) + b"\x80", "DT FV-101 PID OUT %.1f %%" % v.vars["AO OUT %"], "data", err))
        self.tx(self.dll(las, None, 0x04, struct.pack(">I", int(self.t * 1000)), "TD time distribution", "sync"))
        for d in ("ft", "fv", "tt"):
            self.tx(self.dll(las, d, 0x03, b"", "PT token -> %s" % self.by[d].label.split(" ")[-1], "ctl"))
            self.tx(self.dll(d, las, 0x06, b"", "RT return token from %s" % self.by[d].label.split(" ")[-1], "ack"))
        if self.fault["addr"]:
            self.tx(self.dll(las, "tt", 0x05, b"", "PN probe 0x20: TWO answers (address conflict)", "err", "Address conflict at 0x20"))

    def on_fault(self, key, on):
        if key == "las":
            self.by["host"].on = not on

    def cond(self, net):
        c = super().cond(net)
        if c["nterm"] < 2:
            c.update(atten=1.8, refl=0.3, ringf=4e5, ringd=6e-6)
        return c

    def tpls(self):
        return [Tpl("Write PID setpoint", [P("sp", "SP m3/h", 50.0, 0.0, 100.0, 1.0)], lambda s, v, send: self._sp(v, send), "Client/server write during the host's token time."),
                Tpl("Set PID mode", [P("m", "Mode", "AUTO", opts=["AUTO", "MAN", "CAS"])], lambda s, v, send: self._mode(v, send), "Target mode of the PID block.")]

    def _sp(self, v, send):
        f = self.dll("host", "fv", 0x02, struct.pack(">f", v["sp"]), "WRITE FV-101 PID.SP = %.1f" % v["sp"], "cmd")
        if send:
            self.by["fv"].vars["PID SP"] = v["sp"]
            return self.tx(f)
        return f

    def _mode(self, v, send):
        f = self.dll("host", "fv", 0x02, v["m"].encode(), "WRITE FV-101 PID.MODE_BLK = %s" % v["m"], "cmd")
        if send:
            self.by["fv"].vars["PID mode"] = v["m"]
            return self.tx(f)
        return f


# ================================================================ CC-Link
class CCLink(Scenario):
    key, name, cat = "cclink", "CC-Link", "ind"
    blurb = "Industrial automation networks"
    phy, rate = "rs485", 10e6
    medium = "CC-Link Ver.1.10 at 10 Mbit/s on dedicated 3-core cable (DA, DB, DG), master station 0 + 3 stations, 4 ms link refresh"
    nets = [("A", "DA"), ("B", "DB"), ("VDIFF", "DA - DB")]
    lines = ["D", "DE"]
    faults = [("dup", "Two stations set to station number 1", "Both answer the same poll: their responses collide and both report data link errors."),
              ("no_term1", "110 Ω terminator missing", "At 10 Mbit/s the unterminated end reflects; link errors."),
              ("speed", "Inverter set to 156 kbit/s", "A station on the wrong transmission speed never joins the link (SB0080 / SW0080 show it faulty)."),
              ("off", "Remote I/O powered off", "Its station is reported faulty; the rest of the link keeps scanning.")]
    spec = [("Standard", "CC-Link Partner Association (CLPA), IEC 61158 / 61784 Type 18"), ("Physical", "RS-485-based 3-core twisted cable, 156 kbit/s - 10 Mbit/s (1200 m - 100 m)"),
            ("Stations", "Master (0) + up to 64 stations; a device occupies 1-4 station numbers"), ("Cyclic data", "RX/RY bit devices and RWr/RWw word registers, refreshed every link scan"),
            ("Access", "Master polls each station; broadcast of output data"), ("Diagnostics", "Link special relays/registers SB/SW show station status")]
    frame = [["Polling frame", ("Flag", 8), ("Station no.", 8), ("Command", 8), ("RY/RWw data", "n x 8"), ("CRC", 16), ("Flag", 8)]]
    about = ("CC-Link is a Mitsubishi-originated fieldbus with a very simple data model: every station owns blocks of remote inputs (RX), remote "
             "outputs (RY) and 16-bit registers (RWr, RWw) in the master's memory. Each link scan the master polls the stations and refreshes all "
             "of them, so the PLC program just reads and writes those devices.")
    guide = ["Follow one link scan in FLOW: a poll and a response for each station.",
             "Write an RY bit with COMPOSE and see the remote I/O output change.",
             "Set the inverter to the wrong speed and read its status in the master's panel."]

    def build(self):
        m = self.node("m", "MASTER (st 0)", "plc", 30, 40, "station 0", "QJ61BT11N")
        sts = [("io", "REMOTE I/O", "io", 230, 1, 1), ("inv", "INVERTER", "drive", 470, 2, 1), ("hmi", "GOT HMI", "hmi", 700, 3, 2)]
        nodes = [m]
        for nid, lab, kind, x, st, occ in sts:
            n = self.node(nid, lab, kind, x - 30, 260, "station %d" % st, "%d occupied" % occ)
            n.at_top()
            n.extra["st"] = st
            n.vars.update({"RX": 0, "RY": 0, "RWr0": 0, "RWw0": 0, "Status": "OK"})
            nodes.append(n)
        self.trunk(180, 60, 860, nodes, "rs485", net="VDIFF", label="CC-Link Ver.1.10 cable, 10 Mbit/s", t0=True, t1=True, drop_conn="screw", tlabel="110 Ω")
        self.user = "m"
        self.by["io"].vars["RX"] = 0x0F
        self.by["io"].ctl = [("RX", "INPUTS RX", 0, 255, 1, lambda v: "0x%02X" % int(v))]
        self.by["inv"].vars["RWr0"] = 3000
        self.every(0.004, self.scan, 0.01)

    def cc(self, src, dst, st, cmd, data, info, kind, err=None):
        b = Bld("CC-Link frame", "Polling/response frame (simplified field layout).")
        b.u8("Flag", 0x7E, "0x7E", "Frame flag")
        b.u8("Station", st, None, "Polled station number")
        b.u8("Command", cmd, {0x10: "0x10 poll + RY/RWw refresh", 0x90: "0x90 response RX/RWr"}.get(cmd, "0x%02X" % cmd), "")
        b.raw("Data", data, None, "Cyclic bit/word data")
        c = crcn("CRC-16/X-25", bytes([st, cmd]) + data)
        b.u16("CRC", c, "0x%04X" % c, "")
        b.u8("Flag", 0x7E, "0x7E", "")
        return serial_frame(self, src, dst, "CC-Link", info, b.done(), 10e6, 8, "N", 1, rs485=2, kind=kind, err=err, key=info.split(" ")[0] + " st%d" % st)

    def cond(self, net):
        c = super().cond(net)
        if c["nterm"] < 2:
            c.update(refl=0.4, ringf=60e6, ringd=60e-9)
        return c

    def scan(self):
        if not self.by["m"].on:
            return
        for nid in ("io", "inv", "hmi"):
            n = self.by[nid]
            st = n.extra["st"]
            err = "Link error: reflections" if self.fault["no_term1"] and self.rng.random() < 0.1 else None
            self.tx(self.cc("m", nid, st, 0x10, struct.pack("<HH", int(n.vars["RY"]), int(n.vars["RWw0"])), "Poll st %d RY=0x%04X RWw0=%d" % (st, int(n.vars["RY"]), int(n.vars["RWw0"])), "cmd", err))
            if not n.on or (nid == "inv" and self.fault["speed"]) or (nid == "io" and self.fault["off"]):
                n.vars["Status"] = "FAULTY (SW0080 bit set)"
                n.state = "NO LINK"
                continue
            n.vars["Status"] = "OK"
            n.state = ""
            e2 = "Response collision (duplicate station number)" if self.fault["dup"] and st == 1 else err
            self.tx(self.cc(nid, "m", st, 0x90, struct.pack("<HH", int(n.vars["RX"]), int(n.vars["RWr0"])), "Resp st %d RX=0x%04X RWr0=%d" % (st, int(n.vars["RX"]), int(n.vars["RWr0"])), "resp", e2))

    def on_fault(self, key, on):
        if key == "off":
            self.by["io"].on = not on
        if key == "dup":
            self.by["hmi"].addr = "station 1 (!)" if on else "station 3"
            self.by["hmi"].extra["st"] = 1 if on else 3

    def tpls(self):
        return [Tpl("Write RY bits", [P("st", "Station", "io", opts=["io", "inv", "hmi"]), P("ry", "RY word", 0x0005, 0, 0xFFFF)], lambda s, v, send: self._w(v, "RY", "ry", send), "Remote outputs refreshed at the next link scan."),
                Tpl("Write RWw register", [P("st", "Station", "inv", opts=["io", "inv", "hmi"]), P("w", "RWw0", 4500, 0, 65535)], lambda s, v, send: self._w(v, "RWw0", "w", send), "For the inverter: frequency command in 0.01 Hz.")]

    def _w(self, v, var, k, send):
        if send:
            self.by[v["st"]].vars[var] = v[k]
        return None


# ============================================================== CC-Link IE
class CCLinkIE(IpNet):
    key, name, cat = "cclink_ie", "CC-Link IE", "ind"
    blurb = "Ethernet-based industrial networking"
    phy = "eth1000"
    link_rate = 1e9
    nets = [("PAIR A", "1000BASE-T pair A (PAM-5)"), ("PAIR B", "pair B")]
    lines = ["PA", "PB"]
    medium = "CC-Link IE Field: 1 Gbit/s Ethernet ring, token passing, master + 3 slaves, cyclic link devices RX/RY/RWr/RWw"
    faults = [("ring", "Cable between slave 2 and slave 3 cut", "Ring topology: the stations next to the break loop the frames back, the network keeps running as a line."),
              ("token", "Master loses the token (station reset)", "The token is regenerated after the token monitoring time."),
              ("dup", "Two stations set to number 2", "Station number duplication is detected; one station is disconnected.")]
    spec = [("Standard", "CLPA CC-Link IE Field (IEC 61158 Type 23); TSN version CC-Link IE TSN"), ("Physical", "1000BASE-T, Cat5e, 100 m per segment; line, star or ring"),
            ("Access", "Token passing: only the token holder sends its cyclic data"), ("Data", "Link devices RX/RY (bits), RWr/RWw (words), shared like a distributed memory"),
            ("Frames", "Ethernet frames with EtherType 0x890F"), ("Redundancy", "Ring with loopback on cable break")]
    frame = [["Cyclic frame", ("Ethernet hdr", 112), ("Type 0x890F", 16), ("Station no.", 8), ("Token/cyclic flags", 8), ("Link devices", "n x 8"), ("FCS", 32)]]
    about = ("CC-Link IE Field takes CC-Link's shared link devices to Gigabit Ethernet. Instead of the master polling, a token travels from station to "
             "station; whoever holds it broadcasts its share of the cyclic memory and then passes the token on. The cabling can form a ring that "
             "heals itself when a cable is cut.")
    guide = ["Watch the token frames circulate in FLOW, each followed by that station's cyclic data.",
             "Cut the ring between slaves 2 and 3: loopback, the scan continues."]

    def setup(self):
        names = [("m", "MASTER st 0", "plc", 60, 60), ("s1", "REMOTE I/O st 1", "io", 330, 60), ("s2", "SERVO AMP st 2", "servo", 600, 60), ("s3", "INVERTER st 3", "drive", 460, 290)]
        prev = None
        for i, (nid, lab, kind, x, y) in enumerate(names):
            n = self.node(nid, lab, kind, x, y, "station %d" % i)
            self.lan.host(nid, "00:26:92:00:00:%02x" % i)
            n.port = (x + n.w / 2, y + n.h / 2)
        pts = [(self.by["m"].x + 124, 86), (self.by["s1"].x, 86)]
        self.seg(pts, "cat6", net="PAIR A", c0="rj45", c1="rj45", label="ring, Cat5e")
        self.seg([(self.by["s1"].x + 124, 86), (self.by["s2"].x, 86)], "cat6", net="PAIR A", c0="rj45", c1="rj45")
        self.seg([(self.by["s2"].x + 62, 112), (self.by["s2"].x + 62, 316), (self.by["s3"].x + 124, 316)], "cat6", net="PAIR A", c0="rj45", c1="rj45")
        self.seg([(self.by["s3"].x, 316), (self.by["m"].x + 62, 316), (self.by["m"].x + 62, 112)], "cat6", net="PAIR A", c0="rj45", c1="rj45")
        for n in self.nodes:
            n.port = None
        self.by["m"].port = (self.by["m"].x + 124, 86)
        self.by["s1"].port = (self.by["s1"].x, 86)
        self.by["s2"].port = (self.by["s2"].x, 86)
        self.by["s3"].port = (self.by["s3"].x + 124, 316)
        self.seg([(self.by["s1"].x, 86), (self.by["s1"].x + 124, 86)], "cat6", w=1)
        self.seg([(self.by["s2"].x, 86), (self.by["s2"].x + 62, 86), (self.by["s2"].x + 62, 112)], "cat6", w=1)
        self.seg([(self.by["s3"].x + 124, 316), (self.by["s3"].x, 316)], "cat6", w=1)
        self.seg([(self.by["m"].x + 124, 86), (self.by["m"].x + 62, 86), (self.by["m"].x + 62, 112)], "cat6", w=1)
        self.user = "m"
        self.tok = 0
        for n in self.nodes:
            n.vars.update({"Token holds": 0, "RX/RY": "0x0000"})
        self.every(0.001, self.pass_token, 0.01)

    def pass_token(self):
        order = ["m", "s1", "s2", "s3"]
        if self.fault["token"] and self.rng.random() < 0.02:
            self.log("Token lost: regenerating after token monitoring time")
            self.tok = 0
            return
        h = order[self.tok % 4]
        self.tok += 1
        n = self.by[h]
        if not n.on:
            return
        n.vars["Token holds"] += 1
        st = order.index(h)
        b = Bld("CC-Link IE Field cyclic data", "")
        b.u8("Station", st, None, "Token holder")
        b.u8("Frame type", 0x21, "cyclic data + token", "")
        b.raw("RX/RY", struct.pack("<H", (int(self.t * 1000) + st) & 0xFFFF), None, "Bit link devices owned by this station")
        b.raw("RWr/RWw", bytes(8), None, "Word link devices")
        nxt = order[self.tok % 4]
        b.u8("Next token holder", order.index(nxt), None, "")
        err = "Station number duplication" if self.fault["dup"] and h == "s3" else None
        self.lan.l2(h, None, 0x890F, b.done(), "Token st %d -> cyclic data, token to st %d%s" % (st, order.index(nxt), " (looped back at break)" if self.fault["ring"] and h in ("s2", "s3") else ""),
                    "CCIEF", "data", dmac="09:00:70:00:10:02", err=err)

    def on_fault(self, key, on):
        if key == "ring":
            self.segs[2].broken = on
            self._paths.clear()


# ============================================================== SERCOS III
class Sercos3(IpNet):
    key, name, cat = "sercos3", "SERCOS III", "ind"
    blurb = "Motion control"
    medium = "SERCOS III ring: motion controller + 3 servo drives, 2 ms cycle, MDT/AT telegrams on both ports (P and S)"
    faults = [("ring", "Ring broken between drive 2 and drive 3", "Each half becomes a line served from one master port; the cycle continues without data loss (ring recovery)."),
              ("phase", "Drive 3 cannot switch to CP4", "Communication phase switching stops: drive 3 stays in CP2 with an error, axes not enabled."),
              ("mst", "Master Sync Telegram lost on drive 1", "Telegram failure counter increments; after too many, drive 1 reports a communication error.")]
    spec = [("Standard", "IEC 61158 / 61784 Type 19 (Sercos International)"), ("Topology", "Ring (redundant) or line on 100 Mbit/s Ethernet"),
            ("Telegrams", "MDT (master data, commands) and AT (acknowledge, feedback), up to 4 each per cycle"), ("Cycle", "31.25 us to 65 ms; hardware synchronised (< 1 us jitter)"),
            ("Phases", "CP0 (topology) -> CP1 -> CP2 (parameterisation) -> CP3 -> CP4 (operation)"), ("Parameters", "IDNs such as S-0-0036 velocity command, S-0-0051 position feedback")]
    frame = [["MDT", ("Ethernet hdr", 112), ("Type 0x88CD", 16), ("MST", 48), ("Hot-plug / service channel", "n"), ("Real-time data per drive", "n x 8"), ("FCS", 32)]]
    about = ("SERCOS III is designed for multi-axis motion: one Master Data Telegram per cycle carries the commanded position or velocity of every "
             "drive, and the drives fill the Acknowledge Telegram with feedback as it passes through them. Telegrams leave both master ports so a "
             "broken ring still reaches every drive. Before operation the network climbs through communication phases CP0-CP4.")
    guide = ["Watch MDT and AT telegrams every 1 ms; select one and find each drive's data field.",
             "Break the ring: telegrams arrive via the secondary port instead.",
             "Read IDN S-0-0051 with the service channel template."]

    def setup(self):
        hosts = [("m", "MOTION CTRL", "plc", 40, 150), ("d1", "SERVO 1", "servo", 260, 40), ("d2", "SERVO 2", "servo", 520, 40), ("d3", "SERVO 3", "servo", 520, 280)]
        for nid, lab, kind, x, y in hosts:
            n = self.node(nid, lab, kind, x, y, "", "")
            self.lan.host(nid, "00:20:93:00:00:%02x" % len(self.nodes))
            n.vars.update({"Phase": "CP0", "Pos cmd": 0, "Pos fbk": 0})
        m, d1, d2, d3 = (self.by[k] for k in ("m", "d1", "d2", "d3"))
        m.port = (m.x + 124, m.y + 20)
        d1.port = (d1.x, d1.y + 26)
        d2.port = (d2.x, d2.y + 26)
        d3.port = (d3.x + 62, d3.y)
        self.seg([m.port, (200, m.port[1]), (200, d1.port[1]), d1.port], "cat6", net="TX", c0="rj45", c1="rj45", label="P port")
        self.seg([(d1.x + 124, d1.port[1]), d2.port], "cat6", net="TX", c0="rj45", c1="rj45")
        self.seg([(d2.x + 62, d2.y + 52), d3.port], "cat6", net="TX", c0="rj45", c1="rj45")
        self.seg([(d3.x, d3.y + 26), (200, d3.y + 26), (200, m.y + 34), (m.x + 124, m.y + 34)], "cat6", net="TX", c0="rj45", c1="rj45", label="S port")
        self.seg([d1.port, (d1.x + 124, d1.port[1])], "cat6", w=1)
        self.seg([d2.port, (d2.x + 62, d2.port[1]), (d2.x + 62, d2.y + 52)], "cat6", w=1)
        self.seg([d3.port, (d3.x + 62, d3.y + 26), (d3.x, d3.y + 26)], "cat6", w=1)
        self.seg([m.port, (m.x + 124, m.y + 34)], "cat6", w=1)
        self.user = "m"
        self.cp = 0
        self.n = 0
        self.at(0.02, self.phase_up)
        self.every(0.002, self.cycle, 0.05)

    def phase_up(self):
        if self.cp < 4:
            self.cp += 1
            for d in ("d1", "d2", "d3"):
                ph = self.cp if not (d == "d3" and self.fault["phase"] and self.cp > 2) else 2
                self.by[d].vars["Phase"] = "CP%d%s" % (ph, " (ERROR: phase switch refused)" if ph < self.cp else "")
                self.by[d].state = "CP%d" % ph
            self.log("Communication phase CP%d" % self.cp)
            self.at(self.t + 0.05, self.phase_up)

    def tel(self, kind, data_rows, info, err=None):
        b = Bld("SERCOS III %s" % kind, "")
        b.u8("Telegram type", 0x00 if kind == "MDT0" else 0x80, kind, "MDT = master data telegram (commands), AT = acknowledge telegram (feedback)")
        b.u8("Phase", self.cp, "CP%d" % self.cp, "Current communication phase")
        b.u32("Cycle count", self.n, None, "")
        for lab, v in data_rows:
            b.raw(lab, struct.pack("<i", v), "%d" % v, "")
        return self.lan.l2("m", None, 0x88CD, b.done(), info, "SERCOS III", "data" if kind.startswith("MDT") else "resp", dmac="ff:ff:ff:ff:ff:ff", err=err)

    def cycle(self):
        if not self.by["m"].on or self.cp < 1:
            return
        self.n += 1
        rows = []
        for i, d in enumerate(("d1", "d2", "d3")):
            cmd = int(5000 * math.sin(self.t * 1.5 + i))
            self.by[d].vars["Pos cmd"] = cmd
            rows.append(("Drive %d S-0-0047 position command" % (i + 1), cmd))
        err = "MST lost at drive 1 (telegram failure)" if self.fault["mst"] and self.rng.random() < 0.05 else None
        path = " via S port (ring broken)" if self.fault["ring"] else ""
        self.tel("MDT0", rows, "MDT0 cycle %d (CP%d)%s" % (self.n, self.cp, path), err)
        fb = []
        for i, d in enumerate(("d1", "d2", "d3")):
            n = self.by[d]
            if self.cp >= 4 and not (d == "d3" and self.fault["phase"]):
                n.vars["Pos fbk"] = int(n.vars["Pos fbk"] + (n.vars["Pos cmd"] - n.vars["Pos fbk"]) * 0.4)
            fb.append(("Drive %d S-0-0051 position feedback" % (i + 1), n.vars["Pos fbk"]))
        self.tel("AT0", fb, "AT0 cycle %d feedback%s" % (self.n, path))

    def on_fault(self, key, on):
        if key == "ring":
            self.segs[2].broken = on
            self._paths.clear()
        if key == "phase" and not on:
            self.cp = 0
            self.at(self.t + 0.01, self.phase_up)

    def tpls(self):
        return [Tpl("Service channel: read IDN", [P("d", "Drive", "d1", opts=["d1", "d2", "d3"]), P("idn", "IDN", "S-0-0051", opts=["S-0-0002", "S-0-0036", "S-0-0040", "S-0-0047", "S-0-0051", "S-0-0100"])],
                    lambda s, v, send: self._idn(v, send), "S-0-0002 cycle time, S-0-0036 velocity command, S-0-0040 velocity feedback, S-0-0051 position feedback, S-0-0100 velocity loop gain.")]

    def _idn(self, v, send):
        val = {"S-0-0002": 1000, "S-0-0051": self.by[v["d"]].vars["Pos fbk"], "S-0-0047": self.by[v["d"]].vars["Pos cmd"]}.get(v["idn"], 0)
        if send:
            self.tel("MDT0", [("Service channel %s read" % v["idn"], 0)], "Service channel: read %s on %s" % (v["idn"], v["d"]))
            self.at(self.t + 0.002, lambda: self.tel("AT0", [("Service channel %s = %d" % (v["idn"], val), val)], "Service channel reply %s = %d" % (v["idn"], val)))
        return None


# ============================================================== POWERLINK
PL_MT = {1: "SoC", 3: "PReq", 4: "PRes", 5: "SoA", 6: "ASnd"}


class Powerlink(IpNet):
    key, name, cat = "powerlink", "POWERLINK", "ind"
    blurb = "Real-time Ethernet automation"
    medium = "Ethernet POWERLINK V2 on hubs: managing node (240) polls 3 controlled nodes every 4 ms (SoC, PReq/PRes, SoA/ASnd)"
    faults = [("loss", "CN 2 misses its PRes replies", "The MN counts loss-of-PRes; above the threshold the CN is removed from the isochronous phase and reset."),
              ("cycle", "Cycle time set below the poll time needed", "The isochronous phase overruns the cycle: cycle time exceeded errors."),
              ("mn2", "Second managing node connected", "Two MNs both send SoC: collisions and chaos - only one MN is allowed per network.")]
    spec = [("Standard", "EPSG DS 301, IEC 61158 Type 13"), ("Principle", "Software-only real time on standard Ethernet: the MN grants every transmission (polling)"),
            ("Cycle", "SoC -> PReq/PRes for each CN (isochronous) -> SoA -> ASnd (asynchronous)"), ("Nodes", "MN = 240, CNs 1-239; hubs recommended (low, constant latency)"),
            ("Frames", "EtherType 0x88AB; PRes are multicast so every node can read every other's data (cross-traffic)"), ("Upper layer", "CANopen object dictionary, SDO, PDO mapping")]
    frame = [["POWERLINK frame", ("Ethernet hdr", 112), ("Type 0x88AB", 16), ("Message type", 8), ("Dest node", 8), ("Src node", 8), ("Message data", "n x 8"), ("FCS", 32)]]
    about = ("POWERLINK makes Ethernet deterministic purely in software: nobody talks unless the managing node invites them. Each cycle starts with "
             "a Start of Cycle broadcast, then the MN sends a Poll Request to each controlled node in turn, which answers with a multicast Poll Response "
             "carrying its process data. An asynchronous slot at the end, granted by Start of Asynchronous, carries configuration and IP traffic.")
    guide = ["Watch a cycle in FLOW: SoC, then PReq/PRes pairs, SoA, ASnd.",
             "Note that PRes frames are multicast: CN 1 can consume CN 2's data directly.",
             "Inject loss of PRes on CN 2 and read the counter in the MN's DEVICE panel."]

    def setup(self):
        hosts = [("mn", "MANAGING NODE", "plc", 40, 40, "", "00:00:6c:00:00:f0", "node 240"), ("cn1", "I/O CN 1", "io", 700, 40, "", "00:00:6c:00:00:01", "node 1"),
                 ("cn2", "DRIVE CN 2", "drive", 40, 290, "", "00:00:6c:00:00:02", "node 2"), ("cn3", "ENCODER CN 3", "sensor", 700, 290, "", "00:00:6c:00:00:03", "node 3")]
        self.star(hosts, sw=("hub", "POWERLINK HUB", 380, 160))
        self.user = "mn"
        self.nid = {"mn": 240, "cn1": 1, "cn2": 2, "cn3": 3}
        self.by["mn"].vars.update({"Loss of PRes CN2": 0, "Cycle": "4 ms"})
        for d in ("cn1", "cn2", "cn3"):
            self.by[d].vars["NMT state"] = "OPERATIONAL (0xFD)"
        self.every(0.004, self.cycle, 0.01)
        self.n = 0

    def plf(self, src, dst, mt, data, info, kind, err=None):
        b = Bld("Ethernet POWERLINK", "")
        b.u8("Message type", mt, "%s (%d)" % (PL_MT[mt], mt), "")
        b.u8("Destination node", self.nid.get(dst, 255) if dst else 255, None, "255 = broadcast")
        b.u8("Source node", self.nid[src], None, "")
        if data:
            b.raw("Data", data, None, "")
        dmac = {1: "01:11:1e:00:00:01", 4: "01:11:1e:00:00:02", 5: "01:11:1e:00:00:03", 6: "01:11:1e:00:00:04"}.get(mt)
        return self.lan.l2(src, dst, 0x88AB, b.done(), info, "POWERLINK", kind, dmac=dmac if dmac else None, err=err)

    def cycle(self):
        if not self.by["mn"].on:
            return
        self.n += 1
        err = "SoC collision: two managing nodes" if self.fault["mn2"] else None
        self.plf("mn", None, 1, struct.pack("<Q", int(self.t * 1e9)), "SoC cycle %d" % self.n, "sync", err)
        for d in ("cn1", "cn2", "cn3"):
            self.plf("mn", d, 3, bytes([0x01, 0x00]) + bytes(4), "PReq -> CN %d" % self.nid[d], "cmd")
            if self.fault["loss"] and d == "cn2" and self.rng.random() < 0.6:
                self.by["mn"].vars["Loss of PRes CN2"] += 1
                continue
            self.plf(d, None, 4, bytes([0xFD, 0x00]) + struct.pack("<H", (self.n * 7 + self.nid[d]) & 0xFFFF), "PRes CN %d (multicast)" % self.nid[d], "resp")
        if self.fault["cycle"]:
            self.log("Cycle time exceeded: isochronous phase did not finish in time")
        self.plf("mn", None, 5, bytes([0xFD, 0x00, 0x00]), "SoA (no async request)", "ctl")

    def tpls(self):
        return [Tpl("ASnd IdentRequest", [P("d", "Node", "cn1", opts=["cn1", "cn2", "cn3"])], lambda s, v, send: self._id(v, send), "Asynchronous IdentRequest; the CN answers with its IdentResponse in the next async slot.")]

    def _id(self, v, send):
        if send:
            self.plf("mn", None, 5, bytes([0xFD, 0x01, self.nid[v["d"]]]), "SoA: IdentRequest -> CN %d" % self.nid[v["d"]], "cmd")
            self.at(self.t + 0.0002, lambda: self.plf(v["d"], None, 6, bytes([0x01]) + b"COMM-SIM CN", "ASnd IdentResponse from CN %d" % self.nid[v["d"]], "resp"))
        return None


# ================================================================== OPC UA
UA_SVC = {446: "OpenSecureChannelRequest", 449: "OpenSecureChannelResponse", 461: "CreateSessionRequest", 464: "CreateSessionResponse", 467: "ActivateSessionRequest",
          470: "ActivateSessionResponse", 527: "BrowseRequest", 530: "BrowseResponse", 631: "ReadRequest", 634: "ReadResponse", 673: "WriteRequest", 676: "WriteResponse",
          787: "CreateSubscriptionRequest", 790: "CreateSubscriptionResponse", 751: "CreateMonitoredItemsRequest", 754: "CreateMonitoredItemsResponse",
          826: "PublishRequest", 829: "PublishResponse", 452: "CloseSecureChannelRequest"}
UA_ST = {0: "Good", 0x80340000: "BadNodeIdUnknown", 0x80130000: "BadSecurityChecksFailed", 0x80250000: "BadSessionIdInvalid", 0x80560000: "BadTooManySessions"}


def ua_msg(mtype, chan, body_rows, svc=None, seq=1, req=1, status=None, extra=b""):
    body = Bld()
    if svc is not None:
        body.u8("NodeId encoding", 0x01, "4-byte numeric", "Encoding of the service type NodeId")
        body.u8("Namespace", 0, None, "")
        body.u16("Service", svc, "i=%d %s" % (svc, UA_SVC.get(svc, "")), "Binary encoding NodeId of the request/response type", little=True)
        if status is not None:
            body.u32("Timestamp", 0, None, "", little=True)
            body.u32("RequestHandle", req, None, "", little=True)
            body.u32("ServiceResult", status, "0x%08X %s" % (status, UA_ST.get(status, "")), "StatusCode: top bits 00 Good, 01 Uncertain, 10 Bad", little=True)
        else:
            body.u32("AuthenticationToken", 0x0001, "i=1", "Session authentication token", little=True)
            body.u32("RequestHandle", req, None, "", little=True)
            body.u32("TimeoutHint", 10000, "10000 ms", "", little=True)
    for lab, data, txt, desc in body_rows:
        body.raw(lab, data, txt, desc)
    inner = body.done()
    b = Bld("OPC UA Binary Protocol (opc.tcp), %s" % mtype, "IEC 62541: message chunks over TCP 4840.")
    b.text("MessageType", mtype, "HEL hello, ACK acknowledge, OPN open secure channel, MSG service message, CLO close, ERR error")
    b.text("ChunkType", "F", "F = final chunk, C = intermediate, A = abort")
    total = 8 + (12 if mtype in ("MSG", "OPN", "CLO") else 0) + len(inner.b) + len(extra)
    b.u32("MessageSize", total, None, "Size of this chunk", little=True)
    if mtype in ("MSG", "OPN", "CLO"):
        b.u32("SecureChannelId", chan, None, "Assigned by the server in OpenSecureChannel", little=True)
        b.u32("SequenceNumber", seq, None, "Increments per chunk (replay protection)", little=True)
        b.u32("RequestId", req, None, "Matches responses to requests", little=True)
    if extra:
        b.raw("Hello parameters", extra, None, "Protocol version, buffer sizes, max message size, endpoint URL")
    b.sub(inner)
    return b.done()


class OPCUA(IpNet):
    key, name, cat = "opcua", "OPC UA", "ind"
    blurb = "Industrial data exchange"
    medium = "OPC UA client/server over opc.tcp://plc:4840: secure channel, session, browse, subscription with 500 ms publishing"
    faults = [("cert", "Server does not trust the client certificate", "OpenSecureChannel with Sign&Encrypt is rejected: BadSecurityChecksFailed. Trust the certificate on the server."),
              ("node", "Client asks for 'Line1.Temprature' (typo)", "Read returns BadNodeIdUnknown for that item."),
              ("timeout", "Client stops sending PublishRequests", "No outstanding publish requests: notifications stop and finally the session times out (BadSessionIdInvalid).")]
    spec = [("Standard", "IEC 62541 (OPC Foundation)"), ("Transport", "opc.tcp binary on TCP 4840 (also HTTPS, WebSockets, PubSub over MQTT/UDP)"),
            ("Security", "Secure channel: None / Sign / SignAndEncrypt with X.509 certificates; user authentication in ActivateSession"),
            ("Model", "Address space of nodes (Objects, Variables, Methods) identified by NodeId (ns=2;s=Line1.Temperature)"),
            ("Services", "Read, Write, Browse, Call, Subscriptions with MonitoredItems, Publish"), ("Encoding", "UA Binary (little-endian) or JSON / XML")]
    frame = [["Message chunk", ("Type HEL/OPN/MSG", 24), ("Chunk F", 8), ("Size", 32), ("Channel ID", 32), ("Security header", "n"), ("Seq number", 32), ("Request ID", 32), ("Service body", "n x 8")]]
    about = ("OPC UA is the IT-friendly way to read and write plant data. A client opens a secure channel (certificates), creates and activates a "
             "session, then browses the server's address space of typed nodes. Instead of polling it creates a subscription: the server samples the "
             "monitored items and returns only changes in PublishResponses, which the client keeps requesting.")
    guide = ["Follow the start-up in FLOW: HEL/ACK, OPN, CreateSession, ActivateSession, Browse, CreateSubscription, CreateMonitoredItems.",
             "Select a PublishResponse to see a data change notification.",
             "Inject the certificate fault: the secure channel never opens.",
             "COMPOSE a Read of ns=2;s=Line1.Temperature, then of a non-existent node."]

    def setup(self):
        hosts = [("cli", "MES CLIENT", "server", 40, 60, "10.10.0.5", "00:15:5d:00:00:05"), ("srv", "PLC UA SERVER", "plc", 700, 60, "10.10.0.20", "00:1b:1b:00:00:20"),
                 ("hist", "HISTORIAN", "server", 380, 300, "10.10.0.30", "00:15:5d:00:00:30")]
        self.star(hosts)
        self.user = "cli"
        self.vals = {"Line1.Temperature": 72.4, "Line1.Pressure": 3.11, "Line1.MotorSpeed": 1480.0}
        self.by["srv"].vars.update(dict(self.vals))
        self.by["srv"].ctl = [("Line1.Temperature", "TEMP", 0.0, 150.0, 0, lambda v: "%.1f" % v)]
        self.req = 0
        self.seq = 1
        self.c = None
        self.chan = 0
        self.at(0.02, self.connect)

    def m(self, frm, mtype, rows, svc, info, kind, status=None, extra=b""):
        self.req += 1 if status is None else 0
        self.seq += 1
        p = ua_msg(mtype, self.chan, rows, svc, self.seq, self.req, status, extra)
        return self.c.send(frm, p, info, "OPC UA", kind, auto_ack=True)

    def connect(self):
        self.c = self.tcp("cli", "srv", 52010, 4840, "OPC UA")
        self.c.connect(on_open=self.hello)

    def hello(self):
        url = b"opc.tcp://plc:4840"
        ext = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + struct.pack("<i", len(url)) + url
        self.m("cli", "HEL", [], None, "Hello opc.tcp://plc:4840", "ctl", extra=ext)
        self.at(self.t + 0.001, lambda: self.m("srv", "ACK", [], None, "Acknowledge (buffer sizes agreed)", "ctl", extra=struct.pack("<IIIII", 0, 65536, 65536, 0, 0)))
        self.at(self.t + 0.002, self.opn)

    def opn(self):
        pol = b"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
        self.m("cli", "OPN", [("SecurityPolicyUri", pol, pol.decode(), "Asymmetric security header"), ("SecurityMode", b"\x03\x00\x00\x00", "SignAndEncrypt", "")], 446, "OpenSecureChannel (SignAndEncrypt)", "sec")
        if self.fault["cert"]:
            self.at(self.t + 0.002, lambda: self.m("srv", "ERR", [("Error", struct.pack("<I", 0x80130000), "BadSecurityChecksFailed", "Client certificate not trusted")], None, "ERR BadSecurityChecksFailed: certificate rejected", "err"))
            return
        self.chan = 7

        def ok():
            self.m("srv", "OPN", [("SecurityToken", struct.pack("<II", 7, 1), "channel 7 token 1", "Symmetric keys derived for this channel")], 449, "OpenSecureChannel response: channel 7", "sec", status=0)
            self.at(self.t + 0.001, self.session)
        self.at(self.t + 0.002, ok)

    def session(self):
        steps = [(461, "CreateSession", 464), (467, "ActivateSession (anonymous)", 470), (527, "Browse Objects folder", 530), (787, "CreateSubscription 500 ms", 790),
                 (751, "CreateMonitoredItems x3", 754)]
        t = 0.0
        for rq, nm, rs in steps:
            self.at(self.t + t, lambda rq=rq, nm=nm: self.m("cli", "MSG", [("Parameters", b"\x00" * 8, "", "")], rq, nm, "cmd"))
            self.at(self.t + t + 0.0015, lambda rs=rs, nm=nm: self.m("srv", "MSG", [("Results", b"\x01\x00\x00\x00" + b"\x00" * 8, "Good", "")], rs, nm + " response", "resp", status=0))
            t += 0.004
        self.at(self.t + t + 0.01, self.publish)

    def publish(self):
        if not self.c or not self.c.open or not self.by["cli"].on:
            return
        if self.fault["timeout"]:
            self.log("No PublishRequest outstanding; session will time out")
            self.at(self.t + 2.0, lambda: self.m("srv", "MSG", [("Result", b"", "", "")], 829, "PublishResponse: BadSessionIdInvalid (session timed out)", "err", status=0x80250000))
            return
        self.m("cli", "MSG", [("SubscriptionAcknowledgements", b"\x00\x00\x00\x00", "none", "")], 826, "PublishRequest", "cmd")
        for k in self.vals:
            self.vals[k] = self.by["srv"].vars.get(k, self.vals[k]) + float(self.rng.normal(0, 0.05))
            self.by["srv"].vars[k] = round(self.vals[k], 3)
        data = b"".join(struct.pack("<If", i + 1, v) for i, v in enumerate(self.vals.values()))
        txt = ", ".join("%s=%.2f" % (k.split(".")[1], v) for k, v in self.vals.items())
        self.at(self.t + 0.5, lambda: self.m("srv", "MSG", [("DataChangeNotification", data, txt, "ClientHandle + value for each monitored item that changed")], 829,
                                             "PublishResponse: DataChange %s" % txt, "data", status=0))
        self.at(self.t + 0.5, self.publish)

    def read(self, node, send=True):
        status = 0 if node in self.vals else 0x80340000
        nid = ("ns=2;s=" + node).encode()
        if not send or not self.c or not self.c.open:
            return Frame(self.t, 1e-5, "cli", "srv", "OPC UA", "Read %s" % node, pdu=ua_msg("MSG", 7, [("NodesToRead", nid, nid.decode(), "")], 631, 2, 2))
        fr = self.m("cli", "MSG", [("NodesToRead", nid, nid.decode(), "NodeId + AttributeId 13 (Value)")], 631, "Read ns=2;s=%s" % node, "cmd")
        v = self.vals.get(node)
        res = struct.pack("<f", v) if v is not None else struct.pack("<I", status)
        self.at(self.t + 0.002, lambda: self.m("srv", "MSG", [("Results", res, ("%.3f" % v) if v is not None else UA_ST[status], "DataValue (value, status, timestamps)")], 634,
                                               "ReadResponse %s" % (("%.3f" % v) if v is not None else UA_ST[status]), "resp" if v is not None else "err", status=0))
        return fr

    def on_fault(self, key, on):
        if key == "cert" and not on:
            self.at(self.t + 0.01, self.connect)
        if key == "timeout" and not on:
            self.at(self.t + 0.01, self.publish)

    def tpls(self):
        return [Tpl("Read node value", [P("n", "NodeId (ns=2;s=)", "Line1.Temperature", opts=["Line1.Temperature", "Line1.Pressure", "Line1.MotorSpeed", "Line1.Temprature"])],
                    lambda s, v, send: self.read(v["n"], send), "Read attribute 13 (Value) of a variable node. The last choice has a typo."),
                Tpl("Write node value", [P("n", "NodeId", "Line1.MotorSpeed", opts=list(self.vals.keys())), P("v", "Value", 1500.0, 0.0, 5000.0, 10.0)], lambda s, v, send: self._w(v, send), "WriteRequest with a Float value.")]

    def _w(self, v, send):
        if send and self.c and self.c.open:
            self.vals[v["n"]] = v["v"]
            self.by["srv"].vars[v["n"]] = v["v"]
            fr = self.m("cli", "MSG", [("NodesToWrite", struct.pack("<f", v["v"]), "%s = %.2f" % (v["n"], v["v"]), "")], 673, "Write %s = %.2f" % (v["n"], v["v"]), "cmd")
            self.at(self.t + 0.002, lambda: self.m("srv", "MSG", [("Results", b"\x00" * 4, "Good", "")], 676, "WriteResponse Good", "resp", status=0))
            return fr
        return None


# ==================================================================== MQTT
MQ_T = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
        12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}


def varint(n):
    out = bytearray()
    while True:
        d = n & 0x7F
        n >>= 7
        out.append(d | (0x80 if n else 0))
        if not n:
            return bytes(out)


def mstr(s):
    b = s.encode() if isinstance(s, str) else s
    return len(b).to_bytes(2, "big") + b


def mqtt_pkt(t, flags=0, var=b"", payload=b"", rows=None, v5=False):
    """MQTT control packet + dissection rows (list of (label, nbytes, txt, desc) for var+payload)."""
    rem = var + payload
    hdr = bytes([(t << 4) | flags]) + varint(len(rem))
    b = Bld("MQ Telemetry Transport Protocol%s, %s" % (" 5.0" if v5 else "", MQ_T[t]), "OASIS MQTT: lightweight publish/subscribe over TCP 1883 (8883 with TLS).")
    b.u8("Header flags", hdr[0], "0x%02X (%s%s)" % (hdr[0], MQ_T[t], (", QoS %d%s%s" % ((flags >> 1) & 3, ", retain" if flags & 1 else "", ", DUP" if flags & 8 else "")) if t == 3 else ""),
         "Packet type (upper 4 bits) + flags. For PUBLISH: DUP, QoS (2 bits), RETAIN.")
    b.raw("Remaining length", hdr[1:], "%d" % len(rem), "Variable-length integer (1-4 bytes, 7 bits each).")
    k = 0
    for lab, n, txt, desc in rows or []:
        b.raw(lab, rem[k:k + n], txt, desc)
        k += n
    if k < len(rem):
        b.raw("Payload" if k >= len(var) else "Data", rem[k:], None, "")
    return b.done()


def mq_connect(cid, keep=60, will=None, user=None, clean=True, v5=False):
    flags = (0x02 if clean else 0) | ((0x04 | 0x20) if will else 0) | (0xC0 if user else 0)
    var = mstr("MQTT") + bytes([5 if v5 else 4, flags]) + keep.to_bytes(2, "big") + (b"\x00" if v5 else b"")
    pl = mstr(cid) + ((b"\x00" if v5 else b"") + mstr(will[0]) + mstr(will[1]) if will else b"") + (mstr(user[0]) + mstr(user[1]) if user else b"")
    rows = [("Protocol name", 6, '"MQTT"', ""), ("Version", 1, "%d (MQTT %s)" % (5 if v5 else 4, "5.0" if v5 else "3.1.1"), ""),
            ("Connect flags", 1, "0x%02X%s%s%s" % (flags, " clean" if clean else "", " will(retain, QoS0)" if will else "", " user+pass" if user else ""), "Clean session, will flag/QoS/retain, username, password"),
            ("Keep alive", 2, "%d s" % keep, "Client must send something (or PINGREQ) within 1.5 x keep-alive")]
    if v5:
        rows.append(("Properties length", 1, "0", "MQTT 5 properties"))
    rows.append(("Client ID", 2 + len(cid), cid, "Unique per broker; a second connection with the same ID kicks the first one off"))
    if will:
        if v5:
            rows.append(("Will properties", 1, "0", ""))
        rows += [("Will topic", 2 + len(will[0]), will[0], "Published by the broker if this client disappears without DISCONNECT"), ("Will message", 2 + len(will[1]), will[1].decode("latin-1") if isinstance(will[1], bytes) else will[1], "")]
    if user:
        rows += [("Username", 2 + len(user[0]), user[0], ""), ("Password", 2 + len(user[1]), "********", "Sent in clear unless TLS is used")]
    return mqtt_pkt(1, 0, var, pl, rows, v5)


def mq_publish(topic, payload, qos=0, pid=None, retain=False, dup=False, v5=False, ptxt=None):
    var = mstr(topic) + (pid.to_bytes(2, "big") if qos else b"") + (b"\x00" if v5 else b"")
    rows = [("Topic", 2 + len(topic.encode()), topic, "UTF-8 topic name; '/' separates levels")]
    if qos:
        rows.append(("Packet identifier", 2, str(pid), "Used to match PUBACK / PUBREC-PUBREL-PUBCOMP"))
    if v5:
        rows.append(("Properties length", 1, "0", ""))
    rows.append(("Payload", len(payload), ptxt if ptxt is not None else payload[:60].decode("latin-1"), "Application data - the broker never looks inside"))
    return mqtt_pkt(3, (8 if dup else 0) | (qos << 1) | (1 if retain else 0), var, payload, rows, v5)


def pb_varint_field(f, v):
    return varint((f << 3) | 0) + varint(v)


def pb_float_field(f, v):
    return varint((f << 3) | 5) + struct.pack("<f", v)


def pb_str_field(f, s):
    b = s.encode() if isinstance(s, str) else s
    return varint((f << 3) | 2) + varint(len(b)) + b


def sparkplug(metrics, seq, ts):
    """Sparkplug B Payload protobuf: timestamp (1), metrics (2), seq (3)."""
    out = pb_varint_field(1, ts)
    for name, val in metrics:
        if isinstance(val, bool):
            m = pb_str_field(1, name) + pb_varint_field(4, 11) + pb_varint_field(14, 1 if val else 0)
        else:
            m = pb_str_field(1, name) + pb_varint_field(4, 9) + pb_float_field(12, val)
        out += pb_str_field(2, m)
    return out + pb_varint_field(3, seq)


class MQTTInd(IpNet):
    key, name, cat = "mqtt_ind", "MQTT", "ind"
    blurb = "Telemetry and industrial IoT"
    medium = "MQTT 3.1.1 broker on TCP 1883 with Sparkplug B topics: 2 edge gateways publish, SCADA subscribes; QoS 0/1/2, LWT, keep-alive"
    faults = [("drop", "Edge gateway 2 loses its network", "No DISCONNECT is sent; after 1.5 x keep-alive the broker publishes its Last Will (NDEATH) so SCADA marks its data stale."),
              ("dupid", "Edge 1 and a test tool use the same client ID", "The broker disconnects the existing session whenever the duplicate connects: the two keep knocking each other off."),
              ("qos2", "PUBREC from the broker lost", "QoS 2 handshake stalls; the publisher retransmits the PUBLISH with the DUP flag set."),
              ("acl", "Broker ACL denies SCADA's subscription to spBv1.0/#", "SUBACK returns 0x80 (failure) for that filter: no data arrives.")]
    spec = [("Standard", "OASIS MQTT 3.1.1 (ISO/IEC 20922) and MQTT 5.0; Eclipse Sparkplug B for industrial topic/payload structure"),
            ("Transport", "TCP 1883, TLS 8883, WebSockets"), ("Model", "Publish/subscribe through a broker; clients never address each other"),
            ("QoS", "0 at most once, 1 at least once (PUBACK), 2 exactly once (PUBREC, PUBREL, PUBCOMP)"), ("State", "Retained messages, persistent sessions, Last Will and Testament"),
            ("Sparkplug", "spBv1.0/<group>/<type>/<edge>/<device>, NBIRTH/NDEATH/DDATA..., protobuf payloads with sequence numbers")]
    frame = [["PUBLISH", ("Type 3 + DUP/QoS/RETAIN", 8), ("Remaining length", "8-32"), ("Topic length", 16), ("Topic", "n x 8"), ("Packet ID (QoS>0)", 16), ("Payload", "n x 8")]]
    about = ("MQTT decouples producers and consumers through a broker: an edge gateway publishes measurements to topics, SCADA subscribes with "
             "wildcards, and neither needs to know the other's address. QoS levels trade overhead for delivery guarantees, a Last Will message tells "
             "everyone when a client dies silently, and Sparkplug B adds a standard topic tree, birth/death certificates and compact protobuf payloads.")
    guide = ["Watch the CONNECT with its Last Will (NDEATH) and the NBIRTH publication.",
             "Select a DDATA PUBLISH: topic levels and the protobuf metrics.",
             "Compare QoS 1 (PUBACK) and QoS 2 (PUBREC/PUBREL/PUBCOMP) flows in FLOW.",
             "Pull edge gateway 2 off the network and wait for the broker to publish its NDEATH."]

    def setup(self):
        hosts = [("e1", "EDGE GATEWAY 1", "gw", 40, 40, "10.20.0.11", "b8:27:eb:00:00:11"), ("e2", "EDGE GATEWAY 2", "gw", 40, 290, "10.20.0.12", "b8:27:eb:00:00:12"),
                 ("brk", "MQTT BROKER", "broker", 700, 160, "10.20.0.2", "00:15:5d:00:00:02"), ("scada", "SCADA (host app)", "scada", 700, 40, "10.20.0.5", "00:15:5d:00:00:05")]
        self.star(hosts)
        self.user = "scada"
        self.cn = {}
        self.pid = 0
        self.seq = {"e1": 0, "e2": 0}
        self.by["e1"].vars.update({"Press01 bar": 6.2, "Pump01 run": True})
        self.by["e1"].ctl = [("Press01 bar", "PRESSURE", 0.0, 10.0, 0, lambda v: "%.2f" % v)]
        self.by["e2"].vars.update({"Tank02 %": 61.0})
        self.by["brk"].vars.update({"Clients": 0, "Subscriptions": 0, "Retained": 0})
        self.by["scada"].vars.update({"Edge 1": "-", "Edge 2": "-"})
        for i, c in enumerate(("scada", "e1", "e2")):
            self.at(0.01 + i * 0.01, self.connect, c)
        self.every(1.0, self.data, 0.3)
        self.every(15.0, self.pings, 5.0)

    def connect(self, c):
        conn = self.tcp(c, "brk", 50300 + len(self.cn), 1883, "MQTT")
        self.cn[c] = conn

        def on():
            will = ("spBv1.0/Plant1/NDEATH/%s" % ("Edge1" if c == "e1" else "Edge2"), sparkplug([("bdSeq", 0.0)], 0, 0)) if c != "scada" else None
            cid = {"scada": "scada-host-01", "e1": "Edge1", "e2": "Edge2"}[c]
            conn.send(c, mq_connect(cid, 30, will), "CONNECT client '%s'%s" % (cid, " with Last Will" if will else ""), "MQTT", "ctl", auto_ack=False)
            self.at(self.t + 0.001, lambda: conn.send("brk", mqtt_pkt(2, 0, b"\x00\x00", b"", [("Ack flags", 1, "session present 0", ""), ("Return code", 1, "0 (accepted)", "")]), "CONNACK accepted", "MQTT", "ctl"))
            self.by["brk"].vars["Clients"] += 1
            if c == "scada":
                self.at(self.t + 0.003, self.subscribe)
            else:
                self.at(self.t + 0.003, self.birth, c)
        conn.connect(on_open=on)

    def subscribe(self):
        c = self.cn["scada"]
        flt = "spBv1.0/Plant1/#"
        self.pid += 1
        c.send("scada", mqtt_pkt(8, 2, self.pid.to_bytes(2, "big"), mstr(flt) + b"\x01", [("Packet identifier", 2, str(self.pid), ""), ("Topic filter", 2 + len(flt), flt, "'#' matches all lower levels, '+' one level"), ("Requested QoS", 1, "1", "")]),
               "SUBSCRIBE %s QoS 1" % flt, "MQTT", "cmd", auto_ack=False)
        rc = 0x80 if self.fault["acl"] else 0x01
        self.at(self.t + 0.001, lambda: c.send("brk", mqtt_pkt(9, 0, self.pid.to_bytes(2, "big"), bytes([rc]), [("Packet identifier", 2, str(self.pid), ""), ("Return code", 1, "0x%02X %s" % (rc, "failure (ACL)" if rc == 0x80 else "granted QoS 1"), "")]),
                                               "SUBACK %s" % ("FAILURE 0x80" if rc == 0x80 else "QoS 1"), "MQTT", "resp" if rc != 0x80 else "err"))
        self.by["brk"].vars["Subscriptions"] = 0 if rc == 0x80 else 1

    def birth(self, c):
        name = "Edge1" if c == "e1" else "Edge2"
        self.pub(c, "spBv1.0/Plant1/NBIRTH/%s" % name, [("Node Control/Rebirth", False), ("bdSeq", 0.0)], qos=0, info="NBIRTH %s" % name)

    def pub(self, c, topic, metrics, qos=0, info=None, retain=False):
        conn = self.cn.get(c)
        if not conn or not conn.open or not self.by[c].on:
            return
        self.seq[c] = (self.seq.get(c, 0) + 1) % 256
        pl = sparkplug(metrics, self.seq[c], int(self.t * 1000))
        txt = "Sparkplug B protobuf: seq %d, " % self.seq[c] + ", ".join("%s=%s" % (n, ("%.2f" % v) if isinstance(v, float) else v) for n, v in metrics)
        pid = None
        if qos:
            self.pid += 1
            pid = self.pid
        conn.send(c, mq_publish(topic, pl, qos, pid, retain, ptxt=txt), "PUBLISH %s QoS %d" % (topic, qos), "MQTT", "data", auto_ack=False)
        if qos == 1:
            self.at(self.t + 0.001, lambda: conn.send("brk", mqtt_pkt(4, 0, pid.to_bytes(2, "big"), b"", [("Packet identifier", 2, str(pid), "")]), "PUBACK %d" % pid, "MQTT", "ack"))
        elif qos == 2:
            if self.fault["qos2"]:
                self.at(self.t + 0.5, lambda: conn.send(c, mq_publish(topic, pl, 2, pid, retain, dup=True, ptxt=txt), "PUBLISH %s QoS 2 DUP (no PUBREC received)" % topic, "MQTT", "err"))
            else:
                self.at(self.t + 0.001, lambda: conn.send("brk", mqtt_pkt(5, 0, pid.to_bytes(2, "big"), b"", [("Packet identifier", 2, str(pid), "")]), "PUBREC %d" % pid, "MQTT", "ack", auto_ack=False))
                self.at(self.t + 0.002, lambda: conn.send(c, mqtt_pkt(6, 2, pid.to_bytes(2, "big"), b"", [("Packet identifier", 2, str(pid), "")]), "PUBREL %d" % pid, "MQTT", "ack", auto_ack=False))
                self.at(self.t + 0.003, lambda: conn.send("brk", mqtt_pkt(7, 0, pid.to_bytes(2, "big"), b"", [("Packet identifier", 2, str(pid), "")]), "PUBCOMP %d" % pid, "MQTT", "ack"))
        self.at(self.t + 0.002, self.fanout, topic, pl, txt)

    def fanout(self, topic, pl, txt):
        if self.fault["acl"]:
            return
        s = self.cn.get("scada")
        if s and s.open and self.by["scada"].on:
            s.send("brk", mq_publish(topic, pl, 0, None, ptxt=txt), "PUBLISH -> SCADA %s" % topic, "MQTT", "data")
            edge = "Edge 1" if "Edge1" in topic else "Edge 2"
            self.by["scada"].vars[edge] = ("STALE (NDEATH)" if "NDEATH" in topic else "online")

    def data(self):
        e1 = self.by["e1"]
        self.pub("e1", "spBv1.0/Plant1/DDATA/Edge1/Press01", [("Pressure", float(e1.vars["Press01 bar"])), ("PumpRun", bool(e1.vars["Pump01 run"]))], qos=1)
        if not self.fault["drop"]:
            self.pub("e2", "spBv1.0/Plant1/DDATA/Edge2/Tank02", [("Level", float(self.by["e2"].vars["Tank02 %"]))], qos=2)

    def pings(self):
        for c, conn in self.cn.items():
            if conn.open and self.by[c].on and not (c == "e2" and self.fault["drop"]):
                conn.send(c, mqtt_pkt(12), "PINGREQ", "MQTT", "sync", auto_ack=False)
                self.at(self.t + 0.001, lambda conn=conn: conn.send("brk", mqtt_pkt(13), "PINGRESP", "MQTT", "sync"))

    def on_fault(self, key, on):
        if key == "drop" and on:
            self.at(self.t + 45.0 if False else self.t + 4.5, self.lwt)
        if key == "dupid" and on:
            self.log("Duplicate client ID 'Edge1': broker closes the older session")
            c = self.cn.get("e1")
            if c and c.open:
                c.reset("brk")
            self.at(self.t + 1.0, self.connect, "e1")

    def lwt(self):
        if self.fault["drop"]:
            self.log("Keep-alive expired for Edge2: broker publishes its Last Will")
            self.fanout("spBv1.0/Plant1/NDEATH/Edge2", sparkplug([("bdSeq", 0.0)], 0, 0), "Last Will: NDEATH Edge2")

    def tpls(self):
        return [Tpl("Publish", [P("t", "Topic", "spBv1.0/Plant1/DCMD/Edge1/Pump01"), P("v", "Value", 1.0, 0.0, 100.0), P("q", "QoS", 1, opts=[0, 1, 2]), P("r", "Retain", "no", opts=["no", "yes"])],
                    lambda s, v, send: self.pub("scada", v["t"], [("PumpRun" if "Pump" in v["t"] else "Value", v["v"])], v["q"], retain=v["r"] == "yes") if send else
                    Frame(self.t, 1e-5, "scada", "brk", "MQTT", "PUBLISH", pdu=mq_publish(v["t"], sparkplug([("Value", v["v"])], 1, 0), v["q"], 1 if v["q"] else None)),
                    "A Sparkplug DCMD (device command) is how a host writes to an edge device.")]


# ============================================================= DDS / RTPS
RTPS_SUB = {0x09: "INFO_TS", 0x15: "DATA", 0x07: "HEARTBEAT", 0x06: "ACKNACK", 0x0E: "INFO_DST"}


def rtps(prefix, subs):
    b = Bld("Real-Time Publish-Subscribe (RTPS 2.3)", "OMG DDSI-RTPS wire protocol for DDS, over UDP.")
    b.text("Magic", "RTPS", "")
    b.u16("Protocol version", 0x0203, "2.3", "")
    b.u16("Vendor ID", 0x0101, "0x0101 (example vendor)", "")
    b.raw("GUID prefix", prefix, prefix.hex(" "), "12 bytes: host, app and instance IDs; with an entity ID forms the 16-byte GUID")
    for sid, flags, body, desc in subs:
        b.u8("Submessage ID", sid, "%s (0x%02X)" % (RTPS_SUB.get(sid, "?"), sid), desc)
        b.u8("Flags", flags, "0x%02X (little-endian%s)" % (flags, ", inline QoS" if flags & 2 else ""), "")
        b.u16("Octets to next header", len(body), None, "", little=True)
        if body:
            b.raw("%s body" % RTPS_SUB.get(sid, ""), body, None, "")
    return b.done()


class DDS(IpNet):
    key, name, cat = "dds", "DDS", "ind"
    blurb = "Real-time distributed data exchange"
    medium = "OMG DDS over RTPS/UDP, domain 0: discovery multicast 239.255.0.1:7400, robot publishes 'RobotPose', planner subscribes (reliable)"
    faults = [("qos", "Planner reader RELIABLE, robot writer BEST_EFFORT", "Incompatible QoS: DDS refuses to match the endpoints (requested incompatible QoS) - no data flows."),
              ("domain", "HMI started in domain 1", "Different domain = different port numbers: it never discovers anyone."),
              ("mcast", "Switch blocks multicast", "SPDP discovery is multicast: participants never find each other unless peers are configured explicitly."),
              ("loss", "10 % packet loss on the planner link", "The reliable reader detects gaps from HEARTBEATs and asks for repairs with ACKNACK.")]
    spec = [("Standard", "OMG DDS 1.4 (API) + DDSI-RTPS 2.3 (wire protocol); used by ROS 2"), ("Transport", "UDP: discovery port 7400 + 250 x domain, user data 7401 / 7411..."),
            ("Discovery", "SPDP (participants, multicast) then SEDP (readers/writers, with QoS and topic types)"),
            ("QoS", "Reliability, durability, deadline, history, liveliness... matched writer-to-reader (request vs offer)"),
            ("Reliability", "HEARTBEAT announces available sequence numbers; ACKNACK requests missing ones"), ("Data", "Typed topics, CDR serialisation")]
    frame = [["RTPS message", ("RTPS 2.3 + vendor", 64), ("GUID prefix", 96), ("INFO_TS", 96), ("DATA: reader/writer IDs, SN, payload", "n x 8")]]
    about = ("DDS is a data-centric publish/subscribe middleware with no broker: participants find each other by multicast discovery, exchange "
             "descriptions of their readers and writers, and connect directly when topic, type and QoS policies are compatible. Reliable delivery "
             "uses heartbeats and negative acknowledgements. ROS 2 robots talk DDS.")
    guide = ["Watch SPDP participant announcements (multicast) and SEDP endpoint descriptions at start-up.",
             "Select a DATA submessage: writer sequence number + CDR payload.",
             "Make the QoS incompatible and see the planner stop receiving.",
             "Add packet loss and watch HEARTBEAT / ACKNACK repair the gaps."]

    def setup(self):
        hosts = [("robot", "ROBOT CONTROLLER", "servo", 40, 40, "192.168.10.11", "00:04:4b:00:00:11"), ("plan", "MOTION PLANNER", "server", 700, 40, "192.168.10.12", "00:04:4b:00:00:12"),
                 ("log", "DATA LOGGER", "server", 40, 290, "192.168.10.13", "00:04:4b:00:00:13"), ("hmi", "OPERATOR HMI", "hmi", 700, 290, "192.168.10.14", "00:04:4b:00:00:14")]
        self.star(hosts)
        self.user = "robot"
        self.sn = 0
        self.matched = False
        self.pfx = {h: bytes([0x01, 0x0F] + [i] * 10) for i, h in enumerate(("robot", "plan", "log", "hmi"))}
        self.by["plan"].vars.update({"Samples": 0, "Matched": "no", "Repairs": 0})
        self.by["hmi"].vars["Discovered"] = 0
        self.at(0.01, self.discover)
        self.every(3.0, self.discover, 3.0)
        self.every(0.05, self.publish, 0.2)

    def discover(self):
        for h in ("robot", "plan", "log", "hmi"):
            dom = 1 if (h == "hmi" and self.fault["domain"]) else 0
            pl = struct.pack("<HH", 0x0003, 0) + ("participant %s domain %d" % (h, dom)).encode()
            err = "Multicast blocked by the switch" if self.fault["mcast"] else None
            self.lan.udp(h, None, 7410, 7400 + 250 * dom, rtps(self.pfx[h], [(0x15, 0x05, pl, "SPDP DATA(p): participant announcement")]), "SPDP DATA(p) %s (domain %d)" % (h, dom), "RTPS", "bcast",
                         dip="239.255.0.1", dmac="01:00:5e:7f:00:01", err=err)
        if not self.fault["mcast"]:
            rel = b"RELIABLE" if not self.fault["qos"] else b"BEST_EFFORT"
            self.lan.udp("robot", "plan", 7410, 7410, rtps(self.pfx["robot"], [(0x15, 0x05, b"SEDP DATA(w) topic RobotPose type geometry::Pose reliability " + rel, "SEDP publication")]),
                         "SEDP DATA(w) RobotPose (%s)" % rel.decode(), "RTPS", "ctl")
            self.lan.udp("plan", "robot", 7410, 7410, rtps(self.pfx["plan"], [(0x15, 0x05, b"SEDP DATA(r) topic RobotPose reliability RELIABLE", "SEDP subscription")]),
                         "SEDP DATA(r) RobotPose (RELIABLE)", "RTPS", "ctl")
            self.matched = not self.fault["qos"]
            self.by["plan"].vars["Matched"] = "yes" if self.matched else "NO: requested incompatible QoS (reliability)"
            self.by["hmi"].vars["Discovered"] = 0 if self.fault["domain"] else 3
        else:
            self.matched = False
            self.by["plan"].vars["Matched"] = "no (no discovery)"

    def publish(self):
        if not self.by["robot"].on:
            return
        self.sn += 1
        x, y = math.cos(self.t * 0.5), math.sin(self.t * 0.5)
        payload = struct.pack("<HH", 0x0001, 0) + struct.pack("<ddd", x, y, 0.3)
        body = bytes(4) + b"\x00\x00\x01\x02" + b"\x00\x00\x01\x03" + struct.pack("<iI", 0, self.sn) + payload
        subs = [(0x09, 0x01, struct.pack("<II", int(self.t), 0), "Timestamp"), (0x15, 0x05, body, "DATA: extra flags, readerId, writerId, writerSN, serialized payload (CDR_LE)")]
        if self.matched:
            lost = self.fault["loss"] and self.rng.random() < 0.1
            fr = self.lan.udp("robot", "plan", 50000, 7411, rtps(self.pfx["robot"], subs), "DATA RobotPose SN %d (x=%.2f y=%.2f)" % (self.sn, x, y), "RTPS", "data",
                              err="Lost on the link" if lost else None)
            if not lost:
                self.by["plan"].vars["Samples"] += 1
            if self.sn % 10 == 0:
                self.lan.udp("robot", "plan", 50000, 7411, rtps(self.pfx["robot"], [(0x07, 0x01, struct.pack("<iIiIi", 0, 1, 0, self.sn, self.sn // 10), "HEARTBEAT: first..last available SN")]),
                             "HEARTBEAT SN 1..%d" % self.sn, "RTPS", "sync")
                if self.fault["loss"]:
                    self.lan.udp("plan", "robot", 7411, 50000, rtps(self.pfx["plan"], [(0x06, 0x01, struct.pack("<iI", 0, self.sn - 3), "ACKNACK: bitmap of missing samples")]),
                                 "ACKNACK missing SN %d" % (self.sn - 3), "RTPS", "ack")
                    self.by["plan"].vars["Repairs"] += 1
        self.lan.udp("robot", "log", 50000, 7411, rtps(self.pfx["robot"], subs), "DATA RobotPose SN %d -> logger (best effort)" % self.sn, "RTPS", "data")

    def on_fault(self, key, on):
        self.discover()
