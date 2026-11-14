"""Physical interfaces, part A: RS-232, RS-422, RS-485, RS-423, RS-449,
UART and IEEE-488 / GPIB."""
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import xor8, crcn, hdlc_stuff, bytes_lsb, msb, lsb
from .fam import serial_frame, char_time


def txt_pdu(layer, s, desc, label="Text"):
    b = Bld(layer, desc)
    body = s.rstrip("\r\n")
    term = s[len(body):]
    b.text(label, body, "The characters of the message, one UART character each.")
    if term:
        b.text("Terminator", term, "Line terminator (CR / LF) that tells the receiver the message is complete.")
    return b.done()


# =================================================================== RS-232
class RS232(Scenario):
    key, name, cat = "rs232", "RS-232", "phys"
    blurb = "Serial communication, instruments, legacy equipment"
    phy, rate = "rs232", 9600
    medium = "TIA-232-F, DB9, 9600 bit/s 8N1, RTS/CTS hardware handshake, 2 m cable"
    nets = [("TXD", "pin 3, PC transmit"), ("RXD", "pin 2, PC receive"), ("RTS", "pin 7, request to send"),
            ("CTS", "pin 8, clear to send"), ("DTR", "pin 4, terminal ready"), ("DSR", "pin 6, set ready"), ("GND", "pin 5")]
    lines = ["TX", "RX", "RTS", "CTS", "DTR", "DSR"]
    faults = [("straight", "Straight cable between two DTE ports", "Both ends drive pin 3 and listen on pin 2: nobody hears anybody. Needs a null-modem (crossover) cable."),
              ("baud", "PC set to 19200, instrument at 9600", "Each received character is sampled at the wrong instants: framing errors and garbage."),
              ("parity", "PC sends 7E1, instrument expects 8N1", "The parity bit is taken as data bit 7, so characters arrive changed."),
              ("gnd", "Signal ground (pin 5) not connected", "RS-232 is single-ended: without the common return the receiver sees noise and offsets."),
              ("flow", "PC ignores CTS (no hardware flow control)", "The instrument drops CTS while its input buffer is busy; characters sent anyway are lost (overrun)."),
              ("long", "60 m cable at 115200 bit/s", "Cable capacitance + the slew-rate limit round the edges until bits merge. TIA-232 allows about 2500 pF (15 m) at 20 kbit/s."),
              ("ttl", "3.3 V TTL device wired straight to the port", "TTL idles high at 3.3 V with non-inverted logic; RS-232 needs <-3 V for mark and >+3 V for space.")]
    spec = [("Standard", "TIA-232-F / ITU-T V.24 + V.28"), ("Signalling", "Single-ended, inverted: mark (1) = -3..-15 V, space (0) = +3..+15 V"),
            ("Rate / distance", "Up to 20 kbit/s at 15 m (spec); 115.2 kbit/s common on short cables"),
            ("Connector", "DB9 (DE-9) or DB25; DTE male, DCE female"), ("Topology", "Point-to-point, one transmitter per line"),
            ("Handshake", "RTS/CTS (hardware), DTR/DSR (device ready), XON/XOFF (software)"), ("Framing", "Asynchronous: start bit, 5-8 data bits LSB first, parity, 1-2 stop bits")]
    frame = [["UART character", ("idle", "mark"), ("start", 1), ("D0..D7 LSB first", 8), ("parity", 1), ("stop", 1)],
             ["DB9 pinout (DTE)", ("1 DCD", 1), ("2 RXD", 1), ("3 TXD", 1), ("4 DTR", 1), ("5 GND", 1), ("6 DSR", 1), ("7 RTS", 1), ("8 CTS", 1), ("9 RI", 1)]]
    about = ("RS-232 is the original serial port: one wire per signal referenced to a common ground, with inverted bipolar voltages. "
             "A PC (DTE, Data Terminal Equipment) talks to an instrument wired as DCE (Data Communication Equipment): TXD of one goes to RXD of the other. "
             "Two DTEs need a null-modem cable that crosses TXD/RXD and the handshake pairs. The breakout box in the wiring view shows each line's state the way a real one does.")
    guide = ["Click the TXD cable, open SCOPE, press AUTOSET: idle is about -9 V (mark); each start bit swings to +9 V.",
             "In LOGIC, count the bits of one character: start, 8 data bits LSB first, stop. 9600 bit/s = 104 us per bit.",
             "Inject 'PC set to 19200': the instrument returns nothing and the frames are flagged. Then try the parity fault: characters change instead of vanishing.",
             "Inject 'Straight cable between two DTE ports' and watch the breakout box: both ends drive TXD, RXD stays idle.",
             "Inject the 60 m cable fault and use the EYE button on the scope to see the eye close as the edges slow down.",
             "Use COMPOSE to send *IDN? and read the identity string in the ANALYZER hex dump."]

    def build(self):
        pc = self.node("pc", "PC  COM1", "pc", 40, 150, "DTE", "9600 8N1")
        bb = self.node("bob", "BREAKOUT BOX", "box", 360, 40, "", "line monitor", w=150, h=46)
        bb.extra["power"] = False
        dmm = self.node("dmm", "BENCH DMM", "meter", 700, 150, "DCE", "RS-232 port")
        pc.at_right()
        dmm.at_left()
        self.seg([pc.port, (360, pc.port[1]), (520, pc.port[1]), dmm.port], "rs232", net="TXD", label="DB9 serial cable, 2 m", c0="db9", c1="db9")
        self.seg([(435, 86), (435, pc.port[1])], "ribbon", net="RXD")
        self.user = "pc"
        self.sel = "dmm"
        pc.vars.update({"Port": "COM1", "Format": "9600 8N1", "Flow control": "RTS/CTS", "Last reply": "-"})
        dmm.vars.update({"Reading": 12.3456, "Mode": "DC V", "Errors": 0, "Input buffer": "0/256"})
        dmm.ctl = [("Reading", "INPUT V", -20.0, 20.0, 0, lambda v: "%+.4f" % v)]
        self.cts = True
        self.every(0.5, self.poll, 0.1)
        self.every(0.05, self.drift)

    def drift(self):
        d = self.by["dmm"]
        d.vars["Reading"] = d.vars["Reading"] + float(self.rng.normal(0, 0.0004))

    def cond(self, net):
        c = super().cond(net)
        if self.fault["gnd"] and net != "GND":
            c.update(noise=1.2, off=float(self.rng.normal(0, 2.5)), cm=0)
        if self.fault["long"]:
            c["rise"] = 9.0
        if self.fault["ttl"] and net == "RXD":
            c.update(inv=True, atten=0.19, off=1.65)
        return c

    def msg(self, src, s, kind="cmd", corrupt_why=None, baud=None, parity="N", bits=8, on_rx=None):
        line = "TX" if src == "pc" else "RX"
        dst = "dmm" if src == "pc" else "pc"
        pdu = txt_pdu("RS-232 async characters", s, "ASCII characters sent as asynchronous UART frames over RS-232 levels.")

        def extra(w, spans, line=line):
            other = "RX" if line == "TX" else "TX"
            w.set(other, 0.0, 1)
            for ln, v in (("RTS", 1), ("DTR", 1), ("DSR", 1), ("CTS", 1 if self.cts else 0)):
                w.set(ln, 0.0, v)
            if self.fault["straight"] and line == "TX":
                w.seg(0, w.T, "TXD wired to TXD: no receiver on this line", 8, 1)
        fr = serial_frame(self, src, dst, "RS-232", s.strip(), pdu, baud or 9600, bits, parity, 1, line=line, kind=kind,
                          err=corrupt_why, extra=extra, key="PC>DMM" if src == "pc" else "DMM>PC")
        fr.meta["text"] = s
        return fr

    def poll(self):
        if not self.by["pc"].on:
            return
        self.send_cmd("MEAS:VOLT:DC?\r\n")

    def send_cmd(self, s):
        why = None
        baud, par, bits = 9600, "N", 8
        if self.fault["straight"]:
            why = "No receiver: straight cable puts PC TXD on instrument TXD"
        elif self.fault["baud"]:
            baud, why = 19200, "Instrument sampling at 9600: framing errors"
        elif self.fault["parity"]:
            par, bits, why = "E", 7, "Instrument expects 8N1: characters arrive corrupted"
        elif self.fault["ttl"]:
            why = "Levels wrong: TTL 0/3.3 V is not a valid RS-232 mark/space"
        elif self.fault["long"]:
            baud = 115200
            if self.rng.random() < 0.6:
                why = "Edges too slow for 115200 bit/s on 60 m: bit errors"
        elif self.fault["gnd"] and self.rng.random() < 0.5:
            why = "Garbled by ground noise"
        elif self.fault["flow"] and self.rng.random() < 0.4:
            why = "Overrun: sent while CTS was off, characters lost"
        fr = self.msg("pc", s, "cmd", why, baud, par, bits)
        self.tx(fr, bus="TXD")
        return fr

    def rx(self, fr):
        if fr.src == "pc":
            d = self.by["dmm"]
            if fr.err or not d.on:
                if fr.err:
                    d.vars["Errors"] = d.vars["Errors"] + 1
                return
            cmd = fr.meta.get("text", "").strip().upper()
            if cmd.startswith("MEAS") or cmd == "READ?":
                rep = "%+.5E\r\n" % d.vars["Reading"]
            elif cmd == "*IDN?":
                rep = "COMMSIM,DMM-6510,SN04711,1.07\r\n"
            elif cmd in ("*RST", "*CLS"):
                d.vars["Errors"] = 0
                return
            elif cmd.startswith("SYST:ERR"):
                rep = "+0,\"No error\"\r\n" if not d.vars["Errors"] else "-113,\"Undefined header\"\r\n"
            else:
                d.vars["Errors"] = d.vars["Errors"] + 1
                return
            self.cts = not (self.fault["flow"] and self.rng.random() < 0.5)
            r = self.msg("dmm", rep, "resp")
            r.t = self.t + 0.002
            self.tx(r, bus="RXD")
        else:
            self.by["pc"].vars["Last reply"] = fr.meta.get("text", "").strip()

    def tpls(self):
        return [Tpl("SCPI command", [P("cmd", "Command", "*IDN?"), P("term", "Terminator", "CR LF", opts=["CR LF", "LF", "CR"])],
                    lambda s, v, send: self._cmd(v, send), "Any SCPI text: *IDN?, MEAS:VOLT:DC?, READ?, SYST:ERR?, *RST. The instrument answers queries ending in '?'."),
                Tpl("Read voltage", [], lambda s, v, send: self._cmd({"cmd": "MEAS:VOLT:DC?", "term": "CR LF"}, send), "One DC voltage measurement.")]

    def _cmd(self, v, send):
        s = v["cmd"] + {"CR LF": "\r\n", "LF": "\n", "CR": "\r"}[v["term"]]
        if send:
            return self.send_cmd(s)
        return self.msg("pc", s)

    def inspect(self, n):
        rows = list(n.vars.items())
        if n.id == "bob":
            st = self.cts
            rows = [("TD (pin 3)", "activity" if self.t - (self.cap[-1].t if self.cap else -9) < 0.6 else "idle (mark)"),
                    ("RD (pin 2)", "dead - straight cable!" if self.fault["straight"] else "ok"), ("RTS", "ON"), ("CTS", "ON" if st else "OFF"),
                    ("DTR", "ON"), ("DSR", "ON"), ("DCD", "OFF"), ("Ground", "OPEN" if self.fault["gnd"] else "ok")]
        return rows

    def draw_extra(self, s, r):
        import pygame
        from .. import ui
        x, y = r.x + 372, r.y + 92
        names = [("TD", True), ("RD", not self.fault["straight"]), ("RTS", True), ("CTS", self.cts), ("DTR", True), ("DSR", True), ("CD", False)]
        last = self.cap[-1] if self.cap else None
        now_act = last is not None and (self.t - last.t) < 0.25
        for i, (nm, on) in enumerate(names):
            col = (255, 66, 56) if nm in ("TD", "RD") else (70, 255, 120)
            lit = on and (nm not in ("TD", "RD") or now_act)
            ui.led(s, (x + i * 19 + 6, y + 6), col, lit, r=4)
            ui.text(s, nm, (x + i * 19 + 6, y + 14), 8, (200, 200, 190), align="c")
        del pygame


# =================================================================== RS-422
class RS422(Scenario):
    key, name, cat = "rs422", "RS-422", "phys"
    blurb = "Differential serial communication, avionics, industrial equipment"
    phy, rate = "rs422", 115200
    medium = "TIA-422-B 4-wire full duplex, 115200 bit/s, one driver per pair, 100 Ω at the far end"
    nets = [("A", "TX pair A (-)"), ("B", "TX pair B (+)"), ("VDIFF", "TX pair B-A"), ("RA", "RX pair A"), ("RB", "RX pair B"), ("RDIFF", "RX pair B-A")]
    lines = ["D", "R"]
    faults = [("no_term0", "100 Ω terminator missing (TX pair)", "With 300 m of cable and fast edges, the unterminated end reflects each edge back: ringing that the receivers may count as extra transitions."),
              ("swap", "A/B reversed at the data logger", "A reversed differential pair inverts every bit for that receiver: all its characters are garbage while the drive is fine."),
              ("loads", "14 receivers hung on one driver", "TIA-422 allows 10 unit loads. Each extra receiver lowers the differential swing until margins vanish."),
              ("cm", "9 V ground difference between cabinets", "TIA-422 receivers tolerate -7..+7 V common mode. Beyond that they clip and corrupt data."),
              ("drv", "Drive's transmitter failed (RX pair dead)", "The return pair floats: the controller sees no replies and noise.")]
    spec = [("Standard", "TIA/EIA-422-B, ITU-T V.11"), ("Signalling", "Balanced differential: |B-A| >= 2 V driven, receiver threshold +/-200 mV"),
            ("Rate / distance", "10 Mbit/s at 12 m; 100 kbit/s at 1200 m (4000 ft)"), ("Loads", "1 driver, up to 10 receivers per pair"),
            ("Topology", "Point-to-point or multidrop listeners (simplex / full duplex with 2 pairs)"), ("Common mode", "-7 V .. +7 V"),
            ("Termination", "100 Ω at the far end of each pair")]
    frame = [["Vendor binary packet", ("STX 0x02", 8), ("CMD", 8), ("LEN", 8), ("DATA", "LEN x 8"), ("XOR", 8), ("ETX 0x03", 8)]]
    about = ("RS-422 sends each signal as the difference between two wires of a twisted pair. Noise couples equally into both wires and cancels in the "
             "receiver, which is why it reaches 1200 m. Unlike RS-485 there is only ever one driver per pair, so a full-duplex link needs two pairs. "
             "Here a motion controller commands a servo drive over one pair (a data logger listens on the same pair) and the drive answers on the other.")
    guide = ["Probe A and B separately (CH1, CH2) and turn on MATH: each wire swings ~2.5 V but the difference swings +/-2.5 V around zero.",
             "Remove the terminator and press AUTOSET: ringing appears after every edge.",
             "Reverse A/B at the logger: the drive keeps working but the logger's frames are flagged - only that receiver sees inverted data.",
             "Inject the 9 V ground difference: SCOPE shows both wires shifted up; the difference is unchanged until the receiver's common-mode range is exceeded."]

    def build(self):
        c = self.node("ctl", "MOTION CTRL", "plc", 40, 60, "TX pair driver", "115200 8N1")
        d = self.node("drv", "SERVO DRIVE", "drive", 700, 60, "addr 1", "RS-422 port")
        lg = self.node("log", "DATA LOGGER", "pc", 380, 250, "listener", "on TX pair")
        c.at_right()
        d.at_left()
        y = c.port[1]
        self.seg([c.port, (440, y), d.port], "rs485", net="VDIFF", label="TX pair  (shielded twisted pair, 300 m)", c0="screw", c1="screw")
        self.seg([(440, y), (440, 250)], "rs485", net="VDIFF", c1="screw")
        self.seg([(d.x, d.y + 40), (c.x + c.w, d.y + 40)], "rs485", net="RDIFF", label="RX pair", c0="screw", c1="screw")
        self.term(690, y - 16, "100 Ω", True, "term0")
        self.user = "ctl"
        self.pos, self.tgt = 0, 0
        d.vars.update({"Position": 0, "Target": 0, "Status": "READY", "Errors": 0})
        lg.vars.update({"Frames logged": 0, "Garbled": 0})
        c.vars.update({"Cycle": "20 ms", "Replies": 0})
        self.every(0.02, self.cycle, 0.005)

    def cond(self, net):
        c = super().cond(net)
        if net in ("A", "B", "VDIFF") and self.fault["no_term0"]:
            c.update(refl=0.45, ringf=1.6e6, ringd=1.2e-6)
        if self.fault["loads"] and net in ("A", "B", "VDIFF"):
            c["atten"] = 0.42
        if self.fault["cm"] and net in ("A", "B", "RA", "RB"):
            c["off"] = 9.0
        if self.fault["drv"] and net in ("RA", "RB", "RDIFF"):
            c.update(atten=0.0, noise=0.08)
        return c

    def pkt(self, cmd, data):
        body = bytes([cmd, len(data)]) + data
        x = xor8(body)
        b = Bld("Vendor binary protocol", "Simple framed binary protocol typical of drives and encoders on RS-422.")
        b.u8("STX", 2, "0x02", "Start of text")
        b.u8("Command", cmd, {0x10: "0x10 Move to position", 0x11: "0x11 Status reply"}.get(cmd, "0x%02X" % cmd), "Operation code")
        b.u8("Length", len(data), None, "Number of data bytes")
        if data:
            b.raw("Data", data, "%d (0x%s)" % (int.from_bytes(data, "big", signed=True), data.hex().upper()), "Position in encoder counts, big-endian, signed")
        b.u8("XOR check", x, "0x%02X [correct]" % x, "XOR of CMD, LEN and DATA bytes")
        b.u8("ETX", 3, "0x03", "End of text")
        return b.done()

    def cycle(self):
        if not self.by["ctl"].on:
            return
        self.tgt = int(20000 * __import__("math").sin(self.t * 0.6))
        data = self.tgt.to_bytes(4, "big", signed=True)
        err = None
        if self.fault["cm"] and self.rng.random() < 0.7:
            err = "Common mode beyond +/-7 V: receiver input clipped"
        elif self.fault["loads"] and self.rng.random() < 0.3:
            err = "Differential swing below receiver threshold margin"
        elif self.fault["no_term0"] and self.rng.random() < 0.15:
            err = "Reflection counted as an extra edge: framing error"
        fr = serial_frame(self, "ctl", ["drv", "log"], "RS-422", "MOVE %+d" % self.tgt, self.pkt(0x10, data), 115200, line="D",
                          kind="cmd", err=err, key="CTRL>DRV",
                          extra=lambda w, sp: w.set("R", 0.0, 1))
        self.tx(fr, bus="tx")

    def rx(self, fr):
        if fr.src == "ctl":
            lg = self.by["log"]
            lg.vars["Frames logged"] += 1
            if self.fault["swap"]:
                lg.vars["Garbled"] += 1
                lg.state = "INVERTED DATA"
            else:
                lg.state = ""
            d = self.by["drv"]
            if fr.err or not d.on:
                d.vars["Errors"] += 1 if fr.err else 0
                return
            d.vars["Target"] = self.tgt
            d.vars["Position"] = int(d.vars["Position"] + (self.tgt - d.vars["Position"]) * 0.5)
            rep = self.pkt(0x11, int(d.vars["Position"]).to_bytes(4, "big", signed=True))
            r = serial_frame(self, "drv", "ctl", "RS-422", "STATUS pos %+d" % d.vars["Position"], rep, 115200, line="R", kind="resp",
                             key="DRV>CTRL", err="Drive transmitter dead: return pair floating" if self.fault["drv"] else None,
                             extra=lambda w, sp: w.set("D", 0.0, 1))
            r.t = self.t + 50e-6
            self.tx(r, bus="rx")
        else:
            self.by["ctl"].vars["Replies"] += 0 if fr.err else 1


# =================================================================== RS-485
class RS485(Scenario):
    key, name, cat = "rs485", "RS-485", "phys"
    blurb = "Multidrop industrial serial networks"
    phy, rate = "rs485", 19200
    medium = "TIA-485-A 2-wire half duplex, 19200 bit/s 8N1, 120 Ω both ends, fail-safe bias at master"
    nets = [("A", "line A (D-, inverting)"), ("B", "line B (D+, non-inverting)"), ("VDIFF", "B - A")]
    lines = ["D", "DE"]
    faults = [("no_term0", "Terminator missing at master end", "One end unterminated: edges reflect. At 19200 bit/s on 400 m it still mostly works - try both."),
              ("no_term1", "Terminator missing at far end", "Both missing: strong ringing on every edge."),
              ("nobias", "Fail-safe bias resistors missing", "When no driver is enabled the bus floats near 0 V; noise is decoded as start bits - garbage characters between messages."),
              ("swap", "A/B swapped at controller #3", "That node sees inverted data and answers with inverted data: its replies are garbage to everybody."),
              ("dup", "Two controllers set to address 02", "Both answer the same poll: their drivers fight (bus contention) and the reply is destroyed."),
              ("de", "Master releases DE too early", "The driver is turned off during the last stop bit, so the final character is cut short."),
              ("stub", "6 m unterminated stub to controller #1", "Long stubs act as unterminated lines: reflections appear on the whole bus.")]
    spec = [("Standard", "TIA/EIA-485-A, ISO/IEC 8482"), ("Signalling", "Differential, |VOD| >= 1.5 V into 54 Ω; receiver threshold +/-200 mV"),
            ("Nodes", "32 unit loads (more with 1/4 and 1/8 UL transceivers)"), ("Rate / distance", "10 Mbit/s at 12 m; 100 kbit/s at 1200 m"),
            ("Topology", "Multidrop bus (daisy chain), short stubs, 120 Ω at both ends"), ("Common mode", "-7 V .. +12 V"),
            ("Bias", "Pull-up on B, pull-down on A so idle = mark (B > A by > 200 mV)"), ("Direction", "Half duplex: driver enable (DE) switched per message")]
    frame = [["ASCII poll / reply", (": start", 8), ("ADDR 2 chars", 16), ("CMD", "n x 8"), ("CR", 8)]]
    about = ("RS-485 is RS-422 that allows many drivers on one pair. Every node has a transceiver whose driver is enabled only while that node "
             "talks (DE line); otherwise the bus is released. Because the bus can be left undriven, a fail-safe bias holds it in the mark state, "
             "and terminators at both physical ends absorb the edges. This bench polls three temperature controllers with a simple ASCII protocol.")
    guide = ["Put CH1 on A and CH2 on B with MATH on. Compare the idle level between messages (bias) with the mark level while a driver is on.",
             "In LOGIC, look at the DE line: the master enables its driver just before the first start bit and releases it after the last stop bit.",
             "Pull both terminators (click the resistors) and zoom on an edge: ringing.",
             "Remove the bias: the idle bus now floats at 0 V and noise is picked up as bogus characters (red frames).",
             "Swap A/B at controller #3 - only its replies become garbage.",
             "Set two controllers to address 02 - watch the contention destroy the reply."]

    def build(self):
        m = self.node("m", "MASTER", "plc", 30, 40, "master", "fail-safe bias")
        n1 = self.node("c1", "CONTROLLER #1", "tstat", 230, 250, "addr 01", "TC-48")
        n2 = self.node("c2", "CONTROLLER #2", "tstat", 470, 250, "addr 02", "TC-48")
        n3 = self.node("c3", "CONTROLLER #3", "tstat", 700, 250, "addr 03", "TC-48")
        for n in (n1, n2, n3):
            n.at_top()
        self.trunk(180, 60, 850, [m, n1, n2, n3], "rs485", net="VDIFF", label="Belden 3105A, 120 Ω, 400 m", t0=True, t1=True)
        self.user = "m"
        for i, n in enumerate((n1, n2, n3)):
            n.vars.update({"PV": 21.0 + i * 2.7, "SP": 22.0 + i, "Address": i + 1, "Errors": 0})
            n.ctl = [("PV", "PV degC", 0.0, 99.0, 0, lambda v: "%.1f" % v)]
        m.vars.update({"Polls": 0, "Timeouts": 0, "Bad replies": 0, "Last": "-"})
        self.k = 0
        self.every(0.12, self.poll, 0.01)

    def bias(self):
        return 3 if self.fault["nobias"] else 2

    def cond(self, net):
        c = super().cond(net)
        nt = c["nterm"]
        if self.fault["stub"] or nt < 2:
            c.update(refl=0.12 if nt == 1 else 0.38, ringf=1.1e6, ringd=4e-6)
            if self.fault["stub"]:
                c["refl"] = max(c["refl"], 0.25)
        if self.fault["nobias"]:
            c["noise"] = 0.05
        return c

    def mk(self, src, dst, s, kind, err=None, rs=None):
        pdu = txt_pdu("ASCII poll protocol", s, "Simple master/slave ASCII protocol carried over RS-485.")
        de = self.fault["de"] and src == "m"
        cut = (lambda b: b) if not de else None

        def extra(w, spans):
            if de and spans:
                a, b_ = spans[-1]
                w.set("D", b_ - 0.7 * (b_ - a) / 10, self.bias())
                w.set("DE", b_ - 0.7 * (b_ - a) / 10, 0)
                w.marks.append((b_ - 0.07 * (b_ - a), "DE off"))
        del cut
        return serial_frame(self, src, dst, "RS-485", s.strip(), pdu, 19200, line="D", rs485=rs or self.bias(), kind=kind, err=err,
                            extra=extra, key=("POLL %s" % dst) if src == "m" else ("REPLY %s" % src))

    def poll(self):
        if not self.by["m"].on:
            return
        self.k = self.k % 3 + 1
        dst = "c%d" % self.k
        err = None
        if self.fault["de"]:
            err = "Last character truncated: DE released before the stop bit"
        if self.fault["nobias"] and self.rng.random() < 0.25:
            gl = Bld("Noise", "Characters decoded from noise on an undriven, unbiased bus")
            gl.raw("Garbage", bytes(self.rng.integers(0, 256, 2).tolist()), None, "Noise mistaken for start bits")
            g = serial_frame(self, "c%d" % (1 + int(self.rng.integers(0, 3))), None, "RS-485", "(noise on idle bus)", gl.done(), 19200,
                             rs485=3, kind="err", err="Framing error: floating bus without fail-safe bias")
            g.t = self.t + 0.004
            self.tx(g, bus="bus")
        fr = self.mk("m", dst, ":%02dRPV\r" % self.k, "cmd", err)
        fr.meta["addr"] = self.k
        self.by["m"].vars["Polls"] += 1
        self.tx(fr, bus="bus")
        self.at(self.t + 0.08, self.timeout, self.k, self.by["m"].vars["Polls"])
        self._ans = False

    def timeout(self, k, n):
        if not self._ans and self.by["m"].vars["Polls"] == n:
            self.by["m"].vars["Timeouts"] += 1
            self.log("No reply from controller %02d" % k)

    def rx(self, fr):
        if fr.src == "m":
            k = fr.meta.get("addr")
            if fr.err and self.fault["de"] and self.rng.random() < 0.5:
                return
            targets = [n for n in ("c1", "c2", "c3") if self.by[n].vars["Address"] == k and self.by[n].on]
            if self.fault["dup"] and k == 2:
                targets = ["c1", "c2"] if self.by["c1"].on else targets
            if not targets:
                return
            n = self.by[targets[0]]
            rep = ":%02dPV%+06.1f\r" % (k, n.vars["PV"])
            err = None
            if len(targets) > 1:
                err = "Bus contention: two drivers enabled at once"
            elif targets[0] == "c3" and self.fault["swap"]:
                err = "Inverted data from node with A/B swapped"
            r = self.mk(targets[0], "m", rep, "resp", err)
            r.t = self.t + 0.003
            self.tx(r, bus="bus")
        elif fr.dst == "m":
            self._ans = True
            m = self.by["m"]
            if fr.err:
                m.vars["Bad replies"] += 1
            else:
                m.vars["Last"] = fr.info

    def tpls(self):
        return [Tpl("Poll a controller", [P("a", "Address", 1, 1, 32)], lambda s, v, send: self._p(v, send), "Ask one controller for its process value (PV)."),
                Tpl("Set setpoint", [P("a", "Address", 1, 1, 32), P("sp", "Setpoint degC", 25.0, 0.0, 99.0, 0.5)],
                    lambda s, v, send: self._sp(v, send), "Write a new setpoint; the controller acknowledges with OK.")]

    def _p(self, v, send):
        fr = self.mk("m", "c%d" % min(3, v["a"]), ":%02dRPV\r" % v["a"], "cmd")
        fr.meta["addr"] = v["a"]
        return self.tx(fr) if send else fr

    def _sp(self, v, send):
        fr = self.mk("m", "c%d" % min(3, v["a"]), ":%02dWSP%05.1f\r" % (v["a"], v["sp"]), "cmd")
        fr.meta["addr"] = v["a"]
        if send:
            n = self.by.get("c%d" % v["a"])
            if n:
                n.vars["SP"] = v["sp"]
            return self.tx(fr)
        return fr

    def on_fault(self, key, on):
        if key == "dup":
            self.by["c1"].vars["Address"] = 2 if on else 1
            self.by["c1"].addr = "addr 02 (!)" if on else "addr 01"


# =================================================================== RS-423
class RS423(Scenario):
    key, name, cat = "rs423", "RS-423", "phys"
    blurb = "Unbalanced serial communication"
    phy, rate = "rs423", 9600
    medium = "TIA-423-B: single-ended driver, differential receiver referenced to the driver's signal ground"
    nets = [("SD", "send data (unbalanced)"), ("SG", "driver signal ground"), ("RD", "receive data")]
    lines = ["D", "R"]
    faults = [("slew", "Driver wave-shaping (slew control) disabled", "RS-423 drivers must limit rise time to reduce crosstalk into neighbouring wires; fast edges couple into the RD line."),
              ("gnd", "3 V ground shift between the two ends", "The differential receiver compares SD with the far-end SG wire, so a ground shift is rejected - within its +/-7 V range."),
              ("long", "1200 m cable at 9600 bit/s", "Unbalanced lines are limited to about 100 kbit/s at 10 m and 1 kbit/s near 1200 m.")]
    spec = [("Standard", "TIA/EIA-423-B, ITU-T V.10"), ("Signalling", "Unbalanced driver +/-4..6 V; balanced (differential) receiver"),
            ("Rate / distance", "100 kbit/s at 10 m; about 1 kbit/s at 1200 m"), ("Loads", "1 driver, up to 10 receivers"),
            ("Typical use", "Inside RS-449 links, Apple / Sun serial ports (RS-422 compatible)"), ("Polarity", "Like RS-232: mark = negative")]
    frame = [["Character", ("start", 1), ("data", 8), ("stop", 1)]]
    about = ("RS-423 sits between RS-232 and RS-422: the driver is single-ended like RS-232 but with smaller swings, while the receiver is differential and "
             "measures the data wire against the driver's own ground wire carried in the cable. That rejects some ground noise and allows ten listeners. "
             "Drivers must shape their edges to limit crosstalk - the main weakness of unbalanced signalling.")
    guide = ["Probe SD and SG: SG stays at 0 V at the driver; with the ground-shift fault the receiver still decodes correctly.",
             "Turn off wave-shaping and probe RD while the terminal talks: crosstalk spikes appear on the idle line.",
             "Inject the 1200 m fault and open the EYE: unbalanced signalling closes the eye long before RS-422 would."]

    def build(self):
        a = self.node("cpu", "HOST PORT", "pc", 60, 150, "unbalanced driver", "9600 bit/s").at_right()
        b = self.node("trm", "TERMINAL", "display", 690, 150, "diff. receiver").at_left()
        self.seg([a.port, b.port], "rs232", net="SD", label="SD + SG (twisted), RD + RG", c0="db9", c1="db9")
        self.user = "cpu"
        b.vars["Lines received"] = 0
        a.vars["Lines sent"] = 0
        self.n = 0
        self.every(0.4, self.send, 0.05)

    def cond(self, net):
        c = super().cond(net)
        if self.fault["slew"]:
            c["rise"] = 0.05
            if net == "RD":
                c.update(refl=0.9, ringf=2.5e6, ringd=0.4e-6)
        if self.fault["gnd"] and net in ("SD", "SG"):
            c["off"] = 3.0
        if self.fault["long"]:
            c["rise"] = 18.0
            c["atten"] = 0.7
        return c

    def mk(self, s, err=None, src="cpu", dst="trm", line="D"):
        pdu = txt_pdu("RS-423 characters", s, "ASCII terminal traffic over RS-423 levels.")
        return serial_frame(self, src, dst, "RS-423", s.strip(), pdu, 9600, line=line, kind="data", err=err,
                            extra=lambda w, sp: w.set("R" if line == "D" else "D", 0.0, 1))

    def send(self, s=None):
        self.n += 1
        s = s or "LINE %04d STATUS OK\r\n" % self.n
        err = "Edges smeared over 1200 m: bit errors" if self.fault["long"] and self.rng.random() < 0.7 else None
        self.by["cpu"].vars["Lines sent"] += 1
        return self.tx(self.mk(s, err))

    def rx(self, fr):
        if not fr.err and fr.dst == "trm":
            self.by["trm"].vars["Lines received"] += 1

    def tpls(self):
        return [Tpl("Send a line", [P("s", "Text", "HELLO TERMINAL")], lambda s, v, send: self.send(v["s"] + "\r\n") if send else self.mk(v["s"] + "\r\n"), "Send a line of text to the terminal.")]


# =================================================================== RS-449
class RS449(Scenario):
    key, name, cat = "rs449", "RS-449", "phys"
    blurb = "Legacy serial interface standard"
    phy, rate = "rs422", 64000
    medium = "RS-449 DB37: synchronous HDLC at 64 kbit/s, RS-422 balanced data and clock circuits"
    nets = [("VDIFF", "SD (send data) pair"), ("A", "SD A"), ("B", "SD B"), ("RDIFF", "RD (receive data) pair")]
    lines = ["D", "ST", "TT", "R", "RT"]
    faults = [("tt", "Terminal timing (TT) not returned", "The DTE clocks data with its own delayed copy of ST: at high rates data changes near the DCE's sampling edge - bit errors."),
              ("inv", "Clock pair reversed on ST", "Data is launched on the wrong clock edge: every sample sits on a transition."),
              ("idle", "DTE idles with marks, DCE expects flags", "HDLC links idle with 0x7E flags; an all-ones idle looks like an abort to some equipment.")]
    spec = [("Standard", "EIA RS-449 (withdrawn), mechanical = ISO 4902, electrical = RS-422 / RS-423"), ("Connector", "DB37 (+ DB9 for the secondary channel)"),
            ("Circuits", "SD, RD, TT, ST, RT, RS, CS, DM, TR, RR, IC, LL, RL, TM, SG"), ("Clocking", "Synchronous: DCE supplies ST and RT, DTE may return TT"),
            ("Typical rates", "48 kbit/s - 2 Mbit/s (often 64 kbit/s or T1/E1 fractions)"), ("Successor", "EIA-530 (same signals on a DB25)")]
    frame = [["HDLC frame", ("Flag 0x7E", 8), ("Address", 8), ("Control", 8), ("Information", "N x 8"), ("FCS-16", 16), ("Flag 0x7E", 8)]]
    about = ("RS-449 defined a 37-pin connector for fast synchronous links using balanced RS-422 circuits. Data is clocked: the modem/DSU (DCE) supplies "
             "Send Timing (ST) and Receive Timing (RT); the DTE launches each bit on ST and often loops it back as Terminal Timing (TT) so the DCE samples "
             "data with a clock that has travelled the same cable. The payload here is HDLC with zero-bit insertion and a CRC-16 FCS.")
    guide = ["In LOGIC, compare D (send data) with ST: data changes on one clock edge and is sampled on the other.",
             "Look for the 'S' markers: HDLC inserts a 0 after five 1s so data can never imitate the 0x7E flag.",
             "Disconnect TT and watch errors appear.",
             "Open the ANALYZER: the FCS is the same CRC-16/X-25 used by AIS, PPP and DLMS."]

    def build(self):
        a = self.node("dte", "ROUTER (DTE)", "router", 50, 140, "DB37 male", "HDLC 64k").at_right()
        b = self.node("dce", "DSU / MODEM (DCE)", "gw", 680, 140, "DB37 female", "clock source").at_left()
        self.seg([a.port, b.port], "ribbon", net="VDIFF", label="RS-449 cable: SD RD TT ST RT RS CS DM TR", c0="db37", c1="db37")
        self.user = "dte"
        self.seq = 0
        a.vars.update({"Frames sent": 0, "FCS errors at DCE": 0})
        self.every(0.25, self.send, 0.03)

    def hdlc(self, info):
        hdr = bytes([0x03, (self.seq % 8) << 1])
        fcs = crcn("CRC-16/X-25", hdr + info)
        b = Bld("HDLC (ISO 13239)", "Bit-oriented synchronous framing: flags, address, control, information, FCS.")
        b.u8("Flag", 0x7E, "0x7E", "Opening flag 01111110 - unique because of zero insertion")
        b.u8("Address", 0x03, None, "Station address")
        b.u8("Control", hdr[1], "I-frame N(S)=%d" % (self.seq % 8), "Information frame with send sequence number")
        b.raw("Information", info, "%d bytes" % len(info), "Payload (here an IP packet fragment)")
        b.u16("FCS", fcs, "0x%04X [correct]" % fcs, "CRC-16/X-25 over address..information, sent LSB first", little=True)
        b.u8("Flag", 0x7E, "0x7E", "Closing flag")
        return b.done()

    def send(self, info=None):
        self.seq += 1
        info = info or bytes(self.rng.integers(0, 256, 12).tolist())
        pdu = self.hdlc(info)
        err = None
        if self.fault["tt"] and self.rng.random() < 0.5:
            err = "FCS error: data sampled too close to the clock edge"
        elif self.fault["inv"]:
            err = "FCS error: data launched on the wrong clock edge"
        elif self.fault["idle"] and self.rng.random() < 0.2:
            err = "Abort sequence seen during idle"
        tb = 1.0 / 64000
        core = pdu.b[1:-1]
        bits = bytes_lsb(core)
        stf, pos = hdlc_stuff(bits)
        allb = msb(0x7E, 8)[::-1] + stf + msb(0x7E, 8)[::-1]
        dur = (len(allb) + 8) * tb

        def wf(fr, allb=allb, pos=pos, pdu=pdu):
            w = Wire(bit=tb)
            t = 0.0
            for i in range(len(allb) + 8):
                w.set("ST", t, 1)
                w.set("ST", t + tb / 2, 0)
                w.set("TT", t + tb * 0.08, 1)
                w.set("TT", t + tb * 0.58, 0)
                w.set("RT", t, 1)
                w.set("RT", t + tb / 2, 0)
                t += tb
            w.set("R", 0.0, 1)
            t = 4 * tb
            w.set("D", 0.0, 1)
            for i, bt in enumerate(allb):
                w.set("D", t + tb * 0.5, bt)
                if 8 <= i < 8 + len(stf) and (i - 8) in pos:
                    w.marks.append((t + tb, "S"))
                t += tb
            w.set("D", t + tb * 0.5, 1)
            w.seg(4.5 * tb, 12.5 * tb, "FLAG 7E", 7, 1)
            w.seg(12.5 * tb, (12.5 + len(stf)) * tb, "ADDR CTRL INFO FCS (zero-stuffed)", 1, 1)
            w.seg((12.5 + len(stf)) * tb, (20.5 + len(stf)) * tb, "FLAG 7E", 7, 1)
            w.end(t + 2 * tb)
            return w
        fr = Frame(self.t, dur, "dte", "dce", "HDLC", "I-frame N(S)=%d len %d" % (self.seq % 8, len(info)), pdu=pdu, err=err, kind="data",
                   wirefn=wf, key="I-frame")
        self.by["dte"].vars["Frames sent"] += 1
        if err:
            self.by["dte"].vars["FCS errors at DCE"] += 1
        return self.tx(fr)

    def tpls(self):
        return [Tpl("Send HDLC I-frame", [P("hex", "Info (hex)", "7E7E7E FF FF 00")], lambda s, v, send: self._s(v, send),
                    "Bytes are zero-stuffed: try 7E or FF FF to see the stuffing in LOGIC.")]

    def _s(self, v, send):
        try:
            data = bytes.fromhex(v["hex"].replace(" ", ""))
        except ValueError:
            data = v["hex"].encode()
        if send:
            return self.send(data)
        return Frame(self.t, 0.001, "dte", "dce", "HDLC", "I-frame preview", pdu=self.hdlc(data))


# ===================================================================== UART
class UART(Scenario):
    key, name, cat = "uart", "UART", "phys"
    blurb = "Asynchronous serial communication"
    phy, rate = "ttl", 9600
    medium = "3.3 V TTL UART, 9600 bit/s 8N1, MCU <-> GNSS module, shared ground"
    nets = [("TX", "MCU TX -> GNSS RX"), ("RX", "GNSS TX -> MCU RX"), ("GND", "ground")]
    lines = ["TX", "RX"]
    faults = [("err2", "GNSS clock 2 % fast", "16x oversampling tolerates roughly +/-3-4 % total error: 2 % still decodes, but the sample points drift visibly across the character."),
              ("err5", "GNSS clock 5 % fast", "By the last bits the receiver samples the neighbouring bit: framing errors."),
              ("swap", "TX and RX swapped", "Both outputs drive the same wire and both inputs listen to nothing."),
              ("parity", "MCU expects 8E1", "The stop bit is read as a parity bit: parity errors on most characters."),
              ("gnd", "No common ground wire", "Single-ended logic needs a shared reference; without it the levels float.")]
    spec = [("Signalling", "Logic level (3.3 V / 5 V), idle high, start bit low"), ("Format", "Start, 5-9 data bits LSB first, optional parity, 1/1.5/2 stop bits"),
            ("Clocking", "No clock wire: each end has its own baud generator; receiver oversamples 16x and resynchronises on every start bit"),
            ("Tolerance", "Combined clock error must stay under about 3-4 %"), ("Common rates", "9600, 19200, 38400, 57600, 115200, 921600 bit/s"),
            ("Note", "UART is a framing method; RS-232/422/485 are the line drivers that carry it further")]
    frame = [["8N1 character", ("idle 1", "…"), ("start 0", 1), ("D0", 1), ("D1", 1), ("D2", 1), ("D3", 1), ("D4", 1), ("D5", 1), ("D6", 1), ("D7", 1), ("stop 1", 1)]]
    about = ("A UART turns bytes into a self-timed bit stream: a falling start edge tells the receiver to begin, and it then samples each bit at the centre "
             "using its own clock. Because both clocks only need to agree for about ten bits, cheap oscillators work - but only within a few percent. "
             "The LOGIC view marks where the MCU's receiver actually samples the GNSS data (red lines).")
    guide = ["In LOGIC, zoom into one character on the RX line: the red markers are the receiver's sample points, one per bit centre.",
             "Inject the 2 % clock error: markers drift but stay inside the bits. With 5 % the last ones fall in the wrong bit - framing error.",
             "Swap TX and RX and see both directions die.",
             "Use COMPOSE to send a $PMTK configuration sentence to the module."]

    def build(self):
        m = self.node("mcu", "MCU", "mcu", 70, 150, "USART2", "9600 8N1").at_right()
        g = self.node("gnss", "GNSS MODULE", "gps", 690, 150, "UART", "NMEA output").at_left()
        self.seg([m.port, g.port], "trace", net="RX", label="TX / RX / GND (3 wires, 20 cm)", c0="header", c1="header")
        self.user = "mcu"
        g.vars.update({"Fix": "3D", "Satellites": 9, "Clock error": "0 %"})
        m.vars.update({"Sentences OK": 0, "Framing errors": 0, "Parity errors": 0})
        self.every(1.0, self.burst, 0.1)

    def cond(self, net):
        c = super().cond(net)
        if self.fault["gnd"]:
            c.update(noise=0.25, off=float(self.rng.normal(0, 0.8)))
        return c

    def clkerr(self):
        return 0.05 if self.fault["err5"] else (0.02 if self.fault["err2"] else 0.0)

    def burst(self):
        if not self.by["gnss"].on:
            return
        hh = int(self.t) % 86400
        body = "GPRMC,%02d%02d%02d.00,A,4807.038,N,01131.000,E,0.4,084.4,141126,,,A" % (hh // 3600 + 12, (hh // 60) % 60, hh % 60)
        s = "$%s*%02X\r\n" % (body, xor8(body.encode()))
        self.line(s)

    def line(self, s, src="gnss"):
        e = self.clkerr()
        baud = 9600 * (1 + e) if src == "gnss" else 9600
        err = None
        if self.fault["swap"]:
            err = "TX-TX / RX-RX: nobody is listening on this wire"
        elif e >= 0.05:
            err = "Framing errors: receiver samples drift into the next bit"
        elif self.fault["parity"] and src == "gnss":
            err = "Parity errors: receiver configured for 8E1"
        elif self.fault["gnd"] and self.rng.random() < 0.5:
            err = "Garbled: no common ground"
        pdu = txt_pdu("UART characters", s, "Asynchronous 8N1 characters at logic level.")
        line = "RX" if src == "gnss" else "TX"

        def extra(w, spans, e=e, line=line):
            w.set("TX" if line == "RX" else "RX", 0.0, 1)
            if line != "RX":
                return
            tbr = 1.0 / 9600
            for a, b in spans[:40]:
                for k in range(10):
                    w.marks.append((a + (k + 0.5) * tbr, ""))
        fr = serial_frame(self, src, "mcu" if src == "gnss" else "gnss", "UART", s.strip(), pdu, baud, line=line, kind="data" if src == "gnss" else "cmd",
                          err=err, extra=extra, key="GNSS>MCU" if src == "gnss" else "MCU>GNSS")
        return self.tx(fr, bus=line)

    def rx(self, fr):
        m = self.by["mcu"]
        if fr.dst == "mcu":
            if fr.err and "Framing" in fr.err:
                m.vars["Framing errors"] += 1
            elif fr.err and "Parity" in fr.err:
                m.vars["Parity errors"] += 1
            elif not fr.err:
                m.vars["Sentences OK"] += 1

    def tpls(self):
        return [Tpl("Send text", [P("s", "Text", "$PMTK220,1000*1F")], lambda s, v, send: self.line(v["s"] + "\r\n", "mcu") if send else
                    serial_frame(self, "mcu", "gnss", "UART", v["s"], txt_pdu("UART characters", v["s"] + "\r\n", ""), 9600, line="TX"),
                    "Characters from the MCU to the module. $PMTK220 sets the fix interval on MediaTek receivers.")]

    def on_fault(self, key, on):
        self.by["gnss"].vars["Clock error"] = "%g %%" % (100 * self.clkerr())


# =================================================================== GPIB
GP_LINES = ["DIO1", "DIO2", "DIO3", "DIO4", "DIO5", "DIO6", "DIO7", "DIO8", "DAV", "NRFD", "NDAC", "ATN", "EOI", "IFC", "SRQ", "REN"]


class GPIB(Scenario):
    key, name, cat = "gpib", "IEEE-488 / GPIB", "phys"
    blurb = "Laboratory test equipment"
    phy, rate = "gpib", 8 * 300000
    medium = "IEEE-488.1 bus, 8-bit parallel, three-wire handshake, 4 instruments, 6 m total cable"
    nets = [(n, n) for n in GP_LINES]
    lines = GP_LINES
    faults = [("off", "DMM (addr 22) powered off", "A powered-off device loads the bus. The controller addresses it and the handshake never completes - timeout."),
              ("dup", "Two instruments set to address 22", "Both answer as talkers: the data lines fight and the reply is garbage."),
              ("long", "25 m of cable (limit 20 m)", "Edges degrade and ringing can make devices see false DAV transitions."),
              ("srq", "Power supply asserts SRQ (overcurrent)", "A device pulls SRQ to request service; the controller serial-polls to find who and why.")]
    spec = [("Standard", "IEEE 488.1 (hardware), IEEE 488.2 (formats, common commands), SCPI"), ("Signals", "8 data (DIO1-8), 3 handshake (DAV, NRFD, NDAC), 5 management (ATN, EOI, IFC, SRQ, REN)"),
            ("Logic", "Negative logic, TTL levels: asserted = low (< 0.8 V)"), ("Speed", "1 Mbyte/s (HS488: 8 Mbyte/s)"),
            ("Limits", "15 devices, 20 m total, 2 m per device"), ("Connector", "24-pin Amphenol/Centronics, stackable"),
            ("Addressing", "Primary address 0-30; MLA = 0x20+addr, MTA = 0x40+addr, UNL = 0x3F, UNT = 0x5F")]
    frame = [["Command phase (ATN asserted)", ("UNL 3F", 8), ("UNT 5F", 8), ("MTA ctrl", 8), ("MLA dev", 8)],
             ["Data phase (ATN released)", ("byte", 8), ("byte", 8), ("...", 8), ("last + EOI", 8)],
             ["Per-byte handshake", ("NRFD released", 1), ("DAV asserted", 1), ("NDAC released", 1), ("DAV released", 1)]]
    about = ("GPIB moves one byte at a time on eight data lines with a three-wire handshake: the talker asserts DAV only when every listener has released NRFD "
             "(ready for data), and removes it only when every listener has released NDAC (data accepted). The slowest device sets the pace. "
             "With ATN asserted, bytes are commands (addressing); with ATN released they are data such as SCPI strings ending with EOI.")
    guide = ["Open LOGIC and FIT a frame: ATN low during the command bytes, then the data bytes with EOI on the last.",
             "Zoom on one byte: NRFD high (ready) -> DAV low -> NDAC high (accepted) -> DAV high. That is the interlocked handshake.",
             "Decode MLA 22 = 0x36 and MTA 22 = 0x56 by hand.",
             "Power off the DMM and see the addressing time out.",
             "Inject the SRQ fault: the controller starts a serial poll (SPE, read status byte, SPD)."]

    def build(self):
        c = self.node("ctl", "CONTROLLER", "pc", 30, 40, "addr 0", "GPIB-USB")
        devs = [("dmm", "DMM", "meter", 22, 230), ("psu", "POWER SUPPLY", "meter", 5, 430), ("osc", "OSCILLOSCOPE", "scope", 7, 630)]
        c.at_right()
        self.seg([c.port, (250, c.port[1]), (250, 200)], "gpib", net="DAV", c0="centronics")
        for nid, lab, kind, addr, x in devs:
            n = self.node(nid, lab, kind, x - 50, 250, "addr %d" % addr, "IEEE-488")
            n.vars.update({"Address": addr, "Status byte": 0, "Last command": "-"})
            n.at_top()
        prev = (250, 200)
        for nid, lab, kind, addr, x in devs:
            self.seg([prev, (x + 9, 200), (x + 9, 250)], "gpib", net="DAV", c1="centronics", label="IEEE-488 cable" if nid == "dmm" else "")
            prev = (x + 9, 200)
        self.by["dmm"].vars["Reading"] = 1.23456
        self.by["dmm"].ctl = [("Reading", "INPUT V", -10.0, 10.0, 0, lambda v: "%+.5f" % v)]
        self.user = "ctl"
        self.every(0.6, self.poll_dmm, 0.05)
        self.srq_done = False

    def bytes_wire(self, cmds, data, talker_eoi=True):
        """Three-wire handshake waveform for a list of command bytes (ATN
        asserted) followed by data bytes (ATN released, EOI on the last)."""
        tb = 2.5e-6
        w = Wire(bit=tb)
        for ln in GP_LINES:
            w.set(ln, 0.0, 0)
        w.set("REN", 0.0, 1)
        w.set("NRFD", 0.0, 1)
        w.set("NDAC", 0.0, 1)
        t = 1e-6
        allb = [(b, True) for b in cmds] + [(b, False) for b in data]
        for i, (byte, atn) in enumerate(allb):
            w.set("ATN", t, 1 if atn else 0)
            for k in range(8):
                w.set("DIO%d" % (k + 1), t, (byte >> k) & 1)
            last = (not atn) and i == len(allb) - 1 and talker_eoi
            w.set("EOI", t, 1 if last else 0)
            w.set("NRFD", t + 0.3e-6, 0)
            t0 = t
            t += 0.6e-6
            w.set("DAV", t, 1)
            w.set("NRFD", t + 0.2e-6, 1)
            w.set("NDAC", t + 1.0e-6, 0)
            t += 1.3e-6
            w.set("DAV", t, 0)
            w.set("NDAC", t + 0.2e-6, 1)
            t += 0.6e-6
            lab = {0x3F: "UNL", 0x5F: "UNT", 0x18: "SPE", 0x19: "SPD", 0x04: "SDC", 0x08: "GET", 0x14: "DCL"}.get(byte) if atn else None
            if atn and lab is None:
                lab = ("MLA %d" % (byte - 0x20)) if 0x20 <= byte < 0x3F else ("MTA %d" % (byte - 0x40)) if 0x40 <= byte < 0x5F else "%02X" % byte
            elif not atn:
                lab = repr(chr(byte))[1:-1] if 32 <= byte < 127 else "%02X" % byte
            w.seg(t0, t, lab, 0 if atn else 1, 0)
        w.set("ATN", t, 0)
        w.set("EOI", t, 0)
        if cmds:
            w.seg(1e-6, 1e-6 + len(cmds) * 2.5e-6, "COMMAND (ATN)", 7, 1)
        if data:
            w.seg(1e-6 + len(cmds) * 2.5e-6, t, "DATA", 1, 1)
        w.end(t + 1e-6)
        return w

    def msg(self, src, dst, cmds, data, info, kind, err=None):
        b = Bld("IEEE 488.1 bus transaction", "Bytes transferred with the three-wire handshake.")
        if cmds:
            b.raw("Command bytes (ATN)", bytes(cmds), " ".join("%02X" % x for x in cmds), "Interface messages: UNL/UNT clear addressing, MTA/MLA select talker and listeners.")
        if data:
            b.text("Device-dependent data", bytes(data).decode("latin-1").replace("\n", "\\n"), "Device data (SCPI). The final byte is sent with EOI asserted.")
        pdu = b.done()
        dur = (len(cmds) + len(data)) * 2.5e-6 + 2e-6
        return Frame(self.t, dur, src, dst, "GPIB", info, pdu=pdu, err=err, kind=kind,
                     wirefn=lambda fr: self.bytes_wire(cmds, data), key="%s>%s" % (src, dst) if dst else src)

    def addr(self, nid):
        return self.by[nid].vars["Address"]

    def poll_dmm(self):
        if not self.by["ctl"].on:
            return
        self.query("dmm", "MEAS:VOLT:DC?")
        if self.fault["srq"] and not self.srq_done:
            self.srq_done = True
            self.at(self.t + 0.1, self.serial_poll)

    def query(self, nid, cmd):
        a = self.addr(nid)
        ok = self.by[nid].on
        err = None if ok else "Handshake timeout: no listener accepted the bytes (device off)"
        f1 = self.msg("ctl", nid, [0x3F, 0x5F, 0x40, 0x20 + a], (cmd + "\n").encode(), "WRITE %d: %s" % (a, cmd), "cmd", err)
        self.tx(f1)
        if not ok:
            return f1
        self.by[nid].vars["Last command"] = cmd
        if cmd.endswith("?"):
            rep = {"dmm": "%+.6E" % self.by["dmm"].vars.get("Reading", 0), "psu": "+5.000E+00", "osc": "1.024E-03"}[nid]
            if cmd.upper() == "*IDN?":
                rep = {"dmm": "COMMSIM,DMM-3458,0,9.2", "psu": "COMMSIM,PSU-6632,0,A.01", "osc": "COMMSIM,DSO-9104,0,3.1"}[nid]
            if cmd.upper() == "*STB?":
                rep = str(self.by[nid].vars["Status byte"])
            err2 = "Two talkers at address 22: data lines fight" if self.fault["dup"] and nid == "dmm" else None
            f2 = self.msg(nid, "ctl", [0x3F, 0x5F, 0x40 + a, 0x20], (rep + "\n").encode(), "READ %d: %s" % (a, rep), "resp", err2)
            f2.t = self.t + 1e-4
            self.tx(f2)
        return f1

    def serial_poll(self):
        self.by["psu"].vars["Status byte"] = 0x48
        self.log("SRQ asserted - serial poll")
        f = self.msg("ctl", None, [0x3F, 0x18, 0x20, 0x40 + 5], b"", "SERIAL POLL ENABLE, talk addr 5", "ctl")
        self.tx(f)
        f2 = self.msg("psu", "ctl", [], bytes([0x48]), "STATUS BYTE 0x48 (RQS + MAV)", "evt")
        f2.t = self.t + 1e-4
        self.tx(f2)
        f3 = self.msg("ctl", None, [0x19, 0x5F], b"", "SERIAL POLL DISABLE", "ctl")
        f3.t = self.t + 2e-4
        self.tx(f3)

    def on_fault(self, key, on):
        if key == "off":
            self.by["dmm"].on = not on
        if key == "srq":
            self.srq_done = False

    def tpls(self):
        devs = ["dmm", "psu", "osc"]
        return [Tpl("Write / query", [P("dev", "Device", "dmm", opts=devs), P("cmd", "SCPI", "*IDN?")], lambda s, v, send: self.query(v["dev"], v["cmd"]) if send else
                    self.msg("ctl", v["dev"], [0x3F, 0x5F, 0x40, 0x20 + self.addr(v["dev"])], (v["cmd"] + "\n").encode(), "WRITE", "cmd"),
                    "Address the device as listener, send the SCPI string; for a query, re-address it as talker and read the reply."),
                Tpl("Group Execute Trigger", [P("dev", "Device", "dmm", opts=devs)], lambda s, v, send: (self.tx if send else (lambda f: f))(
                    self.msg("ctl", v["dev"], [0x3F, 0x20 + self.addr(v["dev"]), 0x08], b"", "GET to %s" % v["dev"], "cmd")), "Trigger the addressed listeners simultaneously."),
                Tpl("Serial poll", [], lambda s, v, send: self.serial_poll() if send else self.msg("ctl", None, [0x3F, 0x18], b"", "SPE", "ctl"), "Read every device's status byte to find who requested service.")]
