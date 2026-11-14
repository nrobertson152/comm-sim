"""Marine, part A: NMEA 0183, IEC 61162-1, SeaTalk and AIS.
Also the NMEA 0183 sentence tools (builder + dissector) shared with the
Ethernet-based marine protocols."""
import math
from datetime import datetime, timezone, timedelta
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import nmea_cs, msb, lsb, bits_to_int, pack_bits, bytes_lsb, hdlc_stuff, nrzi, crcn, ais_armor, six_text
from .fam import serial_frame, RfNet, Radio, rf_frame, fsk_wire

T0 = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)


def utc(t):
    return T0 + timedelta(seconds=t)


# ===================================================== NMEA 0183 sentences
TALKERS = {"GP": "GPS receiver", "GN": "GNSS receiver (multi-constellation)", "GL": "GLONASS receiver", "GA": "Galileo receiver", "BD": "BeiDou receiver",
           "HE": "heading sensor, north-seeking gyro", "HC": "heading sensor, magnetic compass", "TI": "turn rate indicator", "SD": "sounder, depth",
           "WI": "weather instruments", "VW": "velocity sensor, mechanical log (water)", "VD": "velocity sensor, Doppler log", "VM": "velocity sensor, electromagnetic log",
           "II": "integrated instrumentation", "IN": "integrated navigation", "AI": "AIS station", "EC": "ECDIS", "AP": "autopilot (heading control)",
           "AG": "autopilot, general", "RA": "radar / ARPA", "ZA": "timekeeper, atomic clock", "CD": "digital selective calling (DSC)", "YX": "transducer",
           "ER": "engine room monitoring", "HN": "heading control (track control)"}
SENTENCES = {
    "GGA": ("Global positioning system fix data", ["UTC time", "Latitude", "N/S", "Longitude", "E/W", "GPS quality (0 no fix, 1 GPS, 2 DGPS)", "Satellites in use", "HDOP",
                                                  "Antenna altitude (m)", "Altitude units", "Geoidal separation (m)", "Separation units", "Age of DGPS data (s)", "DGPS station ID"]),
    "RMC": ("Recommended minimum specific GNSS data", ["UTC time", "Status (A valid, V warning)", "Latitude", "N/S", "Longitude", "E/W", "Speed over ground (knots)",
                                                       "Course over ground (deg true)", "Date (ddmmyy)", "Magnetic variation (deg)", "Variation E/W", "Mode (A autonomous, D differential, N not valid)"]),
    "VTG": ("Course over ground and ground speed", ["COG (deg true)", "T", "COG (deg magnetic)", "M", "SOG (knots)", "N", "SOG (km/h)", "K", "Mode"]),
    "GLL": ("Geographic position, latitude/longitude", ["Latitude", "N/S", "Longitude", "E/W", "UTC time", "Status (A valid)", "Mode"]),
    "ZDA": ("Time and date", ["UTC time", "Day", "Month", "Year", "Local zone hours", "Local zone minutes"]),
    "HDT": ("Heading, true", ["Heading (deg true)", "T"]),
    "HDG": ("Heading, deviation and variation", ["Magnetic sensor heading (deg)", "Deviation (deg)", "Deviation E/W", "Variation (deg)", "Variation E/W"]),
    "THS": ("True heading and status", ["Heading (deg true)", "Mode (A autonomous, E estimated, M manual, S simulator, V not valid)"]),
    "ROT": ("Rate of turn", ["Rate of turn (deg/min, - = to port)", "Status (A valid)"]),
    "DBT": ("Depth below transducer", ["Depth (feet)", "f", "Depth (metres)", "M", "Depth (fathoms)", "F"]),
    "DPT": ("Depth", ["Depth relative to the transducer (m)", "Transducer offset (m, + = to waterline)", "Maximum range scale (m)"]),
    "MWV": ("Wind speed and angle", ["Wind angle (deg)", "Reference (R relative, T true)", "Wind speed", "Speed units (N knots, M m/s, K km/h)", "Status (A valid)"]),
    "MTW": ("Water temperature", ["Temperature", "Units (C)"]),
    "VHW": ("Water speed and heading", ["Heading (deg true)", "T", "Heading (deg magnetic)", "M", "Speed (knots)", "N", "Speed (km/h)", "K"]),
    "VBW": ("Dual ground/water speed", ["Longitudinal water speed (kn)", "Transverse water speed (kn)", "Water speed status", "Longitudinal ground speed (kn)",
                                       "Transverse ground speed (kn)", "Ground speed status", "Stern transverse water speed (kn)", "Status", "Stern transverse ground speed (kn)", "Status"]),
    "APB": ("Heading/track controller (autopilot) sentence B", ["Status: signal (A valid)", "Status: cycle lock (A valid)", "Cross-track error magnitude", "Direction to steer (L/R)",
                                                                "XTE units (N = nautical miles)", "Arrival circle entered (A)", "Perpendicular passed (A)", "Bearing origin to destination",
                                                                "M/T", "Destination waypoint ID", "Bearing present position to destination", "M/T", "Heading to steer", "M/T", "Mode"]),
    "RMB": ("Recommended minimum navigation information", ["Status (A valid)", "Cross-track error (NM)", "Direction to steer", "Origin waypoint ID", "Destination waypoint ID",
                                                           "Destination latitude", "N/S", "Destination longitude", "E/W", "Range to destination (NM)", "Bearing to destination (deg true)",
                                                           "Closing velocity (kn)", "Arrival status", "Mode"]),
    "RSA": ("Rudder sensor angle", ["Starboard (or single) rudder angle (deg, - = port)", "Status (A valid)", "Port rudder angle", "Status"]),
    "HTC": ("Heading/track control command", ["Override (A in use)", "Commanded rudder angle (deg)", "Commanded rudder direction (L/R)", "Selected steering mode (H heading, T track)",
                                              "Turn mode (R radius, T turn rate, N not controlled)", "Commanded rudder limit (deg)", "Commanded off-heading limit (deg)",
                                              "Commanded radius of turn (NM)", "Commanded rate of turn (deg/min)", "Commanded heading to steer (deg)", "Commanded off-track limit (NM)",
                                              "Commanded track (deg)", "Heading reference in use (T/M)"]),
    "HTD": ("Heading/track control data", ["Override", "Commanded rudder angle", "Rudder direction", "Selected steering mode", "Turn mode", "Rudder limit", "Off-heading limit",
                                           "Radius of turn", "Rate of turn", "Heading to steer", "Off-track limit", "Track", "Heading reference", "Rudder status", "Off-heading status",
                                           "Off-track status", "Vessel heading (deg)"]),
    "ALR": ("Set alarm state", ["Time of alarm condition change (UTC)", "Local alarm number", "Alarm condition (A threshold exceeded, V not exceeded)",
                                "Acknowledge state (A acknowledged, V unacknowledged)", "Alarm description text"]),
    "ACK": ("Acknowledge alarm", ["Local alarm number"]),
    "HBT": ("Heartbeat supervision", ["Configured repeat interval (s)", "Equipment status (A normal, V not)", "Sequential sentence identifier"]),
    "TXT": ("Text transmission", ["Total number of sentences", "Sentence number", "Text identifier", "Text message"]),
    "VDM": ("AIS VHF data-link message", ["Total number of sentences", "Sentence number", "Sequential message identifier", "AIS channel (A 161.975 MHz, B 162.025 MHz)",
                                         "Encapsulated ITU-R M.1371 message (6-bit armoured)", "Number of fill bits"]),
    "VDO": ("AIS VHF data-link own-vessel report", ["Total number of sentences", "Sentence number", "Sequential message identifier", "AIS channel",
                                                   "Encapsulated ITU-R M.1371 message", "Number of fill bits"]),
    "GSA": ("GNSS DOP and active satellites", ["Mode (M manual, A automatic)", "Fix (1 none, 2 2D, 3 3D)"] + ["Satellite ID"] * 12 + ["PDOP", "HDOP", "VDOP"]),
    "XDR": ("Transducer measurements", ["Transducer type", "Measurement", "Units", "Transducer ID"]),
}
TAG_CODES = {"s": "Source identification (SFI)", "n": "Line count", "c": "UNIX time", "d": "Destination", "g": "Sentence grouping", "r": "Relative time", "t": "Text", "i": "Information"}
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def sentence(body, bad=False):
    """Full sentence text from the part between '$' and '*'. body may start with '!' for encapsulation."""
    start = "$"
    if body[0] in "$!":
        start, body = body[0], body[1:]
    cs = nmea_cs(body) ^ (0x5A if bad else 0)
    return "%s%s*%02X\r\n" % (start, body, cs)


def _decode(name, v):
    try:
        if name.startswith("Latitude") or name.startswith("Destination latitude"):
            return "%s (%d deg %.4f')" % (v, int(v[:2]), float(v[2:]))
        if name.startswith("Longitude") or name.startswith("Destination longitude"):
            return "%s (%d deg %.4f')" % (v, int(v[:3]), float(v[3:]))
        if name.startswith("UTC time") or name.startswith("Time of alarm"):
            return "%s (%s:%s:%s UTC)" % (v, v[0:2], v[2:4], v[4:])
        if name.startswith("Date"):
            return "%s (%d %s 20%s)" % (v, int(v[0:2]), MONTHS[int(v[2:4]) - 1], v[4:6])
    except (ValueError, IndexError):
        pass
    return v


def sentence_rows(line, off=0, depth=0):
    """Dissection rows for one sentence (optionally led by a TAG block)."""
    rows = []
    i = 0
    if line.startswith("\\") and line.find("\\", 1) > 0:
        j = line.index("\\", 1)
        tag = line[1:j]
        rows.append([depth, "TAG block: \\%s\\" % tag, off, j + 1, "IEC 61162-1 TAG block: source (SFI), line count, time, destination, grouping"])
        body, _, cs = tag.partition("*")
        k = 1
        for p in body.split(","):
            code, _, val = p.partition(":")
            rows.append([depth + 1, "%s: %s" % (TAG_CODES.get(code, code), val), off + k, len(p), ""])
            k += len(p) + 1
        if cs:
            ok = cs.upper() == "%02X" % nmea_cs(body)
            rows.append([depth + 1, "TAG checksum *%s [%s]" % (cs, "correct" if ok else "WRONG"), off + k - 1, len(cs) + 1, ""])
        i = j + 1
    s = line[i:]
    end = s.rstrip("\r\n")
    star = end.find("*")
    core = end[1:star] if star > 0 else end[1:]
    fields = core.split(",")
    addr = fields[0]
    names = []
    if addr.startswith("P"):
        title = "Proprietary sentence (%s)" % addr[1:4]
    elif len(addr) == 5 and addr.endswith("Q"):
        title = "Query sentence: %s asks %s for %s" % (addr[:2], addr[2:4], fields[1] if len(fields) > 1 else "?")
    else:
        d = SENTENCES.get(addr[2:5], ("", []))
        title = "NMEA 0183 / IEC 61162-1: %s%s" % (addr, (" - " + d[0]) if d[0] else "")
        names = d[1]
    rows.append([depth, title, off + i, len(end), "ASCII sentence: start, address, comma-separated fields, '*' + checksum, CR LF (max 82 characters)"])
    rows.append([depth + 1, "Start '%s' (%s)" % (s[0], "parametric sentence" if s[0] == "$" else "encapsulated sentence"), off + i, 1, "'$' = parametric, '!' = encapsulated (e.g. AIS)"])
    if addr.startswith("P"):
        rows.append([depth + 1, "Address %s: proprietary, manufacturer mnemonic %s" % (addr, addr[1:4]), off + i + 1, len(addr), "P + 3-letter manufacturer code"])
    elif len(addr) == 5 and addr.endswith("Q"):
        rows.append([depth + 1, "Address %s: requester %s, addressed talker %s, Q = query" % (addr, addr[:2], addr[2:4]), off + i + 1, 5, ""])
    else:
        rows.append([depth + 1, "Talker ID %s: %s" % (addr[:2], TALKERS.get(addr[:2], "unknown talker")), off + i + 1, 2, "Who is talking (IEC 61162-1 Table 1)"])
        rows.append([depth + 1, "Sentence formatter %s: %s" % (addr[2:5], SENTENCES.get(addr[2:5], ("not in this simulator's table",))[0]), off + i + 3, 3, "What the fields mean"])
    k = off + i + 1 + len(addr)
    for n, f in enumerate(fields[1:]):
        k += 1
        nm = names[n] if n < len(names) else ("Requested sentence" if addr.endswith("Q") else "Field %d" % (n + 1))
        rows.append([depth + 1, "%s: %s" % (nm, _decode(nm, f) if f else "(null field)"), k, len(f), "Empty field = value not available"])
        k += len(f)
    if star > 0:
        cs = end[star + 1:star + 3]
        calc = nmea_cs(core)
        ok = cs.upper() == "%02X" % calc
        rows.append([depth + 1, "Checksum *%s [%s]" % (cs, "correct" if ok else "WRONG - calculated %02X" % calc), off + i + star, 3, "XOR of all characters between '$' and '*'"])
    else:
        rows.append([depth + 1, "No checksum field", None, 0, "IEC 61162-1 requires the checksum; old NMEA 0183 talkers sometimes omit it"])
    if s.endswith("\r\n"):
        rows.append([depth + 1, "<CR><LF> end of sentence", off + i + len(end), 2, ""])
    return rows


def sentence_pdu(line, prefix=None):
    """Pdu of a sentence; prefix = (bytes, rows) put in front (e.g. IEC 61162-450 header)."""
    b = Bld()
    k = 0
    if prefix:
        pb, prows = prefix
        b.b += pb
        b.rows += prows
        k = len(pb)
    b.b += line.encode("latin-1", "replace")
    b.rows += sentence_rows(line, k)
    return b.done()


def char_labels(line):
    return [c if 32 <= ord(c) < 127 else {"\r": "CR", "\n": "LF"}.get(c, ".") for c in line]


def invert_wire(w, line="D"):
    tl, vl = w.L.get(line, ([], []))
    w.L[line] = (tl, [1 - v if v in (0, 1) else v for v in vl])
    return w


def nmea_lat(lat):
    a = abs(lat)
    d = int(a)
    return "%02d%07.4f" % (d, (a - d) * 60), "N" if lat >= 0 else "S"


def nmea_lon(lon):
    a = abs(lon)
    d = int(a)
    return "%03d%07.4f" % (d, (a - d) * 60), "E" if lon >= 0 else "W"


class Vessel:
    """Own-ship state used by the instrument scenarios."""

    def __init__(self, lat=50.7667, lon=-1.3000, sog=6.2, cog=52.0):
        self.lat, self.lon, self.sog, self.cog = lat, lon, sog, cog
        self.hdg, self.stw, self.depth, self.awa, self.aws, self.wtemp, self.rot = cog - 4.0, sog * 0.94, 14.2, 42.0, 13.5, 14.6, 0.0
        self.rudder = 0.0

    def step(self, dt, rng):
        d = self.sog * 1852.0 / 3600.0 * dt
        self.lat += d * math.cos(math.radians(self.cog)) / 111120.0
        self.lon += d * math.sin(math.radians(self.cog)) / (111120.0 * math.cos(math.radians(self.lat)))
        self.depth = max(2.0, self.depth + float(rng.normal(0, 0.05)) + 0.02 * math.sin(self.lon * 500))
        self.awa = (self.awa + float(rng.normal(0, 0.8))) % 360
        self.aws = max(0.0, self.aws + float(rng.normal(0, 0.15)))
        self.rot = float(rng.normal(0, 3))
        self.hdg = (self.hdg + self.rot * dt / 60.0) % 360


def gga(v, t, talker="GP", fix=True):
    tm = utc(t).strftime("%H%M%S.00")
    if not fix:
        return sentence("%sGGA,%s,,,,,0,00,99.9,,M,,M,," % (talker, tm))
    la, ns = nmea_lat(v.lat)
    lo, ew = nmea_lon(v.lon)
    return sentence("%sGGA,%s,%s,%s,%s,%s,1,09,0.9,12.4,M,47.1,M,," % (talker, tm, la, ns, lo, ew))


def rmc(v, t, talker="GP", fix=True):
    u = utc(t)
    if not fix:
        return sentence("%sRMC,%s,V,,,,,,,%s,,,N" % (talker, u.strftime("%H%M%S.00"), u.strftime("%d%m%y")))
    la, ns = nmea_lat(v.lat)
    lo, ew = nmea_lon(v.lon)
    return sentence("%sRMC,%s,A,%s,%s,%s,%s,%.1f,%.1f,%s,1.2,W,A" % (talker, u.strftime("%H%M%S.00"), la, ns, lo, ew, v.sog, v.cog, u.strftime("%d%m%y")))


def vtg(v, talker="GP"):
    return sentence("%sVTG,%.1f,T,%.1f,M,%.1f,N,%.1f,K,A" % (talker, v.cog, (v.cog + 1.2) % 360, v.sog, v.sog * 1.852))


# ======================================================== RS-422 networks
class NmeaNet(Scenario):
    """Talker -> listener RS-422 links carrying sentences (NMEA 0183 / IEC 61162-1)."""
    cat = "marine"
    phy, rate = "rs422", 4800
    nets = [("A", "line A (signal)"), ("B", "line B (return)"), ("VDIFF", "B - A (differential)")]
    lines = ["D"]
    proto = "NMEA 0183"

    def say(self, src, dst, line, port, baud=4800, info=None, kind="data", err=None, invert=False, proto=None, key=None):
        fr = serial_frame(self, src, dst, proto or self.proto, info or line.strip(), sentence_pdu(line), baud, 8, "N", 1, line="D", kind=kind, err=err,
                          key=key or line[1:6], labels=char_labels(line), lead=2.0)
        if invert:
            orig = fr.wirefn
            fr.wirefn = lambda f, o=orig: invert_wire(o(f))
        return self.tx(fr, bus=port, ifs=0.002)

    def backlog(self, port):
        return max(0.0, self.free.get(port, 0.0) - self.t)

    def link(self, pts, a=None, b=None, label="", style="tsp", c0="screw", c1="screw", col=(210, 210, 210)):
        """Cable between node edges; hidden stubs join each end to the node centre so frames can be animated."""
        sg = self.seg(pts, style, net="VDIFF", label=label, c0=c0 if a else None, c1=c1 if b else None, col=col if style == "tsp" else None)
        for n, pt in ((a, pts[0]), (b, pts[-1])):
            if n:
                c = self.by[n].center()
                self.seg([pt, c], style, w=1, col=(30, 32, 36))
                self.by[n].port = c
        return sg


class NMEA0183(NmeaNet):
    key, name = "nmea0183", "NMEA 0183"
    blurb = "Marine electronics communication"
    medium = "NMEA 0183 single-talker / multi-listener RS-422 links, 4800 baud 8N1; a multiplexer combines talkers onto a 38400 baud (0183-HS) feed for the chartplotter"
    faults = [("polarity", "Depth sounder wired with A and B swapped", "Every bit arrives inverted: the multiplexer sees framing errors and drops all depth sentences."),
              ("baud", "Chartplotter input left at 4800 baud", "The multiplexer sends 38400 baud: the plotter receives garbage, nothing is displayed."),
              ("twotalk", "Wind and depth outputs paralleled on one input", "Two talkers on one listener input: whenever both talk at once the characters collide."),
              ("nofix", "GPS antenna cable damaged: no fix", "RMC status V and GGA quality 0 with empty position fields; listeners must not use the position."),
              ("noise", "Unscreened cable next to the alternator", "Interference flips bits: the listener's checksum test rejects the damaged sentences.")]
    spec = [("Standard", "NMEA 0183 v4.11 (NMEA; equivalent to IEC 61162-1); NMEA 0183-HS = 38400 baud (IEC 61162-2)"),
            ("Electrical", "Differential, RS-422 compatible: one talker drives up to several listeners; listeners opto-isolated"),
            ("Format", "4800 baud, 8 data bits, no parity, 1 stop bit; ASCII sentences max 82 characters"),
            ("Sentence", "$ + talker ID (2) + formatter (3) + comma-separated fields + *checksum + CR LF; '!' for encapsulated data (AIS)"),
            ("Checksum", "8-bit XOR of the characters between $ and *, sent as two hex digits"),
            ("Topology", "Point-to-point: a listener input takes exactly one talker. Several talkers need a multiplexer.")]
    frame = [["Sentence", ("$", 8), ("Talker", 16), ("Formatter", 24), (",field,field...", "n x 8"), ("*", 8), ("Checksum", 16), ("CR LF", 16)]]
    about = ("NMEA 0183 is the language of marine electronics: every GPS, depth sounder or wind instrument talks in short ASCII sentences such as "
             "$GPRMC. It is deliberately simple - one talker per wire pair, at 4800 baud - so a listener that needs data from several instruments needs "
             "a multiplexer that merges the sentences onto one faster output. The two-letter talker ID tells who is talking, the three-letter formatter "
             "what the fields mean, and an XOR checksum protects each sentence.")
    guide = ["Select a $GPRMC sentence and read every field in the tree; check the date and the status field.",
             "LOGIC: each character is one 8N1 byte at 4800 baud (about 2 ms). Count how long a whole GGA sentence takes.",
             "Compare a sentence from the GPS with the same sentence repeated by the multiplexer at 38400 baud.",
             "Swap A and B on the depth sounder and watch the inverted waveform on the SCOPE.",
             "COMPOSE your own sentence from the laptop: the checksum is calculated for you - try a wrong one too."]

    def build(self):
        g = self.node("gps", "GPS RECEIVER", "gps", 30, 20, "GP", "talker").at_right()
        d = self.node("depth", "DEPTH SOUNDER", "sensor", 30, 115, "SD", "talker").at_right()
        w = self.node("wind", "WIND INSTRUMENT", "wind", 30, 210, "WI", "talker").at_right()
        pc = self.node("pc", "LAPTOP (USB-NMEA)", "pc", 30, 305, "II", "talker").at_right()
        m = self.node("mux", "NMEA MULTIPLEXER", "box", 330, 150, "4 in / 1 out", "out 38400 baud", h=60)
        m.port = (330, 180)
        p = self.node("plot", "CHARTPLOTTER", "display", 620, 60, "listener", "in 38400, out 4800").at_left()
        ap = self.node("ap", "AUTOPILOT", "pilot", 620, 270, "listener").at_left()
        v = self.node("vhf", "VHF / DSC RADIO", "radio", 330, 300, "listener", "needs position").at_top()
        self.link([(148, 46), (240, 46)], "gps", None, "GPS out (RS-422 pair)")
        self.link([(240, 46), (240, 160), (330, 160)], None, "mux")
        self.link([(240, 46), (270, 46), (270, 270), (389, 270), (389, 300)], None, "vhf")
        self.link([(148, 141), (220, 141), (220, 172), (330, 172)], "depth", "mux")
        self.link([(148, 236), (220, 236), (220, 186), (330, 186)], "wind", "mux")
        self.link([(148, 331), (250, 331), (250, 200), (330, 200)], "pc", "mux", style="usb", c0="usba")
        self.link([(448, 165), (540, 165), (540, 86), (620, 86)], "mux", "plot", "0183-HS 38400 baud")
        self.link([(679, 112), (679, 270)], "plot", "ap", "plotter -> pilot")
        self.ship = Vessel()
        self.user = "pc"
        p.vars.update({"Position": "-", "SOG / COG": "-", "Depth": "-", "Wind": "-", "Water temp": "-", "Sentences OK": 0, "Rejected": 0})
        m.vars.update({"Forwarded": 0, "Dropped (bad)": 0})
        ap.vars.update({"Steering to": "-", "XTE": "-"})
        v.vars.update({"DSC position": "-"})
        self.every(1.0, self.gps_tx, 0.05)
        self.every(1.0, self.depth_tx, 0.31)
        self.every(0.5, self.wind_tx, 0.17)
        self.every(5.0, lambda: self.talk("depth", sentence("SDMTW,%.1f,C" % self.ship.wtemp)), 0.8)
        self.every(1.0, self.pilot_tx, 0.6)
        self.every(0.2, lambda: self.ship.step(0.2, self.rng), 0.0)

    def corrupt(self, line):
        if not self.fault["noise"] or self.rng.random() > 0.35:
            return line, None
        i = int(self.rng.integers(7, max(8, len(line) - 6)))
        c = chr(ord(line[i]) ^ (1 << int(self.rng.integers(0, 6))))
        if not (32 <= ord(c) < 127) or c in "$*,!\\":
            c = "#"
        return line[:i] + c + line[i + 1:], "Bit errors: checksum test fails at the listener"

    def talk(self, src, line, dst=None, baud=4800):
        """A talker sends one sentence on its own output; the multiplexer forwards valid ones."""
        n = self.by[src]
        if not n.on:
            return
        line, err = self.corrupt(line)
        inv = src == "depth" and self.fault["polarity"]
        if inv:
            err = "Inverted polarity (A/B swapped): framing errors, sentence unreadable"
        if self.fault["twotalk"] and src in ("wind", "depth") and self.rng.random() < 0.45:
            err = "Collision: wind and depth talkers drive the same pair at the same time"
        port = "out:" + src
        if dst is None:
            dst = ["mux", "vhf"] if src == "gps" else ["mux"]
        fr = self.say(src, dst, line, port, baud, err=err, invert=inv)
        self.at(fr.t + fr.dur + 0.003, self.mux_fwd, line, err is None)

    def mux_fwd(self, line, ok):
        m = self.by["mux"]
        if not m.on:
            return
        if not ok:
            m.vars["Dropped (bad)"] += 1
            return
        m.vars["Forwarded"] += 1
        err = "Plotter at 4800 baud cannot read a 38400 baud stream (framing errors)" if self.fault["baud"] else None
        self.say("mux", "plot", line, "out:mux", 38400, info="(mux) " + line.strip(), err=err, proto="NMEA 0183-HS")
        p = self.by["plot"]
        if err:
            p.vars["Rejected"] += 1
            p.state = "NO DATA"
            return
        p.state = ""
        p.vars["Sentences OK"] += 1
        self.parse(line, p)

    def parse(self, line, p):
        f = line.strip().split("*")[0].split(",")
        fmt = f[0][3:6]
        try:
            if fmt == "RMC":
                if f[2] == "A":
                    p.vars["Position"] = "%s %s  %s %s" % (f[3], f[4], f[5], f[6])
                    p.vars["SOG / COG"] = "%s kn / %s deg" % (f[7], f[8])
                else:
                    p.vars["Position"] = "NO FIX (RMC status V)"
                    p.vars["SOG / COG"] = "-"
            elif fmt == "DBT":
                p.vars["Depth"] = "%s m" % f[3]
            elif fmt == "MWV":
                p.vars["Wind"] = "%s deg %s, %s kn" % (f[1], "apparent" if f[2] == "R" else "true", f[3])
            elif fmt == "MTW":
                p.vars["Water temp"] = "%s C" % f[1]
            elif fmt == "GGA":
                self.by["vhf"].vars["DSC position"] = ("%s %s %s %s" % (f[2], f[3], f[4], f[5])) if f[6] != "0" else "NO FIX"
        except IndexError:
            pass

    def gps_tx(self):
        fix = not self.fault["nofix"]
        s, t = self.ship, self.t
        self.talk("gps", gga(s, t, "GP", fix))
        self.talk("gps", rmc(s, t, "GP", fix))
        self.talk("gps", vtg(s) if fix else sentence("GPVTG,,T,,M,,N,,K,N"))
        if int(t) % 5 == 0:
            self.talk("gps", sentence("GPGSA,A,%s,02,05,07,13,15,18,20,24,29,,,,1.6,0.9,1.3" % ("3" if fix else "1")))
        if fix:
            self.by["vhf"].vars["DSC position"] = "%s %s" % (nmea_lat(s.lat)[0], nmea_lon(s.lon)[0])

    def depth_tx(self):
        d = self.ship.depth
        self.talk("depth", sentence("SDDBT,%.1f,f,%.1f,M,%.1f,F" % (d * 3.28084, d, d * 0.546807)))
        self.talk("depth", sentence("SDDPT,%.1f,0.5,100" % d))

    def wind_tx(self):
        self.talk("wind", sentence("WIMWV,%.1f,R,%.1f,N,A" % (self.ship.awa, self.ship.aws)))

    def pilot_tx(self):
        p = self.by["plot"]
        if not p.on or p.vars["Position"].startswith("NO") or p.vars["Position"] == "-":
            return
        xte = 0.02 + 0.01 * math.sin(self.t / 7.0)
        brg = 50.0
        self.say("plot", "ap", sentence("ECAPB,A,A,%.2f,%s,N,V,V,%.1f,T,WP07,%.1f,T,%.1f,T,A" % (abs(xte), "L" if xte > 0 else "R", brg, brg + 1.5, brg + 2.0)), "out:plot",
                 info=None, kind="cmd")
        self.by["ap"].vars.update({"Steering to": "WP07, heading %.1f T" % (brg + 2.0), "XTE": "%.2f NM" % xte})

    def cond(self, net):
        c = super().cond(net)
        if self.fault["noise"]:
            c["noise"] = 0.25
            c["cm"] = 0.6
        return c

    def tpls(self):
        return [Tpl("Custom sentence (laptop)", [P("s", "Sentence body", "IIMTW,15.3,C")], lambda s, v, send: self._custom(v["s"], send, False),
                    "Type what goes between '$' and '*'. The laptop computes the checksum and sends it into multiplexer input 4."),
                Tpl("Sentence with a wrong checksum", [P("s", "Sentence body", "IIXDR,C,19.5,C,AIR")], lambda s, v, send: self._custom(v["s"], send, True),
                    "The multiplexer recalculates the checksum, finds a mismatch and drops the sentence."),
                Tpl("Waypoint position (laptop)", [P("lat", "Latitude", 50.80, -89.0, 89.0, 0.01), P("lon", "Longitude", -1.25, -179.0, 179.0, 0.01)],
                    lambda s, v, send: self._custom("IIWPL,%s,%s,%s,%s,WP08" % (nmea_lat(v["lat"]) + nmea_lon(v["lon"])), send, False), "WPL sentence: waypoint location.")]

    def _custom(self, body, send, bad):
        body = body.strip().lstrip("$!").split("*")[0]
        line = sentence(body, bad)
        if not send:
            return serial_frame(self, "pc", "mux", "NMEA 0183", line.strip(), sentence_pdu(line), 4800, line="D", labels=char_labels(line))
        n = self.by["pc"]
        if not n.on:
            return None
        fr = self.say("pc", "mux", line, "out:pc", kind="cmd", err="Checksum mismatch: the multiplexer drops the sentence" if bad else None)
        self.at(fr.t + fr.dur + 0.003, self.mux_fwd, line, not bad)
        return None


class IEC61162_1(NmeaNet):
    key, name = "iec61162_1", "IEC 61162-1"
    blurb = "International marine electronics standards"
    proto = "IEC 61162-1"
    medium = "SOLAS bridge wiring: gyro, GNSS, Doppler log and echo sounder talkers, a distribution unit, radar, ECDIS and autopilot listeners; 4800 baud, opto-isolated inputs"
    faults = [("direct", "Distribution unit bypassed: gyro drives 6 listeners", "Every listener loads the talker: the differential voltage collapses and the listeners see bit errors."),
              ("rate", "Gyro set to 20 Hz on a 4800 baud port", "20 x (HDT + ROT) needs about 740 characters/s, the port carries 480: the output buffer fills, latency grows, sentences are lost."),
              ("loop", "Doppler log output not isolated (ground loop)", "A ground potential difference pushes the common-mode voltage outside the radar's input range: framing errors."),
              ("nocs", "Old echo sounder sends no checksums", "IEC 61162-1 requires the checksum: the ECDIS rejects every DPT sentence."),
              ("alarm", "Autopilot off-heading alarm", "The autopilot raises an ALR alarm until the ECDIS operator acknowledges it (ACK).")]
    spec = [("Standard", "IEC 61162-1 Ed. 6 (2024) - single talker, multiple listeners; IEC 61162-2 for 38400 baud"),
            ("Electrical", "Talker: differential driver (RS-422 compatible); listener: opto-isolated, max 2 mA load, galvanic isolation mandatory"),
            ("Format", "4800 baud 8N1, ASCII sentences of max 82 characters, checksum mandatory"),
            ("Talker IDs", "HE gyro, GN GNSS, VD Doppler log, SD echo sounder, EC ECDIS, AG autopilot, RA radar ..."),
            ("Alarms", "ALR / ACK (legacy) and Bridge Alert Management (ALF, ALC, ACN, ARC, HBT) per IEC 62923"),
            ("Use", "Type-approved navigation equipment on SOLAS ships (IEC 60945, IMO performance standards)")]
    frame = [["Sentence", ("$ / !", 8), ("Talker", 16), ("Formatter", 24), ("Fields", "n x 8"), ("*hh", 24), ("CR LF", 16)]]
    about = ("IEC 61162-1 is the international (IEC) standard behind NMEA 0183, written for type-approved ship's equipment. The sentences look the same, "
             "but the rules are stricter: checksums are mandatory, listener inputs must be galvanically isolated, and talker outputs drive a limited "
             "number of listeners - big bridges use distribution units. At 4800 baud a port carries only about 480 characters a second, so fast "
             "heading data moves to IEC 61162-2 (38400 baud) or IEC 61162-450 Ethernet.")
    guide = ["Look at the gyro's HDT and ROT sentences: talker ID HE (north-seeking gyro).",
             "Read the radar's input latency in DEVICE, then set the gyro to 20 Hz and watch the backlog grow.",
             "Bypass the distribution unit and see the differential amplitude on the SCOPE drop.",
             "Raise the off-heading alarm, then acknowledge it from the ECDIS (COMPOSE).",
             "Turn on 'no checksums' and compare an accepted and a rejected DPT sentence."]

    def build(self):
        g = self.node("gyro", "GYROCOMPASS", "compass", 20, 20, "HE", "HDT + ROT 5 Hz").at_right()
        n = self.node("gnss", "GNSS RECEIVER", "gps", 20, 110, "GN").at_right()
        lg = self.node("log", "DOPPLER LOG", "sensor", 20, 200, "VD").at_right()
        es = self.node("echo", "ECHO SOUNDER", "sensor", 20, 290, "SD").at_right()
        du = self.node("dist", "DISTRIBUTION UNIT", "box", 270, 20, "1 in / 6 out", "isolated buffers").at_left()
        r = self.node("radar", "RADAR / ARPA", "radar", 600, 20, "RA").at_left()
        ec = self.node("ecdis", "ECDIS", "display", 600, 150, "EC").at_left()
        ap = self.node("ap", "AUTOPILOT (HCS)", "pilot", 600, 290, "AG").at_left()
        self.link([(138, 46), (270, 46)], "gyro", "dist", "gyro")
        self.link([(388, 34), (600, 34)], "dist", "radar")
        self.link([(388, 50), (500, 50), (500, 164), (600, 164)], "dist", "ecdis")
        self.link([(388, 64), (480, 64), (480, 304), (600, 304)], "dist", "ap")
        self.link([(138, 136), (200, 136), (200, 176), (600, 176)], "gnss", "ecdis", "GNSS")
        self.link([(138, 226), (540, 226), (540, 60), (600, 60)], "log", "radar", "log -> radar")
        self.link([(138, 316), (560, 316), (560, 190), (600, 190)], "echo", "ecdis", "echo sounder")
        self.link([(659, 202), (659, 290)], "ecdis", "ap", "ECDIS <-> pilot")
        self.ship = Vessel(50.62, -1.05, 13.8, 241.0)
        self.ship.hdg = 238.0
        self.user = "ecdis"
        self.alarm = {"active": False, "acked": False}
        r.vars.update({"Heading": "-", "Input latency": "0 ms", "Speed (log)": "-"})
        ec.vars.update({"Heading": "-", "Position": "-", "Depth": "-", "Rejected": 0, "Alarm": "none"})
        ap.vars.update({"Mode": "heading control", "Set heading": "238.0", "Off-heading alarm": "normal"})
        g.vars.update({"Output rate": "5 Hz", "Buffer": "0 ms", "Dropped": 0})
        self.every(0.2, self.gyro_tx, 0.01)
        self.every(1.0, self.gnss_tx, 0.11)
        self.every(1.0, self.log_tx, 0.23)
        self.every(1.0, self.echo_tx, 0.37)
        self.every(1.0, self.pilot_tx, 0.53)
        self.every(0.1, lambda: self.ship.step(0.1, self.rng), 0.0)
        self.hz = 5

    def gyro_tx(self):
        g = self.by["gyro"]
        if not g.on:
            return
        k = 4 if self.fault["rate"] else 1
        for i in range(k):
            for line in (sentence("HEHDT,%.1f,T" % self.ship.hdg), sentence("HEROT,%.1f,A" % self.ship.rot)):
                if self.backlog("out:gyro") > 0.5:
                    g.vars["Dropped"] += 1
                    continue
                err = None
                if self.fault["direct"] and self.rng.random() < 0.4:
                    err = "Talker overloaded by 6 listeners: amplitude below the receiver threshold, bit errors"
                fr = self.say("gyro", ["dist", "radar", "ecdis", "ap"], line, "out:gyro", err=err)
                if err is None and line[3:6] == "HDT":
                    self.at(fr.t + fr.dur, self.got_hdg, line)
        lat = self.backlog("out:gyro")
        g.vars["Buffer"] = "%d ms" % (lat * 1000)
        g.vars["Output rate"] = "20 Hz (overload)" if self.fault["rate"] else "5 Hz"
        self.by["radar"].vars["Input latency"] = "%d ms" % (lat * 1000 + 40)

    def got_hdg(self, line):
        h = line.split(",")[1]
        self.by["radar"].vars["Heading"] = h + " T"
        self.by["ecdis"].vars["Heading"] = h + " T"

    def gnss_tx(self):
        s, t = self.ship, self.t
        for line in (gga(s, t, "GN"), rmc(s, t, "GN"), sentence("GNZDA,%s,%02d,%02d,%04d,00,00" % (utc(t).strftime("%H%M%S.00"), utc(t).day, utc(t).month, utc(t).year))):
            self.say("gnss", "ecdis", line, "out:gnss")
        la, ns = nmea_lat(s.lat)
        lo, ew = nmea_lon(s.lon)
        self.by["ecdis"].vars["Position"] = "%s %s %s %s" % (la, ns, lo, ew)

    def log_tx(self):
        s = self.ship
        err = "Common-mode voltage outside the receiver's range (ground loop, no isolation)" if self.fault["loop"] else None
        self.say("log", "radar", sentence("VDVBW,%.1f,-0.1,A,%.1f,0.2,A,,V,,V" % (s.stw, s.sog)), "out:log", err=err)
        self.by["radar"].vars["Speed (log)"] = "ERROR" if err else "%.1f kn (water), %.1f kn (ground)" % (s.stw, s.sog)

    def echo_tx(self):
        d = self.ship.depth + 30
        body = "SDDPT,%.1f,1.5,200" % d
        if self.fault["nocs"]:
            line = "$" + body + "\r\n"
            self.say("echo", "ecdis", line, "out:echo", err="No checksum: rejected by the IEC 61162-1 listener")
            self.by["ecdis"].vars["Rejected"] += 1
            self.by["ecdis"].vars["Depth"] = "NO VALID DATA"
        else:
            self.say("echo", "ecdis", sentence(body), "out:echo")
            self.by["ecdis"].vars["Depth"] = "%.1f m below transducer" % d

    def pilot_tx(self):
        s = self.ship
        ap = self.by["ap"]
        if not self.fault["alarm"]:
            try:
                tgt = float(ap.vars["Set heading"])
            except ValueError:
                tgt = 238.0
            e = (tgt - s.hdg + 540) % 360 - 180
            s.rudder = max(-20.0, min(20.0, e * 2.0))
            s.hdg = (s.hdg + max(-1.5, min(1.5, e))) % 360
        self.say("ecdis", "ap", sentence("ECHTC,V,,,H,N,20,10,,,%s,,,T" % ap.vars["Set heading"]), "out:ecdis", kind="cmd")
        self.say("ap", "ecdis", sentence("AGRSA,%.1f,A,," % (s.rudder + float(self.rng.normal(0, 0.3)))), "out:ap")
        if self.fault["alarm"]:
            st = "A" if self.alarm["acked"] else "V"
            self.say("ap", "ecdis", sentence("AGALR,%s,001,A,%s,OFF HEADING" % (utc(self.t).strftime("%H%M%S.00"), st)), "out:ap", kind="evt")
            ap.vars["Off-heading alarm"] = "ACTIVE (%s)" % ("acknowledged" if self.alarm["acked"] else "unacknowledged")
            self.by["ecdis"].vars["Alarm"] = "001 OFF HEADING " + ("(acknowledged)" if self.alarm["acked"] else "- ACKNOWLEDGE!")
        elif int(self.t) % 10 == 0:
            self.say("ap", "ecdis", sentence("AGALR,%s,001,V,V,OFF HEADING" % utc(self.t).strftime("%H%M%S.00")), "out:ap", kind="evt")

    def on_fault(self, key, on):
        if key == "alarm":
            self.alarm = {"active": on, "acked": False}
            if not on:
                self.by["ap"].vars["Off-heading alarm"] = "normal"
                self.by["ecdis"].vars["Alarm"] = "none"
            else:
                self.ship.hdg = (self.ship.hdg + 12) % 360

    def cond(self, net):
        c = super().cond(net)
        if self.fault["direct"]:
            c["atten"] = 0.18
        if self.fault["loop"] and net in ("A", "B"):
            c["off"] = 9.5
            c["cm"] = 1.2
        return c

    def tpls(self):
        return [Tpl("ECDIS acknowledges alarm (ACK)", [P("n", "Alarm number", 1, 1, 999)], lambda s, v, send: self._ack(v["n"], send), "ACK with the alarm's local number."),
                Tpl("ECDIS heading command (HTC)", [P("h", "Heading to steer", 238.0, 0.0, 359.9, 0.5)], lambda s, v, send: self._htc(v["h"], send),
                    "Heading/track control command to the autopilot."),
                Tpl("Custom sentence (ECDIS output)", [P("s", "Sentence body", "ECTXT,01,01,01,ROUTE CHECK OK")], lambda s, v, send: self._custom(v["s"], send),
                    "Sent on the ECDIS output to the autopilot.")]

    def _ack(self, num, send):
        line = sentence("ECACK,%03d" % num)
        if not send:
            return serial_frame(self, "ecdis", "ap", self.proto, line.strip(), sentence_pdu(line), 4800, line="D", labels=char_labels(line))
        self.say("ecdis", "ap", line, "out:ecdis", kind="cmd")
        if self.fault["alarm"] and num == 1:
            self.alarm["acked"] = True
        return None

    def _htc(self, h, send):
        line = sentence("ECHTC,V,,,H,N,20,10,,,%.1f,,,T" % h)
        if not send:
            return serial_frame(self, "ecdis", "ap", self.proto, line.strip(), sentence_pdu(line), 4800, line="D", labels=char_labels(line))
        self.say("ecdis", "ap", line, "out:ecdis", kind="cmd")
        self.by["ap"].vars["Set heading"] = "%.1f" % h
        self.ship.hdg = h
        return None

    def _custom(self, body, send):
        line = sentence(body.strip().lstrip("$").split("*")[0])
        if not send:
            return serial_frame(self, "ecdis", "ap", self.proto, line.strip(), sentence_pdu(line), 4800, line="D", labels=char_labels(line))
        self.say("ecdis", "ap", line, "out:ecdis", kind="cmd")
        return None


# ================================================================== SeaTalk
ST_KEYS = {0x01: "Auto", 0x02: "Standby", 0x03: "Track", 0x04: "Disp", 0x05: "-1", 0x06: "-10", 0x07: "+1", 0x08: "+10", 0x21: "-1 & -10 (port tack)", 0x22: "+1 & +10 (starboard tack)"}
ST_NAMES = {0x00: "Depth below transducer", 0x10: "Apparent wind angle", 0x11: "Apparent wind speed", 0x20: "Speed through water", 0x23: "Water temperature",
            0x30: "Set lamp intensity", 0x50: "Latitude", 0x51: "Longitude", 0x52: "Speed over ground", 0x53: "Course over ground", 0x54: "GMT time", 0x56: "Date",
            0x84: "Compass heading, autopilot course and rudder", 0x86: "Keystroke", 0x9C: "Compass heading and rudder position"}


def st_hdg(h):
    """SeaTalk heading encoding: (U & 3) * 90 + (VW & 0x3F) * 2 + bits set in U & 0xC."""
    h = int(round(h)) % 360
    q = h // 90
    rem = h - 90 * q
    return q | (0x4 if rem % 2 else 0), rem // 2


def st_hdg_dec(u, vw):
    hb = u & 0xC
    return (u & 3) * 90 + (vw & 0x3F) * 2 + (0 if hb == 0 else (2 if hb == 0xC else 1))


def st_decode(d):
    """List of (text, byte offset, length, description) for one datagram."""
    out = []
    c = d[0]
    if c == 0x00 and len(d) >= 5:
        v = (d[3] | d[4] << 8) / 10.0
        out.append(("Depth: %.1f ft (%.1f m)%s" % (v, v * 0.3048, ", transducer defective" if d[2] & 0x04 else ""), 2, 3, "XXXX/10 feet; Y/Z nibble flags: anchor/deep/shallow alarm, metric display"))
    elif c == 0x10 and len(d) >= 4:
        out.append(("Apparent wind angle: %.1f deg right of bow" % ((d[2] << 8 | d[3]) / 2.0), 2, 2, "XXYY / 2 degrees"))
    elif c == 0x11 and len(d) >= 4:
        out.append(("Apparent wind speed: %.1f kn" % ((d[2] & 0x7F) + (d[3] & 0x0F) / 10.0), 2, 2, "(XX & 0x7F) + Y/10 knots"))
    elif c == 0x20 and len(d) >= 4:
        out.append(("Speed through water: %.1f kn" % ((d[2] | d[3] << 8) / 10.0), 2, 2, "XXXX / 10 knots"))
    elif c == 0x23 and len(d) >= 4:
        out.append(("Water temperature: %d C / %d F" % (d[2], d[3]), 2, 2, ""))
    elif c == 0x30 and len(d) >= 3:
        out.append(("Lamp intensity: L%d" % ({0: 0, 4: 1, 8: 2, 0xC: 3}.get(d[2] & 0xF, 0)), 2, 1, "X = 0, 4, 8, C -> L0..L3"))
    elif c in (0x50, 0x51) and len(d) >= 5:
        mm = d[3] | d[4] << 8
        hemi = ("S" if mm & 0x8000 else "N") if c == 0x50 else ("E" if mm & 0x8000 else "W")
        out.append(("%s: %d deg %.2f' %s" % ("Latitude" if c == 0x50 else "Longitude", d[2], (mm & 0x7FFF) / 100.0, hemi), 2, 3, "XX degrees, (YYYY & 0x7FFF)/100 minutes; MSB = hemisphere"))
    elif c == 0x52 and len(d) >= 4:
        out.append(("Speed over ground: %.1f kn" % ((d[2] | d[3] << 8) / 10.0), 2, 2, ""))
    elif c == 0x53 and len(d) >= 3:
        u = d[1] >> 4
        out.append(("Course over ground: %.1f deg" % ((u & 3) * 90 + (d[2] & 0x3F) * 2 + (u & 0xC) / 8.0), 1, 2, "(U & 3) * 90 + (VW & 0x3F) * 2 + (U & 0xC) / 8"))
    elif c == 0x54 and len(d) >= 4:
        rst = (d[2] << 4) | (d[1] >> 4)
        out.append(("GMT time: %02d:%02d:%02d" % (d[3], rst >> 6, rst & 0x3F), 1, 3, "HH hours, RST: 6 bits minutes + 6 bits seconds"))
    elif c == 0x56 and len(d) >= 4:
        out.append(("Date: %02d %s 20%02d" % (d[2], MONTHS[max(1, min(12, d[1] >> 4)) - 1], d[3]), 1, 3, "M month (upper nibble of the attribute), DD day, YY year"))
    elif c in (0x84, 0x9C) and len(d) >= 4:
        u = d[1] >> 4
        out.append(("Compass heading: %d deg (turning %s)" % (st_hdg_dec(u, d[2]), "right" if u & 0x8 else "left"), 1, 2, "(U & 3) * 90 + (VW & 0x3F) * 2 + bits set in U & 0xC"))
        if c == 0x84 and len(d) >= 9:
            course = ((d[2] >> 6) & 3) * 90 + d[3] / 2.0
            mode = d[4] & 0x0F
            out.append(("Autopilot course: %.1f deg" % course, 2, 2, "Two higher bits of V * 90 + XY / 2"))
            out.append(("Mode: %s" % ("standby" if mode == 0 else ", ".join(n for b_, n in ((2, "auto"), (4, "vane"), (8, "track")) if mode & b_)), 4, 1, "Z: 0 standby, 2 auto, 4 vane, 8 track"))
            out.append(("Alarms: %s" % (", ".join(n for b_, n in ((4, "off course"), (8, "wind shift")) if d[5] & b_) or "none"), 5, 1, ""))
            out.append(("Rudder position: %+d deg" % (d[6] - 256 if d[6] > 127 else d[6]), 6, 1, "Positive = steering to starboard"))
        if c == 0x9C:
            out.append(("Rudder position: %+d deg" % (d[3] - 256 if d[3] > 127 else d[3]), 3, 1, ""))
    elif c == 0x86 and len(d) >= 4:
        ok = (d[2] ^ d[3]) == 0xFF
        out.append(("Key: %s (code 0x%02X, check 0x%02X %s)" % (ST_KEYS.get(d[2], "?"), d[2], d[3], "OK" if ok else "BAD"), 2, 2,
                    "X1 YY yy: YY key code, yy = YY inverted; X = 0 ST1000+, 2 ST4000+ / ST600R control head"))
    return out


class SeaTalk(Scenario):
    key, name, cat = "seatalk", "SeaTalk", "marine"
    blurb = "Marine instrument networking"
    phy, rate = "seatalk", 4800
    medium = "SeaTalk (SeaTalk1): 3-wire bus (+12 V, data, 0 V) daisy-chained through the instruments, 4800 baud, 11-bit characters with a command bit, no master"
    nets = [("DATA", "SeaTalk data (yellow)"), ("+12V", "SeaTalk +12 V (red)")]
    lines = ["B"]
    faults = [("collision", "Two instruments start talking at once", "Each talker reads back its own transmission, notices the garbled data and repeats the datagram later."),
              ("short", "Data line pinched to 0 V", "A wired-OR bus held low: every character turns into a break, all communication stops."),
              ("power", "SeaTalk +12 V fuse blown", "Instruments powered from the bus go dark; the course computer and GPS have their own supply and keep talking."),
              ("noise", "Interference corrupts a bit", "SeaTalk1 has NO checksum: a damaged depth datagram is accepted and displayed as a wrong value.")]
    spec = [("Origin", "Autohelm / Raymarine proprietary (1980s-2000s); reverse engineered (Thomas Knauf's reference), replaced by SeaTalkng"),
            ("Electrical", "3 wires in parallel: +12 V, data (+12 V idle = 1, pulled to 0 V = 0, wired OR with pull-ups), 0 V"),
            ("Character", "4800 baud, 11 bits: start, 8 data bits (LSB first), command bit, stop; the command bit marks the first byte of a datagram"),
            ("Datagram", "3-18 bytes: command, attribute (low nibble = additional bytes n, total 3 + n), data"),
            ("Access", "No master: talk when the bus is idle, listen to your own echo, retry after a collision"),
            ("Integrity", "No checksum or CRC"), ("Gateway", "SeaTalk-to-SeaTalkng converter / NMEA bridges in chartplotters")]
    frame = [["Datagram", ("Command (cmd bit 1)", 9), ("Attribute: n", 9), ("Data 1", 9), ("Data 2 .. 2+n", "n x 9")]]
    about = ("SeaTalk was Autohelm's (later Raymarine's) instrument bus: depth, speed, wind and autopilot units daisy-chained with one three-core "
             "cable that also powers them. Everyone shares one data wire at 4800 baud. A ninth 'command' bit marks the first byte of each datagram, "
             "and a device simply starts talking when the bus is quiet, listening to its own echo to catch collisions. There is no checksum - a "
             "simplicity that SeaTalkng (NMEA 2000) later fixed.")
    guide = ["LOGIC: find the command bit (9th data bit) - it is 1 only on the first byte of each datagram.",
             "Decode a depth datagram 00 02 YZ XX XX: XXXX / 10 = depth in feet.",
             "COMPOSE an autopilot keystroke (+10) and watch the course computer change its course.",
             "Inject the noise fault and find the wrong depth value that nobody can detect.",
             "Blow the +12 V fuse and see which devices still talk."]

    def build(self):
        nodes = [self.node("dep", "ST60 DEPTH", "meter", 30, 40, "", "bus powered"), self.node("spd", "ST60 SPEED", "meter", 200, 40, "", "bus powered"),
                 self.node("wind", "ST60 WIND", "wind", 370, 40, "", "bus powered"), self.node("cc", "COURSE COMPUTER", "pilot", 560, 40, "", "feeds +12 V"),
                 self.node("head", "ST6002 CONTROL HEAD", "keypad", 120, 290, "", "bus powered"), self.node("gps", "RAYSTAR GPS", "gps", 360, 290, "", "own supply"),
                 self.node("plot", "CHARTPLOTTER", "display", 600, 290, "", "listener")]
        for n in nodes[4:]:
            n.at_top()
        self.trunk(200, 30, 860, nodes, "wire", net="DATA", label="SeaTalk 3-core cable (red +12 V, yellow data, screen 0 V)", drop_conn="jack")
        self.ship = Vessel()
        self.course = 54.0
        self.mode = 2
        self.user = "head"
        self.lamp = 0
        self.by["cc"].vars.update({"Mode": "auto", "Course": "54", "Rudder": "+0"})
        self.by["plot"].vars.update({"Depth": "-", "Wind": "-", "STW": "-", "Position": "-"})
        for nid in ("dep", "spd", "wind", "head"):
            self.by[nid].vars["Lamp"] = "L0"
        self.every(1.0, self.instruments, 0.05)
        self.every(0.5, self.pilot, 0.27)
        self.every(1.0, self.gps_tx, 0.61)
        self.every(10.0, lambda: self.dg("spd", [0x23, 0x01, int(self.ship.wtemp), int(self.ship.wtemp * 1.8 + 32)]), 1.4)
        self.every(0.2, lambda: self.ship.step(0.2, self.rng), 0.0)

    def dgpdu(self, d, note=None):
        b = Bld("SeaTalk datagram 0x%02X: %s" % (d[0], ST_NAMES.get(d[0], "unknown")), "SeaTalk1 (Raymarine). Decoding per Thomas Knauf's SeaTalk Technical Reference.")
        b.u8("Command", d[0], "0x%02X (%s) - command bit set" % (d[0], ST_NAMES.get(d[0], "?")), "The only byte with the 9th (command) bit = 1")
        b.u8("Attribute", d[1], "0x%02X: %d additional bytes -> total %d" % (d[1], d[1] & 0xF, 3 + (d[1] & 0xF)), "Low nibble = n, total length = 3 + n; high nibble may carry data")
        b.raw("Data", bytes(d[2:]), None, "")
        for txt, o, n, desc in st_decode(d):
            b.note(txt, desc, d=2, off=o, n=n)
        if note:
            b.note(note, "SeaTalk1 has no error detection", d=1)
        b.note("No checksum", "Corrupted datagrams cannot be detected by the listeners", d=1)
        return b.done()

    def dg(self, src, d, info=None, kind="data", note=None, err=None):
        n = self.by[src]
        if not n.on or self.fault["short"]:
            return None
        if src in ("dep", "spd", "wind", "head") and self.fault["power"]:
            return None
        d = list(d)
        if self.fault["collision"] and src in ("dep", "wind") and self.rng.random() < 0.35:
            err = "Collision: another device talked at the same time; the sender saw its echo garbled and will retry"
            self.at(self.t + 0.03 + float(self.rng.random()) * 0.03, self.dg, src, d, info, kind)
        p = self.dgpdu(d, note)
        dec = st_decode(d)
        fr = serial_frame(self, src, None, "SeaTalk", info or "%02X  %s" % (d[0], dec[0][0] if dec else ST_NAMES.get(d[0], "unknown datagram")), p, 4800, 8, "9", 1, line="B",
                          kind=kind, err=err, ninth=[1] + [0] * (len(d) - 1), key="0x%02X" % d[0], gap=0.0, lead=1.0)
        return self.tx(fr, ifs=10 / 4800.0)

    def instruments(self):
        s = self.ship
        raw = int(s.depth * 3.28084 * 10)
        note = None
        info = None
        shown = s.depth
        if self.fault["noise"] and self.rng.random() < 0.5:
            raw ^= 0x0100
            shown = raw / 10.0 * 0.3048
            note = "CORRUPTED in transit (bit 8 of the depth flipped) - accepted anyway"
            info = "00 Depth: %.1f ft  <- wrong value, undetectable" % (raw / 10.0)
        self.dg("dep", [0x00, 0x02, 0x00, raw & 255, raw >> 8], info=info, note=note)
        self.dg("spd", [0x20, 0x01, int(s.stw * 10) & 255, int(s.stw * 10) >> 8])
        awa = int(s.awa * 2)
        self.dg("wind", [0x10, 0x01, awa >> 8, awa & 255])
        self.dg("wind", [0x11, 0x01, int(s.aws) & 0x7F, int((s.aws % 1) * 10)])
        p = self.by["plot"]
        if not self.fault["short"]:
            if not self.fault["power"]:
                p.vars.update({"Depth": "%.1f m%s" % (shown, " (!)" if note else ""), "Wind": "%.0f deg / %.1f kn" % (s.awa, s.aws), "STW": "%.1f kn" % s.stw})
            else:
                p.vars.update({"Depth": "NO DATA", "Wind": "NO DATA", "STW": "NO DATA"})

    def pilot(self):
        s = self.ship
        if self.mode:
            err = (self.course - s.hdg + 540) % 360 - 180
            s.rudder = max(-30, min(30, err * 1.5))
            s.hdg = (s.hdg + s.rudder * 0.05) % 360
        u, vw = st_hdg(s.hdg)
        cq = int(self.course) // 90
        xy = int((self.course - 90 * cq) * 2)
        rr = int(s.rudder) & 255
        self.dg("cc", [0x84, (u << 4) | 0x06, (cq << 6) | (vw & 0x3F), xy, self.mode, 0x00, rr, 0x00, 0x08])
        self.by["cc"].vars.update({"Mode": {0: "standby", 2: "auto", 8: "track"}.get(self.mode, "?"), "Course": "%.0f" % self.course, "Rudder": "%+d" % int(s.rudder)})

    def gps_tx(self):
        s = self.ship
        la, lo = abs(s.lat), abs(s.lon)
        lam = int(round((la - int(la)) * 6000)) | (0x8000 if s.lat < 0 else 0)
        lom = int(round((lo - int(lo)) * 6000)) | (0x8000 if s.lon > 0 else 0)
        self.dg("gps", [0x50, 0x02, int(la), lam & 255, lam >> 8])
        self.dg("gps", [0x51, 0x02, int(lo), lom & 255, lom >> 8])
        sog = int(s.sog * 10)
        self.dg("gps", [0x52, 0x01, sog & 255, sog >> 8])
        c = int(round(s.cog * 2)) / 2.0
        q = int(c) // 90
        rem = c - 90 * q
        vw = int(rem // 2)
        half = rem - 2 * vw
        u = q | (int(half * 8) & 0xC)
        self.dg("gps", [0x53, (u << 4), vw & 0x3F])
        tm = utc(self.t)
        rst = (tm.minute << 6) | tm.second
        self.dg("gps", [0x54, ((rst & 0xF) << 4) | 0x01, rst >> 4, tm.hour])
        self.by["plot"].vars["Position"] = "%d %.2f' N  %d %.2f' W" % (int(la), (la % 1) * 60, int(lo), (lo % 1) * 60)

    def keystroke(self, code, send=True):
        d = [0x86, 0x21, code, code ^ 0xFF]
        if not send:
            return serial_frame(self, "head", None, "SeaTalk", "preview", self.dgpdu(d), 4800, 8, "9", 1, line="B", ninth=[1, 0, 0, 0])
        self.dg("head", d, info="86 Keystroke: %s" % ST_KEYS.get(code, "?"), kind="cmd")
        if self.by["head"].on and not self.fault["power"] and not self.fault["short"]:
            if code in (0x05, 0x06, 0x07, 0x08) and self.mode:
                self.course = (self.course + {0x05: -1, 0x06: -10, 0x07: 1, 0x08: 10}[code]) % 360
            elif code == 0x01:
                self.mode, self.course = 2, round(self.ship.hdg)
            elif code == 0x02:
                self.mode = 0
        return None

    def lamp_set(self, lvl, send=True):
        d = [0x30, 0x00, [0, 4, 8, 0xC][lvl]]
        if not send:
            return serial_frame(self, "head", None, "SeaTalk", "preview", self.dgpdu(d), 4800, 8, "9", 1, line="B", ninth=[1, 0, 0])
        self.dg("head", d, info="30 Set lamp intensity L%d" % lvl, kind="cmd")
        for nid in ("dep", "spd", "wind", "head"):
            self.by[nid].vars["Lamp"] = "L%d" % lvl
        return None

    def raw(self, txt, send=True):
        try:
            d = list(bytes.fromhex(txt.replace(" ", "")))[:18]
        except ValueError:
            d = [0x00, 0x02, 0x00, 0x00, 0x00]
        if len(d) < 3:
            d += [0] * (3 - len(d))
        if not send:
            return serial_frame(self, "head", None, "SeaTalk", "preview", self.dgpdu(d), 4800, 8, "9", 1, line="B", ninth=[1] + [0] * (len(d) - 1))
        self.dg("head", d, kind="cmd")
        return None

    def cond(self, net):
        c = super().cond(net)
        if self.fault["short"]:
            c["atten"] = 0.02
        if self.fault["power"] and net == "+12V":
            c["atten"] = 0.0
        return c

    def on_fault(self, key, on):
        if key == "power":
            for nid in ("dep", "spd", "wind", "head"):
                self.by[nid].state = "DARK" if on else ""

    def tpls(self):
        return [Tpl("Autopilot keystroke", [P("k", "Key", 0x08, opts=[0x01, 0x02, 0x05, 0x06, 0x07, 0x08], fmt=lambda v: "%s (0x%02X)" % (ST_KEYS[v], v))],
                    lambda s, v, send: self.keystroke(v["k"], send), "Datagram 86 21 YY yy from the ST6002 control head (X = 2)."),
                Tpl("Lamp intensity", [P("l", "Level", 2, 0, 3)], lambda s, v, send: self.lamp_set(v["l"], send), "Datagram 30 00 0X: all instruments change their backlight."),
                Tpl("Raw datagram (hex)", [P("d", "Bytes", "00 02 00 2C 01")], lambda s, v, send: self.raw(v["d"], send),
                    "Any datagram; the first byte gets the command bit. 00 02 00 2C 01 = depth 30.0 ft.")]


# ===================================================================== AIS
AIS_NAV = {0: "under way using engine", 1: "at anchor", 2: "not under command", 3: "restricted manoeuvrability", 5: "moored", 7: "engaged in fishing", 8: "under way sailing", 15: "not defined"}
AIS_TYPES = {1: "Position report (class A, scheduled)", 3: "Position report (class A, interrogated)", 4: "Base station report", 5: "Static and voyage related data",
             12: "Addressed safety related message", 13: "Safety related acknowledgement", 14: "Safety related broadcast message", 15: "Interrogation",
             18: "Standard class B position report", 21: "Aid-to-navigation report", 24: "Class B static data report"}
SHIP_TYPES = {30: "fishing", 36: "sailing", 37: "pleasure craft", 60: "passenger", 70: "cargo", 80: "tanker"}


class AisMsg:
    """Bit-level builder for ITU-R M.1371 messages with dissection info."""

    def __init__(self, mtype, mmsi, repeat=0):
        self.bits, self.fields = [], []
        self.mtype = mtype
        self.add("Message ID", 6, mtype, "%d (%s)" % (mtype, AIS_TYPES.get(mtype, "")))
        self.add("Repeat indicator", 2, repeat, None, "How many times a repeater has relayed it")
        self.add("MMSI", 30, mmsi, "%09d" % mmsi, "Maritime Mobile Service Identity; first 3 digits (MID) = flag state")

    def add(self, name, n, v, txt=None, desc=""):
        v = int(v) & ((1 << n) - 1)
        self.fields.append((name, len(self.bits), n, txt if txt is not None else str(v), desc))
        self.bits += msb(v, n)

    def text(self, name, s, nchar, desc=""):
        self.fields.append((name, len(self.bits), nchar * 6, '"%s"' % s.upper()[:nchar], desc or "6-bit ASCII, padded with @"))
        self.bits += six_text(s, nchar)

    def pos(self, lon, lat):
        self.add("Longitude", 28, round(lon * 600000) if lon is not None else 181 * 600000, ("%.5f deg" % lon) if lon is not None else "181 = not available", "1/10 000 minute, two's complement, + = east")
        self.add("Latitude", 27, round(lat * 600000) if lat is not None else 91 * 600000, ("%.5f deg" % lat) if lat is not None else "91 = not available", "1/10 000 minute, + = north")


class MarineRadio(Radio):
    """Log-distance loss plus the radio horizon (antenna heights in node.extra['h'])."""

    def horizon(self, a, b):
        return 4120.0 * (math.sqrt(self.s.by[a].extra.get("h", 10.0)) + math.sqrt(self.s.by[b].extra.get("h", 10.0)))

    def rssi(self, a, b):
        r = Radio.rssi(self, a, b)
        d, hz = self.dist(a, b), self.horizon(a, b)
        if d > hz:
            r -= 20 + 1.0 * (d - hz) / 1000.0
        return r

    def range_for(self, nid, sens=None):
        return min(Radio.range_for(self, nid, sens), 4120.0 * (math.sqrt(self.s.by[nid].extra.get("h", 10.0)) + math.sqrt(4.0)))


class AIS(RfNet):
    key, name, cat = "ais", "AIS", "marine"
    blurb = "Vessel tracking and collision avoidance"
    f_mhz, ptx, sens, n_exp = 162.0, 41.0, -107.0, 2.8
    map_size = 40000.0
    map_grid = 1852.0
    band = {"f0": 161.950, "f1": 162.050, "unit": "MHz", "chans": [("AIS 1 (87B)", 161.975, 0.025), ("AIS 2 (88B)", 162.025, 0.025)]}
    medium = "AIS: VHF 161.975 / 162.025 MHz, 9600 bit/s GMSK, SOTDMA (2250 slots of 26.7 ms per minute and channel); map grid = 1 nautical mile"
    faults = [("gps", "Yacht's GPS antenna disconnected", "The class B unit keeps transmitting, but with latitude 91 / longitude 181 (not available): the target cannot be plotted."),
              ("hidden", "Hidden stations pick the same slot", "The yacht and the fishing vessel are too far apart to hear each other's reservations and choose the same slot: both reports collide at own ship."),
              ("ant", "Own VHF antenna cable soaked (-20 dB)", "Own ship's receiver loses 20 dB: distant targets disappear from the ECDIS."),
              ("mmsi", "Two vessels configured with the same MMSI", "The fishing vessel broadcasts the ferry's MMSI: the target jumps between two positions."),
              ("busy", "Interference blocks AIS 2 (162.025 MHz)", "Every transmission on channel B is lost; stations still get through on channel A.")]
    spec = [("Standard", "ITU-R M.1371-5; IEC 62287 (class B), IEC 61993-2 (class A); IMO SOLAS carriage for ships over 300 GT"),
            ("Radio", "VHF maritime band, AIS 1 = 161.975 MHz (ch 87B), AIS 2 = 162.025 MHz (ch 88B), 25 kHz, GMSK BT 0.4, 9600 bit/s"),
            ("Access", "SOTDMA: 2250 slots per minute and channel; stations announce their next slots; class B CS uses CSTDMA"),
            ("Frame", "Ramp-up, 24-bit training sequence, HDLC flag 0x7E, data (bit-stuffed, NRZI), CRC-16, flag, buffer; 256 bits = one slot"),
            ("Reporting", "Class A: 2-10 s under way (by speed), 3 min at anchor; static data every 6 min. Class B CS: 30 s (3 min below 2 kn)"),
            ("Power", "Class A 12.5 W, class B CS 2 W, class B SO 5 W; range limited mainly by antenna height (radio horizon)"),
            ("Output", "Received messages leave the transponder as !AIVDM sentences (6-bit armoured) at 38400 baud")]
    frame = [["AIS slot (256 bits)", ("Ramp", 8), ("Training 0101...", 24), ("Flag 7E", 8), ("Data (msg 1: 168 bits)", 168), ("CRC-16", 16), ("Flag 7E", 8), ("Buffer", 24)],
             ["Message 1 fields", ("ID", 6), ("Rep", 2), ("MMSI", 30), ("Nav status", 4), ("ROT", 8), ("SOG", 10), ("Acc", 1), ("Longitude", 28), ("Latitude", 27), ("COG", 12),
              ("Heading", 9), ("UTC s", 6), ("...", 6), ("Comm state", 19)]]
    about = ("AIS makes every ship visible to every other ship and to shore stations: transponders broadcast position, course, speed and identity "
             "on two VHF channels. There is no central controller - each station listens, picks free time slots and announces which slots it will "
             "use next (SOTDMA), so hundreds of ships share a channel. Fast ships report every 2 seconds, anchored ones every 3 minutes, and the "
             "ECDIS uses the reports for collision avoidance (CPA / TCPA).")
    guide = ["Select a position report: MMSI, navigation status, SOG, position, COG and the SOTDMA communication state.",
             "Compare the reporting intervals of the ferry (fast), the tanker and the yacht (class B) in STATS.",
             "Read the !AIVDM sentence in the tree: the same bits as the radio message, in 6-bit ASCII armour.",
             "Drag the tanker out beyond the radio horizon and watch the link margin collapse.",
             "Inject the hidden-station fault: two transmissions destroyed in the same slot."]

    def setup(self):
        self.radio_model = MarineRadio(self, self.f_mhz, self.ptx, self.sens, self.n_exp)
        self.lat0, self.lon0 = 50.86, -1.62
        self.dest = {"own": "SOUTHAMPTON", "tank": "FAWLEY", "ferry": "CHERBOURG", "fish": "POOLE"}
        ships = [("own", "OWN SHIP + ECDIS", "ship", 15000, 9500, 235009876, "A", 12.0, 62.0, 25, 41, 70, "SOLENT TRADER"),
                 ("tank", "MT NORDIC STAR", "ship", 28000, 4500, 538007123, "A", 13.0, 248.0, 30, 41, 80, "NORDIC STAR"),
                 ("ferry", "PRIDE OF SOLENT", "ship", 5000, 12500, 232004567, "A", 18.0, 78.0, 22, 41, 60, "PRIDE OF SOLENT"),
                 ("yacht", "SY BLUE HERON", "yacht", 20500, 13000, 235112233, "B", 5.5, 205.0, 12, 33, 36, "BLUE HERON"),
                 ("fish", "FV MARIA", "ship", 34500, 13800, 227123450, "A", 2.5, 120.0, 8, 41, 30, "MARIA"),
                 ("base", "SHORE BASE STATION", "tower", 2500, 2000, 2320123, "base", 0, 0, 60, 41, 0, "BASE"),
                 ("aton", "WEST CARDINAL BUOY", "buoy", 21500, 6500, 992351234, "aton", 0, 0, 3, 35, 0, "BRAMBLE W")]
        self.st = {}
        for nid, lab, kind, x, y, mmsi, cls, sog, cog, h, p, stype, name in ships:
            n = self.rnode(nid, lab, kind, x, y, "%09d" % mmsi, {"A": "class A", "B": "class B CS", "base": "base station", "aton": "AtoN"}[cls], w=112, h=40)
            n.extra.update(h=h, ptx=p)
            self.st[nid] = dict(mmsi=mmsi, cls=cls, sog=sog, cog=cog, stype=stype, name=name, nxt=0.4 + 0.9 * len(self.st), stat=0.8 + 1.7 * len(self.st), seq=0, ch=len(self.st) % 2,
                                slot=int(self.rng.integers(0, 2250)), to=7)
            if cls in ("A", "B"):
                n.vars.update({"SOG": "%.1f kn" % sog, "COG": "%.0f" % cog, "Interval": "-"})
        self.st["fish"]["nav"] = 7
        self.st["tank"]["nav"] = 0
        self.pairs = [(k, "own") for k in self.st if k != "own"]
        self.user = "own"
        self.by["own"].vars.update({"Targets": 0, "Closest": "-", "CPA alert": "-"})
        self.seen = {}
        self.every(0.5, self.tick, 0.1)
        self.every(1.0, self.move, 0.5)

    def latlon(self, nid):
        n = self.by[nid]
        lat = self.lat0 - n.my / 111120.0
        return lat, self.lon0 + n.mx / (111120.0 * math.cos(math.radians(lat)))

    def move(self):
        for nid, s in self.st.items():
            if s["sog"] <= 0:
                continue
            n = self.by[nid]
            d = s["sog"] * 1852 / 3600.0
            n.mx += d * math.sin(math.radians(s["cog"]))
            n.my -= d * math.cos(math.radians(s["cog"]))
            if n.mx < 500 or n.mx > self.map_m - 500 or n.my < 500 or n.my > 16500:
                s["cog"] = (s["cog"] + 180) % 360
        self.ecdis()

    def interval(self, s):
        if s["cls"] == "A":
            if s.get("nav") in (1, 5):
                return 180.0
            return 2.0 if s["sog"] > 23 else (6.0 if s["sog"] > 14 else 10.0)
        if s["cls"] == "B":
            return 30.0 if s["sog"] > 2 else 180.0
        return 10.0 if s["cls"] == "base" else 180.0

    def commstate(self, m, s):
        s["to"] = (s["to"] - 1) % 8
        to = s["to"]
        sub = {0: 1, 1: (utc(self.t).hour << 9) | (utc(self.t).minute << 2), 2: s["slot"], 4: s["slot"], 6: s["slot"]}.get(to, len(self.st) - 1)
        m.add("Communication state (SOTDMA)", 19, (0 << 17) | (to << 14) | (sub & 0x3FFF),
              "sync UTC direct, slot timeout %d, %s %d" % (to, {0: "slot offset", 1: "UTC hour/min", 2: "slot number", 4: "slot number", 6: "slot number"}.get(to, "received stations"), sub),
              "Tells everyone which slot this station will use next and when it changes")

    def build_msg(self, nid, kind):
        s = self.st[nid]
        mmsi = s["mmsi"]
        if self.fault["mmsi"] and nid == "fish":
            mmsi = self.st["ferry"]["mmsi"]
        lat, lon = self.latlon(nid)
        sec = int(self.t) % 60
        if kind == "pos" and s["cls"] == "A":
            m = AisMsg(1, mmsi)
            nav = s.get("nav", 0)
            m.add("Navigational status", 4, nav, "%d (%s)" % (nav, AIS_NAV.get(nav, "")), "")
            m.add("Rate of turn", 8, 0, "0 (not turning)", "ROT_AIS = 4.733 x sqrt(deg/min); -128 = not available")
            m.add("SOG", 10, round(s["sog"] * 10), "%.1f kn" % s["sog"], "0.1 knot steps; 1023 = not available")
            m.add("Position accuracy", 1, 1, "1 (DGNSS, < 10 m)", "")
            m.pos(lon, lat)
            m.add("COG", 12, round(s["cog"] * 10), "%.1f deg" % s["cog"], "0.1 degree; 3600 = not available")
            m.add("True heading", 9, round(s["cog"] - 2) % 360, "%d deg" % (round(s["cog"] - 2) % 360), "511 = not available")
            m.add("Time stamp", 6, sec, "%d s (UTC second)" % sec, "")
            m.add("Special manoeuvre", 2, 0, "0 (not available)", "")
            m.add("Spare", 3, 0, "", "")
            m.add("RAIM", 1, 0, "0", "")
            self.commstate(m, s)
            return m, "Position report: %s %.1f kn %.0f deg" % (s["name"], s["sog"], s["cog"])
        if kind == "pos" and s["cls"] == "B":
            m = AisMsg(18, mmsi)
            nogps = self.fault["gps"] and nid == "yacht"
            m.add("Reserved", 8, 0, "", "")
            m.add("SOG", 10, 1023 if nogps else round(s["sog"] * 10), "not available" if nogps else "%.1f kn" % s["sog"], "")
            m.add("Position accuracy", 1, 0, "0 (> 10 m)", "")
            m.pos(None if nogps else lon, None if nogps else lat)
            m.add("COG", 12, 3600 if nogps else round(s["cog"] * 10), "not available" if nogps else "%.1f deg" % s["cog"], "")
            m.add("True heading", 9, 511, "511 (not available)", "Small craft rarely have a heading sensor connected")
            m.add("Time stamp", 6, 60 if nogps else sec, "60 (no time: positioning system inoperative)" if nogps else "%d s" % sec, "")
            m.add("Reserved", 2, 0, "", "")
            m.add("CS unit flag", 1, 1, "1 (carrier-sense class B)", "")
            m.add("Display / DSC / band / msg22 / assigned", 5, 0b01100, "display no, DSC yes, whole band, no msg 22, autonomous", "")
            m.add("RAIM", 1, 0, "0", "")
            m.add("Comm state selector", 1, 1, "1 (ITDMA)", "")
            m.add("Communication state", 19, 0b1100000000000000110, "carrier-sense fill pattern", "Class B CS units use 1100000000000000110")
            return m, ("Class B position: %s - POSITION NOT AVAILABLE" % s["name"]) if nogps else ("Class B position: %s %.1f kn %.0f deg" % (s["name"], s["sog"], s["cog"]))
        if kind == "stat" and s["cls"] == "A":
            m = AisMsg(5, mmsi)
            m.add("AIS version", 2, 2, "2 (M.1371-5)", "")
            m.add("IMO number", 30, 9000000 + mmsi % 999999, None, "")
            m.text("Call sign", ("2" + s["name"][:3]).replace(" ", ""), 7)
            m.text("Vessel name", s["name"], 20)
            m.add("Ship type", 8, s["stype"], "%d (%s)" % (s["stype"], SHIP_TYPES.get(s["stype"], "")), "")
            m.add("Dimension to bow (A)", 9, 120, "120 m", "Reference point (GNSS antenna) to bow")
            m.add("Dimension to stern (B)", 9, 25, "25 m", "")
            m.add("Dimension to port (C)", 6, 10, "10 m", "")
            m.add("Dimension to starboard (D)", 6, 12, "12 m", "")
            m.add("EPFD type", 4, 1, "1 (GPS)", "")
            m.add("ETA month", 4, 11, "11", "")
            m.add("ETA day", 5, 15, "15", "")
            m.add("ETA hour", 5, 6, "06", "")
            m.add("ETA minute", 6, 30, "30", "")
            m.add("Draught", 8, 84, "8.4 m", "0.1 m")
            m.text("Destination", self.dest.get(nid, "SOUTHAMPTON"), 20)
            m.add("DTE", 1, 0, "0 (available)", "")
            m.add("Spare", 1, 0, "", "")
            return m, "Static and voyage data: %s, %s, to %s" % (s["name"], SHIP_TYPES.get(s["stype"], "ship"), self.dest.get(nid, "SOUTHAMPTON"))
        if kind == "stat" and s["cls"] == "B":
            part = s.get("part", 0)
            s["part"] = 1 - part
            m = AisMsg(24, mmsi)
            m.add("Part number", 2, part, "%d (part %s)" % (part, "A" if part == 0 else "B"), "")
            if part == 0:
                m.text("Vessel name", s["name"], 20)
            else:
                m.add("Ship type", 8, s["stype"], "%d (%s)" % (s["stype"], SHIP_TYPES.get(s["stype"], "")), "")
                m.text("Vendor ID", "SIM", 7)
                m.text("Call sign", "MBHE2", 7)
                m.add("Dimensions A/B/C/D", 30, (6 << 21) | (6 << 12) | (2 << 6) | 2, "6 / 6 / 2 / 2 m", "")
                m.add("Spare", 6, 0, "", "")
            return m, "Class B static data part %s: %s" % ("A" if part == 0 else "B", s["name"])
        if s["cls"] == "base":
            u = utc(self.t)
            m = AisMsg(4, mmsi)
            m.add("UTC year", 14, u.year, None, "")
            m.add("UTC month", 4, u.month, None, "")
            m.add("UTC day", 5, u.day, None, "")
            m.add("UTC hour", 5, u.hour, None, "")
            m.add("UTC minute", 6, u.minute, None, "")
            m.add("UTC second", 6, u.second, None, "")
            m.add("Position accuracy", 1, 1, "1", "")
            m.pos(lon, lat)
            m.add("EPFD type", 4, 7, "7 (surveyed)", "")
            m.add("Spare", 10, 0, "", "")
            m.add("RAIM", 1, 0, "0", "")
            self.commstate(m, s)
            return m, "Base station report: UTC %s" % u.strftime("%H:%M:%S")
        m = AisMsg(21, mmsi)
        m.add("Type of aid", 5, 13, "13 (cardinal mark W)", "")
        m.text("Name", s["name"], 20)
        m.add("Position accuracy", 1, 1, "1", "")
        m.pos(lon, lat)
        m.add("Dimensions", 30, (1 << 21) | (1 << 12) | (1 << 6) | 1, "1 / 1 / 1 / 1 m", "")
        m.add("EPFD type", 4, 7, "7 (surveyed)", "")
        m.add("Time stamp", 6, sec, None, "")
        m.add("Off-position indicator", 1, 0, "0 (on position)", "")
        m.add("Reserved", 8, 0, "", "")
        m.add("RAIM", 1, 0, "0", "")
        m.add("Virtual AtoN", 1, 0, "0 (real buoy)", "")
        m.add("Assigned mode", 1, 0, "0", "")
        m.add("Spare", 1, 0, "", "")
        return m, "AtoN report: %s (west cardinal)" % s["name"]

    def pdu(self, m, ch):
        data = pack_bits(m.bits)
        fcs = crcn("CRC-16/X-25", data)
        b = Bld("AIS message %d: %s" % (m.mtype, AIS_TYPES.get(m.mtype, "")), "ITU-R M.1371-5")
        b.b += data
        for name, bp, n, txt, desc in m.fields:
            b.rows.append([1, "%s: %s" % (name, txt), bp // 8, (bp + n + 7) // 8 - bp // 8, desc + (" [bits %d-%d]" % (bp, bp + n - 1))])
        b.u16("FCS (CRC-16)", fcs, "0x%04X [correct]" % fcs, "CRC-16-CCITT (X.25) over the data bits", little=True)
        st, fill = ais_armor(m.bits)
        pay = "AIVDM,1,1,,%s,%s,%d" % ("A" if ch == 0 else "B", st, fill)
        b.note("NMEA output: %s" % sentence("!" + pay).strip(), "How the transponder passes this message to the ECDIS: 6 bits per character ('armouring')", d=0)
        b.note("HDLC framing: training sequence 24 bits, flag 0x7E, %d data bits + 16 CRC (bit-stuffed, NRZI), flag 0x7E" % len(m.bits), "Data bytes are sent LSB first", d=0)
        return b.done(), data, fcs

    def air_bits(self, data, fcs):
        body = bytes_lsb(data + bytes([fcs & 255, fcs >> 8]))
        stuffed, _ = hdlc_stuff(body)
        flag = [0, 1, 1, 1, 1, 1, 1, 0]
        raw = [0, 1] * 12 + flag + stuffed + flag
        return nrzi(raw, start=0)

    def tx_msg(self, nid, kind, dst=None, ch=None):
        s = self.st[nid]
        n = self.by[nid]
        if not n.on:
            return None
        m, info = self.build_msg(nid, kind)
        if ch is None:
            ch = s["ch"]
            s["ch"] = 1 - s["ch"]
        p, data, fcs = self.pdu(m, ch)
        nbits = len(m.bits) + 16 + 24 + 16 + 8 + 24
        nslots = max(1, -(-nbits // 256))
        dur = nslots * 256 / 9600.0
        rssi = self.radio_model.rssi(nid, "own") if nid != "own" else -40
        err = None
        if nid != "own":
            own = self.by["own"]
            own.extra["sens"] = self.sens + (20 if self.fault["ant"] else 0)
            if self.fault["busy"] and ch == 1:
                err = "Lost: interference on AIS 2"
            elif not self.radio_model.ok(nid, "own"):
                err = "Not decoded at own ship: %.0f dBm (margin %+.0f dB)" % (rssi, self.radio_model.margin(nid, "own"))
            elif self.fault["hidden"] and nid in ("yacht", "fish") and kind == "pos":
                err = "Slot collision: the yacht and the fishing vessel (hidden from each other) used the same slot"
        f = 161.975 if ch == 0 else 162.025
        bits = self.air_bits(data, fcs)
        fr = rf_frame(self, nid, dst, "AIS", "%s  [msg %d, %s]" % (info, m.mtype, "A" if ch == 0 else "B"), p, dur, f, 0.025, kind={"pos": "data", "stat": "ctl"}.get(kind, "sync"),
                      key="msg %d %s" % (m.mtype, s["name"]), err=err, rssi=int(rssi),
                      wirefn=lambda fr, b=bits: fsk_wire(b, 9600, 2.4, lead=16, gauss=0.4))
        self.tx(fr, bus="ch%d" % ch)
        if err is None and nid != "own":
            self.seen[nid] = (self.t, m.mtype)
        return fr

    def tick(self):
        for nid, s in self.st.items():
            if self.t >= s["nxt"]:
                iv = self.interval(s)
                s["nxt"] = self.t + iv
                if nid in self.by and nid not in ("base", "aton") and s["cls"] in ("A", "B"):
                    self.by[nid].vars["Interval"] = "%g s" % iv
                if s["cls"] in ("A", "B"):
                    self.tx_msg(nid, "pos")
                    if self.fault["hidden"] and nid == "yacht":
                        self.tx_msg("fish", "pos", ch=1 - s["ch"])
                else:
                    self.tx_msg(nid, "other")
            if self.t >= s["stat"] and s["cls"] in ("A", "B"):
                self.tx_msg(nid, "stat")
                s["stat"] = self.t + (2.0 if (s["cls"] == "B" and s.get("part", 0) == 1) else 360.0)

    def ecdis(self):
        own = self.by["own"]
        oxy = (own.mx, own.my)
        so = self.st["own"]
        ov = (so["sog"] * 0.5144 * math.sin(math.radians(so["cog"])), -so["sog"] * 0.5144 * math.cos(math.radians(so["cog"])))
        best = None
        alert = []
        n = 0
        for nid, (t, mt) in self.seen.items():
            if self.t - t > 400:
                continue
            if nid == "yacht" and self.fault["gps"]:
                continue
            n += 1
            tn = self.by[nid]
            st = self.st[nid]
            dx, dy = tn.mx - oxy[0], tn.my - oxy[1]
            rng = math.hypot(dx, dy) / 1852.0
            if best is None or rng < best[1]:
                best = (tn.label, rng)
            tv = (st["sog"] * 0.5144 * math.sin(math.radians(st["cog"])), -st["sog"] * 0.5144 * math.cos(math.radians(st["cog"])))
            rv = (tv[0] - ov[0], tv[1] - ov[1])
            v2 = rv[0] ** 2 + rv[1] ** 2
            if v2 > 1e-6:
                tcpa = -(dx * rv[0] + dy * rv[1]) / v2
                if 0 < tcpa < 1800:
                    cpa = math.hypot(dx + rv[0] * tcpa, dy + rv[1] * tcpa) / 1852.0
                    if cpa < 1.0:
                        alert.append("%s CPA %.2f NM in %d min" % (tn.label, cpa, tcpa / 60))
        own.vars["Targets"] = n
        own.vars["Closest"] = "%s at %.1f NM" % best if best else "-"
        own.vars["CPA alert"] = "; ".join(alert) if alert else "none (< 1 NM within 30 min)"

    def draw_map(self, s, r, sc):
        import pygame
        land = [(0, 0), (16000, 0), (14000, 1200), (9000, 2600), (6000, 2400), (3000, 4200), (0, 5200)]
        land2 = [(26000, 17500), (31000, 15800), (40000, 16200), (40000, 17500)]
        for poly in (land, land2):
            pts = [(r.x + x * sc, r.y + y * sc) for x, y in poly]
            pygame.draw.polygon(s, (34, 42, 30), pts)
            pygame.draw.lines(s, (90, 110, 70), False, pts, 1)

    def tpls(self):
        return [Tpl("Safety broadcast (msg 14)", [P("txt", "Text", "SECURITE GALE WARNING")], lambda s, v, send: self._safety(v["txt"], send),
                    "Broadcast safety text from own ship to every station in range."),
                Tpl("Interrogate tanker for static data (msg 15)", [], lambda s, v, send: self._interrogate(send), "Asks the tanker for message 5; it answers in its next slots.")]

    def _safety(self, txt, send):
        m = AisMsg(14, self.st["own"]["mmsi"])
        m.add("Spare", 2, 0, "", "")
        m.text("Safety related text", txt, min(30, len(txt)))
        p, data, fcs = self.pdu(m, 0)
        if not send:
            return Frame(self.t, 0.03, "own", None, "AIS", "preview", pdu=p)
        bits = self.air_bits(data, fcs)
        dur = max(1, -(-(len(m.bits) + 88) // 256)) * 256 / 9600.0
        self.tx(rf_frame(self, "own", None, "AIS", "Safety broadcast (msg 14): %s" % txt, p, dur, 161.975, 0.025, kind="evt", key="msg 14", rssi=-40,
                         wirefn=lambda fr, b=bits: fsk_wire(b, 9600, 2.4, lead=16, gauss=0.4)), bus="ch0")
        return None

    def _interrogate(self, send):
        m = AisMsg(15, self.st["own"]["mmsi"])
        m.add("Spare", 2, 0, "", "")
        m.add("Destination MMSI", 30, self.st["tank"]["mmsi"], "%09d (tanker)" % self.st["tank"]["mmsi"], "")
        m.add("Requested message", 6, 5, "5 (static and voyage data)", "")
        m.add("Slot offset", 12, 0, "0 (any)", "")
        m.add("Spare", 2, 0, "", "")
        p, data, fcs = self.pdu(m, 1)
        if not send:
            return Frame(self.t, 0.03, "own", "tank", "AIS", "preview", pdu=p)
        bits = self.air_bits(data, fcs)
        self.tx(rf_frame(self, "own", "tank", "AIS", "Interrogation (msg 15): tanker, send message 5", p, 256 / 9600.0, 162.025, 0.025, kind="cmd", key="msg 15", rssi=-40,
                         wirefn=lambda fr, b=bits: fsk_wire(b, 9600, 2.4, lead=16, gauss=0.4)), bus="ch1")
        self.at(self.t + 0.2, self.tx_msg, "tank", "stat", "own")
        return None
