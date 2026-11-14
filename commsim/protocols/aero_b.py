"""Aviation and aerospace, part B: surveillance and data links (ADS-B, Mode S,
ACARS, CPDLC, ASTERIX) and space systems (SpaceWire, SpaceFibre, CCSDS)."""
import math
import struct
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, crc, msb, lsb, bits_to_int, pack_bits, bytes_lsb, six_text, odd_parity, enc8b10b
from .fam import RfNet, Radio, rf_frame, fsk_wire, ppm_wire, IpNet, burst_wire
from .marine_a import MarineRadio

FT = 0.3048
ADSB_CHARS = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"


def bits_of(v, n):
    return msb(int(v) & ((1 << n) - 1), n)


def ms_crc(bits):
    """Mode S 24-bit parity (generator 0x1FFF409) over a bit list."""
    return crc(pack_bits(bits), 24, 0xFFF409, 0, False, False, 0) if len(bits) % 8 == 0 else 0


def ac13(alt_ft):
    n = max(0, int(round((alt_ft + 1000) / 25.0)))
    b = bits_of(n, 11)
    return b[:6] + [0] + b[6:7] + [1] + b[7:]


def ac12(alt_ft):
    """12-bit ADS-B altitude field (the 13-bit AC code without the M bit): Q = 1, 25 ft steps."""
    n = max(0, int(round((alt_ft + 1000) / 25.0)))
    b = bits_of(n, 11)
    return b[:7] + [1] + b[7:]


def cpr_nl(lat):
    if abs(lat) >= 87.0:
        return 1
    a = 1 - math.cos(math.pi / 30.0)
    b = math.cos(math.radians(abs(lat))) ** 2
    return int(math.floor(2 * math.pi / math.acos(1 - a / b)))


def cpr_encode(lat, lon, odd):
    i = 1 if odd else 0
    dlat = 360.0 / (60 - i)
    yz = math.floor(131072 * ((lat % dlat) / dlat) + 0.5)
    rlat = dlat * (yz / 131072.0 + math.floor(lat / dlat))
    dlon = 360.0 / max(cpr_nl(rlat) - i, 1)
    xz = math.floor(131072 * ((lon % dlon) / dlon) + 0.5)
    return int(yz) & 0x1FFFF, int(xz) & 0x1FFFF


class FieldBits:
    """Bit-field builder with dissection rows (MSB first)."""

    def __init__(self):
        self.bits, self.f = [], []

    def add(self, name, n, v, txt=None, desc=""):
        self.f.append((name, len(self.bits), n, txt if txt is not None else str(int(v) & ((1 << n) - 1)), desc))
        self.bits += bits_of(v, n)

    def raw(self, name, bl, txt, desc=""):
        self.f.append((name, len(self.bits), len(bl), txt, desc))
        self.bits += list(bl)

    def pdu(self, title, desc=""):
        b = Bld(title, desc)
        b.b += pack_bits(self.bits)
        for name, bp, n, txt, d in self.f:
            b.rows.append([1, "%s: %s" % (name, txt), bp // 8, (bp + n + 7) // 8 - bp // 8, d + " [bits %d-%d]" % (bp + 1, bp + n)])
        return b.done()


def ppm_labels(fb, pre=0):
    return [(bp, bp + n, name if n > 4 else name[:3], k % 2) for k, (name, bp, n, txt, d) in enumerate(fb.f)]


# =================================================================== ADS-B
class ADSB(RfNet):
    key, name, cat = "adsb", "ADS-B", "aero"
    blurb = "Aircraft surveillance"
    f_mhz, ptx, sens, n_exp = 1090.0, 54.0, -84.0, 2.0
    map_size = 400000.0
    map_grid = 50000.0
    band = {"f0": 1086.0, "f1": 1094.0, "unit": "MHz", "chans": [("1090 MHz", 1090.0, 2.6)]}
    medium = "ADS-B 1090 MHz Extended Squitter (DF17): aircraft broadcast GNSS position, velocity and identity twice a second; ground stations and other aircraft listen"
    faults = [("gps", "Aircraft 3 loses GNSS", "Its transponder keeps squittering but airborne position messages carry no position: ground stations lose the track."),
              ("dup", "Two aircraft share an ICAO address", "A mis-programmed transponder: the tracker associates both aircraft with one track, which jumps."),
              ("fruit", "Dense traffic: overlapping squitters (FRUIT)", "Two 120 us messages overlap at the receiver: both are garbled and fail the CRC."),
              ("gs1", "Ground station 1 antenna fault", "Only ground station 2 still hears the traffic.")]
    spec = [("Standards", "ICAO Annex 10 Vol IV, RTCA DO-260B / EUROCAE ED-102A (1090ES); UAT 978 MHz (DO-282) in the US"),
            ("Signal", "1090 MHz, pulse position modulation 1 Mbit/s, 8 us preamble + 112 data bits = 120 us"),
            ("Format", "DF17: DF (5), capability (3), ICAO address (24), ME message (56), parity (24, CRC)"),
            ("Messages", "TC 1-4 identification, 5-8 surface position, 9-18 airborne position (baro alt), 19 velocity, 20-22 airborne position (GNSS alt), 28 status, 31 operational status"),
            ("Position", "Compact Position Reporting: 17-bit lat/lon, alternating even/odd frames; global decoding needs both"),
            ("Rates", "Airborne position and velocity 2 per second, identification every 5 s")]
    frame = [["DF17 extended squitter (112 bits)", ("DF=17", 5), ("CA", 3), ("ICAO address", 24), ("ME (TC + data)", 56), ("Parity / CRC-24", 24)]]
    about = ("With ADS-B an aircraft tells everyone where it is: its transponder broadcasts GNSS position, velocity and call sign several times a "
             "second, without being asked. Ground stations relay the data to air traffic control, and other aircraft (ADS-B In) can see the "
             "traffic directly. Positions are packed with Compact Position Reporting, which needs an even and an odd message to decode globally.")
    guide = ["Select an airborne position message: altitude code and the CPR latitude/longitude (even or odd frame).",
             "Find the identification message: 8 characters of 6 bits each.",
             "Decode a velocity message: east-west and north-south components.",
             "Make aircraft 3 lose GNSS and watch its track disappear from the ground station.",
             "SCOPE: the 8 us preamble pulses and the pulse-position data bits."]

    def setup(self):
        self.radio_model = MarineRadio(self, self.f_mhz, self.ptx, self.sens, self.n_exp)
        self.lat0, self.lon0 = 53.5, -4.0
        acs = [("ac1", "BAW123 A320", 0x4CA2D1, "BAW123", 60000, 80000, 36000, 450, 95), ("ac2", "EZY45 A319", 0x4007F3, "EZY45", 250000, 60000, 34000, 430, 250),
               ("ac3", "RYR8YK B738", 0x4CA8E4, "RYR8YK", 150000, 160000, 24000, 380, 20), ("ac4", "KLM1234 E190", 0x484506, "KLM1234", 320000, 140000, 38000, 460, 280),
               ("ac5", "N123AB C172", 0xA061D9, "N123AB", 110000, 40000, 4500, 110, 180)]
        self.ac = {}
        for nid, lab, icao, cs, x, y, alt, gs, trk in acs:
            n = self.rnode(nid, lab, "plane", x, y, "%06X" % icao, "FL%03d" % (alt // 100), w=110)
            n.extra.update(h=alt * FT, ptx=51.0 if "C172" in lab else 54.0)
            self.ac[nid] = dict(icao=icao, cs=cs, alt=alt, gs=gs, trk=trk, odd=0)
            n.vars.update({"Altitude": "%d ft" % alt, "GS / track": "%d kt / %d" % (gs, trk)})
        for nid, lab, x, y in (("gs1", "GROUND STATION 1", 120000, 120000), ("gs2", "GROUND STATION 2", 300000, 60000)):
            n = self.rnode(nid, lab, "tower", x, y, "", "1090 receiver", w=110)
            n.extra.update(h=40.0)
            n.vars.update({"Tracks": 0, "Messages/s": 0})
        self.pairs = [(a, "gs1") for a in self.ac] + [(a, "gs2") for a in self.ac]
        self.user = None
        self.seen = {"gs1": {}, "gs2": {}}
        self.cnt = 0
        for i, k in enumerate(self.ac):
            self.every(0.5, self.squit_pos, 0.05 + 0.083 * i, 0.04, k)
            self.every(0.5, self.squit_vel, 0.3 + 0.071 * i, 0.04, k)
            self.every(5.0, self.squit_id, 0.2 + 0.7 * i, 0.2, k)
        self.every(1.0, self.move, 0.5)

    def latlon(self, nid):
        n = self.by[nid]
        lat = self.lat0 - n.my / 111120.0
        return lat, self.lon0 + n.mx / (111120.0 * math.cos(math.radians(lat)))

    def move(self):
        for k, a in self.ac.items():
            n = self.by[k]
            d = a["gs"] * 0.5144
            n.mx += d * math.sin(math.radians(a["trk"]))
            n.my -= d * math.cos(math.radians(a["trk"]))
            if not (5000 < n.mx < self.map_m - 5000 and 5000 < n.my < 170000):
                a["trk"] = (a["trk"] + 180) % 360
        for g in ("gs1", "gs2"):
            live = [k for k, t in self.seen[g].items() if self.t - t < 10]
            self.by[g].vars["Tracks"] = len(live)
            self.by[g].vars["Messages/s"] = self.cnt
        self.cnt = 0

    def df17(self, k, me_fn, title):
        a = self.ac[k]
        icao = a["icao"]
        if self.fault["dup"] and k == "ac4":
            icao = self.ac["ac2"]["icao"]
        fb = FieldBits()
        fb.add("DF (downlink format)", 5, 17, "17 extended squitter", "")
        fb.add("CA (capability)", 3, 5, "5 (level 2+, airborne)", "")
        fb.add("ICAO aircraft address", 24, icao, "%06X" % icao, "Unique 24-bit address assigned to the airframe")
        me_fn(fb)
        pi = ms_crc(fb.bits)
        fb.add("PI (parity)", 24, pi, "%06X [correct]" % pi, "CRC-24 (generator 0x1FFF409) over the first 88 bits")
        return fb, icao

    def squit(self, k, fb, info, kind="data"):
        if not self.by[k].on:
            return
        self.cnt += 1
        err = None
        heard = []
        for g in ("gs1", "gs2"):
            if g == "gs1" and self.fault["gs1"]:
                continue
            if self.radio_model.ok(k, g):
                heard.append(g)
        if self.fault["fruit"] and self.rng.random() < 0.25:
            err = "FRUIT: another squitter overlapped this one - CRC fails at the receiver"
            heard = []
        if not heard and err is None:
            err = "Not received by any ground station (range / antenna)"
        for g in heard:
            self.seen[g][k] = self.t
        p = fb.pdu("Mode S extended squitter (DF17) - %s" % info.split(":")[0], "1090 MHz, PPM 1 Mbit/s")
        bits = list(fb.bits)
        rssi = max(self.radio_model.rssi(k, g) for g in ("gs1", "gs2"))
        self.tx(rf_frame(self, k, heard or None, "ADS-B", info, p, 120e-6, 1090.0, 2.6, kind=kind, err=err, rssi=int(rssi),
                         wirefn=lambda f, b=bits, fb=fb: ppm_wire(b, labels=ppm_labels(fb)), key="DF17 %s %s" % (self.ac[k]["cs"], info.split(":")[0]), sd=fb.f[2][3]), bus="air")

    @staticmethod
    def pos_fields(fb, lat, lon, alt, odd):
        fb.add("TC (type code)", 5, 11, "11 (airborne position, baro altitude, NIC 8)", "Type code 9-18: position with barometric altitude")
        fb.add("Surveillance status", 2, 0, "0 (no condition)", "")
        fb.add("NIC supplement-B", 1, 0, "0", "")
        fb.raw("Altitude", ac12(alt), "%d ft (Q bit = 1, 25 ft steps)" % alt, "12 bits: 11-bit N plus the Q bit (8th bit); altitude = 25 N - 1000 ft")
        fb.add("Time", 1, 0, "0 (not UTC synchronised)", "")
        yz, xz = cpr_encode(lat, lon, odd)
        fb.add("CPR format", 1, odd, "%d (%s)" % (odd, "odd" if odd else "even"), "Even and odd frames use 60 and 59 latitude zones")
        fb.add("CPR latitude", 17, yz, "%d  (true %.5f deg)" % (yz, lat), "Position within the latitude zone, 2^17 steps")
        fb.add("CPR longitude", 17, xz, "%d  (true %.5f deg)" % (xz, lon), "Position within the longitude zone (NL zones at this latitude)")

    @staticmethod
    def id_fields(fb, cs, light):
        fb.add("TC (type code)", 5, 4, "4 (identification, category set A)", "")
        fb.add("Emitter category", 3, 1 if light else 3, "light" if light else "large", "")
        fb.raw("Call sign", six_text(cs.upper().ljust(8)[:8], 8), '"%s"' % cs.upper()[:8], "8 characters, 6 bits each (A-Z = 1-26, space = 32, 0-9 = 48-57)")

    def squit_pos(self, k):
        a = self.ac[k]
        lat, lon = self.latlon(k)
        nogps = self.fault["gps"] and k == "ac3"
        a["odd"] ^= 1
        odd = a["odd"]

        def me(fb):
            if nogps:
                fb.add("TC (type code)", 5, 0, "0 (no position information)", "Position unavailable: only barometric altitude is sent")
                fb.add("Surveillance status", 2, 0, "0", "")
                fb.add("NIC supplement", 1, 0, "0", "")
                fb.raw("Altitude", ac12(a["alt"]), "%d ft (Q bit = 1, 25 ft steps)" % a["alt"], "")
                fb.add("Unused", 36, 0, "", "")
                return
            self.pos_fields(fb, lat, lon, a["alt"], odd)
        fb, icao = self.df17(k, me, "pos")
        self.squit(k, fb, ("Airborne position %s: NO GNSS (TC 0), %d ft" % (a["cs"], a["alt"])) if nogps else
                  ("Airborne position %s %s: %d ft, %.4f %.4f" % (a["cs"], "odd" if odd else "even", a["alt"], lat, lon)))
        if nogps:
            for g in ("gs1", "gs2"):
                self.seen[g].pop(k, None)

    def squit_vel(self, k):
        a = self.ac[k]
        vew = a["gs"] * math.sin(math.radians(a["trk"]))
        vns = a["gs"] * math.cos(math.radians(a["trk"]))

        def me(fb):
            fb.add("TC (type code)", 5, 19, "19 (airborne velocity)", "")
            fb.add("Subtype", 3, 1, "1 (ground speed, subsonic)", "")
            fb.add("Intent change", 1, 0, "0", "")
            fb.add("IFR capability", 1, 0, "0", "")
            fb.add("NACv", 3, 2, "2 (< 3 m/s)", "Navigation accuracy category, velocity")
            fb.add("E-W direction", 1, 1 if vew < 0 else 0, "west" if vew < 0 else "east", "")
            fb.add("E-W velocity", 10, int(abs(vew)) + 1, "%d kt" % int(abs(vew)), "Value + 1 (0 = not available)")
            fb.add("N-S direction", 1, 1 if vns < 0 else 0, "south" if vns < 0 else "north", "")
            fb.add("N-S velocity", 10, int(abs(vns)) + 1, "%d kt" % int(abs(vns)), "")
            fb.add("Vertical rate source", 1, 1, "baro", "")
            fb.add("Vertical rate sign", 1, 0, "up", "")
            fb.add("Vertical rate", 9, 1, "0 ft/min", "(value - 1) x 64 ft/min")
            fb.add("Reserved", 2, 0, "", "")
            fb.add("GNSS - baro sign", 1, 0, "", "")
            fb.add("GNSS - baro difference", 7, 5, "100 ft", "(value - 1) x 25 ft")
        fb, icao = self.df17(k, me, "vel")
        self.squit(k, fb, "Airborne velocity %s: %d kt, track %d" % (a["cs"], a["gs"], a["trk"]))

    def squit_id(self, k):
        a = self.ac[k]

        def me(fb):
            self.id_fields(fb, a["cs"], "C172" in self.by[k].label)
        fb, icao = self.df17(k, me, "id")
        self.squit(k, fb, "Identification %s" % a["cs"], "ctl")

    def tpls(self):
        return [Tpl("Encode airborne position", [P("lat", "Latitude", 52.2572, -85.0, 85.0, 0.01), P("lon", "Longitude", 3.91937, -180.0, 180.0, 0.01),
                                                 P("alt", "Altitude (ft)", 38000, -1000, 50000, 100), P("fmt", "CPR format", "even", opts=["even", "odd"])],
                    lambda s, v, send: self._pos(v, send), "Aircraft 1 squitters a DF17 airborne position with your values: see the 12-bit altitude and the 17-bit CPR fields. "
                                                            "52.2572 / 3.91937 / 38000 ft even reproduces a well-known test message (CPR 93000 / 51372)."),
                Tpl("Identification", [P("cs", "Call sign", "TEST123")], lambda s, v, send: self._ident(v, send), "Aircraft 1 broadcasts a new call sign (8 characters of 6 bits).")]

    def _pos(self, v, send):
        odd = 1 if v["fmt"] == "odd" else 0
        fb, icao = self.df17("ac1", lambda fb: self.pos_fields(fb, v["lat"], v["lon"], v["alt"], odd), "pos")
        info = "Airborne position %s %s: %d ft, %.4f %.4f (composed)" % (self.ac["ac1"]["cs"], v["fmt"], v["alt"], v["lat"], v["lon"])
        if not send:
            return Frame(self.t, 120e-6, "ac1", None, "ADS-B", info, pdu=fb.pdu("Mode S extended squitter (DF17) - airborne position"),
                         wirefn=lambda f, b=list(fb.bits), fb=fb: ppm_wire(b, labels=ppm_labels(fb)), sd="%06X" % icao)
        self.squit("ac1", fb, info)
        return None

    def _ident(self, v, send):
        cs = "".join(c for c in v["cs"].upper() if c.isalnum() or c == " ")[:8] or "TEST"
        fb, icao = self.df17("ac1", lambda fb: self.id_fields(fb, cs, False), "id")
        if not send:
            return Frame(self.t, 120e-6, "ac1", None, "ADS-B", "Identification %s (composed)" % cs, pdu=fb.pdu("Mode S extended squitter (DF17) - identification"),
                         wirefn=lambda f, b=list(fb.bits), fb=fb: ppm_wire(b, labels=ppm_labels(fb)), sd="%06X" % icao)
        self.ac["ac1"]["cs"] = cs
        self.squit("ac1", fb, "Identification %s" % cs, "ctl")
        return None

    def links(self):
        out = []
        for a, b in self.pairs:
            if self.by[a].on and self.by[b].on and not (b == "gs1" and self.fault["gs1"]):
                out.append((a, b, int(round(self.radio_model.margin(a, b)))))
        return out


# ================================================================== Mode S
BDS60 = "BDS 6,0 heading and speed"


class ModeS(RfNet):
    key, name, cat = "modes", "Mode S", "aero"
    blurb = "Secondary surveillance radar"
    f_mhz, ptx, sens, n_exp = 1060.0, 57.0, -80.0, 2.0
    map_size = 400000.0
    map_grid = 50000.0
    band = {"f0": 1025.0, "f1": 1095.0, "unit": "MHz", "chans": [("1030 up", 1030.0, 4.0), ("1090 down", 1090.0, 2.6)]}
    medium = "Mode S secondary surveillance radar: interrogations on 1030 MHz from a rotating antenna (4.8 s per scan), transponder replies on 1090 MHz"
    faults = [("stby", "Aircraft 2 transponder in STANDBY", "No replies at all: the aircraft is invisible to the SSR (only a primary radar would see it)."),
              ("alt", "Aircraft 1 altitude encoder failed", "Altitude replies carry AC = 0 (no altitude): the controller sees no flight level."),
              ("lock", "Interrogator II code not accepted (no lockout)", "The aircraft keeps answering all-call interrogations every scan, adding needless replies (FRUIT).")]
    spec = [("Standards", "ICAO Annex 10 Vol IV, EUROCAE ED-73 (transponder), ED-117"),
            ("Uplink", "1030 MHz: P1-P2 pulses then a P6 DPSK block of 56 or 112 bits (4 Mbit/s)"),
            ("Downlink", "1090 MHz: 8 us preamble + 56 or 112 bits PPM at 1 Mbit/s"),
            ("Formats", "UF4/5 surveillance (altitude / identity), UF11 all-call, UF20/21 Comm-A; DF4/5, DF11, DF17, DF20/21 Comm-B"),
            ("Selective", "Each aircraft has a unique 24-bit address; roll-call interrogations go to one aircraft only; all-call lockout"),
            ("EHS", "Enhanced surveillance reads BDS registers via Comm-B: 4,0 selected altitude, 5,0 track and turn, 6,0 heading and speed")]
    frame = [["DF4 altitude reply (56 bits)", ("DF=4", 5), ("FS", 3), ("DR", 5), ("UM", 6), ("AC altitude code", 13), ("AP (address/parity)", 24)]]
    about = ("Secondary surveillance radar asks, aircraft answer. Classic Mode A/C replies to everyone, which garbles in busy airspace; Mode S gives "
             "every aircraft a unique 24-bit address so the radar can interrogate one aircraft at a time ('roll-call') as its beam sweeps past. "
             "After an all-call has found an aircraft, it is locked out of further all-calls. The radar can also read data registers (BDS) from "
             "the aircraft's computers - selected altitude, heading, speeds.")
    guide = ["Watch the beam sweep: interrogations and replies come in bursts as it passes each aircraft.",
             "Decode a DF4 reply: the 13-bit altitude code with the Q bit.",
             "Find a DF20 Comm-B reply carrying BDS 6,0 (heading and speed).",
             "Put aircraft 2's transponder in standby."]

    def setup(self):
        self.radio_model = MarineRadio(self, self.f_mhz, self.ptx, self.sens, self.n_exp)
        r = self.rnode("ssr", "MODE S RADAR", "radar", 200000, 90000, "SI 3", "4.8 s per scan", w=110)
        r.extra.update(h=30.0)
        self.ac = {}
        for nid, lab, icao, alt, sq, x, y, hdg in (("a1", "BAW123", 0x4CA2D1, 36000, 0o2741, 80000, 50000, 95), ("a2", "EZY45", 0x4007F3, 34000, 0o5214, 320000, 70000, 250),
                                                   ("a3", "RYR8YK", 0x4CA8E4, 24000, 0o1000, 230000, 160000, 20)):
            n = self.rnode(nid, lab, "plane", x, y, "%06X" % icao, "squawk %04o" % sq, w=104)
            n.extra.update(h=alt * FT)
            self.ac[nid] = dict(icao=icao, alt=alt, sq=sq, hdg=hdg, locked=False, last=-9.0)
            n.vars.update({"Seen by radar": "-", "Lockout": "no"})
        r.vars.update({"Beam azimuth": "0", "Tracks": 0})
        self.pairs = [(a, "ssr") for a in self.ac]
        self.every(0.05, self.sweep, 0.0)
        self.every(2.4, self.allcall, 0.3)

    def az(self, nid):
        a, r = self.by[nid], self.by["ssr"]
        return math.degrees(math.atan2(a.mx - r.mx, -(a.my - r.my))) % 360

    def beam(self):
        return (self.t * 360.0 / 4.8) % 360

    def up(self, uf, fields, info, dst, kind="cmd", send=True):
        fb = FieldBits()
        fb.add("UF (uplink format)", 5, uf, str(uf), "")
        for f in fields:
            fb.add(*f)
        pi = ms_crc(fb.bits)
        icao = self.ac[dst]["icao"] if dst in self.ac else 0xFFFFFF
        fb.add("AP (address / parity)", 24, pi ^ icao, "%06X (parity XOR address %06X)" % (pi ^ icao, icao), "Only the addressed transponder finds a zero remainder")
        p = fb.pdu("Mode S interrogation UF%d" % uf, "1030 MHz, P6 DPSK")
        n = len(fb.bits)
        dur = (16.25 if n == 56 else 30.25) * 1e-6 + 3.5e-6
        fr = rf_frame(self, "ssr", dst, "Mode S", info, p, dur, 1030.0, 4.0, kind=kind, rssi=-30,
                      wirefn=lambda f, d=dur: burst_wire(d, seed=n, label="P1 P2 + P6 DPSK (%d bits)" % n), key="UF%d" % uf,
                      dd=("%06X" % icao) if dst in self.ac else None)
        if send:
            self.tx(fr, bus="up")
        return fr

    def down(self, k, df, fields, info, kind="resp", pi_xor=True, ii=None):
        a = self.ac[k]
        fb = FieldBits()
        fb.add("DF (downlink format)", 5, df, str(df), "")
        for f in fields:
            fb.add(*f)
        pi = ms_crc(fb.bits)
        if ii is not None:
            fb.add("PI (parity / interrogator ID)", 24, pi ^ ii, "%06X (parity XOR II code %d)" % (pi ^ ii, ii),
                   "All-call replies overlay the interrogator identifier on the parity, so each radar recognises its own replies")
        else:
            fb.add("AP (address / parity)", 24, pi ^ (a["icao"] if pi_xor else 0), "%06X" % (pi ^ (a["icao"] if pi_xor else 0)),
                   "Parity XOR the aircraft address: the radar recovers the address from the remainder")
        p = fb.pdu("Mode S reply DF%d from %06X" % (df, a["icao"]), "1090 MHz, PPM")
        bits = list(fb.bits)
        n = len(bits)
        rssi = self.radio_model.rssi(k, "ssr")
        self.tx(rf_frame(self, k, "ssr", "Mode S", info, p, (8 + n) * 1e-6, 1090.0, 2.6, kind=kind, rssi=int(rssi),
                         wirefn=lambda f, b=bits, fb=fb: ppm_wire(b, labels=ppm_labels(fb)), key="DF%d %06X" % (df, a["icao"]), sd="%06X" % a["icao"]), bus="down:" + k)

    def sweep(self):
        bz = self.beam()
        self.by["ssr"].vars["Beam azimuth"] = "%.0f deg" % bz
        for k, a in self.ac.items():
            d = (self.az(k) - bz + 540) % 360 - 180
            if abs(d) > 2.5 or self.t - a["last"] < 1.0 or not a["locked"]:
                continue
            a["last"] = self.t
            self.roll_call(k)

    REQS = ["UF4 altitude", "UF5 identity (squawk)", "UF20 BDS 2,0 call sign", "UF20 BDS 4,0 selected altitude", "UF20 BDS 6,0 heading and speed"]

    @staticmethod
    def id13(sq):
        a, b, c, d = (sq >> 9) & 7, (sq >> 6) & 7, (sq >> 3) & 7, sq & 7
        return [c & 1, a & 1, (c >> 1) & 1, (a >> 1) & 1, (c >> 2) & 1, (a >> 2) & 1, 0, b & 1, d & 1, (b >> 1) & 1, (d >> 1) & 1, (b >> 2) & 1, (d >> 2) & 1]

    def ac_bits(self, k):
        a = self.ac[k]
        return ac13(a["alt"]) if not (self.fault["alt"] and k == "a1") else [0] * 13

    def mb(self, k, bds):
        a = self.ac[k]
        if bds == 0x20:
            bits = bits_of(0x20, 8) + six_text(self.by[k].label.ljust(8)[:8], 8)
            return bits, '"%s"' % self.by[k].label, "BDS 2,0 aircraft identification: 8 x 6-bit characters"
        if bds == 0x40:
            sel = a.get("sel", a["alt"])
            bits = [1] + bits_of(sel // 16, 12) + [1] + bits_of(sel // 16, 12) + [1] + bits_of(int(round((1013.2 - 800) / 0.1)), 12) + \
                [0] * 8 + [1, 1, 0, 0] + [0, 0] + [1] + [1, 1]
            return bits, "MCP/FCU %d ft, FMS %d ft, QNH 1013.2 hPa" % (sel, sel), "BDS 4,0 selected vertical intention: selected altitudes (16 ft), baro setting (0.1 hPa)"
        hdg = a["hdg"]
        bits = [1, 0 if hdg < 180 else 1] + bits_of(int((hdg if hdg < 180 else hdg - 360) / (90 / 512.0)) & 0x3FF, 10) + [1] + bits_of(280, 10) + [1] + \
            bits_of(int(0.78 * 1000 / 4), 10) + [1, 0] + bits_of(0, 9) + [1, 0] + bits_of(0, 9)
        return bits, "heading %d, IAS 280 kt, Mach 0.78" % hdg, "BDS 6,0 heading and speed: magnetic heading, IAS, Mach, vertical rates"

    def interrogate(self, k, req, send=True):
        """One roll-call interrogation of aircraft k and (if send) its reply 128 us later."""
        a = self.ac[k]
        alt_txt = lambda: ("%d ft" % a["alt"]) if any(self.ac_bits(k)) else "NO ALTITUDE"
        if req.startswith("UF4"):
            fr = self.up(4, [("PC", 3, 0, "0"), ("RR", 5, 0, "0 (short reply)"), ("DI", 3, 0, "0"), ("SD", 16, 0, "0")],
                         "UF4 surveillance altitude request -> %06X" % a["icao"], k, send=send)

            def rep():
                acb = self.ac_bits(k)
                self.down(k, 4, [("FS (flight status)", 3, 0, "0 airborne, no alert"), ("DR", 5, 0, "0"), ("UM", 6, 0, "0"),
                                 ("AC (altitude code)", 13, bits_to_int(acb), ("%d ft" % a["alt"]) if any(acb) else "0 = altitude not available", "M bit 0, Q bit 1: 25 ft steps")],
                          "DF4 altitude reply %06X: %s" % (a["icao"], alt_txt()))
        elif req.startswith("UF5"):
            fr = self.up(5, [("PC", 3, 0, "0"), ("RR", 5, 0, "0 (short reply)"), ("DI", 3, 0, "0"), ("SD", 16, 0, "0")],
                         "UF5 surveillance identity request -> %06X" % a["icao"], k, send=send)

            def rep():
                self.down(k, 5, [("FS (flight status)", 3, 0, "0 airborne, no alert"), ("DR", 5, 0, "0"), ("UM", 6, 0, "0"),
                                 ("ID (identity code)", 13, bits_to_int(self.id13(a["sq"])), "squawk %04o" % a["sq"], "Mode A code bits C1 A1 C2 A2 C4 A4 X B1 D1 B2 D2 B4 D4")],
                          "DF5 identity reply %06X: squawk %04o" % (a["icao"], a["sq"]))
        else:
            bds = {"2": 0x20, "4": 0x40}.get(req.split("BDS ")[1][0], 0x60)
            rr = 16 + (bds >> 4)
            name = req.split("UF20 ")[1]
            fr = self.up(20, [("PC", 3, 0, "0"), ("RR", 5, rr, "%d: Comm-B, BDS1 = %d" % (rr, bds >> 4)), ("DI", 3, 7, "7 (extended SD)"), ("SD", 16, 0x3000, "IIS 3, RRS 0 (BDS2 = 0)"),
                                  ("MA", 56, 0, "0 (no Comm-A message)")], "UF20 Comm-B request %s -> %06X" % (name, a["icao"]), k, send=send)

            def rep():
                bits, txt, desc = self.mb(k, bds)
                acb = self.ac_bits(k)
                self.down(k, 20, [("FS", 3, 0, "0"), ("DR", 5, 0, "0"), ("UM", 6, 0, "0"), ("AC", 13, bits_to_int(acb), alt_txt()),
                                  ("MB (%s)" % name.split(" ")[0] + " " + name.split(" ")[1], 56, bits_to_int(bits), txt, desc)],
                          "DF20 Comm-B %06X: %s (%s)" % (a["icao"], name, txt))
        if not send:
            return fr
        if not (self.fault["stby"] and k == "a2"):
            self.at(self.t + 0.000128, rep)
        return fr

    def roll_call(self, k):
        if self.fault["stby"] and k == "a2":
            self.interrogate(k, "UF4")
            self.by[k].vars["Seen by radar"] = "NO REPLY (transponder standby)"
            return
        self.interrogate(k, "UF4 altitude")
        self.at(self.t + 0.0003, self.interrogate, k, self.REQS[2 + int(self.t / 4.8) % 3])
        if int(self.t / 4.8) % 4 == 0:
            self.at(self.t + 0.0006, self.interrogate, k, "UF5 identity")
        self.by[k].vars["Seen by radar"] = "t = %.1f s, az %.0f" % (self.t, self.az(k))

    def tpls(self):
        return [Tpl("Interrogate aircraft", [P("ac", "Aircraft", "a1", opts=["a1", "a2", "a3"], fmt=lambda v: "%s %06X" % (self.by[v].label, self.ac[v]["icao"])),
                                             P("rq", "Request", self.REQS[0], opts=self.REQS)],
                    lambda s, v, send: self.interrogate(v["ac"], v["rq"], send), "Selective (roll-call) interrogation on 1030 MHz; the transponder answers on 1090 MHz 128 us later."),
                Tpl("Set selected altitude", [P("ac", "Aircraft", "a1", opts=["a1", "a2", "a3"], fmt=lambda v: self.by[v].label), P("alt", "Selected altitude (ft)", 38000, 0, 45000, 1000)],
                    lambda s, v, send: self._sel(v, send), "The crew dials a new altitude on the MCP: the radar sees it in BDS 4,0.")]

    def _sel(self, v, send):
        if send:
            self.ac[v["ac"]]["sel"] = int(v["alt"])
            self.log("%s crew selects %d ft (visible in BDS 4,0)" % (self.by[v["ac"]].label, v["alt"]))
            return None
        return self.interrogate(v["ac"], self.REQS[3], False)

    def allcall(self):
        self.up(11, [("PR", 4, 0, "0"), ("IC", 4, 3, "II code 3"), ("CL", 3, 0, "0"), ("Spare", 16, 0, "")], "UF11 Mode S-only all-call (II 3)", None, "bcast")
        for k, a in self.ac.items():
            if self.fault["stby"] and k == "a2":
                continue
            if a["locked"] and not self.fault["lock"]:
                continue
            fresh = not a["locked"]
            a["locked"] = True
            self.by[k].vars["Lockout"] = "no (fault)" if self.fault["lock"] else "locked out by II 3"
            self.at(self.t + 0.00013 + 0.00002 * int(k[1]), lambda k=k, a=a, fresh=fresh: self.down(k, 11, [("CA", 3, 5, "5"), ("AA (address)", 24, a["icao"], "%06X" % a["icao"])],
                                                                                                   "DF11 all-call reply %06X%s" % (a["icao"], " - acquired" if fresh else " (should be locked out)"),
                                                                                                   "ctl", ii=3))
        self.by["ssr"].vars["Tracks"] = sum(1 for a in self.ac.values() if a["locked"])

    def on_fault(self, key, on):
        if key == "stby":
            self.ac["a2"]["locked"] = False if on else self.ac["a2"]["locked"]


# =================================================================== ACARS
def acars_bits(chars):
    out = []
    for c in chars:
        v = c & 0x7F
        out += lsb(v, 7) + [odd_parity(v, 7)]
    return out


class ACARS(RfNet):
    key, name, cat = "acars", "ACARS", "aero"
    blurb = "Airline data communications"
    f_mhz, ptx, sens, n_exp = 131.55, 44.0, -95.0, 2.0
    map_size = 500000.0
    map_grid = 50000.0
    band = {"f0": 131.50, "f1": 131.60, "unit": "MHz", "chans": [("131.550 ACARS", 131.55, 0.025)]}
    medium = "Plain old ACARS on VHF 131.550 MHz: 2400 bit/s MSK on AM, character blocks with label and technical acknowledgement; ground stations relay to the airline host"
    faults = [("lost", "Ground station misses a downlink", "No technical acknowledgement: the aircraft repeats the block after its timeout."),
              ("busy", "Channel congestion", "Carrier sense finds the frequency busy; transmissions are delayed."),
              ("range", "Aircraft 2 out of VHF coverage", "Its messages reach no ground station (it would switch to SATCOM or VDL in reality).")]
    spec = [("Standards", "ARINC 618 (air-ground character protocol), ARINC 620 (ground network), ARINC 619/622; VDL Mode 2 and SATCOM carry it too"),
            ("Radio", "VHF AM, 131.550 MHz primary worldwide; 2400 bit/s MSK (1200 / 2400 Hz audio tones)"),
            ("Block", "Bit / char sync, SOH, mode, aircraft registration (7), technical acknowledgement, label (2), block ID, STX, text, ETX, BCS (CRC-16), DEL"),
            ("Characters", "7-bit ASCII with odd parity"),
            ("Access", "CSMA on a shared channel; every block is acknowledged in the next uplink (technical ack = block ID)"),
            ("Labels", "Q0 link test, SQ squitter, H1 crew messages, _d general response ...")]
    frame = [["ACARS block", ("Sync + SOH", 40), ("Mode", 8), ("Registration", 56), ("Ack", 8), ("Label", 16), ("Block ID", 8), ("STX", 8), ("Text", "n x 8"), ("ETX", 8), ("BCS", 16), ("DEL", 8)]]
    about = ("ACARS has carried airline messages - position reports, OOOI times, weather, free text - since 1978. A block of 7-bit characters is "
             "sent at 2400 bit/s on a shared VHF channel; ground stations forward it to the airline's host. Every block carries a label that says "
             "what it is, and the reply carries a technical acknowledgement that names the block it confirms.")
    guide = ["Watch a ground station squitter (label SQ) and the aircraft's link test (Q0).",
             "Select a downlink: registration, label, block ID, then the message text and the BCS.",
             "Find the acknowledgement in the next uplink.",
             "Make the ground station miss a block and watch the retransmission."]

    def setup(self):
        self.lat0, self.lon0 = 52.0, -2.0
        for nid, lab, x, y, h in (("gs1", "VHF STATION LONDON", 150000, 120000, 50.0), ("gs2", "VHF STATION MANCHESTER", 330000, 40000, 50.0)):
            n = self.rnode(nid, lab, "tower", x, y, "", "131.550", w=120)
            n.extra.update(h=h)
            n.vars.update({"Blocks received": 0})
        self.planes = {}
        for nid, lab, reg, fl, x, y in (("p1", "G-EUUA A320", ".G-EUUA", "BA0456", 100000, 60000), ("p2", "G-JZHA B738", ".G-JZHA", "LS0811", 420000, 150000)):
            n = self.rnode(nid, lab, "plane", x, y, reg.strip("."), fl, w=110)
            n.extra.update(h=10000.0)
            self.planes[nid] = dict(reg=reg, fl=fl, blk=0, msn=0, pending=None)
            n.vars.update({"Last message": "-", "Unacknowledged": 0})
        self.pairs = [(p, g) for p in self.planes for g in ("gs1", "gs2")]
        self.user = "p1"
        self.every(10.0, self.squitter, 0.5)
        self.every(15.0, lambda: self.downlink("p1", "H1", "REQ WX EGLL EGCC"), 2.0)
        self.every(20.0, lambda: self.downlink("p2", "Q0", ""), 4.0)

    def block(self, mode, reg, ack, label, bid, text, down=True, msn="", flt=""):
        body = [0x01] + list(mode.encode()) + list(reg.rjust(7, ".").encode()) + [ack] + list(label.encode()) + [ord(bid)] + [0x02]
        body += list((msn + flt + text).encode())
        body += [0x03]
        bcs = crcn("CRC-16/KERMIT", bytes(b & 0x7F for b in body[1:]))
        allc = [0x2B, 0x2A, 0x16, 0x16] + body + [bcs & 255, bcs >> 8, 0x7F]
        b = Bld("ACARS %s block, label %s" % ("downlink" if down else "uplink", label), "ARINC 618 character-oriented block")
        b.raw("Bit/char sync", bytes([0x2B, 0x2A, 0x16, 0x16]), "+ * SYN SYN", "Pre-key, bit sync and character sync")
        b.u8("SOH", 0x01, None, "")
        b.text("Mode", mode, "Mode character ('2' = category A, any ground station)")
        b.text("Aircraft registration", reg.rjust(7, "."), "7 characters, padded with dots")
        b.u8("Technical acknowledgement", ack, ("NAK (0x15): nothing to acknowledge" if ack == 0x15 else "'%s': acknowledges block %s" % (chr(ack), chr(ack))), "")
        b.text("Label", label, {"Q0": "link test", "SQ": "ground station squitter", "H1": "crew / printer message", "_\x7f": "general response (ack only)"}.get(label, ""))
        b.text("Block identifier", bid, "Downlink 0-9, uplink A-Z / a-z")
        b.u8("STX", 0x02, None, "")
        if down and (msn or flt):
            b.text("Message sequence number", msn, "")
            b.text("Flight identifier", flt, "")
        if text:
            b.text("Text", text, "Free text / application data")
        b.u8("ETX", 0x03, None, "End of the last block of the message (ETB = more blocks follow)")
        b.u16("BCS", bcs, "0x%04X [correct]" % bcs, "Block check sequence: CRC-16 (CCITT) over mode..ETX", little=True)
        b.u8("DEL", 0x7F, None, "")
        return b.done(), allc

    def send(self, src, dst, p, chars, info, kind, err=None, fwd=None):
        bits = acars_bits(chars)
        dur = len(bits) / 2400.0
        rssi = self.radio_model.rssi(src, dst if isinstance(dst, str) else "gs1")
        fr = rf_frame(self, src, dst, "ACARS", info, p, dur, 131.55, 0.025, kind=kind, err=err, rssi=int(rssi),
                      wirefn=lambda f, b=bits: fsk_wire(b[:240], 2400, 0.6, lead=8, gauss=0.5), key=info.split(":")[0])
        start = self.t + (float(self.rng.random()) * 1.5 if self.fault["busy"] else 0.0)
        self.tx(fr, bus="vhf", ifs=0.05, start=start)
        return fr

    def squitter(self):
        for g, code, pos in (("gs1", "LHREGLL", "05128N00027W"), ("gs2", "MANEGCC", "05321N00216W")):
            p, ch = self.block("2", ".......", 0x15, "SQ", "A", "02XA" + code + pos, down=False)
            self.send(g, None, p, ch, "Uplink squitter SQ from ground station %s" % code[:3], "bcast")

    def downlink(self, pid, label, text, retry=0):
        pl = self.planes[pid]
        if not self.by[pid].on:
            return
        pl["blk"] = pl["blk"] % 9 + 1
        pl["msn"] = (pl["msn"] + 1) % 100
        bid = str(pl["blk"])
        p, ch = self.block("2", pl["reg"], 0x15, label, bid, text, True, "M%02dA" % pl["msn"], pl["fl"])
        gs = [g for g in ("gs1", "gs2") if self.radio_model.ok(pid, g)] if not (self.fault["range"] and pid == "p2") else []
        lost = self.fault["lost"] and retry == 0
        err = "Not received by a ground station" if not gs else ("Missed by the ground station (no technical ack will come)" if lost else None)
        fr = self.send(pid, gs[0] if gs else None, p, ch, "Downlink %s label %s block %s: %s%s" % (pl["reg"].strip("."), label, bid, text or "(link test)",
                                                                                                       " [retransmission]" if retry else ""), "data", err)
        self.by[pid].vars["Last message"] = "%s %s" % (label, text)
        if err:
            self.by[pid].vars["Unacknowledged"] += 1
            if retry < 2:
                self.at(fr.t + fr.dur + 4.0, self.downlink, pid, label, text, retry + 1)
            return
        g = gs[0]
        self.by[g].vars["Blocks received"] += 1
        reply_text = "EGLL 141150Z 24012KT 9999 FEW030 12/06 Q1018" if label == "H1" else ""
        lab = "H1" if label == "H1" else "_\x7f"

        def ack():
            p2, ch2 = self.block("2", pl["reg"], ord(bid), lab, "B", reply_text, down=False)
            self.send(g, pid, p2, ch2, "Uplink to %s: ack block %s%s" % (pl["reg"].strip("."), bid, (", " + reply_text) if reply_text else " (general response)"), "resp")
        self.at(fr.t + fr.dur + 1.2, ack)

    def tpls(self):
        return [Tpl("Crew message (H1)", [P("txt", "Text", "REQ GATE NUMBER")], lambda s, v, send: self._crew(v["txt"], send), "Free-text downlink from aircraft 1."),
                Tpl("Link test (Q0)", [], lambda s, v, send: self._q0(send), "Aircraft 1 tests the data link.")]

    def _crew(self, txt, send):
        if not send:
            pl = self.planes["p1"]
            p, ch = self.block("2", pl["reg"], 0x15, "H1", "1", txt.upper(), True, "M01A", pl["fl"])
            return Frame(self.t, 0.3, "p1", "gs1", "ACARS", "preview", pdu=p)
        self.downlink("p1", "H1", txt.upper())
        return None

    def _q0(self, send):
        if not send:
            pl = self.planes["p1"]
            p, ch = self.block("2", pl["reg"], 0x15, "Q0", "1", "", True, "M01A", pl["fl"])
            return Frame(self.t, 0.2, "p1", "gs1", "ACARS", "preview", pdu=p)
        self.downlink("p1", "Q0", "")
        return None


# =================================================================== CPDLC
CPDLC_UM = {20: "CLIMB TO [level]", 23: "DESCEND TO [level]", 74: "PROCEED DIRECT TO [position]", 117: "CONTACT [unit] [frequency]", 120: "MONITOR [unit] [frequency]",
            169: "[free text]"}
CPDLC_DM = {0: "WILCO", 1: "UNABLE", 2: "STANDBY", 3: "ROGER", 6: "REQUEST [level]"}


class CPDLC(RfNet):
    key, name, cat = "cpdlc", "CPDLC", "aero"
    blurb = "Air traffic control data link"
    f_mhz, ptx, sens, n_exp = 136.975, 44.0, -95.0, 2.0
    map_size = 400000.0
    map_grid = 50000.0
    band = {"f0": 136.9, "f1": 137.05, "unit": "MHz", "chans": [("VDL2 136.975", 136.975, 0.025)]}
    medium = "CPDLC (ATN B1 over VDL Mode 2, 31.5 kbit/s D8PSK): controller and pilot exchange standard message elements instead of voice; logon, connection, WILCO/UNABLE responses"
    faults = [("logon", "Flight ID in the FMS does not match the flight plan", "The ground system rejects the logon: no CPDLC connection."),
              ("slow", "Crew does not respond", "The message times out on the ground (e.g. 100 s): the controller reverts to voice."),
              ("link", "VDL Mode 2 link lost", "Uplinks are not delivered; the connection is eventually terminated.")]
    spec = [("Standards", "ICAO Doc 4444 / Doc 10037 (GOLD), EUROCAE ED-110B / RTCA DO-280B (ATN B1, Europe 'LINK 2000+'), FANS-1/A (DO-258A) over ACARS oceanic"),
            ("Link", "VDL Mode 2 (D8PSK, 31.5 kbit/s, AVLC) or SATCOM / HF; FANS-1/A rides on ACARS"),
            ("Sequence", "Logon (CM / AFN) with flight ID and address, connection request / confirm, then messages"),
            ("Messages", "Uplink elements (UM20 CLIMB TO, UM74 DIRECT TO, UM117 CONTACT...) and downlink elements (DM0 WILCO, DM1 UNABLE, DM2 STANDBY...)"),
            ("Dialogue", "Message identification number (MIN) and reference number (MRN) pair responses with requests; logical acknowledgements")]
    frame = [["CPDLC message", ("MIN", 8), ("MRN", 8), ("Timestamp", 24), ("Element ID", 16), ("Parameters", "n")]]
    about = ("CPDLC replaces routine radio calls with text messages from a fixed catalogue: the controller sends 'CLIMB TO FL360', the pilot "
             "answers WILCO with one button. Each message has a number (MIN) and responses refer to it (MRN), so there is no ambiguity about what "
             "was answered. Before any of that, the aircraft logs on with its flight ID and the ground opens a CPDLC connection.")
    guide = ["Follow the logon, connection request and connection confirm.",
             "Select an uplink: element UM20 with its level parameter and MIN.",
             "COMPOSE the pilot's WILCO or UNABLE: see the MRN refer to the uplink.",
             "Inject a wrong flight ID and watch the logon fail."]

    def setup(self):
        self.lat0, self.lon0 = 51.0, -1.0
        g = self.rnode("vgs", "VDL2 GROUND STATION", "tower", 180000, 100000, "", "", w=120)
        g.extra.update(h=40.0)
        atc = self.rnode("atc", "ATC CENTRE (via ground net)", "server", 340000, 40000, "LECC", "controller", w=140)
        atc.extra.update(h=40.0)
        ac = self.rnode("ac", "EZY45 A319", "plane", 90000, 140000, "4007F3", "FL340", w=110)
        ac.extra.update(h=10400.0)
        self.pairs = [("ac", "vgs")]
        self.user = "ac"
        self.min = 0
        self.state = "not logged on"
        self.pending = None
        ac.vars.update({"CPDLC": "not connected", "Last uplink": "-"})
        atc.vars.update({"Connection": "-", "Open dialogues": 0})
        self.at(0.5, self.logon)
        self.every(20.0, self.clearance, 6.0)

    def msg(self, src, dst, up, elem, txt, mrn=None, info=None, kind="cmd", err=None):
        self.min = (self.min + 1) % 64
        b = Bld("CPDLC %s message (ATN B1, simplified PER view)" % ("uplink" if up else "downlink"), "Carried in AVLC frames over VDL Mode 2")
        b.u8("MIN (message identification number)", self.min, None, "")
        if mrn is not None:
            b.u8("MRN (message reference number)", mrn, None, "Which uplink this answers")
        b.raw("Timestamp", bytes([12, 0, int(self.t) % 60]), "12:00:%02d" % (int(self.t) % 60), "")
        b.u16("Message element", elem, "%s%d %s" % ("UM" if up else "DM", elem, (CPDLC_UM if up else CPDLC_DM).get(elem, "")), "")
        b.text("Element text", txt, "As displayed to the pilot / controller")
        rssi = self.radio_model.rssi("ac", "vgs")
        hop = "ac" if src == "ac" else "vgs"
        self.tx(rf_frame(self, hop, dst, "CPDLC", info or "%s %s%d %s" % ("UPLINK" if up else "DOWNLINK", "UM" if up else "DM", elem, txt), b.done(), 0.012, 136.975, 0.025,
                         kind=kind, err=err, rssi=int(rssi), wirefn=lambda f: burst_wire(0.012, seed=elem, label="VDL2 D8PSK burst")), bus="vdl")
        return self.min

    def logon(self):
        ac = self.by["ac"]
        bad = self.fault["logon"]
        b = Bld("CM logon request (context management)", "Tells the ground system who the aircraft is")
        b.text("Flight ID", "EZY45X" if bad else "EZY45", "Must match the filed flight plan")
        b.raw("Aircraft address", bytes.fromhex("4007F3"), "4007F3", "")
        b.text("Departure / destination", "EGKK LEMD", "")
        self.tx(rf_frame(self, "ac", "atc", "CPDLC", "CM logon request: flight %s, address 4007F3" % ("EZY45X" if bad else "EZY45"), b.done(), 0.01, 136.975, 0.025, kind="ctl", rssi=-60,
                         wirefn=lambda f: burst_wire(0.01, seed=1, label="VDL2 burst")), bus="vdl")
        if bad:
            self.at(self.t + 1.0, lambda: self.tx(rf_frame(self, "vgs", "ac", "CPDLC", "CM logon response: REJECTED (flight ID not found in flight plans)", Bld("CM logon response").done(), 0.008,
                                                           136.975, 0.025, kind="err", err="Logon rejected", rssi=-60, wirefn=lambda f: burst_wire(0.008, seed=2)), bus="vdl"))
            ac.vars["CPDLC"] = "LOGON REJECTED"
            return
        self.at(self.t + 1.0, lambda: self.tx(rf_frame(self, "vgs", "ac", "CPDLC", "CM logon response: accepted (LECC)", Bld("CM logon response").done(), 0.008, 136.975, 0.025,
                                                       kind="resp", rssi=-60, wirefn=lambda f: burst_wire(0.008, seed=3)), bus="vdl"))
        self.at(self.t + 2.0, lambda: self.tx(rf_frame(self, "vgs", "ac", "CPDLC", "CPDLC start request (connection) from LECC", Bld("CPDLC-start request").done(), 0.008, 136.975, 0.025,
                                                       kind="ctl", rssi=-60, wirefn=lambda f: burst_wire(0.008, seed=4)), bus="vdl"))
        self.at(self.t + 2.5, lambda: self.tx(rf_frame(self, "ac", "atc", "CPDLC", "CPDLC start confirm: connection established", Bld("CPDLC-start confirm").done(), 0.008, 136.975, 0.025,
                                                       kind="resp", rssi=-60, wirefn=lambda f: burst_wire(0.008, seed=5)), bus="vdl"))
        self.at(self.t + 2.6, self._connected)

    def _connected(self):
        self.state = "connected"
        self.by["ac"].vars["CPDLC"] = "CONNECTED to LECC (current data authority)"
        self.by["atc"].vars["Connection"] = "EZY45 connected"

    def clearance(self):
        if self.state != "connected":
            return
        lvl = 360 if int(self.t / 20) % 2 else 340
        err = "VDL2 link lost: not delivered" if self.fault["link"] else None
        m = self.msg("atc", "ac", True, 20, "CLIMB TO FL%d" % lvl, kind="cmd", err=err)
        self.pending = (m, lvl)
        self.by["atc"].vars["Open dialogues"] = 1
        self.by["ac"].vars["Last uplink"] = "UM20 CLIMB TO FL%d (MIN %d)" % (lvl, m)
        if err:
            return
        if not self.fault["slow"]:
            self.at(self.t + 4.0, self.respond, 0)
        else:
            self.at(self.t + 10.0, lambda: self.log("Uplink MIN %d not answered: controller will revert to voice after the timeout" % m))

    def respond(self, dm, send=True):
        if not send:
            b = Bld("CPDLC downlink (preview)")
            b.u16("Message element", dm, "DM%d %s" % (dm, CPDLC_DM.get(dm, "")), "")
            return Frame(self.t, 0.01, "ac", "atc", "CPDLC", "preview", pdu=b.done())
        if not self.pending or self.state != "connected":
            return None
        m, lvl = self.pending
        self.msg("ac", "atc", False, dm, CPDLC_DM.get(dm, ""), mrn=m, info="DOWNLINK DM%d %s (MRN %d -> CLIMB TO FL%d)" % (dm, CPDLC_DM.get(dm, ""), m, lvl), kind="resp")
        if dm in (0, 1, 3):
            self.pending = None
            self.by["atc"].vars["Open dialogues"] = 0
        if dm == 0:
            self.by["ac"].sub = "FL%d" % lvl
        return None

    def on_fault(self, key, on):
        if key == "logon" and not on and self.state != "connected":
            self.at(self.t + 0.5, self.logon)

    def tpls(self):
        return [Tpl("Pilot response", [P("dm", "Response", 0, opts=[0, 1, 2, 3], fmt=lambda v: "DM%d %s" % (v, CPDLC_DM[v]))], lambda s, v, send: self.respond(v["dm"], send),
                    "Answer the open uplink. WILCO, UNABLE and ROGER close the dialogue; STANDBY keeps it open.")]


# ================================================================= ASTERIX
def fspec(frns):
    n = max(frns)
    nbytes = (n + 6) // 7
    out = bytearray(nbytes)
    for f in frns:
        i, bit = (f - 1) // 7, (f - 1) % 7
        out[i] |= 0x80 >> bit
    for i in range(nbytes - 1):
        out[i] |= 0x01
    return bytes(out)


class ASTERIX(IpNet):
    key, name, cat = "asterix", "ASTERIX", "aero"
    blurb = "Air traffic surveillance data"
    medium = "EUROCONTROL ASTERIX over UDP multicast: a Mode S radar head sends CAT034 service messages and CAT048 target reports, the tracker sends CAT062 system tracks to the ATC displays"
    faults = [("sic", "Second radar configured with the same SAC/SIC", "Two sources claim the same identity: the tracker mixes their plots."),
              ("tod", "Radar clock not synchronised", "Time of day in I048/140 lags by 2.5 s: plots are placed wrongly in time."),
              ("north", "North marker messages missing", "Without CAT034 the tracker cannot confirm the radar is alive and rotating: it is flagged as failed.")]
    spec = [("Standard", "EUROCONTROL ASTERIX (All-purpose Structured EUROCONTROL Surveillance Information Exchange)"),
            ("Block", "CAT (1 byte) + LEN (2 bytes) + records; each record = FSPEC + data items in UAP order"),
            ("FSPEC", "One bit per field reference number (FRN), 7 per byte, LSB = FX (another FSPEC byte follows)"),
            ("Categories", "001/002 radar (old), 034 monoradar service messages, 048 monoradar target reports, 021 ADS-B, 062 system tracks, 010 surface, 020 MLAT"),
            ("CAT048 items", "I048/010 SAC/SIC, /140 time of day (1/128 s), /020 target report descriptor, /040 polar position, /070 Mode 3/A, /090 flight level, "
                             "/220 aircraft address, /240 identification, /161 track number ..."),
            ("Transport", "UDP multicast (or legacy X.25 / HDLC)")]
    frame = [["ASTERIX data block", ("CAT", 8), ("LEN", 16), ("FSPEC", "n x 8"), ("Data items (UAP order)", "n x 8")]]
    about = ("ASTERIX is the common language between radars, trackers and air traffic control displays in Europe and far beyond. Every data block "
             "names its category (for example 048 = monoradar target reports) and its length; each record starts with a field specification bitmap "
             "saying which data items follow, so senders only include what they have.")
    guide = ["Select a CAT048 record: decode the FSPEC bits and match them to the data items.",
             "Read SAC/SIC, time of day, polar position (range and azimuth), Mode 3/A code and flight level.",
             "Watch the CAT034 north marker once per antenna revolution.",
             "Compare a CAT048 plot with the CAT062 system track built from it."]

    def setup(self):
        hosts = [("rdr", "MODE S RADAR HEAD", "radar", 40, 40, "10.20.1.10", "00:0a:35:01:00:10", "SAC 8 SIC 1"),
                 ("rdr2", "SECOND RADAR", "radar", 40, 290, "10.20.1.11", "00:0a:35:01:00:11", "SAC 8 SIC 2"),
                 ("trk", "MULTI-RADAR TRACKER", "server", 700, 40, "10.20.1.20", "00:0a:35:01:00:20", "SAC 8 SIC 100"),
                 ("cwp", "CONTROLLER DISPLAY", "display", 700, 290, "10.20.1.30", "00:0a:35:01:00:30")]
        self.star(hosts, sw=("sw", "SURVEILLANCE LAN", 380, 160), style="cat6", conn="rj45")
        self.tgts = [dict(addr=0x4CA2D1, cs="BAW123", sq=0o2741, fl=360, rho=42.0, theta=95.0, trk=1201), dict(addr=0x4007F3, cs="EZY45", sq=0o5214, fl=340, rho=67.5, theta=210.0, trk=1202),
                     dict(addr=0x484506, cs="KLM1234", sq=0o1307, fl=380, rho=88.0, theta=320.0, trk=1203)]
        self.user = "rdr"
        self.by["trk"].vars.update({"Radars": "SIC 1, SIC 2", "Tracks": 3})
        self.by["cwp"].vars.update({"Displayed tracks": 3, "Radar status": "OK"})
        self.every(4.0, self.north, 0.1)
        self.every(4.0 / 8, self.sector, 0.6)
        self.every(4.0, self.tracks, 2.0)
        self.every(4.0, lambda: self.cat048_burst("rdr2", 2), 1.3)

    def tod(self):
        t = 12 * 3600 + self.t - (2.5 if self.fault["tod"] else 0.0)
        return int(t * 128) & 0xFFFFFF

    def block(self, cat, records, title):
        b = Bld("ASTERIX CAT%03d: %s" % (cat, title), "EUROCONTROL ASTERIX data block")
        n = 3 + sum(len(r.b) for r in records)
        b.u8("CAT", cat, "%03d" % cat, "Category")
        b.u16("LEN", n, None, "Length of the whole data block")
        for r in records:
            b.sub(r)
        return b.done()

    def send(self, src, cat, records, title, info, kind="data"):
        p = self.block(cat, records, title)
        self.lan.udp(src, None, 8600, 8600 + cat, p, info, "ASTERIX", kind, dip="232.1.1.%d" % (cat % 256), dmac="01:00:5e:01:01:%02x" % (cat % 256))

    def north(self):
        if self.fault["north"]:
            self.by["cwp"].vars["Radar status"] = "RADAR SIC 1 FAILED (no north marker)"
            return
        self.by["cwp"].vars["Radar status"] = "OK"
        r = Bld("CAT034 record: north marker")
        r.raw("FSPEC", fspec([1, 2, 3, 5]), "FRN 1, 2, 3, 5", "Which items are present")
        r.raw("I034/010 Data source identifier", bytes([8, 1]), "SAC 8, SIC 1", "")
        r.u8("I034/000 Message type", 1, "1 north marker", "Once per antenna revolution")
        r.u24("I034/030 Time of day", self.tod(), "%.3f s" % (self.tod() / 128.0), "1/128 s since midnight")
        r.u16("I034/041 Antenna rotation period", int(4.0 * 128), "4.000 s", "1/128 s")
        self.send("rdr", 34, [r.done()], "monoradar service message", "CAT034 north marker, SAC 8 SIC 1, rotation 4.0 s", "sync")

    def sector(self):
        if self.fault["north"]:
            return
        k = int((self.t % 4.0) / 0.5)
        r = Bld("CAT034 record: sector crossing")
        r.raw("FSPEC", fspec([1, 2, 3, 4]), "FRN 1-4", "")
        r.raw("I034/010 Data source identifier", bytes([8, 1]), "SAC 8, SIC 1", "")
        r.u8("I034/000 Message type", 2, "2 sector crossing", "")
        r.u24("I034/030 Time of day", self.tod(), "%.3f s" % (self.tod() / 128.0), "")
        r.u8("I034/020 Sector number", k * 32, "%d deg" % (k * 45), "360/256 deg per unit")
        self.send("rdr", 34, [r.done()], "monoradar service message", "CAT034 sector %d (%d deg)" % (k, k * 45), "sync")
        az = k * 45
        recs = []
        for tg in self.tgts:
            if az <= tg["theta"] < az + 45:
                recs.append(self.rec048(tg, 1))
        if recs:
            self.send("rdr", 48, recs, "monoradar target reports", "CAT048 %d plot(s) in sector %d: %s" % (len(recs), k, ", ".join(t["cs"] for t in self.tgts if az <= t["theta"] < az + 45)))

    def cat048_burst(self, src, sic):
        recs = [self.rec048(tg, sic) for tg in self.tgts]
        sic_shown = 1 if self.fault["sic"] else sic
        self.send(src, 48, recs, "monoradar target reports", "CAT048 %d plots from radar SAC 8 SIC %d%s" % (len(recs), sic_shown, " (DUPLICATE SAC/SIC!)" if self.fault["sic"] else ""))

    def rec048(self, tg, sic):
        if self.fault["sic"]:
            sic = 1
        r = Bld("CAT048 record: %s" % tg["cs"])
        r.raw("FSPEC", fspec([1, 2, 3, 4, 5, 6, 8, 9, 11]), "FRN 1-6, 8, 9, 11", "Bit = item present; LSB of each byte = FX (extension)")
        r.raw("I048/010 Data source identifier", bytes([8, sic]), "SAC 8, SIC %d" % sic, "System area code / system identification code")
        r.u24("I048/140 Time of day", self.tod(), "%.3f s" % (self.tod() / 128.0), "1/128 s")
        r.u8("I048/020 Target report descriptor", 0xA0, "TYP 5: single Mode S roll-call", "")
        rho = int(tg["rho"] * 256)
        th = int(tg["theta"] / 360 * 65536)
        r.raw("I048/040 Measured position (polar)", struct.pack(">HH", rho, th), "RHO %.2f NM, THETA %.2f deg" % (tg["rho"], tg["theta"]), "RHO 1/256 NM, THETA 360/2^16 deg")
        r.u16("I048/070 Mode-3/A code", tg["sq"], "%04o (V G L = 0)" % tg["sq"], "Octal squawk")
        r.u16("I048/090 Flight level", tg["fl"] * 4, "FL%d" % tg["fl"], "1/4 FL")
        r.u24("I048/220 Aircraft address", tg["addr"], "%06X" % tg["addr"], "Mode S address")
        r.raw("I048/240 Aircraft identification", pack_bits(six_text(tg["cs"].ljust(8), 8)), '"%s"' % tg["cs"], "8 characters x 6 bits")
        r.u16("I048/161 Track number", tg["trk"] & 0xFFF, None, "")
        return r.done()

    def tracks(self):
        recs = []
        for tg in self.tgts:
            r = Bld("CAT062 record: system track %d" % tg["trk"])
            r.raw("FSPEC", fspec([1, 4, 5, 9, 10, 12]), "FRN 1, 4, 5, 9, 10, 12", "")
            r.raw("I062/010 Data source identifier", bytes([8, 100]), "SAC 8, SIC 100 (tracker)", "")
            r.u24("I062/070 Time of track information", self.tod(), "%.3f s" % (self.tod() / 128.0), "")
            lat = int((51.0 + tg["rho"] / 60 * math.cos(math.radians(tg["theta"]))) / (180.0 / 2 ** 25))
            lon = int((-1.0 + tg["rho"] / 60 * math.sin(math.radians(tg["theta"]))) / (180.0 / 2 ** 25))
            r.raw("I062/105 Calculated position WGS-84", struct.pack(">ii", lat, lon), "%.5f, %.5f" % (lat * 180.0 / 2 ** 25, lon * 180.0 / 2 ** 25), "180/2^25 deg")
            r.u16("I062/060 Track mode 3/A code", tg["sq"], "%04o" % tg["sq"], "")
            r.raw("I062/245 Target identification", bytes([0]) + pack_bits(six_text(tg["cs"].ljust(8), 8)), '"%s"' % tg["cs"], "")
            r.u16("I062/040 Track number", tg["trk"], None, "")
            recs.append(r.done())
        self.send("trk", 62, recs, "system track data", "CAT062 %d system tracks" % len(recs))
        for tg in self.tgts:
            tg["theta"] = (tg["theta"] + 0.6) % 360

    def tpls(self):
        return [Tpl("CAT048 target report", [P("sic", "Radar SIC", 1, 1, 2), P("rho", "Range (NM)", 55.0, 0.5, 250.0, 0.5), P("theta", "Azimuth (deg)", 135.0, 0.0, 359.9, 1.0),
                                             P("sq", "Mode 3/A (octal)", "7000"), P("fl", "Flight level", 120, 0, 600, 10), P("cs", "Call sign", "TEST01")],
                    lambda s, v, send: self._plot(v, send), "One CAT048 record from the chosen radar: watch the FSPEC and each data item. Squawk 7700 = emergency.")]

    def _plot(self, v, send):
        try:
            sq = int(v["sq"], 8) & 0xFFF
        except ValueError:
            sq = 0o7000
        tg = dict(addr=0x400ABC, cs=v["cs"].upper()[:8], sq=sq, fl=int(v["fl"]), rho=float(v["rho"]), theta=float(v["theta"]), trk=1300)
        rec = self.rec048(tg, int(v["sic"]))
        if not send:
            return Frame(self.t, 1e-4, "rdr" if v["sic"] == 1 else "rdr2", None, "ASTERIX", "preview", pdu=self.block(48, [rec], "monoradar target reports"))
        self.send("rdr" if v["sic"] == 1 else "rdr2", 48, [rec], "monoradar target reports",
                  "CAT048 plot %s squawk %04o FL%d at %.1f NM / %.1f deg" % (tg["cs"], sq, tg["fl"], tg["rho"], tg["theta"]))
        return None


# ================================================================ SpaceWire
SPW_CTRL = {0: "FCT", 1: "EOP", 2: "EEP", 3: "ESC"}


def spw_chars(items):
    """items: ('d', byte) | ('c', code) -> list of (bits, label). Odd parity over the previous char's data + this flag."""
    out = []
    prev_data = []
    for kind, v in items:
        flag = 0 if kind == "d" else 1
        data = lsb(v, 8) if kind == "d" else msb(v, 2)
        p = 1 if (sum(prev_data) + flag) % 2 == 0 else 0
        out.append(([p, flag] + data, ("%02X" % v) if kind == "d" else SPW_CTRL[v]))
        prev_data = data
    return out


def spw_wire(items, tb):
    w = Wire(bit=tb)
    d = s = 0
    w.set("D", 0.0, 0)
    w.set("S", 0.0, 0)
    t = 2 * tb
    for k, (bits, lab) in enumerate(spw_chars(items)):
        t0 = t
        for b in bits:
            if b != d:
                d = b
                w.set("D", t, d)
            else:
                s ^= 1
                w.set("S", t, s)
            t += tb
        w.seg(t0, t, lab, k % 2 if len(bits) == 10 else 7, 0)
    w.end(t + 2 * tb)
    return w


def rmap_crc(data):
    return crc(bytes(data), 8, 0x07, 0x00, True, True, 0x00)


class SpaceWire(Scenario):
    key, name, cat = "spacewire", "SpaceWire", "aero"
    blurb = "Spacecraft data handling"
    phy, rate = "spw", 100e6
    medium = "SpaceWire (ECSS-E-ST-50-12C): LVDS data-strobe links at 100 Mbit/s through a router; the on-board computer reads and writes instruments with RMAP"
    nets = [("D", "Data line (LVDS)"), ("S", "Strobe line (LVDS)")]
    lines = ["D", "S"]
    faults = [("disc", "Camera link cable disconnected", "No transitions for 850 ns: both ends detect a disconnect, reset and re-initialise the link (NULLs, FCTs)."),
              ("par", "Parity error on the mass-memory link", "The receiver detects it, the link is reset and the packet is terminated with EEP (error end of packet)."),
              ("credit", "Router port 3 output blocked", "Wormhole routing: the packet to the GNSS receiver stalls and blocks the path behind it.")]
    spec = [("Standard", "ECSS-E-ST-50-12C SpaceWire; ECSS-E-ST-50-52C RMAP; used by ESA, NASA, JAXA missions"),
            ("Physical", "Full-duplex point-to-point links, LVDS, data-strobe (DS) encoding: S toggles when D does not, so D XOR S is the clock; 2-400 Mbit/s"),
            ("Characters", "Data: parity + flag 0 + 8 bits (LSB first); control: parity + flag 1 + 2 bits (FCT, EOP, EEP, ESC); NULL = ESC FCT; time-code = ESC + data"),
            ("Flow control", "Each FCT gives the sender credit for 8 more data characters"),
            ("Packets", "Destination address (path: router port numbers, or logical address 32-254), cargo, EOP; wormhole routing"),
            ("RMAP", "Remote memory access: write / read commands with header CRC-8 and data CRC-8, replies")]
    frame = [["Data character", ("P", 1), ("Flag 0", 1), ("Data bits 0-7", 8)], ["Control character", ("P", 1), ("Flag 1", 1), ("Code", 2)]]
    about = ("SpaceWire links the computers and instruments of a spacecraft. Each link is a pair of LVDS lines in each direction: Data and Strobe, "
             "where Strobe changes whenever Data does not - so every bit has exactly one edge and the receiver recovers the clock. Packets are routed "
             "through routers by the address bytes at their front, and the Remote Memory Access Protocol lets the on-board computer read and write "
             "registers in any instrument.")
    guide = ["LOGIC: D and S - exactly one of them changes in every bit period.",
             "Find NULL characters (ESC + FCT) on an idle link and the FCTs that grant credit.",
             "Select an RMAP write command: target address, instruction, key, address, length, header CRC.",
             "Disconnect the camera and watch the link re-initialisation sequence."]

    def build(self):
        obc = self.node("obc", "ON-BOARD COMPUTER", "ecu", 40, 150, "LA 0xFE", "RMAP initiator").at_right()
        rt = self.node("rtr", "SPACEWIRE ROUTER", "switch", 360, 140, "", "8 ports", w=130, h=70)
        cam = self.node("cam", "CAMERA", "camera", 700, 30, "LA 0x20", "port 2")
        mm = self.node("mm", "MASS MEMORY", "store", 700, 150, "LA 0x21", "port 1")
        gn = self.node("gnss", "GNSS RECEIVER", "gps", 700, 280, "LA 0x22", "port 3")
        rt.port = (425, 175)
        self.seg([obc.port, (360, 176)], "spw", net="D", label="link 0", c0="mil", c1="mil")
        self.seg([(360, 176), (425, 175)], "spw", w=1, col=(30, 30, 34))
        for n, y, lab in ((cam, 56, "port 2"), (mm, 176, "port 1"), (gn, 306, "port 3")):
            n.at_left()
            self.seg([(490, 176 if y == 176 else (160 if y < 176 else 190)), (600, 176 if y == 176 else (160 if y < 176 else 190)), (600, y), n.port], "spw", net="D", label=lab, c0="mil", c1="mil")
            self.seg([(425, 175), (490, 176 if y == 176 else (160 if y < 176 else 190))], "spw", w=1, col=(30, 30, 34))
        self.tid = 0
        self.tick = 0
        self.user = "obc"
        cam.vars.update({"Link": "Run", "Images": 0})
        mm.vars.update({"Link": "Run", "Bytes stored": 0})
        gn.vars.update({"Link": "Run"})
        obc.vars.update({"RMAP replies": 0, "Errors": 0})
        self.every(0.0156, self.timecode, 0.001)
        self.every(0.2, self.cycle, 0.02)

    def pkt(self, src, dst, items, info, pdu, kind="data", err=None):
        tb = 1 / self.rate
        n = sum(10 if k == "d" else 4 for k, _ in items)
        fr = Frame(self.t, n * tb + 4 * tb, src, dst, "SpaceWire", info, pdu=pdu, kind=kind, err=err, wirefn=lambda f, it=items[:40]: spw_wire(it, tb), key=info.split(":")[0])
        return self.tx(fr, bus="link:%s" % (src if src != "obc" else (dst or "all")))

    def timecode(self):
        self.tick = (self.tick + 1) & 63
        b = Bld("SpaceWire time-code", "ESC + data character, distributed by the routers to every node")
        b.u8("Time-code", self.tick, "time %d, control flags 00" % self.tick, "6-bit time counter + 2 control flags")
        self.pkt("obc", None, [("c", 3), ("d", self.tick)], "Time-code %d (ESC + data)" % self.tick, b.done(), "sync")

    def rmap(self, dst, write, addr, data=b"", length=0):
        la = int(self.by[dst].addr.split()[-1], 16)
        port = {"cam": 2, "mm": 1, "gnss": 3}[dst]
        self.tid = (self.tid + 1) & 0xFFFF
        instr = 0x40 | (0x20 if write else 0) | (0x08) | (0x04)
        hdr = bytes([la, 0x01, instr, 0x00, 0xFE]) + struct.pack(">H", self.tid) + bytes([0x00]) + struct.pack(">I", addr) + (len(data) if write else length).to_bytes(3, "big")
        hcrc = rmap_crc(hdr)
        b = Bld("SpaceWire packet: RMAP %s command" % ("write" if write else "read"), "")
        b.u8("Path address", port, "router output port %d" % port, "Consumed by the router (path addressing)")
        b.u8("Target logical address", la, "0x%02X" % la, "")
        b.u8("Protocol ID", 0x01, "0x01 RMAP", "")
        b.u8("Instruction", instr, "command, %s, verify 0, reply, increment" % ("write" if write else "read"), "")
        b.u8("Key", 0x00, None, "Must match the target's key")
        b.u8("Initiator logical address", 0xFE, "0xFE (OBC)", "")
        b.u16("Transaction ID", self.tid, None, "Matches the reply to the command")
        b.u8("Extended address", 0, None, "")
        b.u32("Address", addr, "0x%08X" % addr, "Memory address in the target")
        b.u24("Data length", len(data) if write else length, None, "")
        b.u8("Header CRC", hcrc, "0x%02X [correct]" % hcrc, "CRC-8 (x^8 + x^2 + x + 1)")
        if write:
            b.raw("Data", data, None, "")
            b.u8("Data CRC", rmap_crc(data), "0x%02X" % rmap_crc(data), "")
        p = b.done()
        items = [("d", x) for x in p.b] + [("c", 1)]
        return p, items, port

    def reply(self, src, tid, write, data=b""):
        la = int(self.by[src].addr.split()[-1], 16)
        instr = 0x2C if write else 0x0C
        hdr = bytes([0xFE, 0x01, instr, 0x00, la]) + struct.pack(">H", tid)
        if not write:
            hdr += bytes([0x00]) + len(data).to_bytes(3, "big")
        r = Bld("SpaceWire packet: RMAP %s reply" % ("write" if write else "read"), "")
        r.u8("Initiator logical address", 0xFE, None, "Reply goes back to the OBC")
        r.u8("Protocol ID", 1, "0x01 RMAP", "")
        r.u8("Instruction", instr, "reply, %s, reply, increment" % ("write" if write else "read"), "Command bit cleared")
        r.u8("Status", 0, "0 command executed OK", "")
        r.u8("Target logical address", la, "0x%02X" % la, "")
        r.u16("Transaction ID", tid, None, "Same TID as the command")
        if not write:
            r.u8("Reserved", 0, None, "")
            r.u24("Data length", len(data), None, "")
        r.u8("Header CRC", rmap_crc(hdr), "0x%02X [correct]" % rmap_crc(hdr), "")
        if not write:
            r.raw("Data", data, None, "")
            r.u8("Data CRC", rmap_crc(data), "0x%02X" % rmap_crc(data), "")
        rp = r.done()
        self.pkt(src, "obc", [("d", x) for x in rp.b] + [("c", 1)], "RMAP %s reply <- %s (TID %d, status 0)" % ("write" if write else "read", self.by[src].label.lower(), tid), rp, "resp")
        self.by["obc"].vars["RMAP replies"] += 1

    def cycle(self):
        mm, cam, gn = self.by["mm"], self.by["cam"], self.by["gnss"]
        if self.fault["disc"]:
            cam.vars["Link"] = "Disconnected -> ErrorReset -> ErrorWait -> Ready -> Started -> Connecting -> Run"
            b = Bld("Link initialisation", "")
            b.note("Disconnect detected (no transition for 850 ns); link restarts sending NULLs then FCTs", "", d=1)
            self.pkt("obc", "cam", [("c", 3), ("c", 0)] * 4 + [("c", 0)] * 3, "Link 2 re-initialisation: NULL NULL NULL NULL FCT FCT FCT", b.done(), "ctl",
                     err="Link disconnect: packet in transit lost (EEP)")
        else:
            cam.vars["Link"] = "Run"
        p, items, port = self.rmap("cam", False, 0x00010000, length=16)
        self.pkt("obc", "cam", items, "RMAP read command -> camera 0x20, 16 bytes @0x00010000 (TID %d)" % self.tid, p, "cmd")
        if not self.fault["disc"]:
            self.reply("cam", self.tid, False, bytes(range(16)))
            cam.vars["Images"] += 1
        data = bytes((i * 3 + self.tid) & 255 for i in range(32))
        p, items, port = self.rmap("mm", True, 0x20000000 + self.tid * 32, data)
        err = None
        if self.fault["par"] and self.rng.random() < 0.5:
            err = "Parity error: link reset, packet ended with EEP"
            items = items[:12] + [("c", 2)]
            self.by["obc"].vars["Errors"] += 1
        self.pkt("obc", "mm", items, "RMAP write command -> mass memory 0x21, 32 bytes (TID %d)" % self.tid, p, "cmd", err)
        if not err:
            mm.vars["Bytes stored"] += 32
            self.reply("mm", self.tid, True)
        if self.fault["credit"]:
            gn.vars["Link"] = "port 3 output blocked: packet stalled in the router (wormhole)"
            return
        gn.vars["Link"] = "Run"
        p, items, port = self.rmap("gnss", False, 0x00000040, length=8)
        self.pkt("obc", "gnss", items, "RMAP read command -> GNSS 0x22, position (TID %d)" % self.tid, p, "cmd")
        self.reply("gnss", self.tid, False, struct.pack(">ii", int(51.48 * 1e6), int(-0.01 * 1e6)))

    def tpls(self):
        return [Tpl("RMAP write to mass memory", [P("addr", "Address", 0x20000100, 0, 0x7FFFFFFF), P("d", "Data (hex)", "DE AD BE EF")], lambda s, v, send: self._w(v, send),
                    "Command packet routed via port 1; the target replies (reply bit set).")]

    def _w(self, v, send):
        try:
            data = bytes.fromhex(v["d"].replace(" ", ""))[:64]
        except ValueError:
            data = b"\x00"
        p, items, port = self.rmap("mm", True, v["addr"], data)
        if not send:
            return Frame(self.t, 1e-6, "obc", "mm", "SpaceWire", "preview", pdu=p, wirefn=lambda f: spw_wire(items[:40], 1e-8))
        self.pkt("obc", "mm", items, "RMAP write command -> mass memory, %d bytes" % len(data), p, "cmd")
        self.by["mm"].vars["Bytes stored"] += len(data)
        return None


# =============================================================== SpaceFibre
class SpaceFibre(Scenario):
    key, name, cat = "spacefibre", "SpaceFibre", "aero"
    blurb = "High-speed spacecraft networking"
    phy, rate = "cml", 2.5e9
    medium = "SpaceFibre (ECSS-E-ST-50-11C): multi-Gbit/s serial links (8b/10b) over copper or fibre; virtual channels with QoS, link-level retry; SAR instrument -> mass memory"
    nets = [("LANE", "lane 0 serial signal (CML)")]
    lines = ["D"]
    faults = [("err", "Bit errors on the instrument link", "The receiver finds a CRC error and sends NACK: the transmitter retries from its retry buffer - nothing is lost."),
              ("lane", "Lane 1 of the 2-lane link fails", "Multi-lane links degrade gracefully: traffic continues at half the bandwidth on lane 0."),
              ("vc", "Mass memory stops granting credit on VC 1", "Virtual channel 1 stalls, VC 0 (housekeeping) keeps flowing - QoS separation.")]
    spec = [("Standard", "ECSS-E-ST-50-11C SpaceFibre (2019); compatible with SpaceWire packets"),
            ("Physical", "2.5 to 6.25 Gbit/s per lane, 8b/10b, CML copper or fibre; multi-lane links"),
            ("Data link", "Data frames of up to 64 words (256 bytes) per lane, sequence numbers and CRC-16; ACK / NACK and retry from a retry buffer"),
            ("Virtual channels", "Many VCs per link with priorities, bandwidth reservation and scheduling; FCTs give credit per VC"),
            ("Broadcast", "Short broadcast messages (e.g. time distribution) with low latency")]
    frame = [["Data frame", ("SDF (start)", 32), ("Data words (up to 64)", "n x 32"), ("EDF (end): CRC-16 + seq", 32)]]
    about = ("SpaceFibre is the very fast successor of SpaceWire: gigabits per second over a single lane of copper or fibre, with the same packet "
             "format above it. Underneath, a data link layer splits traffic into virtual channels with their own priority and bandwidth, numbers "
             "every frame and keeps a copy until it is acknowledged, so an error simply triggers a retry.")
    guide = ["Watch VC 1 (SAR science data) and VC 0 (housekeeping) frames interleave.",
             "Turn on bit errors: a NACK, then the retried frame with the same sequence number.",
             "Stop the credit on VC 1: VC 0 still flows."]

    def build(self):
        sar = self.node("sar", "SAR INSTRUMENT", "radar", 40, 150, "", "science data source").at_right()
        rtr = self.node("rtr", "SPACEFIBRE ROUTER", "switch", 360, 150, "", "", w=130).at_left()
        mm = self.node("mm", "MASS MEMORY", "store", 700, 60, "").at_left()
        obc = self.node("obc", "ON-BOARD COMPUTER", "ecu", 700, 260, "").at_left()
        self.seg([sar.port, rtr.port], "fiber", net="LANE", label="2-lane link", c0="lc", c1="lc")
        self.seg([(490, 176), (600, 176), (600, 86), mm.port], "fiber", net="LANE", c1="lc")
        self.seg([(600, 176), (600, 286), obc.port], "fiber", net="LANE", c1="lc")
        self.seg([rtr.port, (490, 176)], "fiber", w=1, col=(30, 30, 34))
        self.seq = 0
        self.user = None
        mm.vars.update({"VC1 frames": 0, "VC0 frames": 0, "Retries": 0})
        sar.vars.update({"Lanes": "2 x 3.125 Gbit/s"})
        self.every(0.01, self.data, 0.002)
        self.every(0.1, self.hk, 0.05)

    def frame_tx(self, src, dst, vc, words, info, kind="data", err=None, send=True):
        self.seq = (self.seq + 1) & 0xFF
        payload = bytes((self.seq * 7 + i) & 255 for i in range(min(words * 4, 64)))
        c = crcn("CRC-16/CCITT-FALSE", payload)
        b = Bld("SpaceFibre data frame, VC %d, sequence %d" % (vc, self.seq), "")
        b.raw("SDF (start of data frame)", bytes([0xBC, vc, 0x00, self.seq]), "VC %d" % vc, "Control word: comma symbol, then SDF type and virtual channel number (simplified)")
        b.raw("Data words", payload, "%d words (first %d bytes shown)" % (words, len(payload)), "")
        b.raw("EDF (end of data frame)", bytes([0xBC, 0x01]) + struct.pack(">H", c), "CRC-16 0x%04X, seq %d" % (c, self.seq), "Control word with its own K-code; the receiver checks CRC and sequence and answers ACK / NACK (simplified)")
        p = b.done()

        def wf(f, d=p.b):
            syms, rd = enc8b10b(bytes(d[:24]), k=(0, len(p.b) - 4) if len(p.b) > 4 else (0,))
            w = Wire(bit=1 / 2.5e9)
            t = 0.0
            for i, s_ in enumerate(syms):
                w.set("D", t, s_)
                t += 1 / 2.5e9
                if i % 10 == 9:
                    w.seg(t - 10 / 2.5e9, t, "%02X" % d[i // 10] if i // 10 < len(d) else "", (i // 10) % 2, 0)
            w.end(t)
            return w
        dur = (words + 2) * 4 * 10 / (3.125e9 * (1 if self.fault["lane"] else 2))
        fr = Frame(self.t, dur, src, dst, "SpaceFibre", info, pdu=p, kind=kind, err=err, wirefn=wf, key="VC %d" % vc)
        return self.tx(fr, bus="sf") if send else fr

    def data(self):
        mm = self.by["mm"]
        if self.fault["vc"]:
            return
        err = "CRC error at the receiver: NACK, retry from the retry buffer" if (self.fault["err"] and self.rng.random() < 0.2) else None
        fr = self.frame_tx("sar", "mm", 1, 64, "VC 1 SAR science data, 64 words, seq %d" % ((self.seq + 1) & 255), err=err)
        if err:
            b = Bld("SpaceFibre NACK", "")
            b.raw("NACK control word", bytes([0x1C, 0x02, 0x00, fr.pdu.b[3]]), "sequence %d" % fr.pdu.b[3], "")
            self.tx(Frame(self.t, 2e-9, "mm", "sar", "SpaceFibre", "NACK seq %d" % fr.pdu.b[3], pdu=b.done(), kind="err"), bus="sf")
            self.frame_tx("sar", "mm", 1, 64, "VC 1 SAR science data (RETRY of seq %d)" % fr.pdu.b[3], kind="resp")
            mm.vars["Retries"] += 1
        mm.vars["VC1 frames"] += 1

    def hk(self):
        self.frame_tx("obc", "mm", 0, 8, "VC 0 housekeeping, 8 words", kind="sync")
        self.by["mm"].vars["VC0 frames"] += 1

    def tpls(self):
        return [Tpl("Data frame", [P("src", "From", "obc", opts=["obc", "sar"], fmt=lambda v: self.by[v].label), P("vc", "Virtual channel", 2, 0, 31), P("w", "Data words", 16, 1, 64)],
                    lambda s, v, send: self._frm(v, send), "A data frame on the chosen virtual channel to the mass memory (SDF, data words, EDF with CRC-16).")]

    def _frm(self, v, send):
        if not send:
            seq = self.seq
            fr = self.frame_tx(v["src"], "mm", int(v["vc"]), int(v["w"]), "preview", send=False)
            self.seq = seq
            return fr
        self.frame_tx(v["src"], "mm", int(v["vc"]), int(v["w"]), "VC %d frame, %d words, seq %d (composed)" % (v["vc"], v["w"], (self.seq + 1) & 255))
        return None


# =================================================================== CCSDS
def bch_cltu(block7):
    """CCSDS BCH(63,56) code block: 7 data bytes + parity byte (complemented, filler bit 0)."""
    reg = 0
    for byte in block7:
        for k in range(7, -1, -1):
            fb = ((byte >> k) & 1) ^ ((reg >> 6) & 1)
            reg = ((reg << 1) & 0x7F)
            if fb:
                reg ^= 0x45
    return ((~reg & 0x7F) << 1) & 0xFE


class CCSDS(RfNet):
    key, name, cat = "ccsds", "CCSDS", "aero"
    blurb = "Space communication standards"
    f_mhz, ptx, sens, n_exp = 2200.0, 40.0, -125.0, 2.0
    map_size = 6000000.0
    map_grid = 500000.0
    band = {"f0": 2025.0, "f1": 2300.0, "unit": "MHz", "chans": [("TC uplink 2034", 2034.0, 1.0), ("TM downlink 2210", 2210.0, 2.0)]}
    medium = "CCSDS space link: ground station sends telecommands (TC frames in CLTUs) on S-band, spacecraft returns telemetry (TM frames with space packets, CLCW)"
    faults = [("lock", "TC frame sequence jump", "The spacecraft's FARM receives N(S) outside its window and enters LOCKOUT; the ground must send an Unlock control command."),
              ("fade", "Rain fade / low elevation", "TM frames fail Reed-Solomon decoding and are lost; the virtual channel frame counter shows the gap."),
              ("los", "Spacecraft below the horizon", "Loss of signal: no telemetry, telecommands cannot be delivered.")]
    spec = [("Standards", "CCSDS 133.0 (space packets), 132.0 (TM SDLP), 232.0 (TC SDLP), 231.0 (TC sync and coding), 131.0 (TM coding), 232.1 (COP-1); ECSS PUS on top"),
            ("Space packet", "6-byte header: version, type (TM/TC), secondary header flag, APID (11 bits), sequence flags + count, data length - 1"),
            ("TM frame", "ASM 1ACFFC1D + 6-byte header (SCID, VCID, MC and VC frame counters, first header pointer) + packets + OCF (CLCW) + CRC"),
            ("TC frame", "5-byte header (bypass, control command, SCID, VCID, length, sequence N(S)) + segment header + packet + CRC; carried in CLTUs (EB90, BCH(63,56) blocks, tail)"),
            ("COP-1", "FOP-1 on ground, FARM-1 on board: sequence-controlled delivery, retransmission, lockout / unlock; status in the CLCW"),
            ("PUS", "ECSS-E-ST-70-41C services: 17 test, 1 verification, 3 housekeeping, 5 events, 8 functions ...")]
    frame = [["Space packet", ("Ver", 3), ("Type", 1), ("SecHdr", 1), ("APID", 11), ("Seq flags", 2), ("Seq count", 14), ("Length", 16), ("Data", "n x 8")],
             ["TC transfer frame", ("Ver", 2), ("Bypass", 1), ("Ctrl", 1), ("Spare", 2), ("SCID", 10), ("VCID", 6), ("Length", 10), ("N(S)", 8), ("Data", "n"), ("FECF", 16)]]
    about = ("CCSDS standards are how almost every spacecraft talks to the ground. Applications exchange space packets identified by an APID; "
             "on the link, packets ride in fixed-length telemetry frames (with frame counters and an attached sync marker) or in telecommand "
             "frames wrapped in error-correcting CLTUs. A retransmission protocol (COP-1) makes sure every command arrives exactly once and in order, "
             "and reports its state in the CLCW of every telemetry frame.")
    guide = ["Select a TM frame: ASM, SCID, VCID, frame counters, the packet inside, the CLCW and the CRC.",
             "COMPOSE a TC(17,1) 'are you alive' and find the TM(17,2) response and TM(1,1)/(1,7) verification.",
             "Create a sequence gap: the CLCW shows lockout until you send Unlock.",
             "Move the spacecraft below the horizon (fault) and watch telemetry stop."]

    def setup(self):
        gs = self.rnode("gs", "GROUND STATION (13 m)", "ant", 1500000, 1800000, "", "S-band", w=130)
        gs.extra.update(h=20.0)
        sc = self.rnode("sc", "SPACECRAFT (LEO)", "sat", 1500000, 900000, "SCID 0x2A5", "700 km orbit", w=130)
        sc.extra.update(h=700000.0)
        self.pairs = [("sc", "gs")]
        self.user = "gs"
        self.mc = self.vc = 0
        self.ns = 0
        self.farm = {"vr": 0, "lockout": False, "retransmit": False}
        self.pkt_seq = {}
        sc.vars.update({"FARM V(R)": 0, "Lockout": "no", "Commands executed": 0})
        gs.vars.update({"TM frames": 0, "Lost frames": 0, "Last CLCW": "-"})
        self.every(0.25, self.tm, 0.05)
        self.every(5.0, lambda: self.tc_send(17, 1, b"", "TC(17,1) are-you-alive test"), 1.0)

    PW = 5

    def visible(self):
        return not self.fault["los"]

    def space_packet(self, tc, apid, svc, sub, data):
        k = (tc, apid)
        self.pkt_seq[k] = (self.pkt_seq.get(k, -1) + 1) & 0x3FFF
        if tc:
            sec = bytes([0x2F, svc, sub, 0x00, 0x01])
        else:
            self.msg_cnt = (getattr(self, "msg_cnt", -1) + 1) & 0xFFFF
            sec = bytes([0x20, svc, sub]) + struct.pack(">HH", self.msg_cnt, 0x0001) + struct.pack(">IH", 1300000000 + int(self.t), int((self.t % 1) * 65536))
        body = sec + data
        b = Bld("Space packet (CCSDS 133.0) %s(%d,%d) APID 0x%03X" % ("TC" if tc else "TM", svc, sub, apid), "")
        w1 = (0 << 13) | ((1 if tc else 0) << 12) | (1 << 11) | apid
        b.u16("Version / type / sec hdr / APID", w1, "v0, %s, secondary header, APID 0x%03X" % ("TC" if tc else "TM", apid), "Application process identifier")
        b.u16("Sequence flags / count", (3 << 14) | self.pkt_seq[k], "unsegmented, count %d" % self.pkt_seq[k], "")
        b.u16("Packet data length", len(body) + 2 - 1, "%d (= data field length - 1)" % (len(body) + 2 - 1), "")
        b.raw("PUS secondary header", sec, ("PUS-C TC, service %d subservice %d, ack flags 1111, source ID 1" if tc else
                                            "PUS-C TM, service %d subservice %d, message counter, destination ID 1, CUC time") % (svc, sub), "ECSS Packet Utilisation Standard")
        if data:
            b.raw("Application data", data, None, "")
        c = crcn("CRC-16/CCITT-FALSE", bytes(b.b))
        b.u16("Packet error control", c, "0x%04X" % c, "CRC-16 (PUS)")
        return b.done()

    def clcw(self):
        f = self.farm
        v = (0 << 31) | (0 << 29) | (0 << 26) | (1 << 24) | (0 << 18) | (0 << 15) | (0 << 14) | ((1 if f["lockout"] else 0) << 13) | (0 << 12) | ((1 if f["retransmit"] else 0) << 11) | (f["vr"] & 0xFF)
        return v

    def tm(self):
        if not self.visible():
            self.by["gs"].vars["Last CLCW"] = "LOSS OF SIGNAL"
            return
        self.mc = (self.mc + 1) & 0xFF
        self.vc = (self.vc + 1) & 0xFF
        hk = struct.pack(">hHB", int(21.5 * 100), 28000 + int(100 * math.sin(self.t)), 3)
        pkt = self.space_packet(False, 0x064, 3, 25, hk)
        b = Bld("TM transfer frame (CCSDS 132.0), VC 0, MC %d" % self.mc, "Fixed length on the link; shown shortened")
        b.u32("Attached sync marker", 0x1ACFFC1D, "1ACFFC1D", "Marks the start of every frame on the bit stream")
        w = (0 << 14) | (0x2A5 << 4) | (0 << 1) | 1
        b.u16("Version / SCID / VCID / OCF flag", w, "v0, SCID 0x2A5, VC 0, OCF present", "")
        b.u8("Master channel frame count", self.mc, None, "")
        b.u8("Virtual channel frame count", self.vc, None, "Gaps reveal lost frames")
        b.u16("Data field status", 0x1800, "no secondary header, sync flag 0, segment length ID 11, first header pointer 0", "First header pointer: where the first packet starts in the data field")
        b.sub(pkt)
        cl = self.clcw()
        b.u32("OCF: CLCW", cl, "COP-1, VC 0, lockout %d, wait 0, retransmit %d, report value N(R) = %d" % (self.farm["lockout"], self.farm["retransmit"], self.farm["vr"]),
              "Command link control word: the spacecraft's FARM-1 status")
        c = crcn("CRC-16/CCITT-FALSE", bytes(b.b[4:]))
        b.u16("FECF", c, "0x%04X" % c, "Frame error control field (CRC-16)")
        p = b.done()
        err = None
        g = self.by["gs"]
        if self.fault["fade"] and self.rng.random() < 0.4:
            err = "Reed-Solomon decoding failed: frame lost"
            g.vars["Lost frames"] += 1
        else:
            g.vars["TM frames"] += 1
            g.vars["Last CLCW"] = "N(R) %d, lockout %s" % (self.farm["vr"], "YES" if self.farm["lockout"] else "no")
        self.tx(rf_frame(self, "sc", "gs", "CCSDS", "TM frame MC %d VC %d: HK TM(3,25) APID 0x064, CLCW N(R)=%d%s" % (self.mc, self.vc, self.farm["vr"], " LOCKOUT" if self.farm["lockout"] else ""),
                         p, 0.009, 2210.0, 2.0, kind="data", err=err, rssi=-110, wirefn=lambda f: burst_wire(0.009, seed=self.mc, label="PCM/PM/NRZ-L, 1 Mbit/s")), bus="down")

    def tc_send(self, svc, sub, data, info, ctrl=False):
        if not self.visible():
            self.log("TC not sent: spacecraft not visible")
            return
        if ctrl:
            frame_data = bytes([0x00])
            bypass = 1
        else:
            pkt = self.space_packet(True, 0x064, svc, sub, data)
            frame_data = bytes([0xC0]) + pkt.b
            bypass = 0
        ns = self.ns
        if self.fault["lock"] and not ctrl and getattr(self, "jump", False):
            self.jump = False
            ns = (ns + 100) & 0xFF
            self.log("Ground FOP sends a frame with a corrupted sequence number: N(S) %d instead of %d" % (ns, self.ns))
        hdr_len = 5 + len(frame_data) + 2 - 1
        b = Bld("TC transfer frame (CCSDS 232.0) %s" % ("BC (control command)" if ctrl else "AD"), "")
        b.u16("Version / bypass / ctrl / SCID", (bypass << 13) | ((1 if ctrl else 0) << 12) | 0x2A5, "%s, SCID 0x2A5" % ("bypass (BC: Unlock)" if ctrl else "sequence-controlled (AD)"), "")
        b.u16("VCID / frame length", (0 << 10) | hdr_len, "VC 0, length %d" % (hdr_len + 1), "")
        b.u8("Frame sequence number N(S)", 0 if ctrl else ns, None, "FARM-1 accepts only N(S) = V(R) in AD mode")
        if ctrl:
            b.u8("Control command", 0x00, "UNLOCK", "Clears lockout in the FARM")
        else:
            b.u8("Segment header", 0xC0, "unsegmented, MAP 0", "")
            b.sub(Pdu(frame_data[1:], [[0, "Space packet TC(%d,%d)" % (svc, sub), None, 0, ""]]))
        c = crcn("CRC-16/CCITT-FALSE", bytes(b.b))
        b.u16("FECF", c, "0x%04X" % c, "")
        frame = bytes(b.b)
        blocks = [frame[i:i + 7].ljust(7, b"\x55") for i in range(0, len(frame), 7)]
        b.note("CLTU: start EB90 + %d BCH(63,56) code blocks + tail C5C5C5C5C5C5C579" % len(blocks), "Each 7-byte block gets a parity byte; e.g. first block parity 0x%02X" % bch_cltu(blocks[0]), d=0)
        p = b.done()
        self.tx(rf_frame(self, "gs", "sc", "CCSDS", "TC frame N(S)=%d: %s" % (ns if not ctrl else 0, info), p, 0.05 + len(frame) * 8 / 4000.0, 2034.0, 1.0, kind="cmd" if not ctrl else "ctl",
                         rssi=-100, wirefn=lambda f: burst_wire(0.05, seed=ns, label="CLTU, 4 kbit/s")), bus="up")
        f = self.farm
        sc = self.by["sc"]
        if ctrl:
            f["lockout"] = False
            f["retransmit"] = False
            sc.vars["Lockout"] = "no (unlocked)"
            self.ns = f["vr"]
            self.log("FOP-1 re-initialised from the CLCW: V(S) = N(R) = %d" % f["vr"])
            return
        self.ns = (self.ns + 1) & 0xFF
        if f["lockout"]:
            self.log("FARM-1 in lockout: AD frame N(S) %d discarded" % ns)
            return
        diff = (ns - f["vr"]) & 0xFF
        if diff == 0:
            f["vr"] = (f["vr"] + 1) & 0xFF
            f["retransmit"] = False
            sc.vars["FARM V(R)"] = f["vr"]
            sc.vars["Commands executed"] += 1
            self.last_tc = self.pkt_seq.get((True, 0x064), 0)
            self.at(self.t + 0.6, self.tm_reply, svc, sub)
        elif diff < self.PW:
            f["retransmit"] = True
            self.log("FARM-1: N(S) %d ahead of V(R) %d (positive window): discarded, retransmit flag set" % (ns, f["vr"]))
        elif diff > 256 - self.PW:
            self.log("FARM-1: N(S) %d already received (negative window): discarded" % ns)
        else:
            f["retransmit"] = True
            f["lockout"] = True
            sc.vars["Lockout"] = "LOCKOUT (N(S) %d, expected %d)" % (ns, f["vr"])
            self.log("FARM-1 lockout: received N(S) %d outside the window, expected %d" % (ns, f["vr"]))

    def tm_reply(self, svc, sub):
        if not self.visible():
            return
        for s2, txt in ((1, "TM(1,1) acceptance success"), (7, "TM(1,7) completion success")):
            pkt = self.space_packet(False, 0x064, 1, s2, struct.pack(">HH", 0x1864, 0xC000 | getattr(self, "last_tc", 0)))
            self.tx(rf_frame(self, "sc", "gs", "CCSDS", "TM packet %s" % txt, pkt, 0.002, 2210.0, 2.0, kind="ack", rssi=-110, wirefn=lambda f: burst_wire(0.002, seed=s2)), bus="down")
        if svc == 17:
            pkt = self.space_packet(False, 0x064, 17, 2, b"")
            self.tx(rf_frame(self, "sc", "gs", "CCSDS", "TM packet TM(17,2) are-you-alive report", pkt, 0.002, 2210.0, 2.0, kind="resp", rssi=-110, wirefn=lambda f: burst_wire(0.002, seed=17)),
                    bus="down")

    def on_fault(self, key, on):
        if key == "lock":
            self.jump = on

    def tpls(self):
        return [Tpl("TC(17,1) are-you-alive", [], lambda s, v, send: self._tc(17, 1, b"", send), "PUS test service; expect TM(1,1), TM(1,7) and TM(17,2)."),
                Tpl("TC(8,1) perform function", [P("fid", "Function ID", 5, 0, 255)], lambda s, v, send: self._tc(8, 1, bytes([v["fid"]]), send), "Function management service."),
                Tpl("BC Unlock (control command)", [], lambda s, v, send: self._unlock(send), "Bypass frame that clears the FARM lockout.")]

    def _tc(self, svc, sub, data, send):
        if not send:
            return Frame(self.t, 0.05, "gs", "sc", "CCSDS", "preview", pdu=self.space_packet(True, 0x064, svc, sub, data))
        self.tc_send(svc, sub, data, "TC(%d,%d)" % (svc, sub))
        return None

    def _unlock(self, send):
        if not send:
            b = Bld("TC frame BC Unlock (preview)")
            return Frame(self.t, 0.05, "gs", "sc", "CCSDS", "preview", pdu=b.done())
        self.tc_send(0, 0, b"", "BC frame: UNLOCK", ctrl=True)
        return None
