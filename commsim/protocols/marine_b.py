"""Marine, part B: NMEA 2000, SeaTalkng, NMEA OneNet, IEC 61162-450 and
Signal K."""
import datetime as _dt
import math
import struct
from ..engine import Bld, Frame, Tpl, P, Pdu
from ..bits import nmea_cs
from .fam import IpNet, eth_pdu, ipv4_pdu, ipv6_pdu, ipb
from .phys_b import CanNet, hexdata
from .auto_a import j1939_id, j1939_split
from .marine_a import Vessel, sentence, sentence_pdu, gga, rmc, utc, nmea_lat, nmea_lon, ST_KEYS
from .webfam import http_req, http_rsp, ws_frame, jdump, tls_hs, tls_record

# ======================================================== NMEA 2000 tables
MFR = {135: "Airmar", 229: "Garmin", 273: "Actisense", 358: "Victron Energy", 1851: "Raymarine", 1862: "Yamaha Marine"}
IND = {0: "Global", 1: "Highway", 2: "Agriculture", 3: "Construction", 4: "Marine", 5: "Industrial"}
DEV_CLASS = {25: "Internetwork device", 35: "Electrical generation", 40: "Steering and control surfaces", 50: "Propulsion", 60: "Navigation",
             85: "External environment", 120: "Display"}
DEV_FUNC = {(25, 130): "PC gateway", (25, 135): "NMEA 0183 gateway", (35, 170): "Battery", (40, 150): "Autopilot", (40, 155): "Rudder", (40, 160): "Heading sensors",
            (50, 140): "Engine", (60, 135): "Bottom depth / speed", (60, 145): "Ownship position (GNSS)", (85, 130): "Atmospheric", (120, 130): "Display"}
PILOT_MODES = {0: "standby (or wind with sub mode 1)", 64: "auto (heading hold)", 128: "track (route)"}


def F(name, kind, n, sc=1, unit="", lk=None):
    return (name, kind, n, sc, unit, lk)


MFR_HDR = [F("Manufacturer code", "lk", 11, 1, "", MFR), F("Reserved", "res", 2), F("Industry code", "lk", 3, 1, "", IND)]
N2K = {
    59904: ("ISO Request", 6, [F("Requested PGN", "u", 24)]),
    60928: ("ISO Address Claim", 6, [F("Unique number", "u", 21), F("Manufacturer code", "lk", 11, 1, "", MFR), F("Device instance lower", "u", 3), F("Device instance upper", "u", 5),
                                     F("Device function", "u", 8), F("Reserved", "res", 1), F("Device class", "lk", 7, 1, "", DEV_CLASS), F("System instance", "u", 4),
                                     F("Industry group", "lk", 3, 1, "", IND), F("Arbitrary address capable", "u", 1)]),
    126992: ("System Time", 3, [F("SID", "u", 8), F("Source", "lk", 4, 1, "", {0: "GPS", 1: "GLONASS", 2: "Radio station", 5: "Local crystal clock"}), F("Reserved", "res", 4),
                                F("Date", "u", 16, 1, "days"), F("Time", "u", 32, 0.0001, "tod")]),
    126993: ("Heartbeat", 7, [F("Data transmit offset", "u", 16, 0.001, "s"), F("Sequence counter", "u", 8), F("Controller 1 state", "lk", 2, 1, "", {0: "error active", 1: "error passive", 2: "bus off"}),
                              F("Controller 2 state", "u", 2), F("Equipment status", "lk", 2, 1, "", {0: "operational", 1: "fault"}), F("Reserved", "res", 34)]),
    126996: ("Product Information", 6, [F("NMEA 2000 version", "u", 16, 0.001), F("Product code", "u", 16), F("Model ID", "str", 256), F("Software version code", "str", 256),
                                         F("Model version", "str", 256), F("Model serial code", "str", 256), F("Certification level", "lk", 8, 1, "", {0: "level A", 1: "level B", 2: "level C"}),
                                         F("Load equivalency (LEN)", "u", 8, 1, "x 50 mA")]),
    127245: ("Rudder", 2, [F("Instance", "u", 8), F("Direction order", "u", 3), F("Reserved", "res", 5), F("Angle order", "s", 16, 0.0001, "rad"), F("Position", "s", 16, 0.0001, "rad"),
                           F("Reserved", "res", 16)]),
    127250: ("Vessel Heading", 2, [F("SID", "u", 8), F("Heading", "u", 16, 0.0001, "rad"), F("Deviation", "s", 16, 0.0001, "rad"), F("Variation", "s", 16, 0.0001, "rad"),
                                   F("Reference", "lk", 2, 1, "", {0: "True", 1: "Magnetic"}), F("Reserved", "res", 6)]),
    127251: ("Rate of Turn", 2, [F("SID", "u", 8), F("Rate", "s", 32, 3.125e-8, "rad/s"), F("Reserved", "res", 24)]),
    127488: ("Engine Parameters, Rapid Update", 2, [F("Instance", "lk", 8, 1, "", {0: "single engine or dual port", 1: "dual starboard"}), F("Speed", "u", 16, 0.25, "rpm"),
                                                    F("Boost pressure", "u", 16, 100, "Pa"), F("Tilt/trim", "s", 8, 1, "%"), F("Reserved", "res", 16)]),
    127489: ("Engine Parameters, Dynamic", 2, [F("Instance", "lk", 8, 1, "", {0: "single engine or dual port", 1: "dual starboard"}), F("Oil pressure", "u", 16, 100, "Pa"),
                                               F("Oil temperature", "u", 16, 0.1, "K"), F("Coolant temperature", "u", 16, 0.01, "K"), F("Alternator potential", "s", 16, 0.01, "V"),
                                               F("Fuel rate", "s", 16, 0.1, "L/h"), F("Total engine hours", "u", 32, 1, "s"), F("Coolant pressure", "u", 16, 100, "Pa"),
                                               F("Fuel pressure", "u", 16, 1000, "Pa"), F("Reserved", "res", 8), F("Discrete status 1", "u", 16), F("Discrete status 2", "u", 16),
                                               F("Engine load", "s", 8, 1, "%"), F("Engine torque", "s", 8, 1, "%")]),
    127508: ("Battery Status", 6, [F("Instance", "u", 8), F("Voltage", "s", 16, 0.01, "V"), F("Current", "s", 16, 0.1, "A"), F("Temperature", "u", 16, 0.01, "K"), F("SID", "u", 8)]),
    128259: ("Speed, Water Referenced", 2, [F("SID", "u", 8), F("Speed water referenced", "u", 16, 0.01, "m/s"), F("Speed ground referenced", "u", 16, 0.01, "m/s"),
                                            F("Speed type", "lk", 8, 1, "", {0: "paddle wheel", 1: "pitot tube", 2: "Doppler", 3: "correlation (ultrasound)", 4: "electromagnetic"}),
                                            F("Speed direction", "u", 4), F("Reserved", "res", 12)]),
    128267: ("Water Depth", 3, [F("SID", "u", 8), F("Depth", "u", 32, 0.01, "m"), F("Offset", "s", 16, 0.001, "m"), F("Range", "u", 8, 10, "m")]),
    129025: ("Position, Rapid Update", 2, [F("Latitude", "s", 32, 1e-7, "deg"), F("Longitude", "s", 32, 1e-7, "deg")]),
    129026: ("COG & SOG, Rapid Update", 2, [F("SID", "u", 8), F("COG reference", "lk", 2, 1, "", {0: "True", 1: "Magnetic"}), F("Reserved", "res", 6), F("COG", "u", 16, 0.0001, "rad"),
                                            F("SOG", "u", 16, 0.01, "m/s"), F("Reserved", "res", 16)]),
    129029: ("GNSS Position Data", 3, [F("SID", "u", 8), F("Date", "u", 16, 1, "days"), F("Time", "u", 32, 0.0001, "tod"), F("Latitude", "s", 64, 1e-16, "deg"), F("Longitude", "s", 64, 1e-16, "deg"),
                                       F("Altitude", "s", 64, 1e-6, "m"), F("GNSS type", "lk", 4, 1, "", {0: "GPS", 1: "GLONASS", 2: "GPS+GLONASS", 3: "GPS+SBAS", 4: "GPS+SBAS+GLONASS", 8: "Galileo"}),
                                       F("Method", "lk", 4, 1, "", {0: "no GNSS", 1: "GNSS fix", 2: "DGNSS fix", 3: "precise GNSS", 4: "RTK fixed", 5: "RTK float", 6: "estimated (DR)"}),
                                       F("Integrity", "lk", 2, 1, "", {0: "no integrity checking", 1: "safe", 2: "caution"}), F("Reserved", "res", 6), F("Number of SVs", "u", 8),
                                       F("HDOP", "s", 16, 0.01), F("PDOP", "s", 16, 0.01), F("Geoidal separation", "s", 32, 0.01, "m"), F("Reference stations", "u", 8)]),
    130306: ("Wind Data", 2, [F("SID", "u", 8), F("Wind speed", "u", 16, 0.01, "m/s"), F("Wind angle", "u", 16, 0.0001, "rad"),
                              F("Reference", "lk", 3, 1, "", {0: "true (ground, north)", 1: "magnetic (ground)", 2: "apparent", 3: "true (boat referenced)", 4: "true (water referenced)"}),
                              F("Reserved", "res", 21)]),
    130312: ("Temperature", 5, [F("SID", "u", 8), F("Instance", "u", 8), F("Source", "lk", 8, 1, "", {0: "sea temperature", 1: "outside temperature", 2: "inside temperature", 3: "engine room"}),
                                F("Actual temperature", "u", 16, 0.01, "K"), F("Set temperature", "u", 16, 0.01, "K"), F("Reserved", "res", 8)]),
    65359: ("Seatalk: Pilot Heading (Raymarine proprietary)", 2, MFR_HDR + [F("SID", "u", 8), F("Heading true", "u", 16, 0.0001, "rad"), F("Heading magnetic", "u", 16, 0.0001, "rad"),
                                                                            F("Reserved", "res", 8)]),
    65360: ("Seatalk: Pilot Locked Heading (Raymarine proprietary)", 2, MFR_HDR + [F("SID", "u", 8), F("Target heading true", "u", 16, 0.0001, "rad"),
                                                                                   F("Target heading magnetic", "u", 16, 0.0001, "rad"), F("Reserved", "res", 8)]),
    65379: ("Seatalk: Pilot Mode (Raymarine proprietary)", 7, MFR_HDR + [F("Pilot mode", "lk", 8, 1, "", PILOT_MODES), F("Sub mode", "u", 16), F("Pilot mode data", "u", 8), F("Reserved", "res", 16)]),
    126720: ("Seatalk1 keystroke (Raymarine proprietary fast packet)", 7, MFR_HDR + [F("Proprietary ID", "u", 16), F("SeaTalk1 command", "u", 8), F("SeaTalk1 attribute", "u", 8),
                                                                                    F("Key", "lk", 8, 1, "", ST_KEYS), F("Key inverted", "u", 8), F("Trailer (fixed, undocumented)", "str", 112)]),
}
FAST = {126996, 127489, 129029, 126720}


def n2k_encode(pgn, vals):
    """vals: angles in degrees, temperatures in deg C, other units as in the table; missing = not available."""
    acc, pos = 0, 0
    for name, kind, n, sc, unit, lk in N2K[pgn][2]:
        mask = (1 << n) - 1
        if kind == "res":
            raw = mask
        elif kind == "str":
            s = vals.get(name, b"")
            bb = (s.encode("latin-1") if isinstance(s, str) else bytes(s))[:n // 8].ljust(n // 8, b"\xff")
            raw = int.from_bytes(bb, "little")
        else:
            v = vals.get(name)
            if v is None:
                raw = (mask >> 1) if kind == "s" else mask
            else:
                if unit == "rad":
                    v = math.radians(v)
                elif unit == "rad/s":
                    v = math.radians(v) / 60.0
                elif unit == "K":
                    v = v + 273.15
                raw = int(v) if kind == "lk" else int(round(v / sc))
                raw &= mask
        acc |= raw << pos
        pos += n
    return acc.to_bytes((pos + 7) // 8, "little")


def _fmt(kind, raw, n, sc, unit, lk):
    mask = (1 << n) - 1
    if kind == "lk":
        return "%d (%s)" % (raw, lk.get(raw, "?") if lk else "")
    if kind == "u" and raw == mask and n >= 2:
        return "not available"
    if kind == "s":
        if raw == mask >> 1:
            return "not available"
        if raw >> (n - 1):
            raw -= 1 << n
    v = raw * sc
    if unit == "rad":
        return "%.4f rad = %.1f deg" % (v, math.degrees(v))
    if unit == "rad/s":
        return "%.6f rad/s = %.1f deg/min" % (v, math.degrees(v) * 60)
    if unit == "K":
        return "%.2f K = %.1f C" % (v, v - 273.15)
    if unit == "m/s":
        return "%.2f m/s = %.2f kn" % (v, v / 0.514444)
    if unit == "Pa":
        return "%.0f Pa = %.2f bar" % (v, v / 1e5)
    if unit == "days":
        return "%d (%s)" % (raw, (_dt.date(1970, 1, 1) + _dt.timedelta(days=raw)).isoformat())
    if unit == "tod":
        return "%.4f s since midnight (%02d:%02d:%06.3f)" % (v, int(v // 3600), int(v % 3600 // 60), v % 60)
    if unit == "deg":
        return "%.7f deg" % v
    if unit == "s" and n >= 32:
        return "%d s = %.1f h" % (v, v / 3600)
    return ("%g %s" % (round(v, 6), unit)).strip()


def n2k_rows(b, off, pgn, d, depth=0, limit=None):
    """Field rows for one PGN payload d (offsets relative to off; rows beyond `limit` bytes get no offset)."""
    ent = N2K.get(pgn)
    if ent is None:
        b.rows.append([depth, "NMEA 2000 PGN %d (not in this simulator's database)" % pgn, off, len(d), ""])
        return
    b.rows.append([depth, "NMEA 2000 PGN %d: %s" % (pgn, ent[0]), off if limit is None else None, len(d) if limit is None else 0,
                   "Fields packed little-endian, LSB first; all-ones = not available. Definitions: NMEA 2000 Appendix B (public field layouts per canboat)."])
    acc = int.from_bytes(bytes(d), "little")
    pos = 0
    for name, kind, n, sc, unit, lk in ent[2]:
        if kind == "res" or pos >= len(d) * 8:
            pos += n
            continue
        raw = (acc >> pos) & ((1 << n) - 1)
        if kind == "str":
            txt = '"%s"' % raw.to_bytes(n // 8, "little").rstrip(b"\xff\x00 ").decode("latin-1", "replace")
        else:
            txt = _fmt(kind, raw, n, sc, unit, lk)
        o, ln = pos // 8, max(1, (pos + n + 7) // 8 - pos // 8)
        inside = limit is None or o + ln <= limit
        b.rows.append([depth + 1, "%s: %s" % (name, txt), off + o if inside else None, ln if inside else 0, "%d bit%s at bit %d" % (n, "s" if n > 1 else "", pos)])
        pos += n


def n2k_idrows(b, o, cid, names=None):
    prio, pgn, sa, da, pf, ps = j1939_split(cid)
    b.note("Priority %d" % prio, "3 bits: 0 highest .. 7 lowest", d=1)
    b.note("PGN %d (0x%05X) %s" % (pgn, pgn, N2K.get(pgn, ("proprietary / unknown",))[0]), "Parameter Group Number: what the data means (NMEA 2000 uses J1939 / ISO 11783 addressing)", d=1)
    b.note("PDU%d: %s" % (1 if pf < 240 else 2, "destination 0x%02X%s" % (ps, " (global)" if ps == 255 else "") if pf < 240 else "broadcast"), "PF < 240 = addressable PGN", d=1)
    b.note("Source address 0x%02X (%d)%s" % (sa, sa, (" " + names.get(sa)) if names and names.get(sa) else ""), "Claimed with ISO Address Claim (PGN 60928)", d=1)


def n2k_name(unique, mfr, func, cls, inst=0, aac=1):
    return unique | (mfr << 21) | (inst << 32) | (func << 40) | (cls << 49) | (4 << 60) | (aac << 63)


class N2kNet(CanNet):
    """NMEA 2000 network machinery: address claim, PGN codec, fast packets, product info, backbone power."""
    cat = "marine"
    rate = 250000
    can_proto = "NMEA 2000"
    nets = [("CANH", "NET-H"), ("CANL", "NET-L"), ("VDIFF", "NET-H - NET-L"), ("RXD", "transceiver RXD (logic)")]

    def n2k_init(self, devs):
        """devs: {nid: dict(sa, name (int), len, model, mfr)}"""
        self.dev = devs
        self.sa = {k: v["sa"] for k, v in devs.items()}
        self.fpseq = {}
        self.sid = 0
        self.lost_fp = False

    def snames(self):
        return {v: self.by[k].label for k, v in self.sa.items() if k in self.by}

    def frame_rows(self, pgn, payload, idx, total, seq):
        def dis(b, o, d=None):
            if total is None:
                n2k_rows(b, o, pgn, payload)
                return
            if idx == 0:
                b.rows.append([0, "NMEA 2000 fast packet: sequence %d, frame 0 of %d, total %d bytes" % (seq, total, len(payload)), o, 2,
                               "Byte 0: sequence counter (3 bits) + frame counter (5 bits); byte 1: total length; then 6 data bytes"])
                n2k_rows(b, o + 2, pgn, payload, 0, limit=6)
            else:
                b.rows.append([0, "NMEA 2000 fast packet: sequence %d, frame %d of %d (data bytes %d-%d)" % (seq, idx, total, 6 + 7 * (idx - 1), min(len(payload), 6 + 7 * idx) - 1),
                               o, 8, "Byte 0: sequence + frame counter, then 7 more data bytes of PGN %d" % pgn])
        return dis

    def send_pgn(self, node, pgn, vals, da=0xFF, info=None, kind="data", prio=None, raw=None, t=None, lose=None):
        if node not in self.by or not self.by[node].on:
            return
        data = raw if raw is not None else n2k_encode(pgn, vals)
        prio = N2K.get(pgn, ("", 6))[1] if prio is None else prio
        sa = self.sa[node]
        cid = j1939_id(prio, pgn, sa, da)
        dst = None
        if da != 0xFF and ((pgn >> 8) & 0xFF) < 240:
            dst = next((k for k, v in self.sa.items() if v == da and k in self.by and self.by[k].on and k != node), None)
        nm = self.snames()
        idr = lambda b, o, cid=cid: n2k_idrows(b, o, cid, nm)
        name = N2K.get(pgn, ("PGN %d" % pgn,))[0]
        info = info or name
        sd = "0x%02X" % sa
        dd = ("0x%02X" % da) if dst is not None else None
        if pgn not in FAST and len(data) <= 8:
            d = data.ljust(8, b"\xff")
            self.bus.send(node, cid, d, ext=True, info=info, kind=kind, key="PGN %d" % pgn, dst=dst, idrows=idr, dissect=self.frame_rows(pgn, data, 0, None, 0), t=t, sd=sd, dd=dd)
            return
        seq = self.fpseq.get((node, pgn), 0)
        self.fpseq[(node, pgn)] = (seq + 1) & 7
        frames = [(bytes([(seq << 5), len(data)]) + data[:6]).ljust(8, b"\xff")]
        pos, k = 6, 1
        while pos < len(data):
            frames.append((bytes([(seq << 5) | k]) + data[pos:pos + 7]).ljust(8, b"\xff"))
            pos += 7
            k += 1
        for i, fd in enumerate(frames):
            if lose is not None and i == lose:
                continue
            self.bus.send(node, cid, fd, ext=True, info="%s [fast packet %d/%d]" % (info, i + 1, len(frames)), kind=kind, key="PGN %d" % pgn, dst=dst, idrows=idr,
                          dissect=self.frame_rows(pgn, data, i, len(frames), seq), t=t, sd=sd, dd=dd)

    def claim(self, node, sa=None, info=None):
        if sa is not None:
            self.sa[node] = sa
        d = self.dev[node]
        nm = d["name"].to_bytes(8, "little")
        self.send_pgn(node, 60928, None, raw=nm, info=info or "ISO Address Claim: SA 0x%02X, %s %s" % (self.sa[node], MFR.get((d["name"] >> 21) & 0x7FF, "?"), d.get("model", "")),
                      kind="ctl")

    def product_info(self, node, da=0xFF):
        d = self.dev[node]
        self.send_pgn(node, 126996, {"NMEA 2000 version": 2.100, "Product code": d.get("pcode", 1234), "Model ID": d.get("model", "DEVICE"), "Software version code": d.get("sw", "1.0.0"),
                                     "Model version": d.get("hw", "A"), "Model serial code": d.get("serial", "0012345"), "Certification level": 1, "Load equivalency (LEN)": d.get("len", 1)},
                      da=da, info="Product Information: %s (LEN %d)" % (d.get("model", ""), d.get("len", 1)), kind="resp")

    def heartbeat(self, node):
        self.send_pgn(node, 126993, {"Data transmit offset": 60.0, "Sequence counter": int(self.t / 60) % 253, "Controller 1 state": 0, "Controller 2 state": 3, "Equipment status": 0},
                      info="Heartbeat (60 s)", kind="sync")

    def request(self, src, pgn, da, send=True):
        cid = j1939_id(6, 59904, self.sa[src], da)
        data = struct.pack("<I", pgn)[:3]
        if not send:
            return self.preview_can(src, cid, data, ext=True, dissect=lambda b, o: n2k_rows(b, o, 59904, data), idrows=lambda b, o: n2k_idrows(b, o, cid))
        self.send_pgn(src, 59904, None, raw=data, da=da, info="ISO Request for PGN %d (%s) to 0x%02X" % (pgn, N2K.get(pgn, ("?",))[0], da), kind="cmd")
        tgt = [k for k, v in self.sa.items() if (v == da or da == 0xFF) and k in self.by and self.by[k].on and self.dev.get(k)]
        for i, k in enumerate(tgt):
            if pgn == 126996:
                self.at(self.t + 0.01 + 0.003 * i, self.product_info, k, self.sa[src] if da != 0xFF else 0xFF)
            elif pgn == 60928:
                self.at(self.t + 0.01 + 0.003 * i, self.claim, k)
        return None

    def power_volts(self, tee_x, metres_per_px, ohm_per_m, vsup=12.6):
        """Voltage at every device on a backbone fed at tee_x (simple resistive ladder)."""
        loads = [(self.by[k].port[0], self.dev[k].get("len", 1) * 0.05, k) for k in self.dev if k in self.by and self.by[k].on]
        out = {}
        for side in (-1, 1):
            pts = sorted([l for l in loads if (l[0] - tee_x) * side > 0], key=lambda l: abs(l[0] - tee_x))
            v, x0 = vsup, tee_x
            for i, (x, amps, k) in enumerate(pts):
                down = sum(a for _, a, _ in pts[i:])
                v -= down * 2 * ohm_per_m * abs(x - x0) * metres_per_px
                out[k] = v
                x0 = x
        for x, amps, k in loads:
            out.setdefault(k, vsup)
        return out


# ================================================================ NMEA 2000
class NMEA2000(N2kNet):
    key, name = "nmea2000", "NMEA 2000"
    blurb = "Modern marine electronics networking"
    medium = "NMEA 2000: CAN 250 kbit/s, 29-bit IDs (ISO 11783 / J1939 based), Micro-C M12 drop cables, 120 Ω terminators, 12 V on the backbone"
    faults = [("no_term1", "Terminator missing (right end)", "One 120 Ω terminator left: slower edges and ringing - frames start to fail."),
              ("power", "Power tee at one end of a 60 m light backbone", "The voltage drop along the thin cable leaves the far devices below 9 V: the wind sensor browns out and keeps rebooting."),
              ("claim", "Replacement starboard engine gateway wants SA 0x10", "Address claim conflict with the port engine: the lower NAME keeps 0x10, the new unit moves to another address."),
              ("fp", "Noise destroys one fast-packet frame", "GNSS Position Data (43 bytes in 7 frames) arrives with a gap: the plotter discards the whole message."),
              ("instance", "Starboard engine also set to instance 0", "Both engines report 'instance 0': the plotter's port gauge jumps between two RPM values.")]
    spec = [("Standard", "NMEA 2000 (IEC 61162-3), built on ISO 11783 / SAE J1939; NMEA certification"),
            ("Physical", "CAN 250 kbit/s, Micro-C / Mid M12 connectors, backbone + drops (max 6 m), 120 Ω at both ends, 9-16 V network power, max 50 devices"),
            ("Power", "LEN (load equivalency number): 1 LEN = 50 mA; plan the power tee position so no device sees less than 9 V"),
            ("Messages", "PGNs with little-endian fields, all-ones = not available; fast packet for up to 223 bytes; ISO transport for longer"),
            ("Network mgmt", "ISO Address Claim with 64-bit NAME (class / function / manufacturer), ISO Request, product information, heartbeat"),
            ("Instances", "Device and data instances tell identical sources apart (two engines, several batteries)")]
    frame = [["29-bit identifier", ("Priority", 3), ("R", 1), ("DP", 1), ("PDU format", 8), ("PDU specific", 8), ("Source address", 8)],
             ["Fast packet first frame", ("Seq | frame 0", 8), ("Total bytes", 8), ("Data 1-6", 48)]]
    about = ("NMEA 2000 is the plug-and-play network on modern boats: every instrument, engine and display on one CAN backbone with standard M12 "
             "connectors. It borrows J1939's 29-bit identifiers, address claim and ISO requests, and defines Parameter Group Numbers for marine data "
             "such as heading (127250) or water depth (128267). Messages larger than 8 bytes use the fast packet protocol, and devices are told apart "
             "by their NAME and by instance numbers.")
    guide = ["Watch the address claims at power-up (60928): decode a NAME into manufacturer, device class and function.",
             "Select Vessel Heading (127250): heading is in units of 0.0001 rad.",
             "Find the 7 frames of one GNSS Position Data (129029) fast packet and their sequence / frame counters.",
             "COMPOSE an ISO Request for Product Information (126996) to the depth transducer.",
             "Move the power tee to one end (fault) and read each device's supply voltage in DEVICE."]

    def setup(self):
        top = [("mfd", "CHARTPLOTTER", "display", 0x01, 229, 120, 130, 1, "GPSMAP 8610"), ("gnss", "GNSS ANTENNA", "gps", 0x02, 229, 60, 145, 1, "GPS 24xd"),
               ("dst", "DEPTH/SPEED/TEMP", "sensor", 0x23, 135, 60, 135, 2, "DST810"), ("hdg", "HEADING SENSOR", "compass", 0x0B, 135, 40, 160, 1, "H2183"),
               ("wind", "WIND SENSOR", "wind", 0x05, 135, 85, 130, 2, "220WX")]
        bot = [("eng", "PORT ENGINE GW", "engine", 0x10, 1862, 50, 140, 1, "Command Link"), ("eng2", "STBD ENGINE GW", "engine", 0x11, 1862, 50, 140, 1, "Command Link"),
               ("bat", "BATTERY MONITOR", "battery", 0x20, 358, 35, 170, 1, "Lynx Shunt"), ("gw", "USB GATEWAY (PC)", "pc", 0x42, 273, 25, 130, 1, "NGT-1"),
               ("pwr", "12 V POWER TEE", "battery", None, 0, 0, 0, 0, "")]
        nodes, devs = [], {}
        for i, (nid, lab, kind, sa, mfr, cls, fn, ln, model) in enumerate(top + bot):
            x = 20 + 172 * (i % 5)
            y = 40 if i < 5 else 290
            n = self.node(nid, lab, kind, x, y, ("0x%02X" % sa) if sa is not None else "", model if sa is not None else "network power", w=124)
            if i >= 5:
                n.at_top()
            nodes.append(n)
            if sa is not None:
                devs[nid] = dict(sa=sa, name=n2k_name(0x1000 + i * 77, mfr, fn, cls, inst=1 if nid == "eng2" else 0), len=ln, model=model, pcode=1000 + i, serial="%07d" % (4400 + i))
        self.pwr = self.by["pwr"]
        self.pwr.extra["can"] = False
        self.can_trunk(nodes, 200, label="NMEA 2000 Mid backbone, 120 Ω at both ends", conn="m12")
        self.n2k_init(devs)
        self.ship = Vessel(50.7667, -1.30, 6.3, 52.0)
        self.user = "gw"
        self.boot = {}
        m = self.by["mfd"]
        m.vars.update({"Position": "-", "SOG / COG": "-", "Heading": "-", "Depth": "-", "STW": "-", "Wind": "-", "Port RPM": "-", "Stbd RPM": "-", "Battery": "-"})
        self.by["eng"].vars.update({"RPM": 1850.0})
        self.by["eng"].ctl = [("RPM", "RPM", 600.0, 5500.0, 10.0, lambda v: "%.0f" % v)]
        self.by["eng2"].vars.update({"RPM": 1790.0})
        for k in devs:
            self.by[k].vars["Supply V"] = "-"
        for i, k in enumerate(devs):
            self.at(0.01 + 0.004 * i, self.claim, k)
            self.every(60.0, self.heartbeat, 5.0 + i * 0.37, 0.0, k)
        self.at(0.4, self.request, "mfd", 126996, self.sa["gnss"])
        self.every(0.1, self.fast, 0.11)
        self.every(0.25, self.medium_rate, 0.13)
        self.every(1.0, self.slow, 0.17)
        self.every(0.5, self.eng_dyn, 0.29)
        self.every(0.5, self.power, 0.05)

    def alive(self, k):
        return self.by[k].on and not self.boot.get(k)

    def fast(self):
        s = self.ship
        s.step(0.1, self.rng)
        if self.alive("gnss"):
            self.send_pgn("gnss", 129025, {"Latitude": s.lat, "Longitude": s.lon}, info="Position %.5f, %.5f" % (s.lat, s.lon))
        if self.alive("hdg"):
            self.sid = (self.sid + 1) % 253
            self.send_pgn("hdg", 127250, {"SID": self.sid, "Heading": s.hdg, "Reference": 1}, info="Heading %.1f deg (magnetic)" % s.hdg)
            self.send_pgn("hdg", 127251, {"SID": self.sid, "Rate": s.rot}, info="Rate of turn %+.1f deg/min" % s.rot)
        for k, inst in (("eng", 0), ("eng2", 0 if self.fault["instance"] else 1)):
            if self.alive(k):
                rpm = self.by[k].vars["RPM"] + float(self.rng.normal(0, 4))
                self.send_pgn(k, 127488, {"Instance": inst, "Speed": rpm, "Boost pressure": 0, "Tilt/trim": 0}, info="Engine %d: %.0f rpm" % (inst, rpm))
                self.mfd_engine(inst, rpm)

    def mfd_engine(self, inst, rpm):
        m = self.by["mfd"]
        m.vars["Port RPM" if inst == 0 else "Stbd RPM"] = "%.0f" % rpm
        if self.fault["instance"]:
            m.vars["Stbd RPM"] = "- (no instance 1)"

    def medium_rate(self):
        s = self.ship
        m = self.by["mfd"]
        if self.alive("gnss"):
            self.send_pgn("gnss", 129026, {"SID": self.sid, "COG reference": 0, "COG": s.cog, "SOG": s.sog * 0.514444}, info="COG %.1f deg, SOG %.1f kn" % (s.cog, s.sog))
            m.vars["SOG / COG"] = "%.1f kn / %.0f deg" % (s.sog, s.cog)
        if self.alive("wind"):
            self.send_pgn("wind", 130306, {"SID": self.sid, "Wind speed": s.aws * 0.514444, "Wind angle": s.awa, "Reference": 2}, info="Apparent wind %.0f deg %.1f kn" % (s.awa, s.aws))
            m.vars["Wind"] = "%.0f deg / %.1f kn" % (s.awa, s.aws)
        elif self.fault["power"]:
            m.vars["Wind"] = "NO DATA (sensor rebooting)"
        m.vars["Heading"] = "%.1f deg M" % s.hdg if self.alive("hdg") else "-"

    def slow(self):
        s = self.ship
        m = self.by["mfd"]
        tm = utc(self.t)
        days = (tm.date() - tm.date().replace(year=1970, month=1, day=1)).days
        tod = tm.hour * 3600 + tm.minute * 60 + tm.second + tm.microsecond / 1e6
        if self.alive("gnss"):
            self.send_pgn("gnss", 126992, {"SID": self.sid, "Source": 0, "Date": days, "Time": tod}, info="System time %s" % tm.strftime("%H:%M:%S"))
            lose = 3 if self.fault["fp"] else None
            self.send_pgn("gnss", 129029, {"SID": self.sid, "Date": days, "Time": tod, "Latitude": s.lat, "Longitude": s.lon, "Altitude": 12.4, "GNSS type": 0, "Method": 2,
                                           "Integrity": 1, "Number of SVs": 11, "HDOP": 0.8, "PDOP": 1.4, "Geoidal separation": 47.1, "Reference stations": 0},
                          info="GNSS position %.5f %.5f, DGNSS, 11 SVs" % (s.lat, s.lon), lose=lose)
            if lose is not None:
                self.log("Fast packet frame 4 of 7 lost: plotter discards GNSS Position Data, uses 129025 instead")
            m.vars["Position"] = "%.5f N  %.5f W" % (s.lat, -s.lon)
        if self.alive("dst"):
            self.send_pgn("dst", 128267, {"SID": self.sid, "Depth": s.depth, "Offset": 0.4, "Range": 100}, info="Depth %.2f m (offset +0.4 m)" % s.depth)
            self.send_pgn("dst", 128259, {"SID": self.sid, "Speed water referenced": s.stw * 0.514444, "Speed type": 0, "Speed direction": 0}, info="Speed through water %.1f kn" % s.stw)
            if int(self.t) % 2 == 0:
                self.send_pgn("dst", 130312, {"SID": self.sid, "Instance": 0, "Source": 0, "Actual temperature": s.wtemp}, info="Sea temperature %.1f C" % s.wtemp)
            m.vars["Depth"] = "%.1f m" % (s.depth + 0.4)
            m.vars["STW"] = "%.1f kn" % s.stw
        if self.alive("bat"):
            v = 12.9 + 0.1 * math.sin(self.t / 30)
            self.send_pgn("bat", 127508, {"Instance": 0, "Voltage": v, "Current": -8.4, "Temperature": 21.0, "SID": self.sid}, info="Battery 0: %.2f V, -8.4 A" % v)
            m.vars["Battery"] = "%.2f V, -8.4 A" % v

    def eng_dyn(self):
        for k, inst in (("eng", 0), ("eng2", 0 if self.fault["instance"] else 1)):
            if self.alive(k):
                self.send_pgn(k, 127489, {"Instance": inst, "Oil pressure": 420000, "Oil temperature": 92.0, "Coolant temperature": 78.0, "Alternator potential": 14.2, "Fuel rate": 18.5,
                                          "Total engine hours": 3600 * 812 + int(self.t), "Coolant pressure": 110000, "Fuel pressure": 350000, "Discrete status 1": 0, "Discrete status 2": 0,
                                          "Engine load": 46, "Engine torque": 40}, info="Engine %d dynamic: oil 4.2 bar, coolant 78 C, 18.5 L/h" % inst)

    def power(self):
        if not self.pwr.on:
            for k in self.dev:
                self.by[k].vars["Supply V"] = "0.0 V (no network power)"
                self.by[k].on = k in ("mfd",)
                self.by[k].state = "NO POWER" if k != "mfd" else ""
            return
        tee = 30 + 820 * (0.0 if self.fault["power"] else 0.55)
        mpp = (60.0 if self.fault["power"] else 25.0) / 820.0
        ohm = 0.0574 if self.fault["power"] else 0.0332
        volts = self.power_volts(tee, mpp, ohm)
        for k, v in volts.items():
            n = self.by[k]
            if self.fault["power"] and k == "wind":
                v = min(v, 8.6)
            n.vars["Supply V"] = "%.2f V%s" % (v, " (LOW - below 9 V)" if v < 9.0 else "")
            if v < 9.0 and not self.boot.get(k):
                self.boot[k] = True
                n.state = "BROWN-OUT"
                self.log("%s browns out at %.2f V and reboots" % (n.label, v))
                self.at(self.t + 1.2, self.reboot, k)
        if not self.fault["power"]:
            for k in list(self.boot):
                if self.boot[k] is True and k != "wind":
                    pass

    def reboot(self, k):
        n = self.by[k]
        self.boot[k] = False
        n.state = ""
        self.claim(k, info="ISO Address Claim after reboot: SA 0x%02X" % self.sa[k])

    def on_power(self, n):
        if n.id == "pwr" and n.on:
            for k in self.dev:
                self.by[k].on = True
                self.by[k].state = ""
            for i, k in enumerate(self.dev):
                self.at(self.t + 0.05 + 0.004 * i, self.claim, k)

    def can_fault(self, key, on):
        if key == "claim":
            if on:
                self.dev["eng2"]["name"] = n2k_name(0x5555, 1862, 140, 50, inst=1)
                self.claim("eng2", 0x10, "ISO Address Claim: new starboard gateway wants SA 0x10")
                self.at(self.t + 0.003, self.claim, "eng", None, "Port engine defends SA 0x10 (lower NAME)")
                self.at(self.t + 0.25, self.claim, "eng2", 0x12, "New unit lost the conflict: claims SA 0x12 instead")
                self.at(self.t + 0.26, lambda: setattr(self.by["eng2"], "addr", "0x12"))
            else:
                self.by["eng2"].addr = "0x11"
                self.claim("eng2", 0x11)
        if key == "power" and not on:
            for k in self.dev:
                if self.boot.get(k):
                    self.boot[k] = False
                    self.by[k].state = ""

    def tpls(self):
        devs = [k for k in self.dev if k != "gw"]
        return [Tpl("ISO Request (59904)", [P("pgn", "Requested PGN", 126996, opts=[126996, 60928], fmt=lambda v: "%d %s" % (v, N2K[v][0])),
                                            P("da", "Destination", "dst", opts=devs + ["global"], fmt=lambda v: "global (0xFF)" if v == "global" else "%s (0x%02X)" % (self.by[v].label, self.sa[v]))],
                    lambda s, v, send: self.request("gw", v["pgn"], 0xFF if v["da"] == "global" else self.sa[v["da"]], send),
                    "Ask a device (or everyone) to send a PGN. Product Information comes back as a 20-frame fast packet."),
                Tpl("Inject Vessel Heading (127250)", [P("h", "Heading deg", 90.0, 0.0, 359.9, 1.0)], lambda s, v, send: self._hdg(v["h"], send),
                    "The USB gateway (your PC) sends a heading. Two heading sources on one network - which one does the plotter show?"),
                Tpl("Raw single-frame PGN", [P("pgn", "PGN", 130306, 0, 131071), P("data", "Data (hex)", "01 F4 01 10 27 FA FF FF")], lambda s, v, send: self._raw(v, send),
                    "Any PGN with your own 8 data bytes.")]

    def _hdg(self, h, send):
        if not send:
            d = n2k_encode(127250, {"SID": 0, "Heading": h, "Reference": 0})
            cid = j1939_id(2, 127250, self.sa["gw"])
            return self.preview_can("gw", cid, d, ext=True, dissect=lambda b, o: n2k_rows(b, o, 127250, d), idrows=lambda b, o: n2k_idrows(b, o, cid))
        self.send_pgn("gw", 127250, {"SID": 0, "Heading": h, "Reference": 0}, info="Heading %.1f deg true (from the PC)" % h, kind="cmd")
        return None

    def _raw(self, v, send):
        d = hexdata(v["data"], 8)
        cid = j1939_id(6, v["pgn"], self.sa["gw"])
        if not send:
            return self.preview_can("gw", cid, d.ljust(8, b"\xff"), ext=True, dissect=lambda b, o: n2k_rows(b, o, v["pgn"], d), idrows=lambda b, o: n2k_idrows(b, o, cid))
        self.send_pgn("gw", v["pgn"], None, raw=d, info="PGN %d from the PC" % v["pgn"], kind="cmd")
        return None


# ================================================================ SeaTalkng
class SeaTalkNG(N2kNet):
    key, name = "seatalkng", "SeaTalkng"
    blurb = "Integrated marine systems"
    can_proto = "SeaTalkng"
    medium = "Raymarine SeaTalkng: NMEA 2000-compatible CAN (250 kbit/s) with blue backbone and white spur cables; Evolution autopilot, Axiom MFD, i70 / p70 heads, SeaTalk1 converter"
    faults = [("no_term1", "Backbone terminator missing", "One end unterminated: ringing on the backbone, frames start to fail."),
              ("stub", "Spur to the p70 extended to 12 m", "Spurs should be short (max 6 m in NMEA 2000): the long stub reflects and corrupts frames."),
              ("st1", "SeaTalk1 cable unplugged from the converter", "The legacy ST60 tridata disappears: no depth, speed or water temperature on SeaTalkng."),
              ("nohdg", "EV-1 heading sensor failed", "No 127250 heading: the autopilot refuses to engage and stays in standby."),
              ("power", "Power cable connected at the far end of the backbone", "Long backbone fed from one end: the farthest device sees a low supply voltage.")]
    spec = [("System", "Raymarine SeaTalkng (since 2007): NMEA 2000 at the protocol level, proprietary cabling"),
            ("Cabling", "Backbone (blue) with 5-way blocks and T-pieces, spurs (white), one 12 V power cable, terminators at both ends; DeviceNet adaptor cables to standard NMEA 2000"),
            ("Messages", "Standard NMEA 2000 PGNs plus Raymarine proprietary PGNs (manufacturer code 1851), e.g. 65379 pilot mode, 65360 locked heading, 126720 keystrokes"),
            ("SeaTalk1", "A SeaTalk1-SeaTalkng converter translates legacy datagrams (00 depth, 20 speed...) into PGNs"),
            ("Autopilot", "Evolution: EV-1 sensor core + course computer, ACU drives the rudder actuator; p70 control head sends keystrokes")]
    frame = [["Proprietary PGN payload", ("Mfr code 1851", 11), ("Res", 2), ("Industry 4", 3), ("Raymarine data", "n x 8")]]
    about = ("SeaTalkng is Raymarine's flavour of NMEA 2000: the same CAN messages and address claiming, with its own blue and white plug system and "
             "a set of proprietary messages for the autopilot. The p70 head even sends the old SeaTalk1 keystroke datagram (86 21 ...) wrapped "
             "inside a proprietary fast packet, and a converter brings old SeaTalk1 instruments onto the network.")
    guide = ["Watch the p70 keystroke PGN 126720: the SeaTalk1 datagram 86 21 YY yy sits inside it.",
             "COMPOSE 'Auto' then '+10': follow pilot mode (65379) and locked heading (65360).",
             "Find the depth from the SeaTalk1 converter: same data as datagram 00, now as PGN 128267.",
             "Fail the EV-1 and try to engage the pilot.",
             "Extend the p70 spur to 12 m and watch the error counters."]

    def setup(self):
        tops = [("mfd", "AXIOM MFD", "display", 0x00, 2, "Axiom 9"), ("ev1", "EV-1 SENSOR CORE", "compass", 0x0C, 1, "EV-1"), ("acu", "ACU-200 ACTUATOR", "drive", 0x0D, 1, "ACU-200"),
                ("p70", "p70s PILOT HEAD", "keypad", 0x0E, 1, "p70s")]
        bots = [("i70", "i70s DISPLAY", "display", 0x0F, 1, "i70s"), ("itc", "iTC-5 CONVERTER", "box", 0x10, 1, "iTC-5"), ("st1", "SEATALK1 CONVERTER", "box", 0x11, 1, "E22158"),
                ("pwr", "12 V POWER", "battery", None, 0, "")]
        nodes, devs = [], {}
        for i, (nid, lab, kind, sa, ln, model) in enumerate(tops + bots):
            top = i < 4
            x = 30 + 215 * (i if top else i - 4)
            n = self.node(nid, lab, kind, x, 40 if top else 290, ("0x%02X" % sa) if sa is not None else "", model, w=130)
            if not top:
                n.at_top()
            nodes.append(n)
            if sa is not None:
                fn, cls = {"mfd": (130, 120), "ev1": (160, 40), "acu": (150, 40), "p70": (150, 40), "i70": (130, 120), "itc": (135, 60), "st1": (135, 25)}[nid]
                devs[nid] = dict(sa=sa, name=n2k_name(0x2000 + i * 31, 1851, fn, cls), len=ln, model=model)
        y = 200
        xs = sorted(set([30, 860] + [n.port[0] for n in nodes]))
        blue, white = (40, 90, 200), (230, 230, 235)
        for i, (a, b) in enumerate(zip(xs, xs[1:])):
            self.seg([(a, y), (b, y)], "n2k", net="VDIFF", label="SeaTalkng backbone (blue)" if i == 2 else "", col=blue, w=7)
        for n in nodes:
            self.seg([n.port, (n.port[0], y)], "n2k", net="VDIFF", c0="stng", col=white, w=5)
        self.term(30, y, "TERM", True, "term0")
        self.term(860, y, "TERM", True, "term1")
        self.by["pwr"].extra["can"] = False
        self.n2k_init(devs)
        self.ship = Vessel(50.70, -1.45, 6.0, 210.0)
        self.ship.hdg = 212.0
        self.pmode, self.locked = 0, 212.0
        self.user = "p70"
        self.by["p70"].vars.update({"Pilot": "STANDBY", "Locked heading": "-"})
        self.by["i70"].vars.update({"Depth": "-", "Speed": "-", "Wind": "-", "Heading": "-"})
        self.by["mfd"].vars.update({"Pilot": "standby", "Rudder": "-"})
        for i, k in enumerate(devs):
            self.at(0.01 + 0.004 * i, self.claim, k)
        self.every(0.1, self.tick, 0.1)
        self.every(1.0, self.slow, 0.3)

    def tick(self):
        s = self.ship
        hdg_ok = not self.fault["nohdg"] and self.by["ev1"].on
        if self.pmode:
            if not hdg_ok:
                self.pmode = 0
                self.log("Autopilot dropped to standby: no heading data")
            else:
                e = (self.locked - s.hdg + 540) % 360 - 180
                s.rudder = max(-25.0, min(25.0, e * 2.0))
                s.hdg = (s.hdg + s.rudder * 0.02) % 360
        else:
            s.rudder = 0.0
        s.step(0.1, self.rng)
        self.sid = (self.sid + 1) % 253
        if hdg_ok:
            self.send_pgn("ev1", 127250, {"SID": self.sid, "Heading": s.hdg, "Reference": 1}, info="Heading %.1f deg (magnetic)" % s.hdg)
            self.by["i70"].vars["Heading"] = "%.0f deg M" % s.hdg
        else:
            self.by["i70"].vars["Heading"] = "---"
        self.send_pgn("acu", 127245, {"Instance": 0, "Direction order": 0, "Position": s.rudder}, info="Rudder %+.1f deg" % s.rudder)
        self.by["mfd"].vars["Rudder"] = "%+.1f deg" % s.rudder

    def slow(self):
        s = self.ship
        mode = {0: 0, 1: 64}[self.pmode]
        self.send_pgn("ev1", 65379, {"Manufacturer code": 1851, "Industry code": 4, "Pilot mode": mode, "Sub mode": 0, "Pilot mode data": 0},
                      info="Pilot mode: %s" % ("AUTO" if mode else "STANDBY"))
        self.send_pgn("ev1", 65359, {"Manufacturer code": 1851, "Industry code": 4, "SID": self.sid, "Heading magnetic": s.hdg}, info="Pilot heading %.1f deg" % s.hdg)
        if self.pmode:
            self.send_pgn("ev1", 65360, {"Manufacturer code": 1851, "Industry code": 4, "SID": self.sid, "Target heading magnetic": self.locked}, info="Locked heading %.0f deg" % self.locked)
        p = self.by["p70"]
        p.vars["Pilot"] = "AUTO" if self.pmode else "STANDBY"
        p.vars["Locked heading"] = "%.0f" % self.locked if self.pmode else "-"
        self.by["mfd"].vars["Pilot"] = "auto %.0f" % self.locked if self.pmode else "standby"
        i70 = self.by["i70"]
        if not self.fault["st1"]:
            self.send_pgn("st1", 128267, {"SID": self.sid, "Depth": s.depth, "Offset": 0.0}, info="Depth %.1f m (from SeaTalk1 datagram 00)" % s.depth)
            self.send_pgn("st1", 128259, {"SID": self.sid, "Speed water referenced": s.stw * 0.514444, "Speed type": 0}, info="STW %.1f kn (from SeaTalk1 datagram 20)" % s.stw)
            i70.vars.update({"Depth": "%.1f m" % s.depth, "Speed": "%.1f kn" % s.stw})
        else:
            i70.vars.update({"Depth": "---", "Speed": "---"})
        self.send_pgn("itc", 130306, {"SID": self.sid, "Wind speed": s.aws * 0.514444, "Wind angle": s.awa, "Reference": 2}, info="Apparent wind %.0f deg %.1f kn (analog vane)" % (s.awa, s.aws))
        i70.vars["Wind"] = "%.0f deg %.1f kn" % (s.awa, s.aws)
        if self.fault["power"]:
            self.by["i70"].vars["Supply"] = "8.9 V (low!)"
        else:
            self.by["i70"].vars.pop("Supply", None)

    def keystroke(self, code, send=True):
        data = bytes([0x3B, 0x9F, 0xF0, 0x81, 0x86, 0x21, code, code ^ 0xFF]) + bytes.fromhex("ffffffffffc1c2cd6680d342b1c8")
        if not send:
            cid = j1939_id(7, 126720, self.sa["p70"])
            return self.preview_can("p70", cid, data[:8], ext=True, dissect=lambda b, o: n2k_rows(b, o, 126720, data), idrows=lambda b, o: n2k_idrows(b, o, cid))
        self.send_pgn("p70", 126720, None, raw=data, info="p70 keystroke: %s (SeaTalk1 86 21 %02X %02X inside)" % (ST_KEYS.get(code, "?"), code, code ^ 0xFF), kind="cmd")
        if code == 0x01:
            if self.fault["nohdg"] or not self.by["ev1"].on:
                self.log("Auto refused: no heading from the EV-1")
                self.by["p70"].state = "NO PILOT HEADING"
            else:
                self.pmode, self.locked = 1, round(self.ship.hdg)
                self.by["p70"].state = ""
        elif code == 0x02:
            self.pmode = 0
        elif code in (0x05, 0x06, 0x07, 0x08) and self.pmode:
            self.locked = (self.locked + {0x05: -1, 0x06: -10, 0x07: 1, 0x08: 10}[code]) % 360
        return None

    def tpls(self):
        return [Tpl("p70 keystroke", [P("k", "Key", 0x01, opts=[0x01, 0x02, 0x05, 0x06, 0x07, 0x08], fmt=lambda v: "%s (0x%02X)" % (ST_KEYS[v], v))],
                    lambda s, v, send: self.keystroke(v["k"], send), "Raymarine proprietary PGN 126720 (fast packet) carrying the SeaTalk1 keystroke datagram."),
                Tpl("ISO Request: product information", [P("da", "Device", "ev1", opts=["ev1", "acu", "i70", "itc", "st1"], fmt=lambda v: self.by[v].label)],
                    lambda s, v, send: self.request("mfd", 126996, self.sa[v["da"]], send), "The MFD asks a device for PGN 126996.")]


# ================================================================== OneNet
class OneNet(IpNet):
    key, name, cat = "onenet", "NMEA OneNet", "marine"
    blurb = "Ethernet-based marine networking"
    phy = "eth100"
    medium = "NMEA OneNet: IPv6 over Ethernet (Cat5e+, RJ45 / X-coded M12), PoE switch, MFD, radar, thermal camera, engine monitor and a gateway to NMEA 2000"
    faults = [("poe", "PoE budget set to 30 W", "Radar (25.5 W) + camera (13 W) exceed the switch budget: the lower-priority camera port is not powered."),
              ("dad", "Engine monitor has a duplicate interface ID", "IPv6 Duplicate Address Detection finds the address in use: the monitor must not use it and stays offline."),
              ("pair", "Camera not paired with the secure network", "Its messages fail authentication: listeners discard them."),
              ("gw", "Gateway loses its NMEA 2000 backbone", "The mapped GNSS and depth devices disappear from OneNet.")]
    spec = [("Standard", "NMEA OneNet v1.0 (2020+), members-only specification; complements NMEA 2000"),
            ("Physical", "IEEE 802.3 Ethernet, 100 Mbit/s to 10 Gbit/s, Cat5e minimum; RJ45 in protected areas, X-coded M12 (IP67) when exposed"),
            ("Power", "PoE up to 25.5 W per device (IEEE 802.3at)"),
            ("Network", "IPv6 only: link-local addresses from the MAC (EUI-64), Duplicate Address Detection, multicast"),
            ("Messages", "NMEA 2000 PGN messages carried over IPv6 with priority, PGN, source and destination; plus high-bandwidth radar, sonar and video"),
            ("Security", "OneNet Secure network: devices are certified and paired; messages are encrypted and authenticated (TLS)"),
            ("Note", "The exact UDP ports and binary layout are in the members-only standard: this simulator shows the published fields with an illustrative encoding")]
    frame = [["OneNet PGN message (illustrative)", ("Priority", 8), ("PGN", 24), ("Source", 64), ("Destination", 64), ("Length", 16), ("PGN data", "n x 8"), ("Auth tag", 128)]]
    about = ("OneNet is NMEA's Ethernet standard: the same PGN messages as NMEA 2000, but on IPv6 at hundreds of megabits, so radar, sonar and "
             "video can share the network with navigation data. Devices configure their own link-local addresses, power comes over the cable, "
             "gateways map NMEA 2000 devices onto Ethernet, and a secure mode pairs certified devices so messages can be authenticated.")
    guide = ["Watch each device start: IPv6 Duplicate Address Detection (Neighbor Solicitation from ::) before it uses its address.",
             "Follow the pairing (TLS handshake) of the camera with the MFD.",
             "Compare a small PGN message from the gateway with the large radar and video packets in STATS.",
             "Set the PoE budget to 30 W and see which device loses power."]

    def setup(self):
        hosts = [("mfd", "MFD (chartplotter)", "display", 40, 40, "fe80::21a:2bff:fe00:11", "00:1a:2b:00:00:11", "secure mode on"),
                 ("radar", "RADAR (PoE+ 25.5 W)", "radar", 700, 40, "fe80::21a:2bff:fe00:22", "00:1a:2b:00:00:22"),
                 ("cam", "THERMAL CAMERA (13 W)", "camera", 40, 290, "fe80::21a:2bff:fe00:33", "00:1a:2b:00:00:33"),
                 ("gw", "OneNet-N2K GATEWAY", "gw", 380, 300, "fe80::21a:2bff:fe00:44", "00:1a:2b:00:00:44", "maps 2 N2K devices"),
                 ("eng", "ENGINE MONITOR", "engine", 700, 290, "fe80::21a:2bff:fe00:55", "00:1a:2b:00:00:55")]
        self.star(hosts, sw=("sw", "OneNet PoE SWITCH", 380, 160), style="cat6", conn="m12")
        self.by["gw"].at_top()
        self.user = "mfd"
        self.ship = Vessel()
        self.ready = set()
        self.by["sw"].vars.update({"PoE budget": "60 W", "PoE used": "-"})
        self.by["mfd"].vars.update({"Devices": "-", "Position": "-", "Depth": "-", "Engine": "-", "Radar": "-", "Video": "-"})
        for i, k in enumerate(("mfd", "radar", "cam", "gw", "eng")):
            self.at(0.01 + 0.03 * i, self.start, k)
        self.every(0.1, self.pgns, 0.5)
        self.every(0.04, self.radar_tx, 0.6)
        self.every(0.0333, self.video_tx, 0.65)
        self.every(1.0, self.status, 0.7)

    def start(self, k):
        n = self.by[k]
        if k == "cam" and self.fault["poe"]:
            n.on = False
            n.state = "NO PoE POWER"
            return
        n.on = True
        n.state = ""
        ip6 = self.lan.ip6[k]
        tail = bytes.fromhex(ip6.split(":")[-1].zfill(4))
        sol = "ff02::1:ff00:%04x" % int(ip6.split(":")[-1], 16)
        icmp = Bld("ICMPv6 Neighbor Solicitation (Duplicate Address Detection)", "RFC 4861/4862: before using an address, ask whether anyone already has it")
        icmp.u8("Type", 135, "135 Neighbor Solicitation", "")
        icmp.u8("Code", 0, None, "")
        icmp.u16("Checksum", 0x6A2F, "0x6A2F", "")
        icmp.raw("Reserved", bytes(4), None, "")
        icmp.raw("Target address", ipb6(ip6), ip6, "The tentative address being tested")
        pdu = eth_pdu("33:33:ff:00:%02x:%02x" % (tail[0], tail[1]), self.lan.mac[k], 0x86DD, ipv6_pdu("::", sol, 58, icmp.done(), hlim=255))
        self.lan.send(self.lan.frame(k, None, pdu, "DAD: Neighbor Solicitation for %s (from ::)" % ip6, "ICMPv6", "ctl"))
        if k == "eng" and self.fault["dad"]:
            na = Bld("ICMPv6 Neighbor Advertisement", "Another node already owns this address")
            na.u8("Type", 136, "136 Neighbor Advertisement", "")
            na.u8("Code", 0, None, "")
            na.u16("Checksum", 0x1B2C, None, "")
            na.u32("Flags", 0x20000000, "Override", "")
            na.raw("Target address", ipb6(ip6), ip6, "")
            pdu2 = eth_pdu("33:33:00:00:00:01", self.lan.mac["radar"], 0x86DD, ipv6_pdu(self.lan.ip6["radar"], "ff02::1", 58, na.done(), hlim=255))
            self.at(self.t + 0.002, lambda: self.lan.send(self.lan.frame("radar", None, pdu2, "Neighbor Advertisement: %s is already in use!" % ip6, "ICMPv6", "err",
                                                                         err="Duplicate address detected")))
            n.state = "DUPLICATE ADDRESS"
            self.log("Engine monitor: DAD failed, interface stays offline")
            return
        self.at(self.t + 1.0, self.online, k)

    def online(self, k):
        self.ready.add(k)
        if k != "mfd":
            self.pair(k)

    def pair(self, k):
        c = self.tcp(k, "mfd", 49152 + len(self.ready), 443, "TLS")
        bad = k == "cam" and self.fault["pair"]

        def hs():
            c.send(k, tls_hs(1, [("OneNet device certificate presented", "Issued by the NMEA certification tool")]), "TLS ClientHello (%s joins the secure network)" % self.by[k].label, "TLS", "ctl")
            if bad:
                al = tls_record(21, bytes([2, 46]), "Fatal alert: certificate_unknown (device not paired)")
                self.at(self.t + 0.002, lambda: c.send("mfd", al, "TLS Alert: device not paired - rejected", "TLS", "err", err="Pairing missing"))
                self.by[k].state = "NOT PAIRED"
                return
            self.at(self.t + 0.002, lambda: c.send("mfd", tls_hs(2), "TLS ServerHello + EncryptedExtensions + Finished", "TLS", "ctl"))
            self.at(self.t + 0.004, lambda: c.send(k, tls_hs(20), "TLS Finished: secure session established", "TLS", "ctl"))
            self.by[k].state = ""
        c.connect(on_open=hs)

    def pgn_msg(self, src, pgn, payload, info, dst=None, kind="data", big=None):
        b = Bld("OneNet PGN message (illustrative encoding)", "Published fields: priority, PGN, source, destination, data")
        prio = N2K.get(pgn, ("", 6))[1]
        b.u8("Priority", prio, None, "")
        b.u24("PGN", pgn, "%d %s" % (pgn, N2K.get(pgn, ("",))[0]), "Same PGN numbers as NMEA 2000")
        b.raw("Source (interface ID)", ipb6(self.lan.ip6[src])[8:], self.lan.ip6[src], "OneNet devices are identified by their IPv6 identity, not an 8-bit address")
        b.raw("Destination", b"\xff" * 8, "all (multicast)", "")
        b.u16("Length", len(payload), None, "")
        k = len(b.b)
        b.raw("PGN data (encrypted on the wire)", payload, None, "Shown decrypted by the simulator")
        tmp = Bld()
        n2k_rows(tmp, 0, pgn, payload)
        for r in tmp.rows:
            b.rows.append([r[0] + 1, r[1], None if r[2] is None else r[2] + k, r[3], r[4]])
        b.raw("Authentication tag", bytes((i * 29 + pgn) & 255 for i in range(16)), None, "Receivers verify it before using the data")
        bad = src == "cam" and self.fault["pair"]
        self.lan.udp(src, dst, 50100, 50100, b.done(), info, "OneNet", kind, dip="ff02::1", dmac="33:33:00:00:00:01", v6=True,
                     err="Authentication failed: sender not paired" if bad else None)

    def pgns(self):
        s = self.ship
        s.step(0.1, self.rng)
        if "gw" in self.ready and not self.fault["gw"]:
            self.pgn_msg("gw", 129025, n2k_encode(129025, {"Latitude": s.lat, "Longitude": s.lon}), "PGN 129025 position (mapped N2K GNSS)")
            if int(self.t * 10) % 10 == 0:
                self.pgn_msg("gw", 128267, n2k_encode(128267, {"SID": 1, "Depth": s.depth, "Offset": 0.4}), "PGN 128267 depth (mapped N2K transducer)")
        if "eng" in self.ready:
            self.pgn_msg("eng", 127488, n2k_encode(127488, {"Instance": 0, "Speed": 2150 + 20 * math.sin(self.t)}), "PGN 127488 engine rapid update")

    def radar_tx(self):
        if "radar" not in self.ready or not self.by["radar"].on:
            return
        b = Bld("Radar spoke data (proprietary over UDP)", "High-bandwidth stream that NMEA 2000 could never carry")
        b.u16("Spoke angle", int(self.t * 2048 / 2.5) % 4096, None, "4096 spokes per revolution, 24 rpm")
        b.raw("Echo samples", bytes(int(120 + 100 * math.sin(i / 9.0)) & 255 for i in range(64)), "1024 samples (first 64 shown)", "")
        self.lan.udp("radar", "mfd", 50200, 50200, b.done(), "Radar spokes %d-%d" % (int(self.t * 819) % 4096, (int(self.t * 819) + 32) % 4096), "Radar", "data", v6=True)

    def video_tx(self):
        if "cam" not in self.ready or not self.by["cam"].on:
            return
        b = Bld("RTP (RFC 3550) H.264 video", "")
        b.u8("V / P / X / CC", 0x80, "version 2", "")
        b.u8("M / payload type", 96, "96 (dynamic: H.264)", "")
        b.u16("Sequence number", int(self.t * 30) & 0xFFFF, None, "")
        b.u32("Timestamp", int(self.t * 90000) & 0xFFFFFFFF, None, "90 kHz video clock")
        b.u32("SSRC", 0x5EC0CA11, None, "")
        b.raw("H.264 NAL unit", bytes(48), "~1200 bytes (first 48 shown)", "")
        err = "Authentication failed: camera not paired" if self.fault["pair"] else None
        self.lan.udp("cam", "mfd", 5004, 5004, b.done(), "Thermal video RTP seq %d" % (int(self.t * 30) & 0xFFFF), "RTP", "data", v6=True, err=err)

    def status(self):
        sw = self.by["sw"]
        budget = 30 if self.fault["poe"] else 60
        used = 25.5 + (13 if self.by["cam"].on else 0) + 4 + (6 if self.by["eng"].on else 0)
        sw.vars.update({"PoE budget": "%d W" % budget, "PoE used": "%.1f W" % used})
        m = self.by["mfd"]
        m.vars["Devices"] = ", ".join(sorted(self.by[k].label.split(" ")[0] for k in self.ready if k != "mfd")) or "-"
        m.vars["Position"] = "%.5f, %.5f" % (self.ship.lat, self.ship.lon) if "gw" in self.ready and not self.fault["gw"] else "NO SOURCE"
        m.vars["Depth"] = "%.1f m" % (self.ship.depth + 0.4) if "gw" in self.ready and not self.fault["gw"] else "NO SOURCE"
        m.vars["Engine"] = "2150 rpm" if "eng" in self.ready else "-"
        m.vars["Radar"] = "image (24 rpm)" if "radar" in self.ready else "-"
        m.vars["Video"] = "thermal camera" if ("cam" in self.ready and self.by["cam"].on and not self.fault["pair"]) else "NO VIDEO"

    def on_fault(self, key, on):
        if key == "poe":
            if on:
                self.by["cam"].on = False
                self.by["cam"].state = "NO PoE POWER"
                self.ready.discard("cam")
                self.log("PoE budget 30 W: camera port powered down")
            else:
                self.at(self.t + 0.1, self.start, "cam")
        if key == "dad" and not on:
            self.by["eng"].state = ""
            self.at(self.t + 0.1, self.start, "eng")
        if key == "dad" and on:
            self.ready.discard("eng")
            self.at(self.t + 0.1, self.start, "eng")
        if key == "pair" and not on and "cam" in self.ready:
            self.pair("cam")

    def tpls(self):
        return [Tpl("Request product information", [P("d", "Device", "gw", opts=["gw", "eng", "radar", "cam"], fmt=lambda v: self.by[v].label)], lambda s, v, send: self._pi(v["d"], send),
                    "OneNet PGN 59904 request; the device answers with 126996.")]

    def _pi(self, d, send):
        if not send:
            b = Bld("OneNet PGN message (illustrative)", "")
            b.u24("PGN", 59904, "59904 ISO Request", "")
            b.u24("Requested PGN", 126996, "126996 Product Information", "")
            return Frame(self.t, 1e-5, "mfd", d, "OneNet", "preview", pdu=b.done())
        if "mfd" not in self.ready:
            return None
        self.pgn_msg("mfd", 59904, struct.pack("<I", 126996)[:3], "ISO Request: product information from %s" % self.by[d].label, kind="cmd")
        if d in self.ready:
            pi = n2k_encode(126996, {"NMEA 2000 version": 3.0, "Product code": 77, "Model ID": self.by[d].label, "Software version code": "OneNet 1.000", "Model version": "B",
                                     "Model serial code": "0099123", "Certification level": 2, "Load equivalency (LEN)": 0})
            self.at(self.t + 0.002, self.pgn_msg, d, 126996, pi, "Product information: %s" % self.by[d].label, None, "resp")
        return None


def ipb6(a):
    import ipaddress
    return ipaddress.IPv6Address(a).packed


# ========================================================== IEC 61162-450
LWE = {"MISC": ("239.192.0.1", 60001), "TGTD": ("239.192.0.2", 60002), "SATD": ("239.192.0.3", 60003), "NAVD": ("239.192.0.4", 60004), "VDRD": ("239.192.0.5", 60005)}


def lwe_mac(ip):
    o = [int(x) for x in ip.split(".")]
    return "01:00:5e:%02x:%02x:%02x" % (o[1] & 0x7F, o[2], o[3])


def lwe_pdu(sfi, n, line, tag=True, extra=""):
    if tag:
        body = "s:%s,n:%d%s" % (sfi, n, extra)
        text = "\\%s*%02X\\%s" % (body, nmea_cs(body), line)
    else:
        text = line
    hdr = b"UdPbC\x00"
    rows = [[0, "IEC 61162-450 header: UdPbC\\0", 0, 6, "6-byte token: 'UdPbC' + NUL = sentence datagram ('RaUdP' / 'RrUdP' = binary file transfer)"]]
    return sentence_pdu(text, prefix=(hdr, rows))


class IEC61162_450(IpNet):
    key, name, cat = "iec61162_450", "IEC 61162-450", "marine"
    blurb = "Ship networking over Ethernet"
    medium = "IEC 61162-450 'lightweight Ethernet': UDP multicast transmission groups (239.192.0.x, ports 60001+), TAG blocks with system function IDs, IGMP filtering"
    faults = [("sfi", "Second gyro configured with the same SFI (HE0001)", "Listeners can no longer tell the two heading sources apart: the ECDIS reports duplicate source IDs."),
              ("loss", "Switch port overloaded: datagrams dropped", "The TAG block line counter (n:) jumps: listeners detect and count the lost datagrams."),
              ("bcast", "Serial gateway set to broadcast 255.255.255.255", "IEC 61162-450 only allows the defined multicast groups: listeners ignore it, the echo sounder data never reaches the ECDIS."),
              ("notag", "Serial gateway sends sentences without TAG blocks", "The TAG block with a source (s:) is mandatory: listeners reject the datagrams.")]
    spec = [("Standard", "IEC 61162-450 Ed. 3 (2024); security add-on IEC 61162-460; carries IEC 61162-1 sentences and (Ed. 2+) IEC 61162-3 PGNs"),
            ("Transport", "UDP over IPv4 multicast, one group per kind of data: MISC 239.192.0.1:60001, TGTD .2:60002, SATD .3:60003, NAVD .4:60004, VDRD .5:60005 ..."),
            ("Datagram", "'UdPbC\\0' header + TAG block \\s:SFI,n:count*hh\\ + one or more sentences"),
            ("SFI", "System Function ID: 2 letters + 4 digits (e.g. HE0001), unique per function on the network"),
            ("Binary", "Radar images and VDR files use 'RaUdP' / 'RrUdP' binary transfer with retransmission"),
            ("Network", "IGMP (snooping) keeps multicast off ports that did not join; serial devices connect via a serial-to-network gateway (SNGF)")]
    frame = [["Datagram", ("UdPbC\\0", 48), ("TAG block \\s:..,n:..*hh\\", "n x 8"), ("$sentence*hh", "n x 8")]]
    about = ("IEC 61162-450 moves the classic bridge sentences onto Ethernet: every talker sends its sentences as UDP multicast to a transmission "
             "group (heading to SATD, navigation to NAVD, targets to TGTD) and any number of listeners join the groups they need. A TAG block in "
             "front of each sentence names the source (system function ID) and numbers the datagrams so lost ones are noticed. Serial devices "
             "join through gateways, and the VDR simply listens to everything.")
    guide = ["Watch the IGMP membership reports: each listener joins only the groups it needs.",
             "Select a gyro datagram: header UdPbC, TAG block (s:HE0001, n:...) and the HDT sentence.",
             "Compare the transmission groups in STATS: SATD is the busiest (10 Hz heading).",
             "Drop datagrams (fault) and look for gaps in the n: counter.",
             "Remove the TAG blocks from the serial gateway and watch the ECDIS reject the echo sounder."]

    def setup(self):
        hosts = [("gyro", "GYROCOMPASS", "compass", 30, 30, "172.16.1.11", "00:50:c2:01:00:11", "SFI HE0001"), ("gnss", "GNSS", "gps", 200, 30, "172.16.1.12", "00:50:c2:01:00:12", "SFI GN0001"),
                 ("ais", "AIS TRANSPONDER", "radio", 560, 30, "172.16.1.13", "00:50:c2:01:00:13", "SFI AI0001"), ("radar", "X-BAND RADAR", "radar", 730, 30, "172.16.1.14", "00:50:c2:01:00:14", "SFI RA0001"),
                 ("sngf", "SERIAL GATEWAY", "box", 30, 300, "172.16.1.20", "00:50:c2:01:00:20", "echo sounder SD0001"), ("ecdis", "ECDIS", "display", 380, 300, "172.16.1.30", "00:50:c2:01:00:30", "SFI EC0001"),
                 ("vdr", "VOYAGE DATA RECORDER", "store", 730, 300, "172.16.1.40", "00:50:c2:01:00:40", "listens to all")]
        self.star(hosts, sw=("sw", "BRIDGE SWITCH (IGMP)", 380, 160), style="cat6", conn="rj45")
        self.ship = Vessel(50.62, -1.05, 13.8, 241.0)
        self.ship.hdg = 238.0
        self.n = {k: 0 for k in ("gyro", "gyro2", "gnss", "ais", "radar", "sngf", "ecdis")}
        self.user = "ecdis"
        self.by["ecdis"].vars.update({"Heading": "-", "Position": "-", "Depth": "-", "Targets": 0, "Lost datagrams": 0, "Alerts": "none"})
        self.by["vdr"].vars.update({"Recorded datagrams": 0})
        self.at(0.01, self.igmp)
        self.every(0.1, self.gyro_tx, 0.05)
        self.every(1.0, self.gnss_tx, 0.2)
        self.every(1.0, self.sngf_tx, 0.4)
        self.every(2.0, self.targets, 0.6)
        self.every(0.1, lambda: self.ship.step(0.1, self.rng), 0.0)

    def igmp(self):
        joins = {"ecdis": ["SATD", "NAVD", "TGTD", "MISC"], "radar": ["SATD", "NAVD"], "vdr": list(LWE.keys()), "ais": ["SATD", "NAVD"]}
        k = 0
        for who, groups in joins.items():
            for g in groups:
                ip, _ = LWE[g]
                b = Bld("IGMPv2 Membership Report", "RFC 2236: 'I want multicast traffic for this group' - the switch learns which ports need it")
                b.u8("Type", 0x16, "0x16 v2 membership report", "")
                b.u8("Max response time", 0, None, "")
                b.u16("Checksum", 0xFA04, None, "")
                b.raw("Group address", ipb(ip), "%s (%s)" % (ip, g), "")
                pdu = eth_pdu(lwe_mac(ip), self.lan.mac[who], 0x0800, ipv4_pdu(self.lan.ip[who], ip, 2, b.done(), ttl=1))
                self.at(self.t + 0.002 * k, lambda w=who, p=pdu, g=g, ip=ip: self.lan.send(self.lan.frame(w, None, p, "IGMP join %s %s" % (g, ip), "IGMP", "ctl")))
                k += 1

    def dgram(self, src, grp, line, sfi=None, info=None, kind="data", dst=None):
        n = self.by[src if src != "gyro2" else "gyro"]
        if not n.on:
            return
        key = src
        self.n[key] = self.n[key] % 999 + 1
        if self.fault["loss"] and self.rng.random() < 0.15:
            self.n[key] = self.n[key] % 999 + 1
            self.by["ecdis"].vars["Lost datagrams"] += 1
        tag = not (src == "sngf" and self.fault["notag"])
        pdu = lwe_pdu(sfi, self.n[key], line, tag)
        ip, port = LWE[grp]
        err = None
        if not tag:
            err = "No TAG block: rejected by IEC 61162-450 listeners"
        dip, dmac = ip, lwe_mac(ip)
        if src == "sngf" and self.fault["bcast"]:
            dip, dmac = "255.255.255.255", "ff:ff:ff:ff:ff:ff"
            err = "Broadcast is not allowed: listeners only receive the multicast groups"
        if dst is None:
            dst = {"SATD": ["ecdis", "radar", "vdr", "ais"], "NAVD": ["ecdis", "radar", "vdr", "ais"], "TGTD": ["ecdis", "vdr"], "MISC": ["ecdis", "vdr"]}.get(grp)
        src_node = "gyro" if src == "gyro2" else src
        self.lan.udp(src_node, dst, 50000 + list(LWE).index(grp), port, pdu, info or "[%s] %s" % (grp, line.strip()), "IEC 61162-450", kind, dip=dip, dmac=dmac, err=err)
        self.by["vdr"].vars["Recorded datagrams"] += 1
        return err is None

    def gyro_tx(self):
        s = self.ship
        self.dgram("gyro", "SATD", sentence("HEHDT,%.1f,T" % s.hdg), "HE0001")
        if int(self.t * 10) % 2 == 0:
            self.dgram("gyro", "SATD", sentence("HEROT,%.1f,A" % s.rot), "HE0001")
        self.by["ecdis"].vars["Heading"] = "%.1f T" % s.hdg
        if self.fault["sfi"] and int(self.t * 10) % 3 == 0:
            self.dgram("gyro2", "SATD", sentence("HEHDT,%.1f,T" % ((s.hdg + 1.8) % 360)), "HE0001", info="[SATD] second gyro, same SFI HE0001: $HEHDT,%.1f" % ((s.hdg + 1.8) % 360))
            self.by["ecdis"].vars["Alerts"] = "DUPLICATE SFI HE0001 (two heading sources)"

    def gnss_tx(self):
        s, t = self.ship, self.t
        for line in (gga(s, t, "GN"), rmc(s, t, "GN")):
            self.dgram("gnss", "NAVD", line, "GN0001")
        self.by["ecdis"].vars["Position"] = "%s %s, %s %s" % (nmea_lat(s.lat) + nmea_lon(s.lon))
        if not self.fault["sfi"]:
            self.by["ecdis"].vars["Alerts"] = "none"

    def sngf_tx(self):
        ok = self.dgram("sngf", "NAVD", sentence("SDDPT,%.1f,1.5,200" % (self.ship.depth + 30)), "SD0001")
        self.by["ecdis"].vars["Depth"] = ("%.1f m" % (self.ship.depth + 30)) if ok else "NO DATA (gateway misconfigured)"

    def targets(self):
        self.dgram("ais", "TGTD", "!AIVDM,1,1,,A,13u?etPv2;0n:dDPwUM1U1Cb069D,0*24\r\n", "AI0001", info="[TGTD] AIS target report (VDM)")
        self.dgram("radar", "TGTD", sentence("RATTM,05,3.2,124.5,T,11.8,245.0,T,0.6,14.2,N,TGT05,T,,%s,A" % utc(self.t).strftime("%H%M%S.00")), "RA0001",
                   info="[TGTD] radar tracked target 05: 3.2 NM, 124.5 deg, CPA 0.6 NM")
        self.by["ecdis"].vars["Targets"] = 2

    def tpls(self):
        return [Tpl("ECDIS alert (ALR) to MISC", [P("txt", "Alert text", "ROUTE DEVIATION")], lambda s, v, send: self._alr(v["txt"], send), "Published in the MISC group with the ECDIS SFI EC0001."),
                Tpl("Custom sentence to a group", [P("g", "Group", "MISC", opts=list(LWE.keys())), P("s", "Sentence body", "ECTXT,01,01,01,BRIDGE TEST")],
                    lambda s, v, send: self._custom(v, send), "Any IEC 61162-1 sentence, wrapped in a TAG block and sent to the chosen transmission group.")]

    def _alr(self, txt, send):
        line = sentence("ECALR,%s,005,A,V,%s" % (utc(self.t).strftime("%H%M%S.00"), txt[:40]))
        if not send:
            return Frame(self.t, 1e-5, "ecdis", None, "IEC 61162-450", "preview", pdu=lwe_pdu("EC0001", self.n["ecdis"] + 1, line))
        self.dgram("ecdis", "MISC", line, "EC0001", kind="evt", dst=["vdr"])
        return None

    def _custom(self, v, send):
        line = sentence(v["s"].strip().lstrip("$").split("*")[0])
        if not send:
            return Frame(self.t, 1e-5, "ecdis", None, "IEC 61162-450", "preview", pdu=lwe_pdu("EC0001", self.n["ecdis"] + 1, line))
        self.dgram("ecdis", v["g"], line, "EC0001", kind="cmd", dst=["vdr"])
        return None


# ================================================================ Signal K
SK_SELF = "vessels.urn:mrn:imo:mmsi:235112233"


class SignalK(IpNet):
    key, name, cat = "signalk", "Signal K", "marine"
    blurb = "Open marine data format and APIs"
    medium = "Signal K: a server (Raspberry Pi, signalk-server) turns NMEA 2000 / 0183 into JSON; apps use HTTP REST and WebSocket streams over the boat's Wi-Fi"
    faults = [("units", "Plugin publishes speed in knots", "Signal K values are SI (m/s, radians, Kelvin): the apps convert 6.2 'm/s' to 12.1 kn - wrong speed everywhere."),
              ("stale", "NMEA 2000 USB gateway unplugged", "No new data: the server stops sending deltas, the apps keep showing old values with old timestamps."),
              ("sub", "Tablet subscribes to a misspelled path", "'navigation.speedOverGrnd' does not exist: the speed widget never gets data."),
              ("auth", "Server security on, phone has no token", "The anchor light PUT is answered 401 Unauthorized.")]
    spec = [("Project", "Open-source specification (signalk.org), JSON data model, current spec v1.7"),
            ("Model", "Full model: vessels.<id>.navigation.position, environment.depth.belowTransducer ...; values in SI units with $source and timestamp"),
            ("Delta", "{context, updates:[{source, timestamp, values:[{path, value}]}]} - only what changed"),
            ("Transport", "WebSocket stream /signalk/v1/stream (subscribe / unsubscribe messages), REST /signalk/v1/api/..., discovery GET /signalk, mDNS"),
            ("Control", "PUT requests (switches, autopilot) with request state PENDING / COMPLETED; notifications.* paths for alarms"),
            ("Server", "signalk-server (Node.js, port 3000): converts NMEA 0183 / NMEA 2000 (canboatjs), plugins, data logging")]
    frame = [["Delta message (JSON)", ("context", "text"), ("updates[].source", "text"), ("timestamp", "text"), ("values[].path", "text"), ("values[].value", "text")]]
    about = ("Signal K is a free, open way to get boat data into apps and the internet. A small server reads the boat's NMEA 2000 and 0183 "
             "networks and describes everything as one JSON tree - navigation.speedOverGround, environment.wind.angleApparent - always in SI units. "
             "Apps discover the server, open a WebSocket and subscribe to the paths they need, receiving compact 'delta' updates; REST calls "
             "read or change single values.")
    guide = ["Watch the tablet start: discovery GET /signalk, WebSocket upgrade (HTTP 101), the server's hello, the subscription.",
             "Select a delta: path, value (m/s and radians!) and $source (which NMEA 2000 device).",
             "COMPOSE a REST GET for the position, then a PUT to switch on the anchor light.",
             "Turn on the knots-instead-of-m/s plugin fault and compare the tablet's speed with the real one."]

    def setup(self):
        hosts = [("srv", "SIGNAL K SERVER", "server", 40, 40, "192.168.1.10", "b8:27:eb:00:00:10", "Raspberry Pi, port 3000"),
                 ("tab", "TABLET APP", "display", 700, 40, "192.168.1.20", "a4:5e:60:00:00:20", "WebSocket client"),
                 ("kip", "DASHBOARD (browser)", "pc", 700, 290, "192.168.1.21", "a4:5e:60:00:00:21", "KIP instruments"),
                 ("phone", "PHONE", "phone", 40, 290, "192.168.1.22", "a4:5e:60:00:00:22", "REST client")]
        self.star(hosts, sw=("ap", "WI-FI ROUTER", 380, 160), style="radio", conn=None)
        self.ship = Vessel()
        self.user = "phone"
        self.ws = {}
        self.light = 0
        self.by["srv"].vars.update({"Sources": "n2k.2 GNSS, n2k.35 depth, n2k.5 wind", "Clients": 0})
        self.by["tab"].vars.update({"SOG": "-", "Depth": "-", "Position": "-", "Last update": "-"})
        self.by["kip"].vars.update({"Wind": "-", "Heading": "-"})
        self.by["phone"].vars.update({"Anchor light": "off", "Last REST": "-"})
        self.at(0.05, self.connect, "tab", ["navigation.speedOverGround", "environment.depth.belowTransducer", "navigation.position"])
        self.at(0.25, self.connect, "kip", ["environment.wind.angleApparent", "environment.wind.speedApparent", "navigation.headingMagnetic"])
        self.every(1.0, self.deltas, 1.0)
        self.every(0.2, lambda: self.ship.step(0.2, self.rng), 0.0)
        self.last_ok = 0.0

    def connect(self, cli, paths):
        c = self.tcp(cli, "srv", 51000 + len(self.ws), 3000, "HTTP")
        st = {"c": c, "paths": paths, "open": False}
        self.ws[cli] = st

        def on_open():
            disc = jdump({"endpoints": {"v1": {"version": "1.7.0", "signalk-http": "http://192.168.1.10:3000/signalk/v1/api/",
                                               "signalk-ws": "ws://192.168.1.10:3000/signalk/v1/stream"}}, "server": {"id": "signalk-server-node", "version": "2.8.0"}}).encode()
            c.send(cli, http_req("GET", "/signalk", [("Host", "192.168.1.10:3000"), ("Accept", "application/json")]), "HTTP GET /signalk (discovery)", "HTTP", "cmd")
            self.at(self.t + 0.003, lambda: c.send("srv", http_rsp(200, [("Content-Type", "application/json")], disc), "HTTP 200 discovery: endpoints v1, ws URL", "HTTP", "resp"))
            self.at(self.t + 0.010, lambda: c.send(cli, http_req("GET", "/signalk/v1/stream?subscribe=none", [("Host", "192.168.1.10:3000"), ("Upgrade", "websocket"),
                                                                                                             ("Connection", "Upgrade"), ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
                                                                                                             ("Sec-WebSocket-Version", "13")]),
                                                   "HTTP GET /signalk/v1/stream: Upgrade to WebSocket", "HTTP", "cmd"))
            self.at(self.t + 0.013, lambda: c.send("srv", http_rsp(101, [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")]),
                                                   "HTTP 101 Switching Protocols: WebSocket open", "HTTP", "resp"))
            hello = jdump({"name": "signalk-server", "version": "2.8.0", "self": SK_SELF, "roles": ["master", "main"], "timestamp": utc(self.t).strftime("%Y-%m-%dT%H:%M:%S.000Z")})
            self.at(self.t + 0.015, lambda: c.send("srv", ws_frame(hello, title="WebSocket: Signal K hello"), "WS hello: self = " + SK_SELF, "Signal K", "resp"))
            ps = [("navigation.speedOverGrnd" if (p == "navigation.speedOverGround" and self.fault["sub"] and cli == "tab") else p) for p in paths]
            sub = jdump({"context": "vessels.self", "subscribe": [{"path": p, "period": 1000} for p in ps]})
            self.at(self.t + 0.020, lambda: c.send(cli, ws_frame(sub, masked=True, title="WebSocket: Signal K subscribe"), "WS subscribe: %s" % ", ".join(ps), "Signal K", "cmd"))
            self.at(self.t + 0.021, lambda: st.update(open=True, paths=ps))
            self.by["srv"].vars["Clients"] = sum(1 for v in self.ws.values())
        c.connect(on_open=on_open)

    def value(self, path):
        s = self.ship
        kn = 0.514444
        return {"navigation.speedOverGround": round(s.sog if self.fault["units"] else s.sog * kn, 2), "environment.depth.belowTransducer": round(s.depth, 2),
                "navigation.position": {"latitude": round(s.lat, 7), "longitude": round(s.lon, 7)}, "environment.wind.angleApparent": round(math.radians(s.awa), 4),
                "environment.wind.speedApparent": round(s.aws * kn, 2), "navigation.headingMagnetic": round(math.radians(s.hdg), 4)}.get(path)

    def deltas(self):
        if self.fault["stale"]:
            return
        ts = utc(self.t).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        src = {"navigation.speedOverGround": ("n2k", "129026", "2"), "navigation.position": ("n2k", "129025", "2"), "environment.depth.belowTransducer": ("n2k", "128267", "35"),
               "environment.wind.angleApparent": ("n2k", "130306", "5"), "environment.wind.speedApparent": ("n2k", "130306", "5"), "navigation.headingMagnetic": ("n2k", "127250", "11")}
        for cli, st in self.ws.items():
            if not st["open"]:
                continue
            vals = [{"path": p, "value": self.value(p)} for p in st["paths"] if self.value(p) is not None]
            if not vals:
                continue
            lab, pgn, sa = src.get(vals[0]["path"], ("n2k", "?", "?"))
            delta = jdump({"context": SK_SELF, "updates": [{"source": {"label": lab, "type": "NMEA2000", "pgn": int(pgn), "src": sa}, "$source": "%s.%s" % (lab, sa), "timestamp": ts, "values": vals}]})
            shown = ", ".join("%s=%s" % (v["path"].split(".")[-1], ("%.5f,%.5f" % (v["value"]["latitude"], v["value"]["longitude"])) if isinstance(v["value"], dict) else v["value"]) for v in vals)
            st["c"].send("srv", ws_frame(delta, title="WebSocket: Signal K delta"), "WS delta to %s: %s" % (self.by[cli].label, shown),
                         "Signal K", "data", auto_ack=False)
            n = self.by[cli]
            for v in vals:
                p = v["path"]
                if p == "navigation.speedOverGround":
                    n.vars["SOG"] = "%.1f kn%s" % (v["value"] / 0.514444, " (WRONG: value was in knots)" if self.fault["units"] else "")
                elif p == "environment.depth.belowTransducer":
                    n.vars["Depth"] = "%.1f m" % v["value"]
                elif p == "navigation.position":
                    n.vars["Position"] = "%.5f, %.5f" % (v["value"]["latitude"], v["value"]["longitude"])
                elif p == "environment.wind.angleApparent":
                    n.vars["Wind"] = "%.0f deg" % math.degrees(v["value"])
                elif p == "navigation.headingMagnetic":
                    n.vars["Heading"] = "%.0f deg" % math.degrees(v["value"])
            if "Last update" in n.vars:
                n.vars["Last update"] = ts[11:19]
            if cli == "tab" and self.fault["sub"]:
                n.vars["SOG"] = "--- (no data for the subscribed path)"

    def rest(self, kind, send=True):
        cli = "phone"
        if kind == "get":
            req = http_req("GET", "/signalk/v1/api/vessels/self/navigation/position", [("Host", "192.168.1.10:3000"), ("Accept", "application/json")])
        else:
            hs = [("Host", "192.168.1.10:3000"), ("Content-Type", "application/json")] + ([] if self.fault["auth"] else [("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9...")])
            req = http_req("PUT", "/signalk/v1/api/vessels/self/electrical/switches/anchorLight/state", hs, jdump({"value": 1 - self.light}).encode())
        if not send:
            return Frame(self.t, 1e-5, cli, "srv", "HTTP", "preview", pdu=req)
        c = self.tcp(cli, "srv", 52000 + int(self.t * 10) % 1000, 3000, "HTTP")

        def go():
            if kind == "get":
                c.send(cli, req, "HTTP GET .../navigation/position (REST)", "HTTP", "cmd")
                body = jdump({"value": self.value("navigation.position"), "$source": "n2k.2", "timestamp": utc(self.t).strftime("%Y-%m-%dT%H:%M:%S.000Z")}).encode()
                self.at(self.t + 0.003, lambda: c.send("srv", http_rsp(200, [("Content-Type", "application/json")], body), "HTTP 200: position JSON", "HTTP", "resp"))
                self.by["phone"].vars["Last REST"] = "GET position 200 OK"
            else:
                c.send(cli, req, "HTTP PUT anchorLight.state = %d" % (1 - self.light), "HTTP", "cmd")
                if self.fault["auth"]:
                    self.at(self.t + 0.003, lambda: c.send("srv", http_rsp(401, [("Content-Type", "application/json")], b'{"message":"permission denied"}'),
                                                           "HTTP 401 Unauthorized (no token)", "HTTP", "err", err="Unauthorized"))
                    self.by["phone"].vars["Last REST"] = "PUT 401 Unauthorized"
                else:
                    self.light = 1 - self.light
                    body = jdump({"state": "COMPLETED", "statusCode": 200, "requestId": "6b0e2b1c-71f3-4e3e-9a55-1c2f0b7c4d21"}).encode()
                    self.at(self.t + 0.004, lambda: c.send("srv", http_rsp(200, [("Content-Type", "application/json")], body), "HTTP 200: PUT COMPLETED", "HTTP", "resp"))
                    self.by["phone"].vars["Anchor light"] = "ON" if self.light else "off"
                    self.by["phone"].vars["Last REST"] = "PUT 200 COMPLETED"
            self.at(self.t + 0.03, c.close, cli)
        c.connect(on_open=go)
        return None

    def on_fault(self, key, on):
        if key == "sub":
            st = self.ws.get("tab")
            if st and st["open"]:
                st["open"] = False
                self.ws.pop("tab")
                self.at(self.t + 0.05, self.connect, "tab", ["navigation.speedOverGround", "environment.depth.belowTransducer", "navigation.position"])

    def tpls(self):
        return [Tpl("REST GET position", [], lambda s, v, send: self.rest("get", send), "GET /signalk/v1/api/vessels/self/navigation/position"),
                Tpl("REST PUT anchor light", [], lambda s, v, send: self.rest("put", send), "PUT electrical/switches/anchorLight/state with {\"value\": 1}")]
