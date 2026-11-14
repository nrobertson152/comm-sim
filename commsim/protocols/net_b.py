"""Networking, part B (wireless): IEEE 802.15.4, Zigbee, Thread, Bluetooth
LE, Wi-Fi (802.11), LoRaWAN and Z-Wave."""
import math
import struct
from ..engine import Bld, Frame, Tpl, P, Pdu
from ..bits import crcn, lsb, msb
from .fam import RfNet, rf_frame, fsk_wire, chirp_wire, burst_wire

# ========================================================== 802.15.4 helpers
CH154 = {c: 2405.0 + 5 * (c - 11) for c in range(11, 27)}
CHIP0 = "11011001110000110101001000101110"


def chips(sym):
    base = CHIP0[-4 * (sym & 7):] + CHIP0[:-4 * (sym & 7)] if sym & 7 else CHIP0
    if sym >= 8:
        base = "".join(c if i % 2 == 0 else ("1" if c == "0" else "0") for i, c in enumerate(base))
    return [int(c) for c in base]


def oqpsk_wire(data, nbytes=6):
    """2.4 GHz O-QPSK PHY: each 4-bit symbol becomes 32 chips at 2 Mchip/s (shown MSK-equivalent)."""
    syms = []
    for byte in data[:nbytes]:
        syms += [byte & 15, byte >> 4]
    seq = []
    for s in syms:
        seq += chips(s)
    labels = [(32 * i, 32 * (i + 1), "sym %X" % s, i % 2) for i, s in enumerate(syms)]
    return fsk_wire(seq, 2e6, 500.0, lead=16, gauss=0.5, labels=labels)


def addr_bytes(a):
    if a is None:
        return b"", 0, ""
    if isinstance(a, bytes):
        return a[::-1], 3, ":".join("%02x" % x for x in a)
    return struct.pack("<H", a), 2, "0x%04X%s" % (a, " (broadcast)" if a == 0xFFFF else "")


def mac154x(ftype, seq, dpan, dst, span, src, payload=None, ack=True, pending=False, title=None, secure=False):
    db, dm, dt = addr_bytes(dst)
    sb, sm, st = addr_bytes(src)
    comp = dpan is not None and span is not None and dpan == span
    fc = ftype | (0x08 if secure else 0) | (0x10 if pending else 0) | (0x20 if ack else 0) | (0x40 if comp else 0) | (dm << 10) | (sm << 14)
    tn = {0: "Beacon", 1: "Data", 2: "Ack", 3: "MAC command"}[ftype]
    b = Bld(title or "IEEE 802.15.4 MAC: %s" % tn, "MAC frame: frame control, sequence number, addressing fields, payload, FCS.")
    b.u16("Frame control", fc, "0x%04X: %s%s%s%s, dst %s, src %s" % (fc, tn, ", security" if secure else "", ", frame pending" if pending else "", ", ack request" if ack else "",
                                                                 {0: "none", 2: "short", 3: "extended"}[dm], {0: "none", 2: "short", 3: "extended"}[sm]),
          "Frame type, security enabled, frame pending, ack request, PAN ID compression, addressing modes.", little=True)
    b.u8("Sequence number", seq & 255, None, "The ACK carries the same number.")
    if dm:
        b.u16("Destination PAN ID", dpan, "0x%04X" % dpan, "", little=True)
        b.raw("Destination address", db, dt, "Little-endian on the air.")
    if sm:
        if not comp:
            b.u16("Source PAN ID", span, "0x%04X" % span, "", little=True)
        b.raw("Source address", sb, st, "")
    if payload is not None:
        b.sub(payload)
    fcs = crcn("CRC-16/KERMIT", bytes(b.b))
    b.u16("FCS", fcs, "0x%04X [correct]" % fcs, "CRC-16 (ITU-T) over the MAC header and payload.", little=True)
    return b.done()


def phy154(mpdu):
    b = Bld("IEEE 802.15.4 PHY (O-QPSK 2.4 GHz, 250 kbit/s)", "Synchronisation header (preamble + SFD) and PHY header (frame length).")
    b.raw("Preamble", bytes(4), "00 00 00 00 (8 zero symbols)", "Lets the receiver synchronise to the chips.")
    b.u8("SFD", 0xA7, "0xA7", "Start-of-frame delimiter.")
    b.u8("PHR: frame length", len(mpdu.b), "%d bytes (max 127)" % len(mpdu.b), "")
    b.sub(mpdu)
    return b.done()


def pl(rows):
    """Payload builder from (label, bytes, text, desc) rows -> Pdu."""
    b = Bld()
    for lab, data, txt, desc in rows:
        b.raw(lab, data, txt, desc)
    return b.done()


class Net154(RfNet):
    """Shared 2.4 GHz 802.15.4 radio scenario helpers."""
    f_mhz, ptx, sens, n_exp = 2425.0, 3.0, -97.0, 2.6
    map_size = 120.0
    channel = 15

    def send154(self, src, dst, mpdu, info, kind="data", err=None, proto=None, key=None):
        p = phy154(mpdu)
        dur = (len(p.b)) * 8 / 250e3
        rssi = int(self.radio_model.rssi(src, dst)) if dst else -60
        fr = rf_frame(self, src, dst, proto or self.proto, info, p, dur, CH154[self.channel], 2.0, kind, key=key, err=err, rssi=rssi,
                      wirefn=lambda f, d=p.b: oqpsk_wire(d))
        return self.tx(fr, bus="air", ifs=0.000192 + 0.00032 * float(self.rng.integers(0, 8)))

    def ack154(self, src, dst, seq, pending=False):
        a = mac154x(2, seq, None, None, None, None, None, False, pending, "IEEE 802.15.4 MAC: Ack")
        self.send154(src, dst, a, "MAC ACK seq %d%s" % (seq, " (frame pending)" if pending else ""), "ack", proto="802.15.4", key="ACK")

    def heard(self, a, b):
        return self.radio_model.ok(a, b)


# ================================================================ 802.15.4
class IEEE802154(Net154):
    key, name, cat = "ieee802154", "IEEE 802.15.4", "net"
    blurb = "Low-power wireless (foundation of Zigbee, Thread)"
    proto = "802.15.4"
    band = {"f0": 2400.0, "f1": 2483.5, "unit": "MHz", "chans": [("ch%d" % c, f, 2.0) for c, f in CH154.items()]}
    medium = "IEEE 802.15.4 beacon-enabled PAN on channel 15: a coordinator, devices associating, CSMA/CA data with ACKs, indirect data for a sleepy device"
    faults = [("busy", "Channel 15 busy (Wi-Fi traffic)", "Clear channel assessment often finds the channel busy: CSMA/CA backs off, some frames fail with CHANNEL_ACCESS_FAILURE."),
              ("noack", "Sensor 2 out of range", "No ACK: the sender retries up to macMaxFrameRetries (3) times, then reports NO_ACK."),
              ("pan", "Sensor 3 configured with PAN ID 0x1235", "Its frames are filtered out by the coordinator's PAN ID check.")]
    spec = [("Standard", "IEEE 802.15.4-2020: PHY and MAC for low-rate wireless personal area networks"),
            ("PHY", "2.4 GHz O-QPSK, 250 kbit/s, 16 channels (11-26, 5 MHz apart); 4-bit symbols spread to 32 chips (DSSS); also sub-GHz PHYs"),
            ("Frame", "Max 127 bytes; frame control, sequence number, PAN IDs, short (16-bit) or extended (64-bit) addresses, payload, CRC-16"),
            ("Access", "Unslotted or slotted CSMA/CA: random backoff 0..2^BE-1 periods of 320 us, CCA, up to 4 backoffs; ACK within 192 us"),
            ("Beacons", "Optional superframe: beacon, contention access period, guaranteed time slots, inactive period"),
            ("Indirect", "Data for sleeping devices is held by the coordinator; the device polls with a Data Request command")]
    frame = [["PPDU", ("Preamble", 32), ("SFD", 8), ("PHR len", 8), ("FC", 16), ("Seq", 8), ("Dst PAN", 16), ("Dst addr", "16/64"), ("Src addr", "16/64"), ("Payload", "n x 8"), ("FCS", 16)]]
    about = ("IEEE 802.15.4 is the radio and MAC layer under Zigbee, Thread, WirelessHART and others: short packets at 250 kbit/s, "
             "battery-friendly, with optional beacons. Devices listen before talking (CSMA/CA), every unicast frame is acknowledged, and a "
             "sleeping device collects its queued data by polling its coordinator.")
    guide = ["Select a beacon: superframe specification (beacon order, superframe order, association permit).",
             "Follow an association: Association Request (capability info), ACK, Data Request, Association Response with a short address.",
             "LOGIC / SCOPE: the chips of each symbol (O-QPSK spreading).",
             "Move sensor 2 out of range: three retries, then no ACK."]

    def setup(self):
        self.rnode("co", "PAN COORDINATOR", "gateway", 55, 25, "0x0000", "PAN 0x1234", w=118)
        for i, (nid, lab, x, y) in enumerate((("s1", "SENSOR 1", 15, 9), ("s2", "SENSOR 2", 95, 10), ("s3", "SENSOR 3", 20, 42), ("sd", "SLEEPY VALVE", 92, 42))):
            n = self.rnode(nid, lab, "sensor" if nid != "sd" else "valve", x, y, "", "joining", w=104)
            n.vars["Short address"] = "-"
        self.pairs = [(n, "co") for n in ("s1", "s2", "s3", "sd")]
        self.user = "co"
        self.seq = 0
        self.bsn = 0
        self.short = {}
        self.ext = {k: bytes([0x00, 0x12, 0x4B, 0x00, 0x1A, 0x00, 0x00, 0x10 + i]) for i, k in enumerate(("s1", "s2", "s3", "sd"))}
        self.held = []
        self.every(0.983, self.beacon, 0.05)
        for i, k in enumerate(("s1", "s2", "s3", "sd")):
            self.at(0.3 + 0.4 * i, self.associate, k)
        self.every(2.0, self.report, 3.0)
        self.every(4.0, self.queue_cmd, 4.5)
        self.every(1.5, self.poll, 5.0)

    def beacon(self):
        self.bsn = (self.bsn + 1) & 255
        ss = 0x0F | (0x0F << 4) | (0x0F << 8) | 0x8000 | 0x4000
        payload = pl([("Superframe specification", struct.pack("<H", ss), "BO 15, SO 15 (non-beacon timing), final CAP slot 15, PAN coordinator, association permit 1",
                       "Beacon order / superframe order set the beacon interval and active period."),
                      ("GTS fields", b"\x00", "no guaranteed time slots", ""), ("Pending addresses", bytes([len(self.held)]) + b"".join(struct.pack("<H", self.short.get("sd", 0xFFFE)) for _ in self.held[:1]),
                                                                                "%d short address(es) with data pending" % len(self.held[:1]), "Sleeping devices check this list.")])
        m = mac154x(0, self.bsn, None, None, 0x1234, 0x0000, payload, ack=False, title="IEEE 802.15.4 MAC: Beacon")
        self.send154("co", None, m, "Beacon BSN %d, PAN 0x1234, association permitted%s" % (self.bsn, ", data pending for the valve" if self.held else ""), "sync", key="Beacon")

    def associate(self, k):
        if self.fault["pan"] and k == "s3":
            pass
        self.seq += 1
        seq = self.seq
        cmd = pl([("Command identifier", b"\x01", "0x01 Association Request", ""), ("Capability information", bytes([0x80 if k == "sd" else 0x8E]),
                                                                                    "%s, allocate address" % ("sleepy (rx off when idle)" if k == "sd" else "FFD, mains powered, rx on when idle"), "")])
        m = mac154x(3, seq, 0x1234, 0x0000, 0xFFFF, self.ext[k], cmd, title="IEEE 802.15.4 MAC: Association Request")
        self.send154(k, "co", m, "Association Request from %s" % ":".join("%02x" % x for x in self.ext[k][-3:]), "ctl")
        if not self.heard(k, "co"):
            return
        self.at(self.t + 0.002, self.ack154, "co", k, seq, True)
        sa = 0x0001 + len(self.short) * 0x0101
        self.short[k] = sa
        self.at(self.t + 0.5, self._assoc_rsp, k, sa)

    def _assoc_rsp(self, k, sa):
        self.seq += 1
        dr = mac154x(3, self.seq, 0x1234, 0x0000, 0x1234, self.ext[k], pl([("Command identifier", b"\x04", "0x04 Data Request", "Poll the coordinator for pending data.")]),
                     title="IEEE 802.15.4 MAC: Data Request")
        self.send154(k, "co", dr, "Data Request (polling for the association response)", "ctl")
        self.at(self.t + 0.002, self.ack154, "co", k, self.seq, True)
        self.seq += 1
        rsp = pl([("Command identifier", b"\x02", "0x02 Association Response", ""), ("Short address", struct.pack("<H", sa), "0x%04X" % sa, "The device uses this from now on."),
                  ("Association status", b"\x00", "0x00 successful", "")])
        m = mac154x(3, self.seq, 0x1234, self.ext[k], 0x1234, bytes([0x00, 0x12, 0x4B, 0x00, 0x1A, 0x00, 0x00, 0x01]), rsp, title="IEEE 802.15.4 MAC: Association Response")
        self.at(self.t + 0.004, self.send154, "co", k, m, "Association Response: short address 0x%04X" % sa, "resp")
        self.at(self.t + 0.006, self.ack154, k, "co", self.seq)
        self.by[k].vars["Short address"] = "0x%04X" % sa
        self.by[k].addr = "0x%04X" % sa
        self.by[k].sub = "PAN 0x1234"

    def csma(self):
        for nb in range(5):
            if not (self.fault["busy"] and self.rng.random() < 0.55):
                return nb
        return None

    def report(self):
        for k in ("s1", "s2", "s3"):
            if k not in self.short:
                continue
            nb = self.csma()
            if nb is None:
                self.log("%s: CHANNEL_ACCESS_FAILURE after 4 backoffs (CCA busy)" % self.by[k].label)
                continue
            self.at(self.t + 0.0032 * nb * (1 + float(self.rng.random())), self.data_tx, k, 0)

    def data_tx(self, k, retry):
        self.seq += 1
        val = 21.0 + 0.5 * math.sin(self.t + len(k))
        payload = pl([("Application data", struct.pack("<h", int(val * 100)), "%.2f degC" % val, "Upper layers (Zigbee, Thread ...) would sit here.")])
        pan = 0x1235 if (self.fault["pan"] and k == "s3") else 0x1234
        m = mac154x(1, self.seq, pan, 0x0000, pan, self.short[k], payload)
        err = None
        if self.fault["noack"] and k == "s2":
            err = "No ACK received (out of range)"
        fr = self.send154(k, "co", m, "Data 0x%04X -> 0x0000, %.2f degC%s%s" % (self.short[k], val, " retry %d" % retry if retry else "", " (PAN 0x1235: filtered!)" if pan != 0x1234 else ""),
                          "data", err)
        if err:
            if retry < 3:
                self.at(self.t + 0.000864 + 0.002, self.data_tx, k, retry + 1)
            else:
                self.log("%s: NO_ACK after macMaxFrameRetries (3)" % self.by[k].label)
            return
        if pan != 0x1234:
            return
        self.at(fr.t + fr.dur + 0.000192, self.ack154, "co", k, self.seq)

    def queue_cmd(self):
        if "sd" in self.short and not self.held:
            self.held.append(b"\x01")

    def poll(self):
        if "sd" not in self.short:
            return
        self.seq += 1
        dr = mac154x(3, self.seq, 0x1234, 0x0000, 0x1234, self.short["sd"], pl([("Command identifier", b"\x04", "0x04 Data Request", "")]), title="IEEE 802.15.4 MAC: Data Request")
        self.send154("sd", "co", dr, "Data Request from the sleepy valve (wakes up, polls)", "ctl")
        pend = bool(self.held)
        self.at(self.t + 0.002, self.ack154, "co", "sd", self.seq, pend)
        if pend:
            self.held.pop()
            self.seq += 1
            m = mac154x(1, self.seq, 0x1234, self.short["sd"], 0x1234, 0x0000, pl([("Application data", b"\x01", "OPEN valve", "")]))
            self.at(self.t + 0.004, self.send154, "co", "sd", m, "Indirect data -> 0x%04X: OPEN valve (was held until the poll)" % self.short["sd"], "cmd")
            self.at(self.t + 0.006, self.ack154, "sd", "co", self.seq)
            self.by["sd"].vars["Valve"] = "OPEN"

    def tpls(self):
        return [Tpl("Coordinator queues data for the valve", [], lambda s, v, send: self._q(send), "Indirect transmission: delivered at the next poll.")]

    def _q(self, send):
        if not send:
            return Frame(self.t, 0.001, "co", "sd", "802.15.4", "preview", pdu=phy154(mac154x(1, self.seq + 1, 0x1234, 0x0303, 0x1234, 0x0000, pl([("Application data", b"\x01", "OPEN", "")]))))
        self.queue_cmd()
        return None


# ================================================================== Zigbee
ZCL_CL = {0x0006: "On/Off", 0x0402: "Temperature Measurement", 0x0008: "Level Control"}


def zb_nwk(dst, src, radius, seq, inner, secure=True, fc_extra=0):
    b = Bld("Zigbee Network Layer", "NWK header: frame control, 16-bit destination and source, radius, sequence; then (security) auxiliary header and MIC.")
    fc = 0x0008 | (0x0200 if secure else 0) | fc_extra
    b.u16("Frame control", fc, "data, protocol version 2, discover route: suppress%s" % (", security" if secure else ""), "", little=True)
    b.u16("Destination", dst, "0x%04X" % dst, "Final destination network address.", little=True)
    b.u16("Source", src, "0x%04X" % src, "Originator.", little=True)
    b.u8("Radius", radius, None, "Max hops left.")
    b.u8("Sequence number", seq & 255, None, "")
    if secure:
        b.u8("Security control", 0x28, "key id 1 (network key), extended nonce", "")
        b.u32("Frame counter", 0x00010000 + seq * 3, None, "Never repeats: replay protection.", little=True)
        b.raw("Source address (64-bit)", bytes([0x00, 0x12, 0x4B, 0x00, 0x2C, 0x00, 0x00, src & 255]), "", "")
        b.u8("Key sequence number", 0, None, "")
        b.raw("Encrypted payload", bytes(len(inner.b)), "%d bytes (AES-128-CCM*)" % len(inner.b), "Decrypted view below.")
        b.u32("MIC", (seq * 2654435761) & 0xFFFFFFFF, "message integrity code (simulated)", "")
        p = b.done()
        p.rows.append([0, "Decrypted with the network key:", None, 0, "What a sniffer shows when it knows the key."])
        for r in inner.rows:
            p.rows.append([r[0] + 1, r[1], None, 0, r[4]])
        return p
    b.sub(inner)
    return b.done()


def zb_aps(dst_ep, cluster, profile, src_ep, counter, zcl, ack_req=True):
    b = Bld("Zigbee Application Support (APS)", "Endpoints, cluster and profile identify which application object the ZCL command is for.")
    b.u8("Frame control", 0x40 if ack_req else 0x00, "data, unicast%s" % (", ack request" if ack_req else ""), "")
    b.u8("Destination endpoint", dst_ep, None, "")
    b.u16("Cluster", cluster, "0x%04X %s" % (cluster, ZCL_CL.get(cluster, "")), "", little=True)
    b.u16("Profile", profile, "0x%04X Home Automation" % profile, "", little=True)
    b.u8("Source endpoint", src_ep, None, "")
    b.u8("APS counter", counter & 255, None, "")
    b.sub(zcl)
    return b.done()


class Zigbee(Net154):
    key, name, cat = "zigbee", "Zigbee", "net"
    blurb = "Smart home and building automation mesh"
    proto = "Zigbee"
    channel = 15
    band = {"f0": 2400.0, "f1": 2483.5, "unit": "MHz", "chans": [("ch%d" % c, f, 2.0) for c, f in CH154.items()]}
    medium = "Zigbee 3.0 mesh on 802.15.4 channel 15: coordinator, a smart-plug router, bulbs, a wall switch and a sleepy temperature sensor"
    faults = [("wifi", "Wi-Fi access point on channel 4 (overlaps Zigbee ch 15)", "Many frames are lost; MAC retries and APS retries recover most of them."),
              ("plug", "Smart plug (router) unplugged", "The sensor loses its parent; it searches for a new parent and rejoins via the coordinator."),
              ("key", "New bulb joined with the wrong network key", "It cannot decrypt anything: commands to it fail.")]
    spec = [("Standard", "Zigbee 3.0 (Connectivity Standards Alliance) on IEEE 802.15.4 2.4 GHz; Zigbee Cluster Library (ZCL)"),
            ("Roles", "Coordinator (forms the network, trust centre), routers (mains powered, relay), end devices (may sleep, poll their parent)"),
            ("Layers", "802.15.4 MAC > NWK (16-bit addresses, mesh routing, security) > APS (endpoints, clusters, binding) > ZCL commands / attributes"),
            ("Security", "AES-128 CCM*: network key for every frame, link keys between pairs; frame counters against replay"),
            ("ZCL", "Clusters such as On/Off (0x0006), Level Control (0x0008), Temperature Measurement (0x0402): commands and attribute reports")]
    frame = [["Zigbee frame", ("802.15.4 MAC", "9 B"), ("NWK hdr", "8 B"), ("Aux security", "14 B"), ("APS", "8 B"), ("ZCL", "3+ B"), ("MIC", 32), ("FCS", 16)]]
    about = ("Zigbee builds a self-healing mesh on 802.15.4 radios. Mains-powered devices route for each other, battery devices sleep and poll a "
             "parent. Above the network layer the Zigbee Cluster Library standardises what devices say: a switch sends On/Off 'Toggle' to a bulb, "
             "a sensor reports its Temperature Measurement attribute. Every frame is encrypted with the network key.")
    guide = ["Toggle the bulb from the switch (COMPOSE): MAC ACK, then the APS ACK from the bulb.",
             "Select a frame: MAC, NWK (with the security header), APS, ZCL - decrypted view at the bottom.",
             "Find the sensor's attribute report hopping via the smart plug (NWK source vs MAC source).",
             "Unplug the smart plug and watch the sensor find a new parent."]

    def setup(self):
        nodes = [("co", "COORDINATOR (HUB)", "gateway", 55, 26, 0x0000), ("plug", "SMART PLUG (ROUTER)", "box", 30, 10, 0x1A2B), ("b1", "BULB 1", "lamp", 92, 10, 0x22C1),
                 ("b2", "BULB 2", "lamp", 95, 42, 0x22C2), ("sw", "WALL SWITCH", "button", 22, 42, 0x3B10), ("ts", "TEMP SENSOR (SLEEPY)", "temp", 4, 4, 0x4C01)]
        for nid, lab, kind, x, y, a in nodes:
            n = self.rnode(nid, lab, kind, x, y, "0x%04X" % a, "", w=118)
            n.extra["nwk"] = a
        self.by["ts"].extra["ptx"] = -3.0
        self.pairs = [("plug", "co"), ("b1", "co"), ("b2", "co"), ("sw", "co"), ("ts", "plug"), ("b1", "b2"), ("sw", "b2")]
        self.user = "sw"
        self.seq = 0
        self.nseq = 0
        self.aps = 0
        self.parent = "plug"
        self.bulb = {"b1": False, "b2": False}
        self.by["ts"].vars.update({"Parent": "SMART PLUG 0x1A2B", "Temperature": "-"})
        for b in ("b1", "b2"):
            self.by[b].vars["State"] = "OFF"
        self.every(4.0, self.temp_report, 1.0)
        self.every(10.0, lambda: self.toggle("b1"), 3.0)
        self.every(7.0, self.link_status, 2.5)

    def lost(self, a, b):
        if self.fault["wifi"] and self.rng.random() < 0.35:
            return "Lost: Wi-Fi interference on the channel"
        if not self.heard(a, b):
            return "Lost: out of range"
        return None

    def hop(self, src, dst, nwk_dst, nwk_src, inner_pdu, info, kind, aps_ack_to=None, tries=0):
        self.seq += 1
        self.nseq += 1
        mac = mac154x(1, self.seq, 0x6A2F, self.by[dst].extra["nwk"], 0x6A2F, self.by[src].extra["nwk"], zb_nwk(nwk_dst, nwk_src, 30, self.nseq, inner_pdu))
        err = self.lost(src, dst)
        self.send154(src, dst, mac, info + (" (MAC retry %d)" % tries if tries else ""), kind, err)
        if err:
            if tries < 3:
                self.at(self.t + 0.004, self.hop, src, dst, nwk_dst, nwk_src, inner_pdu, info, kind, aps_ack_to, tries + 1)
            return False
        self.at(self.t + 0.0025, self.ack154, dst, src, self.seq)
        return True

    def toggle(self, b, send=True):
        self.aps += 1
        zcl = pl([("ZCL frame control", b"\x01", "cluster-specific, client to server", ""), ("ZCL sequence", bytes([self.aps & 255]), str(self.aps & 255), ""),
                  ("Command", b"\x02", "0x02 Toggle", "On/Off cluster command.")])
        aps = zb_aps(1, 0x0006, 0x0104, 1, self.aps, zcl)
        if not send:
            return Frame(self.t, 0.002, "sw", b, "Zigbee", "preview", pdu=phy154(mac154x(1, 1, 0x6A2F, self.by[b].extra["nwk"], 0x6A2F, 0x3B10, zb_nwk(self.by[b].extra["nwk"], 0x3B10, 30, 1, aps))))
        if self.hop("sw", b, self.by[b].extra["nwk"], 0x3B10, aps, "ZCL On/Off Toggle 0x3B10 -> 0x%04X (bulb %s)" % (self.by[b].extra["nwk"], b[1]), "cmd"):
            if self.fault["key"] and b == "b2":
                self.log("Bulb 2 cannot decrypt the frame (wrong network key): no APS ACK, nothing happens")
                return None
            self.bulb[b] = not self.bulb[b]
            self.by[b].vars["State"] = "ON" if self.bulb[b] else "OFF"
            ack = pl([("APS frame control", b"\x02", "APS acknowledgement", ""), ("Destination endpoint", b"\x01", "1", ""), ("Cluster", struct.pack("<H", 6), "0x0006", ""),
                      ("Profile", struct.pack("<H", 0x0104), "0x0104", ""), ("Source endpoint", b"\x01", "1", ""), ("APS counter", bytes([self.aps & 255]), str(self.aps & 255), "")])
            self.at(self.t + 0.006, self.hop, b, "sw", 0x3B10, self.by[b].extra["nwk"], ack, "APS ACK from bulb %s (end-to-end)" % b[1], "ack")
        return None

    def temp_report(self):
        v = 20.5 + 0.8 * math.sin(self.t / 6)
        self.aps += 1
        zcl = pl([("ZCL frame control", b"\x18", "profile-wide, server to client, disable default response", ""), ("ZCL sequence", bytes([self.aps & 255]), str(self.aps & 255), ""),
                  ("Command", b"\x0a", "0x0A Report Attributes", ""), ("Attribute", struct.pack("<H", 0), "0x0000 MeasuredValue", ""),
                  ("Data type", b"\x29", "0x29 int16", ""), ("Value", struct.pack("<h", int(v * 100)), "%d = %.2f degC" % (int(v * 100), v), "Units of 0.01 degC.")])
        aps = zb_aps(1, 0x0402, 0x0104, 1, self.aps, zcl, False)
        par = self.parent
        if par == "plug" and not self.by["plug"].on:
            self.rejoin()
            return
        if self.hop("ts", par, 0x0000, 0x4C01, aps, "ZCL Report Attributes: temperature %.2f degC (sensor -> %s)" % (v, "plug" if par == "plug" else "hub"), "data"):
            if par == "plug":
                self.at(self.t + 0.008, self.hop, "plug", "co", 0x0000, 0x4C01, aps, "Relayed by the smart plug: NWK source 0x4C01, MAC source 0x1A2B", "data")
            self.by["ts"].vars["Temperature"] = "%.2f degC" % v

    def rejoin(self):
        self.parent = "co"
        self.by["ts"].vars["Parent"] = "COORDINATOR 0x0000 (rejoined)"
        self.pairs = [p for p in self.pairs if p != ("ts", "plug")] + [("ts", "co")]
        self.seq += 1
        m = mac154x(3, self.seq, 0xFFFF, 0xFFFF, None, None, pl([("Command identifier", b"\x07", "0x07 Beacon Request", "Who can be my parent?")]), ack=False)
        self.send154("ts", None, m, "Beacon Request (parent lost - looking for a new parent)", "ctl")
        self.at(self.t + 0.01, self.send154, "co", None, mac154x(0, 1, None, None, 0x6A2F, 0x0000, pl([("Superframe", struct.pack("<H", 0xCFFF), "association permit", ""),
                                                                                                         ("Zigbee beacon payload", bytes(15), "protocol id 0, stack profile 2, router capacity", "")]),
                                                                    ack=False), "Beacon from the coordinator (accepting children)", "resp")
        self.at(self.t + 0.05, self.hop, "ts", "co", 0x0000, 0x4C01, pl([("NWK command", b"\x06", "0x06 Rejoin Request", "")]), "NWK Rejoin Request", "ctl")
        self.log("Temperature sensor: parent 0x1A2B lost - rejoined via the coordinator")

    def link_status(self):
        for r in ("co", "plug"):
            if not self.by[r].on:
                continue
            self.seq += 1
            self.nseq += 1
            mac = mac154x(1, self.seq, 0x6A2F, 0xFFFF, 0x6A2F, self.by[r].extra["nwk"], zb_nwk(0xFFFC, self.by[r].extra["nwk"], 1, self.nseq,
                                                                                               pl([("NWK command", b"\x08", "0x08 Link Status", "Routers tell neighbours how well they hear them."),
                                                                                                   ("Entries", b"\x03", "3 neighbours, incoming / outgoing cost", "")])), ack=False)
            self.send154(r, None, mac, "NWK Link Status from 0x%04X (radius 1)" % self.by[r].extra["nwk"], "sync")

    def on_fault(self, key, on):
        if key == "plug":
            self.by["plug"].on = not on
        if key == "plug" and not on:
            self.log("Smart plug back: the sensor stays with its current parent")

    def tpls(self):
        return [Tpl("Toggle a bulb", [P("b", "Bulb", "b1", opts=["b1", "b2"], fmt=lambda v: self.by[v].label)], lambda s, v, send: self.toggle(v["b"], send),
                    "ZCL On/Off Toggle with APS acknowledgement.")]


# ================================================================== Thread
def iphc(src_iid, dst, hlim=64, nh_udp=True):
    b = Bld("6LoWPAN IPHC (compressed IPv6 header)", "RFC 6282: the 40-byte IPv6 header shrinks to a few bytes using link-layer information.")
    b.u16("IPHC dispatch + fields", 0x7A33 if dst.startswith("ff") else 0x7A33, "011 TF=11 (elided) NH=%d HLIM=%s, CID 0 SAC 0 SAM=11, M=%d DAM=%s" % (
        1 if nh_udp else 0, {64: "10 (64)", 255: "11 (255)", 1: "01 (1)"}.get(hlim, "inline"), 1 if dst.startswith("ff") else 0, "11 (ff02::XX)" if dst.startswith("ff") else "11"),
        "Traffic class / flow label elided, hop limit compressed, addresses derived from the MAC addresses.")
    if dst.startswith("ff"):
        b.u8("Multicast destination", int(dst.split(":")[-1], 16) & 255, dst, "")
    if nh_udp:
        b.u8("UDP NHC", 0xF0, "ports inline, checksum inline", "")
    return b


class Thread(Net154):
    key, name, cat = "thread", "Thread", "net"
    blurb = "IP-based smart home mesh"
    proto = "Thread"
    channel = 20
    band = {"f0": 2400.0, "f1": 2483.5, "unit": "MHz", "chans": [("ch%d" % c, f, 2.0) for c, f in CH154.items()]}
    medium = "Thread network on 802.15.4 channel 20: border router (leader), routers, a sleepy door sensor; IPv6 over 6LoWPAN, MLE, CoAP and Matter"
    faults = [("leader", "Border router (leader) powers off", "Routers stop hearing the leader; after the timeout one of them becomes leader of a new partition."),
              ("parent", "Door sensor's parent router fails", "The sleepy child sends Parent Requests and attaches to another router (Child ID Request / Response)."),
              ("br", "Border router's Wi-Fi uplink down", "The mesh keeps working locally but has no route to the home network: Matter commands from the phone fail.")]
    spec = [("Standard", "Thread 1.3 (Thread Group) on IEEE 802.15.4 2.4 GHz; IPv6 / 6LoWPAN (RFC 4944, 6282), UDP, CoAP, DTLS; carries Matter"),
            ("Roles", "Leader, routers (up to 32), router-eligible end devices, minimal / sleepy end devices, border routers to Wi-Fi / Ethernet"),
            ("MLE", "Mesh Link Establishment (UDP 19788): advertisements, parent / child attach, link quality - encrypted with the network key"),
            ("Addressing", "Mesh-local EID, link-local, RLOC16 (router ID + child ID), off-mesh routable addresses via border routers"),
            ("Security", "802.15.4 MAC frame security (AES-CCM) with the network key; commissioning with DTLS (PSKc)")]
    frame = [["Thread packet", ("802.15.4 MAC", "~11 B"), ("Aux sec", "6 B"), ("6LoWPAN IPHC", "2-10 B"), ("UDP", "2-8 B"), ("CoAP / MLE / Matter", "n x 8"), ("MIC", 32), ("FCS", 16)]]
    about = ("Thread is an IPv6 mesh network for low-power devices: every node has real IPv6 addresses, squeezed into 802.15.4 frames by 6LoWPAN "
             "header compression. There is no single point of failure - routers elect a leader among themselves and re-elect one if it "
             "disappears - and border routers connect the mesh to Wi-Fi or Ethernet. Matter devices use Thread as one of their networks.")
    guide = ["Select an MLE Advertisement: 6LoWPAN IPHC replaces 40 bytes of IPv6 header with a handful.",
             "Watch the sleepy door sensor poll its parent (MAC Data Request) and the parent's ACK with frame pending.",
             "COMPOSE a Matter 'On' from the phone: it enters the mesh at the border router.",
             "Power off the leader: a router takes over as leader of a new partition."]

    def setup(self):
        nodes = [("br", "BORDER ROUTER (LEADER)", "gateway", 55, 24, "RLOC 0x0000"), ("r1", "SMART PLUG (ROUTER)", "box", 18, 10, "RLOC 0x0400"),
                 ("r2", "LIGHT (ROUTER)", "lamp", 90, 10, "RLOC 0x0800"), ("r3", "THERMOSTAT (ROUTER)", "tstat", 92, 42, "RLOC 0x0C00"),
                 ("sed", "DOOR SENSOR (SLEEPY)", "sensor", 8, 42, "RLOC 0x0401"), ("ph", "PHONE (MATTER CTRL)", "phone", 50, 45, "Wi-Fi")]
        for nid, lab, kind, x, y, a in nodes:
            self.rnode(nid, lab, kind, x, y, a, "", w=124)
        self.by["ph"].extra.update(ptx=-40.0)
        self.pairs = [("r1", "br"), ("r2", "br"), ("r3", "br"), ("r1", "r2"), ("r2", "r3"), ("sed", "r1")]
        self.user = "ph"
        self.seq = 0
        self.leader = "br"
        self.parent = "r1"
        self.part = 0x5A3C1E01
        self.light = False
        self.by["br"].vars.update({"Role": "leader", "Partition": "0x%08X" % self.part, "Uplink": "Wi-Fi ok"})
        self.by["sed"].vars.update({"Parent": "SMART PLUG 0x0400", "Door": "closed"})
        self.by["r2"].vars.update({"Light": "OFF"})
        self.every(4.0, self.advertise, 0.2)
        self.every(1.0, self.poll, 0.6)
        self.every(9.0, self.door_event, 2.0)
        self.every(11.0, lambda: self.matter(not self.light), 5.0)

    def mle_pdu(self, cmd, tlvs, dst="ff02::1"):
        b = iphc("", dst, 255)
        b.u16("UDP source port", 19788, "19788 (MLE)", "")
        b.u16("UDP destination port", 19788, "19788 (MLE)", "")
        b.u16("UDP checksum", 0x5A5A, None, "")
        b.u8("MLE security suite", 0, "0 (802.15.4 security)", "")
        b.raw("Aux header + encrypted MLE", bytes(8 + len(tlvs) * 4), "encrypted with the MLE key", "")
        p = b.done()
        p.rows.append([0, "Decrypted MLE: %s" % cmd, None, 0, ""])
        for t in tlvs:
            p.rows.append([1, t, None, 0, ""])
        return p

    def send(self, src, dst, inner, info, kind, err=None, ack=True):
        self.seq += 1
        dst_a = 0xFFFF if dst is None else int(self.by[dst].addr.split()[-1], 16) if self.by[dst].addr.startswith("RLOC") else 0xFFFE
        m = mac154x(1, self.seq, 0xFACE, dst_a, 0xFACE, int(self.by[src].addr.split()[-1], 16) if self.by[src].addr.startswith("RLOC") else 0xFFFE, inner, ack and dst is not None,
                    secure=True, title="IEEE 802.15.4 MAC (Thread, security enabled)")
        if err is None and dst is not None and not self.heard(src, dst):
            err = "Lost: out of range"
        self.send154(src, dst, m, info, kind, err)
        if dst is not None and not err and ack:
            self.at(self.t + 0.0025, self.ack154, dst, src, self.seq)
        return err is None

    def advertise(self):
        for r in ("br", "r1", "r2", "r3"):
            if not self.by[r].on:
                continue
            role = "leader" if r == self.leader else "router"
            p = self.mle_pdu("Advertisement", ["Source Address TLV: %s" % self.by[r].addr, "Leader Data TLV: partition 0x%08X, leader %s" % (self.part, self.by[self.leader].addr),
                                               "Route64 TLV: router ID set, link qualities, route costs"])
            self.at(self.t + 0.05 * ("br", "r1", "r2", "r3").index(r), self.send, r, None, p, "MLE Advertisement from %s (%s), partition 0x%08X" % (self.by[r].addr, role, self.part), "sync")

    def poll(self):
        if not self.by["sed"].on:
            return
        par = self.parent
        if not self.by[par].on:
            self.reattach()
            return
        self.seq += 1
        dr = mac154x(3, self.seq, 0xFACE, int(self.by[par].addr.split()[-1], 16), 0xFACE, 0x0401, pl([("Command identifier", b"\x04", "0x04 Data Request", "")]), secure=True)
        self.send154("sed", par, dr, "MAC Data Request: sleepy door sensor polls its parent", "ctl")
        self.at(self.t + 0.0025, self.ack154, par, "sed", self.seq, False)

    def reattach(self):
        self.parent = "r2"
        self.by["sed"].addr = "RLOC 0x0801"
        self.by["sed"].vars["Parent"] = "LIGHT 0x0800 (re-attached)"
        self.pairs = [p for p in self.pairs if p != ("sed", "r1")] + [("sed", "r2")]
        self.send("sed", None, self.mle_pdu("Parent Request", ["Mode TLV: sleepy, minimal", "Challenge TLV", "Scan Mask: routers"], "ff02::2"), "MLE Parent Request (old parent gone)", "ctl")
        self.at(self.t + 0.1, self.send, "r2", "sed", self.mle_pdu("Parent Response", ["Link Margin TLV", "Connectivity TLV", "Response TLV"], "fe80::"), "MLE Parent Response from 0x0800", "resp")
        self.at(self.t + 0.2, self.send, "sed", "r2", self.mle_pdu("Child ID Request", ["Timeout TLV: 240 s", "Address Registration"], "fe80::"), "MLE Child ID Request", "ctl")
        self.at(self.t + 0.25, self.send, "r2", "sed", self.mle_pdu("Child ID Response", ["Address16 TLV: 0x0801", "Network Data TLV"], "fe80::"), "MLE Child ID Response: RLOC16 0x0801", "resp")
        self.log("Door sensor: parent 0x0400 lost - attached to 0x0800 as child 0x0801")

    def door_event(self):
        st = "open" if int(self.t / 9) % 2 else "closed"
        b = iphc("", "fd00::")
        b.u16("UDP ports", 5540, "Matter (5540)", "")
        b.raw("Matter message (encrypted)", bytes(40), "session encrypted (AES-CCM)", "")
        p = b.done()
        p.rows.append([0, "Decrypted Matter: ReportData BooleanState.StateValue = %s" % ("false (open)" if st == "open" else "true (closed)"), None, 0, ""])
        par = self.parent
        if self.send("sed", par, p, "Matter report: door %s (sleepy sensor -> parent)" % st, "data"):
            self.by["sed"].vars["Door"] = st
            self.at(self.t + 0.01, self.send, par, "br", p, "Forwarded over the mesh to the border router (6LoWPAN mesh header)", "data")

    def matter(self, on, send=True):
        b = iphc("", "fd00::")
        b.u16("UDP ports", 5540, "Matter (5540)", "")
        b.raw("Matter message (encrypted)", bytes(48), "CASE session, AES-CCM", "")
        p = b.done()
        p.rows.append([0, "Decrypted Matter: InvokeCommand OnOff.%s on endpoint 1" % ("On" if on else "Off"), None, 0, ""])
        if not send:
            return Frame(self.t, 0.002, "br", "r2", "Thread", "preview", pdu=phy154(mac154x(1, 1, 0xFACE, 0x0800, 0xFACE, 0x0000, p, secure=True)))
        if self.fault["br"] or not self.by[self.leader].on:
            self.log("Phone: Matter command failed - no route into the Thread network (border router unreachable)")
            return None
        self.log("Phone (Wi-Fi) -> border router: Matter OnOff.%s (IPv6 routed into the mesh)" % ("On" if on else "Off"))
        if self.send("br", "r2", p, "Matter InvokeCommand OnOff.%s -> light (from the phone via the border router)" % ("On" if on else "Off"), "cmd"):
            self.light = on
            self.by["r2"].vars["Light"] = "ON" if on else "OFF"
            self.at(self.t + 0.01, self.send, "r2", "br", p, "Matter InvokeResponse: success", "resp")
        return None

    def on_fault(self, key, on):
        if key == "leader":
            self.by["br"].on = not on
            if on:
                self.at(self.t + 3.0, self.new_leader)
            else:
                self.by["br"].vars["Role"] = "router (rejoined the partition)"
        if key == "parent":
            self.by["r1"].on = not on
        if key == "br":
            self.by["br"].vars["Uplink"] = "DOWN" if on else "Wi-Fi ok"

    def new_leader(self):
        if self.by["br"].on:
            return
        self.leader = "r1"
        self.part = 0x7B11A2C4
        self.by["r1"].vars["Role"] = "leader (new partition)"
        self.log("Leader lost: router 0x0400 starts a new partition 0x%08X and becomes leader" % self.part)

    def tpls(self):
        return [Tpl("Matter command to the light", [P("v", "Command", "On", opts=["On", "Off"])], lambda s, v, send: self.matter(v["v"] == "On", send),
                    "Phone on Wi-Fi -> border router -> 6LoWPAN mesh -> light.")]


# ================================================================== BLE
BLE_ADV = {37: 2402.0, 38: 2426.0, 39: 2480.0}


def ble_data_freq(ch):
    return 2404.0 + 2 * ch if ch <= 10 else 2428.0 + 2 * (ch - 11)


def ble_crc(data, init=0x555555):
    bits = []
    for byte in data:
        bits += lsb(byte, 8)
    c = init
    for b in bits:
        fb = ((c >> 23) & 1) ^ b
        c = (c << 1) & 0xFFFFFF
        if fb:
            c ^= 0x00065B
    return c


def ble_air(aa, pdu_rows, data, title, adv=True):
    crc = ble_crc(data)
    b = Bld(title, "Bluetooth LE 1M PHY: preamble, access address, PDU, CRC-24; GFSK +-250 kHz.")
    b.u8("Preamble", 0xAA if not (aa & 1) else 0x55, "0x%02X" % (0xAA if not (aa & 1) else 0x55), "Alternating bits for receiver training.")
    b.u32("Access address", aa, "0x%08X%s" % (aa, " (advertising)" if aa == 0x8E89BED6 else " (this connection)"), "", little=True)
    base = len(b.b)
    b.b += data
    for d, txt, off, n, desc in pdu_rows:
        b.rows.append([d, txt, base + off, n, desc])
    b.u24("CRC", crc, "0x%06X [correct]" % crc, "CRC-24 (poly 0x65B), init 0x555555 on advertising channels, CRCInit from CONNECT_IND on data channels.", little=True)
    p = b.done()
    p.rows.append([0, "Data whitening (LFSR seeded by the channel) is applied on the air - not shown here", None, 0, ""])
    return p


class BLE(RfNet):
    key, name, cat = "ble", "Bluetooth / BLE", "net"
    blurb = "Wearables, sensors, smartphones"
    f_mhz, ptx, sens, n_exp = 2440.0, 0.0, -94.0, 2.6
    map_size = 30.0
    band = {"f0": 2400.0, "f1": 2483.5, "unit": "MHz", "chans": [("adv%d" % c, f, 1.0) for c, f in BLE_ADV.items()] + [("d%d" % c, ble_data_freq(c), 1.0) for c in range(37)]}
    medium = "Bluetooth Low Energy: a heart-rate strap advertises, a phone scans, connects, discovers GATT services and receives notifications while hopping over 37 data channels"
    faults = [("range", "Runner leaves the phone behind (12 m, body shadowing)", "Packets are lost and retransmitted (SN / NESN); after the supervision timeout the link drops."),
              ("wifi", "Busy Wi-Fi on channel 6 (BLE data ch 11-20)", "Lost packets on those channels; the phone sends a new channel map that excludes them (adaptive frequency hopping)."),
              ("batt", "Strap battery low", "The battery level characteristic (0x2A19) drops and is notified.")]
    spec = [("Standard", "Bluetooth Core Specification 5.x (Bluetooth SIG): LE 1M / 2M / Coded PHYs, GATT"),
            ("Radio", "2.4 GHz GFSK, 40 channels x 2 MHz: 3 advertising (37, 38, 39) + 37 data channels; frequency hopping per connection event"),
            ("Link layer", "Advertising PDUs (ADV_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND); data PDUs with LLID, SN, NESN, MD; CRC-24"),
            ("Connection", "Access address, interval 7.5 ms - 4 s, peripheral latency, supervision timeout, channel map, hop increment"),
            ("Host", "L2CAP > ATT / GATT: services, characteristics, descriptors (CCCD 0x2902 enables notifications); SMP pairing"),
            ("Profiles", "Heart Rate service 0x180D, measurement 0x2A37; Battery service 0x180F, level 0x2A19")]
    frame = [["LE packet (1M)", ("Preamble", 8), ("Access address", 32), ("PDU header", 16), ("Payload", "0-251 B"), ("CRC", 24)],
             ["Data PDU header", ("LLID", 2), ("NESN", 1), ("SN", 1), ("MD", 1), ("RFU", 3), ("Length", 8)]]
    about = ("Bluetooth Low Energy connects a phone to wearables and sensors. Devices advertise on three fixed channels; once connected, both sides "
             "wake up only at agreed connection events, hopping to a new data channel each time. Above the link layer, everything is GATT: the "
             "peripheral exposes services and characteristics, and the phone reads them or asks to be notified when they change.")
    guide = ["SPECTRUM: advertising on channels 37 / 38 / 39, then connection events hopping across the data channels.",
             "Select CONNECT_IND: access address, interval, timeout, channel map, hop increment.",
             "Follow GATT: MTU exchange, Read By Group Type (services), write 0x0001 to the CCCD, then notifications.",
             "Turn on Wi-Fi interference and find the LL_CHANNEL_MAP_IND that removes the bad channels."]

    AA = 0x5A7E3C91

    def setup(self):
        self.rnode("hr", "HEART-RATE STRAP", "sensor", 5, 6, "c4:7b:12:00:a1:9e", "peripheral", w=118)
        self.rnode("ph", "SMARTPHONE", "phone", 14, 7, "", "central", w=104)
        self.rnode("bc", "PROXIMITY BEACON", "radio", 23, 2, "", "non-connectable", w=118)
        self.pairs = [("hr", "ph"), ("bc", "ph")]
        self.user = "ph"
        self.conn = False
        self.unm = 0
        self.hop = 7
        self.ev = 0
        self.sn = 0
        self.chmap = list(range(37))
        self.hr = 72
        self.batt = 88
        self.notif = False
        self.by["ph"].vars.update({"State": "scanning", "Heart rate": "-", "Battery": "-", "Channel map": "37 channels"})
        self.by["hr"].vars.update({"State": "advertising"})
        self.every(0.1, self.advertise, 0.05)
        self.every(1.0, self.beacon, 0.3)
        self.at(0.5, self.connect)

    def air(self, src, dst, ch, p, info, kind, err=None):
        f = BLE_ADV.get(ch) if ch >= 37 else ble_data_freq(ch)
        bits = []
        for byte in p.b[:12]:
            bits += lsb(byte, 8)
        fr = rf_frame(self, src, dst, "BLE", "[ch %d] %s" % (ch, info), p, len(p.b) * 8e-6, f, 1.0, kind, key=info.split(":")[0].split(" (")[0], err=err,
                      rssi=int(self.radio_model.rssi(src, dst or "ph")), wirefn=lambda fr_, b=bits: fsk_wire(b, 1e6, 250.0, lead=8, gauss=0.5))
        return self.tx(fr, bus="air", ifs=150e-6)

    def adv_pdu(self, ptype, adva, adv_data, rows, txadd=0):
        names = {0: "ADV_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ", 4: "SCAN_RSP", 5: "CONNECT_IND"}
        payload = adva + adv_data
        hdr = bytes([ptype | (txadd << 6), len(payload)])
        out = [[0, "BLE advertising channel PDU", 0, 2 + len(payload), ""], [1, "Header: %s, TxAdd %d, length %d" % (names[ptype], txadd, len(payload)), 0, 2,
                                                                                "PDU type (4 bits), ChSel, TxAdd / RxAdd (public / random), length."]]
        out.append([1, "AdvA: %s" % ":".join("%02x" % x for x in adva[::-1]), 2, 6, "Advertiser address (little-endian)."])
        k = 8
        for lab, n, txt, desc in rows:
            out.append([1, "%s: %s" % (lab, txt), k, n, desc])
            k += n
        return hdr + payload, out

    def advertise(self):
        if self.conn:
            return
        adva = bytes.fromhex("9ea100127bc4")
        ad = bytes([2, 0x01, 0x06]) + bytes([3, 0x03, 0x0D, 0x18]) + bytes([9, 0x09]) + b"HRM-1042"
        data, rows = self.adv_pdu(0, adva, ad, [("AD flags", 3, "0x06 LE general discoverable, BR/EDR not supported", ""),
                                                ("AD 16-bit service UUIDs", 4, "0x180D Heart Rate", ""), ("AD complete local name", 10, '"HRM-1042"', "")])
        for i, ch in enumerate((37, 38, 39)):
            self.at(self.t + 0.0004 * i, self.air, "hr", None, ch, ble_air(0x8E89BED6, rows, data, "BLE ADV_IND"), "ADV_IND HRM-1042 (connectable, Heart Rate)", "bcast")

    def beacon(self):
        adva = bytes.fromhex("010203a4b5c6")
        ad = bytes([2, 0x01, 0x04]) + bytes([7, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0xC5, 0x00])
        data, rows = self.adv_pdu(2, adva, ad, [("AD flags", 3, "0x04 BR/EDR not supported", ""), ("AD manufacturer data", 8, "company 0xFFFF (test), id 0x0201, TX power -59 dBm", "")], 1)
        self.air("bc", None, 37 + int(self.t) % 3, ble_air(0x8E89BED6, rows, data, "BLE ADV_NONCONN_IND"), "ADV_NONCONN_IND beacon (broadcast only)", "bcast")

    def connect(self):
        adva = bytes.fromhex("9ea100127bc4")
        inita = bytes.fromhex("33221100aabb")
        sreq = inita + adva
        d = bytes([3 | (1 << 6), 12]) + sreq
        self.air("ph", "hr", 37, ble_air(0x8E89BED6, [[0, "BLE advertising channel PDU", 0, len(d), ""], [1, "Header: SCAN_REQ", 0, 2, ""], [1, "ScanA (phone)", 2, 6, ""],
                                                      [1, "AdvA (strap)", 8, 6, ""]], d, "BLE SCAN_REQ"), "SCAN_REQ (phone asks for more data)", "cmd")
        srsp = adva + bytes([5, 0x16, 0x0F, 0x18, self.batt, 0x00])
        d2 = bytes([4, len(srsp)]) + srsp
        self.at(self.t + 0.0004, self.air, "hr", "ph", 37, ble_air(0x8E89BED6, [[0, "BLE advertising channel PDU", 0, len(d2), ""], [1, "Header: SCAN_RSP", 0, 2, ""],
                                                                                [1, "AD service data: Battery 0x180F = %d %%" % self.batt, 8, 6, ""]], d2, "BLE SCAN_RSP"), "SCAN_RSP", "resp")
        ll = struct.pack("<I", self.AA) + bytes([0x2C, 0x9A, 0x51]) + bytes([2]) + struct.pack("<HHHH", 3, 24, 0, 400) + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]) + bytes([self.hop | (5 << 5)])
        d3 = bytes([5 | (1 << 6), 34]) + inita + adva + ll
        rows = [[0, "BLE advertising channel PDU", 0, len(d3), ""], [1, "Header: CONNECT_IND", 0, 2, ""], [1, "InitA (phone)", 2, 6, ""], [1, "AdvA (strap)", 8, 6, ""],
                [1, "Access address: 0x%08X" % self.AA, 14, 4, "Random, identifies this connection."], [1, "CRCInit: 0x519A2C", 18, 3, ""],
                [1, "WinSize 2 x 1.25 ms, WinOffset 3", 21, 3, ""], [1, "Interval: 24 x 1.25 = 30 ms", 24, 2, "Time between connection events."],
                [1, "Peripheral latency: 0", 26, 2, ""], [1, "Supervision timeout: 400 x 10 ms = 4 s", 28, 2, "Link lost if nothing is received for this long."],
                [1, "Channel map: all 37 data channels", 30, 5, ""], [1, "Hop increment %d, SCA 5" % self.hop, 35, 1, "Channel selection #1: next = (last + hop) mod 37."]]
        self.at(self.t + 0.1, self.air, "ph", "hr", 38, ble_air(0x8E89BED6, rows, d3, "BLE CONNECT_IND"), "CONNECT_IND: AA 0x%08X, interval 30 ms, timeout 4 s, hop %d" % (self.AA, self.hop), "ctl")
        self.at(self.t + 0.11, self._connected)

    def _connected(self):
        self.conn = True
        self.by["ph"].vars["State"] = "connected"
        self.by["hr"].vars["State"] = "connected (peripheral)"
        self.gatt = [("ph", "ATT Exchange MTU Request: client Rx MTU 247", bytes([0x02, 0xF7, 0x00])),
                     ("hr", "ATT Exchange MTU Response: server Rx MTU 247", bytes([0x03, 0xF7, 0x00])),
                     ("ph", "ATT Read By Group Type Request 0x0001-0xFFFF: Primary Service (0x2800)", bytes([0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28])),
                     ("hr", "ATT Read By Group Type Response: 0x0001-0x0005 GAP, 0x0006-0x000B Heart Rate 0x180D, 0x000C-0x000F Battery 0x180F",
                      bytes([0x11, 0x06, 0x01, 0x00, 0x05, 0x00, 0x00, 0x18, 0x06, 0x00, 0x0B, 0x00, 0x0D, 0x18, 0x0C, 0x00, 0x0F, 0x00, 0x0F, 0x18])),
                     ("ph", "ATT Write Request handle 0x0009 (CCCD of 0x2A37) = 0x0001: enable notifications", bytes([0x12, 0x09, 0x00, 0x01, 0x00])),
                     ("hr", "ATT Write Response", bytes([0x13]))]
        self.every(0.03, self.event, 0.03)

    def next_ch(self):
        self.unm = (self.unm + self.hop) % 37
        if self.unm in self.chmap:
            return self.unm
        return self.chmap[self.unm % len(self.chmap)]

    def data_pdu(self, llid, att, txt):
        l2 = struct.pack("<HH", len(att), 0x0004) + att if att else b""
        hdr = bytes([llid | (self.sn << 3) | ((1 - self.sn) << 2), len(l2)])
        rows = [[0, "BLE data channel PDU", 0, 2 + len(l2), ""], [1, "Header: LLID %d (%s), SN %d, length %d" % (llid, {1: "empty / continuation", 2: "L2CAP start", 3: "LL control"}[llid],
                                                                                                                 self.sn, len(l2)), 0, 2, "SN / NESN acknowledge and detect retransmissions."]]
        if att:
            rows += [[0, "L2CAP: length %d, CID 0x0004 (ATT)" % len(att), 2, 4, ""], [0, "ATT: %s" % txt, 6, len(att), ""]]
        return hdr + l2, rows

    def event(self):
        if not self.conn:
            return
        self.ev += 1
        ch = self.next_ch()
        lost = (self.fault["range"] and self.rng.random() < 0.6) or (self.fault["wifi"] and 11 <= ch <= 20 and self.rng.random() < 0.7)
        msg = None
        if self.gatt:
            who, txt, att = self.gatt[0]
            if not lost:
                self.gatt.pop(0)
                if not self.gatt:
                    self.notif = True
            msg = (who, txt, att)
        elif self.notif and self.ev % 33 == 0:
            self.hr = int(72 + 8 * math.sin(self.t / 10))
            msg = ("hr", "ATT Handle Value Notification handle 0x0008 (Heart Rate Measurement): flags 0x00, %d bpm" % self.hr, bytes([0x1B, 0x08, 0x00, 0x00, self.hr]))
        if msg and msg[0] == "ph":
            d, rows = self.data_pdu(2, msg[2], msg[1])
            self.air("ph", "hr", ch, ble_air(self.AA, rows, d, "BLE data PDU"), msg[1], "cmd", "Lost (no response in this event)" if lost else None)
            d2, r2 = self.data_pdu(1, b"", "")
            if not lost:
                self.at(self.t + 0.00015 + len(d) * 8e-6, self.air, "hr", "ph", ch, ble_air(self.AA, r2, d2, "BLE data PDU (empty, ack)"), "Empty PDU (acknowledges via NESN)", "ack")
        else:
            d, rows = self.data_pdu(1, b"", "")
            if self.ev % 10 == 0 or msg:
                self.air("ph", "hr", ch, ble_air(self.AA, rows, d, "BLE data PDU (empty)"), "Empty PDU: connection event %d (keeps the link alive)" % self.ev, "sync",
                         "Lost" if lost else None)
            if msg and not lost:
                d2, r2 = self.data_pdu(2, msg[2], msg[1])
                self.at(self.t + 0.00025, self.air, "hr", "ph", ch, ble_air(self.AA, r2, d2, "BLE data PDU"), msg[1], "data")
                if "bpm" in msg[1]:
                    self.by["ph"].vars["Heart rate"] = "%d bpm" % self.hr
        if not lost:
            self.sn ^= 1
            self.miss = 0
        else:
            self.miss = getattr(self, "miss", 0) + 1
            if self.fault["range"] and self.miss > 133:
                self.conn = False
                self.by["ph"].vars["State"] = "disconnected: supervision timeout (4 s)"
                self.by["hr"].vars["State"] = "advertising again"
                self.log("Link lost: no packet received within the 4 s supervision timeout")
                self.at(self.t + 1.0, self._readvertise)
        if self.fault["wifi"] and self.ev % 40 == 20 and any(11 <= c <= 20 for c in self.chmap):
            self.chmap = [c for c in range(37) if not 11 <= c <= 20]
            ctl = bytes([0x01]) + bytes([0xFF, 0x07, 0xE0, 0xFF, 0x1F]) + struct.pack("<H", self.ev + 6)
            d, rows = self.data_pdu(3, b"", "")
            dd = bytes([3 | (self.sn << 3), len(ctl)]) + ctl
            self.at(self.t + 0.0003, self.air, "ph", "hr", ch, ble_air(self.AA, [[0, "BLE data channel PDU", 0, len(dd), ""], [1, "Header: LLID 3 (LL control)", 0, 2, ""],
                                                                                 [1, "Opcode 0x01 LL_CHANNEL_MAP_IND", 2, 1, ""], [1, "New channel map: data ch 11-20 excluded", 3, 5, ""],
                                                                                 [1, "Instant: event %d" % (self.ev + 6), 8, 2, "Both sides switch at this connection event."]], dd,
                                                                    "BLE LL_CHANNEL_MAP_IND"), "LL_CHANNEL_MAP_IND: exclude channels 11-20 (Wi-Fi), instant %d" % (self.ev + 6), "ctl")
            self.by["ph"].vars["Channel map"] = "27 channels (11-20 excluded)"
        if self.fault["batt"] and self.notif and self.ev % 150 == 75:
            self.batt = max(5, self.batt - 7)
            self.gatt.append(("hr", "ATT Handle Value Notification handle 0x000E (Battery Level 0x2A19): %d %%" % self.batt, bytes([0x1B, 0x0E, 0x00, self.batt])))
            self.by["ph"].vars["Battery"] = "%d %%" % self.batt

    def _readvertise(self):
        if self.fault["range"]:
            self.at(self.t + 1.0, self._readvertise)
            return
        self.chmap = list(range(37))
        self.at(self.t + 0.2, self.connect)

    def on_fault(self, key, on):
        if key == "range":
            self.radio_model.extra[("hr", "ph")] = 28.0 if on else 0.0
        if key == "wifi" and not on:
            self.chmap = list(range(37))
            self.by["ph"].vars["Channel map"] = "37 channels"

    def tpls(self):
        return [Tpl("Read battery level", [], lambda s, v, send: self._rd(send), "ATT Read Request on handle 0x000E.")]

    def _rd(self, send):
        att = bytes([0x0A, 0x0E, 0x00])
        if not send:
            d, rows = self.data_pdu(2, att, "ATT Read Request handle 0x000E")
            return Frame(self.t, 0.0001, "ph", "hr", "BLE", "preview", pdu=ble_air(self.AA, rows, d, "BLE data PDU"))
        self.gatt += [("ph", "ATT Read Request handle 0x000E (Battery Level)", att), ("hr", "ATT Read Response: %d %%" % self.batt, bytes([0x0B, self.batt]))]
        self.by["ph"].vars["Battery"] = "%d %%" % self.batt
        return None


# ================================================================== Wi-Fi
def macb_(m):
    return bytes(int(x, 16) for x in m.split(":"))


def ie(eid, data, txt, name):
    return ("IE %d %s" % (eid, name), bytes([eid, len(data)]) + data, txt, "")


RSN = bytes([1, 0]) + bytes([0x00, 0x0F, 0xAC, 4]) + bytes([1, 0]) + bytes([0x00, 0x0F, 0xAC, 4]) + bytes([1, 0]) + bytes([0x00, 0x0F, 0xAC, 2]) + bytes([0x0C, 0x00])


def dot11(ftype, sub, a1, a2=None, a3=None, seq=0, body=(), flags=0, qos=None, dur=44, title=None):
    tn = {(0, 8): "Beacon", (0, 4): "Probe Request", (0, 5): "Probe Response", (0, 11): "Authentication", (0, 0): "Association Request", (0, 1): "Association Response",
          (0, 12): "Deauthentication", (1, 13): "ACK", (1, 11): "RTS", (1, 12): "CTS", (2, 8): "QoS Data", (2, 0): "Data"}.get((ftype, sub), "?")
    b = Bld(title or "IEEE 802.11 %s" % tn, "MAC frame: frame control, duration, addresses, sequence control, body, FCS.")
    b.u8("Frame control: type / subtype", (sub << 4) | (ftype << 2), "%s (type %d, subtype %d)" % (tn, ftype, sub), "")
    fl = []
    for bit, nm in ((1, "ToDS"), (2, "FromDS"), (8, "Retry"), (16, "PwrMgt"), (32, "MoreData"), (64, "Protected")):
        if flags & bit:
            fl.append(nm)
    b.u8("Frame control: flags", flags, ", ".join(fl) or "none", "ToDS / FromDS say which way the frame goes through the AP; Protected = encrypted body.")
    b.u16("Duration / ID", dur, "%d us" % dur, "NAV: how long the medium stays reserved (virtual carrier sense).", little=True)
    b.raw("Address 1 (receiver)", macb_(a1), a1, "")
    if a2:
        b.raw("Address 2 (transmitter)", macb_(a2), a2, "")
    if a3:
        b.raw("Address 3", macb_(a3), a3, "BSSID for management frames; DA / SA for data frames through an AP.")
        b.u16("Sequence control", seq << 4, "sequence %d, fragment 0" % seq, "Duplicate detection after retries.", little=True)
    if qos is not None:
        b.u16("QoS control", qos, "TID %d (%s)" % (qos & 7, {0: "best effort", 5: "video", 6: "voice"}.get(qos & 7, "")), "", little=True)
    for lab, data, txt, desc in body:
        b.raw(lab, data, txt, desc)
    import zlib
    fcs = zlib.crc32(bytes(b.b)) & 0xFFFFFFFF
    b.u32("FCS", fcs, "0x%08X [correct]" % fcs, "CRC-32 over the whole MAC frame.", little=True)
    return b.done()


def eapol(n, replay, mic_ok=True):
    ki = {1: 0x008A, 2: 0x010A, 3: 0x13CA, 4: 0x030A}[n]
    desc = {1: "ANonce from the AP", 2: "SNonce + MIC (proves the station knows the passphrase)", 3: "install PTK, GTK encrypted in key data", 4: "done"}[n]
    body = [("LLC / SNAP", bytes([0xAA, 0xAA, 0x03, 0, 0, 0, 0x88, 0x8E]), "EtherType 0x888E (802.1X)", ""),
            ("802.1X header", bytes([2, 3, 0, 95]), "version 2, type 3 (EAPOL-Key), length 95", ""),
            ("Key descriptor type", b"\x02", "2 (RSN)", ""),
            ("Key information", struct.pack(">H", ki), "0x%04X: %s" % (ki, {1: "pairwise, ACK", 2: "pairwise, MIC", 3: "pairwise, install, ACK, MIC, secure, encrypted key data",
                                                                          4: "pairwise, MIC, secure"}[n]), ""),
            ("Key length", struct.pack(">H", 16), "16", ""), ("Replay counter", struct.pack(">Q", replay), str(replay), ""),
            ("Key nonce", bytes((i * 7 + n) & 255 for i in range(32)) if n in (1, 2, 3) else bytes(32), "ANonce" if n in (1, 3) else ("SNonce" if n == 2 else "zero"), ""),
            ("Key IV / RSC / reserved", bytes(32), "", ""),
            ("Key MIC", bytes(16) if n == 1 else bytes((i * 13 + n) & 255 for i in range(16)), "none" if n == 1 else ("valid" if mic_ok else "INVALID (wrong passphrase)"),
             "HMAC over the EAPOL frame with the KCK derived from the PMK (passphrase + SSID)."),
            ("Key data length", struct.pack(">H", 22 if n in (2, 3) else 0), "", "")]
    return body


class WiFi(RfNet):
    key, name, cat = "wifi", "Wi-Fi (802.11)", "net"
    blurb = "Wireless LANs"
    f_mhz, ptx, sens, n_exp = 2437.0, 20.0, -82.0, 3.0
    map_size = 60.0
    band = {"f0": 2400.0, "f1": 2483.5, "unit": "MHz", "chans": [("ch1", 2412.0, 20.0), ("ch6", 2437.0, 20.0), ("ch11", 2462.0, 20.0)]}
    medium = "Wi-Fi 2.4 GHz channel 6 (WPA2-Personal): an access point, a laptop on a video call, an IP camera; a phone joins - probe, auth, association, 4-way handshake"
    faults = [("psk", "Phone has the wrong passphrase", "Message 2 of the 4-way handshake carries a MIC the AP cannot verify; after retries the AP deauthenticates (reason 15)."),
              ("hidden", "Laptop and camera cannot hear each other (hidden nodes)", "Their frames collide at the AP; after repeated failures the stations switch to RTS / CTS."),
              ("far", "Phone moves to the far end of the house", "Weaker signal: rate adaptation steps down the MCS, more retries."),
              ("noise", "Microwave oven running", "Wide-band interference: many frames need retries (Retry flag set).")]
    spec = [("Standards", "IEEE 802.11-2020 (a/b/g/n/ac/ax = Wi-Fi 4/5/6/6E/7), WPA2 / WPA3 (Wi-Fi Alliance)"),
            ("Channels", "2.4 GHz: 20 MHz channels, only 1 / 6 / 11 do not overlap; 5 GHz and 6 GHz: 20-320 MHz"),
            ("Access", "CSMA/CA: DIFS, random backoff in 9 us slots, ACK after SIFS (16 us); RTS / CTS for hidden nodes; NAV from the Duration field"),
            ("Joining", "Beacons / probe, open authentication, association (AID), then 802.1X / PSK 4-way handshake derives the keys"),
            ("Security", "CCMP (AES-CCM) with a per-station key (PTK) and a group key (GTK); WPA3 uses SAE instead of the PSK handshake"),
            ("Rates", "OFDM 6-54 Mbit/s, HT/VHT/HE MCS 0-11 with rate adaptation")]
    frame = [["802.11 MAC frame", ("FC", 16), ("Duration", 16), ("Addr1 RA", 48), ("Addr2 TA", 48), ("Addr3", 48), ("Seq ctl", 16), ("QoS", 16), ("[CCMP hdr]", 64),
              ("Body", "n x 8"), ("[MIC]", 64), ("FCS", 32)]]
    about = ("Wi-Fi is Ethernet over radio, with the extra work radio needs: stations listen before sending and back off randomly, every "
             "unicast frame is acknowledged, and an access point announces itself with beacons ten times a second. Joining a WPA2 network "
             "takes a probe, an authentication, an association and the 4-way key handshake; after that every data frame is encrypted.")
    guide = ["Select a beacon: SSID, supported rates, DS channel, RSN (WPA2, CCMP, PSK).",
             "Follow the phone joining: probe, authentication, association (AID), EAPOL messages 1-4.",
             "Look at an encrypted QoS data frame: Protected flag, CCMP header with the packet number, then the ACK after SIFS.",
             "Enter the wrong passphrase and watch message 2 fail."]

    AP, LAP, CAM, PH = "f0:9f:c2:10:00:01", "3c:52:82:10:00:20", "b0:c5:54:00:00:33", "a4:77:33:00:00:40"

    def setup(self):
        self.rnode("ap", "ACCESS POINT", "router", 28, 12, "CommSim-Lab", "ch 6, WPA2", w=118)
        self.rnode("lap", "LAPTOP (VIDEO CALL)", "laptop", 6, 5, "", "MCS 7", w=124)
        self.rnode("cam", "IP CAMERA", "camera", 50, 5, "", "MCS 5", w=104)
        self.rnode("ph", "PHONE (JOINING)", "phone", 40, 21, "", "", w=118)
        self.pairs = [("lap", "ap"), ("cam", "ap"), ("ph", "ap")]
        self.user = "ph"
        self.sn = {k: 100 * (i + 1) for i, k in enumerate(("ap", "lap", "cam", "ph"))}
        self.pn = 1
        self.joined = False
        self.rts = False
        self.mcs = 7
        self.by["ap"].vars.update({"Stations": "laptop, camera", "Beacons": 0})
        self.by["ph"].vars.update({"State": "scanning", "Rate": "-", "Retries": 0})
        self.every(0.1024, self.beacon, 0.01)
        self.every(0.04, self.lap_traffic, 0.02)
        self.every(0.066, self.cam_traffic, 0.03)
        self.at(1.0, self.join)
        self.every(0.5, self.phone_traffic, 3.0)

    def mac(self, k):
        return {"ap": self.AP, "lap": self.LAP, "cam": self.CAM, "ph": self.PH}[k]

    def air(self, src, dst, p, info, kind, rate, err=None):
        dur = 20e-6 + len(p.b) * 8 / (rate * 1e6)
        fr = rf_frame(self, src, dst, "802.11", info, p, dur, 2437.0, 20.0, kind, key=info.split(" ")[0] + " " + info.split(" ")[1] if " " in info else info, err=err,
                      rssi=int(self.radio_model.rssi(src, dst or "ph")), wirefn=lambda f, d=dur: burst_wire(d, seed=len(p.b), label="OFDM (%g Mbit/s)" % rate))
        return self.tx(fr, bus="air", ifs=28e-6 + 9e-6 * float(self.rng.integers(0, 16)))

    def ack(self, src, dst):
        p = dot11(1, 13, self.mac(dst), dur=0)
        self.air(src, dst, p, "ACK -> %s" % self.mac(dst), "ack", 24.0)

    def beacon(self):
        self.sn["ap"] = (self.sn["ap"] + 1) & 4095
        body = [("Timestamp", struct.pack("<Q", int(self.t * 1e6)), "%d us" % int(self.t * 1e6), "TSF timer for synchronisation."),
                ("Beacon interval", struct.pack("<H", 100), "100 TU (102.4 ms)", ""), ("Capability", struct.pack("<H", 0x0411), "ESS, privacy, short slot", ""),
                ie(0, b"CommSim-Lab", '"CommSim-Lab"', "SSID"), ie(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]), "1(B) 2(B) 5.5(B) 11(B) 6 9 12 18 Mbit/s", "Supported rates"),
                ie(3, b"\x06", "channel 6", "DS parameter set"), ie(5, bytes([0, 1, 0, 0]), "DTIM count 0, period 1", "TIM"),
                ie(48, RSN, "RSN v1: group CCMP, pairwise CCMP, AKM PSK", "RSN (WPA2)"), ie(45, bytes(26), "HT capabilities (802.11n)", "HT capabilities")]
        self.air("ap", None, dot11(0, 8, "ff:ff:ff:ff:ff:ff", self.AP, self.AP, self.sn["ap"], body, dur=0), "Beacon SSID=CommSim-Lab ch 6 WPA2", "sync", 1.0)
        self.by["ap"].vars["Beacons"] += 1

    def data(self, src, dst, n, info, tid=0, rate=65.0, retry=0, err=None):
        self.sn[src] = (self.sn[src] + 1) & 4095
        self.pn += 1
        tods = 1 if dst == "ap" else 2
        a1, a2 = self.mac(dst), self.mac(src)
        a3 = "00:1b:21:aa:00:01"
        body = [("CCMP header", struct.pack("<HBB", self.pn & 0xFFFF, 0, 0x20) + struct.pack("<I", self.pn >> 16), "PN %d, key ID 0" % self.pn,
                 "Packet number: increments every frame, replay protection."),
                ("Encrypted payload", bytes(n), "%d bytes (LLC + IP + ...)" % n, "AES-CCM encrypted with the pairwise key."), ("CCMP MIC", bytes(8), "8 bytes", "")]
        p = dot11(2, 8, a1, a2, a3, self.sn[src], body, tods | 64 | (8 if retry else 0), qos=tid, title="IEEE 802.11 QoS Data (protected)")
        fr = self.air(src, dst, p, "QoS Data %s -> %s, %d bytes, MCS %s%s" % (src, dst, n, {65.0: 7, 39.0: 4, 26.0: 3, 13.0: 1, 6.5: 0}.get(rate, "?"), " RETRY" if retry else ""),
                      "data", rate, err)
        if not err:
            self.at(fr.t + fr.dur + 16e-6, self.ack, dst, src)
        return fr

    def lap_traffic(self):
        if self.fault["hidden"] and not self.rts and self.rng.random() < 0.4:
            self.data("lap", "ap", 1200, "video", 5, 65.0, 0, "Collision at the AP with the camera (hidden node)")
            self.coll = getattr(self, "coll", 0) + 1
            if self.coll > 6:
                self.rts = True
                self.log("Laptop: repeated failures - enabling RTS/CTS")
            self.at(self.t + 0.002, self.data, "lap", "ap", 1200, "video", 5, 65.0, 1)
            return
        if self.rts:
            self.air("lap", "ap", dot11(1, 11, self.AP, self.LAP, dur=320), "RTS laptop -> AP (reserve 320 us)", "ctl", 24.0)
            self.at(self.t + 0.00005, self.air, "ap", "lap", dot11(1, 12, self.LAP, dur=280), "CTS -> laptop (heard by the camera too: it defers)", "ctl", 24.0)
            self.at(self.t + 0.0001, self.data, "lap", "ap", 1200, "video", 5)
            return
        err = "Corrupted by interference (FCS error)" if (self.fault["noise"] and self.rng.random() < 0.3) else None
        self.data("lap", "ap", 1200, "video", 5, 65.0, 0, err)
        if err:
            self.at(self.t + 0.0006, self.data, "lap", "ap", 1200, "video", 5, 65.0, 1)

    def cam_traffic(self):
        self.data("cam", "ap", 1400, "camera stream", 5, 39.0)

    def join(self):
        body = [ie(0, b"CommSim-Lab", '"CommSim-Lab"', "SSID"), ie(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]), "rates", "Supported rates")]
        self.air("ph", None, dot11(0, 4, "ff:ff:ff:ff:ff:ff", self.PH, "ff:ff:ff:ff:ff:ff", 1, body, dur=0), "Probe Request SSID=CommSim-Lab", "bcast", 1.0)
        self.at(self.t + 0.002, self.air, "ap", "ph", dot11(0, 5, self.PH, self.AP, self.AP, 7, body + [ie(48, RSN, "WPA2-PSK, CCMP", "RSN")]), "Probe Response", "resp", 1.0)
        self.at(self.t + 0.003, self.ack, "ph", "ap")
        auth = [("Auth algorithm", struct.pack("<H", 0), "0 Open System", "WPA2-PSK uses open authentication; the real check is the 4-way handshake."),
                ("Auth sequence", struct.pack("<H", 1), "1", ""), ("Status", struct.pack("<H", 0), "0 success", "")]
        self.at(self.t + 0.010, self.air, "ph", "ap", dot11(0, 11, self.AP, self.PH, self.AP, 2, auth), "Authentication (Open System, seq 1)", "ctl", 1.0)
        self.at(self.t + 0.012, self.air, "ap", "ph", dot11(0, 11, self.PH, self.AP, self.AP, 8, auth[:1] + [("Auth sequence", struct.pack("<H", 2), "2", ""), auth[2]]),
                "Authentication (seq 2, success)", "resp", 1.0)
        ar = [("Capability", struct.pack("<H", 0x0411), "", ""), ("Listen interval", struct.pack("<H", 10), "10 beacons", ""), ie(0, b"CommSim-Lab", '"CommSim-Lab"', "SSID"),
              ie(48, RSN, "WPA2-PSK, CCMP", "RSN")]
        self.at(self.t + 0.020, self.air, "ph", "ap", dot11(0, 0, self.AP, self.PH, self.AP, 3, ar), "Association Request", "ctl", 1.0)
        self.at(self.t + 0.022, self.air, "ap", "ph", dot11(0, 1, self.PH, self.AP, self.AP, 9, [("Capability", struct.pack("<H", 0x0411), "", ""),
                                                                                            ("Status", struct.pack("<H", 0), "0 success", ""),
                                                                                            ("AID", struct.pack("<H", 0xC003), "3", "Association ID used in the TIM.")]),
                "Association Response: AID 3", "resp", 1.0)
        self.at(self.t + 0.03, self.handshake, 0)
        self.by["ph"].vars["State"] = "associated, 4-way handshake"

    def handshake(self, tries):
        rc = 1 + tries
        m1 = dot11(2, 8, self.PH, self.AP, self.AP, 10 + tries, eapol(1, rc), 2, qos=7, title="IEEE 802.11 QoS Data: EAPOL-Key message 1/4")
        self.air("ap", "ph", m1, "EAPOL-Key 1/4 (ANonce)%s" % (" retry %d" % tries if tries else ""), "ctl", 24.0)
        ok = not self.fault["psk"]
        m2 = dot11(2, 8, self.AP, self.PH, self.AP, 4 + tries, eapol(2, rc, ok), 1, qos=7, title="IEEE 802.11 QoS Data: EAPOL-Key message 2/4")
        self.at(self.t + 0.004, self.air, "ph", "ap", m2, "EAPOL-Key 2/4 (SNonce, MIC%s)" % ("" if ok else " INVALID"), "ctl" if ok else "err", 24.0)
        if not ok:
            if tries < 2:
                self.at(self.t + 1.0, self.handshake, tries + 1)
            else:
                deauth = dot11(0, 12, self.PH, self.AP, self.AP, 20, [("Reason code", struct.pack("<H", 15), "15 4-way handshake timeout", "")])
                self.at(self.t + 1.0, self.air, "ap", "ph", deauth, "Deauthentication reason 15 (4-way handshake timeout: wrong passphrase?)", "err", 1.0)
                self.by["ph"].vars["State"] = "failed: wrong passphrase"
            return
        m3 = dot11(2, 8, self.PH, self.AP, self.AP, 11 + tries, eapol(3, rc + 1), 2, qos=7, title="IEEE 802.11 QoS Data: EAPOL-Key message 3/4")
        self.at(self.t + 0.008, self.air, "ap", "ph", m3, "EAPOL-Key 3/4 (install, GTK)", "ctl", 24.0)
        m4 = dot11(2, 8, self.AP, self.PH, self.AP, 6 + tries, eapol(4, rc + 1), 1, qos=7, title="IEEE 802.11 QoS Data: EAPOL-Key message 4/4")
        self.at(self.t + 0.012, self.air, "ph", "ap", m4, "EAPOL-Key 4/4 (keys installed)", "ctl", 24.0)
        self.at(self.t + 0.013, self._joined)

    def _joined(self):
        self.joined = True
        self.by["ph"].vars["State"] = "connected (WPA2, CCMP)"
        self.by["ap"].vars["Stations"] = "laptop, camera, phone (AID 3)"

    def phone_traffic(self):
        if not self.joined:
            return
        far = self.fault["far"]
        rates = [65.0, 39.0, 26.0, 13.0, 6.5]
        if far:
            self.mcs = max(0, self.mcs - 1)
        else:
            self.mcs = min(7, self.mcs + 1)
        rate = {7: 65.0, 6: 58.5, 5: 52.0, 4: 39.0, 3: 26.0, 2: 19.5, 1: 13.0, 0: 6.5}[self.mcs]
        lost = far and self.mcs > 2 and self.rng.random() < 0.7
        self.data("ap", "ph", 800, "web", 0, rate, 0, "Not decoded at this MCS (too weak)" if lost else None)
        if lost:
            self.by["ph"].vars["Retries"] += 1
            self.at(self.t + 0.001, self.data, "ap", "ph", 800, "web", 0, max(6.5, rate / 2), 1)
        self.by["ph"].vars["Rate"] = "MCS %d (%.1f Mbit/s)" % (self.mcs, rate)
        del rates

    def on_fault(self, key, on):
        if key == "far":
            self.radio_model.extra[("ph", "ap")] = 25.0 if on else 0.0
        if key == "psk" and not on and not self.joined:
            self.at(self.t + 0.5, self.join)
        if key == "hidden" and not on:
            self.rts = False
            self.coll = 0

    def tpls(self):
        return [Tpl("Re-join the phone", [], lambda s, v, send: self.join() if send else Frame(self.t, 0.001, "ph", None, "802.11", "preview",
                                                                                           pdu=dot11(0, 4, "ff:ff:ff:ff:ff:ff", self.PH, "ff:ff:ff:ff:ff:ff", 1, [ie(0, b"CommSim-Lab", "", "SSID")])),
                    "Probe, authentication, association, 4-way handshake.")]


# ================================================================ LoRaWAN
SENS_SF = {7: -124.0, 8: -127.0, 9: -130.0, 10: -133.0, 11: -135.5, 12: -137.0}


def lora_toa(pl_len, sf, bw=125e3, cr=1, npre=8):
    de = 1 if sf >= 11 else 0
    tsym = (2 ** sf) / bw
    n = 8 + max(math.ceil((8 * pl_len - 4 * sf + 28 + 16) / (4.0 * (sf - 2 * de))) * (cr + 4), 0)
    return (npre + 4.25) * tsym + n * tsym


def lw_frame(mtype, rows, title):
    names = {0: "Join Request", 1: "Join Accept", 2: "Unconfirmed Data Up", 3: "Unconfirmed Data Down", 4: "Confirmed Data Up", 5: "Confirmed Data Down"}
    b = Bld("LoRaWAN %s" % names[mtype], "MAC: MHDR, MAC payload, 4-byte MIC (AES-CMAC with the network session key).")
    b.u8("MHDR", mtype << 5, "MType %d %s, major 0" % (mtype, names[mtype]), "")
    for lab, data, txt, desc in rows:
        b.raw(lab, data, txt, desc)
    mic = crcn("CRC-32/ISO-HDLC", bytes(b.b)) & 0xFFFFFFFF
    b.u32("MIC", mic, "0x%08X (AES-CMAC, simulated)" % mic, "Integrity: the network server recomputes it.", little=True)
    p = b.done()
    return p


class LoRaWAN(RfNet):
    key, name, cat = "lorawan", "LoRaWAN", "net"
    blurb = "Long-range low-power IoT"
    f_mhz, ptx, sens, n_exp = 868.0, 14.0, -137.0, 2.7
    map_size = 9000.0
    map_grid = 1000.0
    band = {"f0": 867.9, "f1": 869.7, "unit": "MHz", "chans": [("868.1", 868.1, 0.125), ("868.3", 868.3, 0.125), ("868.5", 868.5, 0.125), ("RX2 869.525", 869.525, 0.125)]}
    medium = "LoRaWAN EU868: class A sensors send uplinks with chirp spread spectrum (SF7-SF12); two gateways forward them to the network server, which answers in RX1 / RX2"
    faults = [("basement", "Water meter moved into a deep basement (+20 dB loss)", "At its current spreading factor nothing gets through; ADR backs off to SF12."),
              ("gw", "Gateway 1 backhaul (4G) down", "It still hears the sensors but cannot forward: only uplinks that gateway 2 also hears survive."),
              ("reset", "Parking sensor reboots and restarts its frame counter at 0", "The network server drops the frames as replays (FCnt not increasing)."),
              ("duty", "Soil sensor firmware tries to send every 2 s at SF12", "The 1 % duty-cycle limit of the 868.0-868.6 MHz sub-band blocks most of them.")]
    spec = [("Standard", "LoRaWAN 1.0.4 / 1.1 (LoRa Alliance), regional parameters RP002 (EU863-870, US902-928 ...); LoRa PHY (Semtech)"),
            ("PHY", "Chirp spread spectrum, 125 kHz, SF7 (5.5 kbit/s) ... SF12 (250 bit/s); each SF step doubles time on air and adds ~2.5 dB link budget"),
            ("Classes", "A: two receive windows after each uplink (RX1 +1 s, RX2 +2 s on 869.525 MHz); B: beacons + ping slots; C: always listening"),
            ("MAC", "MHDR, DevAddr, FCtrl (ADR, ACK), FCnt, FOpts (MAC commands), FPort, encrypted FRMPayload, MIC"),
            ("Security", "AES-128: NwkSKey for the MIC, AppSKey encrypts the payload; OTAA join derives session keys (DevNonce, JoinNonce)"),
            ("Rules", "EU868 duty cycle 1 % per sub-band; ADR lets the network server lower SF / power when the link margin allows")]
    frame = [["Uplink", ("Preamble 8 up-chirps", "8 sym"), ("Sync + SFD", "4.25 sym"), ("PHDR + CRC", "8 sym"), ("MHDR", 8), ("DevAddr", 32), ("FCtrl", 8), ("FCnt", 16),
              ("FOpts", "0-15 B"), ("FPort", 8), ("FRMPayload", "n x 8"), ("MIC", 32), ("CRC", 16)]]
    about = ("LoRaWAN connects battery sensors that send a few bytes every few minutes over kilometres. The LoRa radio spreads each symbol "
             "over a frequency chirp, so it can be decoded far below the noise floor - at the cost of very low data rates. Sensors simply transmit; "
             "every gateway that hears them forwards the packet to a network server, which removes duplicates and may answer in the two short "
             "receive windows that follow each uplink.")
    guide = ["Watch the OTAA join of the water meter: Join Request (DevEUI, DevNonce), Join Accept in RX1.",
             "Compare an SF7 and an SF12 uplink: time on air 50 ms vs 1.3 s (SPECTRUM, SCOPE frequency).",
             "Find the LinkADRReq in a downlink (FOpts) and the node's LinkADRAns in its next uplink.",
             "Put the water meter in the basement: lost uplinks, then ADR to SF12."]

    def setup(self):
        self.rnode("gw1", "GATEWAY 1 (ROOFTOP)", "tower", 2800, 1500, "eui-b827eb...01", "8 channels", w=140)
        self.rnode("gw2", "GATEWAY 2 (TOWER)", "tower", 7000, 2900, "eui-b827eb...02", "8 channels", w=130)
        for g in ("gw1", "gw2"):
            self.by[g].extra.update(h=30.0, sens=-137.0)
        nodes = [("soil", "SOIL SENSOR", "sensor", 1000, 500, 7, 0x260B1A01), ("wm", "WATER METER", "meter", 4300, 3300, 9, 0x260B1A02), ("park", "PARKING SENSOR", "sensor", 5600, 1100, 8, 0x260B1A03)]
        self.dev = {}
        for nid, lab, kind, x, y, sf, addr in nodes:
            n = self.rnode(nid, lab, kind, x, y, "", "SF%d" % sf, w=118)
            self.dev[nid] = dict(sf=sf, addr=addr, fcnt=0, joined=nid != "wm", last_ns=-1, ch=0, busy_until=0.0, ack_pending=False, adr_ans=False, miss=0)
            n.vars.update({"SF": sf, "FCnt": 0, "Last RSSI": "-"})
        self.pairs = [(n, g) for n in ("soil", "wm", "park") for g in ("gw1", "gw2")]
        self.user = "wm"
        self.by["gw1"].vars.update({"Backhaul": "4G ok", "Forwarded": 0})
        self.by["gw2"].vars.update({"Backhaul": "fibre ok", "Forwarded": 0})
        self.ns = {"Uplinks": 0, "Duplicates removed": 0, "Dropped (replay)": 0}
        self.at(0.3, self.join, "wm")
        self.every(9.0, self.uplink, 1.0, 0.0, "soil")
        self.every(12.0, self.uplink, 2.0, 0.0, "park")
        self.every(15.0, self.uplink, 4.0, 0.0, "wm")
        self.every(2.0, self.duty_try, 2.5)

    def heard(self, nid):
        out = []
        for g in ("gw1", "gw2"):
            r = self.radio_model.rssi(nid, g)
            if r >= SENS_SF[self.dev[nid]["sf"]] + (self.rng.normal(0, 2)):
                out.append((g, r))
        return out

    def radio(self, src, dst, p, info, kind, sf, f, err=None):
        toa = lora_toa(len(p.b), sf)
        syms = [x for x in p.b[:12]]
        fr = rf_frame(self, src, dst, "LoRaWAN", info, p, toa, f, 0.125, kind, key=info.split(":")[0], err=err, rssi=int(self.radio_model.rssi(src, dst or "gw1")),
                      wirefn=lambda f_, s=syms, sf_=sf: chirp_wire(s, sf_, 125.0))
        return self.tx(fr, bus="air:%.1f" % f)

    def join(self, nid):
        d = self.dev[nid]
        d["nonce"] = d.get("nonce", 0x1F00) + 1
        rows = [("JoinEUI", bytes.fromhex("70B3D57ED0000001")[::-1], "70B3D57ED0000001", "Identifies the join server (LSB first)."),
                ("DevEUI", bytes.fromhex("0004A30B00F1C2D3")[::-1], "0004A30B00F1C2D3", "Unique device ID."),
                ("DevNonce", struct.pack("<H", d["nonce"]), "0x%04X" % d["nonce"], "Must never repeat: replay protection for joins.")]
        p = lw_frame(0, rows, "Join Request")
        f = (868.1, 868.3, 868.5)[d["nonce"] % 3]
        hs = self.heard(nid)
        fr = self.radio(nid, None, p, "Join Request DevEUI 0004A30B00F1C2D3 DevNonce 0x%04X (SF%d)" % (d["nonce"], d["sf"]), "ctl", d["sf"], f, None if hs else "Not received by any gateway")
        if not hs:
            self.at(self.t + 8.0, self.join, nid)
            return
        end = fr.t + fr.dur
        acc = [("JoinNonce", bytes([0x01, 0x22, 0x33]), "0x332201", ""), ("NetID", bytes([0x13, 0x00, 0x00]), "0x000013", ""),
               ("DevAddr", struct.pack("<I", d["addr"]), "0x%08X" % d["addr"], "Short address for this session."),
               ("DLSettings", b"\x00", "RX1 DR offset 0, RX2 DR0", ""), ("RxDelay", b"\x01", "1 s", "")]
        p2 = lw_frame(1, acc, "Join Accept")
        p2.rows.append([0, "The Join Accept is AES-encrypted with the AppKey (shown decrypted)", None, 0, ""])
        gw = max(hs, key=lambda x: x[1])[0]
        self.at(end + 5.0, self.radio, gw, nid, p2, "Join Accept in RX1 (+5 s join delay): DevAddr 0x%08X" % d["addr"], "resp", d["sf"], f)
        self.at(end + 5.5, self._joined, nid)

    def _joined(self, nid):
        self.dev[nid]["joined"] = True
        self.by[nid].sub = "joined, SF%d" % self.dev[nid]["sf"]

    def uplink(self, nid, payload=None, confirmed=None):
        d = self.dev[nid]
        if not d["joined"] or self.t < d["busy_until"]:
            return
        if self.fault["reset"] and nid == "park" and not d.get("was_reset"):
            d["fcnt"] = 0
            d["was_reset"] = True
        d["fcnt"] += 1
        confirmed = (nid == "wm") if confirmed is None else confirmed
        val = {"soil": b"\x01\x2C\x09\x1A", "park": b"\x01" if int(self.t / 12) % 2 else b"\x00", "wm": struct.pack(">I", 482_311 + int(self.t))}[nid]
        if payload is not None:
            val = payload
        fopts = b"\x03\x07" if d["adr_ans"] else b""
        rows = [("DevAddr", struct.pack("<I", d["addr"]), "0x%08X" % d["addr"], ""),
                ("FCtrl", bytes([0x80 | len(fopts)]), "ADR 1, ACK 0, FOptsLen %d" % len(fopts), ""),
                ("FCnt", struct.pack("<H", d["fcnt"] & 0xFFFF), str(d["fcnt"]), "Frame counter: must always increase.")]
        if fopts:
            rows.append(("FOpts", fopts, "LinkADRAns: power ACK, data rate ACK, channel mask ACK", "MAC command answer piggy-backed on the uplink."))
            d["adr_ans"] = False
        rows += [("FPort", b"\x02", "2", "Application port."), ("FRMPayload", bytes(len(val)), "%d bytes encrypted (AppSKey)" % len(val), "")]
        p = lw_frame(4 if confirmed else 2, rows, "data up")
        p.rows.append([0, "Decrypted FRMPayload: %s" % val.hex(" "), None, 0, ""])
        d["ch"] = (d["ch"] + 1) % 3
        f = (868.1, 868.3, 868.5)[d["ch"]]
        toa = lora_toa(len(p.b), d["sf"])
        d["busy_until"] = self.t + toa * 99
        hs = self.heard(nid)
        fr = self.radio(nid, None, p, "%s uplink %s FCnt %d SF%d %.0f ms (%s)" % ("Confirmed" if confirmed else "Unconfirmed", self.by[nid].label.lower(), d["fcnt"], d["sf"], toa * 1000,
                                                                                ", ".join("%s %.0f dBm" % (g, r) for g, r in hs) or "nobody heard it"), "data", d["sf"], f,
                        None if hs else "Below the sensitivity of every gateway at SF%d" % d["sf"])
        self.by[nid].vars.update({"SF": d["sf"], "FCnt": d["fcnt"], "Last RSSI": ("%.0f dBm" % max(r for _, r in hs)) if hs else "lost"})
        fwd = [(g, r) for g, r in hs if not (g == "gw1" and self.fault["gw"])]
        for g, _ in fwd:
            self.by[g].vars["Forwarded"] += 1
        if not fwd:
            d["miss"] += 1
            if d["miss"] >= 2 and d["sf"] < 12:
                d["sf"] = min(12, d["sf"] + 2)
                self.log("%s: no downlink / ADRACKReq timeout - device backs off to SF%d" % (self.by[nid].label, d["sf"]))
            return
        d["miss"] = 0
        self.ns["Uplinks"] += 1
        self.ns["Duplicates removed"] += len(fwd) - 1
        if d["fcnt"] <= d["last_ns"]:
            self.ns["Dropped (replay)"] += 1
            self.log("Network server: FCnt %d <= last %d for 0x%08X - dropped as a replay" % (d["fcnt"], d["last_ns"], d["addr"]))
            return
        d["last_ns"] = d["fcnt"]
        best = max(r for _, r in fwd)
        margin = best - SENS_SF[d["sf"]]
        adr = None
        if margin > 12 and d["sf"] > 7:
            adr = max(7, d["sf"] - int((margin - 10) // 2.5))
        if confirmed or adr:
            g = max(fwd, key=lambda x: x[1])[0]
            drows = [("DevAddr", struct.pack("<I", d["addr"]), "0x%08X" % d["addr"], ""),
                     ("FCtrl", bytes([(0x20 if confirmed else 0) | (4 if adr else 0)]), "ACK %d, FOptsLen %d" % (1 if confirmed else 0, 4 if adr else 0), ""),
                     ("FCnt (down)", struct.pack("<H", d["fcnt"] // 2), str(d["fcnt"] // 2), "")]
            if adr:
                drows.append(("FOpts", bytes([0x03, ((12 - adr) << 4) | 0x1, 0x07, 0x00, 0x01][:4]), "LinkADRReq: DR%d (SF%d), TX power index 1" % (12 - adr, adr), "ADR: the server lowers the spreading factor."))
            p2 = lw_frame(3, drows, "data down")
            self.at(fr.t + fr.dur + 1.0, self.radio, g, nid, p2, "Downlink in RX1 (+1 s)%s%s" % (": ACK" if confirmed else "", ", LinkADRReq -> SF%d" % adr if adr else ""), "resp", d["sf"], f)
            if adr:
                self.at(fr.t + fr.dur + 1.5, self._adr, nid, adr)

    def _adr(self, nid, sf):
        d = self.dev[nid]
        d["sf"] = sf
        d["adr_ans"] = True
        self.by[nid].sub = "SF%d (ADR)" % sf

    def duty_try(self):
        if not self.fault["duty"]:
            return
        d = self.dev["soil"]
        if self.t < d["busy_until"]:
            self.log("Soil sensor: transmission deferred - duty cycle (1 %%) allows the next uplink in %.0f s" % (d["busy_until"] - self.t))
            return
        d["sf"] = 12
        self.uplink("soil")

    def on_fault(self, key, on):
        if key == "basement":
            for g in ("gw1", "gw2"):
                self.radio_model.extra[("wm", g)] = 20.0 if on else 0.0
        if key == "gw":
            self.by["gw1"].vars["Backhaul"] = "DOWN" if on else "4G ok"
        if key == "duty" and not on:
            self.dev["soil"]["sf"] = 7
        if key == "reset" and not on:
            self.dev["park"]["was_reset"] = False

    def inspect(self, n):
        rows = list(n.vars.items())
        if n.id in ("gw1", "gw2"):
            rows += [("NS " + k, v) for k, v in self.ns.items()]
        return rows

    def tpls(self):
        return [Tpl("Uplink now", [P("n", "Device", "wm", opts=["soil", "wm", "park"], fmt=lambda v: self.by[v].label), P("c", "Type", "confirmed", opts=["confirmed", "unconfirmed"])],
                    lambda s, v, send: self._up(v, send), "Ignores the schedule (but not the duty cycle).")]

    def _up(self, v, send):
        if not send:
            return Frame(self.t, 0.1, v["n"], None, "LoRaWAN", "preview", pdu=lw_frame(4, [("DevAddr", struct.pack("<I", self.dev[v["n"]]["addr"]), "", "")], "data up"))
        self.dev[v["n"]]["busy_until"] = 0.0
        self.uplink(v["n"], None, v["c"] == "confirmed")
        return None


# ================================================================== Z-Wave
ZW_CC = {0x20: "BASIC", 0x25: "SWITCH_BINARY", 0x26: "SWITCH_MULTILEVEL", 0x30: "SENSOR_BINARY", 0x71: "NOTIFICATION", 0x84: "WAKE_UP", 0x9F: "SECURITY_2"}


def zw_frame(home, src, dst, seq, payload_rows, routed=None, ack_req=True, ack=False):
    pl_ = b"".join(r[1] for r in payload_rows)
    route = b""
    if routed:
        route = bytes([0x00, (len(routed) << 4)]) + bytes(routed)
    body = struct.pack(">I", home) + bytes([src])
    hdr = 0x03 if ack else 0x01
    fc = bytes([(0x80 if routed else 0) | (0x40 if ack_req else 0) | hdr, seq & 15])
    ln = 4 + 1 + 2 + 1 + 1 + len(route) + len(pl_) + 1
    allb = body + fc + bytes([ln, dst]) + route + pl_
    cs = 0xFF
    for x in allb:
        cs ^= x
    b = Bld("Z-Wave MAC frame (ITU-T G.9959, R2 40 kbit/s)", "Home ID, source, frame control, length, destination, [routing header], payload, checksum.")
    b.u32("Home ID", home, "0x%08X" % home, "Identifies the network; set by the primary controller.")
    b.u8("Source node", src, str(src), "")
    b.u16("Frame control", (fc[0] << 8) | fc[1], "%s%s%s, sequence %d" % ("routed, " if routed else "", "ACK requested, " if ack_req else "", "header: ACK" if ack else "header: singlecast",
                                                                         seq & 15), "")
    b.u8("Length", ln, None, "Whole frame including the checksum.")
    b.u8("Destination node", dst, "%d%s" % (dst, " (broadcast)" if dst == 0xFF else ""), "")
    if routed:
        b.raw("Routing header", route, "repeaters %s" % ", ".join(str(r) for r in routed), "Source routing: the controller lists the repeaters.")
    for lab, data, txt, desc in payload_rows:
        b.raw(lab, data, txt, desc)
    b.u8("Checksum", cs, "0x%02X [correct]" % cs, "XOR of all bytes, initial value 0xFF (CRC-16 at 100 kbit/s).")
    return b.done()


class ZWave(RfNet):
    key, name, cat = "zwave", "Z-Wave", "net"
    blurb = "Smart home devices"
    f_mhz, ptx, sens, n_exp = 868.42, 0.0, -100.0, 3.0
    map_size = 40.0
    band = {"f0": 868.0, "f1": 869.0, "unit": "MHz", "chans": [("868.42 R2", 868.42, 0.2), ("868.40 R3", 868.40, 0.3)]}
    medium = "Z-Wave (EU 868.42 MHz) mesh: a controller, a wall switch, an S2-secured door lock, a battery motion sensor and a dimmer reached through a repeater"
    faults = [("dead", "Wall switch (the repeater) is unplugged", "The routed frames to the dimmer fail; the controller runs route discovery (explorer frames) and finds the lock as a new repeater."),
              ("s2", "Door lock lost its S2 keys", "Encrypted commands cannot be decrypted: the lock answers with an S2 nonce report and stays locked."),
              ("jam", "Interference near 868 MHz", "Frames lost; every hop retries up to 3 times.")]
    spec = [("Standard", "ITU-T G.9959 (PHY / MAC), Z-Wave Alliance specifications; Z-Wave Long Range in the US"),
            ("Radio", "Sub-GHz (EU 868.4, US 908.4 MHz), FSK / GFSK: R1 9.6 kbit/s, R2 40 kbit/s, R3 100 kbit/s"),
            ("Network", "Home ID (32-bit) + node IDs 1-232; source-routed mesh with up to 4 repeaters; routing done by the controller"),
            ("Application", "Command classes: BASIC, SWITCH_BINARY, SWITCH_MULTILEVEL, NOTIFICATION, WAKE_UP, DOOR_LOCK ..."),
            ("Security", "S2 (ECDH key exchange at inclusion, AES-CCM): SECURITY_2 message encapsulation with nonces"),
            ("Battery", "Sleeping devices wake up periodically (WAKE_UP notification) or on events; FLiRS devices listen briefly every second")]
    frame = [["Z-Wave frame", ("Preamble", "10 B"), ("SOF", 8), ("Home ID", 32), ("Src", 8), ("Frame ctl", 16), ("Len", 8), ("Dst", 8), ("[Route]", "n x 8"),
              ("Command class", 8), ("Command", 8), ("Params", "n x 8"), ("Checksum", 8)]]
    about = ("Z-Wave is a sub-GHz smart-home mesh: lower frequency than Wi-Fi or Zigbee, so it passes walls better and avoids the crowded 2.4 GHz "
             "band. The controller keeps the network map and puts the list of repeaters into each routed frame. Devices speak in command classes - "
             "SWITCH_BINARY SET, NOTIFICATION REPORT - and security-sensitive devices like locks wrap them in S2 encryption.")
    guide = ["Turn on the wall switch (COMPOSE): SWITCH_BINARY SET, the ACK, then the REPORT.",
             "Dim the far dimmer: a routed frame with the switch as repeater, routed ACK back.",
             "Select an S2-encapsulated lock command: sequence number, encrypted command, MAC.",
             "Unplug the repeater and watch route discovery find another path."]

    HOME = 0xE4A1C3F2

    def setup(self):
        nodes = [("ctl", "CONTROLLER (NODE 1)", "gateway", 10, 8, 1), ("sw", "WALL SWITCH (NODE 2)", "button", 22, 2, 2), ("lock", "DOOR LOCK S2 (NODE 3)", "lock", 20, 14, 3),
                 ("pir", "MOTION SENSOR (NODE 4)", "sensor", 2, 14, 4), ("dim", "DIMMER (NODE 5)", "lamp", 33, 7, 5)]
        for nid, lab, kind, x, y, node_id in nodes:
            n = self.rnode(nid, lab, kind, x, y, "node %d" % node_id, "", w=130)
            n.extra["zid"] = node_id
        self.radio_model.extra[("dim", "ctl")] = 25.0
        self.pairs = [("sw", "ctl"), ("lock", "ctl"), ("pir", "ctl"), ("dim", "sw"), ("dim", "lock")]
        self.user = "ctl"
        self.seq = 0
        self.route = ["sw"]
        self.state = {"sw": False, "dim": 0, "lock": True}
        self.s2seq = 0x40
        self.by["sw"].vars["Relay"] = "OFF"
        self.by["dim"].vars["Level"] = "0 %"
        self.by["lock"].vars["Bolt"] = "LOCKED"
        self.by["pir"].vars["Motion"] = "-"
        self.by["ctl"].vars["Route to dimmer"] = "via node 2"
        self.every(8.0, lambda: self.switch(not self.state["sw"]), 1.0)
        self.every(10.0, lambda: self.dim(0 if self.state["dim"] else 60), 3.0)
        self.every(9.0, self.motion, 5.0)
        self.every(14.0, lambda: self.lock(not self.state["lock"]), 7.0)

    def zid(self, k):
        return self.by[k].extra["zid"]

    def radio(self, src, dst, p, info, kind, err=None):
        bits = []
        for byte in p.b[:10]:
            bits += msb(byte, 8)
        fr = rf_frame(self, src, dst, "Z-Wave", info, p, (len(p.b) + 11) * 8 / 40e3, 868.42, 0.2, kind, key=info.split(":")[0], err=err,
                      rssi=int(self.radio_model.rssi(src, dst or "ctl")), wirefn=lambda f, b=bits: fsk_wire(b, 40e3, 20.0, lead=8, gauss=0.5))
        return self.tx(fr, bus="air", ifs=0.003)

    def lost(self, a, b):
        if self.fault["jam"] and self.rng.random() < 0.3:
            return "Lost: interference"
        if not self.by[a].on or not self.by[b].on or not self.radio_model.ok(a, b):
            return "No ACK (out of range / node unreachable)"
        return None

    def hop_send(self, src, dst, rows, info, kind="cmd", routed=None, tries=0, on_ok=None):
        self.seq += 1
        p = zw_frame(self.HOME, self.zid(src), self.zid(dst), self.seq, rows, [self.zid(r) for r in routed] if routed else None)
        path = [src] + (routed or []) + [dst]
        err = None
        for a, b in zip(path, path[1:]):
            err = self.lost(a, b)
            if err:
                break
        self.radio(src, routed[0] if routed else dst, p, info + (" (retry %d)" % tries if tries else ""), kind, err)
        if routed and not err:
            self.at(self.t + 0.01, self.radio, routed[0], dst, p, "Repeated by node %d: %s" % (self.zid(routed[0]), info), kind)
        if err:
            if tries < 2:
                self.at(self.t + 0.05, self.hop_send, src, dst, rows, info, kind, routed, tries + 1, on_ok)
            elif routed and dst == "dim":
                self.discover()
            return
        ack = zw_frame(self.HOME, self.zid(dst), self.zid(src), self.seq, [], [self.zid(r) for r in routed][::-1] if routed else None, False, True)
        self.at(self.t + 0.02 + (0.01 if routed else 0), self.radio, dst, src, ack, "%sACK from node %d" % ("Routed " if routed else "", self.zid(dst)), "ack")
        if on_ok:
            self.at(self.t + 0.05, on_ok)

    def switch(self, on, send=True):
        rows = [("Command class", b"\x25", "0x25 SWITCH_BINARY", ""), ("Command", b"\x01", "0x01 SET", ""), ("Value", bytes([0xFF if on else 0]), "0x%02X (%s)" % (0xFF if on else 0, "on" if on else "off"), "")]
        if not send:
            return Frame(self.t, 0.004, "ctl", "sw", "Z-Wave", "preview", pdu=zw_frame(self.HOME, 1, 2, self.seq + 1, rows))

        def rep():
            self.state["sw"] = on
            self.by["sw"].vars["Relay"] = "ON" if on else "OFF"
            self.hop_send("sw", "ctl", [("Command class", b"\x25", "0x25 SWITCH_BINARY", ""), ("Command", b"\x03", "0x03 REPORT", ""), ("Value", bytes([0xFF if on else 0]), "on" if on else "off", "")],
                          "SWITCH_BINARY REPORT: %s" % ("on" if on else "off"), "resp")
        self.hop_send("ctl", "sw", rows, "SWITCH_BINARY SET -> node 2: %s" % ("on" if on else "off"), "cmd", on_ok=rep)
        return None

    def dim(self, level, send=True):
        rows = [("Command class", b"\x26", "0x26 SWITCH_MULTILEVEL", ""), ("Command", b"\x01", "0x01 SET", ""), ("Value", bytes([level]), "%d %%" % level, ""), ("Duration", b"\x02", "2 s fade", "")]
        if not send:
            return Frame(self.t, 0.004, "ctl", "dim", "Z-Wave", "preview", pdu=zw_frame(self.HOME, 1, 5, self.seq + 1, rows, [self.zid(r) for r in self.route]))

        def done():
            self.state["dim"] = level
            self.by["dim"].vars["Level"] = "%d %%" % level
        self.hop_send("ctl", "dim", rows, "SWITCH_MULTILEVEL SET -> node 5 = %d %% (routed via node %s)" % (level, ",".join(str(self.zid(r)) for r in self.route)), "cmd", self.route, on_ok=done)
        return None

    def discover(self):
        self.log("Controller: route to node 5 failed - sending explorer frames (route discovery)")
        p = zw_frame(self.HOME, 1, 5, self.seq, [("Explorer header", b"\x00\x04", "search, max 4 hops", "Explorer frames are flooded and record the path.")])
        self.radio("ctl", None, p, "Explorer frame: searching a route to node 5", "ctl")
        if self.by["lock"].on:
            self.route = ["lock"]
            self.by["ctl"].vars["Route to dimmer"] = "via node 3 (lock) - rediscovered"
            self.at(self.t + 0.08, self.radio, "dim", "ctl", zw_frame(self.HOME, 5, 1, self.seq, [("Explorer result", b"\x03", "path 1 -> 3 -> 5", "")], [3]),
                    "Explorer response: path via node 3", "resp")

    def motion(self):
        rows = [("Command class", b"\x71", "0x71 NOTIFICATION", ""), ("Command", b"\x05", "0x05 REPORT", ""), ("Type / event", b"\x07\x08", "home security / motion detected", "")]
        self.hop_send("pir", "ctl", rows, "NOTIFICATION REPORT from node 4: motion detected", "data")
        self.by["pir"].vars["Motion"] = "detected at %.0f s" % self.t
        self.at(self.t + 0.3, self.hop_send, "pir", "ctl", [("Command class", b"\x84", "0x84 WAKE_UP", ""), ("Command", b"\x07", "0x07 NOTIFICATION", "I am awake: send queued commands now.")],
                "WAKE_UP NOTIFICATION from node 4 (battery device listens briefly)", "ctl")

    def lock(self, locked, send=True):
        self.s2seq = (self.s2seq + 1) & 255
        rows = [("Command class", b"\x9f", "0x9F SECURITY_2", ""), ("Command", b"\x03", "0x03 MESSAGE ENCAPSULATION", ""), ("Sequence number", bytes([self.s2seq]), str(self.s2seq), ""),
                ("Extensions", b"\x00", "none", ""), ("Encrypted command", bytes(3), "DOOR_LOCK OPERATION_SET (%s) - encrypted" % ("secured" if locked else "unsecured"), "AES-CCM with the S2 key."),
                ("MAC", bytes(8), "8-byte authentication tag", "")]
        if not send:
            return Frame(self.t, 0.004, "ctl", "lock", "Z-Wave", "preview", pdu=zw_frame(self.HOME, 1, 3, self.seq + 1, rows))

        def ok():
            if self.fault["s2"]:
                self.hop_send("lock", "ctl", [("Command class", b"\x9f", "0x9F SECURITY_2", ""), ("Command", b"\x02", "0x02 NONCE REPORT (SOS)", "Cannot decrypt: please resynchronise.")],
                              "S2 NONCE REPORT from the lock: decryption failed", "err")
                return
            self.state["lock"] = locked
            self.by["lock"].vars["Bolt"] = "LOCKED" if locked else "UNLOCKED"
        self.hop_send("ctl", "lock", rows, "S2 encapsulated DOOR_LOCK SET -> node 3: %s" % ("lock" if locked else "unlock"), "cmd", on_ok=ok)
        return None

    def on_fault(self, key, on):
        if key == "dead":
            self.by["sw"].on = not on
            if not on:
                self.route = ["sw"]
                self.by["ctl"].vars["Route to dimmer"] = "via node 2"

    def tpls(self):
        return [Tpl("Wall switch on / off", [P("v", "State", "on", opts=["on", "off"])], lambda s, v, send: self.switch(v["v"] == "on", send), "SWITCH_BINARY SET with ACK and REPORT."),
                Tpl("Dimmer level", [P("l", "Level %", 60, 0, 99)], lambda s, v, send: self.dim(v["l"], send), "Routed through the repeater listed in the routing header."),
                Tpl("Lock / unlock (S2)", [P("v", "Command", "unlock", opts=["lock", "unlock"])], lambda s, v, send: self.lock(v["v"] == "lock", send), "Encrypted with SECURITY_2.")]
