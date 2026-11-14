"""Building automation and lighting: BACnet/IP, BACnet MS/TP, KNX, LonWorks
(LonTalk), DALI and DMX512."""
import math
import struct
import pygame
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, mstp_hcrc, lsb, msb
from .fam import serial_frame, IpNet

# ================================================================= BACnet
OBJ_T = {0: "analog-input", 1: "analog-output", 2: "analog-value", 3: "binary-input", 4: "binary-output", 5: "binary-value", 8: "device", 19: "multi-state-value"}
PROP = {75: "object-identifier", 77: "object-name", 79: "object-type", 85: "present-value", 87: "priority-array", 104: "relinquish-default",
        111: "status-flags", 117: "units", 81: "out-of-service", 28: "description", 121: "vendor-name", 70: "model-name", 112: "system-status"}
SVC_C = {5: "subscribeCOV", 12: "readProperty", 14: "readPropertyMultiple", 15: "writeProperty"}
SVC_U = {0: "i-Am", 1: "i-Have", 2: "unconfirmedCOVNotification", 6: "timeSynchronization", 7: "who-Has", 8: "who-Is"}
UNITS_B = {62: "degrees-Celsius", 98: "percent", 95: "no-units", 53: "pascals"}


def bn_uint(v):
    v = int(v)
    n = 1
    while v >= 1 << (8 * n):
        n += 1
    return v.to_bytes(n, "big")


def bn_tag(tag, ctx, data):
    n = len(data)
    first = (tag << 4) | (0x08 if ctx else 0)
    if n < 5:
        return bytes([first | n]) + data
    return bytes([first | 5, n]) + data


def a_uint(v):
    return bn_tag(2, False, bn_uint(v))


def a_enum(v):
    return bn_tag(9, False, bn_uint(v))


def a_real(v):
    return b"\x44" + struct.pack(">f", v)


def a_oid(t, i):
    return b"\xC4" + struct.pack(">I", (t << 22) | i)


def a_str(s):
    return bn_tag(7, False, b"\x00" + s.encode())


def c_oid(tag, t, i):
    return bytes([(tag << 4) | 0x0C]) + struct.pack(">I", (t << 22) | i)


def c_uint(tag, v):
    return bn_tag(tag, True, bn_uint(v))


def c_open(tag):
    return bytes([(tag << 4) | 0x0E])


def c_close(tag):
    return bytes([(tag << 4) | 0x0F])


def oid_txt(t, i):
    return "%s,%d" % (OBJ_T.get(t, "type %d" % t), i)


def val_enc(v):
    """Python value -> (encoded application-tagged bytes, text)."""
    if v is None:
        return b"\x00", "NULL (relinquish)"
    if isinstance(v, bool):
        return a_enum(1 if v else 0), "active" if v else "inactive"
    if isinstance(v, float):
        return a_real(v), "%.2f (REAL)" % v
    if isinstance(v, str):
        return a_str(v), '"%s"' % v
    return a_uint(v), str(v)


class Apdu:
    def __init__(self, kind, service, invoke=0):
        names = SVC_U if kind == "unconfirmed" else SVC_C
        self.b = Bld("BACnet APDU: %s %s" % ({"confirmed": "Confirmed-Request", "unconfirmed": "Unconfirmed-Request", "simple": "SimpleACK",
                                               "complex": "ComplexACK", "error": "Error"}[kind], names.get(service, "")),
                     "Application layer: PDU type, invoke ID (confirmed services), service choice, tagged parameters.")
        b = self.b
        if kind == "confirmed":
            b.u8("PDU type", 0x00, "0 Confirmed-Request, not segmented, segmented reply not accepted", "")
            b.u8("Max segments / max APDU", 0x05, "unspecified / 1476 octets", "Largest reply the requester accepts.")
            b.u8("Invoke ID", invoke, None, "Matches the ACK / Error to this request.")
        elif kind == "unconfirmed":
            b.u8("PDU type", 0x10, "1 Unconfirmed-Request", "")
        else:
            b.u8("PDU type", {"simple": 0x20, "complex": 0x30, "error": 0x50}[kind], {"simple": "2 SimpleACK", "complex": "3 ComplexACK", "error": "5 Error"}[kind], "")
            b.u8("Invoke ID", invoke, None, "")
        b.u8("Service choice", service, "%d %s" % (service, names.get(service, "?")), "")

    def add(self, label, data, txt, desc=""):
        self.b.raw(label, data, txt, desc, d=2)
        return self

    def done(self):
        return self.b.done()


def npdu(expect=False, dnet=None, dadr=b"", snet=None, sadr=b""):
    b = Bld("BACnet NPDU", "Network layer: version, control flags and, when routed, network numbers and MAC addresses.")
    ctrl = (0x20 if dnet is not None else 0) | (0x08 if snet is not None else 0) | (0x04 if expect else 0)
    b.u8("Version", 1, "0x01", "")
    b.u8("Control", ctrl, "0x%02X: %s%s%sexpecting reply %d, normal priority" % (ctrl, "DNET present, " if dnet is not None else "", "SNET present, " if snet is not None else "",
                                                                                 "", expect), "")
    if dnet is not None:
        b.u16("DNET", dnet, "network %d" % dnet, "Destination network (behind a router).")
        b.u8("DLEN", len(dadr), None, "")
        if dadr:
            b.raw("DADR", dadr, "MAC %s" % dadr.hex(), "Destination MAC on that network (MS/TP: 1 byte).")
    if snet is not None:
        b.u16("SNET", snet, "network %d" % snet, "Source network: added by the router so replies can find their way back.")
        b.u8("SLEN", len(sadr), None, "")
        b.raw("SADR", sadr, "MAC %s" % sadr.hex(), "")
    if dnet is not None:
        b.u8("Hop count", 255, None, "Decremented by each router.")
    return b


def bvlc(func, inner):
    b = Bld("BACnet/IP BVLC", "Annex J virtual link control on UDP 47808 (0xBAC0).")
    b.u8("Type", 0x81, "0x81 BACnet/IP", "")
    b.u8("Function", func, {0x0A: "0x0A Original-Unicast-NPDU", 0x0B: "0x0B Original-Broadcast-NPDU", 0x04: "0x04 Forwarded-NPDU"}.get(func, "0x%02X" % func), "")
    b.u16("Length", 4 + len(inner.b), None, "Whole BVLL message.")
    b.sub(inner)
    return b.done()


def stack(np_bld, apdu):
    np_bld.sub(apdu)
    return np_bld.done()


class BObj:
    def __init__(self, t, i, name, pv, units=95, cmd=False):
        self.t, self.i, self.name, self.pv, self.units = t, i, name, pv, units
        self.pa = [None] * 16 if cmd else None
        self.rd = (False if t in (3, 4, 5) else 0.0) if cmd else None

    def eff(self):
        if self.pa is None:
            return self.pv
        for v in self.pa:
            if v is not None:
                return v
        return self.rd


class BDev:
    def __init__(self, inst, name, objs):
        self.inst, self.name = inst, name
        self.o = {(o.t, o.i): o for o in objs}
        self.o[(8, inst)] = BObj(8, inst, name, None)

    def read(self, t, i, prop):
        o = self.o.get((t, i))
        if o is None:
            return None, (1, 31)
        if prop == 85:
            return val_enc(o.eff())
        if prop == 77:
            return val_enc(o.name)
        if prop == 117:
            return a_enum(o.units), "%d %s" % (o.units, UNITS_B.get(o.units, ""))
        if prop == 111:
            return b"\x82\x04\x00", "{in-alarm F, fault F, overridden F, out-of-service F}"
        if prop == 87 and o.pa is not None:
            enc = b"".join(val_enc(v)[0] for v in o.pa)
            return enc, "[" + ", ".join("%d:%s" % (k + 1, "NULL" if v is None else (("active" if v else "inactive") if isinstance(v, bool) else "%.1f" % v))
                                        for k, v in enumerate(o.pa) if v is not None or k in (7, 15)) + "]"
        if prop == 75:
            return a_oid(t, i), oid_txt(t, i)
        return None, (2, 32)


class BACnetIP(IpNet):
    key, name, cat = "bacnet", "BACnet", "building"
    blurb = "Building automation (HVAC, lighting, access)"
    medium = "BACnet/IP (ASHRAE 135 Annex J, UDP 47808): an operator workstation, AHU and boiler-plant controllers, and a router to an MS/TP field bus"
    faults = [("prio", "Operator override left at priority 8", "The night schedule writes the supply fan OFF at priority 16 - but the forgotten manual ON at priority 8 wins."),
              ("dup", "Two controllers configured as device 2101", "Both answer Who-Is with the same instance: the workstation cannot tell which one it is talking to."),
              ("bbmd", "Workstation on another subnet, no BBMD", "Broadcasts (Who-Is, I-Am) do not cross the IP router: devices are not discovered."),
              ("offline", "Boiler plant controller offline", "Confirmed requests time out (APDU timeout 3 s, 3 retries)."),
              ("unknown", "Workstation graphic points at analog-input 99", "The controller answers with Error: object / unknown-object.")]
    spec = [("Standard", "ANSI/ASHRAE 135 (ISO 16484-5); BACnet/IP Annex J, BACnet/SC (secure connect, WebSocket + TLS), MS/TP clause 9"),
            ("Model", "Devices contain objects (analog-input, binary-output, schedule, trend-log ...) with properties (present-value, status-flags, units ...)"),
            ("Services", "Who-Is / I-Am, ReadProperty(Multiple), WriteProperty with priority, SubscribeCOV / COV notifications, alarms and events"),
            ("Command priority", "Commandable objects keep a 16-level priority array: 1 manual life safety, 8 manual operator, 16 lowest (schedules); relinquish = write NULL"),
            ("Network", "Network numbers + MAC addresses; routers join BACnet/IP, MS/TP, Ethernet; BBMDs forward broadcasts between IP subnets")]
    frame = [["BACnet/IP", ("BVLC 0x81", 8), ("Function", 8), ("Length", 16), ("NPDU ver 0x01", 8), ("Control", 8), ("[DNET...]", "n x 8"),
              ("APDU type", 8), ("Max seg / APDU", 8), ("Invoke ID", 8), ("Service", 8), ("Tagged params", "n x 8")]]
    about = ("BACnet is the open protocol of building automation. Every controller is a device full of standard objects - temperature "
             "inputs, fan commands, setpoints, schedules - and any workstation can find devices with Who-Is, read properties and write "
             "commands. Commands carry a priority from 1 to 16, so a fire system, an operator and a time schedule can all command the same "
             "fan without fighting: the highest-priority non-NULL value wins.")
    guide = ["Watch Who-Is and the I-Am replies (device instance, max APDU, segmentation, vendor).",
             "Select a ReadProperty and its ComplexACK: context tags, opening / closing tag 3, the REAL value.",
             "COMPOSE a WriteProperty to binary-output 1 at priority 8, then read its priority-array.",
             "Inject the stuck override: the schedule's write at priority 16 changes nothing until you relinquish priority 8.",
             "Follow a read to the VAV behind the router: DNET / DADR in the request, SNET / SADR in the reply."]

    def setup(self):
        hosts = [("ws", "OPERATOR WORKSTATION", "pc", 40, 40, "192.168.50.10", "00:0c:29:50:00:10", "device 100"),
                 ("ahu", "AHU-1 CONTROLLER", "plc", 700, 40, "192.168.50.21", "00:20:4a:50:00:21", "device 2101"),
                 ("plant", "BOILER PLANT CTRL", "plc", 700, 290, "192.168.50.22", "00:20:4a:50:00:22", "device 2102"),
                 ("rtr", "BACNET ROUTER IP/MSTP", "router", 40, 290, "192.168.50.30", "00:20:4a:50:00:30", "net 1 <-> net 2")]
        self.star(hosts)
        v5 = self.node("v5", "VAV-5", "box", 205, 300, "MS/TP 5", "device 20005", w=104, h=40)
        v12 = self.node("v12", "VAV-12", "box", 330, 300, "MS/TP 12", "device 20012", w=104, h=40)
        self.seg([(158, 320), (205, 320)], "rs485", label="MS/TP net 2", c0="screw", c1="screw")
        self.seg([(309, 320), (330, 320)], "rs485", c0="screw", c1="screw")
        for n in (v5, v12):
            n.extra["can"] = False
        self.user = "ws"
        self.dev = {"ahu": BDev(2101, "AHU-1", [BObj(0, 1, "SAT", 13.2, 62), BObj(0, 2, "RAT", 21.6, 62), BObj(2, 1, "SAT-SP", 13.0, 62, cmd=True),
                                                 BObj(4, 1, "SF-CMD", True, 95, cmd=True), BObj(3, 1, "SF-STS", True), BObj(1, 1, "CHW-VLV", 42.0, 98, cmd=True)]),
                    "plant": BDev(2102, "PLANT", [BObj(0, 1, "HW-SUPPLY", 71.5, 62), BObj(4, 1, "BOILER-1", True, 95, cmd=True)]),
                    "v5": BDev(20005, "VAV-5", [BObj(0, 1, "ZN-T", 22.4, 62), BObj(2, 1, "ZN-SP", 22.0, 62, cmd=True)]),
                    "v12": BDev(20012, "VAV-12", [BObj(0, 1, "ZN-T", 23.1, 62), BObj(2, 1, "ZN-SP", 22.0, 62, cmd=True)]),
                    "rtr": BDev(2000, "ROUTER", [])}
        self.dev["ahu"].o[(2, 1)].pa[15] = 13.0
        self.dev["ahu"].o[(4, 1)].pa[15] = True
        self.dev["ahu"].o[(1, 1)].pa[15] = 42.0
        self.dev["plant"].o[(4, 1)].pa[15] = True
        for v in ("v5", "v12"):
            self.dev[v].o[(2, 1)].pa[15] = 22.0
        self.inv = 0
        self.pend = {}
        self.cov = {}
        self.found = {}
        self.by["ws"].vars.update({"Devices found": 0, "AHU SAT": "-", "AHU fan": "-", "VAV-5 zone": "-", "Timeouts": 0})
        self.by["ahu"].vars.update({"Supply fan": "ON", "SAT": "13.2 degC"})
        self.at(0.1, self.who_is)
        self.at(1.0, self.subscribe)
        self.every(2.0, self.poll, 1.5)
        self.every(1.0, self.physics, 0.5)
        self.every(15.0, self.schedule, 8.0)

    def mac(self, nid):
        return {"v5": b"\x05", "v12": b"\x0c"}.get(nid, b"")

    def send(self, src, dst, apdu, info, kind, expect=False, bcast=False):
        """dst: host id or MS/TP device behind the router."""
        if bcast:
            if src == "ws" and self.fault["bbmd"]:
                inner = stack(npdu(expect), apdu)
                self.lan.udp(src, None, 47808, 47808, bvlc(0x0B, inner), info + " (stays on the workstation's subnet: no BBMD)", "BACnet", kind,
                             dip="192.168.60.255")
                return
            inner = stack(npdu(expect), apdu)
            self.lan.udp(src, None, 47808, 47808, bvlc(0x0B, inner), info, "BACnet", kind, dip="192.168.50.255")
            return
        if dst in ("v5", "v12"):
            inner = stack(npdu(expect, dnet=2, dadr=self.mac(dst)), apdu)
            self.lan.udp(src, "rtr", 47808, 47808, bvlc(0x0A, inner), info + " (via router to net 2, MAC %d)" % self.mac(dst)[0], "BACnet", kind)
            return
        if src in ("v5", "v12"):
            inner = stack(npdu(expect, snet=2, sadr=self.mac(src)), apdu)
            self.lan.udp("rtr", dst, 47808, 47808, bvlc(0x0A, inner), info + " (routed from net 2, MAC %d)" % self.mac(src)[0], "BACnet", kind)
            return
        inner = stack(npdu(expect), apdu)
        self.lan.udp(src, dst, 47808, 47808, bvlc(0x0A, inner), info, "BACnet", kind)

    def alive(self, nid):
        if nid in ("v5", "v12"):
            return self.by["rtr"].on
        return self.by[nid].on and not (nid == "plant" and self.fault["offline"])

    # ------------------------------------------------------- discovery
    def who_is(self, send=True):
        a = Apdu("unconfirmed", 8).done()
        if not send:
            return Frame(self.t, 0.0001, "ws", None, "BACnet", "preview", pdu=bvlc(0x0B, stack(npdu(), a)))
        self.send("ws", None, a, "who-Is (all devices)", "bcast", bcast=True)
        if self.fault["bbmd"]:
            return None
        for i, nid in enumerate(("ahu", "plant", "rtr", "v5", "v12")):
            if self.alive(nid):
                self.at(self.t + 0.004 + 0.003 * i, self.i_am, nid)
        if self.fault["dup"]:
            self.at(self.t + 0.02, self.i_am, "plant", 2101)
        return None

    def i_am(self, nid, inst=None):
        d = self.dev[nid]
        inst = inst or d.inst
        a = Apdu("unconfirmed", 0)
        a.add("iAmDeviceIdentifier", a_oid(8, inst), "device,%d" % inst, "Application tag 12, object identifier.")
        a.add("maxAPDULengthAccepted", a_uint(1476 if nid not in ("v5", "v12") else 480), "%d" % (1476 if nid not in ("v5", "v12") else 480), "")
        a.add("segmentationSupported", a_enum(3), "3 no-segmentation", "")
        a.add("vendorID", a_uint(999), "999 (example)", "")
        src = nid
        self.send(src, None if nid not in ("v5", "v12") else "ws", a.done(), "i-Am device,%d%s" % (inst, " (DUPLICATE instance!)" if inst != d.inst else ""), "resp",
                  bcast=nid not in ("v5", "v12"))
        if inst in self.found and self.found[inst] != nid:
            self.log("Workstation: device %d answered from two addresses (%s and %s)" % (inst, self.found[inst], nid))
        self.found[inst] = nid
        self.by["ws"].vars["Devices found"] = len(self.found)

    # ------------------------------------------------------- services
    def confirmed(self, dst, svc, params, info, on_ok=None, retry=0, send=True):
        self.inv = (self.inv + 1) & 0xFF
        a = Apdu("confirmed", svc, self.inv)
        for p in params:
            a.add(*p)
        pdu = a.done()
        if not send:
            np = npdu(True, dnet=2, dadr=self.mac(dst)) if dst in ("v5", "v12") else npdu(True)
            return Frame(self.t, 0.0001, "ws", dst if dst not in ("v5", "v12") else "rtr", "BACnet", "preview", pdu=bvlc(0x0A, stack(np, pdu)))
        inv = self.inv
        self.send("ws", dst, pdu, "%s %s [invoke %d]%s" % (SVC_C[svc], info, inv, " retry %d" % retry if retry else ""), "cmd", expect=True)
        tok = object()
        self.pend[inv] = tok
        if self.alive(dst):
            self.at(self.t + (0.03 if dst in ("v5", "v12") else 0.004), self.server, dst, svc, params, inv, on_ok)
        else:
            self.at(self.t + 3.0, self._retry, inv, tok, dst, svc, params, info, on_ok, retry)
        return None

    def _retry(self, inv, tok, dst, svc, params, info, on_ok, retry):
        if self.pend.get(inv) is not tok:
            return
        del self.pend[inv]
        if retry < 3:
            self.confirmed(dst, svc, params, info, on_ok, retry + 1)
        else:
            self.by["ws"].vars["Timeouts"] += 1
            self.log("Workstation: %s did not answer after 3 retries - marked offline" % self.by[dst].label)

    def server(self, dst, svc, params, inv, on_ok):
        d = self.dev[dst]
        self.pend.pop(inv, None)
        oid = struct.unpack(">I", next(x for x in params if "bjectIdentifier" in x[0])[1][1:5])[0]
        t, i = oid >> 22, oid & 0x3FFFFF
        if svc == 12:
            prop = params[1][1][1]
            enc, txt = d.read(t, i, prop)
            if enc is None:
                cls, code = txt
                e = Apdu("error", 12, inv)
                e.add("error-class", a_enum(cls), "%d %s" % (cls, {1: "object", 2: "property"}[cls]), "")
                e.add("error-code", a_enum(code), "%d %s" % (code, {31: "unknown-object", 32: "unknown-property"}[code]), "")
                self.send(dst, "ws", e.done(), "Error readProperty %s: %s" % (oid_txt(t, i), {31: "unknown-object", 32: "unknown-property"}[code]), "err")
                return
            a = Apdu("complex", 12, inv)
            a.add("objectIdentifier", c_oid(0, t, i), oid_txt(t, i), "Context tag 0.")
            a.add("propertyIdentifier", c_uint(1, prop), "%d %s" % (prop, PROP.get(prop, "")), "Context tag 1.")
            a.add("opening tag 3", c_open(3), "propertyValue {", "")
            a.add("value", enc, txt, "Application-tagged value.")
            a.add("closing tag 3", c_close(3), "}", "")
            self.send(dst, "ws", a.done(), "ComplexACK readProperty %s %s = %s" % (oid_txt(t, i), PROP.get(prop, prop), txt), "resp")
            if on_ok:
                self.at(self.t + 0.001, on_ok, d.o[(t, i)].eff() if (t, i) in d.o else None)
        elif svc == 15:
            prop = params[1][1][1]
            o = d.o.get((t, i))
            prio = params[-1][1][1]
            v = params[0][2]
            if o is None or o.pa is None:
                e = Apdu("error", 15, inv)
                e.add("error-class", a_enum(2), "2 property", "")
                e.add("error-code", a_enum(40), "40 write-access-denied", "")
                self.send(dst, "ws", e.done(), "Error writeProperty: write-access-denied", "err")
                return
            o.pa[prio - 1] = getattr(self, "_wv", None)
            self.send(dst, "ws", Apdu("simple", 15, inv).done(), "SimpleACK writeProperty %s priority %d" % (oid_txt(t, i), prio), "ack")
            self.apply(dst)
        elif svc == 5:
            self.cov[(dst, t, i)] = self.t
            self.send(dst, "ws", Apdu("simple", 5, inv).done(), "SimpleACK subscribeCOV %s" % oid_txt(t, i), "ack")

    def read(self, dst, t, i, prop, on_ok=None, send=True):
        return self.confirmed(dst, 12, [("objectIdentifier", c_oid(0, t, i), oid_txt(t, i), "Context tag 0: which object."),
                                        ("propertyIdentifier", c_uint(1, prop), "%d %s" % (prop, PROP.get(prop, "")), "Context tag 1: which property.")],
                              "%s %s" % (oid_txt(t, i), PROP.get(prop, prop)), on_ok, send=send)

    def write(self, dst, t, i, prop, v, prio, send=True):
        enc, txt = val_enc(v)
        self._wv = v
        return self.confirmed(dst, 15, [("objectIdentifier", c_oid(0, t, i), oid_txt(t, i), ""), ("propertyIdentifier", c_uint(1, prop), "%d %s" % (prop, PROP.get(prop, "")), ""),
                                        ("opening tag 3", c_open(3), "propertyValue {", ""), ("value", enc, txt, ""), ("closing tag 3", c_close(3), "}", ""),
                                        ("priority", c_uint(4, prio), "%d%s" % (prio, {8: " (manual operator)", 16: " (lowest, schedules)", 1: " (manual life safety)"}.get(prio, "")),
                                         "Context tag 4: slot in the priority array.")],
                              "%s present-value = %s @ priority %d" % (oid_txt(t, i), txt, prio), send=send)

    def subscribe(self):
        self.confirmed("ahu", 5, [("subscriberProcessIdentifier", c_uint(0, 17), "17", ""), ("monitoredObjectIdentifier", c_oid(1, 0, 1), oid_txt(0, 1), ""),
                                  ("issueConfirmedNotifications", bytes([0x29, 0x00]), "FALSE (unconfirmed)", ""), ("lifetime", c_uint(3, 600), "600 s", "")],
                       "analog-input,1 (SAT) COV, lifetime 600 s")

    def poll(self):
        self.read("ahu", 4, 1, 85, lambda v: self.by["ws"].vars.__setitem__("AHU fan", "ON" if v else "OFF"))
        self.at(self.t + 0.3, self.read, "v5", 0, 1, 85, lambda v: self.by["ws"].vars.__setitem__("VAV-5 zone", "%.1f degC" % v))
        if self.fault["unknown"]:
            self.at(self.t + 0.6, self.read, "ahu", 0, 99, 85)
        self.at(self.t + 0.9, self.read, "plant", 0, 1, 85)

    def schedule(self):
        night = int(self.t / 15) % 2 == 1
        self.log("AHU-1 internal schedule: fan %s at priority 16" % ("OFF (unoccupied)" if night else "ON (occupied)"))
        self.dev["ahu"].o[(4, 1)].pa[15] = not night
        self.apply("ahu")

    def apply(self, nid):
        if nid == "ahu":
            on = self.dev["ahu"].o[(4, 1)].eff()
            self.by["ahu"].vars["Supply fan"] = ("ON" if on else "OFF") + (" (priority 8 override)" if self.dev["ahu"].o[(4, 1)].pa[7] is not None else "")
            self.dev["ahu"].o[(3, 1)].pv = bool(on)

    def physics(self):
        o = self.dev["ahu"].o
        sat = o[(0, 1)]
        tgt = o[(2, 1)].eff() if o[(4, 1)].eff() else 21.0
        new = sat.pv + (tgt - sat.pv) * 0.15 + float(self.rng.normal(0, 0.03))
        self.by["ahu"].vars["SAT"] = "%.1f degC" % new
        if abs(new - getattr(self, "cov_last", sat.pv)) >= 0.5 and ("ahu", 0, 1) in self.cov:
            self.cov_last = new
            sat.pv = new
            self.cov_note(new)
        sat.pv = new
        for v in ("v5", "v12"):
            z = self.dev[v].o[(0, 1)]
            z.pv += (self.dev[v].o[(2, 1)].eff() - z.pv) * 0.05 + float(self.rng.normal(0, 0.02))

    def cov_note(self, v):
        a = Apdu("unconfirmed", 2)
        a.add("subscriberProcessIdentifier", c_uint(0, 17), "17", "")
        a.add("initiatingDeviceIdentifier", c_oid(1, 8, 2101), "device,2101", "")
        a.add("monitoredObjectIdentifier", c_oid(2, 0, 1), oid_txt(0, 1), "")
        a.add("timeRemaining", c_uint(3, 540), "540 s", "")
        a.add("listOfValues", c_open(4) + c_uint(0, 85) + c_open(2) + a_real(v) + c_close(2) + c_uint(0, 111) + c_open(2) + b"\x82\x04\x00" + c_close(2) + c_close(4),
              "present-value %.2f, status-flags {F,F,F,F}" % v, "Sent because the value moved by more than the COV increment (0.5).")
        self.send("ahu", "ws", a.done(), "unconfirmedCOVNotification analog-input,1 SAT = %.2f" % v, "data")
        self.by["ws"].vars["AHU SAT"] = "%.2f degC (COV)" % v

    def on_fault(self, key, on):
        if key == "prio":
            o = self.dev["ahu"].o[(4, 1)]
            o.pa[7] = True if on else o.pa[7]
            self.apply("ahu")
        if key in ("dup", "bbmd") and not on:
            self.found = {}
            self.at(self.t + 0.1, self.who_is)
        if key == "dup" and on:
            self.at(self.t + 0.1, self.who_is)

    def tpls(self):
        devs = ["ahu", "plant", "v5", "v12"]
        objs = [(0, 1), (0, 2), (2, 1), (4, 1), (3, 1), (1, 1), (0, 99), (8, 2101)]
        return [Tpl("Who-Is", [], lambda s, v, send: self.who_is(send), "Broadcast: every device answers with I-Am."),
                Tpl("ReadProperty", [P("d", "Device", "ahu", opts=devs, fmt=lambda v: "%s (device %d)" % (self.by[v].label, self.dev[v].inst)),
                                     P("o", "Object", (0, 1), opts=objs, fmt=lambda v: oid_txt(*v)), P("p", "Property", 85, opts=[85, 77, 117, 87, 111, 75],
                                                                                                         fmt=lambda v: "%d %s" % (v, PROP[v]))],
                    lambda s, v, send: self.read(v["d"], v["o"][0], v["o"][1], v["p"], send=send), "Read one property; try priority-array (87) on binary-output,1."),
                Tpl("WriteProperty (command)", [P("d", "Device", "ahu", opts=devs, fmt=lambda v: self.by[v].label), P("o", "Object", (4, 1), opts=[(4, 1), (2, 1), (1, 1)],
                                                                                                                      fmt=lambda v: oid_txt(*v)),
                                                P("v", "Value", "inactive", opts=["active", "inactive", "12.5", "14.0", "60.0"]), P("pr", "Priority", 8, 1, 16)],
                    lambda s, v, send: self.write(v["d"], v["o"][0], v["o"][1], 85, (v["v"] == "active") if v["v"] in ("active", "inactive") else float(v["v"]), v["pr"], send),
                    "Writes present-value at a priority slot."),
                Tpl("Relinquish (write NULL)", [P("d", "Device", "ahu", opts=devs, fmt=lambda v: self.by[v].label), P("o", "Object", (4, 1), opts=[(4, 1), (2, 1), (1, 1)],
                                                                                                                   fmt=lambda v: oid_txt(*v)), P("pr", "Priority", 8, 1, 16)],
                    lambda s, v, send: self.write(v["d"], v["o"][0], v["o"][1], 85, None, v["pr"], send), "Clears the slot so lower priorities take over.")]


# =========================================================== BACnet MS/TP
MSTP_T = {0: "Token", 1: "Poll For Master", 2: "Reply To Poll For Master", 3: "Test_Request", 4: "Test_Response", 5: "BACnet Data Expecting Reply",
          6: "BACnet Data Not Expecting Reply", 7: "Reply Postponed"}


def mstp_frame(ftype, dst, src, data=b""):
    hdr = bytes([ftype, dst, src]) + struct.pack(">H", len(data))
    hc = mstp_hcrc(hdr)
    b = Bld("BACnet MS/TP frame: %s" % MSTP_T[ftype], "Clause 9 master-slave / token-passing on RS-485.")
    b.raw("Preamble", b"\x55\xFF", "55 FF", "Marks the start of every frame.")
    b.u8("Frame type", ftype, "%d %s" % (ftype, MSTP_T[ftype]), "")
    b.u8("Destination MAC", dst, "255 (broadcast)" if dst == 255 else str(dst), "Masters 0-127, slaves 128-254.")
    b.u8("Source MAC", src, str(src), "")
    b.u16("Length", len(data), None, "Data octets (0 for token / poll frames).")
    b.u8("Header CRC", hc, "0x%02X [correct]" % hc, "8-bit CRC over type, addresses and length (x^8 + x^7 + 1).")
    if data:
        b.raw("Data", data, None, "NPDU + APDU.")
        dc = crcn("CRC-16/X-25", data)
        b.u16("Data CRC", dc, "0x%04X [correct]" % dc, "16-bit CRC-CCITT over the data, LSB first.", little=True)
    return b.done()


class BACnetMSTP(Scenario):
    key, name, cat = "bacnet_mstp", "BACnet MS/TP", "building"
    blurb = "Building controllers on RS-485"
    phy, rate = "rs485", 38400
    speed = 3
    medium = "BACnet MS/TP on RS-485 at 38400 bit/s: four masters pass the token (router MAC 0, VAV controllers 3, 5, 12) plus a slave sensor (MAC 130)"
    nets = [("A", "RS-485 A (-)"), ("B", "RS-485 B (+)"), ("VDIFF", "B - A")]
    lines = ["D", "DE"]
    faults = [("dupmac", "Two VAVs set to MAC address 5", "Both reply to the token at once: garbled frames; the token keeps getting lost."),
              ("maxm", "Masters configured with Max_Master = 10", "Nobody polls addresses above 10: MAC 12 never gets the token and stays invisible."),
              ("baud", "VAV-12 set to 19200 bit/s", "It cannot decode anything - and its own frames are noise to everyone else."),
              ("lost", "VAV-5 powers off while holding the token", "Silence for Tno_token (500 ms); the lowest master regenerates the token by polling."),
              ("no_term1", "End-of-line termination missing", "Reflections at 38400 bit/s cause occasional CRC errors.")]
    spec = [("Standard", "ANSI/ASHRAE 135 clause 9 (MS/TP), RS-485 2-wire with shield, 9600 / 19200 / 38400 / 76800 / 115200 bit/s, 8N1"),
            ("Frame", "Preamble 55 FF, type, destination, source, length (2), header CRC-8, data, data CRC-16"),
            ("Token", "Masters 0-127 pass the token to the next station (NS); the holder may send up to Nmax_info_frames, then passes it on"),
            ("Discovery", "Every Npoll (50) tokens a master sends Poll For Master to addresses between itself and NS, up to Max_Master"),
            ("Timers", "Tno_token 500 ms, Treply_timeout 255 ms, Tusage_timeout 20 ms, Tturnaround 40 bit times"),
            ("Wiring", "Daisy chain, 120 ohm termination at both ends, one set of bias resistors, max 32 unit loads per segment without repeaters")]
    frame = [["MS/TP frame", ("55 FF", 16), ("Type", 8), ("Dest", 8), ("Src", 8), ("Length", 16), ("Header CRC", 8), ("Data (NPDU+APDU)", "n x 8"), ("Data CRC", 16)]]
    about = ("MS/TP is BACnet's low-cost field bus: plain RS-485 twisted pair linking VAV boxes, unit ventilators and sensors to a router. "
             "There is no bus master - the masters pass a token around the ring, and only the token holder may start a transmission. "
             "From time to time a master polls the empty addresses after itself, so new devices can join the ring.")
    guide = ["Watch the token go 0 -> 3 -> 5 -> 12 -> 0, then a Poll For Master to the gap after 12.",
             "Select a BACnet Data Expecting Reply from the router (a ReadProperty for VAV-5) and the reply that follows.",
             "Lower Max_Master on the router: MAC 12 drops out of the ring.",
             "Power off VAV-5 while it holds the token and watch the ring rebuild."]

    def build(self):
        r = self.node("r", "BACNET ROUTER", "router", 30, 40, "MAC 0", "net 1 IP <-> net 2", w=130)
        ns = [self.node("m3", "VAV-3", "box", 200, 260, "MAC 3", "device 20003", w=104), self.node("m5", "VAV-5", "box", 360, 260, "MAC 5", "device 20005", w=104),
              self.node("m12", "VAV-12", "box", 520, 260, "MAC 12", "device 20012", w=104), self.node("s130", "CO2 SENSOR", "sensor", 690, 260, "MAC 130", "slave", w=110)]
        for n in ns:
            n.at_top()
        self.trunk(180, 60, 850, [r] + ns, "rs485", net="VDIFF", label="MS/TP 38400 bit/s, shielded twisted pair", t0=True, t1=True)
        self.user = "r"
        self.ring = [0, 3, 5, 12]
        self.ids = {0: "r", 3: "m3", 5: "m5", 12: "m12", 130: "s130"}
        self.ns = {0: 3, 3: 5, 5: 12, 12: 0}
        self.tok_count = {m: 0 for m in self.ring}
        self.ps = {m: m for m in self.ring}
        self.holder = 0
        self.want = []
        self.inv = 0
        self.tb = 1 / 38400.0
        r.vars.update({"Token passes": 0, "Ring": "0 3 5 12", "Max_Master": 127, "Errors": 0})
        self.at(0.01, self.token_hold, 0)
        self.every(2.5, lambda: self.want.append(("read", 5)), 1.0)
        self.every(4.0, lambda: self.want.append(("read", 130)), 2.0)

    def send(self, src, dst, ftype, data=b"", info=None, kind="ctl", err=None):
        sm, dm = src, dst
        p = mstp_frame(ftype, dm, sm, data)
        if err is None and self.fault["no_term1"] and self.rng.random() < 0.03:
            err = "CRC error: reflections from the unterminated end"
        fr = serial_frame(self, self.ids.get(sm, "r"), self.ids.get(dm) if dm != 255 else None, "MS/TP", info or "%s %d -> %d" % (MSTP_T[ftype], sm, dm), p, 38400,
                          8, "N", 1, rs485=2, kind=kind, err=err, sd="MAC %d" % sm, dd=("MAC %d" % dm) if dm != 255 else "broadcast")
        self.tx(fr, ifs=40 * self.tb)
        return fr

    def present(self, mac):
        n = self.by.get(self.ids.get(mac))
        if n is None or not n.on:
            return False
        if mac == 5 and self.fault["lost"]:
            return False
        if mac == 12 and self.fault["baud"]:
            return False
        return True

    def token_hold(self, mac):
        """Station `mac` has the token: maybe send data, maybe poll, then pass it."""
        self.holder = mac
        t = self.t
        if mac == 0 and self.want:
            what, tgt = self.want.pop(0)
            self.inv = (self.inv + 1) & 0xFF
            ap = Apdu("confirmed", 12, self.inv)
            ap.add("objectIdentifier", c_oid(0, 0 if tgt != 130 else 0, 1), oid_txt(0, 1), "")
            ap.add("propertyIdentifier", c_uint(1, 85), "85 present-value", "")
            data = stack(npdu(True, snet=1, sadr=bytes([192, 168, 50, 10, 0xBA, 0xC0])), ap.done()).b
            fr = self.send(0, tgt, 5, data, "BACnet Data Expecting Reply 0 -> %d: readProperty analog-input,1 [invoke %d]" % (tgt, self.inv), "cmd")
            if self.present(tgt) or (tgt == 130 and self.by["s130"].on):
                a2 = Apdu("complex", 12, self.inv)
                a2.add("objectIdentifier", c_oid(0, 0, 1), oid_txt(0, 1), "")
                a2.add("propertyIdentifier", c_uint(1, 85), "85 present-value", "")
                val = 22.4 if tgt == 5 else 612.0
                a2.add("value", c_open(3) + a_real(val) + c_close(3), "%.1f %s" % (val, "degC" if tgt == 5 else "ppm"), "")
                rdata = stack(npdu(False, dnet=1, dadr=bytes([192, 168, 50, 10, 0xBA, 0xC0])), a2.done()).b
                self.at(fr.t + fr.dur + 0.003, self.send, tgt, 0, 6, rdata, "BACnet Data Not Expecting Reply %d -> 0: ComplexACK %.1f" % (tgt, val), "resp")
                self.at(fr.t + fr.dur + 0.012, self.pass_token, mac)
            else:
                self.at(fr.t + fr.dur + 0.255, self.pass_token, mac)
            return
        self.tok_count[mac] = self.tok_count.get(mac, 0) + 1
        maxm = 10 if self.fault["maxm"] else 127
        if self.tok_count[mac] % 50 == 0:
            nxt = self.ns[mac]
            gap = (self.ps[mac] + 1) % (maxm + 1)
            if gap != nxt and gap <= maxm:
                self.ps[mac] = gap
                self.send(mac, gap, 1, info="Poll For Master %d -> %d (looking for new masters)" % (mac, gap))
                if gap in self.ids and self.present(gap) and gap not in self.ring:
                    self.at(self.t + 0.004, self.send, gap, mac, 2, b"", "Reply To Poll For Master %d -> %d" % (gap, mac), "resp")
                    self.at(self.t + 0.01, self._join, mac, gap)
                self.at(self.t + 0.025, self.pass_token, mac)
                return
            self.ps[mac] = mac
        self.pass_token(mac)

    def _join(self, mac, new):
        self.ns[new] = self.ns[mac]
        self.ns[mac] = new
        self.ring = sorted(set(self.ring + [new]))
        self.by["r"].vars["Ring"] = " ".join(str(m) for m in self.ring)
        self.log("MS/TP: master %d joined the ring after a Poll For Master" % new)

    def pass_token(self, mac, nxt=None):
        nxt = self.ns[mac] if nxt is None else nxt
        err = None
        if self.fault["dupmac"] and nxt == 5:
            err = "Two stations with MAC 5 answered: collision"
        fr = self.send(mac, nxt, 0, info="Token %d -> %d" % (mac, nxt), err=err)
        self.by["r"].vars["Token passes"] += 1
        if err:
            self.by["r"].vars["Errors"] += 1
        if self.present(nxt) and not err:
            self.at(fr.t + fr.dur + 0.0015, self.token_hold, nxt)
        else:
            self.at(fr.t + fr.dur + (0.5 if nxt == 5 and self.fault["lost"] else 0.02), self.lost, mac, nxt)

    def lost(self, mac, nxt):
        if self.fault["lost"] and nxt == 5:
            self.log("MS/TP: no token for Tno_token (500 ms) - master 0 regenerates it, ring rebuilt without MAC 5")
            self.ns[3] = 12
            self.ring = [m for m in self.ring if m != 5]
            self.by["r"].vars["Ring"] = " ".join(str(m) for m in self.ring)
            self.at(self.t + 0.01, self.token_hold, 0)
            return
        if self.fault["dupmac"] and nxt == 5:
            self.dup_n = getattr(self, "dup_n", 0) + 1
            if self.dup_n % 2:
                self.pass_token(mac)
            else:
                self.log("MS/TP: master %d gives up on MAC 5 after a retry and passes the token to %d" % (mac, self.ns[5]))
                self.pass_token(mac, self.ns[5])
            return
        if nxt == 12 and not self.present(12):
            self.ns[mac] = self.ns.get(12, 0)
            self.ring = [m for m in self.ring if m != 12]
            self.by["r"].vars["Ring"] = " ".join(str(m) for m in self.ring)
        self.pass_token(mac)

    def on_fault(self, key, on):
        if key == "maxm":
            self.by["r"].vars["Max_Master"] = 10 if on else 127
            if on and 12 in self.ring:
                self.ns[5] = 0
                self.ring = [m for m in self.ring if m != 12]
                self.by["r"].vars["Ring"] = " ".join(str(m) for m in self.ring)
        if key == "lost" and not on:
            self.log("VAV-5 back on line: it will be found by the next Poll For Master")
        if key == "baud" and not on:
            pass

    def tpls(self):
        return [Tpl("Read VAV zone temperature", [P("m", "Target MAC", 5, opts=[3, 5, 12, 130])], lambda s, v, send: self._rd(v["m"], send),
                    "The router sends it when it next holds the token."),
                Tpl("Test_Request", [P("m", "Target MAC", 3, opts=[3, 5, 12])], lambda s, v, send: self._test(v["m"], send), "Echo test: Test_Response carries the same data.")]

    def _rd(self, m, send):
        if not send:
            ap = Apdu("confirmed", 12, self.inv + 1)
            ap.add("objectIdentifier", c_oid(0, 0, 1), oid_txt(0, 1), "")
            ap.add("propertyIdentifier", c_uint(1, 85), "85 present-value", "")
            return Frame(self.t, 0.003, "r", self.ids[m], "MS/TP", "preview", pdu=mstp_frame(5, m, 0, stack(npdu(True), ap.done()).b))
        self.want.append(("read", m))
        return None

    def _test(self, m, send):
        p = mstp_frame(3, m, 0, b"COMMSIM")
        if not send:
            return Frame(self.t, 0.003, "r", self.ids[m], "MS/TP", "preview", pdu=p)
        fr = self.send(0, m, 3, b"COMMSIM", "Test_Request 0 -> %d" % m, "cmd")
        if self.present(m):
            self.at(fr.t + fr.dur + 0.003, self.send, m, 0, 4, b"COMMSIM", "Test_Response %d -> 0" % m, "resp")
        return None


# =================================================================== KNX
def ga_str(g):
    return "%d/%d/%d" % (g >> 11, (g >> 8) & 7, g & 0xFF)


def ia_str(a):
    return "%d.%d.%d" % (a >> 12, (a >> 8) & 15, a & 0xFF)


def ga(m, mid, s):
    return (m << 11) | (mid << 8) | s


def ia(a, l_, d):
    return (a << 12) | (l_ << 8) | d


def dpt9(v):
    m = int(round(v * 100))
    e = 0
    while m < -2048 or m > 2047:
        m = int(round(m / 2.0))
        e += 1
    mm = m & 0xFFF
    return bytes([((mm >> 4) & 0x80) | (e << 3) | ((mm >> 8) & 0x07), mm & 0xFF])


def knx_wire(data, labels=None, ack=False):
    tb = 1 / 9600.0
    w = Wire(bit=tb)
    w.set("K", 0.0, 0)
    t = 2 * tb
    for i, byte in enumerate(data):
        t0 = t
        par = bin(byte).count("1") & 1
        for bit in [0] + lsb(byte, 8) + [par, 1]:
            if bit == 0:
                w.set("K", t, 1)
                w.set("K", t + 35e-6, 2)
                w.set("K", t + 60e-6, 0)
            t += tb
        w.seg(t0, t, labels[i] if labels else "%02X" % byte, i % 2, 0)
        t += 2 * tb
    w.end(t + tb)
    return w


class KNX(Scenario):
    key, name, cat = "knx", "KNX", "building"
    blurb = "Home and building automation"
    phy, rate = "knx", 9600
    medium = "KNX TP1 line 1.1: 30 V DC bus with data on the same pair, 9600 bit/s; push button, switch and dimming actuators, thermostat, line coupler"
    nets = [("BUS", "KNX TP1 bus voltage (red +, black -)")]
    lines = ["K"]
    faults = [("noack", "Switch actuator lost its programming (no group addresses)", "Nobody acknowledges 1/0/1: the push button repeats the telegram 3 times with the repeat flag cleared."),
              ("busy", "Dimming actuator receive buffer full", "It answers BUSY instead of ACK; the sender waits and repeats."),
              ("psu", "Bus power supply overloaded", "The bus voltage sags towards 21 V: devices brown out and telegrams are lost."),
              ("filter", "Line coupler filter table missing 1/0/1", "Telegrams for 1/0/1 are not passed to the backbone: the visualisation never sees the light switch.")]
    spec = [("Standard", "ISO/IEC 14543-3, EN 50090, KNX Association specifications; media TP1, PL110, RF 868 MHz, KNXnet/IP"),
            ("TP1 physical", "SELV 30 V DC on a twisted pair (also powering the devices), 9600 bit/s; a 0 bit is a 35 us voltage dip plus an equalisation pulse; 1 = no pulse"),
            ("Characters", "Start, 8 data bits LSB first, even parity, stop, 2 bits pause; after a telegram 15 bit times, then ACK (CCh) / NAK (0Ch) / BUSY (C0h)"),
            ("Telegram", "Control, source (individual address area.line.device), destination (group address main/middle/sub), address type + hop count + length, TPCI/APCI + data, checksum"),
            ("Access", "CSMA/CA: a transmitting device that reads back a 0 where it sent a 1 stops - logical 0 dominates, lower values win"),
            ("Data", "Datapoint types: DPT 1.001 switch (1 bit), 3.007 dimming (4 bit), 5.001 percentage (1 byte), 9.001 temperature (2-byte float)")]
    frame = [["Standard telegram", ("Control", 8), ("Source", 16), ("Destination", 16), ("Type/hops/len", 8), ("TPCI/APCI", 16), ("Data", "0-14 x 8"), ("Check", 8)]]
    about = ("KNX is the European standard for home and building control. Every device is wired to one green bus cable that carries both "
             "the 30 V supply and the data. Sensors such as push buttons send group telegrams - 'group 1/0/1 = ON' - and every actuator that "
             "is programmed to listen to that group reacts and acknowledges. Group addresses are the 'virtual wiring' of the installation.")
    guide = ["Press the button (COMPOSE GroupValueWrite 1/0/1 ON): telegram, 15 bit pause, ACK - then the actuator's status telegram 1/0/2.",
             "SCOPE: the 0 bits as 35 us voltage dips with an equalisation pulse on the 30 V bus.",
             "Decode a temperature telegram (DPT 9.001): exponent and mantissa.",
             "Unprogram the switch actuator: the telegram is repeated with the repeat flag cleared."]

    def build(self):
        nodes = [("psu", "POWER SUPPLY 640 mA", "box", 30, 40, "", "30 V DC + choke", 130), ("lc", "LINE COUPLER", "gw", 30, 140, "1.1.0", "to backbone 1.0", 130),
                 ("pb", "PUSH BUTTON", "button", 230, 260, "1.1.10", "2-fold", 104), ("sw", "SWITCH ACTUATOR", "io", 380, 260, "1.1.20", "8-fold 16 A", 120),
                 ("dim", "DIMMING ACTUATOR", "lamp", 545, 260, "1.1.21", "4-fold LED", 120), ("ts", "ROOM THERMOSTAT", "tstat", 710, 260, "1.1.30", "DPT 9.001", 120)]
        ns = []
        for nid, lab, kind, x, y, addr, sub, w in nodes:
            n = self.node(nid, lab, kind, x, y, addr, sub, w=w)
            ns.append(n)
        for n in ns[2:]:
            n.at_top()
        for n in ns[:2]:
            n.at_right()
        self.seg([ns[0].port, (180, 66), (180, 200)], "knx", net="BUS", c0="screw")
        self.seg([ns[1].port, (180, 166)], "knx", net="BUS", c0="screw")
        self.trunk(200, 180, 850, ns[2:], "knx", net="BUS", label="KNX TP1 (YCYM 2x2x0.8, red/black)", c="screw")
        self.user = "pb"
        self.light = False
        self.bright = 0
        self.temp = 21.5
        self.n_rep = 0
        self.by["sw"].vars.update({"Channel A (light)": "OFF", "Group addresses": "1/0/1 switch, 1/0/2 status"})
        self.by["dim"].vars.update({"Brightness": "0 %", "Group addresses": "1/0/3, 1/1/1 dim, 1/2/1 status"})
        self.by["ts"].vars.update({"Room temperature": 21.5})
        self.by["ts"].ctl = [("Room temperature", "TEMP", 10.0, 30.0, 0, lambda v: "%.1f degC" % v)]
        self.by["lc"].vars.update({"Forwarded to backbone": 0, "Blocked": 0})
        self.by["psu"].vars.update({"Bus voltage": "29.8 V", "Current": "212 mA"})
        self.every(10.0, self.temp_report, 2.0)
        self.every(12.0, lambda: self.write(ia(1, 1, 10), ga(1, 0, 1), not self.light, "pb"), 4.0)
        self.every(1.0, self.physics, 0.5)

    def telegram(self, src, dst, tpdu, group=True, repeat=False, prio=3):
        ctrl = 0x90 | (0 if repeat else 0x20) | (prio << 2)
        body = bytes([ctrl]) + struct.pack(">HH", src, dst) + bytes([(0x80 if group else 0) | (6 << 4) | (len(tpdu) - 1)]) + tpdu
        cs = 0xFF
        for x in body:
            cs ^= x
        b = Bld("KNX TP1 standard telegram", "EN 50090-4-1 / KNX data link layer.")
        b.u8("Control field", ctrl, "standard frame, %s, priority %s" % ("REPEATED" if repeat else "not repeated", ["system", "normal", "urgent", "low"][prio]),
             "Bit 5 = 1 for the first transmission; repeats clear it so receivers can drop duplicates.")
        b.u16("Source address", src, ia_str(src), "Individual address of the sender (area.line.device).")
        b.u16("Destination address", dst, ga_str(dst) if group else ia_str(dst), "Group address (main/middle/sub) - the 'virtual wire'.")
        b.u8("Address type / hop count / length", body[5], "%s, hop count 6, length %d" % ("group" if group else "individual", len(tpdu) - 1),
             "Hop count is decremented by each coupler; length = data bytes after the first TPCI byte.")
        apci = ((tpdu[0] & 3) << 2) | (tpdu[1] >> 6)
        b.u8("TPCI / APCI (high)", tpdu[0], "TPCI 0 (UDP, data group)", "")
        b.u8("APCI (low) + 6-bit data", tpdu[1], "%s%s" % ({0: "GroupValueRead", 1: "GroupValueResponse", 2: "GroupValueWrite"}.get(apci, "APCI %d" % apci),
                                                           (", data %d" % (tpdu[1] & 0x3F)) if len(tpdu) == 2 and apci else ""), "")
        if len(tpdu) > 2:
            b.raw("Data", tpdu[2:], None, "")
        b.u8("Checksum", cs, "0x%02X [correct]" % cs, "Odd parity across all bytes: NOT XOR of the telegram.")
        return b.done()

    def ack_pdu(self, code):
        return Pdu(bytes([code]), [[0, "KNX acknowledgement", 0, 1, ""], [1, {0xCC: "ACK (CCh)", 0x0C: "NAK (0Ch)", 0xC0: "BUSY (C0h)"}[code], 0, 1,
                                                                           "Sent by every addressed receiver 15 bit times after the telegram."]])

    def send(self, src_nid, p, info, kind, dst_nid=None, err=None):
        tb = 1 / 9600.0
        dur = len(p.b) * 13 * tb + 2 * tb
        if self.fault["psu"] and err is None and self.rng.random() < 0.5:
            err = "Bus voltage too low: telegram corrupted"
        labels = None
        fr = Frame(self.t, dur, src_nid, dst_nid, "KNX", info, pdu=p, kind=kind, err=err, wirefn=lambda f, d=p.b: knx_wire(d))
        self.tx(fr, ifs=50 * tb)
        return fr

    def write(self, src, dst, val, src_nid, repeat=0, send=True):
        if isinstance(val, bool):
            tp = bytes([0x00, 0x80 | int(val)])
            vt = "ON" if val else "OFF"
        elif isinstance(val, float):
            tp = bytes([0x00, 0x80]) + dpt9(val)
            vt = "%.2f degC (DPT 9.001)" % val
        else:
            tp = bytes([0x00, 0x80, int(val) & 0xFF])
            vt = "%d (DPT 5.001: %.0f %%)" % (val, val / 2.55)
        p = self.telegram(src, dst, tp, repeat=repeat > 0)
        if not send:
            return Frame(self.t, 0.01, src_nid, None, "KNX", "preview", pdu=p, wirefn=lambda f, d=p.b: knx_wire(d))
        fr = self.send(src_nid, p, "%s -> %s GroupValueWrite %s%s" % (ia_str(src), ga_str(dst), vt, " [repeat %d]" % repeat if repeat else ""), "cmd" if src_nid == "pb" else "data")
        self.at(fr.t + fr.dur + 15 / 9600.0, self.receivers, src, dst, val, src_nid, repeat, fr.err)
        return None

    def receivers(self, src, dst, val, src_nid, repeat, err):
        if self.fault["psu"] and err:
            return
        listeners = []
        if dst == ga(1, 0, 1) and not self.fault["noack"]:
            listeners.append("sw")
        if dst in (ga(1, 0, 3), ga(1, 1, 1)):
            listeners.append("dim")
        if dst == ga(3, 0, 1):
            listeners.append("lc")
        if dst in (ga(1, 0, 2), ga(1, 2, 1)):
            listeners.append("lc")
        code = None
        if not listeners:
            if repeat < 3:
                self.at(self.t + 50 / 9600.0, self.write, src, dst, val, src_nid, repeat + 1)
            else:
                self.log("KNX: no ACK for %s after 3 repeats - nobody listens to this group address" % ga_str(dst))
            return
        if "dim" in listeners and self.fault["busy"] and repeat < 2:
            code = 0xC0
        else:
            code = 0xCC
        self.send(listeners[0], self.ack_pdu(code), "%s for %s" % ({0xCC: "ACK", 0xC0: "BUSY"}[code], ga_str(dst)), "ack" if code == 0xCC else "err")
        if code == 0xC0:
            self.at(self.t + 0.15, self.write, src, dst, val, src_nid, repeat + 1)
            return
        if dst in (ga(1, 0, 2), ga(1, 2, 1), ga(3, 0, 1)) or "lc" in listeners:
            self.couple(dst)
        if dst == ga(1, 0, 1):
            self.couple(dst)
            self.light = bool(val)
            self.by["sw"].vars["Channel A (light)"] = "ON" if self.light else "OFF"
            self.at(self.t + 0.06, self.write, ia(1, 1, 20), ga(1, 0, 2), self.light, "sw")
        if dst == ga(1, 0, 3):
            self.bright = 255 if val else 0
            self._dim_status()
        if dst == ga(1, 1, 1):
            step = val if isinstance(val, int) else 0
            self.bright = max(0, min(255, self.bright + (32 if step & 8 else -32)))
            self._dim_status()

    def _dim_status(self):
        self.by["dim"].vars["Brightness"] = "%.0f %%" % (self.bright / 2.55)
        self.at(self.t + 0.08, self.write, ia(1, 1, 21), ga(1, 2, 1), self.bright, "dim")

    def couple(self, dst):
        lc = self.by["lc"].vars
        if self.fault["filter"] and dst == ga(1, 0, 1):
            lc["Blocked"] += 1
        else:
            lc["Forwarded to backbone"] += 1

    def temp_report(self):
        self.temp = self.by["ts"].vars["Room temperature"]
        self.write(ia(1, 1, 30), ga(3, 0, 1), float(self.temp), "ts")

    def read(self, dst, send=True):
        p = self.telegram(ia(1, 1, 10), dst, bytes([0x00, 0x00]))
        if not send:
            return Frame(self.t, 0.01, "pb", None, "KNX", "preview", pdu=p, wirefn=lambda f, d=p.b: knx_wire(d))
        fr = self.send("pb", p, "1.1.10 -> %s GroupValueRead" % ga_str(dst), "cmd")
        owner = {ga(1, 0, 2): ("sw", ia(1, 1, 20), self.light), ga(1, 2, 1): ("dim", ia(1, 1, 21), self.bright), ga(3, 0, 1): ("ts", ia(1, 1, 30), float(self.temp))}.get(dst)
        if owner:
            nid, a, v = owner
            self.at(fr.t + fr.dur + 15 / 9600.0, self.send, nid, self.ack_pdu(0xCC), "ACK for %s" % ga_str(dst), "ack")
            tp = bytes([0x00, 0x40 | int(v)]) if isinstance(v, bool) else (bytes([0x00, 0x40]) + (dpt9(v) if isinstance(v, float) else bytes([v])))
            rp = self.telegram(a, dst, tp)
            self.at(fr.t + fr.dur + 0.03, self.send, nid, rp, "%s -> %s GroupValueResponse %s" % (ia_str(a), ga_str(dst), v), "resp")
        return None

    def physics(self):
        self.by["psu"].vars["Bus voltage"] = "21.4 V (overload!)" if self.fault["psu"] else "29.8 V"
        self.by["psu"].vars["Current"] = "655 mA" if self.fault["psu"] else "212 mA"

    def cond(self, net):
        c = Scenario.cond(self, net)
        if self.fault["psu"]:
            c["off"] = -8.0
        return c

    def tpls(self):
        gas = [ga(1, 0, 1), ga(1, 0, 3), ga(1, 2, 1), ga(1, 0, 2), ga(3, 0, 1)]
        return [Tpl("GroupValueWrite (switch)", [P("g", "Group address", ga(1, 0, 1), opts=[ga(1, 0, 1), ga(1, 0, 3)], fmt=ga_str), P("v", "Value", "ON", opts=["ON", "OFF"])],
                    lambda s, v, send: self.write(ia(1, 1, 10), v["g"], v["v"] == "ON", "pb", send=send), "1/0/1 = light on the switch actuator, 1/0/3 = dimmer channel on / off."),
                Tpl("Relative dimming (DPT 3.007)", [P("d", "Direction", "brighter", opts=["brighter", "darker"])],
                    lambda s, v, send: self._dim(v["d"] == "brighter", send), "4-bit control: direction bit + step code (here 1 = 100 %, sent as one step of 32)."),
                Tpl("GroupValueRead", [P("g", "Group address", ga(1, 0, 2), opts=[ga(1, 0, 2), ga(1, 2, 1), ga(3, 0, 1)], fmt=ga_str)],
                    lambda s, v, send: self.read(v["g"], send), "The device that owns the status object answers with GroupValueResponse."),
                Tpl("Temperature (DPT 9.001)", [P("t", "Value degC", 21.5, -50.0, 99.0, 0.5)], lambda s, v, send: self.write(ia(1, 1, 30), ga(3, 0, 1), float(v["t"]), "ts", send=send),
                    "2-byte float: 0.01 x M x 2^E.")]

    def _dim(self, up, send):
        val = 0x09 if up else 0x01
        p = self.telegram(ia(1, 1, 10), ga(1, 1, 1), bytes([0x00, 0x80 | val]))
        if not send:
            return Frame(self.t, 0.01, "pb", None, "KNX", "preview", pdu=p, wirefn=lambda f, d=p.b: knx_wire(d))
        fr = self.send("pb", p, "1.1.10 -> 1/1/1 GroupValueWrite dim %s (DPT 3.007 0x%X)" % ("brighter" if up else "darker", val), "cmd")
        self.at(fr.t + fr.dur + 15 / 9600.0, self.receivers, ia(1, 1, 10), ga(1, 1, 1), val, "pb", 0, fr.err)
        return None

    def draw_extra(self, s, rect):
        n = self.by["sw"]
        c = (255, 230, 120) if self.light else (60, 60, 60)
        x, y = rect.x + n.x + n.w - 14, rect.y + n.y + n.h + 14
        pygame.draw.circle(s, c, (int(x), int(y)), 7)
        pygame.draw.circle(s, (20, 20, 20), (int(x), int(y)), 7, 1)
        d = self.by["dim"]
        k = self.bright / 255.0
        pygame.draw.circle(s, (int(60 + 195 * k), int(60 + 170 * k), int(60 + 60 * k)), (int(rect.x + d.x + d.w - 14), int(rect.y + d.y + d.h + 14)), 7)


# ========================================================= LonWorks / LonTalk
SNVT = {"SNVT_switch": 95, "SNVT_temp_p": 105, "SNVT_occupancy": 109}


def lon_wire(data):
    """Differential Manchester (FT-10): a transition at every bit boundary, an extra one mid-bit for a 0."""
    tb = 1 / 78125.0
    w = Wire(bit=tb)
    lvl = 0
    w.set("M", 0.0, 2)
    t = tb
    bits = [1] * 8 + [0]
    for byte in data:
        bits += msb(byte, 8)
    for i, b in enumerate(bits):
        lvl ^= 1
        w.set("M", t, lvl)
        if b == 0:
            lvl ^= 1
            w.set("M", t + tb / 2, lvl)
        t += tb
    for i in range(len(data)):
        t0 = tb + (9 + 8 * i) * tb
        w.seg(t0, t0 + 8 * tb, "%02X" % data[i], i % 2, 0)
    w.seg(tb, tb + 9 * tb, "preamble", 7, 0)
    w.set("M", t + 2.5 * tb, 2)
    w.end(t + 3 * tb)
    return w


class LonWorks(Scenario):
    key, name, cat = "lonworks", "LonWorks / LonTalk", "building"
    blurb = "Distributed building control networks"
    phy, rate = "manch", 78125
    medium = "LonWorks FT-10 free-topology channel (78 kbit/s, differential Manchester): network variables bound between switches, sensors and controllers"
    nets = [("BUS", "FT-10 twisted pair (polarity-insensitive)")]
    lines = ["M"]
    faults = [("unconf", "Lighting controller not commissioned", "It is in the unconfigured state: it ignores network variable updates; the switch retries and reports a failure."),
              ("ack", "Noise destroys some acknowledgements", "The switch retransmits with the same transaction number; the receiver recognises the duplicate."),
              ("domain", "Occupancy sensor installed in the wrong domain", "Its updates carry another domain ID: nobody accepts them."),
              ("no_term0", "Free-topology terminator missing", "Ringing on the free-topology wiring causes CRC errors.")]
    spec = [("Standard", "ISO/IEC 14908-1 (LonTalk / CNP), ANSI/CTA-709.1, EN 14908; channels FT-10 (78 kbit/s), TP/XF-1250, PL-20, IP-852"),
            ("Addressing", "Domain (0, 1, 3 or 6 bytes) > subnet (1-255) > node (1-127); groups (1-256); every Neuron chip has a unique 48-bit Neuron ID"),
            ("Services", "Acknowledged (with retries), unacknowledged-repeated, unacknowledged, request / response; 4-bit transaction numbers"),
            ("Data", "Network variables with standard types (SNVTs): SNVT_switch (value + state), SNVT_temp_p (0.01 degC), SNVT_occupancy ..."),
            ("Access", "Predictive p-persistent CSMA: random slots scaled by the estimated channel backlog; priority slots"),
            ("Binding", "A network tool commissions devices (Neuron ID, domain / subnet / node) and binds output NVs to input NVs")]
    frame = [["LonTalk packet", ("Preamble", 9), ("Link: pri/alt/backlog", 8), ("NPDU hdr", 8), ("Addresses", "2-8 x 8"), ("Domain", "0-6 x 8"),
              ("TPDU/APDU", "n x 8"), ("CRC-16", 16)]]
    about = ("LonWorks puts a small processor - originally the Neuron chip - in every device and lets them talk peer to peer over the "
             "LonTalk protocol. Devices publish and consume network variables of standard types; a network tool 'binds' a switch's output "
             "to a lamp controller's input, after which they exchange updates directly, with acknowledgements and retries if needed.")
    guide = ["Toggle the wall switch: acknowledged SNVT_switch update, then the ACK with the same transaction number.",
             "Find the room temperature: unacknowledged-repeated to group 1, sent three times.",
             "LOGIC: the differential Manchester line, a transition at every bit boundary.",
             "Press the service pin of the occupancy sensor (COMPOSE): its Neuron ID goes out to the network tool."]

    def build(self):
        tool = self.node("tool", "NETWORK MGMT TOOL", "laptop", 30, 40, "subnet 1 node 1", "LNS-based", w=140)
        ns = [self.node("sw", "WALL SWITCH", "button", 200, 260, "1/10", "nvoSwitch"), self.node("light", "LIGHTING CONTROLLER", "lamp", 360, 260, "1/20", "nviSwitch", w=130),
              self.node("occ", "OCCUPANCY SENSOR", "sensor", 530, 260, "1/30", "nvoOccupancy", w=130), self.node("rc", "ROOM CONTROLLER", "tstat", 700, 260, "1/40", "nvoSpaceTemp", w=130)]
        for n in ns:
            n.at_top()
        self.trunk(180, 60, 850, [tool] + ns, "tsp", net="BUS", label="FT-10 free topology, 78 kbit/s", t0=True, tlabel="52.3 Ω")
        self.user = "sw"
        self.node_addr = {"tool": (1, 1), "sw": (1, 10), "light": (1, 20), "occ": (1, 30), "rc": (1, 40)}
        self.nid = {"tool": "05 00 41 7C 2A 01", "sw": "04 01 77 3B 10 02", "light": "04 01 77 3B 10 9E", "occ": "05 00 12 C4 08 33", "rc": "04 01 80 01 7F 45"}
        self.trans = 0
        self.lamp = False
        self.occupied = False
        self.by["light"].vars.update({"Lamp": "OFF", "State": "configured online"})
        self.by["sw"].vars.update({"Failures": 0})
        self.by["rc"].vars.update({"Space temp": 21.8})
        self.by["rc"].ctl = [("Space temp", "TEMP", 10.0, 30.0, 0, lambda v: "%.1f degC" % v)]
        self.every(8.0, lambda: self.switch(not self.lamp), 1.0)
        self.every(10.0, self.temp, 3.0)
        self.every(14.0, self.occupancy, 6.0)

    def packet(self, src, dst, apdu_rows, apdu, svc="ackd", group=None, title="", domain=b"\x4C"):
        ss, sn = self.node_addr[src]
        fmt = 3
        afmt = 1 if group is not None else 2
        dlen = {0: 0, 1: 1, 3: 2, 6: 3}[len(domain)]
        hdr = bytes([0x00 | (fmt << 4) | (afmt << 2) | dlen])
        addr = bytes([ss, 0x80 | sn]) + (bytes([group]) if group is not None else bytes(self.node_addr[dst]))
        tp = {"ackd": 0x00, "unackd_rpt": 0x10, "ack": 0x20}[svc] | (self.trans & 15)
        body = bytes([0x01]) + hdr + addr + domain + bytes([tp]) + apdu
        c = crcn("CRC-16/XMODEM", body)
        b = Bld("LonTalk packet (ISO/IEC 14908-1): %s" % title, "Link header, network header and addresses, domain, transport header, application PDU, CRC.")
        b.u8("Link header", 0x01, "priority 0, alt path 0, delta backlog 1", "Delta backlog: how many packets this one is expected to generate (feeds the predictive CSMA).")
        b.u8("Network header", hdr[0], "version 0, PDU format APDU via TPDU, address format %d (%s), domain length %d bytes" % (afmt, "group" if afmt == 1 else "subnet/node",
                                                                                                                           len(domain)), "")
        b.raw("Source", addr[:2], "subnet %d node %d" % (ss, sn), "")
        b.raw("Destination", addr[2:], ("group %d" % group) if group is not None else "subnet %d node %d" % self.node_addr[dst], "")
        b.raw("Domain ID", domain, domain.hex().upper(), "Only devices in the same domain accept the packet.")
        b.u8("Transport header", tp, "%s, transaction number %d" % ({"ackd": "ACKD (acknowledged)", "unackd_rpt": "UNACKD_RPT (repeated)", "ack": "ACK"}[svc], self.trans & 15),
             "Duplicate detection uses the transaction number.")
        base = len(b.b)
        b.b += apdu
        for d, txt, o, n, de in apdu_rows:
            b.rows.append([d, txt, base + o, n, de])
        b.u16("CRC", c, "0x%04X [correct]" % c, "16-bit CRC (CCITT polynomial) over the packet.")
        return b.done()

    def nv(self, sel, value, txt, snvt):
        apdu = struct.pack(">H", 0x8000 | sel) + value
        rows = [[1, "APDU: network variable update, selector 0x%04X" % sel, 0, 2, "Bit 15 = NV message; the 14-bit selector identifies the bound variable."],
                [1, "%s value: %s" % (snvt, txt), 2, len(value), ""]]
        return apdu, rows

    def send(self, src, dst, p, info, kind, err=None):
        if err is None and self.fault["no_term0"] and self.rng.random() < 0.15:
            err = "CRC error: reflections on the unterminated free-topology segment"
        fr = Frame(self.t, (len(p.b) * 8 + 12) / 78125.0, src, dst, "LonTalk", info, pdu=p, kind=kind, err=err, wirefn=lambda f, d=p.b: lon_wire(d))
        self.tx(fr, ifs=0.0006 + float(self.rng.random()) * 0.0004)
        return fr

    def switch(self, on, tries=0, send=True):
        val = bytes([200 if on else 0, 1 if on else 0])
        apdu, rows = self.nv(0x0010, val, "%s (value %.1f %%, state %d)" % ("ON" if on else "OFF", 100.0 if on else 0.0, int(on)), "SNVT_switch")
        if tries == 0 and send:
            self.trans = (self.trans + 1) & 15
        p = self.packet("sw", "light", rows, apdu, "ackd", title="nvoSwitch update")
        if not send:
            return Frame(self.t, 0.001, "sw", "light", "LonTalk", "preview", pdu=p, wirefn=lambda f, d=p.b: lon_wire(d))
        fr = self.send("sw", "light", p, "nvoSwitch -> nviSwitch (subnet 1 node 20): %s, ACKD trans %d%s" % ("ON" if on else "OFF", self.trans, " retry %d" % tries if tries else ""),
                       "cmd")
        if self.fault["unconf"]:
            self.at(self.t + 0.064, self._retry, on, tries)
            return None
        dup = getattr(self, "last_tr", None) == self.trans
        if not dup:
            self.lamp = on
            self.by["light"].vars["Lamp"] = "ON" if on else "OFF"
        self.last_tr = self.trans
        lost = self.fault["ack"] and self.rng.random() < 0.5
        ap = self.packet("light", "sw", [[1, "ACK for transaction %d%s" % (self.trans, " (duplicate: not processed again)" if dup else ""), 0, 0, ""]], b"", "ack", title="ACK")
        self.at(fr.t + fr.dur + 0.002, self.send, "light", "sw", ap, "ACK trans %d%s" % (self.trans, " (duplicate detected)" if dup else ""), "ack",
                "ACK lost to noise" if lost else None)
        if lost:
            self.at(self.t + 0.064, self._retry, on, tries)
        return None

    def _retry(self, on, tries):
        if tries < 3:
            self.switch(on, tries + 1)
        else:
            self.by["sw"].vars["Failures"] += 1
            self.log("Wall switch: no ACK after 3 retries (receiver unconfigured or offline)")

    def temp(self):
        t = self.by["rc"].vars["Space temp"]
        apdu, rows = self.nv(0x0021, struct.pack(">h", int(t * 100)), "%.2f degC (0.01 degC units)" % t, "SNVT_temp_p")
        self.trans = (self.trans + 1) & 15
        p = self.packet("rc", None, rows, apdu, "unackd_rpt", group=1, title="nvoSpaceTemp (group 1)")
        for k in range(3):
            self.at(self.t + 0.024 * k, self.send, "rc", None, p, "nvoSpaceTemp -> group 1: %.2f degC, UNACKD_RPT (copy %d of 3)" % (t, k + 1), "data")

    def occupancy(self):
        self.occupied = not self.occupied
        apdu, rows = self.nv(0x0032, bytes([0 if self.occupied else 1]), "OC_OCCUPIED" if self.occupied else "OC_UNOCCUPIED", "SNVT_occupancy")
        self.trans = (self.trans + 1) & 15
        dom = b"\x55" if self.fault["domain"] else b"\x4C"
        p = self.packet("occ", "light", rows, apdu, "ackd", title="nvoOccupancy", domain=dom)
        self.send("occ", "light", p, "nvoOccupancy -> light: %s%s" % ("occupied" if self.occupied else "unoccupied", " (domain 55, ignored!)" if self.fault["domain"] else ""), "data")
        if not self.fault["domain"] and not self.fault["unconf"]:
            ap = self.packet("light", "occ", [[1, "ACK", 0, 0, ""]], b"", "ack", title="ACK")
            self.at(self.t + 0.004, self.send, "light", "occ", ap, "ACK trans %d" % self.trans, "ack")

    def service_pin(self, nid, send=True):
        nid_b = bytes.fromhex(self.nid[nid].replace(" ", ""))
        apdu = bytes([0x7F]) + nid_b + b"\x9F\xFF\xFF\x05\x01\x05\x01\x02\x03\x04\x05\x06"[:8]
        rows = [[1, "Network management: service pin message (code 0x7F)", 0, 1, "Sent when the installer presses the service pin."],
                [1, "Neuron ID: %s" % self.nid[nid], 1, 6, "Unique 48-bit ID burnt into the chip."], [1, "Program ID (start)", 7, 8, "Identifies the application / device type."]]
        p = self.packet(nid, "tool", rows, apdu, "unackd_rpt", title="Service pin message", domain=b"")
        if not send:
            return Frame(self.t, 0.002, nid, None, "LonTalk", "preview", pdu=p, wirefn=lambda f, d=p.b: lon_wire(d))
        self.send(nid, None, p, "Service pin message from %s: Neuron ID %s" % (self.by[nid].label, self.nid[nid]), "ctl")
        return None

    def on_fault(self, key, on):
        self.by["light"].vars["State"] = "UNCONFIGURED (service LED blinking)" if (key == "unconf" and on) else "configured online"

    def tpls(self):
        return [Tpl("Wall switch update", [P("v", "State", "ON", opts=["ON", "OFF"])], lambda s, v, send: self.switch(v["v"] == "ON", 0, send), "Acknowledged SNVT_switch update."),
                Tpl("Service pin", [P("n", "Device", "occ", opts=["sw", "light", "occ", "rc"], fmt=lambda v: self.by[v].label)],
                    lambda s, v, send: self.service_pin(v["n"], send), "Broadcasts the Neuron ID so the tool can commission the device.")]


# =================================================================== DALI
DALI_CMD = {0: "OFF", 1: "UP", 2: "DOWN", 5: "RECALL MAX LEVEL", 6: "RECALL MIN LEVEL", 144: "QUERY STATUS", 145: "QUERY CONTROL GEAR PRESENT",
            146: "QUERY LAMP FAILURE", 160: "QUERY ACTUAL LEVEL"}
DALI_SPECIAL = {0xA1: "TERMINATE", 0xA3: "DTR0", 0xA5: "INITIALISE", 0xA7: "RANDOMISE", 0xA9: "COMPARE", 0xAB: "WITHDRAW", 0xB1: "SEARCHADDRH",
                0xB3: "SEARCHADDRM", 0xB5: "SEARCHADDRL", 0xB7: "PROGRAM SHORT ADDRESS", 0xB9: "VERIFY SHORT ADDRESS"}


def arc_pct(n):
    return 0.0 if n == 0 else 10 ** ((n - 1) / (253 / 3.0) - 1)


def dali_wire(bits, backward=False):
    te = 1 / 2400.0
    w = Wire(bit=2 * te)
    w.set("B", 0.0, 1)
    t = 2 * te
    seq = [1] + bits
    for i, b in enumerate(seq):
        w.set("B", t, 0 if b else 1)
        w.set("B", t + te, 1 if b else 0)
        t += 2 * te
    w.set("B", t, 1)
    if not backward:
        w.seg(2 * te, 4 * te, "S", 7, 0)
        w.seg(4 * te, 20 * te, "address", 0, 0)
        w.seg(20 * te, 36 * te, "opcode / level", 1, 0)
    else:
        w.seg(2 * te, 4 * te, "S", 7, 0)
        w.seg(4 * te, 20 * te, "answer", 0, 0)
    w.seg(t, t + 4 * te, "stop", 7, 0)
    w.end(t + 4 * te)
    return w


class DALI(Scenario):
    key, name, cat = "dali", "DALI", "building"
    blurb = "Lighting control"
    phy, rate = "dali", 1200
    medium = "DALI (IEC 62386) 2-wire bus at 1200 bit/s: an application controller with a bus power supply commands four LED drivers"
    nets = [("DA", "DALI bus (DA+ / DA-, polarity-free)")]
    lines = ["B"]
    faults = [("lamp", "LED module of driver A2 failed", "QUERY STATUS shows lamp failure; QUERY LAMP FAILURE answers YES."),
              ("dup", "Two drivers have short address A1", "Both answer queries at once: the backward frames collide (framing error)."),
              ("new", "A new driver without a short address is installed", "It obeys broadcasts but cannot be addressed - run the commissioning (COMPOSE)."),
              ("psu", "Bus power supply switched off", "The bus stays low: no communication; drivers go to their system-failure level.")]
    spec = [("Standard", "IEC 62386 (DALI-2: 101 system, 102 control gear, 103 control devices, 2xx device types e.g. 207 LED), DiiA certification"),
            ("Physical", "2 wires, polarity-free, bus power supply 16 V typical (max 250 mA), up to 64 control gear, 300 m"),
            ("Coding", "Manchester (bi-phase) at 1200 bit/s; a 1 is a rising edge mid-bit; idle = high; forward frame 1 + 16 bits + 2 stop, backward 1 + 8 bits"),
            ("Addressing", "Short addresses 0-63 (0AAAAAAS), 16 groups (100GGGGS), broadcast (1111111S), special commands for commissioning"),
            ("Levels", "Arc power 0-254 on a logarithmic curve: 254 = 100 %, 1 = 0.1 %; fade times; 16 scenes stored in each driver"),
            ("Commissioning", "INITIALISE, RANDOMISE (24-bit random address), binary search with COMPARE, PROGRAM SHORT ADDRESS, WITHDRAW")]
    frame = [["Forward frame", ("Start 1", 1), ("Address byte", 8), ("Opcode / level", 8), ("Stop (2 bits idle)", 2)], ["Backward frame", ("Start", 1), ("Answer", 8), ("Stop", 2)]]
    about = ("DALI is the lighting control bus: two wires (any polarity) carry both the power for the interfaces and slow Manchester-coded "
             "commands to up to 64 LED drivers. Each driver has a short address and can belong to groups; it stores scenes and fade times "
             "itself. The controller can ask questions - actual level, lamp failure - and the driver answers with an 8-bit backward frame.")
    guide = ["Select a forward frame: address byte (short address, group or broadcast, selector bit) and opcode.",
             "SCOPE: Manchester bits at 1200 bit/s on a 16 V bus; the backward frame follows a few milliseconds later.",
             "Inject the lamp failure and find the status bit in the QUERY STATUS answer.",
             "Install a new driver and run the commissioning: watch the binary search with COMPARE."]

    def build(self):
        ctl = self.node("ctl", "DALI CONTROLLER", "plc", 30, 40, "application controller", "+ 16 V bus PSU", w=150)
        ns = [self.node("d%d" % i, "LED DRIVER A%d" % i, "ballast", 180 + 150 * i, 260, "A%d" % i, "group %d" % (0 if i < 2 else 1), w=120) for i in range(4)]
        nw = self.node("dn", "NEW DRIVER", "ballast", 780, 260, "no address", "uncommissioned", w=104)
        for n in ns + [nw]:
            n.at_top()
        self.trunk(180, 60, 860, [ctl] + ns + [nw], "wire", net="DA", label="DALI 2 x 1.5 mm2 (mains-rated)", c="screw")
        self.user = "ctl"
        self.lv = {i: 200 for i in range(4)}
        self.lv["n"] = 254
        self.addr_n = None
        self.k = 0
        self.busy = False
        self.cm = None
        ctl.vars.update({"Bus": "16.0 V", "Last answer": "-", "Scene": "-"})
        for i in range(4):
            ns[i].vars.update({"Level": "%d (%.1f %%)" % (200, arc_pct(200)), "Status": "-"})
        nw.vars.update({"Level": "254", "Random address": "-"})
        self.every(1.5, self.poll, 0.5)
        self.every(9.0, self.scene_cycle, 4.0)

    def fwd(self, a, d, info, kind="cmd", then=None, answer_from=None):
        if self.fault["psu"]:
            return None
        bits = msb(a, 8) + msb(d, 8)
        b = Bld("DALI forward frame", "16 bits: address byte + opcode / level, Manchester at 1200 bit/s.")
        if a & 0x80 == 0:
            at = "short address A%d" % (a >> 1)
        elif a & 0xE0 == 0x80:
            at = "group G%d" % ((a >> 1) & 15)
        elif a in (0xFE, 0xFF):
            at = "broadcast"
        else:
            at = "special command %s" % DALI_SPECIAL.get(a, "0x%02X" % a)
        if a >= 0xA1 and a & 1 and a not in (0xFF,):
            ot = "data 0x%02X" % d
        elif a & 1:
            ot = "command %d %s" % (d, DALI_CMD.get(d, "GO TO SCENE %d" % (d - 16) if 16 <= d < 32 else "?"))
        else:
            ot = "direct arc power %d (%.1f %%)" % (d, arc_pct(d))
        b.u8("Address byte", a, "%s, selector %d" % (at, a & 1), "0AAAAAAS short, 100GGGGS group, 1111111S broadcast; S = 1 command, 0 arc power level.")
        b.u8("Opcode / level", d, ot, "")
        p = b.done()
        fr = Frame(self.t, 19 / 1200.0, "ctl", answer_from, "DALI", info, pdu=p, kind=kind, wirefn=lambda f, bb=bits: dali_wire(bb))
        self.tx(fr, ifs=0.0135)
        if then:
            self.at(fr.t + fr.dur + 0.0055, then)
        return fr

    def bwd(self, src, val, info, err=None):
        p = Pdu(bytes([val]), [[0, "DALI backward frame", 0, 1, "8-bit answer, sent 2.9-9.2 ms after the forward frame."], [1, info, 0, 1, ""]])
        fr = Frame(self.t, 11 / 1200.0, src, "ctl", "DALI", "Backward frame from %s: 0x%02X %s" % (self.by[src].label, val, info), pdu=p, kind="resp", err=err,
                   wirefn=lambda f, bb=msb(val, 8): dali_wire(bb, True))
        self.tx(fr, ifs=0.0135)
        self.by["ctl"].vars["Last answer"] = "0x%02X %s" % (val, info)
        return fr

    def status(self, i):
        st = 0x04 if self.lv[i] else 0
        if self.fault["lamp"] and i == 2:
            st |= 0x02
        return st

    def poll(self):
        if self.busy or self.cm:
            return
        self.k = (self.k + 1) % 8
        i = self.k % 4
        cmd = 160 if self.k < 4 else 144
        self.query(i, cmd)

    def query(self, i, cmd, send=True):
        if not send:
            return Frame(self.t, 0.016, "ctl", "d%d" % i, "DALI", "preview", pdu=Pdu(bytes([(i << 1) | 1, cmd]), []), wirefn=lambda f: dali_wire(msb((i << 1) | 1, 8) + msb(cmd, 8)))
        fr = self.fwd((i << 1) | 1, cmd, "A%d %s" % (i, DALI_CMD[cmd]), "cmd", answer_from="d%d" % i)
        if fr is None:
            return None

        def ans():
            n = self.by["d%d" % i]
            if not n.on:
                return
            if cmd == 160:
                v, txt = self.lv[i], "actual level %d (%.1f %%)" % (self.lv[i], arc_pct(self.lv[i]))
            elif cmd == 144:
                v = self.status(i)
                txt = "status 0x%02X: %s" % (v, ", ".join(nm for b, nm in ((1, "gear failure"), (2, "LAMP FAILURE"), (4, "lamp on"), (64, "no short address")) if v & b) or "ok")
                n.vars["Status"] = txt.split(": ")[1]
            elif cmd == 146:
                v, txt = (0xFF, "YES (lamp failure)") if (self.fault["lamp"] and i == 2) else (None, "")
                if v is None:
                    return
            else:
                v, txt = 0xFF, "YES"
            err = "Backward frames from two drivers collided: framing error" if (self.fault["dup"] and i == 1) else None
            self.bwd("d%d" % i, v, txt, err)
        self.at(fr.t + fr.dur + 0.006, ans)
        return None

    def set_level(self, a, lvl, send=True, what=None):
        if not send:
            return Frame(self.t, 0.016, "ctl", None, "DALI", "preview", pdu=Pdu(bytes([a & 0xFE, lvl]), []), wirefn=lambda f: dali_wire(msb(a & 0xFE, 8) + msb(lvl, 8)))
        self.fwd(a & 0xFE, lvl, what or "DAPC %s level %d (%.1f %%)" % ("broadcast" if a >= 0xFE else ("G%d" % ((a >> 1) & 15) if a & 0x80 else "A%d" % (a >> 1)), lvl, arc_pct(lvl)))
        for i in range(4):
            hit = a >= 0xFE or (a & 0x80 == 0 and a >> 1 == i) or (a & 0xE0 == 0x80 and ((a >> 1) & 15) == (0 if i < 2 else 1))
            if self.fault["dup"] and a & 0x80 == 0 and a >> 1 == 1 and i == 3:
                hit = True
            if hit:
                self.lv[i] = lvl
                self.by["d%d" % i].vars["Level"] = "%d (%.1f %%)" % (lvl, arc_pct(lvl))
        if a >= 0xFE and (self.fault["new"] or self.addr_n is not None):
            self.lv["n"] = lvl
        return None

    def scene_cycle(self):
        if self.cm:
            return
        sc = int(self.t / 9) % 3
        self.by["ctl"].vars["Scene"] = ["all 80 %", "presentation", "cleaning (max)"][sc]
        if sc == 0:
            self.set_level(0xFE, 230)
        elif sc == 1:
            self.set_level(0x80, 150)
            self.at(self.t + 0.06, self.set_level, 0x82, 60)
        else:
            self.fwd(0xFF, 5, "Broadcast RECALL MAX LEVEL")
            for i in range(4):
                self.lv[i] = 254
                self.by["d%d" % i].vars["Level"] = "254 (100.0 %)"

    # ------------------------------------------------------ commissioning
    def commission(self, send=True):
        if not send:
            return Frame(self.t, 0.016, "ctl", None, "DALI", "preview", pdu=Pdu(bytes([0xA5, 0xFF]), []), wirefn=lambda f: dali_wire(msb(0xA5, 8) + msb(0xFF, 8)))
        if self.cm:
            return None
        self.cm = dict(lo=0, hi=0xFFFFFF, rnd=int(self.rng.integers(0, 0xFFFFFF)), step=0)
        self.by["dn"].vars["Random address"] = "0x%06X" % self.cm["rnd"]
        self.fwd(0xA5, 0xFF, "INITIALISE (devices without short address), sent twice", "ctl")
        self.at(self.t + 0.04, self.fwd, 0xA5, 0xFF, "INITIALISE (repeat within 100 ms)", "ctl")
        self.at(self.t + 0.1, self.fwd, 0xA7, 0x00, "RANDOMISE (repeat follows)", "ctl")
        self.at(self.t + 0.14, self.fwd, 0xA7, 0x00, "RANDOMISE", "ctl")
        self.at(self.t + 0.25, self.search)
        return None

    def search(self):
        c = self.cm
        if not (self.fault["new"] or self.addr_n is None):
            pass
        if c["lo"] >= c["hi"]:
            a = c["hi"]
            self.fwd(0xB1, a >> 16, "SEARCHADDRH 0x%02X" % (a >> 16), "ctl")
            self.at(self.t + 0.03, self.fwd, 0xB3, (a >> 8) & 255, "SEARCHADDRM 0x%02X" % ((a >> 8) & 255), "ctl")
            self.at(self.t + 0.06, self.fwd, 0xB5, a & 255, "SEARCHADDRL 0x%02X: found 0x%06X" % (a & 255, a), "ctl")
            self.at(self.t + 0.09, self.fwd, 0xB7, (4 << 1) | 1, "PROGRAM SHORT ADDRESS A4", "ctl")
            self.at(self.t + 0.12, self.fwd, 0xAB, 0x00, "WITHDRAW", "ctl")
            self.at(self.t + 0.15, self.fwd, 0xA1, 0x00, "TERMINATE", "ctl")
            self.at(self.t + 0.16, self._done)
            return
        mid = (c["lo"] + c["hi"]) // 2
        self.fwd(0xB1, mid >> 16, "SEARCHADDRH 0x%02X" % (mid >> 16), "ctl")
        self.at(self.t + 0.03, self.fwd, 0xB3, (mid >> 8) & 255, "SEARCHADDRM 0x%02X" % ((mid >> 8) & 255), "ctl")
        self.at(self.t + 0.06, self.fwd, 0xB5, mid & 255, "SEARCHADDRL 0x%02X" % (mid & 255), "ctl")
        present = self.fault["new"] and self.by["dn"].on
        yes = present and c["rnd"] <= mid

        def cmp_():
            self.fwd(0xA9, 0x00, "COMPARE (random address <= 0x%06X ?)" % mid, "cmd", answer_from="dn")
            if yes:
                self.at(self.t + 0.03, self.bwd, "dn", 0xFF, "YES (random address <= search address)")
        self.at(self.t + 0.09, cmp_)
        if not present:
            self.at(self.t + 0.2, self._done, False)
            return
        if yes:
            c["hi"] = mid
        else:
            c["lo"] = mid + 1
        c["step"] += 1
        self.at(self.t + 0.16, self.search)

    def _done(self, ok=True):
        if ok:
            self.addr_n = 4
            self.by["dn"].addr = "A4"
            self.by["dn"].sub = "commissioned"
            self.log("DALI: new driver found after %d COMPARE steps and given short address A4" % self.cm["step"])
        else:
            self.log("DALI: no device answered COMPARE - nothing to commission")
        self.cm = None

    def cond(self, net):
        c = Scenario.cond(self, net)
        if self.fault["psu"]:
            c["off"] = -16.0
        return c

    def on_fault(self, key, on):
        self.by["ctl"].vars["Bus"] = "0 V (no bus power)" if (key == "psu" and on) else "16.0 V"
        if key == "psu" and on:
            for i in range(4):
                self.lv[i] = 254
                self.by["d%d" % i].vars["Level"] = "system failure level (254)"

    def tpls(self):
        addr = [0x01, 0x03, 0x05, 0x07, 0x81, 0x83, 0xFF]
        an = lambda a: "broadcast" if a == 0xFF else ("G%d" % ((a >> 1) & 15) if a & 0x80 else "A%d" % (a >> 1))
        return [Tpl("Direct arc power (DAPC)", [P("a", "Address", 0xFF, opts=addr, fmt=an), P("l", "Level 0-254", 180, 0, 254)],
                    lambda s, v, send: self.set_level(v["a"], v["l"], send), "Logarithmic: 254 = 100 %, 170 = 10 %, 85 = 1 %."),
                Tpl("Query", [P("i", "Driver", 0, opts=[0, 1, 2, 3], fmt=lambda v: "A%d" % v), P("q", "Query", 144, opts=[144, 146, 160, 145], fmt=lambda v: "%d %s" % (v, DALI_CMD[v]))],
                    lambda s, v, send: self.query(v["i"], v["q"], send), "Forward frame + 8-bit backward frame (no answer = NO for yes/no queries)."),
                Tpl("Commissioning (random address search)", [], lambda s, v, send: self.commission(send),
                    "INITIALISE, RANDOMISE, binary search with SEARCHADDR + COMPARE, PROGRAM SHORT ADDRESS. Enable the 'new driver' fault first.")]


# ================================================================ DMX512
def rdm_pdu(dst, src, tn, cc, pid, data=b"", resp=False, rtype=0):
    body = bytes([0xCC, 0x01, 24 + len(data)]) + dst + src + bytes([tn, rtype if resp else 1, 0]) + b"\x00\x00" + bytes([cc]) + struct.pack(">H", pid) + bytes([len(data)]) + data
    cs = sum(body) & 0xFFFF
    b = Bld("RDM (ANSI E1.20) %s" % ("response" if resp else "request"), "Remote Device Management on the DMX line (start code 0xCC).")
    b.u8("START code", 0xCC, "0xCC RDM", "")
    b.u8("Sub-START code", 0x01, None, "")
    b.u8("Message length", body[2], None, "")
    b.raw("Destination UID", dst, "%s" % ("FFFF:FFFFFFFF (broadcast)" if dst == b"\xff" * 6 else "%04X:%08X" % struct.unpack(">HI", dst)), "Manufacturer ID + device ID.")
    b.raw("Source UID", src, "%04X:%08X" % struct.unpack(">HI", src), "")
    b.u8("Transaction number", tn, None, "")
    b.u8("Port ID / response type", body[16], ("ACK" if rtype == 0 else str(rtype)) if resp else "port 1", "")
    b.u8("Message count", 0, None, "")
    b.u16("Sub-device", 0, "0 (root)", "")
    b.u8("Command class", cc, {0x10: "DISCOVERY_COMMAND", 0x20: "GET_COMMAND", 0x21: "GET_COMMAND_RESPONSE", 0x30: "SET_COMMAND", 0x31: "SET_COMMAND_RESPONSE"}.get(cc, ""), "")
    b.u16("Parameter ID", pid, {0x0001: "DISC_UNIQUE_BRANCH", 0x0060: "DEVICE_INFO", 0x00F0: "DMX_START_ADDRESS", 0x1000: "IDENTIFY_DEVICE"}.get(pid, "0x%04X" % pid), "")
    b.u8("Parameter data length", len(data), None, "")
    if data:
        b.raw("Parameter data", data, None, "")
    b.u16("Checksum", cs, "0x%04X [correct]" % cs, "16-bit sum of all previous bytes.")
    return b.done()


FIX = [("dim", "DIMMER PACK", 1, ["Dim 1", "Dim 2", "Dim 3", "Dim 4", "Dim 5", "Dim 6"]),
       ("par", "LED PAR", 7, ["Red", "Green", "Blue", "White", "Dimmer", "Strobe", "Mode"]),
       ("mh", "MOVING HEAD", 20, ["Pan", "Pan fine", "Tilt", "Tilt fine", "Speed", "Colour", "Gobo", "Gobo rot", "Prism", "Focus", "Dimmer", "Shutter",
                                  "Zoom", "Frost", "Macro", "Reset"]),
       ("fog", "FOG MACHINE", 40, ["Fog output", "Fan"])]


class DMX512(Scenario):
    key, name, cat = "dmx512", "DMX512", "building"
    blurb = "Stage and architectural lighting"
    phy, rate = "rs485", 250000
    medium = "DMX512-A universe 1: a lighting console drives a dimmer pack, an LED PAR, a moving head and a fog machine in a daisy chain (RS-485, 250 kbit/s, 5-pin XLR)"
    nets = [("A", "Data- (pin 2)"), ("B", "Data+ (pin 3)"), ("VDIFF", "Data+ minus Data-")]
    lines = ["D", "DE"]
    faults = [("no_term1", "No terminator at the end of the chain", "Reflections corrupt random slots: fixtures flicker and jump."),
              ("overlap", "LED PAR addressed to 20 (overlaps the moving head)", "The PAR now follows the moving head's pan / tilt values as colours."),
              ("brk", "Console sends a 60 us break (minimum is 88 us)", "Some fixtures do not see the start of the packet and freeze on the last look."),
              ("cable", "Microphone cable used instead of DMX cable", "Wrong impedance (about 50 ohm instead of 120): ringing and occasional errors on long runs.")]
    spec = [("Standard", "ANSI E1.11 (DMX512-A, USITT DMX512/1990), ANSI E1.20 RDM; over IP: Art-Net, sACN (E1.31)"),
            ("Physical", "EIA-485 at 250 kbit/s, 8N2, 5-pin XLR (3-pin common), daisy chain, 120 ohm terminator at the end, max 32 unit loads"),
            ("Packet", "BREAK (>= 88 us low), mark after break (>= 8 us), START code (0 = dimmer data, 0xCC = RDM), up to 512 slots, refreshed up to ~44 times/s"),
            ("Addressing", "Each fixture uses a block of consecutive slots from its start address (DIP switch or menu, or set by RDM)"),
            ("RDM", "Bidirectional: discovery (DISC_UNIQUE_BRANCH), GET / SET parameters such as DMX_START_ADDRESS, IDENTIFY_DEVICE")]
    frame = [["DMX packet", ("BREAK >= 88 us", 22), ("MAB >= 8 us", 2), ("START 0x00", 11), ("Slot 1", 11), ("Slot 2", 11), ("...", "11 x n"), ("Slot 512", 11)]]
    about = ("DMX512 is how lighting desks talk to fixtures: a one-way stream of up to 512 one-byte levels, repeated continuously. Every fixture "
             "listens to its own block of slots - a dimmer pack one per channel, a moving head sixteen for pan, tilt, colour, gobo and so on. "
             "A packet starts with a long BREAK, so receivers can find slot 1 again at any time. RDM adds a return path for setup.")
    guide = ["SCOPE / LOGIC: the BREAK, the mark after break, the START code and the first slots at 250 kbit/s (4 us per bit).",
             "Select a packet: find the LED PAR's red, green, blue slots (start address 7).",
             "COMPOSE an RDM SET DMX_START_ADDRESS to move the PAR, or inject the address overlap fault.",
             "Remove the terminator and watch the colours flicker."]

    def build(self):
        con = self.node("con", "LIGHTING CONSOLE", "hmi", 30, 40, "universe 1", "DMX out", w=140)
        ns = []
        for i, (nid, lab, addr, chans) in enumerate(FIX):
            n = self.node(nid, lab, {"dim": "box", "par": "lamp", "mh": "lamp", "fog": "box"}[nid], 200 + 165 * i, 260, "addr %d" % addr, "%d ch" % len(chans), w=120)
            n.at_top()
            ns.append(n)
            n.vars["Start address"] = addr
        self.trunk(180, 60, 860, [con] + ns, "dmx", net="VDIFF", label="DMX cable 120 ohm, 5-pin XLR daisy chain", c="xlr", t1=True)
        self.user = "con"
        self.slots = bytearray(512)
        self.seen = {n: bytearray(512) for n, _, _, _ in FIX}
        self.addr = {n: a for n, _, a, _ in FIX}
        self.tn = 0
        self.uids = {"dim": b"\x7f\xf0\x00\x00\x10\x01", "par": b"\x7f\xf0\x00\x00\x20\x07", "mh": b"\x7f\xf0\x00\x00\x30\x14", "fog": b"\x7f\xf0\x00\x00\x40\x28"}
        con.vars.update({"Cue": "-", "Refresh": "44 Hz", "Slots sent": 512})
        self.every(0.02276 + 0.0002, self.packet, 0.01)
        self.every(0.05, self.program, 0.0)

    def program(self):
        t = self.t
        s = self.slots
        for i in range(6):
            s[i] = int(127 + 127 * math.sin(t * 1.5 + i))
        h = (t * 0.15) % 1.0
        r, g, b = [int(255 * max(0, min(1, abs((h * 6 + k) % 6 - 3) - 1))) for k in (0, 4, 2)]
        s[6:13] = bytes([r, g, b, 0, 255, 0, 0])
        pan = int(128 + 100 * math.sin(t * 0.7))
        tilt = int(90 + 40 * math.sin(t * 0.9))
        s[19:35] = bytes([pan, 0, tilt, 0, 0, int(t * 10) % 8 * 16, 0, 0, 0, 128, 255, 255, 100, 0, 0, 0])
        s[39:41] = bytes([200 if int(t / 6) % 2 else 0, 128])
        hold = getattr(self, "hold", None)
        if hold and t < hold[2]:
            s[hold[0] - 1] = hold[1]
        self.by["con"].vars["Cue"] = "colour chase %.0f%%, pan %d" % (h * 100, pan)

    def packet(self):
        data = bytes([0]) + bytes(self.slots)
        err = None
        if self.fault["no_term1"] and self.rng.random() < 0.3:
            err = "Reflections corrupted slots"
        if self.fault["cable"] and self.rng.random() < 0.1:
            err = "Impedance mismatch: bit errors"
        brk = 60e-6 if self.fault["brk"] else 176e-6
        b = Bld("DMX512-A packet, START code 0x00 (dimmer data)", "BREAK, MAB, START code, 512 slots.")
        b.u8("START code", 0, "0x00 (NULL START code: level data)", "Other codes: 0xCC RDM, 0x17 text, 0x91 manufacturer ...")
        names = {}
        for nid, lab, a0, chans in FIX:
            a = self.addr[nid]
            for k, nm in enumerate(chans):
                names.setdefault(a + k, "%s %s" % (lab.split()[0] if nid != "par" else "PAR", nm))
        for i in range(48):
            b.u8("Slot %d" % (i + 1), self.slots[i], "%d (%.0f %%)%s" % (self.slots[i], self.slots[i] / 2.55, ("  " + names[i + 1]) if (i + 1) in names else ""),
                 "Level for channel %d." % (i + 1))
        b.raw("Slots 49-512", bytes(self.slots[48:]), "464 slots (unused here)", "")
        p = b.done()
        tb = 4e-6

        def wf(f, d=data, brk=brk):
            w = Wire(bit=tb)
            w.set("D", 0.0, 1)
            w.set("DE", 0.0, 1)
            w.set("D", 8e-6, 0)
            w.seg(8e-6, 8e-6 + brk, "BREAK %.0f us" % (brk * 1e6), 7, 1)
            w.set("D", 8e-6 + brk, 1)
            w.seg(8e-6 + brk, 20e-6 + brk, "MAB", 6, 1)
            spans = w.uart("D", d[:49], 250000, 20e-6 + brk, 8, "N", 2)
            w.seg(spans[0][0], spans[0][1], "START", 3, 1)
            for k in range(1, len(spans)):
                w.seg(spans[k][0], spans[k][1], "S%d" % k, k % 2, 1)
            w.end(spans[-1][1] + 8e-6)
            return w
        fr = Frame(self.t, brk + 12e-6 + 513 * 44e-6, "con", None, "DMX512", "DMX packet: %d slots, PAR RGB %d/%d/%d, MH pan %d tilt %d" % (
            512, self.slots[6], self.slots[7], self.slots[8], self.slots[19], self.slots[21]), pdu=p, kind="data", err=err, wirefn=wf, key="DMX data")
        self.tx(fr, bus="dmx")
        for nid, _, _, chans in FIX:
            if self.fault["brk"] and nid in ("mh", "fog"):
                continue
            a = self.addr[nid]
            if err and self.rng.random() < 0.5:
                self.seen[nid][a - 1:a - 1 + len(chans)] = bytes(int(self.rng.integers(0, 256)) for _ in chans)
            else:
                self.seen[nid][:] = self.slots
        for nid, lab, _, chans in FIX:
            a = self.addr[nid]
            v = self.seen[nid][a - 1:a - 1 + len(chans)]
            self.by[nid].vars["Values"] = " ".join(str(x) for x in v[:7])

    def rdm(self, nid, cc, pid, data=b"", send=True):
        self.tn = (self.tn + 1) & 255
        ctrl_uid = b"\x7f\xf0\x00\x00\x00\x01"
        p = rdm_pdu(self.uids[nid], ctrl_uid, self.tn, cc, pid, data)
        if not send:
            return Frame(self.t, 0.002, "con", nid, "RDM", "preview", pdu=p)
        fr = Frame(self.t, 0.000176 + len(p.b) * 44e-6, "con", nid, "RDM", "RDM %s %s -> %s" % ({0x20: "GET", 0x30: "SET"}[cc], {0x0060: "DEVICE_INFO", 0x00F0: "DMX_START_ADDRESS",
                                                                                                                     0x1000: "IDENTIFY_DEVICE"}[pid], self.by[nid].label), pdu=p, kind="cmd")
        self.tx(fr, bus="dmx")
        if pid == 0x00F0 and cc == 0x30:
            new = struct.unpack(">H", data)[0]
            self.addr[nid] = new
            self.by[nid].addr = "addr %d" % new
            self.by[nid].vars["Start address"] = new
            rdata = b""
        elif pid == 0x0060:
            rdata = struct.pack(">HHHIHBBHHB", 0x0100, 0x0101, 0x0101, 0x00010000, len(dict((n, c) for n, _, _, c in FIX)[nid]), 1, 1, self.addr[nid], 0, 0)[:19]
        else:
            rdata = b""
        rp = rdm_pdu(ctrl_uid, self.uids[nid], self.tn, cc + 1, pid, rdata, resp=True)
        self.at(fr.t + fr.dur + 0.0003, lambda: self.tx(Frame(self.t, 0.000176 + len(rp.b) * 44e-6, nid, "con", "RDM", "RDM %s_RESPONSE ACK from %s" % (
            {0x20: "GET", 0x30: "SET"}[cc], self.by[nid].label), pdu=rp, kind="resp"), bus="dmx"))
        return None

    def on_fault(self, key, on):
        if key == "overlap":
            self.addr["par"] = 20 if on else 7
            self.by["par"].addr = "addr %d" % self.addr["par"]
            self.by["par"].vars["Start address"] = self.addr["par"]

    def tpls(self):
        fx = lambda v: self.by[v].label
        return [Tpl("Set channel level", [P("c", "Channel (slot)", 7, 1, 512), P("v", "Level", 255, 0, 255)], lambda s, v, send: self._lev(v, send),
                    "Overrides one slot for the next packets (the chase keeps running on the others)."),
                Tpl("RDM GET DEVICE_INFO", [P("n", "Fixture", "par", opts=[f[0] for f in FIX], fmt=fx)], lambda s, v, send: self.rdm(v["n"], 0x20, 0x0060, b"", send),
                    "Footprint, start address, personality."),
                Tpl("RDM SET DMX_START_ADDRESS", [P("n", "Fixture", "par", opts=[f[0] for f in FIX], fmt=fx), P("a", "Start address", 100, 1, 512)],
                    lambda s, v, send: self.rdm(v["n"], 0x30, 0x00F0, struct.pack(">H", v["a"]), send), "Re-address a fixture from the console - no ladder needed.")]

    def _lev(self, v, send):
        if not send:
            return Frame(self.t, 0.0228, "con", None, "DMX512", "preview", pdu=Pdu(bytes([0, v["v"]]), [[0, "DMX slot %d = %d" % (v["c"], v["v"]), 1, 1, ""]]))
        self.hold = (v["c"], v["v"], self.t + 5.0)
        return None

    def draw_extra(self, s, rect):
        def fixture_rgb(nid):
            a = self.addr[nid]
            v = self.seen[nid]
            if nid == "par":
                d = v[a + 3] / 255.0
                return tuple(int(v[a - 1 + k] * d) for k in range(3))
            if nid == "mh":
                d = v[a + 9] / 255.0
                col = [(255, 255, 255), (255, 60, 60), (60, 255, 60), (60, 60, 255), (255, 200, 40), (255, 60, 255), (60, 255, 255), (255, 140, 40)][(v[a + 4] // 16) % 8]
                return tuple(int(c * d) for c in col)
            if nid == "dim":
                k = sum(v[a - 1:a + 5]) / (6 * 255.0)
                return (int(255 * k), int(210 * k), int(150 * k))
            k = v[a - 1] / 255.0
            return (int(180 * k), int(180 * k), int(190 * k))
        for nid, _, _, _ in FIX:
            n = self.by[nid]
            col = fixture_rgb(nid)
            cx, cy = rect.x + n.x + n.w // 2, rect.y + n.y + n.h + 22
            if nid == "mh":
                pan = (self.seen["mh"][self.addr["mh"] - 1] - 128) / 128.0
                ex, ey = cx + int(60 * pan), cy + 60
                pygame.draw.line(s, col, (cx, cy), (ex, ey), 5)
            pygame.draw.circle(s, col, (int(cx), int(cy)), 9)
            pygame.draw.circle(s, (30, 30, 30), (int(cx), int(cy)), 9, 1)
