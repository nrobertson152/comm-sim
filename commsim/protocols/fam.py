"""Shared protocol families: asynchronous serial, CAN / CAN FD with real
arbitration and fault confinement, Ethernet / IPv4 / IPv6 / UDP / TCP, and
radio links. Individual protocols build on these."""
import ipaddress
import math
import numpy as np
from ..engine import Bld, Pdu, Wire, Frame, SEGC
from ..bits import (msb, lsb, bytes_msb, bytes_lsb, crc_bits, crcn, stuff, inet_cs, enc4b5b, scramble100,
                    mlt3, enc8b10b, nrzi, bits_to_int)
from .. import phy

# ======================================================== async serial / UART


def serial_frame(scn, src, dst, proto, info, pdu, baud, bits=8, parity="N", stop=1, line="D", rs485=None,
                 kind="data", key=None, err=None, t=None, gap=0.0, lead=1.5, extra=None, labels=None,
                 corrupt=None, ninth=None, meta=None, sd=None, dd=None, msbf=False):
    """One message as asynchronous characters. rs485 = idle level when the
    driver is released (2 = fail-safe biased, 3 = floating, None = always driven)."""
    nb = 1 + bits + (0 if parity == "N" else 1) + stop
    n = len(pdu.b)
    tb = 1.0 / baud
    dur = n * (nb * tb + gap) + (lead + 1.0) * tb

    def wf(fr):
        w = Wire(bit=tb)
        if rs485 is not None:
            w.set(line, 0.0, rs485)
            w.set("DE", 0.0, 0)
            w.set("DE", 0.5 * tb, 1)
        else:
            w.set(line, 0.0, 1)
        w.set(line, 0.5 * tb, 1)
        data = corrupt(pdu.b) if corrupt else pdu.b
        spans = w.uart(line, data, baud, lead * tb, bits, parity, stop, gap, ninth=ninth, labels=labels, msbf=msbf)
        w.field_segs(pdu, spans)
        tend = spans[-1][1] if spans else lead * tb
        if rs485 is not None:
            w.set(line, tend + 0.5 * tb, rs485)
            w.set("DE", tend + 0.5 * tb, 0)
        w.end(tend + tb)
        if extra:
            extra(w, spans)
        return w
    return Frame(scn.t if t is None else t, dur, src, dst, proto, info, pdu=pdu, err=err, key=key, kind=kind,
                 wirefn=wf, meta=meta or {}, sd=sd, dd=dd)


def char_time(baud, bits=8, parity="N", stop=1):
    return (1 + bits + (0 if parity == "N" else 1) + stop) / float(baud)


# ======================================================================= CAN
FD_DLC = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]


def fd_code(n):
    for i, v in enumerate(FD_DLC):
        if v >= n:
            return i
    return 15


def can_layout(cid, data, ext=False, rtr=False, fd=False, brs=False, esi=False, acked=True):
    """Bit-exact CAN / CAN FD frame. Returns dict with the transmitted bit
    list [(bit, field, stuff?, phase)], CRC and field names."""
    F = [("SOF", [0], "a")]
    if ext:
        F += [("ID[28:18]", msb(cid >> 18, 11), "a"), ("SRR", [1], "a"), ("IDE", [1], "a"), ("ID[17:0]", msb(cid & 0x3FFFF, 18), "a")]
        F += [("RRS", [0], "a")] if fd else [("RTR", [1 if rtr else 0], "a")]
        if not fd:
            F += [("r1", [0], "a")]
    else:
        F += [("ID", msb(cid, 11), "a"), ("RRS" if fd else "RTR", [0 if fd else (1 if rtr else 0)], "a"), ("IDE", [0], "a")]
    if fd:
        F += [("FDF", [1], "a"), ("res", [0], "a"), ("BRS", [1 if brs else 0], "a")]
        ph = "d" if brs else "a"
        code = fd_code(len(data))
        data = bytes(data) + bytes(FD_DLC[code] - len(data))
        F += [("ESI", [1 if esi else 0], ph), ("DLC", msb(code, 4), ph), ("DATA", bytes_msb(data), ph)]
    else:
        code = min(8, len(data))
        F += [("r0" if not ext else "r0", [0], "a"), ("DLC", msb(code, 4), "a")]
        if not rtr:
            F += [("DATA", bytes_msb(data[:8]), "a")]
    out = []
    last, cnt, nst = None, 0, 0
    for fi, (name, bl, ph) in enumerate(F):
        for b in bl:
            out.append((b, fi, False, ph))
            if b == last:
                cnt += 1
            else:
                last, cnt = b, 1
            if cnt == 5:
                out.append((1 - b, fi, True, ph))
                last, cnt = 1 - b, 1
                nst += 1
    if not fd:
        raw = []
        for name, bl, ph in F:
            raw += bl
        crc = crc_bits(raw, 15, 0x4599)
        fi = len(F)
        F.append(("CRC", msb(crc, 15), "a"))
        for b in msb(crc, 15):
            out.append((b, fi, False, "a"))
            if b == last:
                cnt += 1
            else:
                last, cnt = b, 1
            if cnt == 5:
                out.append((1 - b, fi, True, "a"))
                last, cnt = 1 - b, 1
                nst += 1
        crcw = 15
    else:
        ph = "d" if brs else "a"
        sc = nst % 8
        gray = sc ^ (sc >> 1)
        scb = msb(gray, 3) + [bin(gray).count("1") & 1]
        crcw, poly = (17, 0x1685B) if len(data) <= 16 else (21, 0x102899)
        stream = [b for b, _, _, _ in out] + scb
        crc = crc_bits(stream, crcw, poly, 1 << (crcw - 1))
        fi = len(F)
        F.append(("STUFF CNT", scb, ph))
        F.append(("CRC", msb(crc, crcw), ph))
        prev = out[-1][0]
        out.append((1 - prev, fi, True, ph))
        for i, b in enumerate(scb):
            out.append((b, fi, False, ph))
        k = 0
        for b in msb(crc, crcw):
            if k % 4 == 0:
                out.append((1 - out[-1][0], fi + 1, True, ph))
            out.append((b, fi + 1, False, ph))
            k += 1
    fi = len(F)
    F += [("CRC DEL", [1], "a"), ("ACK", [0 if acked else 1], "a"), ("ACK DEL", [1], "a"), ("EOF", [1] * 7, "a")]
    for j, (name, bl, ph) in enumerate(F[fi:]):
        for b in bl:
            out.append((b, fi + j, False, ph))
    return {"bits": out, "fields": F, "crc": crc, "crcw": crcw, "data": bytes(data), "code": code, "nstuff": nst}


def can_dur(lay, rate, drate):
    ta, td = 1.0 / rate, 1.0 / (drate or rate)
    return sum(ta if ph == "a" else td for _, _, _, ph in lay["bits"])


def can_wire(lay, rate, drate=None, err_at=None, txline=True, errflag_passive=False):
    ta, td = 1.0 / rate, 1.0 / (drate or rate)
    w = Wire(bit=ta)
    t = 0.0
    w.set("B", 0.0, 1)
    w.set("T", 0.0, 1)
    fstart = {}
    k = 0
    for i, (b, fi, st, ph) in enumerate(lay["bits"]):
        tb = ta if ph == "a" else td
        if err_at is not None and i >= err_at:
            break
        w.set("B", t, b)
        w.set("T", t, b)
        if fi not in fstart:
            fstart[fi] = t
        if st:
            w.marks.append((t + tb / 2, "S"))
        name = lay["fields"][fi][0]
        if name == "DATA" and not st:
            pass
        t += tb
        k = i
    names = lay["fields"]
    ends = {}
    tt = 0.0
    for b, fi, st, ph in lay["bits"][:k + 1]:
        tt += ta if ph == "a" else td
        ends[fi] = tt
    for fi, t0 in fstart.items():
        nm = names[fi][0]
        if nm == "ID":
            lab = "ID 0x%03X" % bits_to_int(names[fi][1])
        elif nm == "ID[28:18]":
            lab = "ID hi 0x%03X" % bits_to_int(names[fi][1])
        elif nm == "ID[17:0]":
            lab = "ID lo 0x%05X" % bits_to_int(names[fi][1])
        elif nm == "DLC":
            lab = "DLC %d" % bits_to_int(names[fi][1])
        elif nm == "CRC":
            lab = "CRC 0x%X" % lay["crc"]
        elif nm == "DATA":
            lab = "DATA " + " ".join("%02X" % x for x in lay["data"][:8]) + (" ..." if len(lay["data"]) > 8 else "")
        else:
            lab = nm
        w.seg(t0, ends.get(fi, t0), lab, fi % len(SEGC), 1)
    # data bytes row
    tt, cur, bstart, nb = 0.0, [], None, 0
    for b, fi, st, ph in lay["bits"][:k + 1]:
        tb = ta if ph == "a" else td
        if names[fi][0] == "DATA" and not st:
            if bstart is None:
                bstart = tt
            cur.append(b)
            if len(cur) == 8:
                w.seg(bstart, tt + tb, "%02X" % bits_to_int(cur), nb % 2, 0)
                cur, bstart, nb = [], None, nb + 1
        tt += tb
    if err_at is not None:
        # error flag: 6 dominant (or recessive if error-passive), then 8 recessive delimiter
        lvl = 1 if errflag_passive else 0
        w.set("B", t, lvl)
        w.set("T", t, lvl)
        w.seg(t, t + 6 * ta, "ERROR FLAG", 8, 1)
        w.marks.append((t, "ERR"))
        t += 6 * ta
        w.set("B", t, 1)
        w.set("T", t, 1)
        w.seg(t, t + 8 * ta, "ERR DELIM", 8, 1)
        t += 8 * ta
    w.set("B", t, 1)
    w.set("T", t, 1)
    w.end(t + 3 * ta)
    return w


def can_pdu(cid, lay, ext, rtr, fd, brs, idrows=None, dissect=None, proto_layer=None):
    b = Bld("CAN FD" if fd else "Controller Area Network (CAN 2.0%s)" % ("B" if ext else "A"),
            "ISO 11898-1. Multi-master serial bus: the identifier is also the priority (lowest wins arbitration).")
    if ext:
        b.u32("Identifier", cid, "0x%08X (29-bit extended)" % cid,
              "29-bit extended identifier (CAN 2.0B). Lower value = higher priority on the bus.")
    else:
        b.u16("Identifier", cid, "0x%03X (11-bit standard)" % cid,
              "11-bit base identifier. Lower value = higher priority: a 0 bit (dominant) overwrites a 1 bit (recessive) during arbitration.")
    if idrows:
        idrows(b, 0)
    if fd:
        b.note("FDF = 1 (FD frame), BRS = %d (%s), ESI = 0 (error active)" % (1 if brs else 0, "data phase at the fast rate" if brs else "no bit-rate switch"),
               "FD Format bit marks a CAN FD frame. Bit Rate Switch makes the data phase run at the data bit rate.", d=1)
    else:
        b.note("RTR = %d (%s frame), IDE = %d" % (1 if rtr else 0, "remote" if rtr else "data", 1 if ext else 0),
               "Remote Transmission Request: 1 asks another node to send this identifier. IDE = 1 marks a 29-bit identifier.", d=1)
    code = lay["code"]
    n = len(lay["data"]) if not rtr else 0
    b.u8("DLC", code, "%d (%d data bytes)" % (code, FD_DLC[code] if fd else min(8, code)),
         "Data Length Code. Classical CAN: 0-8 bytes. CAN FD: codes 9-15 mean 12, 16, 20, 24, 32, 48, 64 bytes.")
    off = len(b.b)
    if n:
        b.raw("Data", lay["data"], " ".join("%02X" % x for x in lay["data"]), "Payload bytes, sent MSB first.")
    if dissect:
        dissect(b, off)
        b.rows.append([0, "CAN frame end: CRC, ACK, end of frame", len(b.b), 2 if not fd else 3, "Added by the CAN controller, not by the application"])
    if fd:
        b.u24("CRC-%d" % lay["crcw"], lay["crc"], "0x%05X" % lay["crc"], "CAN FD CRC (17 bits up to 16 data bytes, 21 bits above), covering the stuff bits and the stuff count.")
        b.note("Stuff count: %d dynamic stuff bits (mod 8, Gray coded + parity)" % lay["nstuff"], "CAN FD transmits how many stuff bits were inserted so a receiver can detect lost or added bits.", d=1)
    else:
        b.u16("CRC-15", lay["crc"], "0x%04X" % lay["crc"], "CRC-15 (x^15+x^14+x^10+x^8+x^7+x^4+x^3+1) over SOF..data. Hamming distance 6.")
        b.note("Stuff bits inserted: %d" % lay["nstuff"], "After five identical bits the transmitter inserts one of opposite polarity so receivers can resynchronise.", d=1)
    return b.done()


class CanBus:
    """Arbitration, acknowledgement and fault confinement for one CAN bus."""

    def __init__(self, scn, rate=500000, drate=None, name="bus", proto="CAN"):
        self.s, self.rate, self.drate, self.name, self.proto = scn, rate, drate, name, proto
        self.pend = []
        self._armed = False
        self._seq = 0
        self.tec, self.rec = {}, {}
        self.bad_rate = set()          # nodes configured with the wrong bit rate
        self.classic = set()           # nodes that do not understand CAN FD
        self.p_err = 0.0               # random corruption probability (signal integrity)
        self.shorted = False
        self.lost = 0

    def state(self, nid):
        tec, rec = self.tec.get(nid, 0), self.rec.get(nid, 0)
        if tec >= 256:
            return "BUS OFF"
        if tec >= 128 or rec >= 128:
            return "ERROR PASSIVE"
        return "ERROR ACTIVE"

    def send(self, src, cid, data=b"", ext=False, fd=False, brs=False, rtr=False, t=None, info=None, proto=None,
             kind="data", key=None, dst=None, dissect=None, idrows=None, meta=None, on_tx=None, layer=None, sd=None, dd=None):
        self._seq += 1
        p = dict(t=self.s.t if t is None else t, seq=self._seq, src=src, cid=cid, data=bytes(data), ext=ext, fd=fd, brs=brs,
                 rtr=rtr, info=info, proto=proto or self.proto, kind=kind, key=key, dst=dst, dissect=dissect,
                 idrows=idrows, meta=meta or {}, on_tx=on_tx, tries=0, sd=sd, dd=dd)
        self.pend.append(p)
        self._arm(p["t"])
        return p

    def _arm(self, t):
        if not self._armed:
            self._armed = True
            self.s.at(max(t, self.s.free.get(self.name, 0.0), self.s.t), self._service)

    def _arbkey(self, p):
        cid = p["cid"]
        if p["ext"]:
            return (cid >> 18, 1, cid & 0x3FFFF, p["rtr"], p["seq"])
        return (cid, 0, 0, p["rtr"], p["seq"])

    def online(self, nid):
        n = self.s.by.get(nid)
        return n is not None and n.on and self.state(nid) != "BUS OFF"

    def _service(self):
        self._armed = False
        s = self.s
        now = s.t
        free = s.free.get(self.name, 0.0)
        if now < free:
            self._arm(free)
            return
        self.pend = [p for p in self.pend if self.online(p["src"]) or p["tries"] > 200]
        ready = [p for p in self.pend if p["t"] <= now + 1e-12 and self.online(p["src"])]
        if not ready:
            if self.pend:
                self._arm(min(p["t"] for p in self.pend))
            return
        win = min(ready, key=self._arbkey)
        lost = [p for p in ready if p is not win]
        others = [n.id for n in s.nodes if n.id != win["src"] and self.online(n.id) and n.extra.get("can", True)]
        acked = bool(others) and not self.shorted
        err = None
        ftype = None
        if self.shorted:
            err, ftype = "Bit error: CAN_H shorted to CAN_L, dominant bits cannot be driven", "bit"
        elif win["src"] in self.bad_rate:
            err, ftype = "Stuff/form errors: transmitter is on the wrong bit rate", "stuff"
        elif win["fd"] and any(o in self.classic for o in others):
            err, ftype = "Form error: a classical-CAN node flags the FD frame (FDF bit)", "form"
        elif not acked:
            err, ftype = "ACK error: no other node acknowledged (alone on the bus?)", "ack"
        elif self.p_err and s.rng.random() < self.p_err:
            err, ftype = "Bit/CRC error: signal integrity (reflections / slow edges)", "crc"
        elif self.bad_rate and any(o in self.bad_rate and self.state(o) == "ERROR ACTIVE" for o in others):
            bad = [o for o in others if o in self.bad_rate and self.state(o) == "ERROR ACTIVE"][0]
            err, ftype = "Frame destroyed by error flag from %s (wrong bit rate)" % s.node_label(bad), "flag"
            self.rec[bad] = self.rec.get(bad, 0) + 8
        lay = can_layout(win["cid"], win["data"], win["ext"], win["rtr"], win["fd"], win["brs"], acked=acked)
        dur = can_dur(lay, self.rate, self.drate if win["brs"] else None)
        err_at = None
        if err:
            nb = len(lay["bits"])
            err_at = {"ack": nb - 9, "bit": 1, "stuff": min(nb - 1, 20), "form": 14, "crc": max(20, nb - 22), "flag": max(14, nb // 2)}.get(ftype, nb // 2)
            ta = 1.0 / self.rate
            dur = sum(ta if ph == "a" else 1.0 / (self.drate or self.rate) for _, _, _, ph in lay["bits"][:err_at]) + 14 * ta
        passive = self.state(win["src"]) == "ERROR PASSIVE"
        p = win
        meta = dict(p["meta"])
        meta["bus"] = self.name
        if lost:
            meta["lost"] = [q["cid"] for q in lost]
        info = p["info"] or ("ID 0x%X DLC %d" % (p["cid"], len(p["data"])))
        rate, drate = self.rate, self.drate if p["brs"] else None

        def pdufn(fr, p=p, lay=lay):
            return can_pdu(p["cid"], lay, p["ext"], p["rtr"], p["fd"], p["brs"], p["idrows"], p["dissect"])

        def wirefn(fr, lay=lay, err_at=err_at, passive=passive):
            return can_wire(lay, rate, drate, err_at, errflag_passive=passive)
        fr = Frame(now, dur, p["src"], p["dst"], p["proto"], info, err=err, key=p["key"] if p["key"] is not None else "0x%X" % p["cid"],
                   kind="err" if err else p["kind"], wirefn=wirefn, pdufn=pdufn, meta=meta,
                   n=(4 if p["ext"] else 2) + 1 + len(lay["data"]) + 2, sd=p["sd"], dd=p["dd"])
        s.emit(fr)
        s.free[self.name] = now + dur + 3.0 / self.rate
        if err:
            src = p["src"]
            if ftype in ("ack",) and passive:
                self.tec[src] = self.tec.get(src, 0)          # passive ACK errors do not raise TEC (ISO rule)
            else:
                self.tec[src] = self.tec.get(src, 0) + 8
            for o in others:
                if o not in self.bad_rate:
                    self.rec[o] = self.rec.get(o, 0) + 1
            if self.state(src) == "BUS OFF":
                s.log("%s entered BUS OFF (TEC %d)" % (s.node_label(src), self.tec[src]))
                n = s.by.get(src)
                if n is not None:
                    n.state = "BUS OFF"
                s.at(now + 128 * 11 / self.rate * 50, self._recover, src)
            p["tries"] += 1
            if p["tries"] > 300:
                self.pend.remove(p)
        else:
            self.tec[p["src"]] = max(0, self.tec.get(p["src"], 0) - 1)
            for o in others:
                self.rec[o] = max(0, self.rec.get(o, 0) - 1)
            self.pend.remove(p)
            if p["on_tx"]:
                p["on_tx"](fr)
            if lost:
                self.lost += len(lost)
        self._arm(s.free[self.name])

    def _recover(self, nid):
        if self.tec.get(nid, 0) >= 256:
            self.tec[nid] = 0
            self.rec[nid] = 0
            n = self.s.by.get(nid)
            if n is not None and n.state == "BUS OFF":
                n.state = ""
            self.s.log("%s recovered from BUS OFF (128 x 11 recessive bits)" % self.s.node_label(nid))


# ================================================================== Ethernet
ETYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q", 0x88A4: "EtherCAT", 0x8892: "PROFINET",
          0x88AB: "POWERLINK", 0x88CD: "SERCOS III", 0x890F: "CC-Link IE", 0x88B8: "IEC 61850 GOOSE",
          0x88BA: "IEC 61850 SV", 0x88F7: "PTP", 0x88CC: "LLDP", 0x22F0: "AVTP", 0x888E: "EAPOL", 0x22EA: "SRP"}


def macb(m):
    return bytes(int(x, 16) for x in m.split(":"))


def macs(b):
    return ":".join("%02x" % x for x in b)


def ipb(a):
    return ipaddress.ip_address(a).packed


def eth_pdu(dst, src, etype, inner, vlan=None, pad=True, title=None):
    b = Bld(title or "Ethernet II, Src: %s, Dst: %s" % (src, dst),
            "IEEE 802.3 MAC frame. Preamble (7 x 0x55) and SFD (0xD5) precede it on the wire; the FCS (CRC-32) follows.")
    db = macb(dst)
    bc = " (broadcast)" if dst == "ff:ff:ff:ff:ff:ff" else (" (multicast)" if db[0] & 1 else "")
    b.f("Destination", db, dst + bc, "48-bit destination MAC. Bit 0 of the first byte set = group (multicast/broadcast) address.")
    b.f("Source", macb(src), src, "48-bit source MAC: OUI (vendor, first 3 bytes) + device part.")
    if vlan is not None:
        pri, vid = vlan
        b.u16("802.1Q TPID", 0x8100, "0x8100 (VLAN tag)", "Tag Protocol Identifier: an IEEE 802.1Q VLAN tag follows.")
        b.u16("TCI", (pri << 13) | vid, "PCP %d, DEI 0, VID %d" % (pri, vid), "Priority Code Point (0-7, used for QoS / TSN traffic classes) and VLAN ID.")
    b.u16("Type", etype, "%s (0x%04X)" % (ETYPES.get(etype, "?"), etype), "EtherType: which protocol is in the payload.")
    b.sub(inner)
    n = len(b.b)
    if pad and n < 60:
        b.raw("Padding", bytes(60 - n), "%d bytes" % (60 - n), "Minimum Ethernet frame is 64 bytes including the FCS, so short payloads are padded.")
    fcs = crcn("CRC-32/ISO-HDLC", bytes(b.b))
    b.f("FCS", fcs.to_bytes(4, "little"), "0x%08X [correct]" % fcs, "Frame Check Sequence: CRC-32 over the frame. A receiver silently drops frames with a bad FCS.")
    return b.done()


def ipv4_pdu(src, dst, proto, inner, ttl=64, ident=0, df=True, tos=0, frag=0, mf=False):
    ln = 20 + len(inner.b)
    hdr = bytearray(20)
    hdr[0] = 0x45
    hdr[1] = tos
    hdr[2:4] = ln.to_bytes(2, "big")
    hdr[4:6] = (ident & 0xFFFF).to_bytes(2, "big")
    fl = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag & 0x1FFF)
    hdr[6:8] = fl.to_bytes(2, "big")
    hdr[8] = ttl
    hdr[9] = proto
    hdr[12:16] = ipb(src)
    hdr[16:20] = ipb(dst)
    cs = inet_cs(bytes(hdr))
    hdr[10:12] = cs.to_bytes(2, "big")
    pn = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 89: "OSPF"}.get(proto, str(proto))
    b = Bld("Internet Protocol Version 4, Src: %s, Dst: %s" % (src, dst), "RFC 791. Connectionless, best-effort routing of datagrams between networks.")
    b.u8("Version / IHL", 0x45, "4 / 20 bytes", "Version 4, header length 5 x 32-bit words (no options).")
    b.u8("DSCP / ECN", tos, "0x%02X" % tos, "Differentiated services code point (QoS class) and congestion notification bits.")
    b.u16("Total Length", ln, None, "Header + payload in bytes.")
    b.u16("Identification", ident, None, "Identifies the fragments of one datagram.")
    b.u16("Flags / Fragment offset", fl, "%s%s offset %d" % ("DF " if df else "", "MF " if mf else "", frag),
          "DF = don't fragment (path-MTU discovery); MF = more fragments follow.")
    b.u8("Time to Live", ttl, None, "Decremented by every router; at 0 the packet is dropped and an ICMP Time Exceeded is returned (traceroute uses this).")
    b.u8("Protocol", proto, "%s (%d)" % (pn, proto), "Payload protocol number.")
    b.u16("Header Checksum", cs, "0x%04X [correct]" % cs, "Ones-complement sum of the header (recomputed at every hop because TTL changes).")
    b.f("Source Address", ipb(src), src, "")
    b.f("Destination Address", ipb(dst), dst, "")
    b.sub(inner)
    return b.done()


def ipv6_pdu(src, dst, nh, inner, hlim=64, flow=0, tc=0):
    b = Bld("Internet Protocol Version 6, Src: %s, Dst: %s" % (src, dst), "RFC 8200. 128-bit addresses, fixed 40-byte header, no header checksum, no router fragmentation.")
    vtf = (6 << 28) | (tc << 20) | flow
    b.u32("Version / TC / Flow", vtf, "6 / 0x%02X / 0x%05X" % (tc, flow), "Version 6, traffic class (QoS) and flow label.")
    b.u16("Payload Length", len(inner.b), None, "Bytes after this 40-byte header.")
    pn = {58: "ICMPv6", 6: "TCP", 17: "UDP", 0: "Hop-by-hop"}.get(nh, str(nh))
    b.u8("Next Header", nh, "%s (%d)" % (pn, nh), "Type of the following header (extension header or payload).")
    b.u8("Hop Limit", hlim, None, "Like the IPv4 TTL.")
    b.f("Source Address", ipb(src), src, "")
    b.f("Destination Address", ipb(dst), dst, "")
    b.sub(inner)
    return b.done()


def _pseudo(src, dst, proto, ln):
    a, d = ipb(src), ipb(dst)
    if len(a) == 4:
        return a + d + bytes([0, proto]) + ln.to_bytes(2, "big")
    return a + d + ln.to_bytes(4, "big") + bytes([0, 0, 0, proto])


def udp_pdu(sport, dport, inner, src, dst, names=None):
    ln = 8 + len(inner.b)
    h = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + ln.to_bytes(2, "big") + b"\0\0"
    cs = inet_cs(_pseudo(src, dst, 17, ln) + h + inner.b) or 0xFFFF
    nm = names or {}
    b = Bld("User Datagram Protocol, Src Port: %d, Dst Port: %d" % (sport, dport), "RFC 768. Ports + length + checksum; no handshake, no retransmission, no ordering.")
    b.u16("Source Port", sport, "%d%s" % (sport, " (%s)" % nm[sport] if sport in nm else ""), "")
    b.u16("Destination Port", dport, "%d%s" % (dport, " (%s)" % nm[dport] if dport in nm else ""), "")
    b.u16("Length", ln, None, "Header (8) + data.")
    b.u16("Checksum", cs, "0x%04X [correct]" % cs, "Covers a pseudo-header of the IP addresses, the UDP header and data.")
    b.sub(inner)
    return b.done()


TCP_FLAGS = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"))


def flag_names(f):
    return ",".join(n for m, n in TCP_FLAGS if f & m) or "none"


def tcp_seg(sport, dport, seq, ack, flags, win, inner, src, dst, opts=b"", rseq=None, rack=None):
    """TCP segment with a correct checksum and a readable dissection."""
    hl = 20 + len(opts)
    hdr = bytearray(sport.to_bytes(2, "big") + dport.to_bytes(2, "big"))
    hdr += (seq & 0xFFFFFFFF).to_bytes(4, "big") + (ack & 0xFFFFFFFF).to_bytes(4, "big")
    hdr += bytes([(hl // 4) << 4, flags]) + win.to_bytes(2, "big") + bytes(4) + opts
    cs = inet_cs(_pseudo(src, dst, 6, len(hdr) + len(inner.b)) + bytes(hdr) + inner.b)
    hdr[16:18] = cs.to_bytes(2, "big")
    rs = seq if rseq is None else rseq
    ra = ack if rack is None else rack
    b = Bld("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, Len: %d"
            % (sport, dport, rs, ra, len(inner.b)),
            "RFC 9293: a reliable, ordered byte stream between two ports.")
    b.u16("Source Port", sport, None, "")
    b.u16("Destination Port", dport, None, "")
    b.u32("Sequence Number", seq, "%d (relative %d)" % (seq & 0xFFFFFFFF, rs),
          "Position of the first payload byte in the sender's byte stream. SYN and FIN each count as one.")
    b.u32("Acknowledgment Number", ack, "%d (relative %d)" % (ack & 0xFFFFFFFF, ra),
          "Next byte the sender expects from the peer: everything before it has arrived.")
    b.u8("Header Length", (hl // 4) << 4, "%d bytes" % hl, "Data offset in 32-bit words (20 bytes without options).")
    b.u8("Flags", flags, "0x%02X (%s)" % (flags, flag_names(flags)),
         "SYN opens, FIN closes, RST aborts, ACK marks the acknowledgment field valid, PSH asks for prompt delivery.")
    b.u16("Window", win, None, "Receive window: how many more bytes the sender of this segment can buffer.")
    b.u16("Checksum", cs, "0x%04X [correct]" % cs, "Covers an IP pseudo-header, the TCP header and the data.")
    b.u16("Urgent Pointer", 0, None, "")
    if opts:
        b.raw("Options", opts, "%d bytes" % len(opts), "Options such as MSS, window scale, SACK permitted and timestamps (negotiated on SYN).")
    b.sub(inner)
    return b.done()


MSS_OPTS = bytes([2, 4, 0x05, 0xB4, 4, 2, 1, 3, 3, 7])          # MSS 1460, SACK permitted, NOP, WS 7


def eth_wire(kind, data, rate, max_bytes=96):
    """Line-coded waveform of an Ethernet frame (first max_bytes shown)."""
    data = bytes(data[:max_bytes])
    pre = bytes([0x55] * 7 + [0xD5])
    w = Wire(bit=1.0 / rate)
    t = 0.0
    if kind == "eth10":                                  # Manchester, 10 Mbit/s
        tb = 1.0 / rate
        w.set("TD", 0.0, 2)
        t = 0.2e-6
        for i, byte in enumerate(pre + data):
            t0 = t
            t = w.manch("TD", lsb(byte, 8), t, tb, one_first=0)
            if i >= 8:
                w.seg(t0, t, "%02X" % byte, (i - 8) % 2, 0)
        w.seg(0.2e-6, 0.2e-6 + 64 * tb, "PREAMBLE + SFD", 7, 1)
        w.set("TD", t, 1)
        w.set("TD", t + 2 * tb, 2)
        w.end(t + 4 * tb)
        return w
    if kind == "eth100":                                 # 4B/5B + scrambler + MLT-3 at 125 Mbaud
        tb = 1.0 / 125e6
        w.bit = tb
        sym = scramble100(enc4b5b(data))
        lv = mlt3(sym)
        for v in lv:
            w.set("M", t, v)
            t += tb
        w.seg(0, 10 * tb, "J K (SSD)", 7, 1)
        for i in range(len(data)):
            a = (10 + 10 * i) * tb
            w.seg(a, a + 10 * tb, "%02X" % data[i], i % 2, 0)
        w.seg(t - 10 * tb, t, "T R (ESD)", 7, 1)
        w.end(t)
        return w
    if kind == "eth1000":                                # PAM-5 on 4 pairs at 125 Mbaud (2 shown)
        tb = 1.0 / 125e6
        w.bit = tb
        rng = np.random.default_rng(len(data))
        bits = bytes_lsb(data)
        scr = [b ^ int(rng.integers(0, 2)) for b in bits]
        for i in range(0, len(scr) - 8, 8):
            g = scr[i:i + 8]
            w.set("PA", t, (g[0] * 2 + g[1]) - 2 + (1 if g[2] else 0))
            w.set("PB", t, (g[4] * 2 + g[5]) - 2 + (1 if g[6] else 0))
            w.seg(t, t + tb, "%02X" % bits_to_int(list(reversed(g))), (i // 8) % 2, 0)
            t += tb
        w.end(t)
        return w
    if kind == "t1":                                     # 100BASE-T1: 3B2T PAM-3 at 66.67 Mbaud
        tb = 1.0 / 66.666e6
        w.bit = tb
        bits = bytes_lsb(data)
        tern = [(-1, -1), (-1, 0), (-1, 1), (0, -1), (0, 1), (1, -1), (1, 0), (1, 1)]
        for i in range(0, len(bits) - 2, 3):
            a, c = tern[bits[i] * 4 + bits[i + 1] * 2 + bits[i + 2]]
            w.set("M", t, a)
            w.set("M", t + tb, c)
            t += 2 * tb
        w.end(t)
        return w
    # fibre / 1000BASE-X: 8b/10b NRZ, /S/ start and /T/R/ end ordered sets
    tb = 1.0 / 1.25e9
    w.bit = tb
    syms, rd = enc8b10b(bytes([0xBC, 0x50]), k=(0,))
    sb, rd = enc8b10b(bytes([0xFB]) + data[8:] + bytes([0xFD, 0xF7]), k=(0, len(data) - 7, len(data) - 6), rd=rd)
    allb = syms + sb
    for i, b in enumerate(allb):
        w.set("O", t, b)
        t += tb
        if i % 10 == 9:
            k = i // 10
            lab = "K28.5" if k == 0 else ("D16.2" if k == 1 else "%02X" % (bytes([0, 0, 0xFB]) + data[8:] + bytes([0xFD, 0xF7]))[k] if k < len(data) else "")
            w.seg(t - 10 * tb, t, lab, k % 2, 0)
    w.seg(0, 20 * tb, "/I/ IDLE", 7, 1)
    w.end(t)
    return w


class Lan:
    """Switched Ethernet: each host has a MAC and IP; frames leave on the
    sender's own full-duplex link (no collisions) and are captured at a
    mirror port."""

    def __init__(self, scn, rate=100e6, phy="eth100", lat=8e-6):
        self.s, self.rate, self.phy, self.lat = scn, rate, phy, lat
        self.mac, self.ip, self.ip6 = {}, {}, {}

    def host(self, nid, mac, ip=None, ip6=None):
        self.mac[nid] = mac
        if ip:
            self.ip[nid] = ip
        if ip6:
            self.ip6[nid] = ip6
        return nid

    def frame(self, src, dst, pdu, info, proto, kind="data", key=None, err=None, t=None, lat=None, meta=None, sd=None, dd=None, n=None):
        """pdu may be a Pdu or a callable(frame) -> Pdu (built only when needed)."""
        lazy = callable(pdu)
        nb = n if lazy else len(pdu.b)
        dur = (nb + 8) * 8.0 / self.rate
        m = dict(meta or {})
        m.setdefault("lat", self.lat + dur if lat is None else lat)
        m.setdefault("bus", "link:%s" % src)
        ph, rate = self.phy, self.rate
        return Frame(self.s.t if t is None else t, dur, src, dst, proto, info, pdu=None if lazy else pdu, pdufn=pdu if lazy else None,
                     err=err, key=key, kind=kind, wirefn=lambda fr: eth_wire(ph, fr.pdu.b, rate), meta=m, sd=sd, dd=dd, n=nb)

    def send(self, fr):
        return self.s.tx(fr, bus=fr.meta.get("bus", "link:%s" % fr.src), ifs=96.0 / self.rate)

    @staticmethod
    def _flen(payload, vlan):
        return max(64, 14 + (4 if vlan is not None else 0) + payload + 4)

    def l2(self, src, dst, etype, inner, info, proto, kind="data", key=None, vlan=None, dmac=None, err=None, meta=None):
        dm = dmac or (self.mac.get(dst, "ff:ff:ff:ff:ff:ff") if dst is not None else "ff:ff:ff:ff:ff:ff")
        sm = self.mac[src]
        fr = self.frame(src, dst, lambda f: eth_pdu(dm, sm, etype, inner, vlan), info, proto, kind, key, err, meta=meta, n=self._flen(len(inner.b), vlan))
        return self.send(fr)

    def udp(self, src, dst, sport, dport, inner, info, proto, kind="data", key=None, dip=None, dmac=None, v6=False,
            ttl=64, vlan=None, err=None, meta=None, names=None):
        ident = int(self.s.rng.integers(0, 65535))
        if v6:
            sip, tip = self.ip6[src], dip or self.ip6[dst]
            dm = dmac or self.mac.get(dst, "33:33:00:00:00:01")
            fn = lambda f: eth_pdu(dm, self.mac[src], 0x86DD, ipv6_pdu(sip, tip, 17, udp_pdu(sport, dport, inner, sip, tip, names), hlim=ttl), vlan)
            n = self._flen(40 + 8 + len(inner.b), vlan)
        else:
            sip, tip = self.ip[src], dip or self.ip[dst]
            dm = dmac or self.mac.get(dst, "ff:ff:ff:ff:ff:ff")
            fn = lambda f: eth_pdu(dm, self.mac[src], 0x0800, ipv4_pdu(sip, tip, 17, udp_pdu(sport, dport, inner, sip, tip, names), ttl=ttl, ident=ident), vlan)
            n = self._flen(20 + 8 + len(inner.b), vlan)
        fr = self.frame(src, dst, fn, info, proto, kind, key, err, meta=meta, n=n)
        return self.send(fr)


class Tcp:
    """One TCP connection between two Lan hosts: handshake, data with
    sequence/acknowledgment bookkeeping, delayed ACKs and teardown."""

    def __init__(self, lan, cli, srv, cport, sport, proto="TCP", rtt=0.0004, win=64240):
        self.lan, self.s = lan, lan.s
        self.cli, self.srv = cli, srv
        self.port = {cli: cport, srv: sport}
        rng = self.s.rng
        self.isn = {cli: int(rng.integers(1, 2 ** 31)), srv: int(rng.integers(1, 2 ** 31))}
        self.nxt = dict(self.isn)
        self.rcv = {cli: 0, srv: 0}
        self.state = {cli: "CLOSED", srv: "LISTEN"}
        self.proto, self.rtt, self.win = proto, rtt, win
        self.last = {cli: -1.0, srv: -1.0}
        self.open = False

    def other(self, n):
        return self.srv if n == self.cli else self.cli

    def seg(self, frm, flags, payload=None, info=None, proto=None, kind=None, err=None):
        payload = payload or Pdu()
        to = self.other(frm)
        lan = self.lan
        v6 = not (frm in lan.ip and to in lan.ip)
        sip, dip = (lan.ip6[frm], lan.ip6[to]) if v6 else (lan.ip[frm], lan.ip[to])
        seq = self.nxt[frm]
        ack = self.rcv[frm] if flags & 0x10 else 0
        opts = MSS_OPTS if flags & 0x02 else b""
        tp = tcp_seg(self.port[frm], self.port[to], seq, ack, flags, self.win, payload, sip, dip, opts,
                     rseq=seq - self.isn[frm], rack=(ack - self.isn[to]) if flags & 0x10 else 0)
        self.nxt[frm] = seq + len(payload.b) + (1 if flags & 0x03 else 0)
        self.rcv[to] = self.nxt[frm]
        if v6:
            pdu = eth_pdu(lan.mac[to], lan.mac[frm], 0x86DD, ipv6_pdu(sip, dip, 6, tp))
        else:
            pdu = eth_pdu(lan.mac[to], lan.mac[frm], 0x0800, ipv4_pdu(sip, dip, 6, tp, ident=int(self.s.rng.integers(0, 65535))))
        if info is None:
            info = "%d → %d [%s] Seq=%d Ack=%d Win=%d Len=%d" % (self.port[frm], self.port[to], flag_names(flags),
                                                                  seq - self.isn[frm], (ack - self.isn[to]) if flags & 0x10 else 0,
                                                                  self.win, len(payload.b))
        k = kind or ("ctl" if flags & 0x07 else ("data" if payload.b else "ack"))
        fr = lan.frame(frm, to, pdu, info, proto or ("TCP" if not payload.b else self.proto), k, key="TCP %s" % flag_names(flags) if not payload.b else None, err=err)
        self.last[frm] = self.s.t
        return lan.send(fr)

    def connect(self, on_open=None):
        c, s_ = self.cli, self.srv
        self.state[c] = "SYN_SENT"
        self.seg(c, 0x02)

        def synack():
            self.state[s_] = "SYN_RECEIVED"
            self.seg(s_, 0x12)

        def ack():
            self.state[c] = self.state[s_] = "ESTABLISHED"
            self.open = True
            self.seg(c, 0x10)
            if on_open:
                on_open()
        self.s.at(self.s.t + self.rtt / 2, synack)
        self.s.at(self.s.t + self.rtt, ack)

    def send(self, frm, payload, info, proto=None, kind="data", auto_ack=True, err=None):
        fr = self.seg(frm, 0x18, payload, info, proto, kind, err=err)
        if auto_ack:
            to = self.other(frm)
            t_sent = self.s.t

            def delack():
                if self.open and self.last[to] <= t_sent:
                    self.seg(to, 0x10)
            self.s.at(self.s.t + self.rtt / 2 + 0.04, delack)
        return fr

    def close(self, frm):
        to = self.other(frm)
        self.state[frm] = "FIN_WAIT_1"
        self.seg(frm, 0x11)

        def fin2():
            self.state[to] = "LAST_ACK"
            self.seg(to, 0x11)

        def last():
            self.state[frm] = "TIME_WAIT"
            self.state[to] = "CLOSED"
            self.open = False
            self.seg(frm, 0x10)
        self.s.at(self.s.t + self.rtt / 2, fin2)
        self.s.at(self.s.t + self.rtt, last)

    def reset(self, frm):
        self.open = False
        self.state[frm] = self.state[self.other(frm)] = "CLOSED"
        return self.seg(frm, 0x14)


# ===================================================================== radio
class Radio:
    """Log-distance path loss between nodes placed on the map (metres)."""

    def __init__(self, scn, f_mhz=2440.0, ptx=0.0, sens=-95.0, n=2.6, pl0=None, noise=-100.0):
        self.s, self.f, self.ptx, self.sens, self.n, self.noise = scn, f_mhz, ptx, sens, n, noise
        self.pl0 = pl0 if pl0 is not None else 20 * math.log10(f_mhz) - 27.55     # free-space loss at 1 m
        self.extra = {}                    # (a, b) -> extra loss dB (walls, hills)
        self.jam = 0.0                     # interference raising the noise floor (dB)

    def dist(self, a, b):
        na, nb = self.s.by[a], self.s.by[b]
        return max(1.0, math.hypot(na.mx - nb.mx, na.my - nb.my))

    def rssi(self, a, b):
        na = self.s.by[a]
        p = na.extra.get("ptx", self.ptx)
        return p - (self.pl0 + 10 * self.n * math.log10(self.dist(a, b))) - self.extra.get((a, b), self.extra.get((b, a), 0.0))

    def margin(self, a, b):
        return self.rssi(a, b) - (self.s.by[b].extra.get("sens", self.sens) + self.jam)

    def ok(self, a, b, need=0.0):
        nb = self.s.by.get(b)
        if nb is None or not nb.on or not self.s.by[a].on:
            return False
        m = self.margin(a, b)
        if m >= need + 6:
            return True
        if m < need - 6:
            return False
        return self.s.rng.random() < (m - need + 6) / 12.0

    def range_for(self, nid, sens=None):
        na = self.s.by[nid]
        p = na.extra.get("ptx", self.ptx)
        s_ = (sens if sens is not None else self.sens) + self.jam
        return 10 ** ((p - s_ - self.pl0) / (10 * self.n))


def rf_frame(scn, src, dst, proto, info, pdu, dur, f, bw, kind="data", key=None, err=None, rssi=-55, wirefn=None, meta=None, t=None, sd=None, dd=None):
    m = dict(meta or {})
    m.update(f=f, bw=bw, rssi=rssi)
    return Frame(scn.t if t is None else t, dur, src, dst, proto, info, pdu=pdu, err=err, key=key, kind=kind,
                 wirefn=wirefn, meta=m, sd=sd, dd=dd)


def fsk_wire(bits, rate, dev_khz, lead=8, gauss=0.35, ana_extra=None, labels=None):
    """FSK / GFSK baseband: instantaneous frequency (kHz) and envelope."""
    tb = 1.0 / rate
    w = Wire(bit=tb)
    t = lead * tb
    w.set("D", 0.0, 0)
    for b in bits:
        w.set("D", t, 1 if b else -1)
        t += tb
    w.set("D", t, 0)
    T = t + lead * tb
    w.end(T)
    tl, vl = w.L["D"]
    lv = [v * dev_khz for v in vl]

    def freq(ts):
        return phy.rc_levels(tl, lv, ts, tb * gauss, tb * gauss)

    def env(ts):
        return ((ts >= lead * tb * 0.5) & (ts <= T - lead * tb * 0.5)).astype(float)
    w.ana["FREQ"] = freq
    w.ana["ENV"] = env

    def iq(ts, q=False):
        f = freq(ts) * 1e3
        dt = np.diff(ts, prepend=ts[0])
        ph = np.cumsum(2 * math.pi * f * dt)
        return (np.sin(ph) if q else np.cos(ph)) * env(ts)
    w.ana["I"] = lambda ts: iq(ts)
    w.ana["Q"] = lambda ts: iq(ts, True)
    if labels:
        for (a, b_, txt, c) in labels:
            w.seg(lead * tb + a * tb, lead * tb + b_ * tb, txt, c, 1)
    return w


def ppm_wire(bits, preamble=(0.0, 1.0, 3.5, 4.5), us=1e-6, pulse=0.5e-6, labels=None):
    """Mode S / ADS-B pulse-position modulation envelope (1 Mbit/s)."""
    w = Wire(bit=us)
    w.set("P", 0.0, 0)
    for p in preamble:
        w.set("P", p * us + 2e-6, 1)
        w.set("P", p * us + 2e-6 + pulse, 0)
    t = 8 * us + 2e-6
    for b in bits:
        if b:
            w.set("P", t, 1)
            w.set("P", t + pulse, 0)
        else:
            w.set("P", t + pulse, 1)
            w.set("P", t + 2 * pulse, 0)
        t += us
    w.set("P", t, 0)
    w.end(t + 2e-6)
    tl, vl = w.L["P"]
    w.ana["ENV"] = lambda ts: phy.rc_levels(tl, [float(v) for v in vl], ts, 50e-9, 80e-9)
    w.seg(2e-6, 10e-6, "PREAMBLE", 7, 1)
    if labels:
        for a, b_, txt, c in labels:
            w.seg(10e-6 + a * us, 10e-6 + b_ * us, txt, c, 1)
    return w


def chirp_wire(symbols, sf, bw_khz, preamble=8):
    """LoRa chirp spread spectrum: instantaneous frequency of each chirp."""
    ns = 2 ** sf
    ts_ = ns / (bw_khz * 1e3)
    seq = [("up", 0)] * preamble + [("up", 8), ("up", 16)] + [("down", 0)] * 2 + [("q", 0)] + [("up", s % ns) for s in symbols]
    T = 0.0
    starts = []
    for kind, v in seq:
        d = ts_ * (0.25 if kind == "q" else 1.0)
        starts.append((T, d, kind, v))
        T += d
    w = Wire(bit=ts_)
    w.set("D", 0.0, 1)
    w.end(T)

    def freq(t):
        out = np.zeros_like(t)
        for a, d, kind, v in starts:
            m = (t >= a) & (t < a + d)
            if not m.any():
                continue
            x = (t[m] - a) / ts_
            if kind == "up":
                out[m] = (((x + v / ns) % 1.0) - 0.5) * bw_khz
            else:
                out[m] = (0.5 - (x % 1.0)) * bw_khz
        return out
    w.ana["FREQ"] = freq
    w.ana["ENV"] = lambda t: ((t >= 0) & (t < T)).astype(float)
    w.seg(0, preamble * ts_, "PREAMBLE %d up-chirps" % preamble, 7, 1)
    w.seg(preamble * ts_, (preamble + 4.25) * ts_, "SYNC + SFD", 2, 1)
    w.seg((preamble + 4.25) * ts_, T, "%d data symbols (SF%d)" % (len(symbols), sf), 1, 1)
    return w


def burst_wire(dur, kind="ofdm", seed=0, label="OFDM burst"):
    """Noise-like envelope for wideband bursts (OFDM / DSSS) where the
    individual symbols are not meaningful on a scope."""
    w = Wire(bit=dur / 100.0)
    w.set("D", 0.0, 1)
    w.end(dur)
    rng = np.random.default_rng(seed)
    k = rng.standard_normal(4096)

    def env(t):
        on = (t >= 0) & (t < dur)
        idx = (np.abs(t) / dur * 4000).astype(int) % 4096
        return on * (0.7 + 0.3 * np.abs(k[idx]))
    w.ana["ENV"] = env
    w.ana["I"] = lambda t: env(t) * k[(np.abs(t) / dur * 4000 + 7).astype(int) % 4096]
    w.ana["Q"] = lambda t: env(t) * k[(np.abs(t) / dur * 4000 + 1500).astype(int) % 4096]
    w.ana["FREQ"] = lambda t: np.zeros_like(t)
    w.seg(0, dur, label, 1, 1)
    return w


# ============================================================ IP scenarios
from ..engine import Scenario as _Scenario


class IpNet(_Scenario):
    """Base for protocols carried over switched Ethernet / IP."""
    phy = "eth100"
    rate = 100e6
    nets = [("TX", "100BASE-TX pair (MLT-3)")]
    lines = ["M"]
    link_rate = 100e6

    def build(self):
        self.lan = Lan(self, self.link_rate, self.phy)
        self.setup()

    def setup(self):
        pass

    def star(self, hosts, sw=("sw", "ETHERNET SWITCH", 380, 160), style="cat6", conn="rj45"):
        """hosts: (nid, label, kind, x, y, ip, mac[, sub]). Builds a switch with
        a cable to every host and returns the switch node."""
        sid, slab, sx, sy = sw
        s = self.node(sid, slab, "switch", sx, sy, "", "managed L2", w=130, h=52)
        y_top, y_bot = sy + 16, sy + 36
        for h in hosts:
            nid, lab, kind, x, y, ip, mac = h[:7]
            sub = h[7] if len(h) > 7 else ""
            n = self.node(nid, lab, kind, x, y, ip.split("/")[0] if ip else "", sub)
            self.lan.host(nid, mac, ip if ip and ":" not in ip else None, ip if ip and ":" in ip else None)
            top = y + n.h / 2 < sy + 26
            n.port = (x + n.w / 2, y + n.h) if top else (x + n.w / 2, y)
            yy = y_top if top else y_bot
            ex = sx if n.port[0] < sx + 65 else sx + 130
            if sx <= n.port[0] <= sx + 130:
                self.seg([n.port, (n.port[0], sy if top else sy + 52)], style, net="TX", c0=conn)
                self.seg([(n.port[0], sy if top else sy + 52), (sx, yy)], style, w=1, col=(40, 40, 44))
            else:
                self.seg([n.port, (n.port[0], yy), (ex, yy)], style, net="TX", c0=conn, c1=conn)
        bp = (40, 40, 44)
        self.seg([(sx, y_top), (sx, y_bot)], style, w=1, col=bp)
        self.seg([(sx, y_bot), (sx + 130, y_bot)], style, w=1, col=bp)
        self.seg([(sx + 130, y_bot), (sx + 130, y_top)], style, w=1, col=bp)
        s.port = (sx, y_top)
        s.extra["can"] = False
        self.lan.mac[sid] = "00:1a:2b:00:00:ff"
        return s

    def tcp(self, a, b, aport, bport, proto="TCP", rtt=0.0004):
        return Tcp(self.lan, a, b, aport, bport, proto, rtt)


class RfNet(_Scenario):
    """Base for radio networks: nodes on a map (metres), log-distance path
    loss, link margins drawn on the map, frames on the RF waterfall."""
    radio = True
    phy = "rf"
    nets = [("ENV", "RF envelope"), ("FREQ", "instantaneous frequency"), ("I", "baseband I"), ("Q", "baseband Q")]
    lines = ["D"]
    f_mhz, ptx, sens, n_exp = 2440.0, 0.0, -95.0, 2.8
    map_size = 200.0

    def build(self):
        self.map_m = self.map_size
        self.radio_model = Radio(self, self.f_mhz, self.ptx, self.sens, self.n_exp)
        self.pairs = []
        self.setup()

    def setup(self):
        pass

    def range_m(self, n):
        return self.radio_model.range_for(n.id)

    def links(self):
        out = []
        for a, b in self.pairs:
            if a in self.by and b in self.by and self.by[a].on and self.by[b].on:
                out.append((a, b, int(round(self.radio_model.margin(a, b)))))
        return out

    def rnode(self, nid, label, kind, mx, my, addr="", sub="", w=104, h=40):
        n = self.node(nid, label, kind, 0, 0, addr, sub, w, h)
        self.place(n, mx, my)
        return n
