"""Simulation core shared by every protocol.

* Pdu / Bld  - bytes plus a Wireshark-style dissection tree (depth, text,
               byte offset, byte length, description).
* Wire       - the physical picture of one frame: piecewise-constant logic
               levels on one or more lines plus decode annotations. The phy
               module turns it into volts / mA / optical power.
* Frame      - one transmission: start time, duration, nodes, protocol,
               summary, lazily built Pdu and Wire.
* Node, Seg, Term - devices, cable runs and terminators of the topology.
* Scenario   - discrete-event simulation of one protocol network.
"""
import heapq
import math
import time
from collections import deque
import numpy as np
from .bits import lsb, msb, even_parity

WALL = time.time                  # wall clock used for LEDs/animation (the app swaps in pygame's)

KCOL = {   # frame kind -> analyzer colour
    "data": (150, 220, 255), "cmd": (255, 214, 120), "resp": (150, 255, 170), "ctl": (200, 170, 255),
    "err": (255, 96, 86), "ack": (140, 200, 140), "bcast": (255, 170, 230), "evt": (255, 150, 70),
    "sync": (130, 150, 170), "sec": (120, 230, 230), "mgmt": (220, 200, 140),
}
SEGC = [(255, 200, 70), (90, 220, 255), (150, 255, 120), (255, 120, 200), (200, 160, 255),
        (255, 150, 90), (120, 255, 220), (255, 255, 140), (255, 90, 90)]


# ------------------------------------------------------------- dissection
class Pdu:
    __slots__ = ("b", "rows")

    def __init__(self, b=b"", rows=None):
        self.b = bytes(b)
        self.rows = rows if rows is not None else []


class Bld:
    """Append fields and get bytes + dissection rows with offsets filled in.

    rows: [depth, text, offset, length, description]  (offset None = no bytes)
    """

    def __init__(self, layer=None, desc=""):
        self.b = bytearray()
        self.rows = []
        if layer:
            self.layer(layer, desc)

    def layer(self, name, desc=""):
        self.rows.append([0, name, len(self.b), -1, desc])
        return self

    def f(self, label, data, txt=None, desc="", d=1):
        off = len(self.b)
        self.b += bytes(data)
        if txt is None:
            txt = " ".join("%02X" % x for x in data)
        self.rows.append([d, "%s: %s" % (label, txt) if label else txt, off, len(data), desc])
        return off

    def u8(self, label, v, txt=None, desc="", d=1):
        return self.f(label, bytes([v & 0xFF]), txt if txt is not None else "%d (0x%02X)" % (v & 0xFF, v & 0xFF), desc, d)

    def u16(self, label, v, txt=None, desc="", d=1, little=False):
        b = int(v & 0xFFFF).to_bytes(2, "little" if little else "big")
        return self.f(label, b, txt if txt is not None else "%d (0x%04X)" % (v & 0xFFFF, v & 0xFFFF), desc, d)

    def u24(self, label, v, txt=None, desc="", d=1, little=False):
        b = int(v & 0xFFFFFF).to_bytes(3, "little" if little else "big")
        return self.f(label, b, txt if txt is not None else "%d (0x%06X)" % (v & 0xFFFFFF, v & 0xFFFFFF), desc, d)

    def u32(self, label, v, txt=None, desc="", d=1, little=False):
        b = int(v & 0xFFFFFFFF).to_bytes(4, "little" if little else "big")
        return self.f(label, b, txt if txt is not None else "%d (0x%08X)" % (v & 0xFFFFFFFF, v & 0xFFFFFFFF), desc, d)

    def raw(self, label, data, txt=None, desc="", d=1):
        return self.f(label, data, txt, desc, d)

    def text(self, label, s, desc="", d=1, enc="ascii"):
        data = s.encode(enc, "replace") if isinstance(s, str) else bytes(s)
        return self.f(label, data, '"%s"' % s.replace("\r", "\\r").replace("\n", "\\n") if isinstance(s, str) else None, desc, d)

    def note(self, txt, desc="", d=2, off=None, n=0):
        """Row that explains bits of bytes already added (no new bytes)."""
        self.rows.append([d, txt, off, n, desc])

    def bitf(self, off, n, width, shift, nbits, label, val_txt, desc="", d=2):
        """Wireshark style bit-field line, e.g. '..01 0... = Priority: 2'."""
        total = n * 8 if width is None else width
        v = int.from_bytes(bytes(self.b[off:off + n]), "big")
        fld = (v >> shift) & ((1 << nbits) - 1)
        mask = ["."] * total
        for i in range(nbits):
            pos = total - 1 - (shift + i)
            if 0 <= pos < total:
                mask[pos] = str((fld >> i) & 1)
        ms = "".join(mask)
        ms = " ".join(ms[i:i + 4] for i in range(0, len(ms), 4))
        self.rows.append([d, "%s = %s: %s" % (ms, label, val_txt), off, n, desc])
        return fld

    def sub(self, pdu, dd=0):
        """Append an inner PDU (its rows are shifted to the current offset)."""
        k = len(self.b)
        self.b += pdu.b
        for r in pdu.rows:
            self.rows.append([r[0] + dd, r[1], None if r[2] is None else r[2] + k,
                              r[3] if r[3] != -1 else -1, r[4]])
        return k

    def done(self):
        n = len(self.b)
        tops = [r for r in self.rows if r[3] == -1]
        for i, r in enumerate(tops):
            nxt = tops[i + 1][2] if i + 1 < len(tops) else n
            r[3] = max(0, (nxt if nxt is not None else n) - (r[2] or 0))
        return Pdu(bytes(self.b), self.rows)


def wrap(header_bld, inner, trailer=None):
    """Header builder + inner Pdu (+ trailer builder) -> Pdu."""
    b = header_bld
    b.sub(inner)
    if trailer is not None:
        b.sub(trailer.done() if isinstance(trailer, Bld) else trailer)
    return b.done()


# ---------------------------------------------------------------- the wire
class Wire:
    """Logic levels per line (relative time, seconds) plus decode boxes."""

    def __init__(self, bit=0.0):
        self.L = {}
        self.segs = []          # (t0, t1, text, colour index, row)  row 0 = bytes/bits, 1 = fields
        self.marks = []         # (t, text) small labels, e.g. stuff bits or sample points
        self.T = 0.0
        self.bit = bit
        self.ana = {}           # line -> callable(t array) for analogue lines (FSK, chirps...)

    def set(self, line, t, v):
        tl, vl = self.L.setdefault(line, ([], []))
        if vl and vl[-1] == v:
            return
        if tl and t < tl[-1]:
            t = tl[-1]
        if tl and t == tl[-1]:
            vl[-1] = v
            if len(vl) > 1 and vl[-2] == v:
                tl.pop()
                vl.pop()
        else:
            tl.append(t)
            vl.append(v)
        if t > self.T:
            self.T = t

    def end(self, t):
        if t > self.T:
            self.T = t
        return t

    def seg(self, t0, t1, txt, c=0, row=1):
        self.segs.append((t0, t1, txt, c, row))

    def nrz(self, line, bits, t, tb, hi=1, lo=0):
        for b in bits:
            self.set(line, t, hi if b else lo)
            t += tb
        return self.end(t)

    def manch(self, line, bits, t, tb, one_first=1):
        for b in bits:
            a = one_first if b else 1 - one_first
            self.set(line, t, a)
            self.set(line, t + tb / 2, 1 - a)
            t += tb
        return self.end(t)

    def uart(self, line, data, baud, t=0.0, bits=8, parity="N", stop=1, gap=0.0, ninth=None,
             labels=None, msbf=False, c=0):
        """Asynchronous characters; returns list of (t_start, t_end) per byte."""
        tb = 1.0 / baud
        if line not in self.L:
            self.set(line, 0.0, 1)
        spans = []
        for i, byte in enumerate(data):
            t0 = t
            seq = [0] + (msb(byte, bits) if msbf else lsb(byte, bits))
            if parity == "E":
                seq.append(even_parity(byte, bits))
            elif parity == "O":
                seq.append(1 - even_parity(byte, bits))
            elif parity == "M":
                seq.append(1)
            elif parity == "S":
                seq.append(0)
            elif parity == "9":
                seq.append(ninth[i] if ninth else 0)
            seq += [1] * stop
            for b in seq:
                self.set(line, t, b)
                t += tb
            spans.append((t0, t))
            lab = labels[i] if labels else "%02X" % byte
            self.seg(t0, t, lab, c, 0)
            t += gap
        self.set(line, t, 1)
        self.end(t)
        return spans

    def field_segs(self, pdu, spans, depth=1, maxn=40):
        """Field-level decode boxes from Pdu rows over per-byte time spans."""
        k = 0
        for r in pdu.rows:
            if r[0] != depth or r[2] is None or r[3] in (None, 0, -1):
                continue
            a, b = r[2], min(len(spans), r[2] + r[3]) - 1
            if a >= len(spans) or b < a:
                continue
            txt = r[1].split(":")[0] if len(r[1]) > 22 else r[1]
            self.seg(spans[a][0], spans[b][1], txt, k % len(SEGC), 1)
            k += 1
            if k >= maxn:
                break

    def at(self, line, tt):
        if line in self.ana:
            return self.ana[line](tt)
        tl, vl = self.L.get(line, ([0.0], [1]))
        if not tl:
            return np.ones_like(tt)
        idx = np.searchsorted(np.asarray(tl), tt, side="right") - 1
        v = np.asarray(vl, dtype=np.float64)
        return np.where(idx >= 0, v[np.clip(idx, 0, None)], v[0])


# ------------------------------------------------------------------ frames
class Frame:
    __slots__ = ("no", "t", "dur", "src", "dst", "proto", "info", "_pdu", "pdufn", "err", "key", "kind",
                 "wirefn", "_w", "meta", "sd", "dd", "path", "n")

    def __init__(self, t, dur, src, dst, proto, info, pdu=None, err=None, key=None, kind="data",
                 wirefn=None, meta=None, sd=None, dd=None, pdufn=None, n=None):
        self.no = 0
        self.t, self.dur, self.src, self.dst = t, dur, src, dst
        self.proto, self.info, self._pdu, self.pdufn = proto, info, pdu, pdufn
        self.err, self.key, self.kind, self.wirefn, self._w = err, key, kind, wirefn, None
        self.meta = meta if meta is not None else {}
        self.sd, self.dd, self.path, self.n = sd, dd, None, n

    @property
    def pdu(self):
        if self._pdu is None:
            self._pdu = self.pdufn(self) if self.pdufn else Pdu()
        return self._pdu

    @property
    def raw(self):
        return self.pdu.b

    @property
    def length(self):
        return self.n if self.n is not None else len(self.pdu.b)

    @property
    def wire(self):
        if self._w is None and self.wirefn:
            try:
                self._w = self.wirefn(self)
            except Exception as e:                       # never let a drawing helper kill the sim
                w = Wire()
                w.set("D", 0.0, 1)
                w.end(self.dur or 1e-3)
                w.seg(0, self.dur or 1e-3, "wire model error: %s" % e, 8, 1)
                self._w = w
        return self._w


# ---------------------------------------------------------------- topology
class Node:
    def __init__(self, nid, label, kind="box", x=0, y=0, addr="", sub="", w=118, h=52):
        self.id, self.label, self.kind = nid, label, kind
        self.x, self.y, self.w, self.h = x, y, w, h
        self.addr, self.sub = addr, sub
        self.vars = {}
        self.ctl = []               # [(var, label, lo, hi, step, fmt)]
        self.acts = []              # [(label, callable)] buttons in the DEVICE panel
        self.on = True
        self.ftx = self.frx = self.ferr = -9.0
        self.state = ""
        self.port = (x + w / 2.0, y + h)
        self.mx = self.my = 0.0     # map position (radio scenarios)
        self.extra = {}

    def at_top(self):
        self.port = (self.x + self.w / 2.0, self.y)
        return self

    def at_left(self):
        self.port = (self.x, self.y + self.h / 2.0)
        return self

    def at_right(self):
        self.port = (self.x + self.w, self.y + self.h / 2.0)
        return self

    def center(self):
        return (self.x + self.w / 2.0, self.y + self.h / 2.0)


CABLE = {   # style -> (colour, width, label)
    "rs485": ((52, 92, 170), 6), "rs232": ((150, 150, 150), 7), "can": ((225, 190, 40), 6),
    "cat5": ((60, 120, 210), 5), "cat6": ((40, 160, 210), 5), "fiber": ((240, 150, 30), 4),
    "profibus": ((150, 60, 170), 6), "profinet": ((50, 160, 80), 6), "devnet": ((90, 110, 120), 8),
    "coax": ((40, 40, 46), 7), "twinax": ((60, 60, 70), 7), "asi": ((235, 205, 40), 9),
    "tsp": ((210, 210, 210), 5), "wire": ((200, 60, 50), 3), "loop": ((40, 140, 200), 4),
    "n2k": ((50, 50, 55), 7), "pof": ((230, 60, 40), 4), "harness": ((40, 40, 40), 6),
    "ribbon": ((150, 150, 160), 9), "usb": ((50, 50, 56), 6), "knx": ((70, 160, 70), 5),
    "flat": ((235, 205, 40), 9), "gpib": ((60, 60, 68), 10), "bus": ((200, 120, 40), 5),
    "trace": ((200, 160, 60), 3), "dmx": ((120, 60, 140), 6), "t1": ((40, 160, 120), 5),
    "radio": ((80, 200, 255), 2), "lvds": ((180, 180, 190), 6), "spw": ((60, 110, 200), 6),
}


class Seg:
    def __init__(self, pts, style="rs485", label="", net=None, c0=None, c1=None, col=None, w=None, dash=False, name=""):
        self.pts = [tuple(p) for p in pts]
        self.style = style
        c, ww = CABLE.get(style, ((150, 150, 150), 5))
        self.col, self.w = col or c, w or ww
        self.label, self.net, self.c0, self.c1, self.dash, self.name = label, net, c0, c1, dash, name
        self.broken = False

    def length(self):
        return sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(self.pts, self.pts[1:]))


class Term:
    def __init__(self, x, y, label="120 \u03a9", on=True, key=None, vert=False):
        self.x, self.y, self.label, self.on, self.key, self.vert = x, y, label, on, key, vert


# ---------------------------------------------------------------- composer
class P:
    """Composer parameter. kind: int | sel | text | hex | float."""

    def __init__(self, key, label, v, lo=0, hi=255, step=1, opts=None, fmt=None, kind=None):
        self.key, self.label, self.lo, self.hi, self.step = key, label, lo, hi, step
        self.opts, self.fmt = opts, fmt
        self.kind = kind or ("sel" if opts else ("text" if isinstance(v, str) else ("float" if isinstance(v, float) else "int")))
        self.v = v if self.kind != "sel" else (opts.index(v) if v in opts else int(v) if isinstance(v, int) else 0)

    @property
    def value(self):
        return self.opts[self.v] if self.kind == "sel" else self.v

    def show(self):
        v = self.value
        if self.fmt:
            try:
                return self.fmt(v)
            except Exception:
                return str(v)
        if self.kind == "int" and self.hi > 4095:
            return "%d (0x%X)" % (v, v)
        if self.kind == "float":
            return "%.4g" % v
        return str(v)

    def bump(self, d):
        if self.kind == "sel":
            self.v = (self.v + d) % len(self.opts)
        elif self.kind in ("int", "float"):
            self.v = max(self.lo, min(self.hi, self.v + d * self.step))
            if self.kind == "int":
                self.v = int(self.v)

    def parse(self, s):
        s = s.strip()
        try:
            if self.kind == "int":
                v = int(s, 0) if s.lower().startswith(("0x", "0b", "0o")) else int(float(s))
                self.v = max(self.lo, min(self.hi, v))
            elif self.kind == "float":
                self.v = max(self.lo, min(self.hi, float(s)))
            elif self.kind == "sel":
                q = s.lower()
                num = None
                try:
                    num = int(s, 0)
                except ValueError:
                    try:
                        num = int(s, 16)
                    except ValueError:
                        pass
                for i, o in enumerate(self.opts):
                    if isinstance(o, int) and num is not None and o == num:
                        self.v = i
                        return True
                for i, o in enumerate(self.opts):
                    shown = ""
                    if self.fmt:
                        try:
                            shown = str(self.fmt(o)).lower()
                        except Exception:
                            shown = ""
                    if str(o).lower().startswith(q) or (shown and shown.startswith(q)):
                        self.v = i
                        break
            else:
                self.v = s
            return True
        except ValueError:
            return False


class Tpl:
    def __init__(self, name, params, fn, desc=""):
        self.name, self.params, self.fn, self.desc = name, params, fn, desc

    def vals(self):
        return {p.key: p.value for p in self.params}


# ---------------------------------------------------------------- scenario
class Scenario:
    key = ""
    name = ""
    cat = ""
    blurb = ""                 # 'typical application' from the syllabus
    phy = "uart"               # physical model key (see phy.py)
    rate = 9600                # nominal bit rate for the header strip
    medium = ""                # one line under the topology title
    nets = [("D", "Data")]     # probe points (net key, label)
    lines = None               # logic analyser line order (default: all wire lines)
    radio = False
    band = None                # dict(f0, f1, unit, chans=[(name, fc, bw)]) for the RF waterfall
    speed = 4                  # default time-scale index (see main.SPEEDS)
    faults = []                # [(key, label, description)]
    spec = {}
    guide = []
    about = ""
    eye_ok = False

    def __init__(self):
        self.t = 0.0
        self.q = []
        self._seq = 0
        self.cap = deque(maxlen=5000)
        self.nfr = 0
        self.nodes, self.by = [], {}
        self.segs, self.terms = [], []
        self.fault = {k: False for k, _, _ in self.faults}
        self.anim = deque(maxlen=40)
        self.free = {}
        self.keys = {}
        self.loadw = deque()
        self.nerr = 0
        self.events = deque(maxlen=60)       # text log of protocol events (shown in DEVICE / STATS)
        self.sel = None                       # selected node id
        self.user = None                      # default composer source node id
        self._paths = {}
        self.wall_speed = 1.0
        self.map_m = 1000.0                   # radio map width in metres
        self.rng = np.random.default_rng(abs(hash(self.key)) % (2 ** 31))
        self.build()
        if self.sel is None and self.nodes:
            self.sel = self.nodes[0].id

    # --------------------------------------------------------------- build
    def build(self):
        pass

    def node(self, nid, label, kind="box", x=0, y=0, addr="", sub="", w=118, h=52):
        n = Node(nid, label, kind, x, y, addr, sub, w, h)
        self.nodes.append(n)
        self.by[nid] = n
        return n

    def seg(self, pts, style="rs485", **kw):
        s = Seg(pts, style, **kw)
        self.segs.append(s)
        self._paths.clear()
        return s

    def term(self, x, y, label="120 \u03a9", on=True, key=None, vert=False):
        t = Term(x, y, label, on, key, vert)
        self.terms.append(t)
        return t

    def trunk(self, y, x0, x1, nodes, style="rs485", net=None, label="", c="screw", t0=None, t1=None,
              drop_conn=None, tlabel="120 \u03a9", tkey="term"):
        """Horizontal bus trunk with a drop to each node's port; optional
        terminators at both ends (t0/t1 = True to fit)."""
        xs = sorted(set([x0, x1] + [n.port[0] for n in nodes]))
        longest = max(range(len(xs) - 1), key=lambda i: xs[i + 1] - xs[i]) if len(xs) > 1 else 0
        for i, (a, b) in enumerate(zip(xs, xs[1:])):
            self.seg([(a, y), (b, y)], style, net=net, label=label if i == longest else "")
        for n in nodes:
            self.seg([n.port, (n.port[0], y)], style, net=net, c0=drop_conn or c)
        if t0 is not None:
            self.term(x0, y, tlabel, t0, tkey + "0")
        if t1 is not None:
            self.term(x1, y, tlabel, t1, tkey + "1")

    def p2p(self, a, b, style="rs232", net=None, label="", c0=None, c1=None, mid=None):
        pa, pb = a.port, b.port
        if mid is None:
            pts = [pa, pb] if abs(pa[1] - pb[1]) < 2 or abs(pa[0] - pb[0]) < 2 else [pa, (pa[0], (pa[1] + pb[1]) / 2), (pb[0], (pa[1] + pb[1]) / 2), pb]
        else:
            pts = [pa] + list(mid) + [pb]
        return self.seg(pts, style, net=net, label=label, c0=c0, c1=c1)

    def place(self, n, mx, my):
        """Radio map position in metres."""
        n.mx, n.my = mx, my
        return n

    # ---------------------------------------------------------- scheduling
    def at(self, t, fn, *a):
        self._seq += 1
        heapq.heappush(self.q, (t, self._seq, fn, a))

    def every(self, period, fn, phase=0.0, jitter=0.0, *a):
        def tick():
            fn(*a)
            j = (self.rng.random() - 0.5) * 2 * jitter if jitter else 0.0
            self.at(self.t + period + j, tick)
        self.at(self.t + phase, tick)

    def advance(self, t1, budget=25000):
        q = self.q
        k = 0
        while q and q[0][0] <= t1 and k < budget:
            t, _, fn, a = heapq.heappop(q)
            if t > self.t:
                self.t = t
            fn(*a)
            k += 1
        if k >= budget and q:                # cannot keep up: skip ahead
            self.t = max(self.t, t1)
        self.t = max(self.t, t1)

    def slot(self, bus, t, dur, ifs=0.0):
        s = max(t, self.free.get(bus, 0.0))
        self.free[bus] = s + dur + ifs
        return s

    def tx(self, fr, bus="bus", ifs=0.0, start=None):
        s = self.slot(bus, fr.t if start is None else start, fr.dur, ifs)
        fr.t = s
        self.at(s, self.emit, fr)
        return fr

    def emit(self, fr):
        self.nfr += 1
        fr.no = self.nfr
        self.cap.append(fr)
        w = WALL()
        src = self.by.get(fr.src)
        if src is not None:
            src.ftx = w
            if fr.err:
                src.ferr = w
        for d in self._dsts(fr):
            n = self.by.get(d)
            if n is not None and n.on:
                n.frx = w
                if fr.err:
                    n.ferr = w
        if fr.err:
            self.nerr += 1
        self.anim.append((fr, w))
        k = fr.key if fr.key is not None else fr.info.split(" ")[0]
        e = self.keys.get(k)
        if e is None:
            self.keys[k] = [1, fr.t, 0.0, fr.info, fr.t, fr.err is not None]
        else:
            dt = fr.t - e[1]
            e[2] = dt if e[0] == 1 else e[2] * 0.8 + dt * 0.2
            e[0] += 1
            e[1], e[3], e[5] = fr.t, fr.info, fr.err is not None
        self.loadw.append((fr.t, fr.dur, fr.meta.get("bus", "bus")))
        while self.loadw and self.loadw[0][0] < self.t - 1.0:
            self.loadw.popleft()
        self.at(fr.t + fr.dur + fr.meta.get("lat", 0.0), self.rx, fr)

    def rx(self, fr):
        pass

    def _dsts(self, fr):
        if fr.dst is None:
            return [n.id for n in self.nodes if n.id != fr.src]
        if isinstance(fr.dst, (list, tuple, set)):
            return list(fr.dst)
        return [fr.dst]

    def log(self, msg):
        self.events.append((self.t, msg))

    def busload(self, bus=None):
        tot = sum(d for t, d, b in self.loadw if bus is None or b == bus)
        span = 1.0 if self.t > 1.0 else max(self.t, 1e-3)
        nb = len({b for _, _, b in self.loadw}) or 1
        return min(1.0, tot / span / (1 if bus else nb))

    # ---------------------------------------------------------- per protocol
    def tpls(self):
        return []

    def inspect(self, n):
        return [(k, v) for k, v in n.vars.items()]

    def set_fault(self, key, on):
        self.fault[key] = on
        for t in self.terms:
            if t.key and ("no_" + t.key) == key:
                t.on = not on
        self.on_fault(key, on)
        self.log(("FAULT ON: " if on else "fault cleared: ") + dict((k, l) for k, l, _ in self.faults).get(key, key))

    def on_fault(self, key, on):
        pass

    def cond(self, net):
        """Analogue conditions of a probe point: dict for phy.channel()."""
        c = {"term": all(t.on for t in self.terms) if self.terms else True, "noise": 0.0, "off": 0.0}
        nterm = sum(1 for t in self.terms if t.on)
        c["nterm"] = nterm
        c["nterm_max"] = len(self.terms)
        return c

    def node_label(self, nid):
        n = self.by.get(nid)
        if n is None:
            return "*" if nid is None else str(nid)
        a = n.addr
        if a:
            parts = a.split()
            if len(parts) == 1 and (a[0].isdigit() or a.startswith("0x") or ":" in a):
                return a
            if len(parts) == 2 and parts[0] in ("SA", "NAD", "MID", "ID", "addr", "node") and (parts[1][0].isdigit() or parts[1].startswith("0x")):
                return a
        return n.label

    def src_str(self, fr):
        return fr.sd if fr.sd is not None else self.node_label(fr.src)

    def dst_str(self, fr):
        if fr.dd is not None:
            return fr.dd
        if fr.dst is None:
            return "broadcast"
        if isinstance(fr.dst, (list, tuple, set)):
            return ",".join(self.node_label(d) for d in fr.dst)
        return self.node_label(fr.dst)

    def audio(self, syn, n):
        """Default 'line monitor': as if a small speaker were clipped onto the bus. Each audio chunk
        covers the simulated time that passed since the previous one, so at real time a fast bus
        ticks once per frame and in slow motion you hear the individual bits."""
        from .audio import SR
        t1 = self.t
        t0 = getattr(self, "_aud_t", t1)
        self._aud_t = t1
        if t1 <= t0 or not self.cap:
            return None
        span = t1 - t0
        if span > 1.0:                                   # after a pause or a jump: start afresh
            return None
        ts = t0 + span * np.arange(n) / n
        out = np.zeros(n)
        built = 0
        k = 0
        for fr in reversed(self.cap):
            k += 1
            if k > 60 or fr.t + fr.dur < t0 - 0.5:
                break
            if fr.t > t1 or fr.t + fr.dur < t0:
                continue
            i0 = int(max(0, (fr.t - t0) / span * n))
            wall = fr.dur / span * n / SR                # seconds of audio this frame lasts
            if wall > 0.004 and built < 3 and fr.wirefn is not None:
                w = fr.wire
                built += 1
                if w is not None and (w.L or w.ana):
                    line = next(iter(w.ana)) if w.ana else next(iter(w.L))
                    m = (ts >= fr.t) & (ts <= fr.t + fr.dur)
                    if np.any(m):
                        v = np.asarray(w.at(line, ts[m] - fr.t), dtype=np.float64)
                        v = v - v.mean()
                        pk = np.max(np.abs(v))
                        if pk > 0:
                            v = v / pk
                        if self.radio:
                            v = np.abs(v) * self.rng.standard_normal(len(v)) * 0.6
                        out[m] += v * 0.07
                        continue
            j = np.arange(i0, min(n, i0 + int(0.003 * SR)))  # a short tick per frame
            if len(j):
                out[j] += self.rng.standard_normal(len(j)) * 0.05 * np.exp(-(j - i0) / (0.0008 * SR))
        return out if np.any(out) else None

    def draw_extra(self, s, rect):
        """Optional scenario overlay inside the topology panel."""
        pass

    def draw_stats(self, s, rect):
        """Optional scenario-specific chart in the STATS tab; return True if drawn."""
        return False

    # ----------------------------------------------------- path animation
    def path(self, a, b):
        """Polyline through the cable graph from node a's port to node b's."""
        k = (a, b)
        if k in self._paths:
            return self._paths[k]
        na, nb = self.by.get(a), self.by.get(b)
        if na is None or nb is None:
            return None
        adj = {}

        def key(p):
            return (round(p[0]), round(p[1]))
        for s in self.segs:
            if s.broken:
                continue
            p0, p1 = key(s.pts[0]), key(s.pts[-1])
            L = s.length()
            adj.setdefault(p0, []).append((p1, L, s.pts))
            adj.setdefault(p1, []).append((p0, L, list(reversed(s.pts))))
        start, goal = key(na.port), key(nb.port)
        dist, prev = {start: 0.0}, {}
        h = [(0.0, start)]
        while h:
            d, u = heapq.heappop(h)
            if u == goal:
                break
            if d > dist.get(u, 1e18):
                continue
            for v, L, pts in adj.get(u, []):
                nd = d + L
                if nd < dist.get(v, 1e18):
                    dist[v] = nd
                    prev[v] = (u, pts)
                    heapq.heappush(h, (nd, v))
        if goal not in dist:
            self._paths[k] = None
            return None
        chain = []
        u = goal
        segs = []
        while u != start:
            pu, seg = prev[u]
            segs.append(seg)
            u = pu
        for seg in reversed(segs):
            if chain and chain[-1] == seg[0]:
                chain += seg[1:]
            else:
                chain += seg
        self._paths[k] = chain
        return chain


def fmt_t(t):
    if t < 0:
        return "-"
    return "%.6f" % t


def poly_at(pts, f):
    """Point at fraction f (0..1) along a polyline."""
    if not pts:
        return None
    L = [math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(pts, pts[1:])]
    tot = sum(L)
    if tot <= 0:
        return pts[0]
    d = max(0.0, min(1.0, f)) * tot
    for (a, b), l in zip(zip(pts, pts[1:]), L):
        if d <= l and l > 0:
            k = d / l
            return (a[0] + (b[0] - a[0]) * k, a[1] + (b[1] - a[1]) * k)
        d -= l
    return pts[-1]
