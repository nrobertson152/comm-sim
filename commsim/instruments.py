"""The instrument deck: protocol analyser, oscilloscope, logic analyser,
message-sequence (flow) view, spectrum / waterfall, frame composer and bus
statistics. All of them work from the scenario's captured Frames."""
import math
import numpy as np
import pygame
from . import ui, fx, phy, engine
from .ui import C, text, Button, Knob, Selector
from .engine import KCOL, SEGC

CH = [(255, 226, 70), (80, 220, 255), (255, 110, 220)]
TDIV = [1e-10, 2e-10, 5e-10, 1e-9, 2e-9, 5e-9, 1e-8, 2e-8, 5e-8, 1e-7, 2e-7, 5e-7, 1e-6, 2e-6, 5e-6, 1e-5, 2e-5,
        5e-5, 1e-4, 2e-4, 5e-4, 1e-3, 2e-3, 5e-3, 1e-2, 2e-2, 5e-2, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0]
VDIV = [0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0]


def fmt_s(t):
    a = abs(t)
    if a >= 1:
        return "%.3g s" % t
    if a >= 1e-3:
        return "%.3g ms" % (t * 1e3)
    if a >= 1e-6:
        return "%.3g µs" % (t * 1e6)
    if a >= 1e-9:
        return "%.3g ns" % (t * 1e9)
    return "%.3g ps" % (t * 1e12)


def fmt_v(v, unit="V"):
    a = abs(v)
    if unit in ("V", "mA", "mW", "kHz") and a < 1 and a > 0 and unit == "V":
        return "%.3g mV" % (v * 1e3)
    return "%.3g %s" % (v, unit)


def fmt_hz(f):
    if f >= 1e9:
        return "%.4g GHz" % (f / 1e9)
    if f >= 1e6:
        return "%.4g MHz" % (f / 1e6)
    if f >= 1e3:
        return "%.4g kHz" % (f / 1e3)
    return "%.4g Hz" % f


class Inst:
    name = ""
    tip = ""

    def __init__(self, bench, rect):
        self.b = bench
        self.rect = pygame.Rect(rect)
        self.widgets = []

    @property
    def scn(self):
        return self.b.scn

    def add(self, w):
        self.widgets.append(w)
        return w

    def handle(self, ev):
        for w in self.widgets:
            if w.visible and w.handle(ev):
                return True
        return self.handle2(ev)

    def handle2(self, ev):
        return False

    def tip_at(self, p):
        for w in self.widgets:
            if w.hit(p) and w.tip:
                return w.tip
        return self.tip2(p)

    def tip2(self, p):
        return ""

    def draw_widgets(self, s):
        for w in self.widgets:
            if w.visible:
                w.draw(s)

    def on_scenario(self):
        pass

    def update(self, dt):
        pass


# ================================================================ ANALYZER
class Analyzer(Inst):
    name = "ANALYZER"
    tip = "Packet list, protocol tree and hex dump of every frame on the bus (like Wireshark / a bus monitor)."
    COLS = [("No.", 54), ("Time", 100), ("Source", 112), ("Destination", 112), ("Protocol", 96), ("Len", 40), ("Info", 0)]
    RH = 15

    def __init__(self, bench, rect):
        super().__init__(bench, rect)
        r = self.rect
        self.lr = pygame.Rect(r.x, r.y, 752, r.h)
        self.tr = pygame.Rect(r.x + 760, r.y, r.w - 760, 186)
        self.dr = pygame.Rect(r.x + 760, r.y + 192, r.w - 760, 50)
        self.hr = pygame.Rect(r.x + 760, r.y + 248, r.w - 760, r.h - 248)
        self.top, self.live = 0, True
        self.ttop, self.tsel = 0, None
        self._key, self._rows = None, []
        self._fr = None

    def frames(self):
        b = self.b
        scn = b.scn
        src = b.held if b.held is not None else scn.cap
        key = (id(scn), scn.nfr if b.held is None else -len(b.held), b.filter, len(src))
        if key != self._key:
            f = b.filter.strip().lower()
            if not f:
                self._rows = list(src)
            elif f in ("err", "error", "errors"):
                self._rows = [x for x in src if x.err]
            else:
                rows = []
                for x in src:
                    hay = (x.proto + " " + x.info + " " + scn.src_str(x) + " " + scn.dst_str(x)).lower()
                    if all(tok in hay for tok in f.split()):
                        rows.append(x)
                self._rows = rows
            self._key = key
        return self._rows

    def nvis(self):
        return (self.lr.h - 24) // self.RH

    def handle2(self, ev):
        rows = self.frames()
        if ev.type == pygame.MOUSEWHEEL:
            if self.lr.collidepoint(ui.MOUSE):
                self.live = False
                self.top = max(0, min(max(0, len(rows) - self.nvis()), self.top - ev.y * 3))
                return True
            if self.tr.collidepoint(ui.MOUSE):
                self.ttop = max(0, self.ttop - ev.y * 2)
                return True
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1:
            if self.lr.collidepoint(ev.pos) and ev.pos[1] > self.lr.y + 20:
                i = self.top + (ev.pos[1] - self.lr.y - 22) // self.RH
                if 0 <= i < len(rows):
                    self.b.select(rows[i])
                    self.live = False
                    ui.sfx("blip", 0.4)
                return True
            if self.tr.collidepoint(ev.pos) and self.b.selfr is not None:
                i = self.ttop + (ev.pos[1] - self.tr.y - 6) // 14 - 1
                if 0 <= i < len(self.b.selfr.pdu.rows):
                    self.tsel = i
                return True
        return False

    def draw(self, s):
        scn = self.scn
        rows = self.frames()
        nv = self.nvis()
        if self.live:
            self.top = max(0, len(rows) - nv)
        else:
            self.top = max(0, min(self.top, max(0, len(rows) - nv)))
        r = self.lr
        ui.lcd(s, r, (5, 9, 12), (12, 30, 40), gain=0)
        x = r.x + 6
        pygame.draw.rect(s, (20, 30, 38), (r.x + 1, r.y + 1, r.w - 2, 19))
        for name, w in self.COLS:
            text(s, name, (x, r.y + 4), 11, (150, 190, 210), bold=True)
            x += w
        t0 = scn.cap[0].t if scn.cap else 0.0
        y = r.y + 22
        sel = self.b.selfr
        for fr in rows[self.top:self.top + nv]:
            if fr is sel:
                pygame.draw.rect(s, (30, 70, 120), (r.x + 2, y - 1, r.w - 14, self.RH))
            col = KCOL["err"] if fr.err else (205, 212, 218)
            kc = KCOL.get(fr.kind, col) if not fr.err else col
            x = r.x + 6
            vals = ["%d" % fr.no, "%.6f" % (fr.t), scn.src_str(fr), scn.dst_str(fr), fr.proto, "%d" % fr.length,
                    ("[%s] " % fr.err if fr.err else "") + fr.info]
            for (name, w), v in zip(self.COLS, vals):
                ww = (w or (r.right - x - 14)) - 6
                c = kc if name in ("Protocol", "Info") else col
                text(s, ui.clip_text(v, 11, ww), (x, y), 11, c)
                x += w
            y += self.RH
        ui.scrollbar(s, (r.right - 10, r.y + 22, 8, r.h - 26), self.top, nv, len(rows))
        if not rows:
            text(s, "No frames captured yet (simulation paused?)" if not scn.cap else "No frames match the filter",
                 r.center, 12, (120, 140, 150), align="m")
        self._tree(s)
        self._hex(s)

    def _tree(self, s):
        fr = self.b.selfr
        r = self.tr
        ui.lcd(s, r, (5, 9, 12), (12, 30, 40), gain=0)
        if fr is not self._fr:
            self._fr, self.tsel, self.ttop = fr, None, 0
        if fr is None:
            text(s, "Select a frame to dissect it", r.center, 12, (120, 140, 150), align="m")
            ui.lcd(s, self.dr, (5, 9, 12), gain=0)
            return
        rows = fr.pdu.rows
        lines = [(0, "Frame %d: %d bytes, %s on the wire, t = %.6f s" % (fr.no, fr.length, fmt_s(fr.dur), fr.t), None, 0, fr.err or "")] + rows
        nv = (r.h - 10) // 14
        self.ttop = max(0, min(self.ttop, max(0, len(lines) - nv)))
        y = r.y + 5
        for i, row in enumerate(lines[self.ttop:self.ttop + nv]):
            j = i + self.ttop - 1
            d, txt = row[0], row[1]
            if j == self.tsel and j >= 0:
                pygame.draw.rect(s, (30, 70, 120), (r.x + 2, y - 1, r.w - 14, 14))
            col = (240, 214, 140) if d == 0 else (205, 212, 218) if d == 1 else (160, 175, 185)
            pre = "▾ " if d == 0 else ""
            text(s, ui.clip_text(pre + txt, 11, r.w - 24 - d * 14, bold=d == 0), (r.x + 6 + d * 14, y), 11, col, bold=d == 0)
            y += 14
        ui.scrollbar(s, (r.right - 10, r.y + 4, 8, r.h - 8), self.ttop, nv, len(lines))
        dr = self.dr
        ui.lcd(s, dr, (5, 9, 12), (12, 30, 40), gain=0)
        desc = ""
        if self.tsel is not None and 0 <= self.tsel < len(rows):
            desc = rows[self.tsel][4] or rows[self.tsel][1]
        elif fr.err:
            desc = "ERROR: " + fr.err
        else:
            desc = "Click a field in the tree to see what it means and highlight its bytes."
        ui.text_block(s, desc, dr.inflate(-12, -6), 10, (220, 220, 196), lh=13, mono=False)

    def _hex(self, s):
        r = self.hr
        ui.lcd(s, r, (5, 9, 12), (12, 30, 40), gain=0)
        fr = self.b.selfr
        if fr is None:
            return
        data = fr.raw
        if not data:
            text(s, "(no byte representation - see LOGIC / SCOPE for the bits)", r.center, 11, (120, 140, 150), align="m")
            return
        hi = None
        if self.tsel is not None and 0 <= self.tsel < len(fr.pdu.rows):
            row = fr.pdu.rows[self.tsel]
            if row[2] is not None and row[3]:
                hi = (row[2], row[2] + row[3])
        nv = (r.h - 8) // 14
        first = 0
        if hi:
            first = max(0, hi[0] // 16 - 1)
        first = min(first, max(0, (len(data) + 15) // 16 - nv))
        y = r.y + 4
        cw = ui.font(11).size("0")[0]
        for ln in range(first, min(first + nv, (len(data) + 15) // 16)):
            text(s, "%04X" % (ln * 16), (r.x + 6, y), 11, (120, 150, 170))
            for i in range(16):
                k = ln * 16 + i
                if k >= len(data):
                    break
                hx = r.x + 6 + cw * (6 + i * 3 + (1 if i >= 8 else 0))
                ax = r.x + 6 + cw * (56 + i)
                on = hi and hi[0] <= k < hi[1]
                if on:
                    pygame.draw.rect(s, (40, 90, 150), (hx - 1, y - 1, cw * 2 + 2, 14))
                    pygame.draw.rect(s, (40, 90, 150), (ax, y - 1, cw, 14))
                text(s, "%02X" % data[k], (hx, y), 11, (230, 236, 240) if on else (190, 200, 206))
                ch = chr(data[k]) if 32 <= data[k] < 127 else "."
                text(s, ch, (ax, y), 11, (230, 236, 240) if on else (130, 150, 150))
            y += 14

    def tip2(self, p):
        if self.lr.collidepoint(p):
            return "Click a frame to dissect it. Wheel scrolls (stops live scrolling - press LIVE to resume). Type in FILTER to search, e.g. 'err' or an address."
        if self.tr.collidepoint(p):
            return "Protocol tree: each layer and field with its value. Click a field to see its meaning and its bytes in the hex dump."
        if self.hr.collidepoint(p):
            return "Hex dump of the frame bytes; the selected field is highlighted."
        return ""


# ================================================================== SCOPE
class Scope(Inst):
    name = "SCOPE"
    tip = "Digital storage oscilloscope with serial decode: the real voltages on the wires for the selected frame."

    def __init__(self, bench, rect):
        super().__init__(bench, rect)
        r = self.rect
        self.sr = pygame.Rect(r.x, r.y, 990, r.h)
        px = r.x + 1004
        self.net = [0, 1]
        self.b1 = self.add(Button((px, r.y + 4, 46, 26), "CH1", "Channel 1 on/off.", toggle=True, on=True, color=CH[0], size=10))
        self.b2 = self.add(Button((px, r.y + 36, 46, 26), "CH2", "Channel 2 on/off.", toggle=True, on=True, color=CH[1], size=10))
        self.bm = self.add(Button((px, r.y + 68, 46, 26), "MATH", "Math trace = CH1 - CH2 (what a differential receiver sees).", toggle=True, color=CH[2], size=9))
        for i, y in ((0, 4), (1, 36)):
            self.add(Button((px + 52, r.y + y, 24, 26), "<", "Previous probe point for this channel.", on_click=lambda b, i=i: self._net(i, -1), size=10))
            self.add(Button((px + 238, r.y + y, 24, 26), ">", "Next probe point for this channel.", on_click=lambda b, i=i: self._net(i, 1), size=10))
        self.v1 = self.add(Selector(px + 26, r.y + 146, 17, "CH1 V/DIV", [self._vlab(v) for v in VDIV], 9, "CH1 vertical sensitivity."))
        self.v2 = self.add(Selector(px + 96, r.y + 146, 17, "CH2 V/DIV", [self._vlab(v) for v in VDIV], 9, "CH2 vertical sensitivity."))
        self.td = self.add(Selector(px + 176, r.y + 146, 20, "TIME/DIV", [fmt_s(t) for t in TDIV], 14, "Horizontal sweep speed (seconds per division)."))
        self.pos = self.add(Knob(px + 262, r.y + 146, 17, "H POS", 0.0, 1.0, 0.0, "Horizontal position: slide the 10-division window through the frame."))
        self.o1 = self.add(Knob(px + 26, r.y + 232, 13, "CH1 POS", -4.0, 4.0, 2.0, "CH1 vertical position (divisions)."))
        self.o2 = self.add(Knob(px + 96, r.y + 232, 13, "CH2 POS", -4.0, 4.0, -2.0, "CH2 vertical position (divisions)."))
        self.dc = [0.0, 0.0, 0.0]
        self.bdec = self.add(Button((px + 140, r.y + 210, 58, 26), "DECODE", "Serial-decode overlay: fields and bytes drawn on the trace.", toggle=True, on=True, size=9))
        self.beye = self.add(Button((px + 204, r.y + 210, 58, 26), "EYE", "Eye diagram: every bit of the frame overlaid on 2 unit intervals. Open eye = good signal integrity.", toggle=True, size=9))
        self.btrg = self.add(Button((px + 140, r.y + 242, 122, 26), "TRIG: SELECTED", "Trigger source: the frame selected in the analyser, or LIVE = the newest frame on the bus.", on_click=self._trig, size=9))
        self.bauto = self.add(Button((px, r.y + 290, 120, 30), "AUTOSET", "Fit the frame on screen and choose sensible volts/div.", on_click=lambda b: self.autoset(), color="green", size=10))
        self.brun = self.add(Button((px + 128, r.y + 290, 134, 30), "RUN / STOP", "Freeze the displayed waveform.", toggle=True, size=10))
        self.live = False
        self._fr = None
        self._live_t = 0
        self._cache = {}
        self._eye = None
        self.v1.set(9)
        self.v2.set(9)

    @staticmethod
    def _vlab(v):
        return ("%g mV" % (v * 1000)) if v < 1 else ("%g V" % v)

    def _trig(self, b):
        self.live = not self.live
        b.label = "TRIG: LIVE" if self.live else "TRIG: SELECTED"

    def nets(self):
        scn = self.scn
        return [n for n, _ in scn.nets] or phy.nets_of(scn.phy)

    def _net(self, i, d):
        n = self.nets()
        if n:
            self.net[i] = (self.net[i] + d) % len(n)
            self._cache.clear()
            self._eye = None

    def probe(self, net, ch=0):
        n = self.nets()
        if net in n:
            self.net[ch] = n.index(net)
            self._cache.clear()
            self._eye = None

    def on_scenario(self):
        self.net = [0, 1 if len(self.nets()) > 1 else 0]
        self._cache.clear()
        self._fr = None
        self._eye = None
        self._auto_for = None

    def frame(self):
        scn = self.scn
        if self.brun.on and self._fr is not None:
            return self._fr
        if self.live:
            now = pygame.time.get_ticks()
            if now - self._live_t > 350 or self._fr is None:
                self._live_t = now
                for fr in reversed(scn.cap):
                    if fr.wirefn:
                        self._fr = fr
                        break
            return self._fr
        fr = self.b.selfr
        if fr is None or not fr.wirefn:
            for x in reversed(scn.cap):
                if x.wirefn:
                    fr = x
                    break
        self._fr = fr
        return fr

    def window(self, fr):
        tdiv = TDIV[self.td.idx]
        span = 10 * tdiv
        T = max(fr.wire.T, 1e-12)
        t0 = -0.04 * span + self.pos.val * max(0.0, T - 0.9 * span)
        return t0, span

    def autoset(self):
        fr = self.frame()
        if fr is None:
            return
        w = fr.wire
        T = max(w.T, 1e-12)
        k = 0
        while k < len(TDIV) - 1 and 10 * TDIV[k] < T * 1.04:
            k += 1
        self.td.set(k)
        self.pos.set(0.0)
        nets = self.nets()
        both = self.b1.on and self.b2.on
        ys = []
        ts = np.linspace(0, T, 1500)
        for i, (vs, os_) in enumerate(((self.v1, self.o1), (self.v2, self.o2))):
            if not nets:
                continue
            net = nets[self.net[i] % len(nets)]
            y = phy.trace(self.scn.phy, w, net, ts, self.scn.cond(net))
            ys.append(y)
            lo, hi = float(np.min(y)), float(np.max(y))
            pp = max(hi - lo, 1e-3)
            room = 3.0 if both else 6.0
            j = 0
            while j < len(VDIV) - 1 and VDIV[j] * room < pp:
                j += 1
            vs.set(j)
            self.dc[i] = (hi + lo) / 2
            os_.set((2.0 if i == 0 else -2.0) if both else 0.0)
        if len(ys) == 2:
            d = ys[0] - ys[1]
            self.dc[2] = float((d.max() + d.min()) / 2)
        self._cache.clear()
        self._eye = None
        ui.sfx("relay", 0.6)

    def _trace(self, fr, net, ts):
        key = (fr.no, id(self.scn), net, float(ts[0]), float(ts[-1]), len(ts))
        y = self._cache.get(key)
        if y is None:
            if len(self._cache) > 24:
                self._cache.clear()
            y = phy.trace(self.scn.phy, fr.wire, net, ts, self.scn.cond(net))
            self._cache[key] = y
        return y

    def draw(self, s):
        r = self.sr
        ui.crt(s, r, (2, 7, 6), (10, 40, 30), gain=110)
        gx, gy = r.x + 10, r.y + 8
        gw, gh = r.w - 20, r.h - 16
        dx, dy = gw / 10.0, gh / 8.0
        for i in range(11):
            x = gx + i * dx
            pygame.draw.line(s, (22, 52, 42) if i != 5 else (40, 80, 64), (x, gy), (x, gy + gh))
        for j in range(9):
            y = gy + j * dy
            pygame.draw.line(s, (22, 52, 42) if j != 4 else (40, 80, 64), (gx, y), (gx + gw, y))
        for i in range(51):
            x = gx + i * dx / 5
            pygame.draw.line(s, (40, 80, 64), (x, gy + gh / 2 - 3), (x, gy + gh / 2 + 3))
        fr = self.frame()
        scn = self.scn
        nets = self.nets()
        if nets:
            for i, sel in ((0, self.v1), (1, self.v2)):
                u = phy.unit_of(scn.phy, nets[self.net[i] % len(nets)])
                if getattr(sel, "_unit", "V") != u:
                    sel._unit = u
                    sel.options = [("%g m%s" % (v * 1000, u)) if (v < 1 and u in ("V", "A")) else ("%g %s" % (v, u)) for v in VDIV]
        if fr is not None and getattr(self, "_auto_for", None) != (id(scn), self.net[0], self.net[1]):
            self._auto_for = (id(scn), self.net[0], self.net[1])
            if fr.wire is not None:
                self.autoset()
        if fr is None or fr.wire is None or not nets:
            text(s, "NO SIGNAL - no captured frame with a physical layer yet", r.center, 13, (90, 200, 140), align="m")
            self._side(s, None)
            return
        if self.beye.on:
            self._draw_eye(s, fr, nets, (gx, gy, gw, gh))
            self._side(s, fr)
            return
        t0, span = self.window(fr)
        npts = int(gw) * 2
        ts = t0 + np.linspace(0, span, npts)
        vals = []
        for i, (on, vs, os_) in enumerate(((self.b1.on, self.v1, self.o1), (self.b2.on, self.v2, self.o2))):
            net = nets[self.net[i] % len(nets)]
            y = self._trace(fr, net, ts) if (on or self.bm.on) else None
            vals.append((net, y, VDIV[vs.idx], os_.val))
        clip = s.get_clip()
        s.set_clip(pygame.Rect(gx, gy, gw + 1, gh + 1))
        xs = gx + np.linspace(0, gw, npts)
        mid = gy + gh / 2
        for i, (net, y, vd, off) in enumerate(vals):
            if y is None or not (self.b1.on if i == 0 else self.b2.on):
                continue
            yy = mid - ((y - self.dc[i]) / vd + off) * dy
            yy = np.clip(yy, gy - 50, gy + gh + 50)
            pts = np.column_stack((xs, yy)).astype(int)
            pygame.draw.lines(s, tuple(int(c * 0.45) for c in CH[i]), False, pts + [1, 1], 3)
            pygame.draw.lines(s, CH[i], False, pts, 2)
            gyy = max(gy + 2, min(gy + gh - 14, mid - ((0 - self.dc[i]) / vd + off) * dy - 7))
            text(s, "%d▶" % (i + 1), (gx + 2, gyy - 7), 10, CH[i], bold=True)
        if self.bm.on and vals[0][1] is not None and vals[1][1] is not None:
            y = vals[0][1] - vals[1][1]
            vd = vals[0][2]
            yy = np.clip(mid - ((y - self.dc[2]) / vd) * dy, gy - 50, gy + gh + 50)
            pygame.draw.lines(s, CH[2], False, np.column_stack((xs, yy)).astype(int), 2)
        if self.bdec.on:
            self._decode(s, fr.wire, t0, span, gx, gy, gw, gh)
        s.set_clip(clip)
        # readouts
        u1 = phy.unit_of(scn.phy, vals[0][0])
        u2 = phy.unit_of(scn.phy, vals[1][0])
        lab = []
        if self.b1.on:
            lab.append(("CH1 %s %s/div" % (vals[0][0], self._vlab(vals[0][2]) if u1 == "V" else "%g %s" % (vals[0][2], u1)), CH[0]))
        if self.b2.on:
            lab.append(("CH2 %s %s/div" % (vals[1][0], self._vlab(vals[1][2]) if u2 == "V" else "%g %s" % (vals[1][2], u2)), CH[1]))
        if self.bm.on:
            lab.append(("MATH CH1-CH2", CH[2]))
        lab.append(("%s/div   t0 %s" % (fmt_s(span / 10), fmt_s(t0)), (200, 220, 210)))
        x = gx + 4
        for t, c in lab:
            rr = text(s, t, (x, gy + gh - 15), 11, c, bold=True)
            x = rr.right + 18
        if vals[0][1] is not None:
            y = vals[0][1]
            m = "Vmax %s  Vmin %s  Vpp %s" % (fmt_v(float(y.max()), u1), fmt_v(float(y.min()), u1), fmt_v(float(y.max() - y.min()), u1))
            if fr.wire.bit:
                m += "   bit %s (%s)" % (fmt_s(fr.wire.bit), fmt_hz(1.0 / fr.wire.bit).replace("Hz", "bit/s"))
            text(s, m, (gx + gw - 4, gy + 4), 11, CH[0], align="r")
        text(s, "#%d %s" % (fr.no, ui.clip_text(fr.info, 11, 420)), (gx + 4, gy + gh - 30), 11, (180, 230, 200))
        self._side(s, fr)

    def _decode(self, s, w, t0, span, gx, gy, gw, gh):
        def X(t):
            return gx + (t - t0) / span * gw
        for row, yb in ((1, gy + 22), (0, gy + gh - 40)):
            for (a, b, txt, c, rw) in w.segs:
                if rw != row:
                    continue
                xa, xb = X(a), X(b)
                if xb < gx or xa > gx + gw:
                    continue
                col = SEGC[c % len(SEGC)]
                rr = pygame.Rect(int(xa), yb, max(2, int(xb - xa)), 16 if row else 14)
                pygame.draw.rect(s, tuple(int(k * 0.22) for k in col), rr)
                pygame.draw.rect(s, col, rr, 1)
                if rr.w > 14:
                    text(s, ui.clip_text(txt, 10, rr.w - 4), (rr.x + 3, rr.y + 2 if row else rr.y + 1), 10, col)
        for (t, txt) in w.marks:
            x = X(t)
            if gx <= x <= gx + gw:
                pygame.draw.line(s, (255, 90, 90), (x, gy + 40), (x, gy + gh - 44), 1)
                if txt:
                    text(s, txt, (x + 2, gy + 40), 9, (255, 120, 120))

    def _draw_eye(self, s, fr, nets, g):
        gx, gy, gw, gh = g
        w = fr.wire
        ui_t = w.bit
        net = nets[self.net[0] % len(nets)]
        if not ui_t:
            text(s, "Eye diagram needs a fixed bit rate", (gx + gw / 2, gy + gh / 2), 13, (90, 200, 140), align="m")
            return
        key = (fr.no, net, VDIV[self.v1.idx], self.o1.val)
        if self._eye is None or self._eye[0] != key:
            nb = int(min(w.T / ui_t, 900))
            n = max(200, nb * 48)
            ts = np.linspace(0, nb * ui_t, n)
            y = phy.trace(self.scn.phy, w, net, ts, self.scn.cond(net))
            ph = (ts % (2 * ui_t)) / (2 * ui_t)
            surf = pygame.Surface((int(gw), int(gh)))
            surf.fill((0, 0, 0))
            vd = VDIV[self.v1.idx]
            yy = gh / 2 - ((y - self.dc[0]) / vd + self.o1.val) * (gh / 8.0)
            xs = ph * gw
            acc = np.zeros((int(gw), int(gh)))
            xi = np.clip(xs.astype(int), 0, int(gw) - 1)
            yi = np.clip(yy.astype(int), 0, int(gh) - 1)
            np.add.at(acc, (xi, yi), 1)
            acc = np.clip(np.sqrt(acc) * 60, 0, 255)
            arr = np.dstack([acc * 1.0, acc * 0.9, acc * 0.25]).astype(np.uint8)
            pygame.surfarray.blit_array(surf, arr)
            self._eye = (key, surf)
        s.blit(self._eye[1], (gx, gy), special_flags=pygame.BLEND_RGB_ADD)
        text(s, "EYE  %s  UI = %s  (2 UI across the screen)" % (net, fmt_s(ui_t)), (gx + 4, gy + 4), 11, CH[0], bold=True)

    def _side(self, s, fr):
        nets = self.nets()
        r = self.rect
        px = r.x + 1004
        labels = dict(self.scn.nets)
        for i, y in ((0, 4), (1, 36)):
            box = pygame.Rect(px + 80, r.y + y, 154, 26)
            fx.draw_well(s, box, (10, 14, 12))
            if nets:
                nm = nets[self.net[i] % len(nets)]
                text(s, ui.clip_text(nm, 11, 146), (box.x + 5, box.y + 2), 11, CH[i], bold=True)
                text(s, ui.clip_text(labels.get(nm, ""), 9, 146), (box.x + 5, box.y + 14), 9, (150, 170, 160))
        text(s, "probe: click a cable in the wiring view", (px + 56, r.y + 76), 9, (140, 150, 150))
        self.draw_widgets(s)

    def tip2(self, p):
        if self.sr.collidepoint(p):
            return "Oscilloscope screen. Probe points are chosen with the < > buttons or by clicking a cable in the wiring view. Faults such as missing terminators show up here as ringing and slow edges."
        return ""


# ================================================================== LOGIC
class Logic(Inst):
    name = "LOGIC"
    tip = "Logic analyser: the frame's digital lines with bit-level and field-level decode."

    def __init__(self, bench, rect):
        super().__init__(bench, rect)
        r = self.rect
        self.sr = pygame.Rect(r.x, r.y, r.w - 150, r.h)
        px = r.right - 140
        self.zoom = self.add(Selector(px + 34, r.y + 50, 20, "ZOOM", ["x%d" % z for z in (1, 2, 4, 8, 16, 32, 64, 128, 256)], 0, "Horizontal zoom into the frame."))
        self.pos = self.add(Knob(px + 104, r.y + 50, 17, "POS", 0.0, 1.0, 0.0, "Scroll through the frame."))
        self.bbits = self.add(Button((px, r.y + 120, 130, 28), "BIT VALUES", "Label every bit with its value when zoomed in.", toggle=True, on=True, size=10))
        self.bmark = self.add(Button((px, r.y + 156, 130, 28), "MARKERS", "Show markers: stuff bits, sample points, protocol events.", toggle=True, on=True, size=10))
        self.bfit = self.add(Button((px, r.y + 192, 130, 28), "FIT", "Show the whole frame.", on_click=lambda b: (self.zoom.set(0), self.pos.set(0)), size=10))

    def draw(self, s):
        r = self.sr
        ui.lcd(s, r, (4, 8, 8), (10, 30, 30), gain=40)
        fr = self.b.selfr
        if fr is None or fr.wire is None:
            for x in reversed(self.scn.cap):
                if x.wirefn:
                    fr = x
                    break
        if fr is None or fr.wire is None:
            text(s, "Select a frame in the analyser", r.center, 13, (120, 160, 150), align="m")
            self.draw_widgets(s)
            return
        w = fr.wire
        lines = [ln for ln in (self.scn.lines or sorted(w.L.keys())) if ln in w.L or ln in w.ana]
        z = (1, 2, 4, 8, 16, 32, 64, 128, 256)[self.zoom.idx]
        T = max(w.T, 1e-12)
        span = T * 1.04 / z
        t0 = -T * 0.02 + self.pos.val * max(0, T * 1.04 - span)
        gx, gy, gw = r.x + 70, r.y + 50, r.w - 84
        lh = max(18, min(44, (r.h - 74) // max(1, len(lines))))

        def X(t):
            return gx + (t - t0) / span * gw
        clip = s.get_clip()
        # decode rows
        s.set_clip(pygame.Rect(gx, r.y, gw, r.h))
        for row, yb in ((1, r.y + 8), (0, r.y + 28)):
            for (a, b, txt, c, rw) in w.segs:
                if rw != row:
                    continue
                xa, xb = X(a), X(b)
                if xb < gx or xa > gx + gw:
                    continue
                col = SEGC[c % len(SEGC)]
                rr = pygame.Rect(int(xa), yb, max(2, int(xb - xa)), 17)
                pygame.draw.rect(s, tuple(int(k * 0.22) for k in col), rr)
                pygame.draw.rect(s, col, rr, 1)
                if rr.w > 14:
                    text(s, ui.clip_text(txt, 10, rr.w - 4), (rr.x + 3, rr.y + 3), 10, col)
        s.set_clip(clip)
        for k, ln in enumerate(lines):
            y0 = gy + k * lh
            text(s, ui.clip_text(ln, 10, 62), (r.x + 6, y0 + lh // 2 - 6), 10, (170, 220, 200), bold=True)
            pygame.draw.line(s, (20, 40, 40), (gx, y0 + lh - 2), (gx + gw, y0 + lh - 2))
            s.set_clip(pygame.Rect(gx, y0, gw, lh))
            if ln in w.ana:
                ts = t0 + np.linspace(0, span, int(gw))
                y = w.ana[ln](ts)
                m = max(1e-9, float(np.max(np.abs(y))))
                yy = y0 + lh / 2 - y / m * (lh / 2 - 4)
                pygame.draw.lines(s, (120, 255, 170), False, np.column_stack((np.linspace(gx, gx + gw, len(ts)), yy)).astype(int), 1)
            else:
                tl, vl = w.L[ln]
                lo, hi = min(vl), max(vl)
                if hi == lo:
                    hi = lo + 1

                def Y(v):
                    return y0 + lh - 5 - (v - lo) / (hi - lo) * (lh - 10)
                pts = []
                prev = vl[0]
                pts.append((gx, Y(prev)))
                for t, v in zip(tl, vl):
                    x = X(t)
                    if x < gx:
                        prev = v
                        pts[0] = (gx, Y(v))
                        continue
                    if x > gx + gw:
                        break
                    pts.append((x, Y(prev)))
                    pts.append((x, Y(v)))
                    prev = v
                pts.append((gx + gw, Y(prev)))
                if len(pts) > 1:
                    pygame.draw.lines(s, (120, 255, 170), False, [(int(a), int(b)) for a, b in pts], 2)
                if self.bbits.on and w.bit and span / w.bit < 70 and len(vl) < 20000:
                    tb = w.bit
                    tt = max(0.0, t0 - (t0 % tb))
                    arr_t = np.asarray(tl)
                    while tt < t0 + span and tt < T:
                        i = int(np.searchsorted(arr_t, tt + tb / 2, side="right")) - 1
                        if i >= 0:
                            v = vl[i]
                            text(s, "%d" % v if isinstance(v, int) else "%g" % v, (X(tt + tb / 2), y0 + 1), 9, (90, 150, 130), align="c")
                        tt += tb
            s.set_clip(clip)
        if self.bmark.on:
            s.set_clip(pygame.Rect(gx, gy, gw, len(lines) * lh))
            for (t, txt) in w.marks:
                x = X(t)
                if gx <= x <= gx + gw:
                    pygame.draw.line(s, (255, 90, 90), (x, gy), (x, gy + len(lines) * lh), 1)
                    if txt and span / max(w.bit, 1e-12) < 200:
                        text(s, txt, (x + 2, gy + 1), 9, (255, 120, 120))
            s.set_clip(clip)
        # time axis
        ya = r.bottom - 16
        for i in range(11):
            x = gx + gw * i / 10
            pygame.draw.line(s, (40, 70, 70), (x, ya - 4), (x, ya))
            if i % 2 == 0:
                text(s, fmt_s(t0 + span * i / 10), (x, ya), 9, (120, 160, 150), align="c")
        text(s, "#%d %s   frame %s" % (fr.no, ui.clip_text(fr.info, 10, 500), fmt_s(T)), (r.x + 8, r.bottom - 32), 10, (180, 220, 200))
        self.draw_widgets(s)


# =================================================================== FLOW
class Flow(Inst):
    name = "FLOW"
    tip = "Message sequence chart: who sends what to whom, in order (request / response, handshakes)."
    RH = 21

    def __init__(self, bench, rect):
        super().__init__(bench, rect)
        self.top, self.live = 0, True
        self.blive = self.add(Button((self.rect.right - 92, self.rect.y + 4, 86, 24), "LIVE", "Follow the newest messages.", toggle=True, on=True, size=10))

    def handle2(self, ev):
        if ev.type == pygame.MOUSEWHEEL and self.rect.collidepoint(ui.MOUSE):
            self.blive.on = False
            self.top = max(0, self.top - ev.y * 2)
            return True
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1 and self.rect.collidepoint(ev.pos):
            i = (ev.pos[1] - self.rect.y - 44) // self.RH
            fr = self._rows[i] if 0 <= i < len(getattr(self, "_rows", [])) else None
            if fr is not None:
                self.b.select(fr)
                self.blive.on = False
                return True
        return False

    def draw(self, s):
        r = self.rect
        ui.lcd(s, r, (6, 8, 12), (14, 20, 36), gain=0)
        scn = self.scn
        cap = list(scn.cap)[-600:] if self.b.held is None else list(self.b.held)[-600:]
        if self.b.filter.strip():
            f = self.b.filter.strip().lower()
            cap = [x for x in cap if f in (x.proto + " " + x.info).lower() or (f in ("err", "errors") and x.err)]
        cnt = {}
        for fr in cap:
            for n in [fr.src] + (scn._dsts(fr) if fr.dst is not None and not isinstance(fr.dst, (list, tuple)) else []):
                cnt[n] = cnt.get(n, 0) + 1
        order = [n.id for n in scn.nodes if n.id in cnt]
        if len(order) > 9:
            keep = set(sorted(order, key=lambda k: -cnt[k])[:9])
            order = [k for k in order if k in keep]
        nv = (r.h - 48) // self.RH
        if self.blive.on:
            self.top = max(0, len(cap) - nv)
        self.top = min(self.top, max(0, len(cap) - nv))
        rows = cap[self.top:self.top + nv]
        self._rows = rows
        if not order:
            text(s, "No traffic yet", r.center, 13, (120, 140, 160), align="m")
            self.draw_widgets(s)
            return
        x0, x1 = r.x + 110, r.right - 110
        xs = {}
        for i, nid in enumerate(order):
            xs[nid] = x0 + (x1 - x0) * (i / max(1, len(order) - 1)) if len(order) > 1 else (x0 + x1) / 2
        for nid, x in xs.items():
            box = pygame.Rect(0, 0, 104, 22)
            box.center = (x, r.y + 18)
            pygame.draw.rect(s, (30, 40, 56), box, border_radius=4)
            pygame.draw.rect(s, (90, 120, 160), box, 1, border_radius=4)
            text(s, ui.clip_text(scn.node_label(nid), 10, 98), box.center, 10, (210, 220, 235), bold=True, align="m")
            for y in range(r.y + 32, r.bottom - 4, 8):
                pygame.draw.line(s, (40, 52, 70), (x, y), (x, y + 4))
        y = r.y + 44
        sel = self.b.selfr
        for fr in rows:
            col = KCOL["err"] if fr.err else KCOL.get(fr.kind, (200, 200, 200))
            if fr is sel:
                pygame.draw.rect(s, (30, 60, 100), (r.x + 2, y - 2, r.w - 4, self.RH - 1))
            text(s, "%.6f" % fr.t, (r.x + 6, y + 2), 10, (120, 140, 160))
            xa = xs.get(fr.src)
            if xa is None:
                y += self.RH
                continue
            dsts = scn._dsts(fr)
            bc = fr.dst is None or len(dsts) > 1
            if bc:
                targets = [xs[d] for d in dsts if d in xs]
                lo, hi = min(targets + [xa]), max(targets + [xa])
                pygame.draw.line(s, col, (lo, y + 10), (hi, y + 10), 1)
                for tx in targets:
                    pygame.draw.circle(s, col, (int(tx), y + 10), 3)
                pygame.draw.circle(s, col, (int(xa), y + 10), 4, 1)
                lx = (lo + hi) / 2
            else:
                xb = xs.get(dsts[0]) if dsts else None
                if xb is None:
                    xb = xa + 40
                pygame.draw.line(s, col, (xa, y + 10), (xb, y + 10), 2)
                sgn = 1 if xb >= xa else -1
                pygame.draw.polygon(s, col, [(xb, y + 10), (xb - 8 * sgn, y + 6), (xb - 8 * sgn, y + 14)])
                lx = (xa + xb) / 2
            lab = ui.clip_text(("[%s] " % fr.err if fr.err else "") + fr.info, 10, 360)
            tr = text(s, lab, (lx, y - 2), 10, col, align="c")
            del tr
            y += self.RH
        self.draw_widgets(s)


# =============================================================== SPECTRUM
class Spectrum(Inst):
    name = "SPECTRUM"
    tip = "RF: spectrum and waterfall of the band. Wired: FFT of the probed waveform (why line codes look the way they do)."

    def __init__(self, bench, rect):
        super().__init__(bench, rect)
        r = self.rect
        self.span = self.add(Selector(r.right - 70, r.y + 54, 20, "WATERFALL", ["50 ms", "0.2 s", "1 s", "5 s", "20 s", "60 s", "5 min"], 2, "Waterfall time span (RF) - how much history scrolls down the screen."))
        self._wf = None
        self._fft = None

    SPANS = [0.05, 0.2, 1.0, 5.0, 20.0, 60.0, 300.0]

    def draw(self, s):
        r = pygame.Rect(self.rect.x, self.rect.y, self.rect.w - 150, self.rect.h)
        ui.crt(s, r, (2, 4, 10), (10, 20, 50), gain=90)
        scn = self.scn
        if scn.band:
            self._rf(s, r, scn)
        else:
            self._bb(s, r, scn)
        self.draw_widgets(s)

    def _rf(self, s, r, scn):
        b = scn.band
        f0, f1 = b["f0"], b["f1"]
        unit = b.get("unit", "MHz")
        gx, gw = r.x + 50, r.w - 64
        sp_y, sp_h = r.y + 10, 96
        wf_y, wf_h = r.y + 128, r.h - 152

        def X(f):
            return gx + (f - f0) / (f1 - f0) * gw
        for name, fc, bw in b.get("chans", []):
            xa, xb = X(fc - bw / 2), X(fc + bw / 2)
            pygame.draw.rect(s, (14, 22, 40), (xa, wf_y, max(1, xb - xa), wf_h))
            text(s, name, ((xa + xb) / 2, r.y + 110), 9, (120, 150, 200), align="c")
        now = scn.t
        span = self.SPANS[self.span.idx]
        # spectrum trace
        nb = int(gw)
        fq = f0 + (f1 - f0) * np.arange(nb) / nb
        p = -102 + 2.5 * np.random.default_rng(int(now * 50) % 100000).standard_normal(nb)
        recent = []
        for fr in reversed(scn.cap):
            if fr.t + fr.dur < now - span:
                break
            recent.append(fr)
        for fr in recent:
            m = fr.meta
            if "f" not in m:
                continue
            if fr.t <= now <= fr.t + fr.dur + 0.04:
                lvl = m.get("rssi", -55)
                bw = m.get("bw", (f1 - f0) / 50)
                g = np.exp(-((fq - m["f"]) / (bw / 2.2)) ** 6)
                p = np.maximum(p, lvl * g + p * (1 - g))
        ys = sp_y + sp_h - (p + 110) / 90.0 * sp_h
        pygame.draw.rect(s, (8, 12, 24), (gx, sp_y, gw, sp_h))
        for db in (-100, -80, -60, -40, -20):
            yy = sp_y + sp_h - (db + 110) / 90.0 * sp_h
            pygame.draw.line(s, (20, 30, 50), (gx, yy), (gx + gw, yy))
            text(s, "%d" % db, (gx - 4, yy - 6), 9, (100, 120, 160), align="r")
        pygame.draw.lines(s, (120, 230, 255), False, np.column_stack((gx + np.arange(nb), ys)).astype(int), 1)
        # waterfall
        for fr in recent:
            m = fr.meta
            if "f" not in m:
                continue
            bw = m.get("bw", (f1 - f0) / 50)
            xa, xb = X(m["f"] - bw / 2), X(m["f"] + bw / 2)
            ya = wf_y + (now - (fr.t + fr.dur)) / span * wf_h
            yb = wf_y + (now - fr.t) / span * wf_h
            if yb < wf_y or ya > wf_y + wf_h:
                continue
            ya, yb = max(wf_y, ya), min(wf_y + wf_h, yb)
            lvl = m.get("rssi", -55)
            k = max(0.15, min(1.0, (lvl + 110) / 70.0))
            col = KCOL["err"] if fr.err else (int(255 * k), int(200 * k), int(60 + 120 * k))
            if m.get("chirp"):
                sf = m["chirp"]
                nsym = max(1, int(min(60, (yb - ya) / 2)))
                h = (yb - ya) / nsym
                for i in range(nsym):
                    pygame.draw.line(s, col, (xa, yb - i * h), (xb, yb - (i + 1) * h), 1)
                del sf
            else:
                rr = pygame.Rect(int(xa), int(ya), max(2, int(xb - xa)), max(1, int(yb - ya)))
                pygame.draw.rect(s, tuple(int(c * 0.6) for c in col), rr)
                pygame.draw.rect(s, col, rr, 1)
        for i in range(6):
            f = f0 + (f1 - f0) * i / 5
            text(s, "%.4g" % f, (X(f), r.bottom - 20), 10, (140, 160, 200), align="c")
        text(s, unit, (gx + gw, r.bottom - 20), 10, (140, 160, 200), align="r")
        text(s, "dBm", (r.x + 6, sp_y), 9, (100, 120, 160))
        text(s, "newest", (r.x + 6, wf_y), 9, (100, 120, 160))
        text(s, "-%s" % fmt_s(span), (r.x + 6, wf_y + wf_h - 12), 9, (100, 120, 160))

    def _bb(self, s, r, scn):
        fr = self.b.selfr
        if fr is None or not fr.wirefn:
            for x in reversed(scn.cap):
                if x.wirefn:
                    fr = x
                    break
        if fr is None or fr.wire is None or not fr.wire.bit:
            text(s, "Baseband FFT needs a frame with a bit clock (select one)", r.center, 13, (120, 150, 200), align="m")
            return
        net = self.b.scope.nets()[self.b.scope.net[0] % max(1, len(self.b.scope.nets()))] if self.b.scope.nets() else "D"
        key = (fr.no, net)
        if self._fft is None or self._fft[0] != key:
            w = fr.wire
            fs = 24.0 / w.bit
            n = int(min(16384, max(1024, w.T * fs)))
            ts = np.arange(n) / fs
            y = phy.trace(scn.phy, w, net, ts, scn.cond(net))
            y = (y - y.mean()) * np.hanning(n)
            X_ = np.abs(np.fft.rfft(y)) / n * 4
            fq = np.fft.rfftfreq(n, 1 / fs)
            db = 20 * np.log10(X_ + 1e-9)
            self._fft = (key, fq, db, w.bit)
        _, fq, db, bit = self._fft
        gx, gy, gw, gh = r.x + 54, r.y + 16, r.w - 70, r.h - 50
        fmax = 4.0 / bit
        mask = fq <= fmax
        f, d = fq[mask], db[mask]
        if len(f) < 2:
            return
        top = max(-20, float(d.max()) + 5)
        for k in range(7):
            yy = gy + gh * k / 6
            pygame.draw.line(s, (16, 24, 40), (gx, yy), (gx + gw, yy))
            text(s, "%d" % (top - k * 15), (gx - 4, yy - 6), 9, (100, 120, 160), align="r")
        for k in range(5):
            xx = gx + gw * k / 4
            pygame.draw.line(s, (16, 24, 40), (xx, gy), (xx, gy + gh))
            text(s, fmt_hz(fmax * k / 4), (xx, gy + gh + 4), 10, (140, 160, 200), align="c")
        xs = gx + f / fmax * gw
        ys = gy + (top - d) / 90.0 * gh
        pygame.draw.lines(s, (120, 230, 255), False, np.column_stack((xs, np.clip(ys, gy, gy + gh))).astype(int), 1)
        xb = gx + (1.0 / bit) / fmax * gw
        pygame.draw.line(s, (255, 160, 60), (xb, gy), (xb, gy + gh), 1)
        text(s, "bit rate", (xb + 3, gy + 2), 9, (255, 160, 60))
        text(s, "FFT of %s, frame #%d (dBV, Hann window)" % (net, fr.no), (gx + 4, gy + 2), 11, (180, 220, 255))


# ================================================================ COMPOSE
class Compose(Inst):
    name = "COMPOSE"
    tip = "Frame composer: build a message field by field and transmit it onto the bus."

    def __init__(self, bench, rect):
        super().__init__(bench, rect)
        r = self.rect
        self.lr = pygame.Rect(r.x, r.y, 250, r.h)
        self.pr = pygame.Rect(r.x + 258, r.y, 430, r.h)
        self.vr = pygame.Rect(r.x + 696, r.y, r.w - 696, r.h)
        self.idx = 0
        self.focus = None
        self.edit = ""
        self.msg = ""
        self._pv = None
        self.bsend = self.add(Button((self.pr.x + 10, self.pr.bottom - 44, 200, 36), "TRANSMIT", "Send this frame onto the bus now. Replies show up in the ANALYZER.", color="green", on_click=lambda b: self.send(), size=12))
        self.brep = self.add(Button((self.pr.x + 220, self.pr.bottom - 44, 200, 36), "REPEAT 1 s", "Transmit this frame once per second (simulated time) until switched off.", toggle=True, size=10))
        self._rep_t = 0.0

    def tpls(self):
        return self.b.tpls

    def on_scenario(self):
        self.idx, self.focus, self._pv, self.msg = 0, None, None, ""
        self.brep.on = False

    def cur(self):
        t = self.tpls()
        return t[self.idx] if t and self.idx < len(t) else None

    def send(self):
        t = self.cur()
        if t is None:
            return
        try:
            fr = t.fn(self.scn, t.vals(), True)
            scn = self.scn                     # remembered for the lab checks
            scn._sent_seq = getattr(scn, "_sent_seq", 0) + 1
            sent = scn.__dict__.setdefault("_sent", [])
            sent.append((scn._sent_seq, scn.t, t.name))
            del sent[:-200]
            self.msg = "Queued '%s' at t = %.6f s" % (t.name, self.scn.t)
            ui.sfx("key", 0.8)
            if fr is not None:
                self.b.pending_sel = fr
        except Exception as e:
            self.msg = "Could not build: %s" % e
            ui.sfx("error", 0.8)

    def update(self, dt):
        if self.brep.on and self.scn.t - self._rep_t >= 1.0:
            self._rep_t = self.scn.t
            self.send()

    def preview(self):
        t = self.cur()
        if t is None:
            return None
        key = (id(self.scn), self.idx, tuple((p.key, str(p.value)) for p in t.params))
        if self._pv is None or self._pv[0] != key:
            try:
                fr = t.fn(self.scn, t.vals(), False)
                self._pv = (key, fr, "")
            except Exception as e:
                self._pv = (key, None, str(e))
        return self._pv

    def handle2(self, ev):
        t = self.cur()
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button in (1, 3):
            if self.lr.collidepoint(ev.pos):
                i = (ev.pos[1] - self.lr.y - 26) // 22
                if 0 <= i < len(self.tpls()):
                    self.idx, self.focus = i, None
                    ui.sfx("blip", 0.5)
                return True
            if t and self.pr.collidepoint(ev.pos):
                for i, p in enumerate(t.params):
                    y = self.pr.y + 30 + i * 30
                    box = pygame.Rect(self.pr.x + 150, y, 200, 24)
                    mi = pygame.Rect(self.pr.x + 356, y, 30, 24)
                    pl = pygame.Rect(self.pr.x + 390, y, 30, 24)
                    if mi.collidepoint(ev.pos):
                        p.bump(-1)
                        ui.sfx("detent", 0.6)
                        return True
                    if pl.collidepoint(ev.pos):
                        p.bump(1)
                        ui.sfx("detent", 0.6)
                        return True
                    if box.collidepoint(ev.pos):
                        if p.kind == "sel":
                            p.bump(1 if ev.button == 1 else -1)
                            ui.sfx("clunk", 0.6)
                        else:
                            self.focus, self.edit = i, str(p.value)
                            ui.FOCUS[0] = None
                            ui.sfx("key", 0.5)
                        return True
                self.focus = None
        if ev.type == pygame.MOUSEWHEEL and t:
            if self.lr.collidepoint(ui.MOUSE):
                self.idx = max(0, min(len(self.tpls()) - 1, self.idx - ev.y))
                return True
            for i, p in enumerate(t.params):
                y = self.pr.y + 30 + i * 30
                if pygame.Rect(self.pr.x + 150, y, 200, 24).collidepoint(ui.MOUSE):
                    mult = 10 if pygame.key.get_mods() & pygame.KMOD_SHIFT else 1
                    p.bump(ev.y * mult)
                    ui.sfx("detent", 0.5)
                    return True
        if ev.type == pygame.KEYDOWN and self.focus is not None and t:
            p = t.params[self.focus]
            if ev.key in (pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_TAB):
                p.parse(self.edit)
                self.focus = None
                ui.sfx("key", 0.6)
            elif ev.key == pygame.K_ESCAPE:
                self.focus = None
            elif ev.key == pygame.K_BACKSPACE:
                self.edit = self.edit[:-1]
            elif ev.unicode and ev.unicode.isprintable():
                self.edit += ev.unicode
                ui.sfx("key", 0.3)
            return True
        return False

    def draw(self, s):
        tp = self.tpls()
        r = self.lr
        ui.lcd(s, r, (6, 10, 10), (14, 30, 30), gain=0)
        text(s, "MESSAGE TEMPLATES", (r.x + 8, r.y + 6), 11, (150, 200, 190), bold=True)
        if not tp:
            ui.text_block(s, "This network has no user transmitter (it is a receive-only / broadcast system). Use the DEVICE controls to change what the devices send.", (r.x + 8, r.y + 30, r.w - 16, 200), 11, (180, 200, 190), mono=False)
        for i, t in enumerate(tp):
            y = r.y + 26 + i * 22
            if y > r.bottom - 22:
                break
            if i == self.idx:
                pygame.draw.rect(s, (30, 70, 90), (r.x + 3, y - 2, r.w - 6, 21))
            text(s, ui.clip_text(t.name, 11, r.w - 16), (r.x + 8, y + 1), 11, (220, 230, 220) if i == self.idx else (170, 180, 175))
        p = self.pr
        ui.panel(s, p, None)
        t = self.cur()
        if t:
            text(s, ui.clip_text(t.name, 12, p.w - 20, bold=True), (p.x + 12, p.y + 8), 12, (230, 220, 190), bold=True)
            for i, prm in enumerate(t.params):
                y = p.y + 30 + i * 30
                ui.legend(s, ui.clip_text(prm.label, 10, 136), (p.x + 12, y + 6), 10, align="l")
                box = pygame.Rect(p.x + 150, y, 200, 24)
                fx.draw_well(s, box, (8, 16, 12), (20, 60, 30))
                v = (self.edit + ("_" if (pygame.time.get_ticks() // 400) % 2 == 0 else " ")) if self.focus == i else prm.show()
                text(s, ui.clip_text(v, 11, 190), (box.x + 6, box.y + 5), 11, C["lcdfg"] if self.focus != i else C["yellow"])
                for k, lab in ((0, "-"), (1, "+")):
                    br = pygame.Rect(p.x + 356 + k * 34, y, 30, 24)
                    s.blit(fx.button(br.w, br.h, C["amber"], False, False), br)
                    text(s, lab, br.center, 12, (220, 220, 210), bold=True, align="m")
            yy = p.y + 34 + len(t.params) * 30
            ui.text_block(s, t.desc, (p.x + 12, yy, p.w - 24, p.bottom - 52 - yy), 10, (200, 200, 180), lh=13, mono=False)
        src = self.scn.by.get(self.scn.user)
        text(s, "from: %s" % (src.label if src else "-"), (p.x + 12, p.bottom - 58), 10, (150, 170, 160))
        if self.msg:
            text(s, ui.clip_text(self.msg, 10, p.w - 20), (p.x + 12, p.bottom - 70), 10, C["green"] if not self.msg.startswith("Could") else C["red"])
        self.draw_widgets(s)
        v = self.vr
        ui.lcd(s, v, (5, 9, 12), (12, 30, 40), gain=0)
        pv = self.preview()
        if not pv:
            return
        _, fr, err = pv
        if fr is None:
            if err:
                ui.text_block(s, "Cannot build: " + err, v.inflate(-16, -16), 11, C["red"], mono=False)
            else:
                ui.text_block(s, "No single-frame preview: this action starts a short exchange of messages (or a bus "
                                 "condition such as a wake-up pulse). Press TRANSMIT and follow it in the ANALYZER and FLOW.",
                              v.inflate(-16, -16), 11, (200, 220, 230), mono=False)
            return
        text(s, "PREVIEW  %s  %d bytes  %s" % (fr.proto, fr.length, fmt_s(fr.dur)), (v.x + 8, v.y + 6), 11, (240, 214, 140), bold=True)
        text(s, ui.clip_text(fr.info, 11, v.w - 16), (v.x + 8, v.y + 22), 11, (200, 220, 230))
        y = v.y + 42
        for row in fr.pdu.rows[:14]:
            d = row[0]
            text(s, ui.clip_text(row[1], 10, v.w - 20 - d * 12), (v.x + 8 + d * 12, y), 10, (240, 214, 140) if d == 0 else (200, 208, 214), bold=d == 0)
            y += 13
        data = fr.raw
        y = max(y + 6, v.bottom - 13 * min(6, (len(data) + 15) // 16) - 10)
        for ln in range(min(6, (len(data) + 15) // 16)):
            text(s, "%04X  %s" % (ln * 16, " ".join("%02X" % b for b in data[ln * 16:ln * 16 + 16])), (v.x + 8, y), 10, (170, 190, 200))
            y += 13

    def tip2(self, p):
        if self.pr.collidepoint(p):
            return "Click a value to type it (hex like 0x1F works), click a selector to step it, or use the wheel (SHIFT = x10). -/+ buttons step too."
        if self.lr.collidepoint(p):
            return "Pick a message to build."
        if self.vr.collidepoint(p):
            return "Live encoding of the frame as you edit it - watch checksums and lengths update."
        return ""


# ================================================================== STATS
class Stats(Inst):
    name = "STATS"
    tip = "Bus load, frame rates, error counters and a per-message table (like a CAN trace in fixed mode)."

    def __init__(self, bench, rect):
        super().__init__(bench, rect)
        self.top = 0

    def handle2(self, ev):
        if ev.type == pygame.MOUSEWHEEL and self.rect.collidepoint(ui.MOUSE):
            self.top = max(0, self.top - ev.y * 2)
            return True
        return False

    def draw(self, s):
        r = self.rect
        scn = self.scn
        left = pygame.Rect(r.x, r.y, 330, r.h)
        ui.panel(s, left, None)
        load = scn.busload()
        ui.meter(s, (left.x + 20, left.y + 10, 290, 110), load, "BUS LOAD %", [(0, "0"), (0.25, "25"), (0.5, "50"), (0.75, "75"), (1.0, "100")], red_from=0.7)
        fps = len(scn.loadw)
        lines = [("Simulated time", "%.3f s" % scn.t), ("Frames captured", "%d" % scn.nfr), ("Frames / second", "%d" % fps),
                 ("Errors", "%d" % scn.nerr), ("Error ratio", "%.2f %%" % (100.0 * scn.nerr / max(1, scn.nfr))),
                 ("Bus load", "%.1f %%" % (100 * load))]
        y = left.y + 140
        for k, v in lines:
            text(s, k, (left.x + 18, y), 11, (190, 196, 190))
            text(s, v, (left.right - 18, y), 11, C["amber"], bold=True, align="r")
            y += 16
        text(s, "EVENT LOG", (left.x + 18, y + 6), 10, (150, 160, 150), bold=True)
        y += 22
        for t, msg in list(scn.events)[-8:]:
            text(s, ui.clip_text("%.3f %s" % (t, msg), 9, left.w - 30), (left.x + 18, y), 9, (200, 200, 170))
            y += 12
        right = pygame.Rect(r.x + 338, r.y, r.w - 338, r.h)
        cr = None
        if hasattr(scn, "draw_stats") and type(scn).draw_stats is not engine.Scenario.draw_stats:
            cr = pygame.Rect(right.right - 470, right.y, 470, right.h)
            right = pygame.Rect(right.x, right.y, right.w - 478, right.h)
        ui.lcd(s, right, (5, 9, 12), (12, 30, 40), gain=0)
        cols = [("Message", 0.40), ("Count", 0.12), ("Period", 0.14), ("Last value", 0.34)]
        x = right.x + 8
        for nm, f in cols:
            text(s, nm, (x, right.y + 5), 11, (150, 190, 210), bold=True)
            x += int(f * (right.w - 16))
        keys = sorted(scn.keys.items(), key=lambda kv: str(kv[0]))
        nv = (right.h - 28) // 15
        self.top = min(self.top, max(0, len(keys) - nv))
        y = right.y + 24
        for k, e in keys[self.top:self.top + nv]:
            x = right.x + 8
            per = ("%.1f ms" % (e[2] * 1000)) if e[2] < 10 else ("%.1f s" % e[2])
            vals = [str(k), "%d" % e[0], per if e[0] > 1 else "-", e[3]]
            for (nm, f), v in zip(cols, vals):
                ww = int(f * (right.w - 16)) - 6
                text(s, ui.clip_text(v, 11, ww), (x, y), 11, KCOL["err"] if e[5] else (205, 212, 218))
                x += int(f * (right.w - 16))
            y += 15
        ui.scrollbar(s, (right.right - 10, right.y + 22, 8, right.h - 26), self.top, nv, len(keys))
        if cr is not None:
            ui.lcd(s, cr, (5, 9, 12), (12, 30, 40), gain=0)
            scn.draw_stats(s, cr.inflate(-12, -12))
