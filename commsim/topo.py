"""Wiring view: devices, cables, connectors and terminators, with every
transmission drawn as a pulse travelling along the copper (or a wavefront
for radio links). Click a device to inspect it, a cable to probe it with
the oscilloscope, a terminator to pull it out or fit it."""
import math
import pygame
from . import ui, fx
from .ui import C, text
from . import engine
from .engine import KCOL, poly_at

LED = [("PWR", (70, 255, 120)), ("TX", (255, 178, 46)), ("RX", (90, 215, 255)), ("ERR", (255, 66, 56))]


def _dist_seg(p, a, b):
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    L2 = dx * dx + dy * dy
    if L2 == 0:
        return math.hypot(p[0] - ax, p[1] - ay)
    t = max(0, min(1, ((p[0] - ax) * dx + (p[1] - ay) * dy) / L2))
    return math.hypot(p[0] - (ax + t * dx), p[1] - (ay + t * dy))


class Topo:
    def __init__(self, bench, rect):
        self.b = bench
        self.rect = pygame.Rect(rect)
        self.inner = pygame.Rect(self.rect.x + 8, self.rect.y + 30, self.rect.w - 16, self.rect.h - 38)
        self.drag = None

    @property
    def ox(self):
        return self.inner.x

    @property
    def oy(self):
        return self.inner.y

    # ------------------------------------------------------------ radio map
    def _sc(self, scn):
        return self.inner.w / float(scn.map_m)

    def _layout_radio(self, scn):
        sc = self._sc(scn)
        for n in scn.nodes:
            n.x = n.mx * sc - n.w / 2.0
            n.y = n.my * sc - n.h / 2.0
            n.port = (n.mx * sc, n.my * sc)

    def _map(self, s, scn):
        r = self.inner
        sc = self._sc(scn)
        s.fill((6, 14, 18), r)
        step = scn.map_grid if hasattr(scn, "map_grid") else self._nice(scn.map_m / 8)
        k = 0
        x = 0.0
        while x <= scn.map_m:
            px = r.x + int(x * sc)
            pygame.draw.line(s, (16, 40, 46) if k % 5 else (24, 58, 64), (px, r.y), (px, r.bottom))
            x += step
            k += 1
        y, k = 0.0, 0
        while y * sc <= r.h:
            py = r.y + int(y * sc)
            pygame.draw.line(s, (16, 40, 46) if k % 5 else (24, 58, 64), (r.x, py), (r.right, py))
            y += step
            k += 1
        lab = ("%g km" % (step / 1000.0)) if step >= 1000 else ("%g m" % step)
        pygame.draw.line(s, (120, 200, 210), (r.right - 20 - step * sc, r.bottom - 12), (r.right - 20, r.bottom - 12), 2)
        text(s, lab, (r.right - 20 - step * sc / 2, r.bottom - 26), 10, (140, 210, 220), align="c")
        bg = getattr(scn, "draw_map", None)
        if bg:
            bg(s, r, sc)
        sel = scn.by.get(scn.sel)
        if sel is not None and hasattr(scn, "range_m"):
            R = scn.range_m(sel)
            if R:
                pygame.draw.circle(s, (40, 110, 120), (int(r.x + sel.mx * sc), int(r.y + sel.my * sc)), int(R * sc), 1)
        if hasattr(scn, "links"):
            for a, b, m in scn.links():
                na, nb = scn.by[a], scn.by[b]
                col = (70, 230, 120) if m > 10 else (240, 190, 60) if m > 0 else (220, 70, 60)
                pa = (r.x + na.mx * sc, r.y + na.my * sc)
                pb = (r.x + nb.mx * sc, r.y + nb.my * sc)
                L = max(1, int(math.hypot(pb[0] - pa[0], pb[1] - pa[1])))
                for i in range(0, L, 9):
                    f0, f1 = i / L, min(1, (i + 4) / L)
                    pygame.draw.line(s, col, (pa[0] + (pb[0] - pa[0]) * f0, pa[1] + (pb[1] - pa[1]) * f0),
                                     (pa[0] + (pb[0] - pa[0]) * f1, pa[1] + (pb[1] - pa[1]) * f1), 1)
                if m > -50:
                    text(s, "%+d dB" % m, ((pa[0] + pb[0]) / 2, (pa[1] + pb[1]) / 2 - 6), 9, col, align="m")

    @staticmethod
    def _nice(v):
        e = 10 ** math.floor(math.log10(max(v, 1e-9)))
        for m in (1, 2, 5, 10):
            if m * e >= v:
                return m * e
        return 10 * e

    # ----------------------------------------------------------------- draw
    def draw(self, s, scn):
        r = self.rect
        ui.panel(s, r, "TOPOLOGY / WIRING")
        tr = pygame.Rect(r.x + 200, r.y + 5, r.w - 210, 16)
        text(s, ui.clip_text(scn.medium or scn.name, 10, tr.w), (tr.right, tr.y + 1), 10, (200, 196, 170), align="r")
        inner = self.inner
        clip = s.get_clip()
        s.set_clip(inner)
        if scn.radio:
            self._layout_radio(scn)
            self._map(s, scn)
        else:
            s.blit(fx.mount_panel(inner), inner)
        ox, oy = self.ox, self.oy
        now = engine.WALL()
        # cables
        for g in scn.segs:
            pts = [(ox + p[0], oy + p[1]) for p in g.pts]
            fx.cable(s, pts, g.col, g.w, g.dash)
            if g.broken:
                m = poly_at(pts, 0.5)
                pygame.draw.circle(s, (20, 20, 20), (int(m[0]), int(m[1])), g.w + 3)
                pygame.draw.line(s, C["red"], (m[0] - 6, m[1] - 6), (m[0] + 6, m[1] + 6), 3)
                pygame.draw.line(s, C["red"], (m[0] - 6, m[1] + 6), (m[0] + 6, m[1] - 6), 3)
            if g.label:
                a, b = pts[0], pts[1]
                text(s, g.label, ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2 - g.w - 11), 9, (190, 190, 170), align="c")
        for g in scn.segs:
            for c, p, q in ((g.c0, g.pts[0], g.pts[1] if len(g.pts) > 1 else g.pts[0]), (g.c1, g.pts[-1], g.pts[-2] if len(g.pts) > 1 else g.pts[-1])):
                if not c:
                    continue
                sp = fx.connector(c)
                dx, dy = q[0] - p[0], q[1] - p[1]
                L = math.hypot(dx, dy) or 1
                off = 8
                cx, cy = ox + p[0] + dx / L * off, oy + p[1] + dy / L * off
                if abs(dy) > abs(dx) and sp.get_width() > sp.get_height() * 1.3:
                    sp = pygame.transform.rotate(sp, 90)
                s.blit(sp, (cx - sp.get_width() / 2, cy - sp.get_height() / 2))
        for t in scn.terms:
            x, y = ox + t.x, oy + t.y
            if t.on:
                sp = fx.resistor(t.vert)
                s.blit(sp, (x - sp.get_width() / 2, y - sp.get_height() / 2))
                text(s, t.label, (x, y + 9), 9, (230, 214, 160), align="c")
            else:
                pygame.draw.circle(s, (240, 70, 60), (int(x), int(y)), 9, 1)
                text(s, "OPEN", (x, y + 9), 9, C["red"], bold=True, align="c")
        # travelling frames
        spd = self.b.app.speed
        anims = list(scn.anim)
        if spd > 0.02:
            anims = anims[-8:]
        for fr, w0 in anims:
            if spd <= 0.02:
                dw = min(4.0, max(0.35, fr.dur / max(spd, 1e-9)))
            else:
                dw = 0.45
            p = (now - w0) / dw
            if p < 0 or p > 1.15:
                continue
            col = KCOL.get(fr.kind, (200, 200, 200)) if not fr.err else KCOL["err"]
            src = scn.by.get(fr.src)
            if src is None:
                continue
            if scn.radio:
                cx, cy = ox + src.port[0], oy + src.port[1]
                R = getattr(scn, "range_m", lambda n: scn.map_m * 0.3)(src) * self._sc(scn)
                rad = int(max(3, p * R))
                a = max(0.0, 1 - p)
                cc = tuple(int(c * a) for c in col)
                pygame.draw.circle(s, cc, (int(cx), int(cy)), rad, 2)
                for d in scn._dsts(fr)[:6]:
                    nd = scn.by.get(d)
                    if nd is None:
                        continue
                    q = (ox + nd.port[0], oy + nd.port[1])
                    m = (cx + (q[0] - cx) * min(1, p), cy + (q[1] - cy) * min(1, p))
                    g = fx.glow(4, col, 0.7)
                    s.blit(g, (m[0] - g.get_width() // 2, m[1] - g.get_height() // 2), special_flags=pygame.BLEND_RGB_ADD)
                continue
            for d in scn._dsts(fr)[:10]:
                path = scn.path(fr.src, d)
                if not path:
                    continue
                pts = [(ox + a, oy + b) for a, b in path]
                for k, tail in enumerate((0.0, 0.035, 0.07)):
                    q = poly_at(pts, min(1.0, p - tail))
                    if q is None:
                        continue
                    g = fx.glow(3 - k if k < 2 else 1, col, 0.7 - 0.2 * k)
                    s.blit(g, (q[0] - g.get_width() // 2, q[1] - g.get_height() // 2), special_flags=pygame.BLEND_RGB_ADD)
                q = poly_at(pts, min(1.0, p))
                pygame.draw.circle(s, (255, 255, 255), (int(q[0]), int(q[1])), 2)
        # devices
        for n in scn.nodes:
            self._node(s, scn, n, now)
        scn.draw_extra(s, inner)
        s.set_clip(clip)

    def _node(self, s, scn, n, now):
        r = pygame.Rect(int(self.ox + n.x), int(self.oy + n.y), n.w, n.h)
        sel = scn.sel == n.id
        s.blit(fx.device(r.w, r.h, (64, 70, 80) if n.on else (40, 42, 46), sel), r)
        face = r.inflate(-10, -10)
        gcol = (150, 205, 235) if n.on else (70, 80, 90)
        if r.h >= 40:
            g = pygame.Rect(face.x + 1, face.y + 2, 20, 20)
            fx.glyph(s, n.kind, g, gcol)
            tx = face.x + 25
        else:
            tx = face.x + 2
        wmax = face.right - tx - 2
        text(s, ui.clip_text(n.label, 10, wmax, bold=True), (tx, face.y), 10, (232, 234, 228) if n.on else (120, 120, 120), bold=True)
        sub = "  ".join(x for x in (n.addr, n.sub) if x)
        if sub and r.h >= 34:
            text(s, ui.clip_text(sub, 9, wmax), (tx, face.y + 14), 9, (150, 170, 180))
        if n.state and r.h >= 46:
            text(s, ui.clip_text(n.state, 9, face.w - 4), (face.x + 2, face.bottom - 11), 9, C["amber"] if n.on else (100, 90, 60))
        x = r.right - 9
        for i, (nm, col) in enumerate(reversed(LED)):
            t = {"PWR": 0, "TX": n.ftx, "RX": n.frx, "ERR": n.ferr}[nm]
            on = n.on and (nm == "PWR" or now - t < 0.12)
            ui.led(s, (x - i * 9, r.y + 6), col, on, r=2)
        if sel:
            pygame.draw.rect(s, C["amber"], r.inflate(4, 4), 1, border_radius=7)
        elif r.collidepoint(ui.MOUSE):
            pygame.draw.rect(s, (150, 140, 110), r.inflate(4, 4), 1, border_radius=7)

    # ---------------------------------------------------------------- input
    def node_at(self, scn, p):
        for n in reversed(scn.nodes):
            if pygame.Rect(self.ox + n.x, self.oy + n.y, n.w, n.h).collidepoint(p):
                return n
        return None

    def seg_at(self, scn, p):
        best, bd = None, 7.0
        for g in scn.segs:
            pts = [(self.ox + a, self.oy + b) for a, b in g.pts]
            for a, b in zip(pts, pts[1:]):
                d = _dist_seg(p, a, b)
                if d < bd:
                    best, bd = g, d
        return best

    def term_at(self, scn, p):
        for t in scn.terms:
            if math.hypot(p[0] - self.ox - t.x, p[1] - self.oy - t.y) < 14:
                return t
        return None

    def handle(self, ev, scn):
        if not self.inner.collidepoint(getattr(ev, "pos", ui.MOUSE)) and ev.type != pygame.MOUSEBUTTONUP and not self.drag:
            return False
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1:
            n = self.node_at(scn, ev.pos)
            if n is not None:
                scn.sel = n.id
                self.b.on_select_node()
                ui.sfx("press", 0.5)
                if scn.radio:
                    self.drag = n
                return True
            t = self.term_at(scn, ev.pos)
            if t is not None and t.key and ("no_" + t.key) in scn.fault:
                scn.set_fault("no_" + t.key, t.on)
                ui.sfx("relay", 0.9)
                return True
            g = self.seg_at(scn, ev.pos)
            if g is not None and g.net:
                self.b.probe(g.net)
                ui.sfx("probe", 0.9)
                return True
        if ev.type == pygame.MOUSEMOTION and self.drag is not None:
            sc = self._sc(scn)
            n = self.drag
            n.mx = max(0.0, min(scn.map_m, (ev.pos[0] - self.ox) / sc))
            n.my = max(0.0, min(self.inner.h / sc, (ev.pos[1] - self.oy) / sc))
            return True
        if ev.type == pygame.MOUSEBUTTONUP and ev.button == 1 and self.drag is not None:
            self.drag = None
            if hasattr(scn, "moved"):
                scn.moved()
            return True
        return False

    def tip_at(self, scn, p):
        if not self.inner.collidepoint(p):
            return ""
        n = self.node_at(scn, p)
        if n is not None:
            extra = " Drag it to move it on the map." if scn.radio else ""
            return "%s  %s  %s - click to inspect its state in the DEVICE tab.%s" % (n.label, n.sub or "", n.addr or "", extra)
        t = self.term_at(scn, p)
        if t is not None:
            if t.key and ("no_" + t.key) in scn.fault:
                return "Terminating resistor %s (%s). Click to %s it." % (t.label, "fitted" if t.on else "missing", "remove" if t.on else "refit")
            return "Terminating resistor %s." % t.label
        g = self.seg_at(scn, p)
        if g is not None:
            s = g.label or g.name or "Cable"
            if g.net:
                s += " - click to clip oscilloscope CH1 onto net %s." % g.net
            return s
        return ""
