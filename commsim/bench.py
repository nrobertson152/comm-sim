"""The protocol lab bench: wiring view, device / faults / guide / spec panel
and the instrument deck, all bound to the currently loaded Scenario."""
import pygame
from . import ui, fx
from .ui import C, text, Button, Knob, TextField
from .topo import Topo
from .instruments import Analyzer, Scope, Logic, Flow, Spectrum, Compose, Stats

TOPO_R = pygame.Rect(254, 50, 896, 420)
SIDE_R = pygame.Rect(1154, 50, 442, 420)
DECK_R = pygame.Rect(254, 474, 1342, 390)
CONTENT_R = pygame.Rect(262, 512, 1326, 346)


def frame_diagram(s, rect, rows, y):
    """RFC-style frame layout: boxes sized by bit count, wrapped to width."""
    x0, x1 = rect.x, rect.right
    pal = [(70, 110, 160), (60, 140, 110), (150, 110, 60), (130, 80, 150), (150, 70, 70), (60, 120, 150)]
    for row in rows:
        title = None
        if row and isinstance(row[0], str):
            title, row = row[0], row[1:]
        if title:
            text(s, title, (x0, y), 10, (220, 200, 150), bold=True)
            y += 14
        tot = sum(b if isinstance(b, (int, float)) else 24 for _, b in row) or 1
        scale = max(4.0, min(14.0, (x1 - x0) / float(tot)))
        x = x0
        for i, (name, bits) in enumerate(row):
            wpx = int(max(34, (bits if isinstance(bits, (int, float)) else 24) * scale))
            if x + wpx > x1 and x > x0:
                x = x0
                y += 34
            rr = pygame.Rect(x, y, min(wpx, x1 - x), 30)
            col = pal[i % len(pal)]
            pygame.draw.rect(s, tuple(c // 3 for c in col), rr)
            pygame.draw.rect(s, col, rr, 1)
            text(s, ui.clip_text(name, 9, rr.w - 4), (rr.centerx, rr.y + 3), 9, (230, 230, 220), align="c")
            bl = ("%d bit" % bits if bits != 1 else "1 bit") if isinstance(bits, int) else str(bits)
            text(s, ui.clip_text(bl, 9, rr.w - 4), (rr.centerx, rr.y + 16), 9, (160, 180, 190), align="c")
            x += rr.w
        y += 38
    return y


class Bench:
    SIDE_TABS = ["DEVICE", "FAULTS", "GUIDE", "SPEC"]

    def __init__(self, app):
        self.app = app
        self.scn = None
        self.selfr = None
        self.held = None
        self.filter = ""
        self.tpls = []
        self.pending_sel = None
        self.topo = Topo(self, TOPO_R)
        self.side = 0
        self.side_scroll = 0
        self.fault_desc = ""
        self.widgets = []            # fixed bench widgets
        self.dyn = []                # rebuilt with scenario / node selection
        x = SIDE_R.x + 10
        self.sbtn = []
        for i, nm in enumerate(self.SIDE_TABS):
            b = Button((x + i * 106, SIDE_R.y + 28, 102, 24), nm, "", on_click=lambda b, i=i: self.set_side(i), size=10)
            b.tip = {"DEVICE": "Selected device: live state, variables and controls.", "FAULTS": "Inject wiring, timing and protocol faults.",
                     "GUIDE": "What this protocol is and experiments to try.", "SPEC": "Key facts and the frame format."}[nm]
            self.sbtn.append(b)
            self.widgets.append(b)
        inst = [Analyzer, Scope, Logic, Flow, Spectrum, Compose, Stats]
        self.inst = [cls(self, CONTENT_R) for cls in inst]
        self.scope = self.inst[1]
        self.cur = 0
        self.dbtn = []
        for i, it in enumerate(self.inst):
            b = Button((DECK_R.x + 8 + i * 104, DECK_R.y + 6, 100, 28), it.name, it.tip, on_click=lambda b, i=i: self.set_deck(i), size=10)
            self.dbtn.append(b)
            self.widgets.append(b)
        xr = DECK_R.x + 8 + len(self.inst) * 104 + 10
        self.b_hold = Button((xr, DECK_R.y + 6, 62, 28), "HOLD", "Freeze the capture display (the simulation keeps running).", toggle=True, on_click=self._hold, size=10)
        self.b_live = Button((xr + 66, DECK_R.y + 6, 56, 28), "LIVE", "Resume auto-scrolling to the newest frame.", on_click=self._live, size=10)
        self.b_clr = Button((xr + 126, DECK_R.y + 6, 62, 28), "CLEAR", "Clear the capture buffer and statistics.", on_click=self._clear, size=10)
        self.f_filt = TextField((xr + 192, DECK_R.y + 6, DECK_R.right - xr - 200, 28), "", "Display filter: words that must appear in the protocol / info / addresses. 'err' = errors only.",
                                placeholder="FILTER (e.g. err, 0x7E8, PGN)", on_change=self._filt, size=11)
        self.widgets += [self.b_hold, self.b_live, self.b_clr, self.f_filt]

    # --------------------------------------------------------------- control
    def set_side(self, i):
        self.side = i
        self.side_scroll = 0
        self.rebuild()

    def set_deck(self, i):
        self.cur = i

    def _hold(self, b):
        self.held = list(self.scn.cap) if b.on else None

    def _live(self, b):
        self.inst[0].live = True
        self.inst[3].blive.on = True
        self.b_hold.on = False
        self.held = None

    def _clear(self, b):
        s = self.scn
        s.cap.clear()
        s.keys.clear()
        s.nerr = 0
        self.selfr = None
        self.held = None
        self.b_hold.on = False

    def _filt(self, v):
        self.filter = v

    def select(self, fr):
        self.selfr = fr

    def probe(self, net):
        self.scope.probe(net, 0)
        self.app.status_note = "Scope CH1 clipped onto %s" % net

    def load(self, scn):
        self.scn = scn
        self.selfr = None
        self.held = None
        self.b_hold.on = False
        self.tpls = getattr(scn, "_tpls", None)
        if self.tpls is None:
            try:
                self.tpls = scn._tpls = scn.tpls()
            except Exception as e:                 # a template bug must not take the bench down
                scn.log("composer unavailable: %s" % e)
                self.tpls = scn._tpls = []
        for it in self.inst:
            it.on_scenario()
        self.side_scroll = 0
        self.rebuild()

    def on_select_node(self):
        if self.side != 0:
            self.side = 0
        self.rebuild()

    def rebuild(self):
        """(Re)create the dynamic widgets of the side panel."""
        self.dyn = []
        scn = self.scn
        if scn is None:
            return
        x0, y0 = SIDE_R.x + 14, SIDE_R.y + 60
        if self.side == 0:
            n = scn.by.get(scn.sel)
            if n is None:
                return
            if n.extra.get("power", True):
                def pw(b, n=n):
                    n.on = b.on
                    scn.log("%s power %s" % (n.label, "ON" if n.on else "OFF"))
                    if hasattr(scn, "on_power"):
                        scn.on_power(n)
                self.dyn.append(Button((SIDE_R.right - 84, y0 + 2, 70, 24), "POWER", "Switch this device on or off.", toggle=True, on=n.on, color="green", on_click=pw, size=10))
            kx = x0 + 30
            ky = SIDE_R.bottom - 50
            for i, c in enumerate(n.ctl[:5]):
                var, lab, lo, hi, step = c[:5]
                fmt = c[5] if len(c) > 5 else (lambda v: "%g" % v)
                k = Knob(kx + i * 82, ky, 17, lab, lo, hi, n.vars.get(var, lo), "Set %s on %s." % (lab, n.label), step=step, fmt=fmt)
                k._var, k._node = var, n
                self.dyn.append(k)
            ax = x0
            ay = ky - 70 if n.ctl else SIDE_R.bottom - 40
            for i, (lab, fn) in enumerate(n.acts[:6]):
                w = 136
                bx = ax + (i % 3) * (w + 4)
                by = ay + (i // 3) * 30 - (30 if len(n.acts) > 3 else 0)
                self.dyn.append(Button((bx, by, w, 26), lab, "Action on %s." % n.label, on_click=lambda b, fn=fn: fn(), size=9, color="cyan"))
        elif self.side == 1:
            for i, (k, lab, desc) in enumerate(scn.faults[:13]):
                def tg(b, k=k, desc=desc):
                    scn.set_fault(k, b.on)
                    self.fault_desc = desc
                    ui.sfx("fault" if b.on else "ok", 0.8)
                b = Button((x0, y0 + 2 + i * 27, SIDE_R.w - 28, 24), lab, desc, toggle=True, on=scn.fault.get(k, False), color="red", on_click=tg, size=9)
                b._fkey = k
                self.dyn.append(b)

    # ---------------------------------------------------------------- events
    def handle(self, ev):
        for w in self.widgets + self.dyn:
            if w.visible and w.handle(ev):
                if isinstance(w, Knob) and hasattr(w, "_var"):
                    w._node.vars[w._var] = w.val
                return True
        if ev.type == pygame.MOUSEWHEEL and SIDE_R.collidepoint(ui.MOUSE) and self.side in (2, 3):
            self.side_scroll = max(0, self.side_scroll - ev.y * 28)
            return True
        if self.topo.handle(ev, self.scn):
            return True
        return self.inst[self.cur].handle(ev)

    def update(self, dt):
        scn = self.scn
        for w in self.dyn:
            if isinstance(w, Knob) and hasattr(w, "_var") and not w.drag:
                w.set(w._node.vars.get(w._var, w.val))
            if hasattr(w, "_fkey"):
                w.on = scn.fault.get(w._fkey, False)
        for it in self.inst:
            it.update(dt)

    def tip_at(self, p):
        for w in self.widgets + self.dyn:
            if w.hit(p) and w.tip:
                return w.tip
        t = self.topo.tip_at(self.scn, p)
        if t:
            return t
        if CONTENT_R.collidepoint(p):
            return self.inst[self.cur].tip_at(p)
        return ""

    # ------------------------------------------------------------------ draw
    def draw(self, s):
        scn = self.scn
        self.topo.draw(s, scn)
        self._side(s)
        ui.panel(s, DECK_R, None)
        for i, b in enumerate(self.dbtn):
            b.on = i == self.cur
            b.draw(s)
        for b in (self.b_hold, self.b_live, self.b_clr, self.f_filt):
            b.draw(s)
        self.inst[self.cur].draw(s)

    def _side(self, s):
        r = SIDE_R
        ui.panel(s, r, "INSTRUMENT PANEL")
        for i, b in enumerate(self.sbtn):
            b.on = i == self.side
            b.draw(s)
        body = pygame.Rect(r.x + 10, r.y + 58, r.w - 20, r.h - 66)
        scn = self.scn
        if self.side == 0:
            self._device(s, body)
        elif self.side == 1:
            fx.draw_well(s, body, (14, 15, 17))
            if not scn.faults:
                text(s, "No faults defined for this network", body.center, 11, C["dim"], align="m")
            nf = len(scn.faults[:13])
            d = self.fault_desc or "Toggle a fault; the effect appears on the wire (SCOPE), in the frames (ANALYZER) and in the device states. Hover a fault for details."
            yy = body.y + 8 + nf * 27
            if yy < body.bottom - 30:
                ui.text_block(s, d, (body.x + 6, yy, body.w - 12, body.bottom - yy - 4), 10, (220, 210, 180), lh=13, mono=False)
        elif self.side == 2:
            self._guide(s, body)
        else:
            self._spec(s, body)
        for w in self.dyn:
            w.draw(s)

    def _device(self, s, body):
        scn = self.scn
        n = scn.by.get(scn.sel)
        fx.draw_well(s, body, (10, 13, 14), (20, 30, 34))
        if n is None:
            text(s, "Click a device in the wiring view", body.center, 11, C["dim"], align="m")
            return
        text(s, ui.clip_text(n.label, 14, body.w - 100, bold=True), (body.x + 8, body.y + 6), 14, (236, 230, 210), bold=True)
        sub = " ".join(x for x in (n.sub, n.addr) if x)
        text(s, ui.clip_text(sub, 10, body.w - 100), (body.x + 8, body.y + 25), 10, (160, 180, 190))
        if n.state:
            text(s, ui.clip_text(n.state, 11, body.w - 16), (body.x + 8, body.y + 40), 11, C["amber"], bold=True)
        rows = scn.inspect(n)
        y = body.y + 58
        lim = body.bottom - (130 if n.ctl else 50) - (30 if len(n.acts) > 3 else 0)
        for k, v in rows:
            if y > lim:
                break
            text(s, ui.clip_text(str(k), 10, 168), (body.x + 8, y), 10, (170, 180, 178))
            text(s, ui.clip_text(str(v), 10, body.w - 190), (body.x + 182, y), 10, (130, 255, 170))
            y += 14

    def _guide(self, s, body):
        scn = self.scn
        fx.draw_well(s, body, (12, 13, 15))
        clip = s.get_clip()
        s.set_clip(body.inflate(-4, -4))
        y = body.y + 8 - self.side_scroll
        text(s, scn.name, (body.x + 8, y), 13, (240, 220, 160), bold=True)
        y += 18
        text(s, scn.blurb, (body.x + 8, y), 10, (160, 180, 190))
        y += 18
        y = ui.text_block(s, scn.about, (body.x + 8, y, body.w - 16, 4000), 10, (215, 215, 205), lh=13, mono=False) + 6
        if scn.guide:
            text(s, "TRY THIS", (body.x + 8, y), 11, C["amber"], bold=True)
            y += 16
            for i, g in enumerate(scn.guide):
                text(s, "%d." % (i + 1), (body.x + 8, y), 10, C["amber"], bold=True)
                y = ui.text_block(s, g, (body.x + 26, y, body.w - 34, 4000), 10, (220, 220, 200), lh=13, mono=False) + 4
        s.set_clip(clip)
        if y + self.side_scroll > body.bottom:
            text(s, "wheel to scroll", (body.right - 8, body.bottom - 14), 9, (120, 120, 110), align="r")

    def _spec(self, s, body):
        scn = self.scn
        fx.draw_well(s, body, (12, 13, 15))
        clip = s.get_clip()
        s.set_clip(body.inflate(-4, -4))
        y = body.y + 8 - self.side_scroll
        for k, v in scn.spec:
            text(s, k, (body.x + 8, y), 10, (170, 175, 170), bold=True)
            y = ui.text_block(s, v, (body.x + 128, y, body.w - 136, 400), 10, (130, 255, 170), lh=13, mono=False) + 3
        fr = getattr(scn, "frame", None)
        if fr and not callable(fr):
            y += 6
            text(s, "FRAME FORMAT", (body.x + 8, y), 11, C["amber"], bold=True)
            y = frame_diagram(s, pygame.Rect(body.x + 8, y + 16, body.w - 16, 1000), fr, y + 16)
        s.set_clip(clip)


class Rack:
    """Left-hand protocol selector for one category."""

    def __init__(self, app):
        self.app = app
        self.btns = []
        self.top = 0
        self.nvis = 25                   # visible buttons (fewer while a lab card is shown)
        self.cur = None

    def build(self, items, cur_key, on_pick):
        self.btns = []
        self.top = 0
        for i, (key, name, tip) in enumerate(items):
            b = Button((8, 82 + i * 31, 236, 28), name, tip, toggle=False, on_click=lambda b, k=key: on_pick(k), size=10)
            b._key = key
            self.btns.append(b)
        self.cur = cur_key

    def handle(self, ev):
        if ev.type == pygame.MOUSEWHEEL and ui.MOUSE[0] < 250 and len(self.btns) > self.nvis:
            self.top = max(0, min(len(self.btns) - self.nvis, self.top - ev.y))
            self._place()
            return True
        for b in self.btns:
            if b.visible and b.handle(ev):
                return True
        return False

    def _place(self):
        self.top = max(0, min(self.top, len(self.btns) - self.nvis))
        if self.cur is not None:                 # keep the selected protocol in view
            k = next((i for i, b in enumerate(self.btns) if b._key == self.cur), None)
            if k is not None and not self.top <= k < self.top + self.nvis and getattr(self, "_seen", None) != (self.cur, self.nvis):
                self.top = max(0, min(k - self.nvis // 2, len(self.btns) - self.nvis))
            self._seen = (self.cur, self.nvis)
        for i, b in enumerate(self.btns):
            j = i - self.top
            b.rect.y = 82 + j * 31
            b.visible = 0 <= j < self.nvis

    def tip_at(self, p):
        for b in self.btns:
            if b.visible and b.hit(p):
                return b.tip
        return ""

    def draw(self, s, title):
        r = pygame.Rect(0, ui.TOP, 250, ui.BOT - ui.TOP)
        ui.panel(s, r, title)
        self._place()
        for b in self.btns:
            if b.visible:
                b.on = b._key == self.cur
                b.draw(s)
        if len(self.btns) > self.nvis:
            if self.top > 0:
                text(s, "more above - scroll", (126, 68), 9, C["dim"], align="c")
            if self.top + self.nvis < len(self.btns):
                text(s, "more below - scroll", (126, 82 + self.nvis * 31 - 2), 9, C["dim"], align="c")
